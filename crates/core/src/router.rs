use crate::config::{RoutingConfig, RouteMode};
use log::{info, error, debug};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use ipnet::IpNet;
use tokio::fs;

/// 核心路由分流引擎，负责根据黑白名单及局域网/大陆IP绕行规则判断流量走向
pub struct Router {
    config: RoutingConfig,
    /// 缓存的 CIDR 路由规则 (start_ip, end_ip) 供二分查找
    chnroutes: Vec<(u32, u32)>,
    whitelist_cidrs: Vec<IpNet>,
    whitelist_domains: Vec<String>,
    blacklist_cidrs: Vec<IpNet>,
    blacklist_domains: Vec<String>,
}

impl Router {
    /// 初始化路由引擎，解析黑白名单并异步加载大陆直连路由表 (若开启)
    pub async fn new(config: RoutingConfig, chnroute_url: &str) -> Self {
        let mut whitelist_cidrs = Vec::new();
        let mut whitelist_domains = Vec::new();
        for rule in &config.whitelist {
            if let Ok(net) = rule.parse::<IpNet>() {
                whitelist_cidrs.push(net);
            } else if let Ok(ip) = rule.parse::<IpAddr>() {
                whitelist_cidrs.push(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap());
            } else {
                whitelist_domains.push(rule.clone());
            }
        }
        
        let mut blacklist_cidrs = Vec::new();
        let mut blacklist_domains = Vec::new();
        for rule in &config.blacklist {
            if let Ok(net) = rule.parse::<IpNet>() {
                blacklist_cidrs.push(net);
            } else if let Ok(ip) = rule.parse::<IpAddr>() {
                blacklist_cidrs.push(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap());
            } else {
                blacklist_domains.push(rule.clone());
            }
        }

        let mut router = Self {
            config,
            chnroutes: Vec::new(),
            whitelist_cidrs,
            whitelist_domains,
            blacklist_cidrs,
            blacklist_domains,
        };

        if router.config.bypass_lan {
            router.load_chnroutes(chnroute_url).await;
        }

        router
    }

    async fn load_chnroutes(&mut self, url: &str) {
        let cache_dir = dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("OxiTun");
        let _ = fs::create_dir_all(&cache_dir).await;
        let cache_file = cache_dir.join("chnroutes.txt");

        let mut lines = String::new();
        
        // 尝试从远端下载路由列表
        
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().unwrap();
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text().await {
                    lines = text;
                    let _ = fs::write(&cache_file, &lines).await;
                    info!("已成功下载并缓存最新的 chnroutes.txt 路由表");
                }
            }
            _ => {
                // 若下载失败，回退使用本地缓存
                if let Ok(text) = fs::read_to_string(&cache_file).await {
                    lines = text;
                    info!("从本地缓存成功加载 chnroutes.txt 路由表");
                } else {
                    error!("下载 chnroutes.txt 失败，且未找到本地缓存");
                }
            }
        }

        let mut routes = Vec::new();
        for line in lines.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(parsed) = parse_cidr(line) {
                routes.push(parsed);
            }
        }
        
        routes.sort_by_key(|r| r.0);
        self.chnroutes = routes;
        info!("成功加载 {} 条大陆 IP 直连路由规则", self.chnroutes.len());
    }

    fn match_rules(&self, host: &str, domains: &[String], cidrs: &[IpNet]) -> bool {
        let is_ip = host.parse::<IpAddr>();
        if let Ok(ip) = is_ip {
            cidrs.iter().any(|cidr| cidr.contains(&ip))
        } else {
            domains.iter().any(|d| host == d || host.ends_with(&format!(".{}", d)))
        }
    }

    pub async fn should_proxy(&self, host: &str) -> bool {
        match self.config.mode {
            RouteMode::Global => {
                if self.config.bypass_lan {
                    if let Ok(ip) = self.resolve_and_check_bypass(host).await {
                        if ip {
                            return false;
                        }
                    }
                }
                true
            },
            RouteMode::Direct => false,
            RouteMode::Whitelist => {
                self.match_rules(host, &self.whitelist_domains, &self.whitelist_cidrs)
            }
            RouteMode::Blacklist => {
                let in_blacklist = self.match_rules(host, &self.blacklist_domains, &self.blacklist_cidrs);
                if in_blacklist {
                    return false;
                }
                // 若不在黑名单内则默认代理，除非启用了绕过局域网/大陆IP，并且目标为境内 IP
                if self.config.bypass_lan {
                    if let Ok(ip) = self.resolve_and_check_bypass(host).await {
                        if ip {
                            return false; // 局域网及大陆 IP 执行直连
                        }
                    }
                }
                true
            }
        }
    }

    async fn resolve_and_check_bypass(&self, host: &str) -> Result<bool, anyhow::Error> {
        // 简单启发式策略：若 host 已经是 IP 格式，则直接解析判断
        // 警告：绝对禁止在此处使用 tokio::net::lookup_host！
        // 对被污染的域名（如 youtube.com）进行本地 DNS 解析会导致每次请求长达 10 秒以上的延迟！
        let ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else {
            // 目标为域名，我们默认其非局域网 IP。
            // 如果用户想让特定域名直连，应使用域名规则路由。
            return Ok(false);
        };

        if is_local_or_lan(ip) {
            debug!("IP {} 属于本地/局域网/多播地址，跳过代理直接连接", ip);
            return Ok(true);
        }
        
        if let std::net::IpAddr::V4(ipv4) = ip {
            if self.is_cn_ip(ipv4) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_cn_ip(&self, ip: Ipv4Addr) -> bool {
        let val = u32::from_be_bytes(ip.octets());
        self.chnroutes.binary_search_by(|&(start, end)| {
            if val < start {
                std::cmp::Ordering::Greater
            } else if val > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).is_ok()
    }
}

fn is_local_or_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 127.0.0.0/8 (Loopback)
            octets[0] == 127 || 
            // 10.0.0.0/8 (Private)
            octets[0] == 10 || 
            // 172.16.0.0/12 (Private)
            (octets[0] == 172 && (16..=31).contains(&octets[1])) || 
            // 192.168.0.0/16 (Private)
            (octets[0] == 192 && octets[1] == 168) ||
            // 169.254.0.0/16 (Link-local)
            (octets[0] == 169 && octets[1] == 254) ||
            // 224.0.0.0/4 (Multicast)
            (octets[0] >= 224 && octets[0] <= 239) ||
            // 255.255.255.255 (Broadcast)
            ipv4.is_broadcast()
        },
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // ::1 (Loopback)
            ipv6.is_loopback() ||
            // fc00::/7 (唯一本地地址)
            (segments[0] & 0xfe00) == 0xfc00 ||
            // fe80::/10 (链路本地地址)
            (segments[0] & 0xffc0) == 0xfe80 ||
            // 多播地址 (ff00::/8)
            (segments[0] & 0xff00) == 0xff00
        }
    }
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return None; }
    let ip = parts[0].parse::<Ipv4Addr>().ok()?;
    let mask = parts[1].parse::<u32>().ok()?;
    let ip_val = u32::from_be_bytes(ip.octets());
    let mask_val = if mask == 0 { 0 } else if mask > 32 { return None; } else { !0u32 << (32 - mask) };
    
    let start = ip_val & mask_val;
    let end = start | !mask_val;
    
    Some((start, end))
}
