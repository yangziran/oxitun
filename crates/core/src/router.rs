use crate::config::{RouteMode, RoutingConfig};
use ipnet::IpNet;
use log::{debug, error, info};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
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
                // 容错：非法 CIDR 不应静默降级为域名规则，记警告并跳过
                // （正常入口已由 Config::validate 拦截，此处仅兜底）
                if rule.contains('/') {
                    log::warn!("白名单规则 '{}' 不是合法 CIDR，已忽略", rule);
                    continue;
                }
                whitelist_domains.push(normalize_domain(rule));
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
                // 容错：非法 CIDR 不应静默降级为域名规则，记警告并跳过
                // （正常入口已由 Config::validate 拦截，此处仅兜底）
                if rule.contains('/') {
                    log::warn!("黑名单规则 '{}' 不是合法 CIDR，已忽略", rule);
                    continue;
                }
                blacklist_domains.push(normalize_domain(rule));
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
        let cache_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("OxiTun");
        let _ = fs::create_dir_all(&cache_dir).await;
        let cache_file = cache_dir.join("chnroutes.txt");

        // 尝试从远端下载路由列表；
        // 下载失败、body 读取失败、或解析不出任何有效 CIDR 一律视为失败，
        // 回退旧缓存（避免用损坏/空白内容覆盖可用缓存）
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let downloaded = match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => {
                    let routes = parse_route_lines(&text);
                    if routes.is_empty() {
                        error!("下载的 chnroutes.txt 不含有效 CIDR 规则，回退本地缓存");
                        None
                    } else {
                        // 确认内容有效后才写缓存
                        let _ = fs::write(&cache_file, &text).await;
                        info!("已成功下载并缓存最新的 chnroutes.txt 路由表");
                        Some(routes)
                    }
                }
                Err(e) => {
                    error!("读取 chnroutes.txt 响应体失败: {}，回退本地缓存", e);
                    None
                }
            },
            _ => None,
        };

        let routes = match downloaded {
            Some(routes) => routes,
            None => {
                // 回退使用本地旧缓存
                match fs::read_to_string(&cache_file).await {
                    Ok(text) => {
                        info!("从本地缓存成功加载 chnroutes.txt 路由表");
                        parse_route_lines(&text)
                    }
                    Err(_) => {
                        error!("获取 chnroutes.txt 失败，且未找到本地缓存");
                        Vec::new()
                    }
                }
            }
        };

        // 合并重叠/相邻区间后再交给二分查找，避免嵌套或交叉区间破坏二分前提
        self.chnroutes = merge_ranges(routes);
        info!("成功加载 {} 条大陆 IP 直连路由规则", self.chnroutes.len());
    }

    fn match_rules(&self, host: &str, domains: &[String], cidrs: &[IpNet]) -> bool {
        let is_ip = host.parse::<IpAddr>();
        if let Ok(ip) = is_ip {
            cidrs.iter().any(|cidr| cidr.contains(&ip))
        } else {
            // 与规则加载侧统一规范化：小写并去掉根域结尾点号
            let host = normalize_domain(host);
            domains
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{}", d)))
        }
    }

    pub async fn should_proxy(&self, host: &str) -> bool {
        match self.config.mode {
            RouteMode::Global => {
                if self.config.bypass_lan
                    && let Ok(ip) = self.resolve_and_check_bypass(host).await
                    && ip
                {
                    return false;
                }
                true
            }
            RouteMode::Direct => false,
            RouteMode::Whitelist => {
                self.match_rules(host, &self.whitelist_domains, &self.whitelist_cidrs)
            }
            RouteMode::Blacklist => {
                let in_blacklist =
                    self.match_rules(host, &self.blacklist_domains, &self.blacklist_cidrs);
                if in_blacklist {
                    return false;
                }
                // 若不在黑名单内则默认代理，除非启用了绕过局域网/大陆IP，并且目标为境内 IP
                if self.config.bypass_lan
                    && let Ok(ip) = self.resolve_and_check_bypass(host).await
                    && ip
                {
                    return false; // 局域网及大陆 IP 执行直连
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

        if let std::net::IpAddr::V4(ipv4) = ip
            && self.is_cn_ip(ipv4)
        {
            return Ok(true);
        }
        Ok(false)
    }

    fn is_cn_ip(&self, ip: Ipv4Addr) -> bool {
        let val = u32::from_be_bytes(ip.octets());
        self.chnroutes
            .binary_search_by(|&(start, end)| {
                if val < start {
                    std::cmp::Ordering::Greater
                } else if val > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
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
        }
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

/// 域名规则/匹配目标的统一规范化：转小写并去掉根域结尾点号
fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// 从文本中解析出全部有效 CIDR 路由条目（忽略空行与 # 注释行）
fn parse_route_lines(lines: &str) -> Vec<(u32, u32)> {
    lines
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(parse_cidr)
        .collect()
}

fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip = parts[0].parse::<Ipv4Addr>().ok()?;
    let mask = parts[1].parse::<u32>().ok()?;
    let ip_val = u32::from_be_bytes(ip.octets());
    let mask_val = if mask == 0 {
        0
    } else if mask > 32 {
        return None;
    } else {
        !0u32 << (32 - mask)
    };

    let start = ip_val & mask_val;
    let end = start | !mask_val;

    Some((start, end))
}

/// 合并重叠或相邻的 IP 区间（IPv4 以 u32 表示，IPv6 同理可用 u128），
/// 返回按起点排序且互不重叠的区间列表。
/// chnroutes 的二分查找要求区间集合满足该不变量：嵌套（如 10.0.0.0/8 包含
/// 10.1.0.0/16）或交叉的区间会破坏二分的有序前提，导致漏判应直连的 IP。
/// 合并后既消除重叠又保持二分正确。
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_by_key(|r| r.0);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            // 包含（start <= last.1）或首尾相邻（start == last.1 + 1）都合并；
            // saturating_add 防止 last.1 == u32::MAX 时溢出
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteMode;

    async fn make_router(mode: RouteMode, whitelist: Vec<&str>, blacklist: Vec<&str>) -> Router {
        // bypass_lan=false 避免测试联网下载 chnroutes
        let config = RoutingConfig {
            mode,
            bypass_lan: false,
            whitelist: whitelist.into_iter().map(String::from).collect(),
            blacklist: blacklist.into_iter().map(String::from).collect(),
        };
        Router::new(config, "").await
    }

    #[test]
    fn parse_cidr_range() {
        let (start, end) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(start, u32::from_be_bytes([192, 168, 1, 0]));
        assert_eq!(end, u32::from_be_bytes([192, 168, 1, 255]));
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("not-a-cidr").is_none());
    }

    #[tokio::test]
    async fn domain_suffix_matching_has_boundary() {
        let router = make_router(RouteMode::Whitelist, vec!["google.com"], vec![]).await;
        assert!(router.should_proxy("google.com").await, "精确匹配");
        assert!(router.should_proxy("mail.google.com").await, "子域匹配");
        assert!(
            !router.should_proxy("evilgoogle.com").await,
            "后缀拼接不得误匹配"
        );
        assert!(!router.should_proxy("google.com.evil.com").await);
    }

    /// 域名规则加载与匹配统一规范化：大小写不敏感，结尾点号不影响匹配
    #[tokio::test]
    async fn domain_rules_are_normalized() {
        // 规则侧：大写 + 结尾点号
        let router = make_router(RouteMode::Whitelist, vec!["Google.COM."], vec![]).await;
        assert!(router.should_proxy("google.com").await);
        assert!(router.should_proxy("mail.GOOGLE.COM").await);
        // 目标侧：结尾点号（DNS 根域写法）
        assert!(router.should_proxy("google.com.").await);
        assert!(router.should_proxy("Mail.Google.Com.").await);
    }

    /// parse_route_lines 跳过注释与空行，且对无有效 CIDR 的内容返回空
    #[test]
    fn parse_route_lines_skips_invalid() {
        let text = "# comment\n\n10.0.0.0/8\nnot-a-cidr\n192.168.0.0/16\n";
        let routes = parse_route_lines(text);
        assert_eq!(routes.len(), 2);
        assert!(parse_route_lines("# only comments\n\n垃圾内容\n").is_empty());
    }

    /// 嵌套 CIDR（10.0.0.0/8 包含 10.1.0.0/16）合并后，内部 IP 仍能正确判定直连；
    /// 重叠/相邻区间应合并为更大区间，且结果有序互不重叠（二分前提）
    #[test]
    fn merge_ranges_collapses_nested_and_overlapping() {
        let text = "10.1.0.0/16\n10.0.0.0/8\n192.168.1.0/24\n192.168.0.0/16\n172.16.0.0/24\n172.16.1.0/24\n";
        let merged = merge_ranges(parse_route_lines(text));

        // 10.0.0.0/8 与 10.1.0.0/16 嵌套 → 一条；192.168.0.0/16 与 192.168.1.0/24 重叠 → 一条；
        // 172.16.0.0/24 与 172.16.1.0/24 首尾相邻 → 合并为 172.16.0.0 - 172.16.1.255
        assert_eq!(merged.len(), 3);
        assert_eq!(
            merged[0],
            (
                u32::from_be_bytes([10, 0, 0, 0]),
                u32::from_be_bytes([10, 255, 255, 255])
            )
        );
        assert_eq!(
            merged[1],
            (
                u32::from_be_bytes([172, 16, 0, 0]),
                u32::from_be_bytes([172, 16, 1, 255])
            )
        );
        assert_eq!(
            merged[2],
            (
                u32::from_be_bytes([192, 168, 0, 0]),
                u32::from_be_bytes([192, 168, 255, 255])
            )
        );

        // 合并后的区间集合交给二分查找：嵌套区间内部的 IP 不得漏判
        let router = Router {
            config: RoutingConfig::default(),
            chnroutes: merged,
            whitelist_cidrs: Vec::new(),
            whitelist_domains: Vec::new(),
            blacklist_cidrs: Vec::new(),
            blacklist_domains: Vec::new(),
        };
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(router.is_cn_ip(ip("10.1.2.3")), "嵌套区间内部 IP 必须命中");
        assert!(
            router.is_cn_ip(ip("10.200.1.1")),
            "外层区间其他 IP 必须命中"
        );
        assert!(router.is_cn_ip(ip("192.168.1.1")));
        assert!(router.is_cn_ip(ip("192.168.200.1")));
        assert!(
            router.is_cn_ip(ip("172.16.1.1")),
            "相邻合并区间的右半部分必须命中"
        );
        assert!(!router.is_cn_ip(ip("11.0.0.1")));
        assert!(!router.is_cn_ip(ip("172.16.2.1")));
    }

    /// 不重叠且不相邻的区间必须保持独立，不得被误合并
    #[test]
    fn merge_ranges_keeps_disjoint_intervals() {
        let merged = merge_ranges(parse_route_lines("10.0.0.0/24\n10.0.2.0/24\n"));
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].1, u32::from_be_bytes([10, 0, 0, 255]));
        assert_eq!(merged[1].0, u32::from_be_bytes([10, 0, 2, 0]));
    }

    #[tokio::test]
    async fn cidr_matching() {
        let router = make_router(RouteMode::Whitelist, vec!["10.0.0.0/8"], vec![]).await;
        assert!(router.should_proxy("10.1.2.3").await);
        assert!(!router.should_proxy("11.0.0.1").await);
    }

    #[tokio::test]
    async fn mode_semantics() {
        let r = make_router(RouteMode::Global, vec![], vec![]).await;
        assert!(r.should_proxy("anything.com").await, "Global 全部代理");

        let r = make_router(RouteMode::Direct, vec![], vec![]).await;
        assert!(!r.should_proxy("anything.com").await, "Direct 全部直连");

        let r = make_router(RouteMode::Blacklist, vec![], vec!["ads.com"]).await;
        assert!(!r.should_proxy("ads.com").await, "黑名单内直连");
        assert!(r.should_proxy("news.com").await, "黑名单外默认代理");

        let r = make_router(RouteMode::Whitelist, vec!["work.com"], vec![]).await;
        assert!(r.should_proxy("work.com").await, "白名单内代理");
        assert!(!r.should_proxy("news.com").await, "白名单外默认直连");
    }

    #[tokio::test]
    async fn lan_ip_bypasses_when_enabled() {
        let config = RoutingConfig {
            mode: RouteMode::Global,
            bypass_lan: true,
            whitelist: vec![],
            blacklist: vec![],
        };
        let router = Router::new(config, "http://127.0.0.1:1/unreachable").await;
        assert!(!router.should_proxy("192.168.1.1").await, "局域网 IP 直连");
        assert!(!router.should_proxy("127.0.0.1").await);
        assert!(
            router.should_proxy("8.8.8.8").await,
            "公网 IP 仍代理（chnroutes 下载失败为空表）"
        );
        assert!(
            router.should_proxy("example.com").await,
            "域名不本地解析，默认代理"
        );
    }
}
