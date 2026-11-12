use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// 核心配置模块
/// 定义了 OxiTun 的所有配置结构体（支持 YAML 序列化与反序列化）。
/// 包含服务器配置、隧道配置（支持 Local、Dynamic、Remote、Dns 等）、全局路由规则等。
/// OxiTun 根配置结构体，负责整合全局设置、服务器列表、隧道和路由配置
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// 客户端全局通用行为配置，例如自启动、GUI 交互偏好和订阅链接等
pub struct GeneralConfig {
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub auto_startup: bool,
    #[serde(default)]
    pub auto_set_system_proxy: bool,
    #[serde(default)]
    pub pin_window: bool,
    #[serde(default = "default_chnroute_url")]
    pub chnroute_url: String,
    #[serde(default = "default_update_interval")]
    pub chnroute_update_interval_hours: f32,
    /// 可选：Prometheus 指标监听地址（如 "127.0.0.1:9090"）；不配置则不启动监听器
    #[serde(default)]
    pub metrics_addr: Option<String>,
}

fn default_update_interval() -> f32 {
    24.0
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            auto_startup: false,
            auto_set_system_proxy: false,
            pin_window: false,
            auto_connect: false,
            chnroute_url: default_chnroute_url(),
            chnroute_update_interval_hours: default_update_interval(),
            metrics_addr: None,
        }
    }
}

fn default_chnroute_url() -> String {
    "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// 路由引擎的配置，包括代理模式（全局、直连、黑白名单）以及自定义的 IP/域名 分流规则
pub struct RoutingConfig {
    /// 缺省为全局代理（与 Rust Default 一致）
    #[serde(default)]
    pub mode: RouteMode,
    /// 缺省绕过局域网（serde 与 Rust Default 均为 true）
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
}

// 手工 Default：保证与 serde 逐字段缺省语义完全一致。
// 此前 derive 的 Default 在整体缺省 routing 段时给出 bypass_lan=false，
// 而字段级 serde 缺省为 true，两者行为不一致
impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mode: RouteMode::default(),
            bypass_lan: default_true(),
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
/// 代理路由模式
pub enum RouteMode {
    #[default]
    Global,
    Whitelist,
    Blacklist,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// 远端代理服务器节点配置（如 SSH 登录凭证、加密方式及并发连接池大小等）
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,

    // 认证设置：password 或 key；未设置时优先使用非空 key_path
    pub auth_type: Option<String>,
    pub password: Option<String>,
    pub key_path: Option<String>,
    #[serde(default)]
    pub encrypted: Option<bool>,

    // 连接设置
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_keep_alive")]
    pub keep_alive_interval: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    // 高级设置
    #[serde(default = "default_true")]
    pub strict_host_key: bool,
    /// 预置的主机密钥 SHA256 指纹（形如 `SHA256:xxxx`），用于无人值守部署的首次信任
    #[serde(default)]
    pub host_key: Option<String>,

    /// ProxyJump 跳板节点名称（引用 servers 中另一节点；支持链式，自动检测循环）
    #[serde(default)]
    pub jump_host: Option<String>,
}

fn default_pool_size() -> u32 {
    8
}
fn default_keep_alive() -> u64 {
    3
}
fn default_timeout() -> u32 {
    15
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
/// 多服务器节点选择策略
pub enum TunnelStrategy {
    /// 按 server_names 顺序优先使用前者，故障时切换（默认；主节点恢复后不自动回切）
    #[default]
    Failover,
    /// 每个新入站连接在可用节点间轮询分摊
    RoundRobin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// 本地监听隧道的定义配置（将本地端口转发到何处，或者开启何种类型的网络代理）
pub struct TunnelConfig {
    pub name: String,
    pub server_names: Vec<String>,
    #[serde(rename = "type")]
    pub tunnel_type: TunnelType,
    pub port: u16,
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub share_on_lan: bool,
    /// 是否为主代理（显式标记，替代 tunnels[0] 位置约定；至多一个且必须为 Dynamic）
    #[serde(default)]
    pub primary: bool,
    /// 多节点策略（仅多 server_names 时有意义）
    #[serde(default)]
    pub strategy: TunnelStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// 支持的隧道工作模式
pub enum TunnelType {
    Local,
    Dynamic,
    Remote,
    Dns,
    DnsDot,
    DnsDoh,
}

impl Config {
    /// 事务式热加载的整批校验：任一错误则整批拒绝，调用方继续运行旧配置
    ///
    /// 校验项：
    /// - 服务器名、隧道名必须唯一
    /// - 隧道引用的服务器必须存在
    /// - ProxyJump 引用的节点必须存在且不得成环
    /// - 相同传输协议（TCP/UDP）且相同端口的隧道视为监听冲突
    pub fn validate(&self) -> Result<()> {
        // 名称唯一性校验
        let mut seen_servers: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for srv in &self.servers {
            if !seen_servers.insert(srv.name.as_str()) {
                return Err(anyhow::anyhow!("服务器名 {} 重复", srv.name));
            }
        }
        let mut seen_tunnels: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for tun in &self.tunnels {
            if !seen_tunnels.insert(tun.name.as_str()) {
                return Err(anyhow::anyhow!("隧道名 {} 重复", tun.name));
            }
        }

        // 路由规则校验：含 '/' 的规则必须是合法 CIDR。
        // 否则如 "10.0.0.0/33" 会静默降级为域名规则，不报错也不生效
        for (list_name, rules) in [
            ("白名单", &self.routing.whitelist),
            ("黑名单", &self.routing.blacklist),
        ] {
            for rule in rules {
                if rule.contains('/') && rule.parse::<ipnet::IpNet>().is_err() {
                    return Err(anyhow::anyhow!(
                        "路由{}规则 '{}' 不是合法 CIDR",
                        list_name,
                        rule
                    ));
                }
            }
        }

        let server_names: std::collections::HashSet<&str> =
            self.servers.iter().map(|s| s.name.as_str()).collect();

        // 隧道引用校验
        for tun in &self.tunnels {
            for name in &tun.server_names {
                if !server_names.contains(name.as_str()) {
                    return Err(anyhow::anyhow!(
                        "隧道 {} 引用了不存在的服务器 {}",
                        tun.name,
                        name
                    ));
                }
            }
            if tun.tunnel_type != TunnelType::Dynamic && tun.server_names.is_empty() {
                return Err(anyhow::anyhow!("隧道 {} 未绑定任何服务器", tun.name));
            }
        }

        // 主代理校验：至多一个，且必须是动态代理（SOCKS5）类型
        let mut primary_count = 0;
        for tun in &self.tunnels {
            if tun.primary {
                primary_count += 1;
                if tun.tunnel_type != TunnelType::Dynamic {
                    return Err(anyhow::anyhow!(
                        "主代理必须是动态代理（SOCKS5）类型（隧道 {} 当前为 {:?}）",
                        tun.name,
                        tun.tunnel_type
                    ));
                }
            }
        }
        if primary_count > 1 {
            return Err(anyhow::anyhow!(
                "最多只能有一个主代理（primary）隧道，当前有 {} 个",
                primary_count
            ));
        }

        // 跳板引用与循环检测（DFS）
        for srv in &self.servers {
            if let Some(jump) = srv.jump_host.as_deref().filter(|s| !s.trim().is_empty())
                && !server_names.contains(jump)
            {
                return Err(anyhow::anyhow!(
                    "服务器 {} 的跳板 {} 不存在",
                    srv.name,
                    jump
                ));
            }
            let mut stack: Vec<&str> = vec![srv.name.as_str()];
            let mut cur = srv.jump_host.as_deref();
            while let Some(j) = cur.filter(|s| !s.trim().is_empty()) {
                if stack.contains(&j) {
                    return Err(anyhow::anyhow!(
                        "检测到 ProxyJump 跳板循环: {} -> {}",
                        stack.join(" -> "),
                        j
                    ));
                }
                stack.push(j);
                cur = self
                    .servers
                    .iter()
                    .find(|s| s.name == j)
                    .and_then(|s| s.jump_host.as_deref());
            }
        }

        // 监听端口冲突：DNS 类隧道监听 UDP，其余监听 TCP；
        // 仅同传输协议且同端口才算冲突（TCP 与 UDP 端口空间相互独立）
        let mut seen: std::collections::HashMap<(u16, &'static str), &str> =
            std::collections::HashMap::new();
        for tun in &self.tunnels {
            let proto = match tun.tunnel_type {
                TunnelType::Dns | TunnelType::DnsDot | TunnelType::DnsDoh => "UDP",
                _ => "TCP",
            };
            let key = (tun.port, proto);
            if let Some(other) = seen.insert(key, &tun.name) {
                return Err(anyhow::anyhow!(
                    "隧道 {} 与 {} 监听端口冲突 ({} 端口 {})",
                    tun.name,
                    other,
                    proto,
                    tun.port
                ));
            }
        }
        Ok(())
    }

    /// 返回显式标记为 primary 的主代理隧道（无则返回 None）
    pub fn primary_tunnel(&self) -> Option<&TunnelConfig> {
        self.tunnels.iter().find(|t| t.primary)
    }

    /// 确保存在主代理：
    /// - 已有 primary 标记则不动
    /// - 否则把第一个 Dynamic 隧道标记为主代理
    /// - 没有任何 Dynamic 隧道则创建一个默认主代理（name: 主代理, port: 1080）
    pub fn ensure_primary(&mut self) {
        if self.tunnels.iter().any(|t| t.primary) {
            return;
        }
        if let Some(tun) = self
            .tunnels
            .iter_mut()
            .find(|t| t.tunnel_type == TunnelType::Dynamic)
        {
            tun.primary = true;
            return;
        }
        self.tunnels.push(TunnelConfig {
            name: "主代理".to_string(),
            server_names: vec![],
            tunnel_type: TunnelType::Dynamic,
            port: 1080,
            remote_addr: None,
            share_on_lan: false,
            primary: true,
            strategy: TunnelStrategy::default(),
        });
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("读取配置文件失败: {}", path.as_ref().display()))?;
        let mut config: Config =
            serde_yaml::from_str(&content).with_context(|| "解析 YAML 配置失败")?;

        for srv in &mut config.servers {
            if srv.encrypted == Some(true) {
                if let Some(pwd) = &srv.password {
                    let decrypted = crate::crypto::decrypt(pwd)
                        .with_context(|| format!("解密服务器 {} 的密码失败", srv.name))?;
                    srv.password = Some(decrypted);
                    srv.encrypted = Some(false);
                } else {
                    srv.encrypted = Some(false);
                }
            }
        }

        // 旧配置迁移：无 primary 标记时，把第一个 Dynamic 隧道标记为主代理
        if !config.tunnels.iter().any(|t| t.primary)
            && let Some(tun) = config
                .tunnels
                .iter_mut()
                .find(|t| t.tunnel_type == TunnelType::Dynamic)
        {
            tun.primary = true;
        }

        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut config_to_save = self.clone();

        for srv in &mut config_to_save.servers {
            if srv.encrypted != Some(true)
                && let Some(pwd) = &srv.password
            {
                let encrypted = crate::crypto::encrypt(pwd)
                    .with_context(|| format!("加密服务器 {} 的密码失败", srv.name))?;
                srv.password = Some(encrypted);
                srv.encrypted = Some(true);
            }
        }

        let content = serde_yaml::to_string(&config_to_save)?;
        // 原子写：先写同目录临时文件再 rename，
        // 避免写入中途失败（断电/磁盘满）留下截断的半截配置。
        // pid + 随机数保证多进程/多线程不会共用临时文件并互相截断
        let path = path.as_ref();
        let random_suffix = {
            use rand::RngExt as _;
            rand::rng().random::<u64>()
        };
        let tmp_path =
            path.with_extension(format!("tmp.{}.{:016x}", std::process::id(), random_suffix));
        if let Err(e) = fs::write(&tmp_path, &content) {
            let _ = fs::remove_file(&tmp_path); // 清理残留临时文件
            return Err(e).with_context(|| format!("写入临时配置文件失败: {}", tmp_path.display()));
        }
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e).with_context(|| format!("重命名配置文件失败: {}", path.display()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str, jump: Option<&str>) -> ServerConfig {
        ServerConfig {
            name: name.into(),
            host: "127.0.0.1".into(),
            port: 22,
            user: "u".into(),
            auth_type: None,
            password: Some("p".into()),
            key_path: None,
            encrypted: None,
            pool_size: 1,
            keep_alive_interval: 3,
            timeout_seconds: 5,
            strict_host_key: true,
            host_key: None,
            jump_host: jump.map(String::from),
        }
    }

    fn tunnel(name: &str, servers: Vec<&str>, port: u16, share: bool) -> TunnelConfig {
        TunnelConfig {
            name: name.into(),
            server_names: servers.into_iter().map(String::from).collect(),
            tunnel_type: TunnelType::Dynamic,
            port,
            remote_addr: None,
            share_on_lan: share,
            primary: false,
            strategy: TunnelStrategy::Failover,
        }
    }

    #[test]
    fn validate_rejects_missing_server_reference() {
        let cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![tunnel("t1", vec!["ghost"], 1080, false)],
            routing: Default::default(),
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("不存在的服务器"), "{}", err);
    }

    #[test]
    fn validate_detects_jump_cycle_and_missing_jump() {
        let cfg = Config {
            general: Default::default(),
            servers: vec![server("a", Some("b")), server("b", Some("a"))],
            tunnels: vec![],
            routing: Default::default(),
        };
        assert!(cfg.validate().unwrap_err().to_string().contains("循环"));

        let cfg2 = Config {
            general: Default::default(),
            servers: vec![server("a", Some("ghost"))],
            tunnels: vec![],
            routing: Default::default(),
        };
        assert!(cfg2.validate().unwrap_err().to_string().contains("跳板"));
    }

    #[test]
    fn validate_detects_port_conflict_and_accepts_valid() {
        // 同为 TCP 隧道（Dynamic）同端口：冲突
        let bad = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![
                tunnel("t1", vec!["a"], 1080, false),
                tunnel("t2", vec!["a"], 1080, false),
            ],
            routing: Default::default(),
        };
        assert!(bad.validate().unwrap_err().to_string().contains("冲突"));

        // 同为 UDP 的 DNS 类隧道同端口：冲突
        let mut d1 = tunnel("d1", vec!["a"], 5353, false);
        d1.tunnel_type = TunnelType::Dns;
        let mut d2 = tunnel("d2", vec!["a"], 5353, true);
        d2.tunnel_type = TunnelType::DnsDot;
        let bad_udp = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![d1, d2],
            routing: Default::default(),
        };
        assert!(
            bad_udp.validate().unwrap_err().to_string().contains("冲突"),
            "DNS 类隧道同 UDP 端口必须判定冲突"
        );

        // 合法：不同端口；且 TCP 与 UDP 同端口不冲突（端口空间独立），
        // share_on_lan 差异不再影响冲突判定
        let mut dns = tunnel("dns1", vec!["a"], 1080, false);
        dns.tunnel_type = TunnelType::DnsDoh;
        let ok = Config {
            general: Default::default(),
            servers: vec![server("a", None), server("b", Some("a"))],
            tunnels: vec![
                tunnel("t1", vec!["a", "b"], 1080, false),
                tunnel("t2", vec!["a"], 1081, true),
                dns, // UDP 1080 与 t1 的 TCP 1080 不冲突
            ],
            routing: Default::default(),
        };
        ok.validate().unwrap();
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        // 服务器名重复
        let dup_srv = Config {
            general: Default::default(),
            servers: vec![server("a", None), server("a", None)],
            tunnels: vec![],
            routing: Default::default(),
        };
        assert!(
            dup_srv.validate().unwrap_err().to_string().contains("重复"),
            "服务器名重复必须报错"
        );

        // 隧道名重复
        let dup_tun = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![
                tunnel("t1", vec!["a"], 1080, false),
                tunnel("t1", vec!["a"], 1081, false),
            ],
            routing: Default::default(),
        };
        assert!(
            dup_tun.validate().unwrap_err().to_string().contains("重复"),
            "隧道名重复必须报错"
        );
    }

    #[test]
    fn validate_rejects_non_dynamic_primary() {
        let mut t = tunnel("t1", vec!["a"], 1080, false);
        t.tunnel_type = TunnelType::Local;
        t.remote_addr = Some("127.0.0.1:80".into());
        t.primary = true;
        let cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![t],
            routing: Default::default(),
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("主代理必须是动态代理（SOCKS5）类型"),
            "{}",
            err
        );
    }

    #[test]
    fn validate_rejects_multiple_primaries() {
        let mut t1 = tunnel("t1", vec!["a"], 1080, false);
        t1.primary = true;
        let mut t2 = tunnel("t2", vec!["a"], 1081, false);
        t2.primary = true;
        let cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![t1, t2],
            routing: Default::default(),
        };
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("最多只能有一个主代理"), "{}", err);
    }

    #[test]
    fn validate_accepts_single_dynamic_primary() {
        let mut t1 = tunnel("t1", vec!["a"], 1080, false);
        t1.primary = true;
        let cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![t1, tunnel("t2", vec!["a"], 1081, false)],
            routing: Default::default(),
        };
        cfg.validate().unwrap();
        assert_eq!(cfg.primary_tunnel().map(|t| t.name.as_str()), Some("t1"));
    }

    #[test]
    fn ensure_primary_marks_first_dynamic() {
        let mut cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![
                {
                    let mut t = tunnel("t1", vec!["a"], 8080, false);
                    t.tunnel_type = TunnelType::Local;
                    t.remote_addr = Some("127.0.0.1:80".into());
                    t
                },
                tunnel("t2", vec!["a"], 1080, false),
            ],
            routing: Default::default(),
        };
        assert!(cfg.primary_tunnel().is_none());
        cfg.ensure_primary();
        assert_eq!(cfg.primary_tunnel().map(|t| t.name.as_str()), Some("t2"));
        // 幂等：再次调用不改变结果
        cfg.ensure_primary();
        assert_eq!(
            cfg.tunnels.iter().filter(|t| t.primary).count(),
            1,
            "ensure_primary 必须幂等"
        );
    }

    #[test]
    fn ensure_primary_creates_default_when_no_dynamic() {
        let mut cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![{
                let mut t = tunnel("t1", vec!["a"], 8080, false);
                t.tunnel_type = TunnelType::Local;
                t.remote_addr = Some("127.0.0.1:80".into());
                t
            }],
            routing: Default::default(),
        };
        cfg.ensure_primary();
        let p = cfg.primary_tunnel().expect("应创建默认主代理");
        assert_eq!(p.name, "主代理");
        assert_eq!(p.port, 1080);
        assert_eq!(p.tunnel_type, TunnelType::Dynamic);

        // 空隧道列表同样创建默认主代理
        let mut empty = Config {
            general: Default::default(),
            servers: vec![],
            tunnels: vec![],
            routing: Default::default(),
        };
        empty.ensure_primary();
        assert_eq!(empty.primary_tunnel().map(|t| t.port), Some(1080));
    }

    #[test]
    fn load_marks_first_dynamic_as_primary_for_legacy_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(
            &path,
            r#"servers:
  - name: a
    host: example.com
    port: 22
    user: root
    password: "p"
tunnels:
  - name: rule1
    server_names: [a]
    type: local
    port: 8080
    remote_addr: "127.0.0.1:80"
  - name: rule2
    server_names: [a]
    type: dynamic
    port: 1080
"#,
        )
        .unwrap();

        let cfg = Config::load_from_file(&path).unwrap();
        assert_eq!(
            cfg.primary_tunnel().map(|t| t.name.as_str()),
            Some("rule2"),
            "旧配置应自动把第一个 Dynamic 隧道标记为主代理"
        );
        assert!(!cfg.tunnels[0].primary, "非 Dynamic 隧道不得被标记");
    }

    #[test]
    fn load_rejects_invalid_encrypted_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(
            &path,
            r#"servers:
  - name: broken
    host: example.com
    port: 22
    user: root
    password: "not-base64!"
    encrypted: true
tunnels: []
"#,
        )
        .unwrap();

        let err = Config::load_from_file(&path).unwrap_err();
        assert!(format!("{:#}", err).contains("解密服务器 broken 的密码失败"));
    }

    #[test]
    fn validate_rejects_invalid_cidr_rule() {
        // 非法 CIDR（掩码越界）必须报错并定位到具体规则，
        // 不得静默降级为域名规则
        let mut cfg = Config {
            general: Default::default(),
            servers: vec![server("a", None)],
            tunnels: vec![],
            routing: Default::default(),
        };
        cfg.routing.whitelist.push("10.0.0.0/33".to_string());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("10.0.0.0/33"), "{}", err);
        assert!(err.contains("白名单"), "{}", err);

        // 黑名单同样校验
        cfg.routing.whitelist.clear();
        cfg.routing.blacklist.push("192.168.0.0/40".to_string());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("黑名单"), "{}", err);

        // 合法 CIDR 与域名规则不受影响
        cfg.routing.blacklist.clear();
        cfg.routing
            .whitelist
            .extend(["10.0.0.0/8".to_string(), "example.com".to_string()]);
        cfg.validate().unwrap();
    }

    /// RoutingConfig 手工 Default 与 serde 逐字段缺省语义必须一致
    #[test]
    fn routing_default_matches_serde_defaults() {
        let d = RoutingConfig::default();
        assert_eq!(d.mode, RouteMode::Global, "缺省路由模式应为全局");
        assert!(d.bypass_lan, "Rust Default 的 bypass_lan 应为 true");
        assert!(d.whitelist.is_empty());
        assert!(d.blacklist.is_empty());

        // 整体缺省 routing 段：与手工 Default 完全一致
        let cfg: Config = serde_yaml::from_str("servers: []\ntunnels: []\n").unwrap();
        assert_eq!(cfg.routing, d, "缺省 routing 段应与 Default 一致");
    }

    /// routing 段只给 mode 时必须可加载（其余字段走 serde 缺省）
    #[test]
    fn routing_partial_fields_load_with_defaults() {
        let cfg: Config =
            serde_yaml::from_str("servers: []\ntunnels: []\nrouting:\n  mode: global\n").unwrap();
        assert_eq!(cfg.routing.mode, RouteMode::Global);
        assert!(cfg.routing.bypass_lan, "mode 之外字段应缺省为 true");
        assert!(cfg.routing.whitelist.is_empty());
        assert!(cfg.routing.blacklist.is_empty());
    }

    /// 多线程向同一路径保存时使用各自临时文件，最终文件必须是某一份完整配置
    #[test]
    fn concurrent_save_to_file_keeps_final_config_parseable() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("config.yaml"));
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();

        for i in 0..workers {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut config = Config {
                    general: Default::default(),
                    servers: vec![],
                    tunnels: vec![],
                    routing: Default::default(),
                };
                config.general.metrics_addr = Some(format!("127.0.0.1:{}", 20000 + i));
                barrier.wait();
                config.save_to_file(path.as_path())
            }));
        }

        for handle in handles {
            handle
                .join()
                .expect("保存线程不应 panic")
                .expect("并发保存均应成功");
        }

        let saved = Config::load_from_file(path.as_path()).expect("最终配置必须完整可解析");
        let marker = saved.general.metrics_addr.expect("应保留保存的标记");
        assert!(
            (0..workers).any(|i| marker == format!("127.0.0.1:{}", 20000 + i)),
            "最终内容必须完整来自某一次保存，实际为 {}",
            marker
        );
    }

    #[test]
    fn enums_accept_only_canonical_names() {
        assert_eq!(
            serde_yaml::from_str::<TunnelType>("dns_dot").unwrap(),
            TunnelType::DnsDot
        );
        assert!(serde_yaml::from_str::<TunnelType>("DnsDot").is_err());
        assert_eq!(
            serde_yaml::from_str::<RouteMode>("global").unwrap(),
            RouteMode::Global
        );
        assert!(serde_yaml::from_str::<RouteMode>("Global").is_err());
    }
}
