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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
/// 路由引擎的配置，包括代理模式（全局、直连、黑白名单）以及自定义的 IP/域名 分流规则
pub struct RoutingConfig {
    pub mode: RouteMode,
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
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
    /// - 隧道引用的服务器必须存在
    /// - ProxyJump 引用的节点必须存在且不得成环
    /// - 相同端口且相同 share_on_lan 的隧道视为监听冲突
    pub fn validate(&self) -> Result<()> {
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

        // 监听端口冲突：同端口且 share_on_lan 相同的隧道
        let mut seen: std::collections::HashMap<(u16, bool), &str> =
            std::collections::HashMap::new();
        for tun in &self.tunnels {
            let key = (tun.port, tun.share_on_lan);
            if let Some(other) = seen.insert(key, &tun.name) {
                return Err(anyhow::anyhow!(
                    "隧道 {} 与 {} 监听端口冲突 (端口 {} 且局域网共享设置相同)",
                    tun.name,
                    other,
                    tun.port
                ));
            }
        }
        Ok(())
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
        fs::write(&path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.as_ref().display()))?;
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

        let ok = Config {
            general: Default::default(),
            servers: vec![server("a", None), server("b", Some("a"))],
            tunnels: vec![
                tunnel("t1", vec!["a", "b"], 1080, false),
                tunnel("t2", vec!["a"], 1081, true),
            ],
            routing: Default::default(),
        };
        ok.validate().unwrap();
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
