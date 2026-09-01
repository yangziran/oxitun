use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

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
        }
    }
}

fn default_chnroute_url() -> String {
    "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// 路由引擎的配置，包括代理模式（全局、直连、黑白名单）以及自定义的 IP/域名 分流规则
pub struct RoutingConfig {
    pub mode: RouteMode,
    #[serde(default = "default_true")]
    pub bypass_lan: bool,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
/// 代理路由模式
pub enum RouteMode {
    #[default]
    #[serde(alias = "Global")]
    Global,
    #[serde(alias = "Whitelist")]
    Whitelist,
    #[serde(alias = "Blacklist")]
    Blacklist,
    #[serde(alias = "Direct")]
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// 远端代理服务器节点配置（如 SSH 登录凭证、加密方式及并发连接池大小等）
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    
    // 认证设置
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
    #[serde(default = "default_attempts")]
    pub reconnect_attempts: u32,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    // 高级设置
    #[serde(default)]
    pub compression: bool,
    #[serde(default = "default_true")]
    pub check_host_ip: bool,
    #[serde(default = "default_true")]
    pub strict_host_key: bool,
    #[serde(default = "default_address_family")]
    pub address_family: String,
    
    pub host_key_algorithms: Option<String>,
    pub kex_algorithms: Option<String>,
    pub ciphers: Option<String>,
}

fn default_pool_size() -> u32 { 8 }
fn default_keep_alive() -> u64 { 3 }
fn default_attempts() -> u32 { 999 }
fn default_timeout() -> u32 { 15 }
fn default_address_family() -> String { "Any".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// 支持的隧道工作模式
pub enum TunnelType {
    #[serde(alias = "local", alias = "Local")]
    Local,
    #[serde(alias = "dynamic", alias = "Dynamic")]
    Dynamic,
    #[serde(alias = "remote", alias = "Remote")]
    Remote,
    #[serde(alias = "dns", alias = "Dns")]
    Dns,
    #[serde(alias = "dns_dot", alias = "DnsDot")]
    DnsDot,
    #[serde(alias = "dns_doh", alias = "DnsDoh")]
    DnsDoh,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("读取配置文件失败: {}", path.as_ref().display()))?;
        let mut config: Config = serde_yaml::from_str(&content)
            .with_context(|| "解析 YAML 配置失败")?;
            
        // 自动解密服务器密码
        for srv in &mut config.servers {
            if srv.encrypted == Some(true) {
                if let Some(pwd) = &srv.password {
                    if let Ok(dec) = crate::crypto::decrypt(pwd) {
                        srv.password = Some(dec);
                        srv.encrypted = Some(false);
                    } else {
                        log::error!("解密服务器 {} 的密码失败", srv.name);
                    }
                } else {
                    srv.encrypted = Some(false);
                }
            }
        }
            
        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut config_to_save = self.clone();
        
        // 自动加密服务器密码
        for srv in &mut config_to_save.servers {
            if srv.encrypted != Some(true) {
                if let Some(pwd) = &srv.password {
                    if let Ok(enc) = crate::crypto::encrypt(pwd) {
                        srv.password = Some(enc);
                        srv.encrypted = Some(true);
                    }
                }
            }
        }
        
        let content = serde_yaml::to_string(&config_to_save)?;
        fs::write(&path, content)
            .with_context(|| format!("写入配置文件失败: {}", path.as_ref().display()))?;
        Ok(())
    }
}
