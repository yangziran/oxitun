use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct ServerConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    
    // Auth
    pub auth_type: Option<String>,
    pub password: Option<String>,
    pub key_path: Option<String>,
    #[serde(default)]
    pub encrypted: Option<bool>,
    
    // Connection
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    #[serde(default = "default_keep_alive")]
    pub keep_alive_interval: u64,
    #[serde(default = "default_attempts")]
    pub reconnect_attempts: u32,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    // Advanced
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
pub enum TunnelType {
    #[serde(alias = "local", alias = "Local")]
    Local,
    #[serde(alias = "dynamic", alias = "Dynamic")]
    Dynamic,
}

impl Config {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
        let mut config: Config = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse YAML configuration")?;
            
        // Auto decrypt passwords
        for srv in &mut config.servers {
            if srv.encrypted == Some(true) {
                if let Some(pwd) = &srv.password {
                    if let Ok(dec) = crate::crypto::decrypt(pwd) {
                        srv.password = Some(dec);
                        srv.encrypted = Some(false);
                    } else {
                        log::error!("Failed to decrypt password for server {}", srv.name);
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
        
        // Auto encrypt passwords
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
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;
        Ok(())
    }
}
