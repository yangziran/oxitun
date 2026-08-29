#![allow(linker_messages)]
use clap::Parser;
use log::{error, info};
use oxitun_core::config::Config;
use oxitun_core::pool::ServerPool;
use oxitun_core::tunnel::TunnelManager;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about = "OxiTun CLI - High performance SSH tunnel proxy", long_about = None)]
struct Args {
    /// 配置文件路径 (Path to configuration file)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志，默认级别为 info
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    let args = Args::parse();
    info!("Starting OxiTun CLI...");
    
    // 1. 加载配置
    if !args.config.exists() {
        error!("Configuration file not found: {}", args.config.display());
        std::process::exit(1);
    }
    
    let config = Config::load_from_file(&args.config)?;
    info!("Loaded config: {} servers, {} tunnels", config.servers.len(), config.tunnels.len());
    
    // 2. 初始化核心引擎
    let pool = Arc::new(ServerPool::new(config.servers.clone()));
    let manager = TunnelManager::new(
        pool.clone(),
        config.routing.clone(),
        config.general.chnroute_url.clone()
    ).await;
    
    // 3. 启动所有隧道
    for tun_cfg in &config.tunnels {
        if let Err(e) = manager.start_tunnel(tun_cfg.clone()).await {
            error!("Failed to start tunnel {}: {}", tun_cfg.name, e);
            std::process::exit(1);
        }
    }
    
    info!("OxiTun is running. Press Ctrl+C to stop.");
    
    // 4. 等待中止信号
    tokio::signal::ctrl_c().await?;
    info!("Received Ctrl+C, shutting down gracefully...");
    
    // 5. 优雅清理资源
    manager.stop_all().await;
    info!("Shutdown complete.");
    
    Ok(())
}
