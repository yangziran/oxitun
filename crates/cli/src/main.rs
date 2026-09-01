#![allow(linker_messages)]
use clap::Parser;
use log::{error, info};
use oxitun_core::config::Config;
use oxitun_core::pool::ServerPool;
use oxitun_core::tunnel::TunnelManager;
use std::path::PathBuf;
use std::sync::Arc;

/// CLI 应用运行参数配置结构体
#[derive(Parser, Debug)]
#[command(author, version, about = "OxiTun CLI - 高性能 SSH 隧道代理客户端", long_about = None)]
struct Args {
    /// 配置文件路径 (Path to configuration file)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

/// OxiTun 命令行工具的异步主入口
/// 负责读取配置、构建全局依赖资源、启动底层代理隧道，并监听退出信号以提供优雅停机功能。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志，默认级别为 info
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    let args = Args::parse();
    info!("正在启动 OxiTun CLI...");
    
    // 1. 加载配置
    if !args.config.exists() {
        error!("未找到配置文件: {}", args.config.display());
        std::process::exit(1);
    }
    
    let config = Config::load_from_file(&args.config)?;
    info!("已加载配置: 发现 {} 个服务器, {} 个隧道规则", config.servers.len(), config.tunnels.len());
    
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
            error!("启动隧道 {} 失败: {}", tun_cfg.name, e);
            std::process::exit(1);
        }
    }
    
    info!("OxiTun 正在运行，按 Ctrl+C 停止。");
    
    // 4. 等待中止信号
    tokio::signal::ctrl_c().await?;
    info!("收到退出信号，正在优雅关闭...");
    
    // 5. 优雅清理资源
    manager.stop_all().await;
    info!("已完全关闭。");
    
    Ok(())
}
