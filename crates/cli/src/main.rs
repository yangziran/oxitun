#![allow(linker_messages)]
mod service_cmd;
#[cfg(windows)]
mod windows_service;

use clap::{Parser, Subcommand};
use log::{error, info};
use oxitun_core::config::Config;
use oxitun_core::pool::ServerPool;
use oxitun_core::tunnel::TunnelManager;
use std::path::PathBuf;
use std::sync::Arc;

/// 热加载全局串行化锁：防止并发 SIGHUP 交错执行 reload_config
/// （避免配置的读/写与 pool.update_servers 相互穿插）
#[cfg(unix)]
static RELOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// CLI 应用运行参数配置结构体
#[derive(Parser, Debug)]
#[command(author, version, about = "OxiTun CLI - 高性能 SSH 隧道代理客户端", long_about = None)]
struct Args {
    /// 配置文件路径 (Path to configuration file)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// 自动信任首次连接的主机密钥（仅对未知主机生效；
    /// 已记录指纹发生变化时该参数无效，连接仍会被拒绝）
    #[arg(long)]
    accept_new_host_key: bool,

    /// 内部使用：由 Windows SCM 以服务模式启动（service install 注册时附加）
    #[cfg(windows)]
    #[arg(long, hide = true)]
    as_windows_service: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 系统服务管理（launchd / systemd / Windows Service）
    Service {
        #[command(subcommand)]
        action: service_cmd::ServiceAction,
    },
}

/// OxiTun 命令行工具的异步主入口
/// 负责读取配置、构建全局依赖资源、启动底层代理隧道，并监听退出信号以提供优雅停机功能。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志，默认级别为 info
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let args = Args::parse();

    // 子命令：系统服务管理（处理完即退出）
    if let Some(Commands::Service { action }) = args.command {
        if let Err(e) = service_cmd::handle(action) {
            eprintln!("服务操作失败: {:#}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    info!("正在启动 OxiTun CLI...");

    // 1. 加载配置
    if !args.config.exists() {
        error!("未找到配置文件: {}", args.config.display());
        std::process::exit(1);
    }

    let config = Config::load_from_file(&args.config)?;
    config.validate()?;
    info!(
        "已加载配置: 发现 {} 个服务器, {} 个隧道规则",
        config.servers.len(),
        config.tunnels.len()
    );

    // 提前初始化主密钥：配置目录不可用时在此即失败退出（而非运行到加解密时才报错）
    oxitun_core::crypto::get_master_key()?;

    // 2. 初始化核心引擎
    let pool = Arc::new(ServerPool::new(config.servers.clone()));

    // 主机密钥首次确认（TOFU）：
    // - --accept-new-host-key：自动信任新主机（指纹变化场景仍会被 Core 拒绝）
    // - 有 TTY：交互确认
    // - 无 TTY（服务/脚本）：不订阅事件，Core 会明确失败并在日志中给出预置指纹指引
    use std::io::IsTerminal;
    if args.accept_new_host_key {
        let broker = pool.broker();
        let mut sub = broker.subscribe();
        tokio::spawn(async move {
            while let Ok(p) = sub.recv().await {
                log::warn!(
                    "自动信任新主机密钥 {}:{} ({}) {}",
                    p.host,
                    p.port,
                    p.key_type,
                    p.fingerprint
                );
                broker.resolve(&p.host, p.port, true);
            }
        });
    } else if std::io::stdin().is_terminal() {
        let broker = pool.broker();
        let mut sub = broker.subscribe();
        tokio::spawn(async move {
            while let Ok(p) = sub.recv().await {
                eprintln!();
                eprintln!("==========================================");
                eprintln!("首次连接服务器 {}:{}", p.host, p.port);
                eprintln!("密钥类型: {}", p.key_type);
                eprintln!("SHA256 指纹: {}", p.fingerprint);
                eprintln!("请与服务器提供方公布的指纹核对后再信任。");
                eprintln!("==========================================");
                eprint!("信任并继续连接？[y/N] ");
                let mut line = String::new();
                let read = tokio::io::AsyncBufReadExt::read_line(
                    &mut tokio::io::BufReader::new(tokio::io::stdin()),
                    &mut line,
                )
                .await;
                let accept = matches!(read, Ok(_n) if matches!(line.trim().to_lowercase().as_str(), "y" | "yes"));
                broker.resolve(&p.host, p.port, accept);
                if accept {
                    eprintln!("已信任并保存该主机密钥。");
                } else {
                    eprintln!("已拒绝连接。");
                }
            }
        });
    }

    let manager = Arc::new(
        TunnelManager::new(
            pool.clone(),
            config.routing.clone(),
            config.general.chnroute_url.clone(),
        )
        .await,
    );

    // 3. 启动所有隧道
    for tun_cfg in &config.tunnels {
        if let Err(e) = manager.start_tunnel(tun_cfg.clone()).await {
            error!("启动隧道 {} 失败: {}", tun_cfg.name, e);
            std::process::exit(1);
        }
    }

    // 3.4 可选 Prometheus 指标（未配置 metrics_addr 时不启动监听器）
    if let Some(handle) =
        oxitun_core::metrics::maybe_serve(config.general.metrics_addr.as_deref()).await
    {
        manager.add_task(handle).await;
    }

    // 3.5 SIGHUP 事务式热加载（仅 Unix；Windows 不支持该信号）
    #[cfg(unix)]
    {
        let current_config = Arc::new(tokio::sync::RwLock::new(config));
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let pool_h = pool.clone();
        let manager_h = manager.clone();
        let config_h = current_config.clone();
        let path_h = args.config.clone();
        tokio::spawn(async move {
            while sighup.recv().await.is_some() {
                info!("收到 SIGHUP，开始事务式热加载...");
                match reload_config(&path_h, &pool_h, &manager_h, &config_h).await {
                    Ok(_) => info!("热加载完成。"),
                    Err(e) => error!("热加载被拒绝: {:#}，继续运行旧配置", e),
                }
            }
        });
    }

    // 3.6 Windows 服务模式：注册 SCM 控制循环，将 Stop 事件桥接到优雅关闭通道
    #[cfg(windows)]
    if args.as_windows_service {
        info!("以 Windows 服务模式运行，等待 SCM 控制事件...");
        windows_service::install_shutdown_channel();
        std::thread::spawn(|| {
            if let Err(e) = windows_service::dispatch() {
                log::error!("Windows 服务派发失败: {:#}", e);
            }
        });
    }

    info!("OxiTun 正在运行，按 Ctrl+C 停止。");

    // 4. 等待中止信号（Ctrl+C / SIGINT 始终监听；Unix 附加 SIGTERM；
    //    Windows 服务模式下同时桥接 SCM 停止事件），两条路径共用同一优雅关闭逻辑
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(windows)]
    {
        if args.as_windows_service {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = windows_service::wait_for_shutdown() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("收到退出信号，正在优雅关闭...");

    // 5. 优雅清理资源
    manager.stop_all().await;
    info!("已完全关闭。");

    Ok(())
}

/// 事务式热加载（仅 Unix）：
/// 1. 读取并解析新配置，失败则拒绝
/// 2. Config::validate 整批校验，任一错误拒绝，旧配置继续运行
/// 3. 通过后提交：未变化的服务器连接组复用，变化的隧道重启，路由引擎热替换
#[cfg(unix)]
async fn reload_config(
    path: &std::path::Path,
    pool: &Arc<ServerPool>,
    manager: &Arc<TunnelManager>,
    current: &Arc<tokio::sync::RwLock<Config>>,
) -> anyhow::Result<()> {
    // 全局串行化：并发 SIGHUP 依次执行，避免配置读/写与 pool.update_servers 交错
    let _guard = RELOAD_LOCK.lock().await;

    let new_config = Config::load_from_file(path)?;
    new_config.validate()?; // 整批校验，失败即拒绝

    let old_tunnels = current.read().await.tunnels.clone();

    pool.update_servers(new_config.servers.clone()).await;
    manager
        .reload_with_diff(
            &old_tunnels,
            new_config.tunnels.clone(),
            new_config.routing.clone(),
            new_config.general.chnroute_url.clone(),
        )
        .await?;

    *current.write().await = new_config;
    Ok(())
}
