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
use tokio::sync::broadcast::error::RecvError;

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

    // Windows 服务模式：尽早进入 SCM 派发循环（应先于耗时的初始化），
    // 使初始化期间 SCM 能看到 StartPending 状态，而非长时间无任何状态上报
    #[cfg(windows)]
    let as_windows_service = args.as_windows_service;
    #[cfg(windows)]
    if as_windows_service {
        windows_service::install_shutdown_channel();
        std::thread::spawn(|| {
            if let Err(e) = windows_service::dispatch() {
                error!("Windows 服务派发失败: {:#}", e);
                // 派发失败时通知主流程退出，避免进程悬挂在不受 SCM 控制的状态
                windows_service::notify_shutdown();
            }
        });
    }

    let result = run(args).await;

    // Windows 服务模式：初始化/运行失败时向 SCM 上报 Stopped（带 Win32 错误码）。
    // 必须等待最终 ACK，确保 service_main 完成状态上报后进程才退出。
    #[cfg(windows)]
    if as_windows_service {
        if let Err(e) = &result {
            // 正常停止路径已消费最终 ACK 时，不重复通知初始化失败或等待 ACK。
            if windows_service::can_wait_for_final_ack() {
                windows_service::report_init_failure(format!("{:#}", e));
                // 若 Stop 先于初始化失败到达，service_main 正在等待清理完成通知。
                windows_service::notify_cleanup_done();
                if let Err(ack_error) =
                    windows_service::wait_for_failure_final_ack(std::time::Duration::from_secs(5))
                {
                    // result 本身为 Err，记录收尾异常后仍会以非零状态退出。
                    error!("等待 Windows 服务初始化失败最终 ACK 失败: {}", ack_error);
                }
            }
        }
    }

    result
}

/// 代理主流程：加载配置、构建依赖、启动隧道并等待退出信号。
/// 任何失败统一返回 Err，由 main 负责收尾（Windows 服务模式下向 SCM 上报失败状态）。
async fn run(args: Args) -> anyhow::Result<()> {
    info!("正在启动 OxiTun CLI...");

    // 1. 加载配置
    if !args.config.exists() {
        error!("未找到配置文件: {}", args.config.display());
        anyhow::bail!("未找到配置文件: {}", args.config.display());
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

    // 2. 初始化核心引擎。
    // known_hosts 打开失败（如文件损坏）在此明确失败退出，绝不静默降级：
    // 错误信息中已包含文件路径与修复/删除指引
    let pool = Arc::new(ServerPool::new(config.servers.clone())?);

    // 主机密钥首次确认（TOFU）：
    // - --accept-new-host-key：自动信任新主机（指纹变化场景仍会被 Core 拒绝）
    // - 有 TTY：交互确认
    // - 无 TTY（服务/脚本）：不订阅事件，Core 会明确失败并在日志中给出预置指纹指引
    use std::io::IsTerminal;
    if args.accept_new_host_key {
        let broker = pool.broker();
        let mut sub = broker.subscribe();
        tokio::spawn(async move {
            loop {
                let pending_batch = match sub.recv().await {
                    Ok(pending) => vec![pending],
                    Err(RecvError::Lagged(skipped)) => {
                        // 广播溢出不会关闭接收器；补拉遗漏请求后继续自动信任。
                        log::warn!(
                            "主机密钥确认事件通道滞后 {} 条，正在补拉待确认请求",
                            skipped
                        );
                        broker.pending_list()
                    }
                    Err(RecvError::Closed) => break,
                };
                for p in pending_batch {
                    log::warn!(
                        "自动信任新主机密钥 {}:{} ({}) {}",
                        p.host,
                        p.port,
                        p.key_type,
                        p.fingerprint
                    );
                    // 决策必须携带本次事件的 request_id：同一主机旧请求超时后，
                    // 其 request_id 已失效，不会误批准后续的新请求
                    broker.resolve_by_id(&p.request_id, true);
                }
            }
        });
    } else if std::io::stdin().is_terminal() {
        let broker = pool.broker();
        let mut sub = broker.subscribe();
        tokio::spawn(async move {
            loop {
                let pending_batch = match sub.recv().await {
                    Ok(pending) => vec![pending],
                    Err(RecvError::Lagged(skipped)) => {
                        // 广播溢出后逐个补拉并交互确认，不能退出监听而遗留 pending。
                        log::warn!(
                            "主机密钥确认事件通道滞后 {} 条，正在补拉待确认请求",
                            skipped
                        );
                        broker.pending_list()
                    }
                    Err(RecvError::Closed) => break,
                };
                for p in pending_batch {
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
                    // 决策必须携带本次事件的 request_id，避免 A 请求超时后旧交互误批准 B 请求
                    broker.resolve_by_id(&p.request_id, accept);
                    if accept {
                        eprintln!("已信任并保存该主机密钥。");
                    } else {
                        eprintln!("已拒绝连接。");
                    }
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
            // 返回错误前停止已启动的隧道，避免后台任务悬挂、进程残留
            manager.stop_all().await;
            return Err(e);
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
                    // reload_with_diff 失败会返回 Err：隧道层已回滚，
                    // 基线已对齐实际运行快照，下次 SIGHUP 基于真实运行状态继续收敛
                    Err(e) => error!("热加载被拒绝: {:#}，配置基线已对齐当前实际运行状态", e),
                }
            }
        });
    }

    // 3.6 Windows 服务模式：初始化完成，通知 SCM 控制循环上报 Running
    // （dispatch 已在 main 中尽早启动，初始化期间 SCM 侧呈现 StartPending）
    #[cfg(windows)]
    if args.as_windows_service {
        info!("以 Windows 服务模式运行，初始化完成，等待 SCM 控制事件...");
        windows_service::report_init_success();
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
                _ = tokio::signal::ctrl_c() => {
                    // Ctrl+C 也必须唤醒 service_main，使其进入 StopPending → Stopped 流程
                    windows_service::notify_shutdown();
                },
                _ = windows_service::wait_for_shutdown() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("收到退出信号，正在优雅关闭...");

    // 5. 优雅清理资源
    manager.stop_all().await;
    // Windows 服务模式：通知 SCM 控制循环上报 Stopped，并等待最终 ACK。
    // 上报完成前不能返回，否则主进程可能先于 Stopped 状态提交而退出。
    #[cfg(windows)]
    if args.as_windows_service {
        windows_service::notify_cleanup_done();
        if let Err(e) = windows_service::wait_for_final_ack(std::time::Duration::from_secs(5)) {
            error!("Windows 服务停止失败: {}", e);
            // 将错误传递到 main 的 Result，确保清理超时等异常以非零状态退出
            return Err(anyhow::anyhow!(e));
        }
    }
    info!("已完全关闭。");

    Ok(())
}

/// 事务式热加载（仅 Unix）：
/// 1. 读取并解析新配置，失败则拒绝
/// 2. Config::validate 整批校验，任一错误拒绝，旧配置继续运行
/// 3. 通过后提交：未变化的服务器连接组复用，变化的隧道重启，路由引擎热替换
/// 4. 任一步骤失败均返回 Err：隧道层已向旧基线回滚（恢复已删除隧道、停止已新增隧道），
///    但运行状态可能与旧配置文件不一致，故把基线推进为「实际生效配置」
///    （servers/routing 取新配置、general 保留旧字段、tunnels 取实际运行快照），
///    保证下次 SIGHUP 的 diff 以真实运行状态为准，能正确识别并收敛差异
///
/// 注意：general 段字段（metrics_addr、chnroute_url 等）不参与热加载，
/// 变更后需重启进程才能生效（此处仅给出警告提示）
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

    let (old_tunnels, old_general) = {
        let guard = current.read().await;
        (guard.tunnels.clone(), guard.general.clone())
    };

    // general 段字段热加载不生效：检测到变更时提示需要重启进程
    if old_general.metrics_addr != new_config.general.metrics_addr {
        log::warn!("热加载检测到 general.metrics_addr 变更，该字段需重启进程后生效");
    }
    if old_general.chnroute_url != new_config.general.chnroute_url {
        log::warn!("热加载检测到 general.chnroute_url 变更，该字段需重启进程后生效");
    }
    if (old_general.chnroute_update_interval_hours
        - new_config.general.chnroute_update_interval_hours)
        .abs()
        > f32::EPSILON
    {
        log::warn!(
            "热加载检测到 general.chnroute_update_interval_hours 变更，该字段需重启进程后生效"
        );
    }

    pool.update_servers(new_config.servers.clone()).await;
    if let Err(e) = manager
        .reload_with_diff(
            &old_tunnels,
            new_config.tunnels.clone(),
            new_config.routing.clone(),
            // chnroute_url 热加载不生效（见上方警告），沿用旧值保持一致
            old_general.chnroute_url.clone(),
        )
        .await
    {
        // 热加载部分生效：基线推进为「实际生效配置」——
        // servers 用已提交的连接池配置、routing 用新配置、
        // general 保留旧字段（不参与热加载），tunnels 用管理器实际运行快照，
        // 使下一次 diff 以真实运行状态为旧基线，能正确识别并收敛差异。
        // 错误信息中已注明「热加载未完全生效，以实际运行配置为准」
        let mut baseline = new_config;
        baseline.general = old_general;
        baseline.tunnels = manager.tunnel_configs_snapshot().await;
        *current.write().await = baseline;
        return Err(e);
    }

    // 全部提交成功后推进实际运行基线：general 未热生效，必须继续保留旧值，
    // 避免文件中的新 chnroute_url 等字段在下一次 SIGHUP 时被误当作已生效配置。
    let mut baseline = new_config;
    baseline.general = old_general;
    *current.write().await = baseline;
    Ok(())
}
