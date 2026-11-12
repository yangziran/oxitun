//! 系统服务管理子命令（launchd / systemd / Windows Service 等，由 service-manager 适配）
//!
//! 注册后由系统服务管理器直接以前台方式运行本二进制（`--config <绝对路径>`），
//! OxiTun 默认行为即持续运行直至收到退出信号，无需额外的 run 包装。

use anyhow::{Context, Result};
use clap::Subcommand;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatus,
    ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use std::ffi::OsString;
use std::path::PathBuf;

const SERVICE_LABEL: &str = "com.oxitun.cli";

#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// 注册为系统服务（开机自启）
    Install {
        /// 配置文件路径（将转换为绝对路径）
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 卸载系统服务
    Uninstall,
    /// 启动服务
    Start,
    /// 停止服务
    Stop,
    /// 重启服务
    Restart,
    /// 查看服务状态
    Status,
}

fn label() -> Result<ServiceLabel> {
    SERVICE_LABEL
        .parse()
        .with_context(|| format!("非法的服务标识: {}", SERVICE_LABEL))
}

fn manager() -> Result<Box<dyn ServiceManager>> {
    <dyn ServiceManager>::native().context("当前平台不支持系统服务管理")
}

pub fn handle(action: ServiceAction) -> Result<()> {
    let mgr = manager()?;
    let label = label()?;

    match action {
        ServiceAction::Install { config } => {
            let abs_config = std::fs::canonicalize(&config)
                .with_context(|| format!("配置文件不存在: {}", config.display()))?;
            let program = std::env::current_exe().context("无法获取当前可执行文件路径")?;
            // 安全检查：服务通常以高权限（root / SYSTEM）运行，
            // 若可执行文件或配置位于普通用户可写的路径，存在被篡改提权的风险。
            // 此处仅打印醒目警告，不强制失败
            warn_writable_path_risk(&program, "可执行文件");
            warn_writable_path_risk(&abs_config, "配置文件");
            // Windows 下附加隐藏参数，使二进制启动时进入 SCM 服务控制循环
            // 而非普通的前台运行（macOS / Linux 的 launchd / systemd 无需区分）
            #[allow(unused_mut)]
            let mut args = vec![
                OsString::from("--config"),
                OsString::from(abs_config.as_os_str()),
            ];
            #[cfg(windows)]
            args.push(OsString::from("--as-windows-service"));
            mgr.install(ServiceInstallCtx {
                label: label.clone(),
                program,
                args,
                contents: None,
                username: None,
                working_directory: None,
                environment: None,
                autostart: true,
                restart_policy: service_manager::RestartPolicy::default(),
            })?;
            println!(
                "服务已注册（标识 {}，配置 {}）。使用 `oxitun-cli service start` 启动。",
                SERVICE_LABEL,
                abs_config.display()
            );
        }
        ServiceAction::Uninstall => {
            mgr.uninstall(ServiceUninstallCtx { label })?;
            println!("服务已卸载。");
        }
        ServiceAction::Start => {
            mgr.start(ServiceStartCtx { label })?;
            println!("服务已启动。");
        }
        ServiceAction::Stop => {
            mgr.stop(ServiceStopCtx { label })?;
            println!("服务已停止。");
        }
        ServiceAction::Restart => {
            // service-manager 无原生 restart，按 stop → start 组合实现。
            // 先查询状态以区分 stop 失败的性质：
            // - 服务正处于运行状态：停止失败属于真实错误，直接中止重启，
            //   避免旧实例未停又拉起新实例（端口占用、双实例并存）
            // - 未运行 / 未安装 / 状态未知：停止失败属可忽略场景，记录警告后继续 start
            let running = matches!(
                mgr.status(ServiceStatusCtx {
                    label: label.clone()
                }),
                Ok(ServiceStatus::Running)
            );
            if let Err(e) = mgr.stop(ServiceStopCtx {
                label: label.clone(),
            }) {
                if running {
                    return Err(e).context("重启前停止运行中的服务失败，已中止重启");
                }
                log::warn!("重启前停止服务失败（服务未运行或未安装，忽略）: {}", e);
                eprintln!("警告: 停止服务失败（服务未运行或未安装，忽略）: {}", e);
            }
            mgr.start(ServiceStartCtx { label })?;
            println!(
                "服务已重启。启动为异步过程，状态可能尚未就绪，\
                 请稍后使用 `oxitun-cli service status` 确认。"
            );
        }
        ServiceAction::Status => {
            // 查询失败时返回 Err（退出码非 0），避免脚本误判服务正常
            let status = mgr
                .status(ServiceStatusCtx { label })
                .context("查询服务状态失败（服务可能未安装）")?;
            println!("服务状态: {:?}", status);
        }
    }
    Ok(())
}

/// 高权限安装场景下的路径安全检查（仅 Unix）：
/// 当前进程以高权限（euid == 0）执行 install 时，服务日后将以 root 运行；
/// 若可执行文件或配置位于普通用户可控制的路径（属主为非 root 用户，
/// 或组/其他用户可写），存在被篡改提权的风险，此时打印醒目安全警告。
/// 非高权限安装不存在提权风险，跳过检查；非 Unix 平台保守跳过
/// （Windows 的 ACL 模型不同，无法用权限位统一判断）
fn warn_writable_path_risk(path: &std::path::Path, desc: &str) {
    #[cfg(unix)]
    {
        // 仅以高权限（root）安装时才需要告警：
        // 服务权限不高于安装者时，路径可被安装者改写属正常预期
        if euid() != 0 {
            return;
        }
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mut cur = Some(path);
        while let Some(p) = cur {
            if let Ok(meta) = std::fs::metadata(p) {
                // 属主为普通用户（该用户可随意改写/替换该路径），
                // 或组/其他用户可写，均视为高风险
                if meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
                    let msg = format!(
                        "安全警告: {desc}路径 {} 位于普通用户可控制的目录；\
                         服务以 root 高权限运行时可能被篡改提权，\
                         建议将{desc}移至仅管理员可写的受保护目录（如 /usr/local、/etc）",
                        p.display()
                    );
                    log::warn!("{}", msg);
                    eprintln!("*** {} ***", msg);
                    return;
                }
            }
            cur = p.parent();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, desc);
    }
}

/// 获取当前进程的有效用户 ID（仅 Unix；直接声明 POSIX geteuid，避免引入额外依赖）
#[cfg(unix)]
fn euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}
