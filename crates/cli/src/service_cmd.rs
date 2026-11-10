//! 系统服务管理子命令（launchd / systemd / Windows Service 等，由 service-manager 适配）
//!
//! 注册后由系统服务管理器直接以前台方式运行本二进制（`--config <绝对路径>`），
//! OxiTun 默认行为即持续运行直至收到退出信号，无需额外的 run 包装。

use anyhow::{Context, Result};
use clap::Subcommand;
use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceManager, ServiceStartCtx, ServiceStatusCtx,
    ServiceStopCtx, ServiceUninstallCtx,
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
            // service-manager 无原生命令，按 stop → start 组合实现
            let _ = mgr.stop(ServiceStopCtx {
                label: label.clone(),
            });
            mgr.start(ServiceStartCtx { label })?;
            println!("服务已重启。");
        }
        ServiceAction::Status => match mgr.status(ServiceStatusCtx { label }) {
            Ok(status) => println!("服务状态: {:?}", status),
            Err(e) => println!("查询状态失败（服务可能未安装）: {}", e),
        },
    }
    Ok(())
}
