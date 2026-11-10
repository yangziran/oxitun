//! Windows 服务控制循环（仅 Windows 编译）：
//! 通过 windows-service crate 注册 SCM 控制处理器（RegisterServiceCtrlHandler 的封装），
//! 将 `SERVICE_CONTROL_STOP` 等控制事件桥接到主进程的优雅关闭通道，
//! 避免 SCM 停服务时进程被强杀、优雅关闭（manager.stop_all）无法执行。
//!
//! 触发方式：service install 注册的服务带隐藏参数 `--as-windows-service`，
//! main 检测到该参数后调用 [`install_shutdown_channel`] 与 [`dispatch`] 进入本模块。

use std::ffi::OsString;
use std::sync::mpsc as std_mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

define_windows_service!(ffi_service_main, service_main_impl);

/// SCM 服务名，与 service_cmd 注册的服务标识保持一致
const SERVICE_NAME: &str = "com.oxitun.cli";

/// SCM 控制事件 → service_main 的同步停止通道（发送端）
static SHUTDOWN_TX: OnceLock<std_mpsc::Sender<()>> = OnceLock::new();
/// SCM 控制事件 → 主进程异步运行时的停止通知
static SHUTDOWN_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();
/// service_main 侧消费的接收端（仅服务模式下存在）
static SHUTDOWN_RX: OnceLock<Mutex<Option<std_mpsc::Receiver<()>>>> = OnceLock::new();

/// 初始化停止信号通道（以服务方式启动时调用一次）
pub fn install_shutdown_channel() {
    let (tx, rx) = std_mpsc::channel();
    let _ = SHUTDOWN_TX.set(tx);
    let _ = SHUTDOWN_NOTIFY.set(tokio::sync::Notify::new());
    let _ = SHUTDOWN_RX.set(Mutex::new(Some(rx)));
}

/// 阻塞进入 SCM 服务派发循环（应在独立线程中调用，直至服务停止才返回）
pub fn dispatch() -> anyhow::Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

/// 等待 SCM 停止事件（异步桥接，可在 tokio::select! 中与 ctrl_c 一起等待）
pub async fn wait_for_shutdown() {
    if let Some(notify) = SHUTDOWN_NOTIFY.get() {
        notify.notified().await;
    }
}

/// SCM 服务入口（由 define_windows_service! 生成的 FFI 包装调用）：
/// 注册控制处理器、上报 Running 状态，随后阻塞直至收到 Stop
fn service_main_impl(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("Windows 服务控制循环出错: {}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    let status_handle = service_control_handler::register(SERVICE_NAME, |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // 桥接停止事件：通知 service_main（上报 Stopped 状态）与主进程（优雅关闭）
                if let Some(tx) = SHUTDOWN_TX.get() {
                    let _ = tx.send(());
                }
                if let Some(notify) = SHUTDOWN_NOTIFY.get() {
                    notify.notify_one();
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    let make_status = |current_state: ServiceState| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    status_handle.set_service_status(make_status(ServiceState::Running))?;

    // 阻塞等待 SCM 停止信号（由控制处理器发送），保持服务处于 Running 状态
    let rx = SHUTDOWN_RX
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take());
    if let Some(rx) = rx {
        let _ = rx.recv();
    }

    // 上报 Stopped 状态，控制权交还 SCM 派发线程
    status_handle.set_service_status(make_status(ServiceState::Stopped))?;

    Ok(())
}
