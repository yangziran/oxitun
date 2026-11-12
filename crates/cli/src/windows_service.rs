//! Windows 服务控制循环（仅 Windows 编译）：
//! 通过 windows-service crate 注册 SCM 控制处理器（RegisterServiceCtrlHandler 的封装），
//! 将 `SERVICE_CONTROL_STOP` 等控制事件桥接到主进程的优雅关闭通道，
//! 避免 SCM 停服务时进程被强杀、优雅关闭（manager.stop_all）无法执行。
//!
//! 状态机：
//! - main 尽早调用 [`install_shutdown_channel`] 与 [`dispatch`]，注册后立即上报
//!   StartPending（wait_hint 30s），避免初始化慢时 SCM 看不到任何状态；
//! - 主线程初始化完成调用 [`report_init_success`]，上报 Running；
//!   初始化失败调用 [`report_init_failure`]，上报 Stopped（带 Win32 错误码）；
//! - 收到 Stop / Shutdown 先上报 StopPending（wait_hint 30s），
//!   主线程 manager.stop_all() 完成并调用 [`notify_cleanup_done`] 后再上报 Stopped；
//! - 上报 Stopped 后通过最终 ACK 通知主线程，主线程收到成功 ACK 才正常退出；
//!   清理超时则保持 StopPending、返回失败 ACK，最终由主线程以非零状态退出。
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

/// StartPending / StopPending 的 wait_hint（上报给 SCM 的预计耗时）
const PENDING_WAIT_HINT: Duration = Duration::from_secs(30);
/// StopPending 等待主线程优雅清理完成的超时兜底，避免主线程异常导致服务悬挂
const CLEANUP_WAIT_TIMEOUT: Duration = Duration::from_secs(25);
/// 启动阶段同时轮询初始化结果与 SCM 停止事件的间隔
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// SCM 控制事件 → service_main 的同步停止通道（发送端）
static SHUTDOWN_TX: OnceLock<std_mpsc::Sender<()>> = OnceLock::new();
/// SCM 控制事件 → 主进程异步运行时的停止通知
static SHUTDOWN_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();
/// service_main 侧消费的接收端（仅服务模式下存在）
static SHUTDOWN_RX: OnceLock<Mutex<Option<std_mpsc::Receiver<()>>>> = OnceLock::new();
/// 主线程 → service_main：初始化结果（Ok 上报 Running，Err 上报 Stopped 带错误码）
static INIT_RESULT_TX: OnceLock<std_mpsc::Sender<Result<(), String>>> = OnceLock::new();
/// service_main 侧消费的初始化结果接收端
static INIT_RESULT_RX: OnceLock<Mutex<Option<std_mpsc::Receiver<Result<(), String>>>>> =
    OnceLock::new();
/// 主线程 → service_main：优雅清理完成，可上报 Stopped
static CLEANUP_TX: OnceLock<std_mpsc::Sender<()>> = OnceLock::new();
/// service_main 侧消费的清理完成接收端
static CLEANUP_RX: OnceLock<Mutex<Option<std_mpsc::Receiver<()>>>> = OnceLock::new();
/// service_main → 主线程：最终停止结果（成功表示 Stopped 已完成上报）
static FINAL_ACK_TX: OnceLock<std_mpsc::Sender<Result<(), String>>> = OnceLock::new();
/// 主线程侧消费的最终停止结果接收端
static FINAL_ACK_RX: OnceLock<Mutex<Option<std_mpsc::Receiver<Result<(), String>>>>> =
    OnceLock::new();

/// 初始化各协调通道（以服务方式启动时调用一次，应先于 dispatch）
pub fn install_shutdown_channel() {
    let (tx, rx) = std_mpsc::channel();
    let _ = SHUTDOWN_TX.set(tx);
    let _ = SHUTDOWN_NOTIFY.set(tokio::sync::Notify::new());
    let _ = SHUTDOWN_RX.set(Mutex::new(Some(rx)));

    let (init_tx, init_rx) = std_mpsc::channel();
    let _ = INIT_RESULT_TX.set(init_tx);
    let _ = INIT_RESULT_RX.set(Mutex::new(Some(init_rx)));

    let (cleanup_tx, cleanup_rx) = std_mpsc::channel();
    let _ = CLEANUP_TX.set(cleanup_tx);
    let _ = CLEANUP_RX.set(Mutex::new(Some(cleanup_rx)));

    let (final_ack_tx, final_ack_rx) = std_mpsc::channel();
    let _ = FINAL_ACK_TX.set(final_ack_tx);
    let _ = FINAL_ACK_RX.set(Mutex::new(Some(final_ack_rx)));
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

/// 同时通知 service_main 与主流程进入统一停止流程。
/// 用于 SCM Stop / Shutdown、服务模式下 Ctrl+C，以及 dispatch 失败等异常场景。
pub fn notify_shutdown() {
    if let Some(tx) = SHUTDOWN_TX.get() {
        let _ = tx.send(());
    }
    if let Some(notify) = SHUTDOWN_NOTIFY.get() {
        notify.notify_one();
    }
}

/// 主线程初始化完成：通知 service_main 上报 Running
pub fn report_init_success() {
    if let Some(tx) = INIT_RESULT_TX.get() {
        let _ = tx.send(Ok(()));
    }
}

/// 主线程初始化/运行失败：通知 service_main 上报 Stopped（带 Win32 错误码）
pub fn report_init_failure(msg: String) {
    log::error!("Windows 服务初始化失败: {}", msg);
    if let Some(tx) = INIT_RESULT_TX.get() {
        let _ = tx.send(Err(msg));
    }
}

/// 主线程优雅清理完成：通知 service_main 上报 Stopped
pub fn notify_cleanup_done() {
    if let Some(tx) = CLEANUP_TX.get() {
        let _ = tx.send(());
    }
}

/// service_main 回执最终停止结果；成功 ACK 必须在 Stopped 上报完成后发送
fn send_final_ack(result: Result<(), String>) {
    if let Some(tx) = FINAL_ACK_TX.get() {
        let _ = tx.send(result);
    }
}

/// 是否尚未消费最终 ACK。正常停止路径已等待过 ACK 时，失败统一出口不得重复等待。
pub fn can_wait_for_final_ack() -> bool {
    FINAL_ACK_RX
        .get()
        .and_then(|m| m.lock().ok())
        .is_some_and(|guard| guard.is_some())
}

/// 接收最终 ACK，并将通道/等待错误与 ACK 携带的服务停止结果区分开。
fn recv_final_ack(timeout: Duration) -> Result<Result<(), String>, String> {
    let rx = FINAL_ACK_RX
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take())
        .ok_or_else(|| "Windows 服务最终 ACK 通道不可用".to_string())?;

    match rx.recv_timeout(timeout) {
        Ok(result) => Ok(result),
        Err(std_mpsc::RecvTimeoutError::Timeout) => {
            Err("等待 Windows 服务最终 ACK 超时".to_string())
        }
        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
            Err("Windows 服务控制循环在发送最终 ACK 前退出".to_string())
        }
    }
}

/// 主线程等待 service_main 的最终 ACK，避免状态尚未上报完成进程就退出。
/// 清理超时、控制循环异常或 ACK 等待超时都会返回 Err，使进程以非零状态退出。
pub fn wait_for_final_ack(timeout: Duration) -> Result<(), String> {
    recv_final_ack(timeout)?
}

/// 初始化失败路径只校验最终 ACK 是否到达；Err ACK 是 Stopped(Win32(1)) 的预期回执。
pub fn wait_for_failure_final_ack(timeout: Duration) -> Result<(), String> {
    recv_final_ack(timeout)?;
    Ok(())
}

/// SCM 服务入口（由 define_windows_service! 生成的 FFI 包装调用）：
/// 注册控制处理器、按初始化/停止事件推进状态机
fn service_main_impl(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("Windows 服务控制循环出错: {}", e);
        // 控制循环异常退出时通知主流程停止，避免进程悬挂
        notify_shutdown();
    }
}

fn run_service() -> windows_service::Result<()> {
    let status_handle = service_control_handler::register(SERVICE_NAME, |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // 桥接停止事件：通知 service_main（推进 StopPending → Stopped）
                // 与主进程（优雅关闭）
                notify_shutdown();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    let make_status = |current_state: ServiceState,
                       checkpoint: u32,
                       wait_hint: Duration,
                       exit_code: ServiceExitCode| {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            // 声明同时接受 STOP 与 SHUTDOWN（Shutdown 事件已在处理器中处理）
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code,
            checkpoint,
            wait_hint,
            process_id: None,
        }
    };
    let ok = || ServiceExitCode::Win32(0);

    // 尽早上报 StartPending：主线程仍在初始化（加载配置、启动隧道）
    let mut start_checkpoint = 1_u32;
    status_handle.set_service_status(make_status(
        ServiceState::StartPending,
        start_checkpoint,
        PENDING_WAIT_HINT,
        ok(),
    ))?;

    let init_rx = INIT_RESULT_RX
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take());
    let shutdown_rx = SHUTDOWN_RX
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take());

    // std::sync::mpsc 不支持 select!：启动阶段每 100ms 轮询两个通道。
    // 优先响应 SCM Stop / Shutdown，避免初始化期间收到的停止事件被延迟到 Running 后才处理。
    let mut stop_requested = false;
    let mut init_result = None;
    if let (Some(init_rx), Some(shutdown_rx)) = (init_rx.as_ref(), shutdown_rx.as_ref()) {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                stop_requested = true;
                break;
            }

            match init_rx.try_recv() {
                Ok(result) => {
                    init_result = Some(result);
                    break;
                }
                Err(std_mpsc::TryRecvError::Empty) => {}
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    init_result = Some(Err("主线程初始化结果通道已断开".to_string()));
                    break;
                }
            }

            // 持续刷新 checkpoint 与 wait_hint，让 SCM 能观察到启动进度
            start_checkpoint = start_checkpoint.saturating_add(1);
            status_handle.set_service_status(make_status(
                ServiceState::StartPending,
                start_checkpoint,
                PENDING_WAIT_HINT,
                ok(),
            ))?;
            std::thread::sleep(STARTUP_POLL_INTERVAL);
        }
    }

    if !stop_requested {
        match init_result {
            Some(Ok(())) => {
                status_handle.set_service_status(make_status(
                    ServiceState::Running,
                    0,
                    Duration::ZERO,
                    ok(),
                ))?;
            }
            Some(Err(msg)) => {
                log::error!("服务初始化失败，上报 Stopped: {}", msg);
                status_handle.set_service_status(make_status(
                    ServiceState::Stopped,
                    0,
                    Duration::ZERO,
                    ServiceExitCode::Win32(1),
                ))?;
                send_final_ack(Err(msg));
                return Ok(());
            }
            None => {}
        }

        // 初始化成功后阻塞等待 SCM 停止信号，保持服务处于 Running 状态；
        // 若启动轮询期间事件已入队，这里会立即返回并进入停止流程。
        if let Some(rx) = shutdown_rx {
            let _ = rx.recv();
        }
    }

    // 先上报 StopPending：主线程正在执行优雅清理（manager.stop_all）
    status_handle.set_service_status(make_status(
        ServiceState::StopPending,
        1,
        PENDING_WAIT_HINT,
        ok(),
    ))?;

    // 等待主线程清理完成；只有明确收到完成通知才允许上报成功 Stopped
    let cleanup_rx = CLEANUP_RX
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|mut guard| guard.take());
    let cleanup_result = match cleanup_rx {
        Some(rx) => rx.recv_timeout(CLEANUP_WAIT_TIMEOUT),
        None => Err(std_mpsc::RecvTimeoutError::Disconnected),
    };

    match cleanup_result {
        Ok(()) => {
            // Stop 先于初始化结果到达时，失败通知会先于清理完成通知发送；
            // 此时仍须上报失败退出码，不能按正常 Stop 返回成功。
            let init_failure = match (stop_requested, init_rx.as_ref()) {
                (true, Some(rx)) => match rx.try_recv() {
                    Ok(Err(msg)) => Some(msg),
                    _ => None,
                },
                _ => None,
            };
            if let Some(msg) = &init_failure {
                log::error!("服务初始化失败，上报 Stopped: {}", msg);
            }

            // 先完成 Stopped 上报，再回执主线程，确保主进程不会提前退出
            status_handle.set_service_status(make_status(
                ServiceState::Stopped,
                0,
                Duration::ZERO,
                if init_failure.is_some() {
                    ServiceExitCode::Win32(1)
                } else {
                    ok()
                },
            ))?;
            match init_failure {
                Some(msg) => send_final_ack(Err(msg)),
                None => send_final_ack(Ok(())),
            }
        }
        Err(recv_error) => {
            let msg = match recv_error {
                std_mpsc::RecvTimeoutError::Timeout => format!(
                    "等待主线程清理超过 {} 秒，停止失败",
                    CLEANUP_WAIT_TIMEOUT.as_secs()
                ),
                std_mpsc::RecvTimeoutError::Disconnected => {
                    "主线程清理完成通道已断开，停止失败".to_string()
                }
            };
            log::error!("{}", msg);

            // 超时不伪装成正常 Stopped：更新 StopPending checkpoint，并携带错误码。
            // 失败 ACK 会让主线程返回 Err，最终以非零退出码结束进程。
            status_handle.set_service_status(make_status(
                ServiceState::StopPending,
                2,
                PENDING_WAIT_HINT,
                ServiceExitCode::Win32(1),
            ))?;
            send_final_ack(Err(msg));
        }
    }

    Ok(())
}
