#![allow(linker_messages)]
mod app_menu;
mod logs;
use oxitun_core::config::Config;
use oxitun_core::pool::ServerPool;
use oxitun_core::tunnel::TunnelManager;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Emitter;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_autostart::MacosLauncher;
use tokio::sync::Mutex;

struct AppState {
    config_path: Mutex<PathBuf>,
    config: Mutex<Option<Config>>,
    manager: Mutex<Option<Arc<TunnelManager>>>,
    /// 最近一次启动是否失败（用于托盘错误图标）
    last_error: Mutex<bool>,
    /// 当前连接池的主机密钥确认协调器（随隧道启动而更新）
    broker: Mutex<Option<oxitun_core::host_key::HostKeyBroker>>,
    /// 当前连接池的 known_hosts 存储
    known_hosts: Mutex<Option<Arc<oxitun_core::known_hosts::KnownHostsStore>>>,
    /// 内存日志缓冲（诊断页）
    log_store: Arc<logs::LogStore>,
}

fn get_config_path(app: &AppHandle) -> PathBuf {
    let config_dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    if !config_dir.exists() {
        let _ = std::fs::create_dir_all(&config_dir);
    }
    config_dir.join("config.yaml")
}

// 托盘状态图标：编译期内嵌，运行时按状态切换
const TRAY_ICON_RUNNING: &[u8] = include_bytes!("../icons/tray-running.png");
const TRAY_ICON_STOPPED: &[u8] = include_bytes!("../icons/tray-stopped.png");
const TRAY_ICON_ERROR: &[u8] = include_bytes!("../icons/tray-error.png");

fn tray_icon_image(running: bool, error: bool) -> Option<tauri::image::Image<'static>> {
    let bytes = if error {
        TRAY_ICON_ERROR
    } else if running {
        TRAY_ICON_RUNNING
    } else {
        TRAY_ICON_STOPPED
    };
    // Tauri 2 的 Image 需要解码后的 RGBA 数据
    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    Some(tauri::image::Image::new_owned(
        buf[..info.buffer_size()].to_vec(),
        info.width,
        info.height,
    ))
}

fn update_tray_menu(app: &AppHandle) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app_handle.state::<AppState>();
        let config_guard = state.config.lock().await;
        let is_running = state.manager.lock().await.is_some();
        let has_error = *state.last_error.lock().await;

        let mut builder = MenuBuilder::new(&app_handle);

        // 代理状态
        builder = builder.item(
            &MenuItemBuilder::new(if is_running {
                "状态: 已开启"
            } else {
                "状态: 已关闭"
            })
            .enabled(false)
            .build(&app_handle)
            .unwrap(),
        );
        builder = builder.item(
            &MenuItemBuilder::with_id(
                "toggle",
                if is_running {
                    "关闭代理"
                } else {
                    "开启代理"
                },
            )
            .build(&app_handle)
            .unwrap(),
        );
        builder = builder.separator();

        // 服务器列表
        if let Some(cfg) = config_guard.as_ref() {
            let configured_active = cfg
                .tunnels
                .first()
                .and_then(|t| t.server_names.first())
                .cloned()
                .unwrap_or_else(|| {
                    cfg.servers
                        .first()
                        .map(|s| s.name.clone())
                        .unwrap_or_default()
                });

            let mut server_menu = SubmenuBuilder::new(&app_handle, "服务器");
            for srv in &cfg.servers {
                let prefix = if srv.name == configured_active {
                    "✔ "
                } else {
                    ""
                };
                let text = format!("{}{}", prefix, srv.name);
                let id = format!("srv_{}", srv.name);
                server_menu = server_menu.item(
                    &MenuItemBuilder::with_id(id, text)
                        .build(&app_handle)
                        .unwrap(),
                );
            }
            builder = builder.item(&server_menu.build().unwrap());

            // 路由模式
            let mut mode_menu = SubmenuBuilder::new(&app_handle, "路由模式");
            let modes = [
                ("global", "全局模式"),
                ("whitelist", "白名单模式"),
                ("blacklist", "黑名单模式"),
                ("direct", "直连模式"),
            ];
            for (id, name) in modes.iter() {
                let prefix = if format!("{:?}", cfg.routing.mode).to_lowercase() == *id {
                    "✔ "
                } else {
                    ""
                };
                let text = format!("{}{}", prefix, name);
                let mode_id = format!("mode_{}", id);
                mode_menu = mode_menu.item(
                    &MenuItemBuilder::with_id(mode_id, text)
                        .build(&app_handle)
                        .unwrap(),
                );
            }
            builder = builder.item(&mode_menu.build().unwrap());
        }

        builder = builder.separator();
        builder = builder.item(
            &MenuItemBuilder::with_id("preferences", "偏好设置...")
                .build(&app_handle)
                .unwrap(),
        );
        builder = builder.separator();
        builder = builder.item(
            &MenuItemBuilder::with_id("quit", "退出 OxiTun")
                .build(&app_handle)
                .unwrap(),
        );

        if let Some(tray) = app_handle.tray_by_id("main") {
            // 托盘 tooltip 与图标随运行状态联动
            let _ = tray.set_tooltip(Some(if is_running {
                "OxiTun - 已开启"
            } else {
                "OxiTun - 已关闭"
            }));
            if let Some(icon) = tray_icon_image(is_running, has_error) {
                let _ = tray.set_icon(Some(icon));
            }
            let _ = tray.set_menu(Some(builder.build().unwrap()));
        }
    });
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    let config_guard = state.config.lock().await;
    config_guard
        .clone()
        .ok_or_else(|| "Config not loaded".to_string())
}

#[tauri::command]
async fn save_config(
    state: State<'_, AppState>,
    app: AppHandle,
    new_config: Config,
) -> Result<(), String> {
    new_config.validate().map_err(|e| e.to_string())?;
    let path = state.config_path.lock().await.clone();
    new_config.save_to_file(&path).map_err(|e| e.to_string())?;

    let mut config_guard = state.config.lock().await;
    *config_guard = Some(new_config.clone());
    drop(config_guard);

    let was_running = state.manager.lock().await.is_some();
    if was_running {
        stop_tunnels_internal(&state, &app).await;
        let _ = start_tunnels_internal(&state, &app).await;
    }

    update_tray_menu(&app);
    let _ = app.emit("state-changed", "");
    Ok(())
}

async fn start_tunnels_internal(state: &AppState, app: &AppHandle) -> Result<(), String> {
    let result = start_tunnels_inner(state, app).await;
    *state.last_error.lock().await = result.is_err();
    update_tray_menu(app);
    result
}

async fn start_tunnels_inner(state: &AppState, app: &AppHandle) -> Result<(), String> {
    let config_guard = state.config.lock().await;
    let config = config_guard
        .as_ref()
        .ok_or_else(|| "Config not loaded".to_string())?
        .clone();
    drop(config_guard);

    if config.servers.is_empty() {
        return Err("No servers available".to_string());
    }

    let mut actual_config = config.clone();
    let mut modified = false;
    if actual_config.tunnels.is_empty() {
        actual_config
            .tunnels
            .push(oxitun_core::config::TunnelConfig {
                name: "SOCKS5 代理".to_string(),
                server_names: vec![actual_config.servers[0].name.clone()],
                tunnel_type: oxitun_core::config::TunnelType::Dynamic,
                port: 1080,
                remote_addr: None,
                share_on_lan: false,
                strategy: Default::default(),
            });
        modified = true;
    } else if actual_config.tunnels[0].server_names.is_empty() {
        actual_config.tunnels[0].server_names = vec![actual_config.servers[0].name.clone()];
        modified = true;
    }

    if modified {
        let path = state.config_path.lock().await.clone();
        actual_config
            .save_to_file(&path)
            .map_err(|e| e.to_string())?;
        let mut cg = state.config.lock().await;
        *cg = Some(actual_config.clone());
    }

    let pool = Arc::new(ServerPool::new(actual_config.servers.clone()));

    // 注册主机密钥确认通道：Broker 事件 → 前端弹窗
    let broker = pool.broker();
    *state.broker.lock().await = Some(broker.clone());
    *state.known_hosts.lock().await = Some(pool.known_hosts());

    let manager = Arc::new(
        TunnelManager::new(
            pool.clone(),
            actual_config.routing.clone(),
            actual_config.general.chnroute_url.clone(),
        )
        .await,
    );

    {
        let mut sub = broker.subscribe();
        let app_clone = app.clone();
        let handle = tokio::spawn(async move {
            while let Ok(pending) = sub.recv().await {
                // 自动连接触发确认时主动显示窗口
                if let Some(window) = app_clone.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                let _ = app_clone.emit("host-key-verify", pending);
            }
        });
        // 监听任务随隧道管理器生命周期回收
        manager.add_task(handle).await;
    }

    // 路由表自动更新任务
    let update_interval = actual_config.general.chnroute_update_interval_hours;
    let url = actual_config.general.chnroute_url.clone();
    if update_interval > 0.0 {
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                (update_interval * 3600.0) as u64,
            ));
            interval.tick().await; // 忽略首次立即执行的触发
            loop {
                interval.tick().await;
                log::info!("Auto-updating chnroutes...");
                if let Ok(resp) = reqwest::get(&url).await {
                    if let Ok(text) = resp.text().await {
                        let cache_dir = dirs::data_dir()
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                            .join("OxiTun");
                        let _ = tokio::fs::create_dir_all(&cache_dir).await;
                        let _ = tokio::fs::write(cache_dir.join("chnroutes.txt"), text).await;
                    }
                }
            }
        });
        manager.add_task(handle).await;
    }

    // 可选 Prometheus 指标（未配置 metrics_addr 时不启动监听器）
    if let Some(handle) =
        oxitun_core::metrics::maybe_serve(actual_config.general.metrics_addr.as_deref()).await
    {
        manager.add_task(handle).await;
    }

    // 连接前检查
    for tun_cfg in &actual_config.tunnels {
        let mut any_success = false;
        let mut last_err = String::new();
        for server_name in &tun_cfg.server_names {
            let timeout_secs = config
                .servers
                .iter()
                .find(|s| &s.name == server_name)
                .map(|s| s.timeout_seconds)
                .unwrap_or(15) as u64;
            // 网络失败在 timeout_seconds 内返回；挂起只可能发生在主机密钥确认（最长 300s）
            let fut = pool.get_connection(server_name);
            match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs.max(305)), fut)
                .await
            {
                Ok(Ok(_)) => {
                    any_success = true;
                    break;
                }
                Ok(Err(e)) => {
                    last_err = format!("无法连接到 {}: {}", server_name, e);
                }
                Err(_) => {
                    last_err = format!("连接到 {} 超时 ({}秒)", server_name, timeout_secs);
                }
            }
        }
        if !any_success && !tun_cfg.server_names.is_empty() {
            return Err(last_err);
        }
    }

    for tun_cfg in &actual_config.tunnels {
        if let Err(e) = manager.start_tunnel(tun_cfg.clone()).await {
            return Err(e.to_string());
        }
    }

    let mut state_manager = state.manager.lock().await;
    *state_manager = Some(manager);

    // 根据配置应用系统代理
    let mut socks_port = 1080;
    for t in &actual_config.tunnels {
        if matches!(t.tunnel_type, oxitun_core::config::TunnelType::Dynamic) {
            socks_port = t.port;
            break;
        }
    }
    // 仅当存在 DNS 隧道时，macOS 才把系统 DNS 指向本地 127.0.0.1，避免误断系统解析
    let has_dns_tunnel = actual_config.tunnels.iter().any(|t| {
        matches!(
            t.tunnel_type,
            oxitun_core::config::TunnelType::Dns
                | oxitun_core::config::TunnelType::DnsDot
                | oxitun_core::config::TunnelType::DnsDoh
        )
    });
    let _ = oxitun_core::sysproxy::set_system_proxy_ex(
        actual_config.general.auto_set_system_proxy,
        "127.0.0.1",
        socks_port,
        has_dns_tunnel,
    );

    let _ = app.emit("state-changed", "");
    Ok(())
}

async fn stop_tunnels_internal(state: &AppState, app: &AppHandle) {
    let mut state_manager = state.manager.lock().await;
    if let Some(manager) = state_manager.take() {
        manager.stop_all().await;
    }

    // 停止时必定关闭系统代理，防止系统无网
    let port = state
        .config
        .lock()
        .await
        .as_ref()
        .and_then(|c| c.tunnels.first())
        .map(|t| t.port)
        .unwrap_or(1080);
    let _ = oxitun_core::sysproxy::set_system_proxy(false, "127.0.0.1", port);

    update_tray_menu(app);
    let _ = app.emit("state-changed", "");
}

#[tauri::command]
async fn start_tunnels(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    start_tunnels_internal(&state, &app).await
}

#[tauri::command]
async fn stop_tunnels(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    stop_tunnels_internal(&state, &app).await;
    Ok(())
}

#[tauri::command]
async fn test_ssh_connection(
    state: State<'_, AppState>,
    app: AppHandle,
    server_name: String,
) -> Result<String, String> {
    let config_guard = state.config.lock().await;
    let config = config_guard
        .as_ref()
        .ok_or_else(|| "Config not loaded".to_string())?
        .clone();
    drop(config_guard);

    let server_config = config
        .servers
        .iter()
        .find(|s| s.name == server_name)
        .cloned()
        .ok_or_else(|| format!("Server {} not found", server_name))?;

    let pool = std::sync::Arc::new(oxitun_core::pool::ServerPool::new(vec![server_config]));

    // 与主流程共用同一套 TOFU：测试连接遇到未知主机密钥同样弹窗确认
    let broker = pool.broker();
    *state.broker.lock().await = Some(broker.clone());
    let mut sub = broker.subscribe();
    let app_clone = app.clone();
    let listener = tokio::spawn(async move {
        while let Ok(pending) = sub.recv().await {
            if let Some(window) = app_clone.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
            let _ = app_clone.emit("host-key-verify", pending);
        }
    });

    let timeout_secs = server_config_timeout(&config, &server_name);
    // 用户确认最长 300 秒，这里放宽到确认超时之外
    let fut = pool.get_connection(&server_name);
    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.max(305)),
        fut,
    )
    .await
    {
        Ok(Ok(_)) => Ok("连接测试成功！".to_string()),
        Ok(Err(e)) => Err(format!("连接失败: {}", e)),
        Err(_) => Err(format!("连接超时 ({}秒)", timeout_secs)),
    };
    listener.abort();
    result
}

fn server_config_timeout(config: &Config, server_name: &str) -> u64 {
    config
        .servers
        .iter()
        .find(|s| s.name == server_name)
        .map(|s| s.timeout_seconds)
        .unwrap_or(15) as u64
}

#[tauri::command]
async fn get_running_state(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.manager.lock().await.is_some())
}

/// 用户决策待确认的主机密钥：accept=true 信任并持久化，false 拒绝
#[tauri::command]
async fn resolve_host_key(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    accept: bool,
) -> Result<(), String> {
    let broker = state
        .broker
        .lock()
        .await
        .clone()
        .ok_or("当前没有运行中的连接")?;
    if broker.resolve(&host, port, accept) {
        Ok(())
    } else {
        Err("主机密钥确认已过期，请重新连接".to_string())
    }
}

/// 补拉当前所有待确认的主机密钥（窗口刚打开时事件可能已发出）
#[tauri::command]
async fn get_pending_host_keys(
    state: State<'_, AppState>,
) -> Result<Vec<oxitun_core::host_key::PendingHostKey>, String> {
    let broker = state.broker.lock().await.clone();
    Ok(broker.map(|b| b.pending_list()).unwrap_or_default())
}

/// 清除某主机的信任记录（指纹变化后由用户显式确认清除，绝不自动覆盖）
#[tauri::command]
async fn remove_known_host(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<(), String> {
    let store = state
        .known_hosts
        .lock()
        .await
        .clone()
        .ok_or("known_hosts 未初始化")?;
    store.remove(&host, port).map_err(|e| e.to_string())
}

/// 诊断页：获取内存日志
#[tauri::command]
async fn get_logs(state: State<'_, AppState>) -> Result<Vec<logs::LogEntry>, String> {
    Ok(state.log_store.snapshot())
}

/// 诊断页：清空日志
#[tauri::command]
async fn clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    state.log_store.clear();
    Ok(())
}

/// 诊断页：运行指标快照（来自全局计数器）
#[derive(serde::Serialize)]
struct MetricsSnapshot {
    active_connections: i64,
    bytes_tx: u64,
    bytes_rx: u64,
    ssh_pool_rebuilds: u64,
    ssh_reconnects: u64,
}

#[tauri::command]
async fn get_metrics() -> Result<MetricsSnapshot, String> {
    use std::sync::atomic::Ordering;
    let m = &oxitun_core::metrics::METRICS;
    Ok(MetricsSnapshot {
        active_connections: m.active_connections.load(Ordering::Relaxed),
        bytes_tx: m.bytes_tx.load(Ordering::Relaxed),
        bytes_rx: m.bytes_rx.load(Ordering::Relaxed),
        ssh_pool_rebuilds: m.ssh_pool_rebuilds.load(Ordering::Relaxed),
        ssh_reconnects: m.ssh_reconnects.load(Ordering::Relaxed),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 日志同时输出 stderr 与内存缓冲（诊断页）
    let log_store = Arc::new(logs::LogStore::new());
    logs::TeeLogger::new(log_store.clone()).init();
    let log_store_setup = log_store.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = app
                .get_webview_window("main")
                .expect("no main window")
                .set_focus();
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Regular);

            let app_handle = app.handle().clone();

            if let Ok(app_menu) = app_menu::create_app_menu(&app_handle) {
                let _ = app.set_menu(app_menu);
                app.on_menu_event(|app_handle, event| {
                    if event.id() == "preferences" {
                        if let Some(window) = app_handle.get_webview_window("main") {
                            #[cfg(target_os = "macos")]
                            {
                                let _ = app_handle
                                    .set_activation_policy(tauri::ActivationPolicy::Regular);
                                let _ = app_handle.show();
                            }
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                });
            }

            let config_path = get_config_path(&app_handle);

            let initial_config = if config_path.exists() {
                Config::load_from_file(&config_path)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            } else {
                Config {
                    general: Default::default(),
                    servers: vec![],
                    tunnels: vec![],
                    routing: Default::default(),
                }
            };

            app.manage(AppState {
                config_path: Mutex::new(config_path),
                config: Mutex::new(Some(initial_config)),
                manager: Mutex::new(None),
                last_error: Mutex::new(false),
                broker: Mutex::new(None),
                known_hosts: Mutex::new(None),
                log_store: log_store_setup.clone(),
            });

            // 初始为停止状态图标；update_tray_menu 会在状态变化时切换
            let initial_icon =
                tray_icon_image(false, false).or_else(|| app.default_window_icon().cloned());

            let mut tray_builder = TrayIconBuilder::with_id("main");
            if let Some(icon) = initial_icon {
                tray_builder = tray_builder.icon(icon);
            }
            let _tray = tray_builder
                .on_menu_event(|app, event| {
                    let app_handle = app.clone();
                    let event_id = event.id.clone();
                    tauri::async_runtime::spawn(async move {
                        let state = app_handle.state::<AppState>();
                        match event_id.as_ref() {
                            "quit" => {
                                stop_tunnels_internal(&state, &app_handle).await;
                                app_handle.exit(0);
                            }
                            "preferences" => {
                                if let Some(window) = app_handle.get_webview_window("main") {
                                    #[cfg(target_os = "macos")]
                                    {
                                        let _ = app_handle.set_activation_policy(
                                            tauri::ActivationPolicy::Regular,
                                        );
                                        let _ = app_handle.show();
                                    }
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                    let w = window.clone();
                                    tauri::async_runtime::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_millis(50))
                                            .await;
                                        let _ = w.set_focus();
                                    });
                                }
                            }
                            "toggle" => {
                                let is_running = state.manager.lock().await.is_some();
                                if is_running {
                                    stop_tunnels_internal(&state, &app_handle).await;
                                } else {
                                    let _ = start_tunnels_internal(&state, &app_handle).await;
                                }
                            }
                            id if id.starts_with("mode_") => {
                                let mode_str = id.replace("mode_", "");
                                let mode = match mode_str.as_str() {
                                    "whitelist" => oxitun_core::config::RouteMode::Whitelist,
                                    "blacklist" => oxitun_core::config::RouteMode::Blacklist,
                                    "direct" => oxitun_core::config::RouteMode::Direct,
                                    _ => oxitun_core::config::RouteMode::Global,
                                };
                                let mut config_guard = state.config.lock().await;
                                if let Some(cfg) = config_guard.as_mut() {
                                    cfg.routing.mode = mode;
                                    let path = state.config_path.lock().await.clone();
                                    if let Err(e) = cfg.save_to_file(&path) {
                                        let message = format!("保存配置失败: {e:#}");
                                        log::error!("{}", message);
                                        let _ = app_handle.emit("config-save-error", message);
                                        return;
                                    }
                                }
                                drop(config_guard);

                                let was_running = state.manager.lock().await.is_some();
                                if was_running {
                                    stop_tunnels_internal(&state, &app_handle).await;
                                    let _ = start_tunnels_internal(&state, &app_handle).await;
                                }

                                update_tray_menu(&app_handle);
                                let _ = app_handle.emit("state-changed", "");
                            }
                            id if id.starts_with("srv_") => {
                                let srv = id.replace("srv_", "");
                                let mut config_guard = state.config.lock().await;
                                if let Some(cfg) = config_guard.as_mut() {
                                    if cfg.tunnels.is_empty() {
                                        cfg.tunnels.push(oxitun_core::config::TunnelConfig {
                                            name: "SOCKS5 代理".to_string(),
                                            server_names: vec![srv.clone()],
                                            tunnel_type: oxitun_core::config::TunnelType::Dynamic,
                                            port: 1080,
                                            remote_addr: None,
                                            share_on_lan: false,
                                            strategy: Default::default(),
                                        });
                                    } else {
                                        cfg.tunnels[0].server_names = vec![srv.clone()];
                                    }
                                    let path = state.config_path.lock().await.clone();
                                    if let Err(e) = cfg.save_to_file(&path) {
                                        let message = format!("保存配置失败: {e:#}");
                                        log::error!("{}", message);
                                        let _ = app_handle.emit("config-save-error", message);
                                        return;
                                    }
                                }
                                drop(config_guard);

                                let is_running = state.manager.lock().await.is_some();
                                if is_running {
                                    stop_tunnels_internal(&state, &app_handle).await;
                                    let _ = start_tunnels_internal(&state, &app_handle).await;
                                } else {
                                    update_tray_menu(&app_handle);
                                }
                                let _ = app_handle.emit("state-changed", "");
                            }
                            _ => {}
                        }
                    });
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            #[cfg(target_os = "macos")]
                            let _ = app.show();
                            let _ = window.show();
                            let _ = window.set_focus();
                            let w = window.clone();
                            tauri::async_runtime::spawn(async move {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                let _ = w.set_focus();
                            });
                        }
                    }
                })
                .build(app)?;

            update_tray_menu(&app_handle);
            let app_handle_clone = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle_clone.state::<AppState>();
                let auto_connect = {
                    let config_guard = state.config.lock().await;
                    config_guard
                        .as_ref()
                        .map(|c| c.general.auto_connect)
                        .unwrap_or(false)
                };
                if auto_connect {
                    let _ = start_tunnels_internal(&state, &app_handle_clone).await;
                }
            });
            if let Some(window) = app.get_webview_window("main") {
                let window_clone = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        window_clone.hide().unwrap();
                        #[cfg(target_os = "macos")]
                        let _ = window_clone
                            .app_handle()
                            .set_activation_policy(tauri::ActivationPolicy::Accessory);
                        api.prevent_close();
                    }
                });
            }

            // 原生退出清理在 build() 的 RunEvent 回调中注册（见下方 .build(app, ...) 处）。

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            test_ssh_connection,
            get_config,
            save_config,
            start_tunnels,
            stop_tunnels,
            get_running_state,
            resolve_host_key,
            get_pending_host_keys,
            remove_known_host,
            get_logs,
            clear_logs,
            get_metrics
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // 原生退出（Cmd+Q / 菜单"退出 OxiTun"）也走清理：还原系统代理/DNS、停止隧道。
            // 同步等待清理完成，避免进程在异步清理结束前退出而残留系统代理。
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let state = app_handle.state::<AppState>();
                let app_handle_cleanup = app_handle.clone();
                tauri::async_runtime::block_on(async move {
                    stop_tunnels_internal(&state, &app_handle_cleanup).await;
                });
            }
        });
}
