#![allow(linker_messages)]
mod app_menu;
use tauri::Emitter;
use oxitun_core::config::Config;
use oxitun_core::pool::ServerPool;
use oxitun_core::tunnel::TunnelManager;
use std::sync::Arc;
use tauri::{State, Manager, AppHandle};
use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent};
use tokio::sync::Mutex;
use std::path::PathBuf;
use tauri_plugin_autostart::MacosLauncher;

struct AppState {
    config_path: Mutex<PathBuf>,
    config: Mutex<Option<Config>>,
    manager: Mutex<Option<Arc<TunnelManager>>>,
    active_server: Mutex<Option<String>>,
}

fn get_config_path(app: &AppHandle) -> PathBuf {
    let config_dir = app.path().app_config_dir().unwrap_or_else(|_| PathBuf::from("."));
    if !config_dir.exists() {
        let _ = std::fs::create_dir_all(&config_dir);
    }
    config_dir.join("config.yaml")
}

fn update_tray_menu(app: &AppHandle) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app_handle.state::<AppState>();
        let config_guard = state.config.lock().await;
        let is_running = state.manager.lock().await.is_some();
        
        let mut builder = MenuBuilder::new(&app_handle);
        
        // Proxy Status
        builder = builder.item(&MenuItemBuilder::new(if is_running { "状态: 已开启" } else { "状态: 已关闭" }).enabled(false).build(&app_handle).unwrap());
        builder = builder.item(&MenuItemBuilder::with_id("toggle", if is_running { "关闭代理" } else { "开启代理" }).build(&app_handle).unwrap());
        builder = builder.separator();
        
        // Servers
        if let Some(cfg) = config_guard.as_ref() {
            let configured_active = cfg.tunnels.first()
                .and_then(|t| t.server_names.first())
                .cloned()
                .unwrap_or_else(|| cfg.servers.first().map(|s| s.name.clone()).unwrap_or_default());
                
            let mut server_menu = SubmenuBuilder::new(&app_handle, "服务器");
            for srv in &cfg.servers {
                let prefix = if srv.name == configured_active { "✔ " } else { "" };
                let text = format!("{}{}", prefix, srv.name);
                let id = format!("srv_{}", srv.name);
                server_menu = server_menu.item(&MenuItemBuilder::with_id(id, text).build(&app_handle).unwrap());
            }
            builder = builder.item(&server_menu.build().unwrap());
            
            // Routing Mode
            let mut mode_menu = SubmenuBuilder::new(&app_handle, "路由模式");
            let modes = [
                ("global", "全局模式"),
                ("whitelist", "白名单模式"),
                ("blacklist", "黑名单模式"),
                ("direct", "直连模式"),
            ];
            for (id, name) in modes.iter() {
                let prefix = if format!("{:?}", cfg.routing.mode).to_lowercase() == *id { "✔ " } else { "" };
                let text = format!("{}{}", prefix, name);
                let mode_id = format!("mode_{}", id);
                mode_menu = mode_menu.item(&MenuItemBuilder::with_id(mode_id, text).build(&app_handle).unwrap());
            }
            builder = builder.item(&mode_menu.build().unwrap());
        }
        
        builder = builder.separator();
        builder = builder.item(&MenuItemBuilder::with_id("preferences", "偏好设置...").build(&app_handle).unwrap());
        builder = builder.separator();
        builder = builder.item(&MenuItemBuilder::with_id("quit", "退出 OxiTun").build(&app_handle).unwrap());

        if let Some(tray) = app_handle.tray_by_id("main") {
            let _ = tray.set_menu(Some(builder.build().unwrap()));
        }
    });
}

#[tauri::command]
async fn get_config(state: State<'_, AppState>) -> Result<Config, String> {
    let config_guard = state.config.lock().await;
    config_guard.clone().ok_or_else(|| "Config not loaded".to_string())
}

#[tauri::command]
async fn save_config(state: State<'_, AppState>, app: AppHandle, new_config: Config) -> Result<(), String> {
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
    let config_guard = state.config.lock().await;
    let config = config_guard.as_ref().ok_or_else(|| "Config not loaded".to_string())?.clone();
    drop(config_guard);
    
    if config.servers.is_empty() {
        return Err("No servers available".to_string());
    }

    let mut actual_config = config.clone();
    let mut modified = false;
    if actual_config.tunnels.is_empty() {
        actual_config.tunnels.push(oxitun_core::config::TunnelConfig {
            name: "SOCKS5 代理".to_string(),
            server_names: vec![actual_config.servers[0].name.clone()],
            tunnel_type: oxitun_core::config::TunnelType::Dynamic,
            port: 1080,
            remote_addr: None,
            share_on_lan: false,
        });
        modified = true;
    } else if actual_config.tunnels[0].server_names.is_empty() {
        actual_config.tunnels[0].server_names = vec![actual_config.servers[0].name.clone()];
        modified = true;
    }

    if modified {
        let path = state.config_path.lock().await.clone();
        let _ = actual_config.save_to_file(&path);
        let mut cg = state.config.lock().await;
        *cg = Some(actual_config.clone());
    }

    let pool = Arc::new(ServerPool::new(actual_config.servers.clone()));
    let manager = Arc::new(TunnelManager::new(pool.clone(), actual_config.routing.clone(), actual_config.general.chnroute_url.clone()).await);

    // Auto-updater task
    let update_interval = actual_config.general.chnroute_update_interval_hours;
    let url = actual_config.general.chnroute_url.clone();
    if update_interval > 0.0 {
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs((update_interval * 3600.0) as u64));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                log::info!("Auto-updating chnroutes...");
                if let Ok(resp) = reqwest::get(&url).await {
                    if let Ok(text) = resp.text().await {
                        let cache_dir = dirs::data_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join("OxiTun");
                        let _ = tokio::fs::create_dir_all(&cache_dir).await;
                        let _ = tokio::fs::write(cache_dir.join("chnroutes.txt"), text).await;
                    }
                }
            }
        });
        manager.add_task(handle).await;
    }

    // Pre-connect check
    for tun_cfg in &actual_config.tunnels {
        let mut any_success = false;
        let mut last_err = String::new();
        for server_name in &tun_cfg.server_names {
            let timeout_secs = config.servers.iter().find(|s| &s.name == server_name).map(|s| s.timeout_seconds).unwrap_or(15) as u64;
            let fut = pool.get_connection(server_name);
            match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), fut).await {
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

    let mut first_server = None;
    for tun_cfg in &actual_config.tunnels {
        if let Err(e) = manager.start_tunnel(tun_cfg.clone()).await {
            return Err(e.to_string());
        }
        if first_server.is_none() && !tun_cfg.server_names.is_empty() {
            first_server = Some(tun_cfg.server_names[0].clone());
        }
    }

    let mut state_manager = state.manager.lock().await;
    *state_manager = Some(manager);
    
    let mut active_guard = state.active_server.lock().await;
    *active_guard = first_server;
    
    // Apply system proxy if needed
    let mut socks_port = 1080;
    for t in &actual_config.tunnels {
        if matches!(t.tunnel_type, oxitun_core::config::TunnelType::Dynamic) {
            socks_port = t.port;
            break;
        }
    }
    let _ = oxitun_core::sysproxy::set_system_proxy(actual_config.general.auto_set_system_proxy, "127.0.0.1", socks_port);
    
    update_tray_menu(app);
    let _ = app.emit("state-changed", "");
    Ok(())
}

async fn stop_tunnels_internal(state: &AppState, app: &AppHandle) {
    let mut state_manager = state.manager.lock().await;
    if let Some(manager) = state_manager.take() {
        manager.stop_all().await;
    }
    
    // Always disable system proxy when stopping
    let port = state.config.lock().await.as_ref().and_then(|c| c.tunnels.first()).map(|t| t.port).unwrap_or(1080);
    let _ = oxitun_core::sysproxy::set_system_proxy(false, "127.0.0.1", port);
    
    let mut active_guard = state.active_server.lock().await;
    *active_guard = None;
    
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
async fn test_ssh_connection(state: State<'_, AppState>, server_name: String) -> Result<String, String> {
    let config_guard = state.config.lock().await;
    let config = config_guard.as_ref().ok_or_else(|| "Config not loaded".to_string())?.clone();
    drop(config_guard);

    let server_config = config.servers.iter().find(|s| s.name == server_name)
        .cloned()
        .ok_or_else(|| format!("Server {} not found", server_name))?;

    let pool = std::sync::Arc::new(oxitun_core::pool::ServerPool::new(vec![server_config]));
    let timeout_secs = config.servers.iter().find(|s| s.name == server_name).map(|s| s.timeout_seconds).unwrap_or(15) as u64;
    let fut = pool.get_connection(&server_name);
    
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), fut).await {
        Ok(Ok(_)) => Ok("连接测试成功！".to_string()),
        Ok(Err(e)) => Err(format!("连接失败: {}", e)),
        Err(_) => Err(format!("连接超时 ({}秒)", timeout_secs)),
    }
}

#[tauri::command]
async fn get_running_state(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.manager.lock().await.is_some())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = env_logger::try_init();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let _ = app.get_webview_window("main").expect("no main window").set_focus();
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec![])))
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Regular);

            let app_handle = app.handle().clone();
            
            if let Ok(app_menu) = app_menu::create_app_menu(&app_handle) {
                let _ = app.set_menu(app_menu);
                app.on_menu_event(|app_handle, event| {
                    if event.id() == "preferences" {
                        if let Some(window) = app_handle.get_webview_window("main") {
                            let _ = app_handle.set_activation_policy(tauri::ActivationPolicy::Regular);
                            #[cfg(target_os = "macos")]
                            let _ = app_handle.show();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                });
            }
            
            let config_path = get_config_path(&app_handle);
            
            let initial_config = Config::load_from_file(&config_path).unwrap_or_else(|_| Config {
                general: Default::default(),
                servers: vec![],
                tunnels: vec![],
                routing: Default::default(),
            });

            app.manage(AppState {
                config_path: Mutex::new(config_path),
                config: Mutex::new(Some(initial_config)),
                manager: Mutex::new(None),
                active_server: Mutex::new(None),
            });

            let default_icon = app.default_window_icon().cloned().unwrap();
            
            let _tray = TrayIconBuilder::with_id("main")
                .icon(default_icon)
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
                            "show" => {
                                if let Some(window) = app_handle.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                            "preferences" => {
                                if let Some(window) = app_handle.get_webview_window("main") {
                                    let _ = app_handle.set_activation_policy(tauri::ActivationPolicy::Regular);
                                    #[cfg(target_os = "macos")]
                                    let _ = app_handle.show();
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                    let w = window.clone();
                                    tauri::async_runtime::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
                                    let _ = cfg.save_to_file(&path);
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
                                        });
                                    } else {
                                        cfg.tunnels[0].server_names = vec![srv.clone()];
                                    }
                                    let path = state.config_path.lock().await.clone();
                                    let _ = cfg.save_to_file(&path);
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
                    config_guard.as_ref().map(|c| c.general.auto_connect).unwrap_or(false)
                };
                if auto_connect {
                    let _ = start_tunnels_internal(&state, &app_handle_clone).await;
                }
            });
            if let Some(window) = app.get_webview_window("main") {
                let window_clone = window.clone();
                window.on_window_event(move |event| match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        window_clone.hide().unwrap();
                        let _ = window_clone.app_handle().set_activation_policy(tauri::ActivationPolicy::Accessory);
                        api.prevent_close();
                    }
                    _ => {}
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            test_ssh_connection,
            get_config, save_config, start_tunnels, stop_tunnels, get_running_state
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
