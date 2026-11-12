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
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Mutex;

struct AppState {
    config_path: Mutex<PathBuf>,
    config: Mutex<Option<Config>>,
    manager: Mutex<Option<Arc<TunnelManager>>>,
    /// 生命周期锁：start/stop/save 重启段全程持有，消除启停并发竞争。
    /// 锁顺序约定：lifecycle 最外层；任何路径不得持有 manager 锁再 await config 锁。
    lifecycle: Mutex<()>,
    /// 最近一次启动是否失败（用于托盘错误图标）
    last_error: Mutex<bool>,
    /// 当前连接池的主机密钥确认协调器（随隧道启动而更新）
    broker: Mutex<Option<oxitun_core::host_key::HostKeyBroker>>,
    /// 「测试连接」独立连接池的主机密钥协调器（不覆盖运行中 broker，避免串扰）
    test_broker: Mutex<Option<oxitun_core::host_key::HostKeyBroker>>,
    /// 当前连接池的 known_hosts 存储
    known_hosts: Mutex<Option<Arc<oxitun_core::known_hosts::KnownHostsStore>>>,
    /// 内存日志缓冲（诊断页）
    log_store: Arc<logs::LogStore>,
}

/// 系统代理调用失败统一处理：记录 error 日志并通知前端（payload 为错误信息字符串，不再静默吞错）
fn report_sysproxy_error(app: &AppHandle, action: &'static str, err: &impl std::fmt::Display) {
    let message = format!(
        "{}: {err:#}",
        if action == "restore" {
            "还原系统代理失败，请检查系统网络设置"
        } else {
            "接管系统代理失败"
        }
    );
    log::error!("{}", message);
    let _ = app.emit("sysproxy-error", message);
}

/// 托盘修改配置后的统一错误上报：保存失败与重启失败分别用对应事件通知前端，不吞错
/// （托盘路径没有命令调用方可返回错误，必须 emit 事件；重启失败时托盘图标已由
/// start 内部更新为错误态，这里再补前端错误提示）
fn report_tray_save_error(app: &AppHandle, action: &str, err: SaveError) {
    match err {
        SaveError::Save(msg) => {
            log::error!("托盘{}保存配置失败: {}", action, msg);
            let _ = app.emit("config-save-error", msg);
        }
        SaveError::Restart(msg) => {
            log::error!("托盘{}后重启代理失败: {}", action, msg);
            let _ = app.emit("start-error", msg);
        }
    }
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
    // Tauri 2 的 Image 需要解码后的 RGBA 数据；托盘显示时自动缩放
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
        // 先克隆出所需数据再逐个取锁，避免 config→manager 持锁顺序与其他路径相反而死锁
        let config_snapshot = state.config.lock().await.clone();
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
        if let Some(cfg) = config_snapshot.as_ref() {
            let configured_active = cfg
                .primary_tunnel()
                .or_else(|| cfg.tunnels.first())
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
            &MenuItemBuilder::with_id("quit", "退出")
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
    let mut config_guard = state.config.lock().await;
    let cfg = config_guard
        .as_mut()
        .ok_or_else(|| "Config not loaded".to_string())?;
    // 保证前端总能拿到主代理（内存修正，不落盘）
    cfg.ensure_primary();
    Ok(cfg.clone())
}

#[tauri::command]
async fn save_config(
    state: State<'_, AppState>,
    app: AppHandle,
    new_config: Config,
) -> Result<(), String> {
    save_config_transaction(&state, &app, new_config)
        .await
        .map_err(SaveError::into_message)
}

/// 保存事务失败阶段：区分「配置未保存」与「已保存但重启失败」，
/// 供托盘调用点选择对应的前端通知事件（保存失败 / 启动失败）
enum SaveError {
    Save(String),
    Restart(String),
}

impl SaveError {
    fn into_message(self) -> String {
        match self {
            SaveError::Save(m) | SaveError::Restart(m) => m,
        }
    }
}

/// 统一保存事务：validate → 写盘 → 更新内存 → 按需重启，全程持有 lifecycle 锁，
/// 与启停命令互斥，避免并发保存造成磁盘/内存配置分裂。
async fn save_config_transaction(
    state: &AppState,
    app: &AppHandle,
    new_config: Config,
) -> Result<(), SaveError> {
    let _lifecycle = state.lifecycle.lock().await;
    save_config_transaction_locked(state, app, new_config).await
}

/// 托盘局部修改入口：在同一事务内读取最新配置、克隆并修改，再执行写盘。
/// 共享 state.config 只在写盘成功后更新，且两次保存之间不会插入过期的配置快照。
async fn modify_config_transaction<F>(
    state: &AppState,
    app: &AppHandle,
    modify: F,
) -> Result<(), SaveError>
where
    F: FnOnce(&mut Config),
{
    let _lifecycle = state.lifecycle.lock().await;
    let mut new_config = {
        let config_guard = state.config.lock().await;
        match config_guard.as_ref() {
            Some(config) => config.clone(),
            None => return Ok(()),
        }
    };
    modify(&mut new_config);
    save_config_transaction_locked(state, app, new_config).await
}

/// 保存事务的持锁实现；调用方必须已持有 lifecycle 锁。
async fn save_config_transaction_locked(
    state: &AppState,
    app: &AppHandle,
    new_config: Config,
) -> Result<(), SaveError> {
    new_config
        .validate()
        .map_err(|e| SaveError::Save(e.to_string()))?;

    // 先备份旧配置：写盘失败时恢复内存，避免与磁盘分裂
    let old_config = state.config.lock().await.clone();
    let path = state.config_path.lock().await.clone();
    if let Err(e) = new_config.save_to_file(&path) {
        let mut config_guard = state.config.lock().await;
        *config_guard = old_config;
        return Err(SaveError::Save(format!("保存配置失败: {e:#}")));
    }

    {
        let mut config_guard = state.config.lock().await;
        *config_guard = Some(new_config);
    }

    let was_running = state.manager.lock().await.is_some();
    if was_running {
        stop_tunnels_internal(state, app).await;
        // 重启失败必须返回 Err：否则 UI 显示保存成功但代理已停
        if let Err(e) = start_tunnels_internal(state, app).await {
            log::error!("保存配置后重启代理失败: {}", e);
            return Err(SaveError::Restart(format!(
                "配置已保存，但重启代理失败: {e}"
            )));
        }
    }

    update_tray_menu(app);
    let _ = app.emit("state-changed", "");
    Ok(())
}

/// 统一启停入口（托盘 / auto_connect / 前端命令共用）：
/// 全程持有 lifecycle 锁，与保存事务的重启段互斥
async fn lifecycle_start(state: &AppState, app: &AppHandle) -> Result<(), String> {
    let _lifecycle = state.lifecycle.lock().await;
    start_tunnels_internal(state, app).await
}

async fn lifecycle_stop(state: &AppState, app: &AppHandle) {
    let _lifecycle = state.lifecycle.lock().await;
    stop_tunnels_internal(state, app).await;
}

/// 按当前运行状态切换启停
async fn lifecycle_toggle(state: &AppState, app: &AppHandle) -> Result<(), String> {
    let _lifecycle = state.lifecycle.lock().await;
    if state.manager.lock().await.is_some() {
        stop_tunnels_internal(state, app).await;
        Ok(())
    } else {
        start_tunnels_internal(state, app).await
    }
}

async fn start_tunnels_internal(state: &AppState, app: &AppHandle) -> Result<(), String> {
    // 幂等：已在运行则直接成功，避免并发/重复启动覆盖现有管理器
    // （调用方均持有 lifecycle 锁，此处检查与置位之间无竞争）
    if state.manager.lock().await.is_some() {
        return Ok(());
    }
    let result = start_tunnels_inner(state, app).await;
    *state.last_error.lock().await = result.is_err();
    update_tray_menu(app);
    result
}

/// 启动失败回滚：回收已启动的监听器/后台任务，并清掉已登记的主机密钥协调器，
/// 避免已建任务脱离管理、避免 resolve 落到已废弃的 broker 上。
/// 注意：known_hosts 不清——它是持久化信任存储而非本次启动的资源，
/// 清掉会导致 KeyChanged 恢复按钮（remove_known_host）报「known_hosts 未初始化」
async fn rollback_failed_start(state: &AppState, manager: &TunnelManager) {
    manager.stop_all().await;
    // 只回收本次启动的协调器；known_hosts 保留，停止隧道时也不清
    *state.broker.lock().await = None;
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
    // 确保存在显式标记的主代理（无 primary 时把第一个 Dynamic 隧道提升，或创建默认主代理）
    let had_primary = actual_config.primary_tunnel().is_some();
    actual_config.ensure_primary();
    let mut modified = !had_primary;

    // 主代理（primary 标记）类型锁定为 Dynamic：若被手改 YAML 破坏则自动修正
    let primary_idx = actual_config
        .tunnels
        .iter()
        .position(|t| t.primary)
        .expect("ensure_primary 后必定存在主代理");
    {
        let primary = &mut actual_config.tunnels[primary_idx];
        if !matches!(
            primary.tunnel_type,
            oxitun_core::config::TunnelType::Dynamic
        ) {
            log::warn!(
                "主代理隧道「{}」类型不是 Dynamic，已自动修正为 Dynamic",
                primary.name
            );
            primary.tunnel_type = oxitun_core::config::TunnelType::Dynamic;
            if primary.port == 0 {
                primary.port = 1080;
            }
            modified = true;
        }
        if primary.server_names.is_empty() {
            primary.server_names = vec![actual_config.servers[0].name.clone()];
            modified = true;
        }
    }

    // 自动修正可能引入重名或端口冲突，必须在写盘和创建任何运行资源前整批校验。
    // 此处 actual_config 仍是局部副本，校验失败不会改变内存配置或磁盘文件。
    actual_config
        .validate()
        .map_err(|e| format!("启动代理前配置校验失败: {e:#}"))?;

    if modified {
        let path = state.config_path.lock().await.clone();
        actual_config
            .save_to_file(&path)
            .map_err(|e| e.to_string())?;
        let mut cg = state.config.lock().await;
        *cg = Some(actual_config.clone());
    }

    // known_hosts 打开失败（如文件损坏）在此明确失败并回滚：绝不静默降级，
    // 错误信息中已包含文件路径与修复/删除指引
    let pool = Arc::new(ServerPool::new(actual_config.servers.clone()).map_err(|e| e.to_string())?);

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
            loop {
                let pending_batch = match sub.recv().await {
                    Ok(pending) => vec![pending],
                    Err(RecvError::Lagged(skipped)) => {
                        // Lagged 只表示广播通知被覆盖，接收器仍有效；补拉遗漏的待确认请求。
                        log::warn!(
                            "主机密钥确认事件通道滞后 {} 条，正在补拉待确认请求",
                            skipped
                        );
                        broker.pending_list()
                    }
                    Err(RecvError::Closed) => break,
                };
                for pending in pending_batch {
                    // 自动连接触发确认时主动显示窗口
                    if let Some(window) = app_clone.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    let _ = app_clone.emit("host-key-verify", pending);
                }
            }
        });
        // 监听任务随隧道管理器生命周期回收
        manager.add_task(handle).await;
    }

    // 路由表自动更新任务
    let update_interval = actual_config.general.chnroute_update_interval_hours;
    let url = actual_config.general.chnroute_url.clone();
    if update_interval > 0.0 {
        // 更新成功后热替换运行中的路由引擎，需要持有 manager 与路由配置副本
        let manager_for_update = manager.clone();
        let routing_for_update = actual_config.routing.clone();
        let handle = tokio::spawn(async move {
            // 30 秒超时，避免网络挂起时任务永久卡住
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    log::error!("创建 chnroute 更新 HTTP 客户端失败: {e:#}");
                    return;
                }
            };
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                (update_interval * 3600.0) as u64,
            ));
            interval.tick().await; // 忽略首次立即执行的触发
            loop {
                interval.tick().await;
                log::info!("Auto-updating chnroutes...");
                // error_for_status：非 2xx 响应不得当作规则文本写入缓存
                let text = match client
                    .get(&url)
                    .send()
                    .await
                    .and_then(|r| r.error_for_status())
                {
                    Ok(resp) => match resp.text().await {
                        Ok(text) => text,
                        Err(e) => {
                            log::warn!("读取 chnroute 响应体失败: {e:#}");
                            continue;
                        }
                    },
                    Err(e) => {
                        log::warn!("更新 chnroute 失败: {e:#}");
                        continue;
                    }
                };
                // 内容校验：至少含一条合法 CIDR 行，防止把错误页/空响应写进缓存
                let has_valid_cidr = text.lines().map(str::trim).any(|line| {
                    !line.is_empty()
                        && !line.starts_with('#')
                        && line
                            .split_once('/')
                            .is_some_and(|(ip, _)| ip.parse::<std::net::IpAddr>().is_ok())
                });
                if !has_valid_cidr {
                    log::warn!("chnroute 响应内容不含合法 CIDR 行，跳过本次更新");
                    continue;
                }
                let cache_dir = dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("OxiTun");
                if let Err(e) = tokio::fs::create_dir_all(&cache_dir).await {
                    log::warn!("创建 chnroute 缓存目录失败: {e:#}");
                    continue;
                }
                if let Err(e) = tokio::fs::write(cache_dir.join("chnroutes.txt"), &text).await {
                    log::warn!("写入 chnroute 缓存失败: {e:#}");
                    continue;
                }
                // 写缓存成功后热替换运行中的路由引擎，无需重启隧道
                manager_for_update
                    .update_router(routing_for_update.clone(), Some(url.clone()))
                    .await;
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
            // 预连接失败：回收已启动的 broker 监听/chnroute/metrics 任务后再返回
            rollback_failed_start(state, &manager).await;
            return Err(last_err);
        }
    }

    for tun_cfg in &actual_config.tunnels {
        if let Err(e) = manager.start_tunnel(tun_cfg.clone()).await {
            // 任一隧道启动失败：同样统一回滚，避免已建监听器脱离管理
            rollback_failed_start(state, &manager).await;
            return Err(e.to_string());
        }
    }

    let mut state_manager = state.manager.lock().await;
    *state_manager = Some(manager);

    // 根据配置应用系统代理（端口取显式标记的主代理隧道）
    let socks_port = actual_config
        .primary_tunnel()
        .map(|t| t.port)
        .unwrap_or(1080);
    // 仅当存在 DNS 隧道时，macOS 才把系统 DNS 指向本地 127.0.0.1，避免误断系统解析
    let has_dns_tunnel = actual_config.tunnels.iter().any(|t| {
        matches!(
            t.tunnel_type,
            oxitun_core::config::TunnelType::Dns
                | oxitun_core::config::TunnelType::DnsDot
                | oxitun_core::config::TunnelType::DnsDoh
        )
    });
    // 仅当配置开启「接管系统代理」时才写入系统设置；
    // auto_set_system_proxy=false 时绝不执行禁用写操作（避免改动用户未托管的系统配置）
    if actual_config.general.auto_set_system_proxy {
        if let Err(e) = oxitun_core::sysproxy::set_system_proxy_ex(
            true,
            "127.0.0.1",
            socks_port,
            has_dns_tunnel,
        ) {
            report_sysproxy_error(app, "takeover", &e);
        }
    }

    let _ = app.emit("state-changed", "");
    Ok(())
}

async fn stop_tunnels_internal(state: &AppState, app: &AppHandle) {
    // 先 take 出 manager 并立刻释放锁，再异步 stop_all，
    // 避免「持有 manager 锁时再 await config 锁」的反向锁顺序
    let manager = state.manager.lock().await.take();
    if let Some(manager) = manager {
        manager.stop_all().await;
    }

    // 仅当本进程确实接管过系统代理时才还原（core 对未接管场景也是安全 no-op，双保险）；
    // 还原失败必须提示：残留指向本机的代理/DNS 会导致系统断网
    if oxitun_core::sysproxy::has_saved_state() {
        let port = state
            .config
            .lock()
            .await
            .as_ref()
            .and_then(|c| c.primary_tunnel().or_else(|| c.tunnels.first()))
            .map(|t| t.port)
            .unwrap_or(1080);
        if let Err(e) = oxitun_core::sysproxy::set_system_proxy(false, "127.0.0.1", port) {
            report_sysproxy_error(app, "restore", &e);
        }
    }

    update_tray_menu(app);
    let _ = app.emit("state-changed", "");
}

#[tauri::command]
async fn start_tunnels(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    // 统一走 lifecycle 包装：与 stop/save 的重启段互斥，消除双启动与「停止中又启动」竞争
    lifecycle_start(&state, &app).await
}

#[tauri::command]
async fn stop_tunnels(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    lifecycle_stop(&state, &app).await;
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

    let pool = std::sync::Arc::new(
        oxitun_core::pool::ServerPool::new(vec![server_config]).map_err(|e| e.to_string())?,
    );

    // 与主流程共用同一套 TOFU：测试连接遇到未知主机密钥同样弹窗确认。
    // 关键：测试 broker 存入独立的 test_broker 字段，绝不覆盖运行中的 state.broker，
    // 否则运行中的主代理后续 pending 的 resolve 会被提交到错误的 broker。
    let broker = pool.broker();
    *state.test_broker.lock().await = Some(broker.clone());
    let mut sub = broker.subscribe();
    let app_clone = app.clone();
    let listener_broker = broker.clone();
    let listener = tokio::spawn(async move {
        loop {
            let pending_batch = match sub.recv().await {
                Ok(pending) => vec![pending],
                Err(RecvError::Lagged(skipped)) => {
                    // 测试连接同样保留接收器，并补拉广播溢出期间遗漏的请求。
                    log::warn!(
                        "测试连接的主机密钥确认事件通道滞后 {} 条，正在补拉待确认请求",
                        skipped
                    );
                    listener_broker.pending_list()
                }
                Err(RecvError::Closed) => break,
            };
            for pending in pending_batch {
                if let Some(window) = app_clone.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
                let _ = app_clone.emit("host-key-verify", pending);
            }
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
    // 测试结束：拒绝所有未决确认并注销测试 broker，避免残留 pending 悬空等待
    broker.reject_all();
    *state.test_broker.lock().await = None;
    result
}

/// 规范化主代理：确保存在显式 primary，且主代理类型锁定为 Dynamic
/// （与 start_tunnels_inner 中的自动修正保持一致）。
/// setup 加载后、validate 前调用，使主代理类型被手改破坏的旧配置
/// 能被自动修正通过校验，而不是在启动阶段直接失败。
fn normalize_primary(config: &mut Config) {
    config.ensure_primary();
    // 提前取出兜底服务器名，避免与 tunnels 的可变借用冲突
    let fallback_server = config.servers.first().map(|s| s.name.clone());
    if let Some(primary) = config.tunnels.iter_mut().find(|t| t.primary) {
        if !matches!(
            primary.tunnel_type,
            oxitun_core::config::TunnelType::Dynamic
        ) {
            log::warn!(
                "主代理隧道「{}」类型不是 Dynamic，已自动修正为 Dynamic",
                primary.name
            );
            primary.tunnel_type = oxitun_core::config::TunnelType::Dynamic;
            if primary.port == 0 {
                primary.port = 1080;
            }
        }
        if primary.server_names.is_empty() {
            // 无可用服务器时保持为空（交由 validate 按原规则处理）
            primary.server_names = fallback_server.into_iter().collect();
        }
    }
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

/// 用户决策待确认的主机密钥：accept=true 信任并持久化，false 拒绝。
/// 决策身份为 request_id（前端从事件/补拉列表中获得）：精确匹配本次请求，
/// 旧弹窗残留的 request_id 在请求超时/被替换后自动失效，不会误批准后续请求
#[tauri::command]
async fn resolve_host_key(
    state: State<'_, AppState>,
    request_id: String,
    accept: bool,
) -> Result<(), String> {
    // 运行中的连接池 broker 优先（按 request_id 精确命中），
    // 未命中再尝试「测试连接」的独立 broker；request_id 天然隔离两个 broker，
    // 不存在跨 broker 串扰
    let running_broker = state.broker.lock().await.clone();
    if let Some(broker) = running_broker {
        if broker.resolve_by_id(&request_id, accept) {
            return Ok(());
        }
    }
    let test_broker = state.test_broker.lock().await.clone();
    if let Some(broker) = test_broker {
        if broker.resolve_by_id(&request_id, accept) {
            return Ok(());
        }
    }
    Err("主机密钥确认已过期，请重新连接".to_string())
}

/// 补拉当前所有待确认的主机密钥（窗口刚打开时事件可能已发出）
#[tauri::command]
async fn get_pending_host_keys(
    state: State<'_, AppState>,
) -> Result<Vec<oxitun_core::host_key::PendingHostKey>, String> {
    // 运行中 broker 与测试 broker 的待确认请求都需要补拉
    let mut list = state
        .broker
        .lock()
        .await
        .clone()
        .map(|b| b.pending_list())
        .unwrap_or_default();
    if let Some(test_broker) = state.test_broker.lock().await.clone() {
        list.extend(test_broker.pending_list());
    }
    Ok(list)
}

/// 清除某主机的信任记录（指纹变化后由用户显式确认清除，绝不自动覆盖）
#[tauri::command]
async fn remove_known_host(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<(), String> {
    let store = {
        let mut guard = state.known_hosts.lock().await;
        if guard.is_none() {
            // 兜底：尚未启动过隧道（或 store 打开失败）时按默认路径打开一次，
            // 保证 KeyChanged 恢复按钮在代理未运行的场景下也能工作
            *guard = Some(
                oxitun_core::known_hosts::KnownHostsStore::open_shared(
                    oxitun_core::known_hosts::KnownHostsStore::default_path(),
                )
                .map_err(|e| format!("打开 known_hosts 存储失败: {e:#}"))?,
            );
        }
        guard.clone()
    };
    let store = store.ok_or("known_hosts 未初始化")?;
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
            // 第二实例启动时把已有窗口带到前台（参照托盘左键逻辑：
            // macOS 需恢复 Regular activation policy 并 show app，仅 set_focus 不够）
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "macos")]
                {
                    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
                    let _ = app.show();
                }
                let _ = window.show();
                let _ = window.set_focus();
            }
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
                            // 通知前端打开设置弹窗（前端监听 "open-preferences"）
                            let _ = app_handle.emit("open-preferences", ());
                        }
                    }
                });
            }

            let config_path = get_config_path(&app_handle);

            let mut initial_config = if config_path.exists() {
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
            // 校验前先规范化主代理（ensure_primary + 非 Dynamic primary 自动修正），
            // 与 start_tunnels_inner 保持一致；否则主代理类型被手改破坏的旧配置
            // 会在此被 validate 拒绝而无法启动。修正只作用于内存副本，不落盘。
            normalize_primary(&mut initial_config);
            // load_from_file 已完成旧配置迁移，规范化后立即整批校验；失败时中止 setup。
            initial_config.validate().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("配置文件 {} 校验失败: {e:#}", config_path.display()),
                )
            })?;

            app.manage(AppState {
                config_path: Mutex::new(config_path),
                config: Mutex::new(Some(initial_config)),
                manager: Mutex::new(None),
                lifecycle: Mutex::new(()),
                last_error: Mutex::new(false),
                broker: Mutex::new(None),
                test_broker: Mutex::new(None),
                // setup 时即打开 known_hosts 存储：remove_known_host 无需运行中的
                // manager 也能工作；隧道启动后会被连接池的 store 句柄替换（同一文件）
                known_hosts: Mutex::new(
                    oxitun_core::known_hosts::KnownHostsStore::open_shared(
                        oxitun_core::known_hosts::KnownHostsStore::default_path(),
                    )
                    .ok(),
                ),
                log_store: log_store_setup.clone(),
            });

            // 初始托盘图标为「已停止」状态
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
                                lifecycle_stop(&state, &app_handle).await;
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
                                    // 通知前端打开设置弹窗（与原生菜单行为一致）
                                    let _ = app_handle.emit("open-preferences", ());
                                    let w = window.clone();
                                    tauri::async_runtime::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_millis(50))
                                            .await;
                                        let _ = w.set_focus();
                                    });
                                }
                            }
                            "toggle" => {
                                // 启停全程持有生命周期锁，与前端命令/保存重启段互斥
                                if let Err(e) = lifecycle_toggle(&state, &app_handle).await {
                                    log::error!("托盘切换代理状态失败: {}", e);
                                    let _ = app_handle.emit("start-error", e);
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
                                // 读取、克隆、修改与保存处于同一事务，绝不提前修改共享配置。
                                if let Err(e) =
                                    modify_config_transaction(&state, &app_handle, move |config| {
                                        config.routing.mode = mode
                                    })
                                    .await
                                {
                                    report_tray_save_error(&app_handle, "切换路由模式", e);
                                }
                            }
                            id if id.starts_with("srv_") => {
                                let srv = id.replace("srv_", "");
                                if let Err(e) =
                                    modify_config_transaction(&state, &app_handle, move |config| {
                                        // 托盘切换节点作用于主代理隧道（而非隐式的 tunnels[0]）
                                        config.ensure_primary();
                                        if let Some(idx) =
                                            config.tunnels.iter().position(|t| t.primary)
                                        {
                                            config.tunnels[idx].server_names = vec![srv];
                                        }
                                    })
                                    .await
                                {
                                    report_tray_save_error(&app_handle, "切换节点", e);
                                }
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
                    // 统一走 lifecycle 包装：auto_connect 与前端命令/托盘操作互斥
                    let _ = lifecycle_start(&state, &app_handle_clone).await;
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
            // 必须经 lifecycle_stop 获取 lifecycle 锁：与保存事务的「stop → start」重启段串行，
            // 否则退出恰逢 stop 完成/start 进行中时会看到 manager=None 直接返回，
            // start 随后写入的系统代理将指向已退出进程的端口而残留。
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let state = app_handle.state::<AppState>();
                let app_handle_cleanup = app_handle.clone();
                // block_on 内对 tokio::Mutex 用异步 lock().await（处于运行时上下文，合法）
                tauri::async_runtime::block_on(async move {
                    lifecycle_stop(&state, &app_handle_cleanup).await;
                });
            }
        });
}
