use crate::config::{RoutingConfig, TunnelConfig, TunnelStrategy, TunnelType};
use crate::pool::{ClientHandler, ServerPool};
use crate::router::Router;
use crate::socks5::{handle_socks5_handshake, send_socks5_reply};
use anyhow::{Result, anyhow};
use log::{debug, error, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// 按隧道策略选择节点并取连接：
/// - failover：严格按 server_names 顺序，第一个可用者胜出
/// - round_robin：每个新入站连接从不同节点起步，故障时继续向后尝试
/// - server_names 为空（Dynamic「跟随主代理」）时使用主代理隧道的服务器列表
async fn pick_connection(
    pool: &Arc<ServerPool>,
    config: &TunnelConfig,
    rr_counter: &AtomicUsize,
    primary_server_names: &RwLock<Vec<String>>,
) -> Result<(String, Arc<russh::client::Handle<ClientHandler>>)> {
    let names = if config.server_names.is_empty() {
        primary_server_names.read().await.clone()
    } else {
        config.server_names.clone()
    };
    if names.is_empty() {
        return Err(anyhow!(
            "隧道 {} 未指定绑定的代理服务器，且主代理服务器列表为空",
            config.name
        ));
    }
    let start = match config.strategy {
        TunnelStrategy::RoundRobin => rr_counter.fetch_add(1, Ordering::Relaxed) % names.len(),
        TunnelStrategy::Failover => 0,
    };
    let mut last_err = None;
    for i in 0..names.len() {
        let name = &names[(start + i) % names.len()];
        match pool.get_connection(name).await {
            Ok(handle) => return Ok((name.clone(), handle)),
            Err(e) => {
                debug!("节点 {} 不可用（{}），尝试下一节点", name, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("所有绑定服务器均不可用")))
}

/// 外部任务（非隧道）在任务表中的保留键
const EXTERNAL_TASKS_KEY: &str = "__external__";

/// 单条隧道的生命周期状态：监听任务句柄 + 取消令牌 + 活跃子任务追踪器。
/// 停止隧道时先取消令牌（通知所有 per-connection 数据任务退出），
/// 再 abort 监听任务，最后 close()+wait() 追踪器确保派生的
/// TCP/SSH 数据流、DNS 查询等活跃任务真正结束，而非仅中止监听循环
struct TunnelTasks {
    handles: Vec<JoinHandle<()>>,
    token: CancellationToken,
    tracker: TaskTracker,
}

/// 隧道生命周期管理器，负责不同类型的代理隧道（Local/Remote/SOCKS5/DNS）的启动、注册、维护和销毁
pub struct TunnelManager {
    pool: Arc<ServerPool>,
    /// 路由引擎（RwLock 支持热替换：路由规则变化时无需重启隧道任务）
    router: Arc<RwLock<Arc<Router>>>,
    /// 当前生效的路由配置副本（热加载 diff 用）
    routing_snapshot: Mutex<RoutingConfig>,
    /// 隧道任务表：键为隧道名（外部衍生任务归入 `__external__`），
    /// value 持有监听任务句柄与 per-tunnel 取消令牌
    tasks: Mutex<HashMap<String, TunnelTasks>>,
    /// 全局取消令牌：stop_all 时取消，供外部衍生任务（metrics HTTP 服务、
    /// 连接池 Remote 回调转发等）在数据面监听退出
    external_token: CancellationToken,
    /// 运行中隧道的配置副本：停止/删除 Remote 隧道时据此显式注销远端端口映射（abort 不走注销路径）
    tunnel_configs: Mutex<HashMap<String, TunnelConfig>>,
    /// 主代理（primary）隧道当前的服务器列表：
    /// server_names 为空的 Dynamic 隧道表示「跟随状态栏主节点」，选路时读取此列表
    primary_server_names: Arc<RwLock<Vec<String>>>,
    /// 当前生效的主代理隧道名（后启动的 primary 覆盖先启动的）。
    /// refresh 据此从 tunnel_configs 取列表，避免 HashMap 遍历顺序导致
    /// 同时存在多个 primary 时选中错误的隧道
    primary_name: Mutex<Option<String>>,
    /// 热加载互斥：同一时刻只允许一个 reload
    reload_lock: Mutex<()>,
}

impl TunnelManager {
    /// 初始化隧道管理器并挂载底层的 SSH 连接池和路由引擎
    pub async fn new(pool: Arc<ServerPool>, routing: RoutingConfig, chnroute_url: String) -> Self {
        let external_token = CancellationToken::new();
        // 连接池的 Remote 反向回调转发任务共用全局令牌：stop_all 时一并退出
        pool.set_cancellation_token(external_token.clone());
        Self {
            pool,
            router: Arc::new(RwLock::new(Arc::new(
                Router::new(routing.clone(), &chnroute_url).await,
            ))),
            routing_snapshot: Mutex::new(routing),
            tasks: Mutex::new(HashMap::new()),
            external_token,
            tunnel_configs: Mutex::new(HashMap::new()),
            primary_server_names: Arc::new(RwLock::new(Vec::new())),
            primary_name: Mutex::new(None),
            reload_lock: Mutex::new(()),
        }
    }

    /// 根据传入的配置类型派发任务，启动对应的底层代理监听服务
    pub async fn start_tunnel(&self, config: TunnelConfig) -> Result<()> {
        let name = config.name.clone();
        // 每条隧道独立取消令牌与子任务追踪器：停止时先通知数据任务退出，
        // 再 abort 监听任务，最后等待追踪器收尾
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let handles = match config.tunnel_type {
            TunnelType::Local => {
                self.spawn_local_tunnel(config.clone(), token.clone(), tracker.clone())
                    .await?
            }
            TunnelType::Dynamic => {
                self.spawn_dynamic_tunnel(config.clone(), token.clone(), tracker.clone())
                    .await?
            }
            TunnelType::Remote => {
                self.spawn_remote_tunnel(config.clone(), token.clone())
                    .await?
            }
            TunnelType::Dns | TunnelType::DnsDot | TunnelType::DnsDoh => {
                self.spawn_dns_tunnel(config.clone(), token.clone(), tracker.clone())
                    .await?
            }
        };
        self.tasks.lock().await.insert(
            name.clone(),
            TunnelTasks {
                handles,
                token,
                tracker,
            },
        );
        // 后启动的 primary 成为生效主代理（多个 primary 并存的过渡场景下，
        // 以最后启动者为准，不依赖 HashMap 遍历顺序）
        if config.primary {
            *self.primary_name.lock().await = Some(name.clone());
        }
        self.tunnel_configs.lock().await.insert(name, config);
        // 主代理列表统一重建：任何启动顺序下最终一致
        self.refresh_primary_server_names().await;
        Ok(())
    }

    /// 停止指定隧道（释放其监听端口；不触碰其他隧道）
    ///
    /// Remote 反向隧道的停止顺序（修复停止缺陷，顺序不可调换）：
    /// 1) 先取消令牌并 abort 顶层 Remote 轮询任务——任务死后无法再执行
    ///    register_remote_forward 重新注册映射（旧实现先删映射后 abort，
    ///    任务可能在间隙内重新注册，导致 port_forwards 残留指向已停止隧道）
    /// 2) 再按保存的配置调用 cancel_remote_forward——向 SSH 服务端发送
    ///    cancel-tcpip-forward 释放远端端口（旧实现从不通知 sshd，热加载复用
    ///    连接池时远端端口仍被占用），内部成功/失败后均删除本地映射
    /// 3) 最后删除配置表条目
    pub async fn stop_tunnel(&self, name: &str) {
        let entry = self.tasks.lock().await.remove(name);
        if let Some(entry) = entry {
            // 先广播取消：per-connection 数据任务（copy/DNS 查询等）收到后自行退出
            entry.token.cancel();
            // abort 顶层监听任务并等待其退出
            for handle in entry.handles {
                handle.abort();
                let _ = handle.await;
            }
            // 等待监听循环派生的活跃数据任务真正结束（取消已广播，通常立即返回）；
            // 超时仅告警不阻塞——这些任务均内建取消分支，最坏随运行时回收
            entry.tracker.close();
            if tokio::time::timeout(std::time::Duration::from_secs(3), entry.tracker.wait())
                .await
                .is_err()
            {
                log::warn!("隧道 {} 存在未在 3 秒内退出的数据任务", name);
            }
            info!("隧道 {} 已停止", name);
        }
        // 顶层 Remote 轮询任务已 abort：此后再无重新注册映射的可能，
        // 按保存的配置向 SSH 服务端注销远端端口（cancel 内部删除本地映射）
        let removed = self.tunnel_configs.lock().await.remove(name);
        if let Some(cfg) = &removed
            && cfg.tunnel_type == TunnelType::Remote
        {
            for server_name in &cfg.server_names {
                // 失败仅告警：停止路径上本地映射已由 cancel 内部清除，
                // 不得因网络通知失败阻断后续清理
                if let Err(e) = self
                    .pool
                    .cancel_remote_forward(server_name, cfg.port as u32)
                    .await
                {
                    log::warn!(
                        "隧道 {}: 向 {} 注销远端端口 {} 失败: {}",
                        name,
                        server_name,
                        cfg.port,
                        e
                    );
                }
            }
        }
        // 若停止的正是当前生效的主代理，则从剩余隧道中重新指定一个 primary（或清空）
        if removed.as_ref().is_some_and(|c| c.primary)
            && *self.primary_name.lock().await == Some(name.to_string())
        {
            let next = self
                .tunnel_configs
                .lock()
                .await
                .iter()
                .find(|(_, c)| c.primary)
                .map(|(n, _)| n.clone());
            *self.primary_name.lock().await = next;
        }
        // 主代理列表统一重建：停止旧 primary 不会误清新 primary 的节点
        self.refresh_primary_server_names().await;
    }

    /// 依据当前生效的主代理（primary_name 指向的隧道）重建服务器列表：
    /// primary_name 缺失时退回任意一个 primary 兜底，无 primary 则清空。
    /// 不再在 start/stop 时各自增减维护，而是在 start_tunnel、stop_tunnel、
    /// stop_all、reload_with_diff 末尾统一调用，保证任何执行顺序最终一致
    /// （修复：新 primary 先启动、旧 primary 后停止时列表被误清空、跟随者失效）
    async fn refresh_primary_server_names(&self) {
        let configs = self.tunnel_configs.lock().await;
        let primary = {
            let name = self.primary_name.lock().await.clone();
            name.and_then(|n| configs.get(&n))
                .filter(|c| c.primary)
                .or_else(|| configs.values().find(|c| c.primary))
                .map(|c| c.server_names.clone())
        };
        drop(configs);
        let mut guard = self.primary_server_names.write().await;
        match primary {
            Some(names) => *guard = names,
            None => guard.clear(),
        }
    }

    /// 返回当前实际运行中隧道的配置快照（热加载失败时作为下一轮 diff 的旧基线）
    pub async fn tunnel_configs_snapshot(&self) -> Vec<TunnelConfig> {
        self.tunnel_configs.lock().await.values().cloned().collect()
    }

    /// 当前运行中的隧道名列表
    pub async fn running_tunnels(&self) -> Vec<String> {
        self.tasks
            .lock()
            .await
            .keys()
            .filter(|k| k.as_str() != EXTERNAL_TASKS_KEY)
            .cloned()
            .collect()
    }

    /// 事务式热加载的提交阶段（调用方须先完成整批校验，见 Config::validate）
    ///
    /// 语义：
    /// - 路由规则变化：仅替换路由引擎，隧道任务不重启
    /// - 未变化的隧道：原样保留（监听器与活跃连接不受影响）
    /// - 变化的隧道：先停旧再启新；启动失败时尝试用旧配置回滚
    /// - 任一隧道处理失败即整批返回 Err：停止新增隧道、用旧配置恢复既有变化隧道，
    ///   并恢复已删除隧道，尽量向旧基线收敛；调用方须以 tunnel_configs_snapshot() 作为下一轮 diff 的旧基线，
    ///   因为实际运行状态可能已与旧配置文件不一致（部分生效）
    ///
    /// 带旧配置对比的热加载（CLI 使用）：精确判断哪些隧道需要重启
    pub async fn reload_with_diff(
        &self,
        old_tunnels: &[TunnelConfig],
        new_tunnels: Vec<TunnelConfig>,
        new_routing: RoutingConfig,
        chnroute_url: String,
    ) -> Result<()> {
        let _permit = self.reload_lock.lock().await;

        // 路由热替换
        let routing_changed = *self.routing_snapshot.lock().await != new_routing;
        if routing_changed {
            let new_router = Arc::new(Router::new(new_routing.clone(), &chnroute_url).await);
            *self.router.write().await = new_router;
            *self.routing_snapshot.lock().await = new_routing;
            info!("热加载：路由规则已更新（隧道不重启）");
        }

        let old_map: HashMap<String, TunnelConfig> = old_tunnels
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let new_map: HashMap<String, TunnelConfig> = new_tunnels
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect();

        // —— 阶段一：停止所有删除/变化的隧道（含旧 primary）。
        // 先全部停干净再统一启动，避免 HashMap 遍历顺序导致的交错——
        // 若新 primary B 先启动写入列表、旧 primary A 后停止清空列表，
        // 跟随主代理的 Dynamic 隧道将全部失效
        let mut deleted: Vec<TunnelConfig> = Vec::new();
        for name in old_map.keys() {
            if !new_map.contains_key(name) {
                info!("热加载：停止已删除的隧道 {}", name);
                if let Some(cfg) = old_map.get(name) {
                    deleted.push(cfg.clone());
                }
                self.stop_tunnel(name).await;
            }
        }
        // 新增或变化的隧道名（阶段二统一启动）
        let mut changed_names: Vec<String> = Vec::new();
        for (name, new_cfg) in &new_map {
            let changed = match old_map.get(name) {
                Some(old_cfg) => old_cfg != new_cfg,
                None => true,
            };
            if changed {
                info!("热加载：停止变化的隧道 {}", name);
                changed_names.push(name.clone());
                self.stop_tunnel(name).await;
            }
        }

        // —— 阶段二：统一启动所有新增/变化的隧道；启动失败时尝试用旧配置回滚。
        // 任何启动失败或回滚失败都记入 failures，最终返回 Err 通知调用方
        let mut failures: Vec<String> = Vec::new();
        // 记录每个已成功启动的变化及其旧配置：整体失败时，新增隧道需停止，
        // 既有隧道也必须恢复旧配置，不能只撤销新增项而留下部分新配置生效
        let mut started_changed: Vec<(String, Option<TunnelConfig>)> = Vec::new();
        for name in &changed_names {
            let new_cfg = &new_map[name];
            let old_cfg = old_map.get(name).cloned();
            info!("热加载：启动变化的隧道 {}", name);
            match self.start_tunnel(new_cfg.clone()).await {
                Ok(()) => started_changed.push((name.clone(), old_cfg)),
                Err(e) => {
                    error!("热加载：隧道 {} 启动失败: {}", name, e);
                    let mut msg = format!("隧道 {} 启动失败: {}", name, e);
                    if let Some(old) = old_cfg {
                        log::warn!("热加载：尝试用旧配置回滚隧道 {}", name);
                        if let Err(e2) = self.start_tunnel(old).await {
                            error!("热加载：隧道 {} 回滚也失败: {}", name, e2);
                            msg.push_str(&format!("；回滚也失败: {}", e2));
                        }
                    }
                    failures.push(msg);
                }
            }
        }

        // 存在失败：整批视为未完全生效，向旧基线收敛——按相反顺序停止本轮
        // 所有成功变化，既有隧道用旧配置重启，新增隧道保持停止，再恢复已删除项。
        // 注意：无法保证 100% 回到旧基线（旧配置回滚也可能失败），
        // 调用方须以 tunnel_configs_snapshot() 作为下一轮 diff 的旧基线
        if !failures.is_empty() {
            for (name, old_cfg) in started_changed.into_iter().rev() {
                log::warn!("热加载：回滚已成功启动的变化隧道 {}", name);
                self.stop_tunnel(&name).await;
                if let Some(old) = old_cfg {
                    log::warn!("热加载：用旧配置恢复隧道 {}", name);
                    if let Err(e) = self.start_tunnel(old).await {
                        error!("热加载：恢复变化隧道 {} 的旧配置失败: {}", name, e);
                        failures.push(format!("恢复变化隧道 {} 的旧配置失败: {}", name, e));
                    }
                }
            }
            for cfg in deleted {
                log::warn!("热加载：回滚恢复已删除的隧道 {}", cfg.name);
                if let Err(e) = self.start_tunnel(cfg.clone()).await {
                    error!("热加载：恢复已删除隧道 {} 失败: {}", cfg.name, e);
                    failures.push(format!("恢复已删除隧道 {} 失败: {}", cfg.name, e));
                }
            }
        }

        // 主代理列表统一重建（本函数内的 start/stop 顺序不影响最终结果）
        self.refresh_primary_server_names().await;

        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "热加载未完全生效，以实际运行配置为准；以下隧道处理失败: {}",
                failures.join("；")
            ))
        }
    }

    /// 热替换路由引擎（chnroute 自动更新成功后调用）：
    /// 仅替换路由规则，运行中的隧道任务与活跃连接不受影响。
    /// 与 reload_with_diff 共用 reload_lock，保证路由引擎与 routing_snapshot 一致提交
    pub async fn update_router(&self, routing: RoutingConfig, url: Option<String>) {
        // 同一时刻只允许一个热加载提交：避免 router 与 routing_snapshot 分两次写入
        // 期间被 reload_with_diff 读到中间态（引擎已换、快照仍旧，或反之）
        let _permit = self.reload_lock.lock().await;
        let new_router =
            Arc::new(Router::new(routing.clone(), url.as_deref().unwrap_or_default()).await);
        *self.router.write().await = new_router;
        *self.routing_snapshot.lock().await = routing;
        info!("路由引擎已热更新（隧道不重启）");
    }

    /// 将外部衍生的异步协程任务（如后台定时更新路由表的任务）注册到管理器的生命周期中，
    /// 确保在调用 `stop_all` 时能够一并被平滑取消。
    pub async fn add_task(&self, handle: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().await;
        let entry = tasks
            .entry(EXTERNAL_TASKS_KEY.to_string())
            .or_insert_with(|| {
                // 外部任务复用全局令牌：stop_all 统一取消
                TunnelTasks {
                    handles: Vec::new(),
                    token: self.external_token.clone(),
                    tracker: TaskTracker::new(),
                }
            });
        entry.handles.push(handle);
    }

    /// 全局取消令牌（克隆）：外部数据面任务（metrics HTTP 服务等）在
    /// select! 中监听 `token.cancelled()`，`stop_all` 时会触发取消
    pub fn external_cancellation_token(&self) -> CancellationToken {
        self.external_token.clone()
    }

    /// 强行终止并清理所有当前处于活跃状态的代理隧道和后台维护任务，
    /// 同时向 SSH 连接池下发断开指令，释放所有底层网络连接。
    pub async fn stop_all(&self) {
        // 先按配置显式注销所有 Remote 映射（abort 不走注销路径）
        let configs = {
            let mut tc = self.tunnel_configs.lock().await;
            std::mem::take(&mut *tc)
        };
        for cfg in configs.values() {
            if cfg.tunnel_type == TunnelType::Remote {
                for server_name in &cfg.server_names {
                    self.pool
                        .unregister_remote_forward(server_name, cfg.port as u32)
                        .await;
                }
            }
        }
        // 先取消全局令牌（metrics、Remote 回调转发等外部任务）与全部隧道令牌，
        // 再 abort 监听任务，最后统一等待各隧道的活跃数据任务收尾
        self.external_token.cancel();
        let mut tasks = self.tasks.lock().await;
        let mut entries: Vec<TunnelTasks> = tasks.drain().map(|(_, entry)| entry).collect();
        let mut join_handles = vec![];
        for entry in &mut entries {
            entry.token.cancel();
            for task in entry.handles.drain(..) {
                task.abort();
                join_handles.push(task);
            }
        }
        for task in join_handles {
            let _ = task.await;
        }
        for entry in entries {
            entry.tracker.close();
            if tokio::time::timeout(std::time::Duration::from_secs(3), entry.tracker.wait())
                .await
                .is_err()
            {
                log::warn!("stop_all 时仍有数据任务未在 3 秒内退出");
            }
        }
        self.pool.disconnect_all().await;
        info!("所有活跃隧道已停止工作。");
        // 全部隧道已停止：主代理指针与列表一并清空
        *self.primary_name.lock().await = None;
        self.refresh_primary_server_names().await;
    }

    /// 启动本地端口转发 (Local Forwarding)
    /// 会监听本地指定端口，并将接收到的所有流量透明地借助 SSH 通道发送至 `remote_addr`
    async fn spawn_local_tunnel(
        &self,
        config: TunnelConfig,
        cancel: CancellationToken,
        tracker: TaskTracker,
    ) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let remote_addr = config
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow!("本地隧道 (Local) 必须配置目标地址 (remote_addr)"))?;
        if config.server_names.is_empty() {
            return Err(anyhow!("隧道未指定绑定的代理服务器"));
        }
        let rr_counter = Arc::new(AtomicUsize::new(0));

        for ip in &[v4_ip, v6_ip] {
            let local_addr = format!("{}:{}", ip, config.port);
            let listener = match TcpListener::bind(&local_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("绑定地址 {}: {} 失败", local_addr, e);
                    continue;
                }
            };
            info!("在 {} 监听本地隧道 {}", local_addr, config.name);

            let pool = self.pool.clone();
            let cfg = config.clone();
            let remote_addr = remote_addr.clone();
            let rr_counter = rr_counter.clone();
            let primary_server_names = self.primary_server_names.clone();
            let cancel = cancel.clone();
            let tracker = tracker.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        // 隧道停止：监听循环退出，监听 socket 随任务 drop 而释放
                        _ = cancel.cancelled() => break,
                        res = listener.accept() => {
                            let Ok((mut inbound, _)) = res else { break };
                            let _ = inbound.set_nodelay(true);

                            let pool = pool.clone();
                            let cfg = cfg.clone();
                            let remote_addr = remote_addr.clone();
                            let rr_counter = rr_counter.clone();
                            let primary_server_names = primary_server_names.clone();
                            let cancel = cancel.clone();
                            let tracker = tracker.clone();

                            // 每条入站连接的数据任务纳入隧道追踪器：
                            // stop_tunnel 时会真正等待其结束，而非仅中止监听循环
                            tracker.spawn(async move {
                                tokio::select! {
                                    biased;
                                    // 取消优先：隧道停止时活跃数据流立即中断（drop 流即关闭连接）
                                    _ = cancel.cancelled() => {}
                                    _ = async {
                                        if let Ok((_server, handle_arc)) = pick_connection(
                                            &pool, &cfg, &rr_counter, &primary_server_names,
                                        )
                                        .await
                                        {
                                            match parse_host_port(&remote_addr, 80) {
                                                Ok((host, port)) => {
                                                    let host = host.trim_matches(|c| c == '[' || c == ']');

                                                    let channel_res = handle_arc
                                                        .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
                                                        .await;
                                                    if let Ok(channel) = channel_res {
                                                        let mut stream = channel.into_stream();
                                                        let _guard = crate::metrics::ConnectionGuard::new();
                                                        if let Ok((tx, rx)) =
                                                            crate::copy_bidirectional::copy_bidirectional_64k(
                                                                &mut inbound,
                                                                &mut stream,
                                                            )
                                                            .await
                                                        {
                                                            crate::metrics::add_bytes(tx, rx);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("解析目标地址 {} 失败: {}", remote_addr, e);
                                                }
                                            }
                                        }
                                    } => {}
                                }
                            });
                        }
                    }
                }
            });
            handles.push(handle);
        }

        if handles.is_empty() {
            return Err(anyhow!("本地隧道绑定地址失败（IPv4 与 IPv6 均失败）"));
        }
        Ok(handles)
    }

    /// 启动动态代理 (SOCKS5 - Dynamic Forwarding)
    /// 在本地监听 SOCKS5 端口，解析握手包提取目标地址，并将其送入智能路由引擎以判断是“直连”还是“走代理穿透”
    async fn spawn_dynamic_tunnel(
        &self,
        config: TunnelConfig,
        cancel: CancellationToken,
        tracker: TaskTracker,
    ) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        // server_names 为空表示「跟随主代理」：选路时动态读取主代理隧道的服务器列表
        if config.server_names.is_empty() {
            info!(
                "SOCKS5 隧道 {} 未绑定服务器，将跟随主代理的节点列表",
                config.name
            );
        }
        let rr_counter = Arc::new(AtomicUsize::new(0));

        for ip in &[v4_ip, v6_ip] {
            let local_addr = format!("{}:{}", ip, config.port);
            let listener = match TcpListener::bind(&local_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("绑定地址 {}: {} 失败", local_addr, e);
                    continue;
                }
            };
            info!("在 {} 监听 SOCKS5 隧道 {}", local_addr, config.name);

            let pool = self.pool.clone();
            let router = self.router.clone();
            let cfg = config.clone();
            let rr_counter = rr_counter.clone();
            let primary_server_names = self.primary_server_names.clone();
            let cancel = cancel.clone();
            let tracker = tracker.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        // 隧道停止：监听循环退出，监听 socket 随任务 drop 而释放
                        _ = cancel.cancelled() => break,
                        res = listener.accept() => {
                            let Ok((mut inbound, _)) = res else { break };
                            let _ = inbound.set_nodelay(true);
                            let pool = pool.clone();
                            let router = router.clone();
                            let cfg = cfg.clone();
                            let rr_counter = rr_counter.clone();
                            let primary_server_names = primary_server_names.clone();
                            let cancel = cancel.clone();
                            let tracker = tracker.clone();

                            // 每条入站连接的数据任务纳入隧道追踪器：
                            // stop_tunnel 时会真正等待其结束，而非仅中止监听循环
                            tracker.spawn(async move {
                                tokio::select! {
                                    biased;
                                    // 取消优先：隧道停止时活跃数据流立即中断（drop 流即关闭连接）
                                    _ = cancel.cancelled() => {}
                                    _ = async {
                                        match handle_socks5_handshake(&mut inbound).await {
                                            Ok(target) => {
                                                let host = target.host();
                                                let port = target.port();

                                                // 读取当前路由引擎快照（热替换后对后续连接立即生效）
                                                let should_proxy = router.read().await.should_proxy(&host).await;
                                                if should_proxy {
                                                    debug!("通过代理请求 {}:{}", host, port);
                                                    if let Ok((_server, handle_arc)) = pick_connection(
                                                        &pool,
                                                        &cfg,
                                                        &rr_counter,
                                                        &primary_server_names,
                                                    )
                                                    .await
                                                    {
                                                        let channel_res = handle_arc
                                                            .channel_open_direct_tcpip(
                                                                &host,
                                                                port as u32,
                                                                "127.0.0.1",
                                                                0,
                                                            )
                                                            .await;
                                                        match channel_res {
                                                            Ok(channel) => {
                                                                let _ = send_socks5_reply(&mut inbound, true).await;
                                                                let mut stream = channel.into_stream();
                                                                let _guard = crate::metrics::ConnectionGuard::new();
                                                                if let Ok((tx, rx)) = crate::copy_bidirectional::copy_bidirectional_64k(&mut inbound, &mut stream).await {
                                                                    crate::metrics::add_bytes(tx, rx);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!(
                                                                    "请求 {}:{} 建立直连通道失败: {:?}",
                                                                    host, port, e
                                                                );
                                                                let _ =
                                                                    send_socks5_reply(&mut inbound, false).await;
                                                            }
                                                        }
                                                    } else {
                                                        let _ = send_socks5_reply(&mut inbound, false).await;
                                                    }
                                                } else {
                                                    debug!("直连请求 {}:{}", host, port);
                                                    if let Ok(outbound) =
                                                        tokio::net::TcpStream::connect((host.as_str(), port)).await
                                                    {
                                                        let _ = send_socks5_reply(&mut inbound, true).await;
                                                        let mut outbound = outbound;
                                                        let _guard = crate::metrics::ConnectionGuard::new();
                                                        if let Ok((tx, rx)) =
                                                            crate::copy_bidirectional::copy_bidirectional_64k(
                                                                &mut inbound,
                                                                &mut outbound,
                                                            )
                                                            .await
                                                        {
                                                            crate::metrics::add_bytes(tx, rx);
                                                        }
                                                    } else {
                                                        let _ = send_socks5_reply(&mut inbound, false).await;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("SOCKS5 握手失败: {}", e);
                                            }
                                        }
                                    } => {}
                                }
                            });
                        }
                    }
                }
            });
            handles.push(handle);
        }

        if handles.is_empty() {
            return Err(anyhow!("SOCKS5 隧道绑定地址失败（IPv4 与 IPv6 均失败）"));
        }
        Ok(handles)
    }

    /// 启动远程反向转发 (Remote Forwarding / 内网穿透)
    /// 主动通知远端代理服务器监听某端口，并将所有进入该端口的流量，反向沿着 SSH 通道拉回本地网络的目标地址
    async fn spawn_remote_tunnel(
        &self,
        config: TunnelConfig,
        cancel: CancellationToken,
    ) -> Result<Vec<JoinHandle<()>>> {
        if config.server_names.is_empty() {
            return Err(anyhow!("隧道未指定绑定的代理服务器"));
        }
        let remote_port = config.port as u32;
        let local_target = config
            .remote_addr
            .clone()
            .ok_or_else(|| anyhow!("远程隧道 (Remote) 必须配置目标地址 (remote_addr)"))?;
        let bind_address = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let server_names = config.server_names.clone();

        let pool = self.pool.clone();
        let tunnel_name = config.name.clone();

        // Remote failover：
        // - 同一时刻只有一个活动注册节点
        // - 节点不可用立即尝试下一节点（get_connection 内部有超时，不会长期阻塞）
        // - 断开后按序推进到下一节点；不因主节点恢复而主动回切
        let handle = tokio::spawn(async move {
            tokio::select! {
                biased;
                // 隧道停止：退出注册循环。此后任务无法再注册映射，
                // 远端端口由 stop_tunnel 通过 cancel_remote_forward 通知 sshd 释放并删除本地映射
                _ = cancel.cancelled() => {
                    log::info!("远程隧道 {} 已停止，退出反向转发注册循环", tunnel_name);
                }
                _ = async {
                    let mut idx = 0usize;
                    loop {
                        let name = server_names[idx % server_names.len()].clone();
                        idx += 1;

                        match pool.get_connection(&name).await {
                            Ok(handle_arc) => {
                                // 隧道级子令牌：随注册一并落入映射，stop_tunnel 取消隧道令牌
                                // （或注销映射）时，该映射的在途反向拷贝立即终止。
                                // 每轮注册使用新的子令牌：注销会取消其令牌，
                                // failover 换节点重注册时不得复用已取消的令牌
                                let fwd_token = cancel.child_token();
                                // 映射键含服务器名，跨节点同端口互不覆盖
                                pool.register_remote_forward(
                                    &name,
                                    remote_port,
                                    local_target.clone(),
                                    fwd_token,
                                )
                                .await;
                                match handle_arc.tcpip_forward(bind_address, remote_port).await {
                                    Ok(_) => {
                                        log::info!(
                                            "成功在远端 {} 注册反向端口穿透 (端口: {})",
                                            name,
                                            remote_port
                                        );
                                        // 阻塞等待，直到当前底层的 SSH 会话断开，再切换到下一节点
                                        while !handle_arc.is_closed() {
                                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                                        }
                                        log::warn!("节点 {} 的穿透会话已断开，切换到下一节点...", name);
                                    }
                                    Err(e) => {
                                        log::error!(
                                            "在节点 {} 注册端口 {} 失败 (可能被占用或无权限): {}",
                                            name,
                                            remote_port,
                                            e
                                        );
                                    }
                                }
                                pool.unregister_remote_forward(&name, remote_port).await;
                            }
                            Err(e) => {
                                log::warn!("节点 {} 不可用: {}，尝试下一节点", name, e);
                            }
                        }
                        // 节点间尝试间隔，避免全部不可用时高速空转
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    }
                } => {}
            }
        });

        Ok(vec![handle])
    }

    /// 启动 DNS 代理隧道 (DNS Proxy)
    /// 在本地开启一个 UDP 端口专门接收系统的 DNS 请求报文，随后根据具体的 DNS 隧道模式，
    /// 借助远端代理节点发起对 TCP DNS / DoT / DoH 服务器的隐秘解析请求，最后回传给系统
    async fn spawn_dns_tunnel(
        &self,
        config: TunnelConfig,
        cancel: CancellationToken,
        tracker: TaskTracker,
    ) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        // 缺省上游保持默认主机风格，端口按隧道类型选择：DNS→53、DoT→853、DoH→443
        let remote_addr = config.remote_addr.clone().unwrap_or_else(|| {
            match config.tunnel_type {
                TunnelType::DnsDot => "8.8.8.8:853",
                TunnelType::DnsDoh => "8.8.8.8:443",
                _ => "8.8.8.8:53",
            }
            .to_string()
        });
        let server_name = config.server_names.first().cloned();

        let dns_server = Arc::new(crate::dns::DnsServer::new());

        for ip in &[v4_ip, v6_ip] {
            let local_addr = format!("{}:{}", ip, config.port);
            let socket = match tokio::net::UdpSocket::bind(&local_addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    error!("绑定 DNS UDP 到 {}: {} 失败", local_addr, e);
                    continue;
                }
            };
            info!("在 {} 监听 DNS 隧道 {}", local_addr, config.name);

            let dns_server_clone = dns_server.clone();
            let remote_addr_clone = remote_addr.clone();
            let server_name_clone = server_name.clone();
            let pool_clone = self.pool.clone();
            let tunnel_type = config.tunnel_type.clone();
            let cancel = cancel.clone();
            let tracker = tracker.clone();

            let handle = tokio::spawn(async move {
                let _ = dns_server_clone
                    .run_server_with_socket(
                        socket.clone(),
                        remote_addr_clone,
                        server_name_clone,
                        pool_clone,
                        tunnel_type,
                        cancel,
                        tracker,
                    )
                    .await;
            });
            handles.push(handle);
        }

        if handles.is_empty() {
            return Err(anyhow!("DNS 隧道绑定地址失败（IPv4 与 IPv6 均失败）"));
        }
        Ok(handles)
    }
}

/// 解析传入的网络地址字符串，从中提取出目标主机（IP 或域名）和端口号。
/// 支持标准的 `IP:Port` 格式以及带中括号的 `[IPv6]:Port` 格式，如果未明确指定端口则使用提供的默认端口。
/// 显式指定的端口非法（非数字或超出 0-65535）时返回 Err，绝不静默回退默认端口。
pub fn parse_host_port(addr: &str, default_port: u32) -> Result<(String, u32)> {
    if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
        return Ok((socket_addr.ip().to_string(), socket_addr.port() as u32));
    }
    if addr.starts_with('[')
        && let Some(end) = addr.find(']')
    {
        let host = addr[1..end].to_string();
        if addr.len() > end + 1 && addr.as_bytes()[end + 1] == b':' {
            let port = parse_explicit_port(&addr[end + 2..])?;
            return Ok((host, port));
        }
        return Ok((host, default_port));
    }
    if addr.chars().filter(|&c| c == ':').count() > 1 {
        return Ok((addr.to_string(), default_port));
    }
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = parse_explicit_port(port_str)?;
        Ok((host.to_string(), port))
    } else {
        Ok((addr.to_string(), default_port))
    }
}

/// 解析显式指定的端口：非数字或大于 65535 均视为配置错误
fn parse_explicit_port(port_str: &str) -> Result<u32> {
    let port: u32 = port_str
        .parse()
        .map_err(|_| anyhow!("无效的端口号: {}", port_str))?;
    if port > 65535 {
        return Err(anyhow!("端口号超出范围 (0-65535): {}", port));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RouteMode, RoutingConfig, TunnelConfig, TunnelType};

    fn remote_tunnel_cfg(name: &str, servers: Vec<&str>, port: u16) -> TunnelConfig {
        TunnelConfig {
            name: name.to_string(),
            server_names: servers.into_iter().map(String::from).collect(),
            tunnel_type: TunnelType::Remote,
            port,
            remote_addr: Some("127.0.0.1:8000".to_string()),
            share_on_lan: false,
            primary: false,
            strategy: Default::default(),
        }
    }

    fn dynamic_tunnel_cfg(name: &str, servers: Vec<&str>, port: u16) -> TunnelConfig {
        TunnelConfig {
            name: name.to_string(),
            server_names: servers.into_iter().map(String::from).collect(),
            tunnel_type: TunnelType::Dynamic,
            port,
            remote_addr: None,
            share_on_lan: false,
            primary: false,
            strategy: Default::default(),
        }
    }

    /// primary 切换顺序敏感场景：新 primary 先启动、旧 primary 后停止，
    /// 主代理服务器列表必须仍指向新 primary，不得被误清空（跟随者失效缺陷）
    #[tokio::test]
    async fn primary_server_names_consistent_after_switch() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let mut p1 = dynamic_tunnel_cfg("p1", vec!["s1"], 0);
        p1.primary = true;
        let mut p2 = dynamic_tunnel_cfg("p2", vec!["s2"], 0);
        p2.primary = true;

        manager.start_tunnel(p1).await.unwrap();
        manager.start_tunnel(p2).await.unwrap();
        assert_eq!(
            manager.primary_server_names.read().await.clone(),
            vec!["s2".to_string()]
        );

        // 旧 primary 后停止：列表仍应指向新 primary
        manager.stop_tunnel("p1").await;
        assert_eq!(
            manager.primary_server_names.read().await.clone(),
            vec!["s2".to_string()],
            "停止旧 primary 不得清空新 primary 的节点列表"
        );

        // 最后一个 primary 停止后才清空
        manager.stop_tunnel("p2").await;
        assert!(
            manager.primary_server_names.read().await.is_empty(),
            "全部 primary 停止后列表应清空"
        );
    }

    /// 热加载切换 primary（old={primary A} → new={primary B}）：
    /// 无论 HashMap 遍历顺序如何，全部隧道提交后 primary_server_names 必须指向
    /// 新 primary B（不得被旧 primary A 的停止动作误清空），
    /// 且跟随主代理（server_names 为空）的 Dynamic 隧道保持运行可用
    #[tokio::test]
    async fn reload_primary_switch_keeps_follower_usable() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let mut old_primary = dynamic_tunnel_cfg("primary-a", vec!["s1"], 0);
        old_primary.primary = true;
        // 跟随主代理的 Dynamic 隧道：server_names 为空，选路时读 primary_server_names
        let follower = dynamic_tunnel_cfg("follower", vec![], 0);
        let old = vec![old_primary, follower.clone()];
        manager.start_tunnel(old[0].clone()).await.unwrap();
        manager.start_tunnel(follower.clone()).await.unwrap();
        assert_eq!(
            manager.primary_server_names.read().await.clone(),
            vec!["s1".to_string()]
        );

        let mut new_primary = dynamic_tunnel_cfg("primary-b", vec!["s2"], 0);
        new_primary.primary = true;
        // follower 配置未变化，必须原样保留（监听器与活跃连接不受影响）
        let new = vec![new_primary, follower];

        manager
            .reload_with_diff(&old, new, RoutingConfig::default(), String::new())
            .await
            .unwrap();

        // 最终主代理列表必须指向新 primary B
        assert_eq!(
            manager.primary_server_names.read().await.clone(),
            vec!["s2".to_string()],
            "切换 primary 后列表必须指向新 primary B，不得被旧 primary 停止动作误清空"
        );
        // 跟随隧道可用：仍运行，且主代理列表非空（选路有节点可取）
        let running = manager.running_tunnels().await;
        assert!(
            running.contains(&"follower".to_string()),
            "跟随主代理的隧道必须保持运行"
        );
        assert!(!running.contains(&"primary-a".to_string()));
        assert!(running.contains(&"primary-b".to_string()));
        assert!(
            !manager.primary_server_names.read().await.is_empty(),
            "跟随隧道选路所需的主代理列表不得为空"
        );
    }

    /// 热加载失败：已删除的隧道须回滚恢复，tunnel_configs_snapshot 须反映实际运行状态
    #[tokio::test]
    async fn reload_failure_restores_deleted_tunnel() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let old = vec![dynamic_tunnel_cfg("keep", vec!["s1"], 0)];
        manager.start_tunnel(old[0].clone()).await.unwrap();

        // 新配置：删除 keep，新增一个缺 remote_addr 的 Local 隧道（必然启动失败）
        let mut bad = dynamic_tunnel_cfg("bad", vec!["s1"], 0);
        bad.tunnel_type = TunnelType::Local;
        bad.remote_addr = None;
        let new = vec![bad];

        let result = manager
            .reload_with_diff(&old, new, RoutingConfig::default(), String::new())
            .await;
        assert!(result.is_err(), "存在启动失败必须返回 Err");

        // 回滚：已删除的 keep 应恢复运行，失败的 bad 不得残留
        let running = manager.running_tunnels().await;
        assert!(
            running.contains(&"keep".to_string()),
            "已删除隧道应回滚恢复"
        );
        assert!(!running.contains(&"bad".to_string()));

        // 快照必须与运行状态一致，可作下一轮 diff 的旧基线
        let snap = manager.tunnel_configs_snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "keep");
    }

    /// 热加载失败：本次已成功启动的新增隧道须回滚停止
    #[tokio::test]
    async fn reload_failure_stops_started_new_tunnels() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let old = vec![dynamic_tunnel_cfg("keep", vec!["s1"], 0)];
        manager.start_tunnel(old[0].clone()).await.unwrap();

        // 新配置：keep 不变，新增 added（可启动）与 bad（必然启动失败）
        let mut bad = dynamic_tunnel_cfg("bad", vec!["s1"], 0);
        bad.tunnel_type = TunnelType::Local;
        bad.remote_addr = None;
        let new = vec![dynamic_tunnel_cfg("added", vec!["s1"], 0), bad];

        let result = manager
            .reload_with_diff(&old, new, RoutingConfig::default(), String::new())
            .await;
        assert!(result.is_err(), "存在启动失败必须返回 Err");

        // 新增且启动成功的 added 必须被回滚停止，keep 不受影响
        let running = manager.running_tunnels().await;
        assert!(running.contains(&"keep".to_string()));
        assert!(
            !running.contains(&"added".to_string()),
            "本次新增且已启动的隧道在失败时必须回滚停止"
        );
    }

    /// 热加载失败必须撤销既有隧道的新配置：B 曾成功提升为 primary，
    /// 另一隧道失败后 B 应恢复旧配置，删除的旧 primary A 也应恢复，最终只有 A 是 primary
    #[tokio::test]
    async fn reload_failure_rolls_back_changed_primary() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let mut old_primary = dynamic_tunnel_cfg("primary-a", vec!["s1"], 0);
        old_primary.primary = true;
        let old_secondary = dynamic_tunnel_cfg("secondary-b", vec!["s2"], 0);
        let old = vec![old_primary, old_secondary];
        for cfg in &old {
            manager.start_tunnel(cfg.clone()).await.unwrap();
        }

        // 删除 A、把既有隧道 B 提升为 primary，同时加入必然启动失败的 bad
        let mut promoted = old[1].clone();
        promoted.primary = true;
        let mut bad = dynamic_tunnel_cfg("bad", vec!["s1"], 0);
        bad.tunnel_type = TunnelType::Local;
        bad.remote_addr = None;

        let result = manager
            .reload_with_diff(
                &old,
                vec![promoted, bad],
                RoutingConfig::default(),
                String::new(),
            )
            .await;
        assert!(result.is_err(), "存在启动失败必须返回 Err");

        let snapshot = manager.tunnel_configs_snapshot().await;
        assert_eq!(snapshot.len(), 2, "bad 不得残留，A 与 B 均应恢复");
        let primaries: Vec<_> = snapshot.iter().filter(|cfg| cfg.primary).collect();
        assert_eq!(primaries.len(), 1, "回滚后至多只能有一个 primary");
        assert_eq!(
            primaries[0].name, "primary-a",
            "生效 primary 必须是旧 primary A"
        );
        assert_eq!(
            manager.primary_name.lock().await.as_deref(),
            Some("primary-a"),
            "primary_name 必须与回滚后的配置一致"
        );
        assert_eq!(
            manager.primary_server_names.read().await.clone(),
            vec!["s1".to_string()],
            "主代理节点列表必须恢复为旧 primary A 的节点"
        );

        let restored_a = snapshot.iter().find(|cfg| cfg.name == "primary-a").unwrap();
        let restored_b = snapshot
            .iter()
            .find(|cfg| cfg.name == "secondary-b")
            .unwrap();
        assert_eq!(restored_a, &old[0], "A 必须按旧配置恢复");
        assert_eq!(restored_b, &old[1], "B 必须撤销本次提升并恢复完整旧配置");
    }

    /// 热加载全部成功：删除、新增、变化均按新配置生效
    #[tokio::test]
    async fn reload_success_applies_new_baseline() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, RoutingConfig::default(), String::new()).await;

        let old = vec![dynamic_tunnel_cfg("old", vec!["s1"], 0)];
        manager.start_tunnel(old[0].clone()).await.unwrap();

        let new = vec![dynamic_tunnel_cfg("fresh", vec!["s1"], 0)];
        manager
            .reload_with_diff(&old, new, RoutingConfig::default(), String::new())
            .await
            .unwrap();

        let running = manager.running_tunnels().await;
        assert!(!running.contains(&"old".to_string()));
        assert!(running.contains(&"fresh".to_string()));
    }

    /// 停止 Remote 隧道必须注销其远端端口映射（修复 abort 不触发 unregister 的残留缺陷）。
    /// 测试不启动真实隧道：直接向注册表插入"任务映射"，再经 stop_tunnel 验证映射被清除。
    #[tokio::test]
    async fn stop_remote_tunnel_clears_port_forwards() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        // 构造与真实路径一致的"运行中 Remote 隧道"状态：
        // port_forwards 里有映射 + tunnel_configs 里有配置 + tasks 里有占位任务
        pool.register_remote_forward(
            "srv_a",
            8080,
            "127.0.0.1:80".to_string(),
            CancellationToken::new(),
        )
        .await;
        pool.register_remote_forward(
            "srv_b",
            8080,
            "127.0.0.1:80".to_string(),
            CancellationToken::new(),
        )
        .await;
        let cfg = remote_tunnel_cfg("rt", vec!["srv_a", "srv_b"], 8080);
        manager
            .tunnel_configs
            .lock()
            .await
            .insert("rt".to_string(), cfg);
        manager.tasks.lock().await.insert(
            "rt".to_string(),
            TunnelTasks {
                handles: vec![tokio::spawn(async { std::future::pending::<()>().await })],
                token: CancellationToken::new(),
                tracker: TaskTracker::new(),
            },
        );

        // 与当前隧道无关的其他映射必须保留
        pool.register_remote_forward(
            "other",
            9090,
            "127.0.0.1:90".to_string(),
            CancellationToken::new(),
        )
        .await;

        manager.stop_tunnel("rt").await;

        let fwds = pool.remote_forwards_snapshot().await;
        let has = |k: (String, u32)| fwds.iter().any(|(kk, _)| kk == &k);
        assert!(!has(("srv_a".to_string(), 8080)), "srv_a 映射应被清除");
        assert!(!has(("srv_b".to_string(), 8080)), "srv_b 映射应被清除");
        assert!(has(("other".to_string(), 9090)), "无关隧道映射不得误删");
        // 配置表同步清除
        assert!(manager.tunnel_configs.lock().await.get("rt").is_none());
    }

    /// stop_tunnel 必须终止 Remote 隧道的在途反向拷贝（修复在途拷贝仅监听池级令牌、
    /// 不随 stop_tunnel 结束的缺陷）：拷贝任务监听映射中的隧道级令牌，
    /// 停止隧道取消隧道令牌时，子令牌随之触发，拷贝任务必须结束
    #[tokio::test]
    async fn stop_remote_tunnel_cancels_inflight_copy() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        // 构造与真实路径一致的"运行中 Remote 隧道"状态：
        // 隧道令牌派生子令牌随映射注册（与 spawn_remote_tunnel 一致）
        let tunnel_token = CancellationToken::new();
        let fwd_token = tunnel_token.child_token();
        pool.register_remote_forward("srv_a", 8080, "127.0.0.1:80".to_string(), fwd_token.clone())
            .await;
        let cfg = remote_tunnel_cfg("rt", vec!["srv_a"], 8080);
        manager
            .tunnel_configs
            .lock()
            .await
            .insert("rt".to_string(), cfg);
        manager.tasks.lock().await.insert(
            "rt".to_string(),
            TunnelTasks {
                handles: vec![tokio::spawn(async { std::future::pending::<()>().await })],
                token: tunnel_token,
                tracker: TaskTracker::new(),
            },
        );

        // 模拟在途拷贝任务：与 ClientHandler 反向回调一致地监听隧道级令牌
        let copy_task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = fwd_token.cancelled() => {}
                // 模拟永不自然结束的拷贝流
                _ = std::future::pending::<()>() => {}
            }
        });

        manager.stop_tunnel("rt").await;

        // stop_tunnel 返回后在途拷贝任务必须已收到取消并结束
        tokio::time::timeout(std::time::Duration::from_secs(3), copy_task)
            .await
            .expect("在途拷贝任务必须在 stop_tunnel 后结束")
            .expect("拷贝任务不应 panic");
        assert!(
            pool.remote_forwards_snapshot().await.is_empty(),
            "映射应被清除"
        );
    }

    /// stop_all 清理全部 Remote 映射
    #[tokio::test]
    async fn stop_all_clears_all_port_forwards() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        pool.register_remote_forward(
            "srv_a",
            8080,
            "127.0.0.1:80".to_string(),
            CancellationToken::new(),
        )
        .await;
        manager.tunnel_configs.lock().await.insert(
            "rt".to_string(),
            remote_tunnel_cfg("rt", vec!["srv_a"], 8080),
        );
        manager.tasks.lock().await.insert(
            "rt".to_string(),
            TunnelTasks {
                handles: vec![tokio::spawn(async { std::future::pending::<()>().await })],
                token: CancellationToken::new(),
                tracker: TaskTracker::new(),
            },
        );

        manager.stop_all().await;
        assert!(
            pool.remote_forwards_snapshot().await.is_empty(),
            "全部映射应清空"
        );
        assert!(
            manager.tunnel_configs.lock().await.is_empty(),
            "配置表应清空"
        );
    }

    /// 非 Remote 隧道停止不触碰映射表
    #[tokio::test]
    async fn stop_non_remote_tunnel_keeps_forwards() {
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        pool.register_remote_forward(
            "srv_a",
            8080,
            "127.0.0.1:80".to_string(),
            CancellationToken::new(),
        )
        .await;
        let mut cfg = remote_tunnel_cfg("lt", vec!["srv_a"], 8080);
        cfg.tunnel_type = TunnelType::Local; // 同键注册来自其他 Remote 隧道，本隧道为 Local
        manager
            .tunnel_configs
            .lock()
            .await
            .insert("lt".to_string(), cfg);
        manager.tasks.lock().await.insert(
            "lt".to_string(),
            TunnelTasks {
                handles: vec![tokio::spawn(async { std::future::pending::<()>().await })],
                token: CancellationToken::new(),
                tracker: TaskTracker::new(),
            },
        );

        manager.stop_tunnel("lt").await;
        let fwds = pool.remote_forwards_snapshot().await;
        assert!(
            fwds.iter().any(|(k, _)| k == &("srv_a".to_string(), 8080)),
            "Local 隧道停止不得清除 Remote 映射"
        );
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("google.com:80", 443).unwrap(),
            ("google.com".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("192.168.1.1", 443).unwrap(),
            ("192.168.1.1".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("[2402:4e00::]:53", 80).unwrap(),
            ("2402:4e00::".to_string(), 53)
        );
        // 不带端口的 IPv6 字面量整体作为主机名，使用默认端口
        assert_eq!(
            parse_host_port("2402:4e00::", 53).unwrap(),
            ("2402:4e00::".to_string(), 53)
        );
        // 显式端口非法或超范围必须返回 Err，不得静默回退默认端口
        assert!(parse_host_port("google.com:abc", 443).is_err());
        assert!(parse_host_port("google.com:70000", 443).is_err());
        assert!(parse_host_port("google.com:", 443).is_err());
        assert!(parse_host_port("[2402:4e00::]:99999", 80).is_err());
    }

    /// 探测一个空闲的本地 TCP 端口（先绑定获取端口号后释放，测试用途）
    fn free_local_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    }

    /// stop_tunnel 必须真正结束隧道派生的活跃连接任务，而非仅 abort 监听循环：
    /// 经 SOCKS5 握手建立一条真实双向流（直连本地 echo 服务器），
    /// stop_tunnel 返回后 tracker 必须清零，且客户端连接应被关闭（读到 EOF）
    #[tokio::test]
    async fn stop_tunnel_ends_active_connection_tasks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 本地 echo 服务器作为直连目标（路由模式 Direct，无需 SSH 连接池）
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = s.into_split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });

        // 全部直连：无需 SSH 连接池即可建立真实双向流
        let routing = RoutingConfig {
            mode: RouteMode::Direct,
            ..Default::default()
        };
        let pool = Arc::new(ServerPool::new(vec![]).unwrap());
        let manager = TunnelManager::new(pool, routing, String::new()).await;

        let tun_port = free_local_port();
        manager
            .start_tunnel(dynamic_tunnel_cfg("dyn", vec![], tun_port))
            .await
            .unwrap();

        // 白盒拿到隧道的 tracker，用于观察活跃连接任务
        let tracker = manager
            .tasks
            .lock()
            .await
            .get("dyn")
            .expect("隧道应已注册")
            .tracker
            .clone();

        // 客户端完成 SOCKS5 握手并 CONNECT 到 echo 服务器，形成真实双向流
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", tun_port))
            .await
            .unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting_reply = [0u8; 2];
        client.read_exact(&mut greeting_reply).await.unwrap();
        assert_eq!(greeting_reply, [0x05, 0x00]);
        let ip: std::net::Ipv4Addr = echo_addr.ip().to_string().parse().unwrap();
        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
        connect_req.extend_from_slice(&ip.octets());
        connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&connect_req).await.unwrap();
        let mut connect_reply = [0u8; 10];
        client.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(connect_reply[1], 0x00, "CONNECT 应成功");

        // 确认隧道已派生活跃连接任务（双向 copy 任务）
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while tracker.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("连接任务应被隧道 tracker 追踪");
        assert!(!tracker.is_empty());

        manager.stop_tunnel("dyn").await;

        // stop_tunnel 返回即代表活跃连接任务全部收尾：tracker 必须清零
        assert!(tracker.is_empty(), "stop_tunnel 后活跃连接任务应全部结束");
        // 客户端连接应被真正关闭（读到 EOF），而非继续挂起
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.read(&mut greeting_reply),
        )
        .await
        .expect("连接不应永久挂起")
        .unwrap();
        assert_eq!(n, 0, "隧道停止后客户端连接应被关闭");
    }
}
