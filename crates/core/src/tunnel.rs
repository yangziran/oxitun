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

/// 按隧道策略选择节点并取连接：
/// - failover：严格按 server_names 顺序，第一个可用者胜出
/// - round_robin：每个新入站连接从不同节点起步，故障时继续向后尝试
async fn pick_connection(
    pool: &Arc<ServerPool>,
    config: &TunnelConfig,
    rr_counter: &AtomicUsize,
) -> Result<(String, Arc<russh::client::Handle<ClientHandler>>)> {
    let names = &config.server_names;
    if names.is_empty() {
        return Err(anyhow!("隧道未指定绑定的代理服务器"));
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

/// 隧道生命周期管理器，负责不同类型的代理隧道（Local/Remote/SOCKS5/DNS）的启动、注册、维护和销毁
pub struct TunnelManager {
    pool: Arc<ServerPool>,
    /// 路由引擎（RwLock 支持热替换：路由规则变化时无需重启隧道任务）
    router: Arc<RwLock<Arc<Router>>>,
    /// 当前生效的路由配置副本（热加载 diff 用）
    routing_snapshot: Mutex<RoutingConfig>,
    /// 隧道任务表：键为隧道名（外部衍生任务归入 `__external__`）
    tasks: Mutex<HashMap<String, Vec<JoinHandle<()>>>>,
    /// 运行中隧道的配置副本：停止/删除 Remote 隧道时据此显式注销远端端口映射（abort 不走注销路径）
    tunnel_configs: Mutex<HashMap<String, TunnelConfig>>,
    /// 热加载互斥：同一时刻只允许一个 reload
    reload_lock: Mutex<()>,
}

impl TunnelManager {
    /// 初始化隧道管理器并挂载底层的 SSH 连接池和路由引擎
    pub async fn new(pool: Arc<ServerPool>, routing: RoutingConfig, chnroute_url: String) -> Self {
        Self {
            pool,
            router: Arc::new(RwLock::new(Arc::new(
                Router::new(routing.clone(), &chnroute_url).await,
            ))),
            routing_snapshot: Mutex::new(routing),
            tasks: Mutex::new(HashMap::new()),
            tunnel_configs: Mutex::new(HashMap::new()),
            reload_lock: Mutex::new(()),
        }
    }

    /// 根据传入的配置类型派发任务，启动对应的底层代理监听服务
    pub async fn start_tunnel(&self, config: TunnelConfig) -> Result<()> {
        let name = config.name.clone();
        let handles = match config.tunnel_type {
            TunnelType::Local => self.spawn_local_tunnel(config.clone()).await?,
            TunnelType::Dynamic => self.spawn_dynamic_tunnel(config.clone()).await?,
            TunnelType::Remote => self.spawn_remote_tunnel(config.clone()).await?,
            TunnelType::Dns | TunnelType::DnsDot | TunnelType::DnsDoh => {
                self.spawn_dns_tunnel(config.clone()).await?
            }
        };
        self.tasks.lock().await.insert(name.clone(), handles);
        self.tunnel_configs.lock().await.insert(name, config);
        Ok(())
    }

    /// 停止指定隧道（释放其监听端口；不触碰其他隧道）
    pub async fn stop_tunnel(&self, name: &str) {
        // 先按保存的配置显式注销 Remote 远端端口映射：
        // 任务被 abort 时 unregister 不会执行，不显式注销会导致 port_forwards 残留
        if let Some(cfg) = self.tunnel_configs.lock().await.remove(name)
            && cfg.tunnel_type == TunnelType::Remote
        {
            for server_name in &cfg.server_names {
                self.pool
                    .unregister_remote_forward(server_name, cfg.port as u32)
                    .await;
            }
        }
        let handles = self.tasks.lock().await.remove(name);
        if let Some(handles) = handles {
            for handle in handles {
                handle.abort();
                let _ = handle.await;
            }
            info!("隧道 {} 已停止", name);
        }
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

        // 停止已删除的隧道
        for name in old_map.keys() {
            if !new_map.contains_key(name) {
                info!("热加载：停止已删除的隧道 {}", name);
                self.stop_tunnel(name).await;
            }
        }

        // 新增或变化的隧道：先停旧再启新；启动失败时用旧配置回滚
        for (name, new_cfg) in &new_map {
            let changed = match old_map.get(name) {
                Some(old_cfg) => old_cfg != new_cfg,
                None => true,
            };
            if !changed {
                continue; // 未变化：监听器与活跃连接保持不动
            }
            info!("热加载：重启变化的隧道 {}", name);
            let old_cfg = old_map.get(name).cloned();
            self.stop_tunnel(name).await;
            if let Err(e) = self.start_tunnel(new_cfg.clone()).await {
                error!("热加载：隧道 {} 启动失败: {}", name, e);
                if let Some(old) = old_cfg {
                    log::warn!("热加载：尝试用旧配置回滚隧道 {}", name);
                    if let Err(e2) = self.start_tunnel(old).await {
                        error!("热加载：隧道 {} 回滚也失败: {}", name, e2);
                    }
                }
            }
        }
        Ok(())
    }

    /// 将外部衍生的异步协程任务（如后台定时更新路由表的任务）注册到管理器的生命周期中，
    /// 确保在调用 `stop_all` 时能够一并被平滑取消。
    pub async fn add_task(&self, handle: JoinHandle<()>) {
        self.tasks
            .lock()
            .await
            .entry(EXTERNAL_TASKS_KEY.to_string())
            .or_default()
            .push(handle);
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
        let mut tasks = self.tasks.lock().await;
        let mut join_handles = vec![];
        for (_, handles) in tasks.drain() {
            for task in handles {
                task.abort();
                join_handles.push(task);
            }
        }
        for task in join_handles {
            let _ = task.await;
        }
        self.pool.disconnect_all().await;
        info!("所有活跃隧道已停止工作。");
    }

    /// 启动本地端口转发 (Local Forwarding)
    /// 会监听本地指定端口，并将接收到的所有流量透明地借助 SSH 通道发送至 `remote_addr`
    async fn spawn_local_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
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

            let handle = tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let _ = inbound.set_nodelay(true);

                    let pool = pool.clone();
                    let cfg = cfg.clone();
                    let remote_addr = remote_addr.clone();
                    let rr_counter = rr_counter.clone();

                    tokio::spawn(async move {
                        if let Ok((_server, handle_arc)) =
                            pick_connection(&pool, &cfg, &rr_counter).await
                        {
                            let (host, port) = parse_host_port(&remote_addr, 80);
                            {
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
                        }
                    });
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
    async fn spawn_dynamic_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

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
            info!("在 {} 监听 SOCKS5 隧道 {}", local_addr, config.name);

            let pool = self.pool.clone();
            let router = self.router.clone();
            let cfg = config.clone();
            let rr_counter = rr_counter.clone();

            let handle = tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let _ = inbound.set_nodelay(true);
                    let pool = pool.clone();
                    let router = router.clone();
                    let cfg = cfg.clone();
                    let rr_counter = rr_counter.clone();

                    tokio::spawn(async move {
                        match handle_socks5_handshake(&mut inbound).await {
                            Ok(target) => {
                                let host = target.host();
                                let port = target.port();

                                // 读取当前路由引擎快照（热替换后对后续连接立即生效）
                                let should_proxy = router.read().await.should_proxy(&host).await;
                                if should_proxy {
                                    debug!("通过代理请求 {}:{}", host, port);
                                    if let Ok((_server, handle_arc)) =
                                        pick_connection(&pool, &cfg, &rr_counter).await
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
                    });
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
    async fn spawn_remote_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
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

        // Remote failover：
        // - 同一时刻只有一个活动注册节点
        // - 节点不可用立即尝试下一节点（get_connection 内部有超时，不会长期阻塞）
        // - 断开后按序推进到下一节点；不因主节点恢复而主动回切
        let handle = tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let name = server_names[idx % server_names.len()].clone();
                idx += 1;

                match pool.get_connection(&name).await {
                    Ok(handle_arc) => {
                        // 映射键含服务器名，跨节点同端口互不覆盖
                        pool.register_remote_forward(&name, remote_port, local_target.clone())
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
        });

        Ok(vec![handle])
    }

    /// 启动 DNS 代理隧道 (DNS Proxy)
    /// 在本地开启一个 UDP 端口专门接收系统的 DNS 请求报文，随后根据具体的 DNS 隧道模式，
    /// 借助远端代理节点发起对 TCP DNS / DoT / DoH 服务器的隐秘解析请求，最后回传给系统
    async fn spawn_dns_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let remote_addr = config
            .remote_addr
            .unwrap_or_else(|| "8.8.8.8:53".to_string());
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

            let handle = tokio::spawn(async move {
                let _ = dns_server_clone
                    .run_server_with_socket(
                        socket.clone(),
                        remote_addr_clone,
                        server_name_clone,
                        pool_clone,
                        tunnel_type,
                    )
                    .await;
            });
            handles.push(handle);
        }

        Ok(handles)
    }
}

/// 解析传入的网络地址字符串，从中提取出目标主机（IP 或域名）和端口号。
/// 支持标准的 `IP:Port` 格式以及带中括号的 `[IPv6]:Port` 格式，如果未明确指定端口则使用提供的默认端口。
pub fn parse_host_port(addr: &str, default_port: u32) -> (String, u32) {
    if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
        return (socket_addr.ip().to_string(), socket_addr.port() as u32);
    }
    if addr.starts_with('[')
        && let Some(end) = addr.find(']')
    {
        let host = addr[1..end].to_string();
        if addr.len() > end + 1 && addr.as_bytes()[end + 1] == b':' {
            let port = addr[end + 2..].parse().unwrap_or(default_port);
            return (host, port);
        }
        return (host, default_port);
    }
    if addr.chars().filter(|&c| c == ':').count() > 1 {
        return (addr.to_string(), default_port);
    }
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(default_port);
        (host.to_string(), port)
    } else {
        (addr.to_string(), default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RoutingConfig, TunnelConfig, TunnelType};

    fn remote_tunnel_cfg(name: &str, servers: Vec<&str>, port: u16) -> TunnelConfig {
        TunnelConfig {
            name: name.to_string(),
            server_names: servers.into_iter().map(String::from).collect(),
            tunnel_type: TunnelType::Remote,
            port,
            remote_addr: Some("127.0.0.1:8000".to_string()),
            share_on_lan: false,
            strategy: Default::default(),
        }
    }

    /// 停止 Remote 隧道必须注销其远端端口映射（修复 abort 不触发 unregister 的残留缺陷）。
    /// 测试不启动真实隧道：直接向注册表插入"任务映射"，再经 stop_tunnel 验证映射被清除。
    #[tokio::test]
    async fn stop_remote_tunnel_clears_port_forwards() {
        let pool = Arc::new(ServerPool::new(vec![]));
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        // 构造与真实路径一致的"运行中 Remote 隧道"状态：
        // port_forwards 里有映射 + tunnel_configs 里有配置 + tasks 里有占位任务
        pool.register_remote_forward("srv_a", 8080, "127.0.0.1:80".to_string())
            .await;
        pool.register_remote_forward("srv_b", 8080, "127.0.0.1:80".to_string())
            .await;
        let cfg = remote_tunnel_cfg("rt", vec!["srv_a", "srv_b"], 8080);
        manager
            .tunnel_configs
            .lock()
            .await
            .insert("rt".to_string(), cfg);
        manager.tasks.lock().await.insert(
            "rt".to_string(),
            vec![tokio::spawn(async { std::future::pending::<()>().await })],
        );

        // 与当前隧道无关的其他映射必须保留
        pool.register_remote_forward("other", 9090, "127.0.0.1:90".to_string())
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

    /// stop_all 清理全部 Remote 映射
    #[tokio::test]
    async fn stop_all_clears_all_port_forwards() {
        let pool = Arc::new(ServerPool::new(vec![]));
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        pool.register_remote_forward("srv_a", 8080, "127.0.0.1:80".to_string())
            .await;
        manager.tunnel_configs.lock().await.insert(
            "rt".to_string(),
            remote_tunnel_cfg("rt", vec!["srv_a"], 8080),
        );
        manager.tasks.lock().await.insert(
            "rt".to_string(),
            vec![tokio::spawn(async { std::future::pending::<()>().await })],
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
        let pool = Arc::new(ServerPool::new(vec![]));
        let manager =
            TunnelManager::new(pool.clone(), RoutingConfig::default(), String::new()).await;

        pool.register_remote_forward("srv_a", 8080, "127.0.0.1:80".to_string())
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
            vec![tokio::spawn(async { std::future::pending::<()>().await })],
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
            parse_host_port("google.com:80", 443),
            ("google.com".to_string(), 80)
        );
        assert_eq!(
            parse_host_port("192.168.1.1", 443),
            ("192.168.1.1".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("[2402:4e00::]:53", 80),
            ("2402:4e00::".to_string(), 53)
        );
    }
}
