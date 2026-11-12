use crate::config::ServerConfig;
use crate::host_key::{HostKeyBroker, PendingHostKey};
use crate::known_hosts::KnownHostsStore;
use anyhow::Result;
use russh::client::{self, Handler};
use russh::keys::{HashAlg, PublicKeyOrCertificate, decode_secret_key, key::PrivateKeyWithHashAlg};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// 主机密钥确认等待超时时间（秒）
const HOST_KEY_TIMEOUT_SECS: u64 = 300;
/// 单次 cancel-tcpip-forward 等待服务端响应的超时时间（秒）
const CANCEL_REMOTE_FORWARD_TIMEOUT_SECS: u64 = 10;

/// 测试门控：entered 通知已进入临界点前，release 控制何时继续。
#[cfg(test)]
#[derive(Clone)]
struct TestGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl TestGate {
    fn new() -> Self {
        Self {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

/// 反向端口映射项：转发目标地址 + 隧道级取消令牌。
/// 令牌由隧道任务在注册时下发（隧道令牌的子令牌）：stop_tunnel 取消隧道令牌
/// 或注销映射时，该映射派生的在途反向拷贝任务立即终止，
/// 避免热加载改变 remote_addr 后旧拷贝仍向旧目标转发
#[derive(Clone)]
pub struct RemoteForward {
    /// 反向流量的本地转发目标（host:port）
    pub target: String,
    /// 隧道级取消令牌：取消即终止该映射的全部在途拷贝
    pub cancel: CancellationToken,
}

#[derive(Clone)]
/// 异步 SSH 客户端处理器
/// 实现 `russh::client::Handler` trait，负责主机密钥 TOFU 校验与远端反向连接（Remote Port Forwarding）的底层事件
pub struct ClientHandler {
    /// 反向端口映射表：键为 (服务器名, 远端端口)
    pub port_forwards: Arc<RwLock<HashMap<(String, u32), RemoteForward>>>,
    /// 所属服务器名称（反向回调时定位映射）
    pub server_name: String,
    /// 目标服务器主机与端口（用于 known_hosts 规范化键）
    pub host: String,
    pub port: u16,
    /// 是否严格校验主机密钥（false 为显式不安全模式）
    pub strict_host_key: bool,
    /// 配置中预置的主机密钥指纹（无人值守部署路径）
    pub preset_host_key: Option<String>,
    /// TOFU 信任存储
    pub known_hosts: Arc<KnownHostsStore>,
    /// 首连确认协调器
    pub broker: HostKeyBroker,
    /// 全局取消令牌（由连接池注入）：整池停止时在途反向转发数据拷贝一并退出
    pub cancel_token: CancellationToken,
    /// 测试注入：缩短单次主机密钥等待，避免测试真实等待 300 秒。
    #[cfg(test)]
    test_host_key_timeout: Option<std::time::Duration>,
    /// 测试注入：在超时清理前暂停，确定性覆盖请求被替换的竞态。
    #[cfg(test)]
    test_host_key_timeout_gate: Option<TestGate>,
}

impl ClientHandler {
    /// 计算服务器公钥的 OpenSSH 风格 SHA256 指纹（形如 `SHA256:xxxx`，无填充）
    fn fingerprint_of(server_public_key: &PublicKeyOrCertificate) -> (String, String) {
        let key = server_public_key.public_key();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        let key_type = key.algorithm().to_string();
        (fingerprint, key_type)
    }
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // 显式不安全模式：跳过校验但持续告警
        if !self.strict_host_key {
            log::warn!(
                "{}:{} 已配置 strict_host_key=false，跳过主机密钥校验（存在中间人攻击风险）",
                self.host,
                self.port
            );
            return Ok(true);
        }

        let (fingerprint, key_type) = Self::fingerprint_of(server_public_key);

        // 1. 配置预置指纹：匹配则信任并持久化，不匹配视同指纹变化拒绝
        if let Some(preset) = &self.preset_host_key {
            if preset.trim() == fingerprint {
                let _ = self
                    .known_hosts
                    .trust(&self.host, self.port, &key_type, &fingerprint);
                return Ok(true);
            }
            log::error!(
                "{}:{} 主机密钥与预置指纹不匹配！期望 {}，实际 {}",
                self.host,
                self.port,
                preset,
                fingerprint
            );
            return Err(russh::Error::KeyChanged { line: 0 });
        }

        // 2. known_hosts 已有记录：一致通过，不一致拒绝（绝不自动覆盖）
        if let Some(known) = self.known_hosts.lookup(&self.host, self.port) {
            if known.fingerprint == fingerprint {
                return Ok(true);
            }
            log::error!(
                "{}:{} 主机密钥发生变化！已记录 {}，当前 {}。可能存在中间人攻击，连接已拒绝。",
                self.host,
                self.port,
                known.fingerprint,
                fingerprint
            );
            return Err(russh::Error::KeyChanged { line: 0 });
        }

        // 3. 首次连接：无人值守（无交互监听者）时明确失败并引导预置指纹
        if !self.broker.has_subscribers() {
            log::error!(
                "首次连接 {}:{} 需要确认主机密钥 {}，但当前无交互界面可确认。请在配置中预置 host_key: \"{}\" 后重试。",
                self.host,
                self.port,
                fingerprint,
                fingerprint
            );
            return Err(russh::Error::UnknownKey);
        }

        // 4. 挂起握手，等待用户决策（同一主机并发请求自动去重）。
        // 保存 request_id：超时清理必须精确命中本请求，不能误删同主机的新请求。
        let info = PendingHostKey {
            host: self.host.clone(),
            port: self.port,
            key_type: key_type.clone(),
            fingerprint: fingerprint.clone(),
            request_id: String::new(),
        };
        let (mut decision_rx, request_id, _is_new) = match self.broker.request(info) {
            Ok(v) => v,
            Err(existing) => {
                // 同一主机已有不同指纹/类型的待确认请求：严禁搭车复用他人决策，
                // 直接拒绝本次连接（可能是中间人攻击或密钥轮换）
                log::warn!(
                    "拒绝连接 {}:{}：已有不同指纹的待确认请求（等待中: {}，本次: {}）",
                    self.host,
                    self.port,
                    existing.fingerprint,
                    fingerprint
                );
                return Err(russh::Error::UnknownKey);
            }
        };
        #[cfg(test)]
        let host_key_timeout = self
            .test_host_key_timeout
            .unwrap_or(std::time::Duration::from_secs(HOST_KEY_TIMEOUT_SECS));
        #[cfg(not(test))]
        let host_key_timeout = std::time::Duration::from_secs(HOST_KEY_TIMEOUT_SECS);
        let wait = decision_rx.wait_for(|v| v.is_some());
        // 立即复制 watch 引用中的值，避免非 Send 的 Ref 跨超时清理门控持有。
        let decision = tokio::time::timeout(host_key_timeout, wait)
            .await
            .map(|result| result.map(|value| *value));
        let accepted = match decision {
            Ok(Ok(v)) => v.unwrap_or(false),
            _ => {
                // 测试在超时后、清理前暂停，使用户决策可以先移除 A 并建立替代请求 B。
                #[cfg(test)]
                if let Some(gate) = &self.test_host_key_timeout_gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
                // 仅清理本次 request_id；若 A 已被移除，缺失 ID 返回 false 且不影响 B。
                self.broker.resolve_by_id(&request_id, false);
                false
            }
        };

        if accepted {
            log::info!(
                "用户已信任 {}:{} 的主机密钥 {}",
                self.host,
                self.port,
                fingerprint
            );
            // 持久化失败仅告警不放任静默：本次会话内存已信任，连接可继续，
            // 但重启后需重新确认（避免把磁盘写失败误判为连接失败）
            if let Err(e) = self
                .known_hosts
                .trust(&self.host, self.port, &key_type, &fingerprint)
            {
                log::warn!("主机密钥信任记录持久化失败（本次会话仍信任）: {}", e);
            }
            Ok(true)
        } else {
            log::warn!(
                "用户拒绝或超时未确认 {}:{} 的主机密钥 {}",
                self.host,
                self.port,
                fingerprint
            );
            Err(russh::Error::UnknownKey)
        }
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let fwd = {
            let fwds = self.port_forwards.read().await;
            fwds.get(&(self.server_name.clone(), connected_port))
                .cloned()
        };
        if let Some(fwd) = fwd {
            reply.accept().await;
            // 隧道级取消令牌：stop_tunnel 停止对应 Remote 隧道时在途拷贝立即终止
            let tunnel_cancel = fwd.cancel.clone();
            // 池级全局令牌兜底：stop_all/整池断开时在途的反向转发数据拷贝一并退出
            let pool_cancel = self.cancel_token.clone();
            let target = fwd.target.clone();
            tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = tunnel_cancel.cancelled() => {}
                    _ = pool_cancel.cancelled() => {}
                    _ = async {
                        if let Ok(mut local_stream) = tokio::net::TcpStream::connect(&target).await {
                            let mut stream = channel.into_stream();
                            let _ = crate::copy_bidirectional::copy_bidirectional_64k(
                                &mut local_stream,
                                &mut stream,
                            )
                            .await;
                        }
                    } => {}
                }
            });
        }
        Ok(())
    }
}

/// 高可用 SSH 代理服务器连接池
/// 负责管理多节点的 SSH 会话连接、并发轮询调度 (Round-Robin) 和断线自动重连机制
/// 连接组状态机
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupState {
    /// 正在建立/重建连接
    Connecting,
    /// 至少有一条可用连接
    Ready,
    /// 终态失败（认证失败/主机密钥问题等），自动重建需谨慎
    Failed(String),
}

/// 单个服务器的连接组：句柄列表 + 重建互斥锁 + 状态
struct ServerGroup {
    handles: RwLock<Vec<Arc<russh::client::Handle<ClientHandler>>>>,
    /// 重建互斥：并发请求只会触发一次真实重建（锁内双检）
    rebuild_lock: tokio::sync::Mutex<()>,
    state: std::sync::RwLock<GroupState>,
    /// 期望池大小（初始为 pool_size；重建部分失败时仍按此补齐缺失槽位）
    desired_size: std::sync::RwLock<usize>,
    /// 防止重复 spawn 后台补池任务
    healing: std::sync::atomic::AtomicBool,
    /// 关闭标志：disconnect_all/热更新移除该组时置位，
    /// 在途重建/补池发布新句柄前必须检查，避免向已脱离的组写入连接
    closed: AtomicBool,
}

impl ServerGroup {
    fn new() -> Self {
        Self {
            handles: RwLock::new(Vec::new()),
            rebuild_lock: tokio::sync::Mutex::new(()),
            state: std::sync::RwLock::new(GroupState::Connecting),
            desired_size: std::sync::RwLock::new(0),
            healing: std::sync::atomic::AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    fn set_state(&self, state: GroupState) {
        *self.state.write().expect("group state lock") = state;
    }
}

/// 高可用 SSH 代理服务器连接池
/// 负责管理多节点的 SSH 会话连接、并发轮询调度 (Round-Robin) 和断线自动重连机制
pub struct ServerPool {
    /// 维护服务器名称到连接组的映射关系
    groups: RwLock<HashMap<String, Arc<ServerGroup>>>,
    /// 存储各个服务器的具体连接配置，供重连时使用（RwLock 支持热加载更新）
    configs: RwLock<HashMap<String, ServerConfig>>,
    /// 原子计数器，用于实现无锁的 Round-Robin 会话分发
    counter: AtomicUsize,
    /// 反向端口映射表：键为 (服务器名, 远端端口)，避免跨服务器同端口互相覆盖；
    /// 值含隧道级取消令牌，stop_tunnel/注销时终止在途拷贝
    port_forwards: Arc<RwLock<HashMap<(String, u32), RemoteForward>>>,
    /// TOFU 主机密钥信任存储
    known_hosts: Arc<KnownHostsStore>,
    /// 首连主机密钥确认协调器
    broker: HostKeyBroker,
    /// 整池重建次数（可观测性与测试用）
    rebuild_count: AtomicUsize,
    /// 全局 shutdown 代际：disconnect_all/热更新移除连接组时递增。
    /// 在途重建/补池开头读取代际，发布句柄前复查：代际已变化说明结果已过期，必须丢弃
    shutdown_gen: AtomicUsize,
    /// 生命周期互斥：代际变更、关闭/移除连接组与句柄发布必须串行，
    /// 防止代际校验通过后、句柄写入或返回前连接组被并发关闭。
    lifecycle: tokio::sync::Mutex<()>,
    /// 全局取消令牌（由 TunnelManager 注入，仅启动时写入一次）：stop_all/整池断开时
    /// 中断在途的反向转发数据拷贝等池内衍生任务
    cancellation_token: std::sync::RwLock<CancellationToken>,
    /// 测试注入：替换底层建连实现（失败计数/门控在途建连），仅测试构建存在。
    /// 生产路径恒为 None，create_connection 直接走真实建连
    #[cfg(test)]
    test_connector: std::sync::Mutex<Option<TestConnectorFn>>,
    /// 测试注入：建连完成后的首次代际校验与最终发布之间暂停。
    #[cfg(test)]
    test_publish_gate: std::sync::Mutex<Option<TestGate>>,
}

impl ServerPool {
    /// 利用指定的服务器配置列表，初始化连接池引擎（known_hosts 使用默认路径）。
    /// 打开失败（如文件损坏）返回 Err：绝不静默降级到临时空存储，
    /// 否则既有信任约束失效、指纹变化会被误判为首次连接
    pub fn new(servers: Vec<ServerConfig>) -> Result<Self, anyhow::Error> {
        Self::with_known_hosts_path(servers, KnownHostsStore::default_path())
    }

    /// 指定 known_hosts 存储路径（测试与自定义部署使用）。
    /// 打开失败返回 Err（含修复路径提示），由调用方决定失败策略
    pub fn with_known_hosts_path(
        servers: Vec<ServerConfig>,
        known_hosts_path: std::path::PathBuf,
    ) -> Result<Self, anyhow::Error> {
        // open_shared：同进程内同路径复用同一实例，保证运行池、测试池、GUI
        // 管理实例内存视图一致，lookup 立即可见，无需重启或重载同步
        let known_hosts = KnownHostsStore::open_shared(known_hosts_path.clone()).map_err(|e| {
            anyhow::anyhow!(
                "打开主机密钥信任存储（known_hosts）失败: {e}\n\
                 路径: {}\n\
                 该文件可能已损坏，请修复或删除后重试（删除后首次连接需重新确认主机密钥）",
                known_hosts_path.display()
            )
        })?;
        let mut configs = HashMap::new();
        for server in servers {
            configs.insert(server.name.clone(), server);
        }
        Ok(Self {
            groups: RwLock::new(HashMap::new()),
            configs: RwLock::new(configs),
            counter: AtomicUsize::new(0),
            port_forwards: Arc::new(RwLock::new(HashMap::new())),
            known_hosts,
            broker: HostKeyBroker::new(),
            rebuild_count: AtomicUsize::new(0),
            shutdown_gen: AtomicUsize::new(0),
            lifecycle: tokio::sync::Mutex::new(()),
            cancellation_token: std::sync::RwLock::new(CancellationToken::new()),
            #[cfg(test)]
            test_connector: std::sync::Mutex::new(None),
            #[cfg(test)]
            test_publish_gate: std::sync::Mutex::new(None),
        })
    }

    /// 获取主机密钥确认协调器（GUI/CLI 用于监听待确认请求与提交决策）
    pub fn broker(&self) -> HostKeyBroker {
        self.broker.clone()
    }

    /// 获取 known_hosts 存储（用于查看/清除信任记录）
    pub fn known_hosts(&self) -> Arc<KnownHostsStore> {
        self.known_hosts.clone()
    }

    /// 注入全局取消令牌（TunnelManager::new 调用）：
    /// stop_all/整池断开时，连接池内衍生的反向转发数据任务监听该令牌一并退出
    pub fn set_cancellation_token(&self, token: CancellationToken) {
        *self
            .cancellation_token
            .write()
            .expect("cancellation token lock") = token;
    }

    /// 断开并清理全局所有受控的 SSH 会话连接与反向端口映射
    pub async fn disconnect_all(&self) {
        // 与所有句柄发布路径共用生命周期锁：代际递增、关闭、清组和映射注销
        // 必须作为一个整体执行，不能在发布校验与写入/返回之间插入。
        let _lifecycle = self.lifecycle.lock().await;
        self.broker.reject_all();
        // 递增代际使在途重建/补池的结果过期
        self.shutdown_gen.fetch_add(1, Ordering::Relaxed);
        let mut groups = self.groups.write().await;
        // 先标记关闭再清空：在途重建/补池发布新句柄前会据此丢弃，
        // 不会向已脱离池的组写入新连接
        for g in groups.values() {
            g.closed.store(true, Ordering::Relaxed);
        }
        groups.clear();
        // 清空映射并取消其隧道令牌：整池断开时在途反向拷贝随映射注销而终止
        for (_, fwd) in self.port_forwards.write().await.drain() {
            fwd.cancel.cancel();
        }
        log::info!("已关闭所有 SSH 连接。");
    }

    /// 查询某服务器连接组的当前状态（可观测性）
    pub async fn group_state(&self, name: &str) -> GroupState {
        let groups = self.groups.read().await;
        match groups.get(name) {
            Some(g) => g.state.read().expect("group state lock").clone(),
            None => GroupState::Connecting,
        }
    }

    /// 整池重建次数（可观测性与测试用）
    pub fn rebuild_count(&self) -> usize {
        self.rebuild_count.load(Ordering::Relaxed)
    }

    /// 热加载：对比新旧服务器配置，未变化的连接组保留复用，变化/删除的组关闭并移除
    ///
    /// 语义：仅配置内容变化的组被重建；其余组及其活跃连接不受影响。
    pub async fn update_servers(&self, new_servers: Vec<ServerConfig>) {
        // 热更新与 disconnect_all 使用同一互斥，不得插入句柄发布临界区。
        let _lifecycle = self.lifecycle.lock().await;
        let mut new_map: HashMap<String, ServerConfig> = HashMap::new();
        for s in new_servers {
            new_map.insert(s.name.clone(), s);
        }

        // 代际递增：配置变化期间的在途重建/补池结果一律丢弃
        self.shutdown_gen.fetch_add(1, Ordering::Relaxed);
        let mut configs = self.configs.write().await;
        let mut groups = self.groups.write().await;

        // 删除或变化的组：关闭旧连接（句柄释放后 SSH 会话随之断开）
        let old_names: Vec<String> = configs.keys().cloned().collect();
        for name in old_names {
            match new_map.get(&name) {
                Some(new_cfg) if Some(new_cfg) == configs.get(&name) => {
                    // 未变化：保留
                }
                _ => {
                    log::info!("热加载：服务器 {} 配置已变化或被移除，关闭其连接池", name);
                    // 先标记关闭再移除：在途重建/补池不会向已脱离的组写入新句柄
                    if let Some(g) = groups.remove(&name) {
                        g.closed.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
        // 移除配置中已删除的服务器映射
        configs.retain(|name, _| new_map.contains_key(name));
        // 合并新配置（新增或更新）
        for (name, cfg) in new_map {
            configs.insert(name, cfg);
        }
    }

    /// 获取或创建某服务器的连接组
    async fn get_group(&self, name: &str) -> Result<Arc<ServerGroup>> {
        if !self.configs.read().await.contains_key(name) {
            return Err(anyhow::anyhow!("在配置中未找到服务器 {}", name));
        }
        {
            let groups = self.groups.read().await;
            if let Some(g) = groups.get(name) {
                return Ok(g.clone());
            }
        }
        let mut groups = self.groups.write().await;
        Ok(groups
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(ServerGroup::new()))
            .clone())
    }

    /// 在句柄列表中按 Round-Robin 找一条存活连接；返回 (命中句柄, 是否存在死连接)
    fn pick_alive(
        &self,
        handles: &[Arc<russh::client::Handle<ClientHandler>>],
    ) -> (Option<Arc<russh::client::Handle<ClientHandler>>>, bool) {
        if handles.is_empty() {
            return (None, false);
        }
        let mut has_dead = false;
        for _ in 0..handles.len() {
            let idx = self.counter.fetch_add(1, Ordering::Relaxed) % handles.len();
            if handles[idx].is_closed() {
                has_dead = true;
                continue;
            }
            return (Some(handles[idx].clone()), has_dead);
        }
        (None, true)
    }

    /// 从连接池中获取一个可用的 SSH 会话句柄
    ///
    /// 行为：
    /// - 快路径：跳过死亡连接直接返回存活连接；发现死连接则触发后台补池
    /// - 全部失效：持 per-server 互斥锁重建，锁内双检保证并发只重建一次
    pub async fn get_connection(
        self: &Arc<Self>,
        name: &str,
    ) -> Result<Arc<russh::client::Handle<ClientHandler>>> {
        self.get_connection_inner(name, &mut Vec::new()).await
    }

    /// ProxyJump 递归入口；因递归调用需返回 boxed future
    ///
    /// visited 语义为「当前递归路径」：进入节点 push、返回前 pop（含错误路径），
    /// 每次顶层建连以空 visited 开始，因此无环链路的多次顺序建连不会误报循环
    fn get_connection_inner<'a>(
        self: &'a Arc<Self>,
        name: &'a str,
        visited: &'a mut Vec<String>,
    ) -> BoxedConnectionFuture<'a> {
        Box::pin(async move {
            enter_jump_path(visited, name)?;
            let result = self.get_connection_on_path(name, visited).await;
            leave_jump_path(visited);
            result
        })
    }

    /// 在当前跳板路径上获取或重建连接（调用前 visited 已包含 name）
    async fn get_connection_on_path(
        self: &Arc<Self>,
        name: &str,
        visited: &mut Vec<String>,
    ) -> Result<Arc<russh::client::Handle<ClientHandler>>> {
        // 记录进入时的全局代际：本次取连接期间若发生 disconnect_all/热更新，
        // 即使拿到存活句柄也不得返回（句柄属于已脱离池的组）
        let entry_gen = self.shutdown_gen.load(Ordering::Relaxed);

        // 可能拿到刚被 disconnect_all/热更新标记关闭、但尚未从表中移除的旧组：
        // 短暂让出等待移除后重新获取全新组（关闭组绝不可复用）
        let group = loop {
            let g = self.get_group(name).await?;
            if !g.closed.load(Ordering::Relaxed) {
                break g;
            }
            tokio::task::yield_now().await;
        };

        // 快路径：不持重建锁
        {
            let handles = group.handles.read().await;
            let (hit, has_dead) = self.pick_alive(&handles);
            if let Some(handle) = hit {
                if has_dead {
                    self.spawn_heal(name, group.clone());
                }
                // 先释放 handles 读锁，再按统一顺序获取生命周期锁，避免与补池写路径死锁。
                drop(handles);
                // 校验与返回必须和关闭/移除连接组互斥，防止旧句柄越过 disconnect_all 流出。
                let _lifecycle = self.lifecycle.lock().await;
                if group.closed.load(Ordering::Relaxed)
                    || entry_gen != self.shutdown_gen.load(Ordering::Relaxed)
                {
                    return Err(anyhow::anyhow!("连接池已关闭"));
                }
                return Ok(handle);
            }
        }

        // 慢路径：整池重建（互斥 + 双检）
        let _permit = group.rebuild_lock.lock().await;
        {
            let handles = group.handles.read().await;
            if let (Some(handle), _) = self.pick_alive(&handles) {
                drop(handles);
                // 与快路径同一语义：等锁期间池被断开/热更新则不得返回旧句柄。
                let _lifecycle = self.lifecycle.lock().await;
                if group.closed.load(Ordering::Relaxed)
                    || entry_gen != self.shutdown_gen.load(Ordering::Relaxed)
                {
                    return Err(anyhow::anyhow!("连接池已关闭"));
                }
                return Ok(handle);
            }
        }

        group.set_state(GroupState::Connecting);
        // 热更新可能在 get_group 校验后、此处读取前删除该配置：
        // 不得 expect panic，向上传播错误由调用方按普通失败处理
        let config = match self.configs.read().await.get(name).cloned() {
            Some(c) => c,
            None => {
                return Err(anyhow::anyhow!("服务器 {} 的配置在重建期间已被移除", name));
            }
        };
        let pool_size = (config.pool_size as usize).max(1);
        // 记录期望池大小：部分成功时后台补池按此补齐缺失槽位
        *group.desired_size.write().expect("desired size lock") = pool_size;
        // 记录当前代际：建连期间若发生 disconnect_all/热更新，结果必须丢弃
        let start_gen = self.shutdown_gen.load(Ordering::Relaxed);
        self.rebuild_count.fetch_add(1, Ordering::Relaxed);
        crate::metrics::inc_pool_rebuild();
        log::info!("正在为 {} 建立 SSH 连接池 (大小为 {})...", name, pool_size);

        let mut new_handles = Vec::with_capacity(pool_size);
        let mut last_err = None;
        for i in 0..pool_size {
            match self.create_connection(&config, visited).await {
                Ok(handle) => new_handles.push(Arc::new(handle)),
                Err(e) => {
                    log::warn!(
                        "建立针对 {} 的 SSH 会话 {}/{} 失败: {}，跳过此连接",
                        name,
                        i + 1,
                        pool_size,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        if new_handles.is_empty() {
            let msg = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| format!("为 {} 建立 SSH 连接池失败", name));
            group.set_state(GroupState::Failed(msg.clone()));
            return Err(anyhow::anyhow!(msg));
        }

        let publish_expired = || {
            group.closed.load(Ordering::Relaxed)
                || start_gen != self.shutdown_gen.load(Ordering::Relaxed)
        };
        // 先在锁外快速丢弃已过期结果；最终发布时还必须持生命周期锁复查。
        if publish_expired() {
            log::warn!("连接池已关闭或已热更新，丢弃服务器 {} 的新建句柄", name);
            return Err(anyhow::anyhow!("连接池已关闭"));
        }

        // 测试在此暂停，覆盖“首次校验通过后、最终发布前关闭池”的竞态窗口。
        #[cfg(test)]
        let publish_gate = self
            .test_publish_gate
            .lock()
            .expect("test publish gate lock")
            .clone();
        #[cfg(test)]
        if let Some(gate) = publish_gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }

        // 最终校验、写 handles 和返回 picked 与 disconnect_all/update_servers 串行。
        // 任一方先取得锁即先完成，另一方随后能看到明确的代际或已发布状态。
        let _lifecycle = self.lifecycle.lock().await;
        if publish_expired() {
            log::warn!("连接池已关闭或已热更新，丢弃服务器 {} 的新建句柄", name);
            return Err(anyhow::anyhow!("连接池已关闭"));
        }
        if new_handles.len() < pool_size {
            log::warn!(
                "针对 {} 的连接池降级运行：成功 {}/{}",
                name,
                new_handles.len(),
                pool_size
            );
        } else {
            log::info!("针对 {} 的 SSH 连接池建立成功。", name);
        }
        group.set_state(GroupState::Ready);
        let published = new_handles.len();
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % published;
        let picked = new_handles[idx].clone();
        *group.handles.write().await = new_handles;
        // 部分重建成功：缺失槽位永不触发快路径 has_dead，必须后台补池补齐
        if published < pool_size {
            self.spawn_heal(name, group.clone());
        }
        Ok(picked)
    }

    /// 后台补池：重建死连接槽位并补齐缺失槽位（与整池重建分离；走完整建连逻辑含跳板）
    fn spawn_heal(self: &Arc<Self>, name: &str, group: Arc<ServerGroup>) {
        if group.healing.swap(true, Ordering::Relaxed) {
            return; // 已有补池任务在运行（healing 标志防止重复 spawn）
        }
        let pool = self.clone();
        let name_owned = name.to_string();
        tokio::spawn(async move {
            pool.heal_loop(&name_owned, &group).await;
            // 补池彻底结束（补齐或组已关闭）后复位 healing 标志，允许后续死连接再次触发补池
            group.healing.store(false, Ordering::Relaxed);
        });
    }

    /// 补池主循环：一轮未补齐时按指数退避重试（1s/2s/4s/8s…上限 30s），
    /// 避免对故障节点持续重试形成风暴；组被关闭/配置移除时立即停止
    async fn heal_loop(self: &Arc<Self>, name: &str, group: &Arc<ServerGroup>) {
        let mut backoff = std::time::Duration::from_secs(1);
        while !group.closed.load(Ordering::Relaxed) {
            if self.heal_dead_slots(name, group).await {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
        }
    }

    /// 重建组内所有死连接槽位，并在末尾追加补齐缺失槽位直到 desired_size
    ///
    /// 返回 true 表示已补齐或无需再补（配置移除/组关闭），调用方停止退避重试；
    /// 返回 false 表示仍有槽位缺失，需要下一轮退避重试。
    /// 网络建连期间不持有 handles 写锁：先快照死槽位下标，逐条建连完成后
    /// 再短暂获取写锁替换，避免阻塞正常读路径
    async fn heal_dead_slots(self: &Arc<Self>, name: &str, group: &Arc<ServerGroup>) -> bool {
        // 配置可能已被热更新移除：无需再补
        let config = match self.configs.read().await.get(name) {
            Some(c) => c.clone(),
            None => return true,
        };
        // 与整池重建互斥，避免并发重复建连
        let _permit = group.rebuild_lock.lock().await;
        if group.closed.load(Ordering::Relaxed) {
            return true; // 组已脱离连接池，立即停止补池
        }
        // 记录代际：逐条建连完成后复查，过期结果一律丢弃
        let start_gen = self.shutdown_gen.load(Ordering::Relaxed);
        let expired = |group: &ServerGroup, start_gen: usize, pool: &ServerPool| {
            group.closed.load(Ordering::Relaxed)
                || start_gen != pool.shutdown_gen.load(Ordering::Relaxed)
        };
        // 快照死槽位下标（仅短暂持读锁）
        let dead_slots: Vec<usize> = {
            let handles = group.handles.read().await;
            handles
                .iter()
                .enumerate()
                .filter(|(_, h)| h.is_closed())
                .map(|(i, _)| i)
                .collect()
        };
        let mut healed = 0usize;
        for idx in dead_slots {
            // 补池从本服务器开始新的跳板链
            match self
                .create_connection(&config, &mut vec![name.to_string()])
                .await
            {
                Ok(new_handle) => {
                    let new_handle = Arc::new(new_handle);
                    // 代际复查与死槽位替换必须和关闭/清组互斥，防止校验后旧组被移除。
                    let _lifecycle = self.lifecycle.lock().await;
                    if expired(group, start_gen, self) {
                        drop(new_handle);
                        return true;
                    }
                    // 若槽位已被并发重建为存活连接，则丢弃多余句柄，不覆盖可用连接。
                    let mut handles = group.handles.write().await;
                    if handles.get(idx).is_some_and(|h| h.is_closed()) {
                        handles[idx] = new_handle;
                        healed += 1;
                        crate::metrics::inc_reconnect();
                    }
                }
                Err(e) => {
                    log::warn!("补池：重建 {} 的死连接失败: {}", name, e);
                }
            }
        }
        // 缺失槽位（部分重建失败的遗留）：在末尾追加补齐直到 desired_size
        let deficit = {
            let desired = *group.desired_size.read().expect("desired size lock");
            let handles = group.handles.read().await;
            desired.saturating_sub(handles.len())
        };
        for _ in 0..deficit {
            match self
                .create_connection(&config, &mut vec![name.to_string()])
                .await
            {
                Ok(new_handle) => {
                    let new_handle = Arc::new(new_handle);
                    // 追加缺失槽位同样必须在生命周期锁内复查后再提交。
                    let _lifecycle = self.lifecycle.lock().await;
                    if expired(group, start_gen, self) {
                        drop(new_handle);
                        return true;
                    }
                    let mut handles = group.handles.write().await;
                    handles.push(new_handle);
                    healed += 1;
                    crate::metrics::inc_reconnect();
                }
                Err(e) => {
                    log::warn!("补池：为 {} 追加缺失槽位失败: {}", name, e);
                }
            }
        }
        if healed > 0 {
            log::info!("补池：已为 {} 重建/补齐 {} 条连接", name, healed);
        }
        // 按存活句柄数判定补齐：死槽位重建全部失败时死句柄仍占位 Vec，
        // 若以 len 判定会把占位误判为补齐、heal_loop 退出后死槽位不再自动重试；
        // 死句柄占位不计入，未补齐则交由主循环退避重试
        let desired = *group.desired_size.read().expect("desired size lock");
        let alive = group
            .handles
            .read()
            .await
            .iter()
            .filter(|h| !h.is_closed())
            .count();
        alive >= desired
    }

    /// 注册远端反向端口映射（键含服务器名，跨服务器同端口互不覆盖）。
    /// cancel 为隧道级取消令牌（隧道任务令牌的子令牌）：隧道停止或映射注销时
    /// 取消它即可终止该映射的全部在途反向拷贝。覆盖同键旧注册时同步取消旧令牌，
    /// 避免旧隧道的在途拷贝泄漏
    pub async fn register_remote_forward(
        &self,
        server_name: &str,
        port: u32,
        target: String,
        cancel: CancellationToken,
    ) {
        let old = self.port_forwards.write().await.insert(
            (server_name.to_string(), port),
            RemoteForward { target, cancel },
        );
        if let Some(old) = old {
            old.cancel.cancel();
        }
    }

    /// 注销某服务器的远端端口映射（隧道停止/重载时调用）；
    /// 同时取消其隧道令牌，终止该映射的在途反向拷贝
    pub async fn unregister_remote_forward(&self, server_name: &str, port: u32) {
        let old = self
            .port_forwards
            .write()
            .await
            .remove(&(server_name.to_string(), port));
        if let Some(old) = old {
            old.cancel.cancel();
        }
    }

    /// 停止 Remote 反向隧道时调用：向 SSH 服务端发送 cancel-tcpip-forward 释放远端端口，
    /// 然后删除本地 port_forwards 映射。
    ///
    /// 停止路径上只读组内句柄快照、绝不触发 get_connection 重建（拆隧道时不得反向建连）。
    /// tcpip-forward 注册时的 bind 地址（"0.0.0.0"/"127.0.0.1"）池内未记录，
    /// 且转发只挂在其中一条会话上，因此逐条存活会话 × 逐个候选地址尝试：
    /// 不匹配的 cancel 仅被服务端拒绝（request-failure），连接不受影响。
    ///
    /// 容错语义：句柄不存在/全部已断开时跳过网络通知，仅删本地映射并告警——
    /// 会话已断则 sshd 会随连接关闭释放监听，但本地映射绝不允许残留，
    /// 否则已停止的隧道仍被反向回调引用。cancel 请求失败时同样删映射（仅告警），
    /// 避免停止路径上残留指向死隧道的映射。
    pub async fn cancel_remote_forward(&self, server_name: &str, port: u32) -> anyhow::Result<()> {
        // 快照组内全部存活句柄（短暂持读锁）
        let alive: Vec<Arc<russh::client::Handle<ClientHandler>>> = {
            let groups = self.groups.read().await;
            match groups.get(server_name) {
                Some(g) => {
                    let handles = g.handles.read().await;
                    handles.iter().filter(|h| !h.is_closed()).cloned().collect()
                }
                None => Vec::new(),
            }
        };

        if alive.is_empty() {
            log::warn!(
                "服务器 {} 无存活 SSH 句柄，跳过 cancel-tcpip-forward，仅删除本地端口 {} 映射",
                server_name,
                port
            );
            self.unregister_remote_forward(server_name, port).await;
            return Ok(());
        }

        let mut last_err: Option<anyhow::Error> = None;
        for handle in &alive {
            for addr in ["0.0.0.0", "127.0.0.1"] {
                // russh 会等待服务端 global request 响应；服务端不回包时必须限时退出。
                // Handle 无法 mock，超时网络路径由逻辑审查覆盖，无句柄容错路径由单元测试覆盖。
                match tokio::time::timeout(
                    std::time::Duration::from_secs(CANCEL_REMOTE_FORWARD_TIMEOUT_SECS),
                    handle.cancel_tcpip_forward(addr, port),
                )
                .await
                {
                    Ok(Ok(())) => {
                        log::info!(
                            "已向 {} 发送 cancel-tcpip-forward (地址 {}, 端口 {})",
                            server_name,
                            addr,
                            port
                        );
                        self.unregister_remote_forward(server_name, port).await;
                        return Ok(());
                    }
                    Ok(Err(e)) => last_err = Some(e.into()),
                    Err(_) => {
                        let err = anyhow::anyhow!(
                            "cancel-tcpip-forward 等待服务端响应超过 {} 秒",
                            CANCEL_REMOTE_FORWARD_TIMEOUT_SECS
                        );
                        log::warn!(
                            "向 {} 发送 cancel-tcpip-forward (地址 {}, 端口 {}) 超时，继续尝试其他地址或句柄",
                            server_name,
                            addr,
                            port
                        );
                        last_err = Some(err);
                    }
                }
            }
        }
        // 全部尝试失败：远端监听可能已随会话断开释放，本地映射仍必须清除（不得残留）
        let err = last_err.unwrap_or_else(|| anyhow::anyhow!("无可用句柄"));
        log::warn!(
            "向 {} 发送 cancel-tcpip-forward (端口 {}) 失败: {}；仍删除本地映射",
            server_name,
            port,
            err
        );
        self.unregister_remote_forward(server_name, port).await;
        Err(err)
    }

    /// 当前远端端口映射快照（诊断/测试用，仅含目标地址）
    pub async fn remote_forwards_snapshot(&self) -> Vec<((String, u32), String)> {
        self.port_forwards
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.target.clone()))
            .collect()
    }

    /// 建立单条 SSH 会话；配置含 jump_host 时经跳板节点嵌套建立（逐跳独立 TOFU 校验）
    ///
    /// 测试构建下若注入了 test_connector（模拟失败/门控在途建连）则优先走注入逻辑，
    /// 未注入时与生产路径一致走真实建连
    async fn create_connection(
        self: &Arc<Self>,
        config: &ServerConfig,
        visited: &mut Vec<String>,
    ) -> Result<russh::client::Handle<ClientHandler>> {
        #[cfg(test)]
        let hook = self
            .test_connector
            .lock()
            .expect("test connector lock")
            .clone();
        #[cfg(test)]
        if let Some(hook) = hook {
            return hook(config).await;
        }
        self.create_connection_inner(config, visited).await
    }

    /// create_connection 的真实建连实现。
    /// 测试注入的 hook 委托到此函数完成真实建连（不会再次被注入逻辑拦截）
    async fn create_connection_inner(
        self: &Arc<Self>,
        config: &ServerConfig,
        visited: &mut Vec<String>,
    ) -> Result<russh::client::Handle<ClientHandler>> {
        let russh_config = russh::client::Config {
            nodelay: true,
            keepalive_interval: if config.keep_alive_interval > 0 {
                Some(std::time::Duration::from_secs(config.keep_alive_interval))
            } else {
                None
            },
            ..Default::default()
        };
        let host = config.host.clone();
        let port = config.port;
        let handler = ClientHandler {
            port_forwards: self.port_forwards.clone(),
            server_name: config.name.clone(),
            host: host.clone(),
            port,
            strict_host_key: config.strict_host_key,
            preset_host_key: config.host_key.clone().filter(|s| !s.trim().is_empty()),
            known_hosts: self.known_hosts.clone(),
            broker: self.broker.clone(),
            #[cfg(test)]
            test_host_key_timeout: None,
            #[cfg(test)]
            test_host_key_timeout_gate: None,
            cancel_token: self
                .cancellation_token
                .read()
                .expect("cancellation token lock")
                .clone(),
        };

        let timeout_secs = config.timeout_seconds as u64;
        let jump_host = config.jump_host.clone().filter(|s| !s.trim().is_empty());

        let mut session = if let Some(jump_name) = jump_host {
            // ProxyJump：先取得跳板连接（递归，含完整 TOFU 与循环检测），再开 direct-tcpip 通道
            log::info!("经跳板 {} 连接到 {}:{}", jump_name, host, port);
            let jump_handle = self.get_connection_inner(&jump_name, visited).await?;
            let channel = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                jump_handle.channel_open_direct_tcpip(&host, port as u32, "127.0.0.1", 0),
            )
            .await
            .map_err(|_| anyhow::anyhow!("经跳板 {} 建立通道超时", jump_name))?
            .map_err(|e| anyhow::anyhow!("经跳板 {} 建立通道失败: {}", jump_name, e))?;
            let stream = channel.into_stream();
            handshake_stream(russh_config, stream, handler, timeout_secs).await?
        } else {
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                tokio::net::TcpStream::connect((host.as_str(), port)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(anyhow::anyhow!("TCP 连接错误: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("SSH 连接超时")),
            };
            let _ = stream.set_nodelay(true);
            handshake_stream(russh_config, stream, handler, timeout_secs).await?
        };

        // 认证过程
        let key_path_opt = config.key_path.as_deref().filter(|s| !s.trim().is_empty());
        let pwd_opt = config.password.as_deref().filter(|s| !s.trim().is_empty());
        let auth_type = config
            .auth_type
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let use_key = match auth_type {
            Some("password") => false,
            Some("key") => true,
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "不支持的认证方式 {}，仅支持 password 或 key",
                    other
                ));
            }
            None => key_path_opt.is_some(),
        };

        let auth_res = if use_key {
            let key_path =
                key_path_opt.ok_or_else(|| anyhow::anyhow!("私钥认证未提供 key_path"))?;
            let key_path = expand_home_path(key_path)?;
            let key_str = tokio::fs::read_to_string(&key_path)
                .await
                .map_err(|e| anyhow::anyhow!("读取私钥失败 {}: {}", key_path.display(), e))?;
            let key = decode_secret_key(&key_str, pwd_opt)
                .map_err(|e| anyhow::anyhow!("解析私钥失败: {}", e))?;
            let key_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            // 认证同样受 timeout_seconds 约束，避免对端挂起导致建连永久阻塞
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                session.authenticate_publickey(&config.user, key_alg),
            )
            .await
            .map_err(|_| anyhow::anyhow!("SSH 私钥认证超时（{} 秒）", timeout_secs))??
        } else {
            let pwd = pwd_opt.ok_or_else(|| anyhow::anyhow!("密码认证未提供 password"))?;
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                session.authenticate_password(&config.user, pwd),
            )
            .await
            .map_err(|_| anyhow::anyhow!("SSH 密码认证超时（{} 秒）", timeout_secs))??
        };

        if !auth_res.success() {
            return Err(anyhow::anyhow!("身份认证失败"));
        }

        Ok(session)
    }
}

fn expand_home_path(path: &str) -> Result<std::path::PathBuf> {
    if path == "~" {
        return dirs::home_dir().ok_or_else(|| anyhow::anyhow!("无法确定用户主目录"));
    }
    if let Some(relative) = path.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("无法确定用户主目录"))?;
        return Ok(home.join(relative));
    }
    Ok(std::path::PathBuf::from(path))
}

/// 连接获取的 boxed future 类型（ProxyJump 递归用）
type BoxedConnectionFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<Arc<russh::client::Handle<ClientHandler>>>>
            + Send
            + 'a,
    >,
>;

/// 测试注入的建连函数（仅测试构建）：用于模拟建连失败计数、门控在途建连等场景，
/// 便于确定性验证补池与关闭代际语义
#[cfg(test)]
type TestConnectorFn = Arc<
    dyn Fn(
            &ServerConfig,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<russh::client::Handle<ClientHandler>>>
                    + Send,
            >,
        > + Send
        + Sync,
>;

/// 进入跳板路径节点：已在当前路径中则报告循环，否则 push
/// （与 leave_jump_path 配对，visited 仅表示「当前递归路径」）
fn enter_jump_path(visited: &mut Vec<String>, name: &str) -> Result<()> {
    if visited.iter().any(|v| v == name) {
        return Err(anyhow::anyhow!(
            "检测到 ProxyJump 跳板循环: {} -> {}",
            visited.join(" -> "),
            name
        ));
    }
    visited.push(name.to_string());
    Ok(())
}

/// 离开跳板路径节点（与 enter_jump_path 配对，含错误返回路径也必须调用）
fn leave_jump_path(visited: &mut Vec<String>) {
    visited.pop();
}

/// 在任意字节流上完成 SSH 握手（TCP 直连或跳板通道通用），带超时
///
/// 外层超时取 `timeout_secs + HOST_KEY_TIMEOUT_SECS` 作为兜底：
/// connect_stream 内部包含主机密钥 TOFU 用户确认等待（check_server_key 自带
/// HOST_KEY_TIMEOUT_SECS=300 秒超时），若外层仅用 timeout_secs（默认 15 秒），
/// 用户实际确认窗口会被压缩到十几秒。网络握手阶段本身通常远快于 timeout_secs，
/// 取两者之和既保证 TOFU 交互可用满 300 秒，网络异常挂起最终仍会超时返回。
async fn handshake_stream<S>(
    russh_config: russh::client::Config,
    stream: S,
    handler: ClientHandler,
    timeout_secs: u64,
) -> Result<russh::client::Handle<ClientHandler>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs + HOST_KEY_TIMEOUT_SECS),
        client::connect_stream(Arc::new(russh_config), stream, handler),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(anyhow::anyhow!("SSH 握手错误: {}", e)),
        Err(_) => Err(anyhow::anyhow!("SSH 握手超时")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    #[test]
    fn private_key_path_expands_home_directory() {
        let home = dirs::home_dir().expect("测试需要用户主目录");
        assert_eq!(
            expand_home_path("~/.ssh/id_rsa").unwrap(),
            home.join(".ssh/id_rsa")
        );
        assert_eq!(
            expand_home_path("/tmp/id_rsa").unwrap(),
            std::path::PathBuf::from("/tmp/id_rsa")
        );
    }

    /// 生成一对随机密钥的公钥视图（模拟服务器出示的主机密钥）
    fn server_key() -> PublicKeyOrCertificate {
        let mut rng = russh::keys::key::safe_rng();
        let private = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        PublicKeyOrCertificate::PublicKey {
            key: private.public_key().clone(),
            hash_alg: None,
        }
    }

    fn fingerprint_of(key: &PublicKeyOrCertificate) -> String {
        key.public_key().fingerprint(HashAlg::Sha256).to_string()
    }

    struct HandlerFixture {
        handler: ClientHandler,
        _dir: tempfile::TempDir,
    }

    fn make_handler(strict: bool, preset: Option<String>) -> HandlerFixture {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::open(dir.path().join("kh.json")).unwrap();
        HandlerFixture {
            handler: ClientHandler {
                port_forwards: Arc::new(RwLock::new(HashMap::new())),
                server_name: "test-server".to_string(),
                host: "Test.Host".to_string(),
                port: 22,
                strict_host_key: strict,
                preset_host_key: preset,
                known_hosts: Arc::new(store),
                broker: HostKeyBroker::new(),
                test_host_key_timeout: None,
                test_host_key_timeout_gate: None,
                cancel_token: CancellationToken::new(),
            },
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn known_matching_fingerprint_passes() {
        let key = server_key();
        let fp = fingerprint_of(&key);
        let mut fx = make_handler(true, None);
        fx.handler
            .known_hosts
            .trust("test.host", 22, "ssh-ed25519", &fp)
            .unwrap();
        assert!(fx.handler.check_server_key(&key).await.unwrap());
    }

    #[tokio::test]
    async fn changed_fingerprint_is_rejected() {
        let key = server_key();
        let mut fx = make_handler(true, None);
        fx.handler
            .known_hosts
            .trust("test.host", 22, "ssh-ed25519", "SHA256:old")
            .unwrap();
        let err = fx.handler.check_server_key(&key).await.unwrap_err();
        assert!(matches!(err, russh::Error::KeyChanged { .. }));
    }

    #[tokio::test]
    async fn unknown_host_headless_fails_with_guidance() {
        let key = server_key();
        let mut fx = make_handler(true, None);
        // 无订阅者（无人值守）：必须明确失败，不得挂起
        let err = fx.handler.check_server_key(&key).await.unwrap_err();
        assert!(matches!(err, russh::Error::UnknownKey));
    }

    #[tokio::test]
    async fn first_connect_trusted_by_user_is_persisted() {
        let key = server_key();
        let fp = fingerprint_of(&key);
        let mut fx = make_handler(true, None);
        let broker = fx.handler.broker.clone();
        let mut sub = broker.subscribe();

        let known_hosts = fx.handler.known_hosts.clone();
        let check = tokio::spawn(async move { fx.handler.check_server_key(&key).await });
        // 等待 pending 事件并信任
        let pending = tokio::time::timeout(std::time::Duration::from_secs(2), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.fingerprint, fp);
        assert!(!pending.request_id.is_empty(), "事件必须携带 request_id");
        // 决策必须携带事件中的 request_id：host/port 不再是决策身份
        assert!(broker.resolve_by_id(&pending.request_id, true));

        assert!(check.await.unwrap().unwrap());
        // 信任已持久化到 known_hosts（主机名已规范化为小写）
        let saved = known_hosts
            .lookup("TEST.HOST", 22)
            .expect("信任记录应已写入存储");
        assert_eq!(saved.fingerprint, fp);
        assert_eq!(saved.key_type, "ssh-ed25519");
        assert!(broker.pending_list().is_empty(), "信任后 pending 必须清理");
    }

    #[tokio::test]
    async fn first_connect_rejected_by_user_fails() {
        let key = server_key();
        let mut fx = make_handler(true, None);
        let broker = fx.handler.broker.clone();
        let _sub = broker.subscribe();

        let check = tokio::spawn(async move { fx.handler.check_server_key(&key).await });
        // 等 pending 出现后，用其 request_id 拒绝
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let pending = broker.pending_list().pop().expect("应存在待确认请求");
        assert!(broker.resolve_by_id(&pending.request_id, false));

        let err = check.await.unwrap().unwrap_err();
        assert!(matches!(err, russh::Error::UnknownKey));
        assert!(broker.pending_list().is_empty(), "拒绝后 pending 必须清理");
    }

    #[tokio::test]
    async fn stale_host_key_timeout_does_not_reject_replacement_request() {
        let private =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let HandlerFixture {
            handler: mut a_handler,
            _dir: _a_dir,
        } = make_handler(true, None);
        let broker = a_handler.broker.clone();
        let _sub = broker.subscribe();
        let gate = TestGate::new();
        a_handler.test_host_key_timeout = Some(std::time::Duration::from_millis(50));
        a_handler.test_host_key_timeout_gate = Some(gate.clone());

        let a_key = PublicKeyOrCertificate::PublicKey {
            key: private.public_key().clone(),
            hash_alg: None,
        };
        let a_task = tokio::spawn(async move { a_handler.check_server_key(&a_key).await });
        // A 已进入超时清理分支，但尚未删除任何 pending。
        tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("A 应在测试超时后进入清理门控");
        let pending_a = broker.pending_list().pop().expect("A 应仍在等待清理");
        assert!(broker.resolve_by_id(&pending_a.request_id, false));

        // A 被用户决策移除后，同主机、同密钥建立替代请求 B。
        let HandlerFixture {
            handler: mut b_handler,
            _dir: _b_dir,
        } = make_handler(true, None);
        b_handler.broker = broker.clone();
        let b_key = PublicKeyOrCertificate::PublicKey {
            key: private.public_key().clone(),
            hash_alg: None,
        };
        let b_task = tokio::spawn(async move { b_handler.check_server_key(&b_key).await });
        let a_id = pending_a.request_id.clone();
        let pending_b = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(pending) = broker
                    .pending_list()
                    .into_iter()
                    .find(|pending| pending.request_id != a_id)
                {
                    break pending;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("B 应建立新的待确认请求");
        assert_ne!(pending_a.request_id, pending_b.request_id);

        // 放行 A 的旧超时清理：按 host/port 清理会误拒 B，按 request_id 则无副作用。
        gate.release.notify_one();
        let a_err = a_task.await.unwrap().unwrap_err();
        assert!(matches!(a_err, russh::Error::UnknownKey));
        let remaining = broker.pending_list();
        assert_eq!(remaining.len(), 1, "A 的超时清理不得删除 B");
        assert_eq!(remaining[0].request_id, pending_b.request_id);
        assert!(!b_task.is_finished(), "B 不应被 A 的旧超时唤醒并拒绝");

        assert!(broker.resolve_by_id(&pending_b.request_id, true));
        assert!(b_task.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn preset_fingerprint_match_passes_and_mismatch_rejects() {
        let key = server_key();
        let fp = fingerprint_of(&key);

        let mut ok_fx = make_handler(true, Some(fp.clone()));
        assert!(ok_fx.handler.check_server_key(&key).await.unwrap());

        let mut bad_fx = make_handler(true, Some("SHA256:wrong".to_string()));
        let err = bad_fx.handler.check_server_key(&key).await.unwrap_err();
        assert!(matches!(err, russh::Error::KeyChanged { .. }));
    }

    #[tokio::test]
    async fn insecure_mode_skips_verification() {
        let key = server_key();
        let mut fx = make_handler(false, None);
        assert!(fx.handler.check_server_key(&key).await.unwrap());
    }

    fn dummy_server_config(name: &str) -> ServerConfig {
        ServerConfig {
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port: 1, // 不可达，用于不依赖网络的测试
            user: "u".to_string(),
            auth_type: None,
            password: Some("p".to_string()),
            key_path: None,
            encrypted: None,
            pool_size: 2,
            keep_alive_interval: 3,
            timeout_seconds: 1,
            strict_host_key: true,
            host_key: None,
            jump_host: None,
        }
    }

    #[test]
    fn visited_path_allows_sequential_rebuilds_without_false_cycle() {
        // 同一 visited 缓冲顺序完成两次 A->B 建连：每条建连路径结束后节点已弹出，
        // 第二次进入 B 不得被误判为循环（修复前 visited 只 push 不 pop，
        // pool_size=2 的第二条连接会误报循环）
        let mut visited = Vec::new();
        for _ in 0..2 {
            enter_jump_path(&mut visited, "a").unwrap();
            enter_jump_path(&mut visited, "b").unwrap();
            leave_jump_path(&mut visited); // b
            leave_jump_path(&mut visited); // a
        }
        assert!(visited.is_empty(), "建连路径结束后 visited 必须为空");
    }

    #[test]
    fn visited_path_detects_true_cycle() {
        // 真正的循环 A->B->A 仍必须被检出
        let mut visited = Vec::new();
        enter_jump_path(&mut visited, "a").unwrap();
        enter_jump_path(&mut visited, "b").unwrap();
        let err = enter_jump_path(&mut visited, "a").unwrap_err();
        assert!(err.to_string().contains("循环"));
    }

    #[tokio::test]
    async fn proxyjump_cycle_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        // a -> b -> a 循环
        let mut a = dummy_server_config("a");
        a.jump_host = Some("b".to_string());
        let mut b = dummy_server_config("b");
        b.jump_host = Some("a".to_string());
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(vec![a, b], dir.path().join("kh.json")).unwrap(),
        );
        let err = pool
            .get_connection("a")
            .await
            .err()
            .expect("跳板循环必须报错");
        // 错误可能经多层 anyhow 包装，检查链条中是否包含循环提示
        let chain = format!("{:#}", err);
        assert!(
            chain.contains("ProxyJump") || chain.contains("循环") || chain.contains("SSH"),
            "实际错误: {}",
            chain
        );
    }

    #[tokio::test]
    async fn self_jump_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = dummy_server_config("a");
        a.jump_host = Some("a".to_string());
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(vec![a], dir.path().join("kh.json")).unwrap(),
        );
        let err = pool
            .get_connection("a")
            .await
            .err()
            .expect("自跳板必须报错");
        assert!(format!("{:#}", err).contains("循环"));
    }

    #[tokio::test]
    async fn remote_forward_mapping_isolated_per_server() {
        let dir = tempfile::tempdir().unwrap();
        let pool = ServerPool::with_known_hosts_path(
            vec![dummy_server_config("a"), dummy_server_config("b")],
            dir.path().join("kh.json"),
        )
        .unwrap();
        // 两个服务器注册相同远端端口，互不覆盖
        let token_a = CancellationToken::new();
        pool.register_remote_forward("a", 8080, "10.0.0.1:80".into(), token_a.clone())
            .await;
        pool.register_remote_forward("b", 8080, "10.0.0.2:80".into(), CancellationToken::new())
            .await;
        {
            let fwds = pool.port_forwards.read().await;
            assert_eq!(
                fwds.get(&("a".to_string(), 8080)).unwrap().target,
                "10.0.0.1:80"
            );
            assert_eq!(
                fwds.get(&("b".to_string(), 8080)).unwrap().target,
                "10.0.0.2:80"
            );
        }
        // 注销只影响对应服务器，且取消其隧道令牌（在途拷贝随之终止）
        pool.unregister_remote_forward("a", 8080).await;
        assert!(
            token_a.is_cancelled(),
            "注销映射必须取消隧道令牌以终止在途拷贝"
        );
        let fwds = pool.port_forwards.read().await;
        assert!(fwds.get(&("a".to_string(), 8080)).is_none());
        assert!(fwds.get(&("b".to_string(), 8080)).is_some());
    }

    /// 同键重复注册（隧道重载/换绑）：旧注册的隧道令牌必须被取消，避免在途拷贝泄漏
    #[tokio::test]
    async fn register_remote_forward_overwrite_cancels_old_token() {
        let dir = tempfile::tempdir().unwrap();
        let pool = ServerPool::with_known_hosts_path(
            vec![dummy_server_config("a")],
            dir.path().join("kh.json"),
        )
        .unwrap();
        let old_token = CancellationToken::new();
        pool.register_remote_forward("a", 8080, "10.0.0.1:80".into(), old_token.clone())
            .await;
        let new_token = CancellationToken::new();
        pool.register_remote_forward("a", 8080, "10.0.0.2:80".into(), new_token.clone())
            .await;
        assert!(old_token.is_cancelled(), "覆盖注册必须取消旧令牌");
        assert!(!new_token.is_cancelled(), "新令牌不得被误取消");
        let fwds = pool.port_forwards.read().await;
        assert_eq!(
            fwds.get(&("a".to_string(), 8080)).unwrap().target,
            "10.0.0.2:80"
        );
    }

    /// cancel_remote_forward 容错路径：服务器无连接组/句柄已断开时不得报错，
    /// 必须仅删本地映射并告警——停止路径上映射绝不允许残留（russh Handle 无法 mock，
    /// 网络通知路径由真实隧道集成验证，此处覆盖逻辑语义）
    #[tokio::test]
    async fn cancel_remote_forward_without_handle_still_clears_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let pool = ServerPool::with_known_hosts_path(
            vec![dummy_server_config("a")],
            dir.path().join("kh.json"),
        )
        .unwrap();
        // 未建连：组存在但句柄为空（对应"句柄不存在/已断开"场景）
        let token = CancellationToken::new();
        pool.register_remote_forward("a", 8080, "10.0.0.1:80".into(), token.clone())
            .await;
        // 容错语义：无存活句柄时返回 Ok（仅 warn），且映射被清除
        pool.cancel_remote_forward("a", 8080)
            .await
            .expect("无存活句柄属容错场景，不得返回 Err");
        assert!(
            pool.port_forwards.read().await.is_empty(),
            "cancel_remote_forward 必须清除本地映射，不得残留"
        );
        assert!(
            token.is_cancelled(),
            "cancel_remote_forward 必须取消隧道令牌以终止在途拷贝"
        );
        // 未注册的服务器同样幂等可调用
        pool.cancel_remote_forward("ghost", 8080)
            .await
            .expect("未注册服务器同样容错");
    }

    #[test]
    fn corrupted_known_hosts_fails_pool_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kh.json");
        std::fs::write(&path, "not-json").unwrap();
        // 用 .err() 取 Option，避免 expect_err 要求 ServerPool 实现 Debug
        let err = ServerPool::with_known_hosts_path(vec![], path.clone())
            .err()
            .expect("known_hosts 损坏必须明确失败，不得静默降级");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("known_hosts") && msg.contains("修复或删除"),
            "错误必须包含修复路径提示，实际: {}",
            msg
        );
        assert!(
            msg.contains(&path.display().to_string()),
            "错误必须包含存储路径，实际: {}",
            msg
        );
    }

    #[tokio::test]
    async fn unknown_server_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(vec![], dir.path().join("kh.json")).unwrap(),
        );
        let err = pool
            .get_connection("ghost")
            .await
            .err()
            .expect("未知服务器必须报错");
        assert!(err.to_string().contains("未找到服务器"));
    }

    #[tokio::test]
    async fn failed_rebuild_records_desired_size_for_backfill() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = dummy_server_config("a");
        cfg.pool_size = 3;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(vec![cfg], dir.path().join("kh.json")).unwrap(),
        );
        // 目标不可达，重建必然失败；但期望池大小必须已落记录，供后台补池补齐
        let _ = pool.get_connection("a").await;
        let group = pool.get_group("a").await.expect("组应已创建");
        assert_eq!(
            *group.desired_size.read().expect("desired size lock"),
            3,
            "重建时必须按 pool_size 记录期望池大小"
        );
    }

    #[tokio::test]
    async fn disconnect_all_marks_groups_closed_and_detaches() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![dummy_server_config("a")],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        // 触发组创建（建连失败但组已入表）
        let _ = pool.get_connection("a").await;
        let group = pool.get_group("a").await.expect("组应已创建");
        assert!(!group.closed.load(Ordering::Relaxed));
        pool.disconnect_all().await;
        // 已脱离的旧组必须标记关闭：在途重建/补池不会向其中发布新句柄
        assert!(
            group.closed.load(Ordering::Relaxed),
            "disconnect_all 后旧组必须标记关闭"
        );
        assert!(
            pool.groups.read().await.is_empty(),
            "disconnect_all 后 groups 必须为空"
        );
        // 再次取组必须是全新实例（旧组句柄不落池、不被复用）
        let group2 = pool.get_group("a").await.expect("组应重新创建");
        assert!(!Arc::ptr_eq(&group, &group2));
        assert!(!group2.closed.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn heal_never_publishes_into_closed_group() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![dummy_server_config("a")],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        let _ = pool.get_connection("a").await;
        let group = pool.get_group("a").await.expect("组应已创建");
        // 期望 2 条但句柄为空：若未被关闭，补池会尝试建连（不可达，返回 false 待重试）
        *group.desired_size.write().expect("desired size lock") = 2;
        pool.disconnect_all().await;
        // 组已关闭：补池直接结束（true），且不得产生任何新句柄
        assert!(
            pool.heal_dead_slots("a", &group).await,
            "已关闭的组必须立即停止补池"
        );
        assert!(
            group.handles.read().await.is_empty(),
            "已关闭的组不得落任何新句柄"
        );
    }

    #[tokio::test]
    async fn heal_reports_unfilled_deficit_for_backoff_retry() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![dummy_server_config("a")],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        let _ = pool.get_connection("a").await;
        let group = pool.get_group("a").await.expect("组应已创建");
        // 期望 2 条、实际 0 条且目标不可达：本轮补不齐，必须返回 false 以触发退避重试
        *group.desired_size.write().expect("desired size lock") = 2;
        assert!(
            !pool.heal_dead_slots("a", &group).await,
            "缺失槽位未补齐时必须返回 false 交由退避重试"
        );
    }

    // ---- 以下测试依赖进程内真实 SSH 服务器（russh server），验证并发缺陷修复 ----

    /// 测试用 SSH 服务端 handler：接受任意密码认证（仅用于连接池集成测试）
    #[derive(Clone)]
    struct TestSshHandler;

    impl russh::server::Handler for TestSshHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
    }

    struct TestSshServerImpl;

    impl russh::server::Server for TestSshServerImpl {
        type Handler = TestSshHandler;

        fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
            TestSshHandler
        }
    }

    /// 在 127.0.0.1 随机端口启动测试 SSH 服务器，返回监听地址与服务器任务句柄
    async fn start_test_ssh_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use russh::server::Server as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key =
            PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
        let config = russh::server::Config {
            keys: vec![key],
            nodelay: true,
            ..Default::default()
        };
        let handle = tokio::spawn(async move {
            let mut server = TestSshServerImpl;
            let _ = server.run_on_socket(Arc::new(config), &listener).await;
        });
        (addr, handle)
    }

    /// 指向进程内测试服务器的配置（关闭主机密钥校验，密码认证）
    fn live_server_config(name: &str, addr: std::net::SocketAddr, pool_size: u32) -> ServerConfig {
        ServerConfig {
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            user: "u".to_string(),
            auth_type: Some("password".to_string()),
            password: Some("p".to_string()),
            key_path: None,
            encrypted: None,
            pool_size,
            keep_alive_interval: 0,
            timeout_seconds: 10,
            strict_host_key: false,
            host_key: None,
            jump_host: None,
        }
    }

    /// 安装测试建连注入（失败计数/门控在途建连）
    fn install_test_connector(pool: &ServerPool, hook: TestConnectorFn) {
        *pool.test_connector.lock().expect("test connector lock") = Some(hook);
    }

    /// 委托真实建连的注入闭包公共部分：克隆所需状态并返回 boxed future
    fn delegate_connect(
        pool: Arc<ServerPool>,
        config: ServerConfig,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<russh::client::Handle<ClientHandler>>> + Send>,
    > {
        Box::pin(async move {
            pool.create_connection_inner(&config, &mut vec![config.name.clone()])
                .await
        })
    }

    #[tokio::test]
    async fn partial_rebuild_backfills_missing_slots_via_heal() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, server_task) = start_test_ssh_server().await;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![live_server_config("a", addr, 3)],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        // 注入前 2 次建连失败（两败一成），其后放行真实建连
        let calls = Arc::new(AtomicUsize::new(0));
        {
            let pool_ref = pool.clone();
            let calls = calls.clone();
            install_test_connector(
                &pool,
                Arc::new(move |config: &ServerConfig| {
                    if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                        return Box::pin(async {
                            Err(anyhow::anyhow!("测试注入：模拟建连失败"))
                        });
                    }
                    delegate_connect(pool_ref.clone(), config.clone())
                }),
            );
        }
        let handle = pool
            .get_connection("a")
            .await
            .expect("两败一成后仍应返回存活连接");
        assert!(!handle.is_closed());
        let group = pool.get_group("a").await.expect("组应已创建");
        assert_eq!(
            group.handles.read().await.len(),
            1,
            "两败一成后池内应仅有 1 条存活连接"
        );
        // 快路径全部存活不会触发补池，必须由部分重建时调度的后台 heal 补齐缺失槽位
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let alive = group
                .handles
                .read()
                .await
                .iter()
                .filter(|h| !h.is_closed())
                .count();
            if alive >= 3 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "后台补池未在限时内补齐缺失槽位（当前 {} 条）",
                alive
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        server_task.abort();
    }

    #[tokio::test]
    async fn get_connection_fails_when_disconnect_all_during_inflight_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, server_task) = start_test_ssh_server().await;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![live_server_config("a", addr, 1)],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        // 门控注入：建连在途时挂起，直到测试显式放行
        let (engage_tx, engage_rx) = tokio::sync::oneshot::channel::<()>();
        let release = Arc::new(tokio::sync::Notify::new());
        {
            let pool_ref = pool.clone();
            let release = release.clone();
            let engage_tx = std::sync::Mutex::new(Some(engage_tx));
            install_test_connector(
                &pool,
                Arc::new(move |config: &ServerConfig| {
                    let pool_ref = pool_ref.clone();
                    let config = config.clone();
                    let release = release.clone();
                    let mut engage_tx = engage_tx.lock().expect("engage lock").take();
                    Box::pin(async move {
                        if let Some(tx) = engage_tx.take() {
                            let _ = tx.send(());
                        }
                        // 在途挂起：等待测试在 disconnect_all 后放行
                        release.notified().await;
                        delegate_connect(pool_ref, config).await
                    })
                }),
            );
        }
        let task = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get_connection("a").await }
        });
        engage_rx.await.expect("connector 应已被调用");
        pool.disconnect_all().await;
        release.notify_one();
        let err = task
            .await
            .expect("取连接任务不应 panic")
            .err()
            .expect("池断开后在途重建不得返回存活句柄");
        assert!(
            format!("{:#}", err).contains("连接池已关闭"),
            "错误应提示连接池已关闭，实际: {:#}",
            err
        );
        assert!(
            pool.groups.read().await.is_empty(),
            "disconnect_all 后 groups 必须保持为空"
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn disconnect_between_validation_and_publish_drops_handle() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, server_task) = start_test_ssh_server().await;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![live_server_config("a", addr, 1)],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        let group = pool.get_group("a").await.expect("组应已创建");
        let gate = TestGate::new();
        *pool
            .test_publish_gate
            .lock()
            .expect("test publish gate lock") = Some(gate.clone());

        let task = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get_connection("a").await }
        });
        // 真实建连已完成，且首次代际校验已通过；任务尚未取得最终发布锁。
        tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
            .await
            .expect("建连任务应到达发布门控");
        pool.disconnect_all().await;
        gate.release.notify_one();

        let err = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("发布路径不应因生命周期锁卡死")
            .expect("取连接任务不应 panic")
            .err()
            .expect("关闭发生在发布前，句柄不得流出");
        assert!(format!("{:#}", err).contains("连接池已关闭"));
        assert!(
            group.handles.read().await.is_empty(),
            "过期句柄不得写入已脱离连接池的组"
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn in_flight_heal_drops_handle_when_generation_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (addr, server_task) = start_test_ssh_server().await;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![live_server_config("a", addr, 3)],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        // 前 2 次建连失败（两败一成）；第 3 次（首成）直接放行；
        // 其后补池发起的建连进入门控：挂起直到测试放行
        let calls = Arc::new(AtomicUsize::new(0));
        let (engage_tx, engage_rx) = tokio::sync::oneshot::channel::<()>();
        let release = Arc::new(tokio::sync::Notify::new());
        {
            let pool_ref = pool.clone();
            let calls = calls.clone();
            let release = release.clone();
            let engage_tx = std::sync::Mutex::new(Some(engage_tx));
            install_test_connector(
                &pool,
                Arc::new(move |config: &ServerConfig| {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        return Box::pin(async {
                            Err(anyhow::anyhow!("测试注入：模拟建连失败"))
                        });
                    }
                    if n == 2 {
                        // 首条成功连接：直接真实建连
                        return delegate_connect(pool_ref.clone(), config.clone());
                    }
                    let pool_ref = pool_ref.clone();
                    let config = config.clone();
                    let release = release.clone();
                    let mut engage_tx = engage_tx.lock().expect("engage lock").take();
                    Box::pin(async move {
                        if let Some(tx) = engage_tx.take() {
                            let _ = tx.send(());
                        }
                        // 在途挂起：等待测试在 disconnect_all 后放行
                        release.notified().await;
                        delegate_connect(pool_ref, config).await
                    })
                }),
            );
        }
        let handle = pool
            .get_connection("a")
            .await
            .expect("两败一成后仍应返回存活连接");
        assert!(!handle.is_closed());
        let group = pool.get_group("a").await.expect("组应已创建");
        assert_eq!(
            group.handles.read().await.len(),
            1,
            "两败一成后池内应仅有 1 条存活连接"
        );
        // 部分重建已自动调度后台补池；等待补池进入门控建连
        engage_rx.await.expect("补池应已发起门控建连");
        pool.disconnect_all().await;
        release.notify_one();
        // 代际已变化：补池拿到的在途新句柄必须被丢弃，不得发布进旧组
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let handles = group.handles.read().await;
        assert_eq!(
            handles.len(),
            1,
            "代际变化后补池不得向旧组发布新句柄（防止在途建连返回存活连接）"
        );
        assert!(
            !handles[0].is_closed(),
            "原有存活句柄不应被过期补池结果覆盖"
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn heal_completion_counts_only_alive_handles() {
        // 复现补齐判定缺陷：死槽位重建全部失败时死句柄仍占位 Vec，
        // 若以 len 判定会把占位误判为补齐（len==desired），heal_loop 退出后死槽位不再自动重试
        let dir = tempfile::tempdir().unwrap();
        let (addr, server_task) = start_test_ssh_server().await;
        let pool = Arc::new(
            ServerPool::with_known_hosts_path(
                vec![live_server_config("a", addr, 2)],
                dir.path().join("kh.json"),
            )
            .unwrap(),
        );
        let handle = pool.get_connection("a").await.expect("应建立存活连接");
        assert!(!handle.is_closed());
        let group = pool.get_group("a").await.expect("组应已创建");
        assert_eq!(group.handles.read().await.len(), 2, "池应建满 2 条连接");

        // 主动断开全部会话：句柄转为死连接但占位仍在（len 保持为 desired）
        {
            let handles = group.handles.read().await.clone();
            for h in &handles {
                let _ = h
                    .disconnect(russh::Disconnect::ByApplication, "test", "")
                    .await;
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if group.handles.read().await.iter().all(|h| h.is_closed()) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "会话断开后句柄未及时转为关闭态"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // 注入恒失败的建连：死槽位重建全部失败
        let calls = Arc::new(AtomicUsize::new(0));
        {
            let calls = calls.clone();
            install_test_connector(
                &pool,
                Arc::new(move |_config: &ServerConfig| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Err(anyhow::anyhow!("测试注入：模拟建连失败")) })
                }),
            );
        }
        // len(2) 已满但存活为 0：必须返回 false 交由 heal_loop 退避重试，
        // 死句柄占位不得计入补齐判定
        assert!(
            !pool.heal_dead_slots("a", &group).await,
            "len 满但全为死句柄时必须返回 false 继续重试"
        );
        assert_eq!(
            group.handles.read().await.len(),
            2,
            "重建失败的死句柄仍占位，不得被清出"
        );

        // 继续重试语义：heal_loop 在 false 后应持续发起新一轮死槽位重建
        //（首轮 2 次失败 + 补池循环后续轮次各 2 次，计数持续增长）
        pool.spawn_heal("a", group.clone());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while calls.load(Ordering::SeqCst) < 6 {
            assert!(
                std::time::Instant::now() < deadline,
                "heal_loop 未持续重试死槽位重建（当前尝试 {} 次）",
                calls.load(Ordering::SeqCst)
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // 收尾：关闭整池使补池循环退出
        pool.disconnect_all().await;
        server_task.abort();
    }
}
