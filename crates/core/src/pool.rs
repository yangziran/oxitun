use crate::config::ServerConfig;
use crate::host_key::{HostKeyBroker, PendingHostKey};
use crate::known_hosts::KnownHostsStore;
use anyhow::Result;
use russh::client::{self, Handler};
use russh::keys::{HashAlg, PublicKeyOrCertificate, decode_secret_key, key::PrivateKeyWithHashAlg};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

/// 主机密钥确认等待超时时间（秒）
const HOST_KEY_TIMEOUT_SECS: u64 = 300;

#[derive(Clone)]
/// 异步 SSH 客户端处理器
/// 实现 `russh::client::Handler` trait，负责主机密钥 TOFU 校验与远端反向连接（Remote Port Forwarding）的底层事件
pub struct ClientHandler {
    /// 反向端口映射表：键为 (服务器名, 远端端口)
    pub port_forwards: Arc<RwLock<HashMap<(String, u32), String>>>,
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

        // 4. 挂起握手，等待用户决策（同一主机并发请求自动去重）
        let info = PendingHostKey {
            host: self.host.clone(),
            port: self.port,
            key_type: key_type.clone(),
            fingerprint: fingerprint.clone(),
        };
        let (mut decision_rx, _is_new) = self.broker.request(info);
        let wait = decision_rx.wait_for(|v| v.is_some());
        let accepted =
            match tokio::time::timeout(std::time::Duration::from_secs(HOST_KEY_TIMEOUT_SECS), wait)
                .await
            {
                Ok(Ok(v)) => v.unwrap_or(false),
                _ => {
                    // 超时或通道关闭：清理 pending，按拒绝处理
                    self.broker.expire(&self.host, self.port);
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
            let _ = self
                .known_hosts
                .trust(&self.host, self.port, &key_type, &fingerprint);
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
        let target = {
            let fwds = self.port_forwards.read().await;
            fwds.get(&(self.server_name.clone(), connected_port))
                .cloned()
        };
        if let Some(target) = target {
            reply.accept().await;
            tokio::spawn(async move {
                if let Ok(mut local_stream) = tokio::net::TcpStream::connect(&target).await {
                    let mut stream = channel.into_stream();
                    let _ = crate::copy_bidirectional::copy_bidirectional_64k(
                        &mut local_stream,
                        &mut stream,
                    )
                    .await;
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
    /// 防止重复 spawn 后台补池任务
    healing: std::sync::atomic::AtomicBool,
}

impl ServerGroup {
    fn new() -> Self {
        Self {
            handles: RwLock::new(Vec::new()),
            rebuild_lock: tokio::sync::Mutex::new(()),
            state: std::sync::RwLock::new(GroupState::Connecting),
            healing: std::sync::atomic::AtomicBool::new(false),
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
    /// 反向端口映射表：键为 (服务器名, 远端端口)，避免跨服务器同端口互相覆盖
    port_forwards: Arc<RwLock<HashMap<(String, u32), String>>>,
    /// TOFU 主机密钥信任存储
    known_hosts: Arc<KnownHostsStore>,
    /// 首连主机密钥确认协调器
    broker: HostKeyBroker,
    /// 整池重建次数（可观测性与测试用）
    rebuild_count: AtomicUsize,
}

impl ServerPool {
    /// 利用指定的服务器配置列表，初始化连接池引擎
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        Self::with_known_hosts_path(servers, KnownHostsStore::default_path())
    }

    /// 指定 known_hosts 存储路径（测试与自定义部署使用）
    pub fn with_known_hosts_path(
        servers: Vec<ServerConfig>,
        known_hosts_path: std::path::PathBuf,
    ) -> Self {
        let known_hosts = KnownHostsStore::open(known_hosts_path).unwrap_or_else(|e| {
            log::error!("打开 known_hosts 存储失败: {}，主机密钥信任将无法持久化", e);
            KnownHostsStore::open(
                std::env::temp_dir()
                    .join(format!("oxitun-known-hosts-{}.json", std::process::id())),
            )
            .expect("无法创建临时 known_hosts 存储")
        });
        let mut configs = HashMap::new();
        for server in servers {
            configs.insert(server.name.clone(), server);
        }
        Self {
            groups: RwLock::new(HashMap::new()),
            configs: RwLock::new(configs),
            counter: AtomicUsize::new(0),
            port_forwards: Arc::new(RwLock::new(HashMap::new())),
            known_hosts: Arc::new(known_hosts),
            broker: HostKeyBroker::new(),
            rebuild_count: AtomicUsize::new(0),
        }
    }

    /// 获取主机密钥确认协调器（GUI/CLI 用于监听待确认请求与提交决策）
    pub fn broker(&self) -> HostKeyBroker {
        self.broker.clone()
    }

    /// 获取 known_hosts 存储（用于查看/清除信任记录）
    pub fn known_hosts(&self) -> Arc<KnownHostsStore> {
        self.known_hosts.clone()
    }

    /// 断开并清理全局所有受控的 SSH 会话连接与反向端口映射
    pub async fn disconnect_all(&self) {
        self.broker.reject_all();
        let mut groups = self.groups.write().await;
        groups.clear();
        self.port_forwards.write().await.clear();
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
        let mut new_map: HashMap<String, ServerConfig> = HashMap::new();
        for s in new_servers {
            new_map.insert(s.name.clone(), s);
        }

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
                    groups.remove(&name);
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
    fn get_connection_inner<'a>(
        self: &'a Arc<Self>,
        name: &'a str,
        visited: &'a mut Vec<String>,
    ) -> BoxedConnectionFuture<'a> {
        Box::pin(async move {
            // ProxyJump 循环检测
            if visited.iter().any(|v| v == name) {
                return Err(anyhow::anyhow!(
                    "检测到 ProxyJump 跳板循环: {} -> {}",
                    visited.join(" -> "),
                    name
                ));
            }
            visited.push(name.to_string());

            let group = self.get_group(name).await?;

            // 快路径：不持重建锁
            {
                let handles = group.handles.read().await;
                let (hit, has_dead) = self.pick_alive(&handles);
                if let Some(handle) = hit {
                    if has_dead {
                        self.spawn_heal(name, group.clone());
                    }
                    return Ok(handle);
                }
            }

            // 慢路径：整池重建（互斥 + 双检）
            let _permit = group.rebuild_lock.lock().await;
            {
                let handles = group.handles.read().await;
                if let (Some(handle), _) = self.pick_alive(&handles) {
                    return Ok(handle);
                }
            }

            group.set_state(GroupState::Connecting);
            let config = self
                .configs
                .read()
                .await
                .get(name)
                .cloned()
                .expect("get_group 已校验服务器存在");
            let pool_size = (config.pool_size as usize).max(1);
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
            let idx = self.counter.fetch_add(1, Ordering::Relaxed) % new_handles.len();
            let picked = new_handles[idx].clone();
            *group.handles.write().await = new_handles;
            Ok(picked)
        })
    }

    /// 后台补池：单独重建死连接槽位（与整池重建分离；走完整建连逻辑含跳板）
    fn spawn_heal(self: &Arc<Self>, name: &str, group: Arc<ServerGroup>) {
        if group.healing.swap(true, Ordering::Relaxed) {
            return; // 已有补池任务在运行
        }
        let pool = self.clone();
        let name_owned = name.to_string();
        tokio::spawn(async move {
            let config = match pool.configs.read().await.get(&name_owned) {
                Some(c) => c.clone(),
                None => {
                    group.healing.store(false, Ordering::Relaxed);
                    return;
                }
            };
            let _permit = group.rebuild_lock.lock().await;
            let mut handles = group.handles.write().await;
            let mut healed = 0usize;
            for slot in handles.iter_mut() {
                if slot.is_closed() {
                    // 补池从本服务器开始新的跳板链
                    match pool
                        .create_connection(&config, &mut vec![name_owned.clone()])
                        .await
                    {
                        Ok(new_handle) => {
                            *slot = Arc::new(new_handle);
                            healed += 1;
                            crate::metrics::inc_reconnect();
                        }
                        Err(e) => {
                            log::warn!("补池：重建 {} 的死连接失败: {}", name_owned, e);
                        }
                    }
                }
            }
            if healed > 0 {
                log::info!("补池：已为 {} 重建 {} 条失效连接", name_owned, healed);
            }
            drop(handles);
            group.healing.store(false, Ordering::Relaxed);
        });
    }

    /// 注册远端反向端口映射（键含服务器名，跨服务器同端口互不覆盖）
    pub async fn register_remote_forward(&self, server_name: &str, port: u32, target: String) {
        self.port_forwards
            .write()
            .await
            .insert((server_name.to_string(), port), target);
    }

    /// 注销某服务器的远端端口映射（隧道停止/重载时调用）
    pub async fn unregister_remote_forward(&self, server_name: &str, port: u32) {
        self.port_forwards
            .write()
            .await
            .remove(&(server_name.to_string(), port));
    }

    /// 当前远端端口映射快照（诊断/测试用）
    pub async fn remote_forwards_snapshot(&self) -> Vec<((String, u32), String)> {
        self.port_forwards
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// 建立单条 SSH 会话；配置含 jump_host 时经跳板节点嵌套建立（逐跳独立 TOFU 校验）
    async fn create_connection(
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
            session
                .authenticate_publickey(&config.user, key_alg)
                .await?
        } else {
            let pwd = pwd_opt.ok_or_else(|| anyhow::anyhow!("密码认证未提供 password"))?;
            session.authenticate_password(&config.user, pwd).await?
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

/// 在任意字节流上完成 SSH 握手（TCP 直连或跳板通道通用），带超时
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
        std::time::Duration::from_secs(timeout_secs),
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
        assert!(broker.resolve("test.host", 22, true));

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
        // 等 pending 出现后拒绝
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        broker.resolve("test.host", 22, false);

        let err = check.await.unwrap().unwrap_err();
        assert!(matches!(err, russh::Error::UnknownKey));
        assert!(broker.pending_list().is_empty(), "拒绝后 pending 必须清理");
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

    #[tokio::test]
    async fn proxyjump_cycle_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        // a -> b -> a 循环
        let mut a = dummy_server_config("a");
        a.jump_host = Some("b".to_string());
        let mut b = dummy_server_config("b");
        b.jump_host = Some("a".to_string());
        let pool = Arc::new(ServerPool::with_known_hosts_path(
            vec![a, b],
            dir.path().join("kh.json"),
        ));
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
        let pool = Arc::new(ServerPool::with_known_hosts_path(
            vec![a],
            dir.path().join("kh.json"),
        ));
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
        );
        // 两个服务器注册相同远端端口，互不覆盖
        pool.register_remote_forward("a", 8080, "10.0.0.1:80".into())
            .await;
        pool.register_remote_forward("b", 8080, "10.0.0.2:80".into())
            .await;
        {
            let fwds = pool.port_forwards.read().await;
            assert_eq!(fwds.get(&("a".to_string(), 8080)).unwrap(), "10.0.0.1:80");
            assert_eq!(fwds.get(&("b".to_string(), 8080)).unwrap(), "10.0.0.2:80");
        }
        // 注销只影响对应服务器
        pool.unregister_remote_forward("a", 8080).await;
        let fwds = pool.port_forwards.read().await;
        assert!(fwds.get(&("a".to_string(), 8080)).is_none());
        assert!(fwds.get(&("b".to_string(), 8080)).is_some());
    }

    #[tokio::test]
    async fn unknown_server_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(ServerPool::with_known_hosts_path(
            vec![],
            dir.path().join("kh.json"),
        ));
        let err = pool
            .get_connection("ghost")
            .await
            .err()
            .expect("未知服务器必须报错");
        assert!(err.to_string().contains("未找到服务器"));
    }
}
