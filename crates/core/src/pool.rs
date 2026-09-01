use crate::config::ServerConfig;
use anyhow::Result;
use russh::client::{self, Handler};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use russh::keys::{PublicKeyOrCertificate, decode_secret_key, key::PrivateKeyWithHashAlg};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
/// 异步 SSH 客户端处理器
/// 实现 `russh::client::Handler` trait，专门用于处理远端反向连接（Remote Port Forwarding）的底层事件
pub struct ClientHandler {
    /// 维护一张映射表，记录“被绑定的远端代理端口”对应的“本地目标服务地址”。
    /// 当远端收到穿透请求时，借助此表查找应当将其流转发给本地的哪个 IP/端口。
    pub port_forwards: Arc<RwLock<HashMap<u32, String>>>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
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
            fwds.get(&connected_port).cloned()
        };
        if let Some(target) = target {
            reply.accept().await;
            tokio::spawn(async move {
                if let Ok(mut local_stream) = tokio::net::TcpStream::connect(&target).await {
                    let mut stream = channel.into_stream();
                    let _ = crate::copy_bidirectional::copy_bidirectional_64k(&mut local_stream, &mut stream).await;
                }
            });
        }
        Ok(())
    }
}

/// 高可用 SSH 代理服务器连接池
/// 负责管理多节点的 SSH 会话连接、并发轮询调度 (Round-Robin) 和断线自动重连机制
pub struct ServerPool {
    /// 维护服务器名称到其下多个 SSH 会话（连接池）的映射关系
    connections: RwLock<HashMap<String, Vec<Arc<russh::client::Handle<ClientHandler>>>>>,
    /// 存储各个服务器的具体连接配置，供重连时使用
    configs: HashMap<String, ServerConfig>,
    /// 原子计数器，用于实现无锁的 Round-Robin 会话分发
    counter: AtomicUsize,
    /// 共享的反向端口映射表（注入到 ClientHandler 中供穿透使用）
    port_forwards: Arc<RwLock<HashMap<u32, String>>>,
}

impl ServerPool {
    /// 利用指定的服务器配置列表，初始化连接池引擎
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        let mut configs = HashMap::new();
        for server in servers {
            configs.insert(server.name.clone(), server);
        }
        Self {
            connections: RwLock::new(HashMap::new()),
            configs,
            counter: AtomicUsize::new(0),
            port_forwards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 断开并清理全局所有受控的 SSH 会话连接
    pub async fn disconnect_all(&self) {
        let mut conns = self.connections.write().await;
        conns.clear();
        log::info!("已关闭所有 SSH 连接。");
    }

    /// 从连接池中获取一个可用的 SSH 会话句柄（使用原子计数器进行简单的轮询调度）
    /// 如果发现连接全部断开或尚未建立，则会触发重连机制重建整个池子
    pub async fn get_connection(&self, name: &str) -> Result<Arc<russh::client::Handle<ClientHandler>>> {
        
        {
            let conns = self.connections.read().await;
            if let Some(handles) = conns.get(name) {
                // 跳过池中的死亡连接
                for _ in 0..handles.len() {
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % handles.len();
                    let handle = &handles[idx];
                    if !handle.is_closed() {
                        return Ok(handle.clone());
                    }
                }
                log::warn!("至 {} 的所有 SSH 连接均已失效，准备重连连接池...", name);
            }
        }

        let mut conns = self.connections.write().await;
        // 再次检查确认
        if let Some(handles) = conns.get(name) {
            for _ in 0..handles.len() {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % handles.len();
                let handle = &handles[idx];
                if !handle.is_closed() {
                    return Ok(handle.clone());
                }
            }
        }

        let config = self.configs.get(name).ok_or_else(|| anyhow::anyhow!("在配置中未找到服务器 {}", name))?;
        let pool_size = config.pool_size as usize;
        
        log::info!("正在为 {} 建立 SSH 连接池 (大小为 {})...", name, pool_size);
        
        let mut new_handles = Vec::with_capacity(pool_size);
        let mut last_err = None;
        for i in 0..pool_size {
            log::info!("正在建立针对 {} 的 SSH 会话 {}/{}", name, i+1, pool_size);
            match self.create_connection(config).await {
                Ok(handle) => new_handles.push(Arc::new(handle)),
                Err(e) => {
                    log::warn!("建立针对 {} 的 SSH 会话 {}/{} 失败: {}，跳过此连接", name, i+1, pool_size, e);
                    last_err = Some(e);
                }
            }
        }

        // 如果一个连接都没建立成功，才向上层返回错误
        if new_handles.is_empty() {
            return Err(last_err.unwrap_or_else(|| anyhow::anyhow!("为 {} 建立 SSH 连接池失败", name)));
        }

        if new_handles.len() < pool_size {
            log::warn!("针对 {} 的连接池降级运行：成功 {}/{}", name, new_handles.len(), pool_size);
        } else {
            log::info!("针对 {} 的 SSH 连接池建立成功。", name);
        }
        conns.insert(name.to_string(), new_handles.clone());

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % new_handles.len();
        Ok(new_handles[idx].clone())
    }

    pub async fn register_remote_forward(&self, port: u32, target: String) {
        let mut fwds = self.port_forwards.write().await;
        fwds.insert(port, target);
    }

    async fn create_connection(&self, config: &ServerConfig) -> Result<russh::client::Handle<ClientHandler>> {
        let russh_config = russh::client::Config::default();
        let host = config.host.clone();
        let port = config.port;
        let handler = ClientHandler { port_forwards: self.port_forwards.clone() };

        let connect_future = async {
            let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            let _ = stream.set_nodelay(true);
            client::connect_stream(
                Arc::new(russh_config),
                stream,
                handler,
            ).await
        };

        let mut session = match tokio::time::timeout(
            std::time::Duration::from_secs(config.timeout_seconds as u64),
            connect_future,
        ).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow::anyhow!("SSH 连接错误: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("SSH 连接超时")),
        };

        // 认证过程
        let key_path_opt = config.key_path.as_deref().filter(|s| !s.trim().is_empty());
        let pwd_opt = config.password.as_deref().filter(|s| !s.trim().is_empty());

        let auth_res = if let Some(key_path) = key_path_opt {
            let key_str = tokio::fs::read_to_string(key_path).await
                .map_err(|e| anyhow::anyhow!("读取私钥失败 {}: {}", key_path, e))?;
            let key = decode_secret_key(&key_str, pwd_opt)
                .map_err(|e| anyhow::anyhow!("解析私钥失败: {}", e))?;
            let key_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            session.authenticate_publickey(&config.user, key_alg).await?
        } else if let Some(pwd) = pwd_opt {
            session.authenticate_password(&config.user, pwd).await?
        } else {
            return Err(anyhow::anyhow!("未提供任何认证方式"));
        };

        if !auth_res.success() {
            return Err(anyhow::anyhow!("身份认证失败"));
        }

        Ok(session)
    }
}
