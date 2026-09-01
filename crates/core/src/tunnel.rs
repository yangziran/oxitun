use crate::config::{TunnelConfig, TunnelType, RoutingConfig};
use crate::pool::ServerPool;
use crate::socks5::{handle_socks5_handshake, send_socks5_reply};
use crate::router::Router;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::sync::Mutex;
use log::{info, error, debug};


/// 隧道生命周期管理器，负责不同类型的代理隧道（Local/Remote/SOCKS5/DNS）的启动、注册、维护和销毁
pub struct TunnelManager {

    pool: Arc<ServerPool>,
    router: Arc<Router>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl TunnelManager {
    /// 初始化隧道管理器并挂载底层的 SSH 连接池和路由引擎
    pub async fn new(pool: Arc<ServerPool>, routing: RoutingConfig, chnroute_url: String) -> Self {
        Self { 
            pool,
            router: Arc::new(Router::new(routing, &chnroute_url).await),
            tasks: Mutex::new(Vec::new()),
        }
    }

    /// 根据传入的配置类型派发任务，启动对应的底层代理监听服务
    pub async fn start_tunnel(&self, config: TunnelConfig) -> Result<()> {
        let handles = match config.tunnel_type {
            TunnelType::Local => self.spawn_local_tunnel(config).await?,
            TunnelType::Dynamic => self.spawn_dynamic_tunnel(config).await?,
            TunnelType::Remote => self.spawn_remote_tunnel(config).await?,
            TunnelType::Dns | TunnelType::DnsDot | TunnelType::DnsDoh => self.spawn_dns_tunnel(config).await?,
        };
        let mut tasks = self.tasks.lock().await;
        for handle in handles {
            tasks.push(handle);
        }
        Ok(())
    }

    /// 将外部衍生的异步协程任务（如后台定时更新路由表的任务）注册到管理器的生命周期中，
    /// 确保在调用 `stop_all` 时能够一并被平滑取消。
    pub async fn add_task(&self, handle: JoinHandle<()>) {
        self.tasks.lock().await.push(handle);
    }

    /// 强行终止并清理所有当前处于活跃状态的代理隧道和后台维护任务，
    /// 同时向 SSH 连接池下发断开指令，释放所有底层网络连接。
    pub async fn stop_all(&self) {
        let mut tasks = self.tasks.lock().await;
        let mut join_handles = vec![];
        for task in tasks.drain(..) {
            task.abort();
            join_handles.push(task);
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
        let v4_ip = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let remote_addr = config.remote_addr.ok_or_else(|| anyhow!("本地隧道 (Local) 必须配置目标地址 (remote_addr)"))?;
        let server_name = config.server_names.first().ok_or_else(|| anyhow!("隧道未指定绑定的代理服务器"))?.clone();

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
            let server_name = server_name.clone();
            let remote_addr = remote_addr.clone();

            let handle = tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let _ = inbound.set_nodelay(true);
                    
                    let pool = pool.clone();
                    let server_name = server_name.clone();
                    let remote_addr = remote_addr.clone();
                    
                    tokio::spawn(async move {
                        if let Ok(handle_arc) = pool.get_connection(&server_name).await {
                            let (host, port) = parse_host_port(&remote_addr, 80);
                            {
                                let host = host.trim_matches(|c| c == '[' || c == ']');
                                
                                
                                let channel_res = handle_arc.channel_open_direct_tcpip(host, port, "127.0.0.1", 0).await;
                                if let Ok(channel) = channel_res {
                                    let mut stream = channel.into_stream();
                                    let _ = crate::copy_bidirectional::copy_bidirectional_64k(&mut inbound, &mut stream).await;
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
        let v4_ip = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let server_name = config.server_names.first().ok_or_else(|| anyhow!("隧道未指定绑定的代理服务器"))?.clone();

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
            let server_name = server_name.clone();

            let handle = tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let _ = inbound.set_nodelay(true);
                    let pool = pool.clone();
                    let router = router.clone();
                    let server_name = server_name.clone();
                    
                    tokio::spawn(async move {
                        match handle_socks5_handshake(&mut inbound).await {
                            Ok(target) => {
                                let host = target.host();
                                let port = target.port();
                                
                                if router.should_proxy(&host).await {
                                    debug!("通过代理请求 {}:{}", host, port);
                                    if let Ok(handle_arc) = pool.get_connection(&server_name).await {
                                        let channel_res = handle_arc.channel_open_direct_tcpip(&host, port as u32, "127.0.0.1", 0).await;
                                        match channel_res {
                                            Ok(channel) => {
                                                let _ = send_socks5_reply(&mut inbound, true).await;
                                                let mut stream = channel.into_stream();
                                                let _ = crate::copy_bidirectional::copy_bidirectional_64k(&mut inbound, &mut stream).await;
                                            }
                                            Err(e) => {
                                                error!("请求 {}:{} 建立直连通道失败: {:?}", host, port, e);
                                                let _ = send_socks5_reply(&mut inbound, false).await;
                                            }
                                        }
                                    } else {
                                        let _ = send_socks5_reply(&mut inbound, false).await;
                                    }
                                } else {
                                    debug!("直连请求 {}:{}", host, port);
                                    if let Ok(outbound) = tokio::net::TcpStream::connect((host.as_str(), port)).await {
                                        
                                        let _ = send_socks5_reply(&mut inbound, true).await;
                                        let mut outbound = outbound;
                                        let _ = crate::copy_bidirectional::copy_bidirectional_64k(&mut inbound, &mut outbound).await;
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
        let server_name = config.server_names.first().ok_or_else(|| anyhow!("隧道未指定绑定的代理服务器"))?.clone();
        let remote_port = config.port as u32;
        let local_target = config.remote_addr.ok_or_else(|| anyhow!("远程隧道 (Remote) 必须配置目标地址 (remote_addr)"))?.clone();
        let bind_address = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        
        let pool = self.pool.clone();
        
        let handle = tokio::spawn(async move {
            pool.register_remote_forward(remote_port, local_target).await;
            
            loop {
                if let Ok(handle_arc) = pool.get_connection(&server_name).await {
                    // 尝试在当前分配的 SSH 会话上注册远程端口监听
                    match handle_arc.tcpip_forward(bind_address, remote_port).await {
                        Ok(_) => {
                            log::info!("成功在远端 {} 注册反向端口穿透 (端口: {})", server_name, remote_port);
                            // 阻塞等待，直到当前底层的 SSH 会话断开，才进行下一轮重连与注册
                            while !handle_arc.is_closed() {
                                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            }
                            log::warn!("提供穿透服务的会话已断开，准备尝试重新注册...");
                        }
                        Err(e) => {
                            log::error!("在远端注册端口 {} 失败 (可能被占用或无权限): {}", remote_port, e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        }
                    }
                } else {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        });
        
        Ok(vec![handle])
    }

    /// 启动 DNS 代理隧道 (DNS Proxy)
    /// 在本地开启一个 UDP 端口专门接收系统的 DNS 请求报文，随后根据具体的 DNS 隧道模式，
    /// 借助远端代理节点发起对 TCP DNS / DoT / DoH 服务器的隐秘解析请求，最后回传给系统
    async fn spawn_dns_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let remote_addr = config.remote_addr.unwrap_or_else(|| "8.8.8.8:53".to_string());
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
                let _ = dns_server_clone.run_server_with_socket(
                    socket.clone(),
                    remote_addr_clone,
                    server_name_clone,
                    pool_clone,
                    tunnel_type,
                ).await;
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
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            let host = addr[1..end].to_string();
            if addr.len() > end + 1 && addr.as_bytes()[end+1] == b':' {
                let port = addr[end+2..].parse().unwrap_or(default_port);
                return (host, port);
            }
            return (host, default_port);
        }
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

    #[test]
    fn test_parse_host_port() {
        assert_eq!(parse_host_port("google.com:80", 443), ("google.com".to_string(), 80));
        assert_eq!(parse_host_port("192.168.1.1", 443), ("192.168.1.1".to_string(), 443));
        assert_eq!(parse_host_port("[2402:4e00::]:53", 80), ("2402:4e00::".to_string(), 53));
    }
}
