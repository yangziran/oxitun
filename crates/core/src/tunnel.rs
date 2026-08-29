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


pub struct TunnelManager {

    pool: Arc<ServerPool>,
    router: Arc<Router>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl TunnelManager {
    pub async fn new(pool: Arc<ServerPool>, routing: RoutingConfig, chnroute_url: String) -> Self {
        Self { 
            pool,
            router: Arc::new(Router::new(routing, &chnroute_url).await),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub async fn start_tunnel(&self, config: TunnelConfig) -> Result<()> {
        let handles = match config.tunnel_type {
            TunnelType::Local => self.spawn_local_tunnel(config).await?,
            TunnelType::Dynamic => self.spawn_dynamic_tunnel(config).await?,
        };
        let mut tasks = self.tasks.lock().await;
        for handle in handles {
            tasks.push(handle);
        }
        Ok(())
    }

    pub async fn add_task(&self, handle: JoinHandle<()>) {
        self.tasks.lock().await.push(handle);
    }

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
        info!("All active tunnels have been stopped.");
    }

    async fn spawn_local_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let remote_addr = config.remote_addr.ok_or_else(|| anyhow!("Local tunnel requires remote_addr"))?;
        let server_name = config.server_names.first().ok_or_else(|| anyhow!("No server specified for tunnel"))?.clone();

        for ip in &[v4_ip, v6_ip] {
            let local_addr = format!("{}:{}", ip, config.port);
            let listener = match TcpListener::bind(&local_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind to {}: {}", local_addr, e);
                    continue;
                }
            };
            info!("Listening on {} for local tunnel {}", local_addr, config.name);

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
                            let (host, port_str) = remote_addr.rsplit_once(':').unwrap_or((&remote_addr, "80"));
                            {
                                let host = host.trim_matches(|c| c == '[' || c == ']');
                                let port = port_str.parse::<u32>().unwrap_or(80);
                                
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
            return Err(anyhow!("Failed to bind local tunnel to any address (IPv4 or IPv6)"));
        }
        Ok(handles)
    }

    async fn spawn_dynamic_tunnel(&self, config: TunnelConfig) -> Result<Vec<JoinHandle<()>>> {
        let mut handles = Vec::new();
        let v4_ip = if config.share_on_lan { "0.0.0.0" } else { "127.0.0.1" };
        let v6_ip = if config.share_on_lan { "[::]" } else { "[::1]" };

        let server_name = config.server_names.first().ok_or_else(|| anyhow!("No server specified for tunnel"))?.clone();

        for ip in &[v4_ip, v6_ip] {
            let local_addr = format!("{}:{}", ip, config.port);
            let listener = match TcpListener::bind(&local_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind to {}: {}", local_addr, e);
                    continue;
                }
            };
            info!("Listening on {} for SOCKS5 tunnel {}", local_addr, config.name);

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
                                    debug!("Proxying request to {}:{}", host, port);
                                    if let Ok(handle_arc) = pool.get_connection(&server_name).await {
                                        let channel_res = handle_arc.channel_open_direct_tcpip(&host, port as u32, "127.0.0.1", 0).await;
                                        match channel_res {
                                            Ok(channel) => {
                                                let _ = send_socks5_reply(&mut inbound, true).await;
                                                let mut stream = channel.into_stream();
                                                let _ = crate::copy_bidirectional::copy_bidirectional_64k(&mut inbound, &mut stream).await;
                                            }
                                            Err(e) => {
                                                error!("channel_open_direct_tcpip failed for {}:{}: {:?}", host, port, e);
                                                let _ = send_socks5_reply(&mut inbound, false).await;
                                            }
                                        }
                                    } else {
                                        let _ = send_socks5_reply(&mut inbound, false).await;
                                    }
                                } else {
                                    debug!("Direct request to {}:{}", host, port);
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
                                error!("SOCKS5 handshake failed: {}", e);
                            }
                        }
                    });
                }
            });
            handles.push(handle);
        }

        if handles.is_empty() {
            return Err(anyhow!("Failed to bind SOCKS5 tunnel to any address (IPv4 or IPv6)"));
        }
        Ok(handles)
    }
}
