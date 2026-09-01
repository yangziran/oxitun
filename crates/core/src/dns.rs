use base64::Engine;
use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use moka::future::Cache;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use crate::pool::ServerPool;
use crate::config::TunnelType;
use log::{debug, error, info};
use std::convert::TryFrom;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

/// 核心 DNS 服务器模块
/// 支持标准的 DNS (UDP 转 TCP)、DNS over TLS (DoT) 和 DNS over HTTPS (DoH)。
/// 内置基于 Moka 的高性能异步 TTL 缓存机制。
pub struct DnsServer {
    cache: Cache<Vec<u8>, (Message, Instant, u32)>, 
}

impl DnsServer {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(Duration::from_secs(600))
                .build(),
        }
    }

    /// 启动 DNS UDP 监听服务并循环处理查询请求
    /// 支持智能缓存（依据 TTL），并将 Cache Miss 的请求通过连接池经由远程服务器发送
    pub async fn run_server_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        
        remote_addr: String,
        server_name: Option<String>,
        pool: Arc<ServerPool>,
        tunnel_type: TunnelType,
    ) -> Result<()> {

        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()]; // 针对 DoH
        
        let tls_connector = TlsConnector::from(Arc::new(config));

        let mut buf = [0u8; 1500];
        loop {
            if let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let query = buf[..len].to_vec();
                let socket = socket.clone();
                let remote_addr = remote_addr.clone();
                let pool = pool.clone();
                let server_name = server_name.clone();
                let cache = self.cache.clone();
                let tunnel_type = tunnel_type.clone();
                let tls_connector = tls_connector.clone();

                tokio::spawn(async move {
                    if let Ok(msg) = Message::from_vec(&query) {
                        let query_key = Self::cache_key(&msg);
                        if let Some((mut cached_msg, ts, ttl)) = cache.get(&query_key).await {
                            if ts.elapsed().as_secs() < ttl as u64 {
                                cached_msg.metadata.id = msg.metadata.id;
                                if let Ok(res_bytes) = cached_msg.to_vec() {
                                    let _ = socket.send_to(&res_bytes, src).await;
                                    return; // 缓存命中，直接返回
                                }
                            } else {
                                cache.invalidate(&query_key).await; // 缓存已过期，从缓存中移除
                            }
                        }
                    }

                    let mut res_opt = None;
                    if let Some(s_name) = &server_name {
                        if let Ok(handle_arc) = pool.get_connection(s_name).await {
                            let default_port = match tunnel_type {
                                TunnelType::DnsDot => 853,
                                TunnelType::DnsDoh => 443,
                                _ => 53,
                            };
                            let (host, port) = crate::tunnel::parse_host_port(&remote_addr, default_port);
                            
                            if let Ok(channel) = handle_arc.channel_open_direct_tcpip(&host, port, "127.0.0.1", 0).await {
                                let stream = channel.into_stream();
                                res_opt = Self::forward_query(stream, &query, &tunnel_type, &host, tls_connector.clone()).await.ok();
                            }
                        }
                    }

                    if res_opt.is_none() {
                        let default_port = match tunnel_type {
                            TunnelType::DnsDot => 853,
                            TunnelType::DnsDoh => 443,
                            _ => 53,
                        };
                        let (host, port) = crate::tunnel::parse_host_port(&remote_addr, default_port);
                        
                        info!("准备直接连接到目标地址: {}:{}", host, port);
                        if let Ok(stream) = tokio::net::TcpStream::connect((host.as_str(), port as u16)).await {
                            info!("连接成功！正在转发 DNS 查询...");
                            res_opt = Self::forward_query(stream, &query, &tunnel_type, &host, tls_connector.clone()).await.ok();
                        }
                    }

                    debug!("收到 {} 字节的 DNS 响应", res_opt.as_ref().map(|b| b.len()).unwrap_or(0));
                    if let Some(res_bytes) = res_opt {
                        let _ = socket.send_to(&res_bytes, src).await;
                        
                        if let Ok(res_msg) = Message::from_vec(&res_bytes) {
                            if res_msg.metadata.response_code == ResponseCode::NoError {
                                let min_ttl = res_msg.answers.iter().map(|r| r.ttl).min().unwrap_or(60);
                                if min_ttl > 0 {
                                    if let Ok(req_msg) = Message::from_vec(&query) {
                                        let key = Self::cache_key(&req_msg);
                                        cache.insert(key, (res_msg, Instant::now(), min_ttl)).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    fn cache_key(msg: &Message) -> Vec<u8> {
        let mut key = Vec::new();
        for q in &msg.queries {
            key.extend_from_slice(q.name().to_string().as_bytes());
            key.push(0);
            let t: u16 = q.query_type().into();
            key.extend_from_slice(&t.to_be_bytes());
            key.push(0);
            let c: u16 = q.query_class().into();
            key.extend_from_slice(&c.to_be_bytes());
        }
        key
    }

    /// 发起具体的 DNS 协议转发，支持三种模式：
    /// 1. Dns (TCP): 通过长度前缀发送标准的 DNS TCP 数据包
    /// 2. DnsDot: 发起 TLS 握手，然后基于 TLS 层发送长度前缀 DNS 报文
    /// 3. DnsDoh: 发起 TLS 握手，构建 HTTP/1.1 GET 请求，将查询报文经过 base64(URL_SAFE) 编码后传入 Query 字符串
    pub async fn forward_query<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
        stream: S,
        query: &[u8],
        tunnel_type: &TunnelType,
        host: &str,
        tls_connector: TlsConnector,
    ) -> Result<Vec<u8>> {
        match tunnel_type {
            TunnelType::Dns => {
                let mut stream = stream;
                let len_bytes = (query.len() as u16).to_be_bytes();
                stream.write_all(&len_bytes).await?;
                stream.write_all(query).await?;
                
                let mut res_len_bytes = [0u8; 2];
                stream.read_exact(&mut res_len_bytes).await?;
                let res_len = u16::from_be_bytes(res_len_bytes) as usize;
                
                let mut res = vec![0u8; res_len];
                stream.read_exact(&mut res).await?;
                Ok(res)
            }
            TunnelType::DnsDot => {
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| anyhow::anyhow!("无效的 DNS 域名格式"))?;
                let mut tls_stream = tls_connector.connect(server_name, stream).await?;
                
                let len_bytes = (query.len() as u16).to_be_bytes();
                tls_stream.write_all(&len_bytes).await?;
                tls_stream.write_all(query).await?;
                
                let mut res_len_bytes = [0u8; 2];
                tls_stream.read_exact(&mut res_len_bytes).await?;
                let res_len = u16::from_be_bytes(res_len_bytes) as usize;
                
                let mut res = vec![0u8; res_len];
                tls_stream.read_exact(&mut res).await?;
                Ok(res)
            }
            TunnelType::DnsDoh => {
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| anyhow::anyhow!("无效的 DNS 域名格式"))?;
                let mut tls_stream = tls_connector.connect(server_name, stream).await?;
                
                let base64_query = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query);
                
                // 构建标准的 HTTP/1.1 GET 请求
                let req = format!(
                    "GET /dns-query?dns={} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n",
                    base64_query, host
                );
                tls_stream.write_all(req.as_bytes()).await?;
                
                let mut response_buf = Vec::new();
                tls_stream.read_to_end(&mut response_buf).await?;
                
                // 解析基础 HTTP 响应（定位空行并提取消息体）
                if let Some(pos) = response_buf.windows(4).position(|window| window == b"\r\n\r\n") {
                    let body = &response_buf[pos + 4..];
                    Ok(body.to_vec())
                } else {
                    error!("HTTP 响应异常: {}", String::from_utf8_lossy(&response_buf));
                    Err(anyhow::anyhow!("无效的 HTTP 响应格式"))
                }
            }
            _ => Err(anyhow::anyhow!("不支持的 DNS 隧道类型")),
        }
    }
}
