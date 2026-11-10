use crate::config::TunnelType;
use crate::pool::ServerPool;
use anyhow::Result;
use base64::Engine;
use hickory_proto::op::{Message, ResponseCode};
use log::{debug, error, info};
use moka::future::Cache;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;

/// 核心 DNS 服务器模块
/// 支持标准的 DNS (UDP 转 TCP)、DNS over TLS (DoT) 和 DNS over HTTPS (DoH)。
/// 内置基于 Moka 的高性能异步 TTL 缓存机制。
pub struct DnsServer {
    cache: Cache<Vec<u8>, (Message, Instant, u32)>,
}

impl Default for DnsServer {
    fn default() -> Self {
        Self::new()
    }
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
                    let default_port = match tunnel_type {
                        TunnelType::DnsDot => 853,
                        TunnelType::DnsDoh => 443,
                        _ => 53,
                    };
                    let (host, port) = crate::tunnel::parse_host_port(&remote_addr, default_port);

                    if let Some(s_name) = &server_name {
                        // 经 SSH 隧道转发；任一环节失败仅记录错误，
                        // 不回退明文直连（避免 DNS 查询绕过隧道泄露隐私）
                        match pool.get_connection(s_name).await {
                            Ok(handle_arc) => {
                                match handle_arc
                                    .channel_open_direct_tcpip(&host, port, "127.0.0.1", 0)
                                    .await
                                {
                                    Ok(channel) => {
                                        let stream = channel.into_stream();
                                        match Self::forward_query(
                                            stream,
                                            &query,
                                            &tunnel_type,
                                            &host,
                                            tls_connector.clone(),
                                        )
                                        .await
                                        {
                                            Ok(res) => res_opt = Some(res),
                                            Err(e) => error!(
                                                "经 SSH 隧道 {} 转发 DNS 查询失败: {}",
                                                s_name, e
                                            ),
                                        }
                                    }
                                    Err(e) => {
                                        error!("经 SSH 节点 {} 打开 DNS 通道失败: {}", s_name, e)
                                    }
                                }
                            }
                            Err(e) => {
                                error!("获取 SSH 节点 {} 连接失败，丢弃 DNS 查询: {}", s_name, e)
                            }
                        }
                    } else {
                        // 该隧道未绑定 SSH 服务器，即明确配置为直连上游 DNS
                        info!("准备直接连接到目标地址: {}:{}", host, port);
                        if let Ok(stream) =
                            tokio::net::TcpStream::connect((host.as_str(), port as u16)).await
                        {
                            info!("连接成功！正在转发 DNS 查询...");
                            res_opt = Self::forward_query(
                                stream,
                                &query,
                                &tunnel_type,
                                &host,
                                tls_connector.clone(),
                            )
                            .await
                            .ok();
                        }
                    }

                    debug!(
                        "收到 {} 字节的 DNS 响应",
                        res_opt.as_ref().map(|b| b.len()).unwrap_or(0)
                    );
                    if let Some(res_bytes) = res_opt {
                        let _ = socket.send_to(&res_bytes, src).await;

                        if let Ok(res_msg) = Message::from_vec(&res_bytes)
                            && res_msg.metadata.response_code == ResponseCode::NoError
                        {
                            let min_ttl = res_msg.answers.iter().map(|r| r.ttl).min().unwrap_or(60);
                            if min_ttl > 0
                                && let Ok(req_msg) = Message::from_vec(&query)
                            {
                                let key = Self::cache_key(&req_msg);
                                cache.insert(key, (res_msg, Instant::now(), min_ttl)).await;
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
    pub async fn forward_query<
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    >(
        stream: S,
        query: &[u8],
        tunnel_type: &TunnelType,
        host: &str,
        tls_connector: TlsConnector,
    ) -> Result<Vec<u8>> {
        let res = match tunnel_type {
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
                res
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
                res
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

                Self::parse_doh_response(&response_buf)?
            }
            _ => return Err(anyhow::anyhow!("不支持的 DNS 隧道类型")),
        };

        // 返回前校验响应与本次查询关联（QR/ID/Question），不匹配则丢弃
        Self::validate_dns_response(&res, query)?;
        Ok(res)
    }

    /// 解析 DoH（HTTP/1.1）响应并提取 DNS 报文 body：
    /// - 校验状态行必须为 2xx（错误页不会当作 DNS 报文返回）
    /// - `Transfer-Encoding: chunked` 时按 chunked 编码解码
    /// - 优先按 `Content-Length` 精确截断 body，防止 trailing 数据混入
    fn parse_doh_response(response_buf: &[u8]) -> Result<Vec<u8>> {
        let pos = response_buf
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| {
                error!("HTTP 响应异常: {}", String::from_utf8_lossy(response_buf));
                anyhow::anyhow!("无效的 HTTP 响应格式")
            })?;
        let head = &response_buf[..pos];
        let body = &response_buf[pos + 4..];

        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("无法解析 HTTP 状态行: {}", status_line))?;
        if !(200..300).contains(&code) {
            return Err(anyhow::anyhow!("DoH 上游返回非 2xx 状态码: {}", code));
        }

        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_ascii_lowercase();
                let v = v.trim();
                if k == "content-length" {
                    content_length = v.parse().ok();
                } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                }
            }
        }

        if chunked {
            return Self::decode_chunked_body(body);
        }
        match content_length {
            Some(n) if n <= body.len() => Ok(body[..n].to_vec()),
            Some(n) => Err(anyhow::anyhow!(
                "DoH 响应 body 长度不足：期望 {} 字节，实际 {} 字节",
                n,
                body.len()
            )),
            None => Ok(body.to_vec()),
        }
    }

    /// 解码 HTTP chunked 编码的 body（最小实现：忽略 chunk extensions 与 trailer）
    fn decode_chunked_body(mut rest: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let pos = rest
                .windows(2)
                .position(|window| window == b"\r\n")
                .ok_or_else(|| anyhow::anyhow!("chunked 编码缺少行结束符"))?;
            let size_str = std::str::from_utf8(&rest[..pos])
                .map_err(|_| anyhow::anyhow!("chunked 长度行不是合法 UTF-8"))?;
            let size_str = size_str.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16)
                .map_err(|_| anyhow::anyhow!("无效的 chunk 长度"))?;
            rest = &rest[pos + 2..];
            if size == 0 {
                break;
            }
            if rest.len() < size + 2 {
                return Err(anyhow::anyhow!("chunked 数据被截断"));
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size..];
            if rest.len() < 2 || &rest[..2] != b"\r\n" {
                return Err(anyhow::anyhow!("chunked 数据缺少 CRLF 分隔"));
            }
            rest = &rest[2..];
        }
        Ok(out)
    }

    /// 校验上游返回的 DNS 报文与本次查询关联：
    /// 必须是响应（QR=1）、ID 与请求一致、Question 与请求匹配；
    /// 不匹配视为错误丢弃（不缓存、不返回客户端）。
    fn validate_dns_response(res: &[u8], query: &[u8]) -> Result<()> {
        let res_msg = Message::from_vec(res)
            .map_err(|e| anyhow::anyhow!("上游返回的 DNS 报文无法解析: {}", e))?;
        if res_msg.metadata.message_type != hickory_proto::op::MessageType::Response {
            return Err(anyhow::anyhow!("上游返回的报文 QR=0，不是响应"));
        }
        let req_msg =
            Message::from_vec(query).map_err(|e| anyhow::anyhow!("请求报文无法解析: {}", e))?;
        if res_msg.metadata.id != req_msg.metadata.id {
            return Err(anyhow::anyhow!(
                "上游响应 ID({}) 与请求 ID({}) 不匹配",
                res_msg.metadata.id,
                req_msg.metadata.id
            ));
        }
        if res_msg.queries != req_msg.queries {
            return Err(anyhow::anyhow!("上游响应的 Question 与请求不匹配"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn build_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));
        msg
    }

    fn build_response(req: &Message) -> Message {
        let mut res = req.clone();
        res.metadata.message_type = MessageType::Response;
        res
    }

    #[test]
    fn validate_accepts_matching_response() {
        let req = build_query(0x1234, "www.example.com.");
        let res = build_response(&req);
        let res_bytes = res.to_vec().unwrap();
        assert!(DnsServer::validate_dns_response(&res_bytes, &req.to_vec().unwrap()).is_ok());
    }

    /// ID 与请求不一致的响应必须被拒（防止串包/污染报文被缓存或返回）
    #[test]
    fn validate_rejects_mismatched_id() {
        let req = build_query(0x1234, "www.example.com.");
        let res = build_response(&build_query(0x5678, "www.example.com."));
        debug_assert_ne!(res.metadata.id, req.metadata.id);
        let res_bytes = res.to_vec().unwrap();
        assert!(DnsServer::validate_dns_response(&res_bytes, &req.to_vec().unwrap()).is_err());
    }

    /// QR=0 的报文不是响应，必须被拒
    #[test]
    fn validate_rejects_non_response() {
        let req = build_query(0x1234, "www.example.com.");
        // 直接拿请求当"响应"返回
        let bytes = req.to_vec().unwrap();
        assert!(DnsServer::validate_dns_response(&bytes, &bytes).is_err());
    }

    /// Question 与请求不匹配必须被拒
    #[test]
    fn validate_rejects_mismatched_question() {
        let req = build_query(0x1234, "www.example.com.");
        let res = build_response(&build_query(0x1234, "evil.example.com."));
        let res_bytes = res.to_vec().unwrap();
        assert!(DnsServer::validate_dns_response(&res_bytes, &req.to_vec().unwrap()).is_err());
    }

    /// DoH 2xx 响应按 Content-Length 精确截断 body
    #[test]
    fn doh_parse_uses_content_length() {
        let body = [0xde, 0xad, 0xbe, 0xef];
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut buf = resp.into_bytes();
        buf.extend_from_slice(&body);
        // 追加 trailing 数据，验证按 Content-Length 截断
        buf.extend_from_slice(&[0x00, 0x11, 0x22]);
        let parsed = DnsServer::parse_doh_response(&buf).unwrap();
        assert_eq!(parsed, body);
    }

    /// 非 2xx 的错误页不得被当作 DNS 报文
    #[test]
    fn doh_parse_rejects_non_2xx() {
        let buf = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nOops!";
        assert!(DnsServer::parse_doh_response(buf).is_err());
        let buf404 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert!(DnsServer::parse_doh_response(buf404).is_err());
    }

    /// chunked 编码的 DoH body 被正确解码（chunk 长度行不会被当作 DNS 报文）
    #[test]
    fn doh_parse_decodes_chunked() {
        let body = b"WOOFHELLO";
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWOOF\r\n5\r\nHELLO\r\n0\r\n\r\n";
        let parsed = DnsServer::parse_doh_response(resp).unwrap();
        assert_eq!(parsed, body);
    }

    /// Content-Length 声明与 body 实际长度不符时报错
    #[test]
    fn doh_parse_rejects_truncated_body() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        assert!(DnsServer::parse_doh_response(buf).is_err());
    }
}
