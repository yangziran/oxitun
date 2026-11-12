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
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

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

/// DNS 查询全链路（通道建立、转发、响应读取）的统一超时
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// DoH 响应最大读取字节数（防止恶意/异常上游耗尽内存）
const DOH_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// UDP 接收缓冲大小：需容纳合法的 EDNS 大查询（1500 会截断）
const UDP_RECV_BUF_SIZE: usize = 4096;

/// 单个 DNS 服务允许的最大并发查询处理数（超出即丢弃，防止无界 spawn）
const MAX_CONCURRENT_QUERIES: usize = 256;

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
    // 参数含 socket/上游/连接池/隧道类型/取消令牌/任务追踪器等完整运行上下文，刻意保持显式
    #[allow(clippy::too_many_arguments)]
    pub async fn run_server_with_socket(
        &self,
        socket: Arc<UdpSocket>,

        remote_addr: String,
        server_name: Option<String>,
        pool: Arc<ServerPool>,
        tunnel_type: TunnelType,
        cancel: CancellationToken,
        tracker: TaskTracker,
    ) -> Result<()> {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()]; // 针对 DoH

        let tls_connector = TlsConnector::from(Arc::new(config));
        // 并发许可：每个数据报消耗一个许可，耗尽时丢弃查询并记 debug 日志
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES));

        let mut buf = [0u8; UDP_RECV_BUF_SIZE];
        loop {
            if let Ok((len, src)) = socket.recv_from(&mut buf).await {
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!("DNS 并发查询数已达上限，丢弃来自 {} 的查询", src);
                        continue;
                    }
                };
                let query = buf[..len].to_vec();
                let socket = socket.clone();
                let remote_addr = remote_addr.clone();
                let pool = pool.clone();
                let server_name = server_name.clone();
                let cache = self.cache.clone();
                let tunnel_type = tunnel_type.clone();
                let tls_connector = tls_connector.clone();
                let cancel = cancel.clone();

                // 查询任务纳入隧道级 TaskTracker：stop_tunnel 时统一等待收尾
                tracker.spawn(async move {
                    tokio::select! {
                        biased;
                        // 隧道停止：丢弃未完成的查询任务（permit 随任务 drop 自动归还）
                        _ = cancel.cancelled() => {}
                        _ = async {
                            // 持有许可直到本查询处理完毕，析构时自动归还
                            let _permit = permit;
                            // 含任何 OPT 选项的查询均可能改变响应，保守绕过缓存
                            let uncacheable = Self::is_uncacheable(&query);
                            let query_key = Self::cache_key(&query);
                            if let Ok(msg) = Message::from_vec(&query)
                                && !uncacheable
                                && let Some((mut cached_msg, inserted_at, ttl)) =
                                    cache.get(&query_key).await
                            {
                                if let Some(elapsed) = Self::cache_freshness(inserted_at, ttl) {
                                    cached_msg.metadata.id = msg.metadata.id;
                                    // 命中时按已缓存时长逐条扣减响应中的 TTL（最低为 0），
                                    // 避免客户端拿到完整 TTL 而超出上游授权期限
                                    if let Ok(mut res_bytes) = cached_msg.to_vec()
                                        && Self::adjust_response_ttl(&mut res_bytes, elapsed)
                                    {
                                        let _ = socket.send_to(&res_bytes, src).await;
                                        return; // 缓存命中，直接返回
                                    }
                                    // 序列化或 TTL 扣减失败：落到上游查询路径
                                } else {
                                    cache.invalidate(&query_key).await; // 缓存已过期，从缓存中移除
                                }
                            }

                    let mut res_opt = None;
                    let default_port = match tunnel_type {
                        TunnelType::DnsDot => 853,
                        TunnelType::DnsDoh => 443,
                        _ => 53,
                    };
                    let (host, port) =
                        match crate::tunnel::parse_host_port(&remote_addr, default_port) {
                            Ok(hp) => hp,
                            Err(e) => {
                                error!("解析上游 DNS 地址 {} 失败: {}，丢弃查询", remote_addr, e);
                                return;
                            }
                        };

                    if let Some(s_name) = &server_name {
                        // 经 SSH 隧道转发；任一环节失败仅记录错误，
                        // 不回退明文直连（避免 DNS 查询绕过隧道泄露隐私）
                        match pool.get_connection(s_name).await {
                            Ok(handle_arc) => {
                                let open_fut = handle_arc.channel_open_direct_tcpip(
                                    &host,
                                    port,
                                    "127.0.0.1",
                                    0,
                                );
                                match tokio::time::timeout(DNS_QUERY_TIMEOUT, open_fut).await {
                                    Ok(Ok(channel)) => {
                                        let stream = channel.into_stream();
                                        match tokio::time::timeout(
                                            DNS_QUERY_TIMEOUT,
                                            Self::forward_query(
                                                stream,
                                                &query,
                                                &tunnel_type,
                                                &host,
                                                tls_connector.clone(),
                                            ),
                                        )
                                        .await
                                        {
                                            Ok(Ok(res)) => res_opt = Some(res),
                                            Ok(Err(e)) => error!(
                                                "经 SSH 隧道 {} 转发 DNS 查询失败: {}",
                                                s_name, e
                                            ),
                                            Err(_) => {
                                                error!("经 SSH 隧道 {} 转发 DNS 查询超时", s_name)
                                            }
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        error!("经 SSH 节点 {} 打开 DNS 通道失败: {}", s_name, e)
                                    }
                                    Err(_) => {
                                        error!("经 SSH 节点 {} 打开 DNS 通道超时", s_name)
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
                        match tokio::time::timeout(
                            DNS_QUERY_TIMEOUT,
                            // parse_host_port 已校验端口 ≤ 65535，此处截断转换是安全的
                            tokio::net::TcpStream::connect((host.as_str(), port as u16)),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                info!("连接成功！正在转发 DNS 查询...");
                                res_opt = tokio::time::timeout(
                                    DNS_QUERY_TIMEOUT,
                                    Self::forward_query(
                                        stream,
                                        &query,
                                        &tunnel_type,
                                        &host,
                                        tls_connector.clone(),
                                    ),
                                )
                                .await
                                .ok()
                                .and_then(|r| r.ok());
                            }
                            Ok(Err(e)) => {
                                error!("直连上游 DNS {}:{} 失败: {}", host, port, e)
                            }
                            Err(_) => {
                                error!("直连上游 DNS {}:{} 超时", host, port)
                            }
                        }
                    }

                    debug!(
                        "收到 {} 字节的 DNS 响应",
                        res_opt.as_ref().map(|b| b.len()).unwrap_or(0)
                    );
                    if let Some(res_bytes) = res_opt {
                        let _ = socket.send_to(&res_bytes, src).await;

                        if let Ok(res_msg) = Message::from_vec(&res_bytes)
                        && !uncacheable
                        && let Some(min_ttl) = Self::cacheable_ttl(&res_msg, &res_bytes)
                    {
                        let key = Self::cache_key(&query);
                        cache.insert(key, (res_msg, Instant::now(), min_ttl)).await;
                    }
                    }
                    } => {}
                }
                });
            }
        }
    }

    /// 计算缓存键：Question 的 name/qtype/qclass（原始报文字节）加上
    /// DNSSEC 语义标志 (DO bit, CD bit, RD bit)，以及是否存在 OPT、EDNS version
    /// 和 UDP payload size，避免不同 DNSSEC/EDNS 语义的查询互相复用错误缓存。
    /// 含任何 OPT 选项的查询由 is_uncacheable 直接绕过缓存，无需把选项原文放入键。
    fn cache_key(query: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        if query.len() >= 12 {
            let mut pos = 12; // 跳过报文头
            let qdcount = u16::from_be_bytes([query[4], query[5]]) as usize;
            for _ in 0..qdcount {
                match Self::skip_name(query, pos) {
                    // Question：NAME + QTYPE(2) + QCLASS(2)
                    Some(p) if p + 4 <= query.len() => {
                        key.extend_from_slice(&query[pos..p + 4]);
                        pos = p + 4;
                    }
                    _ => break, // Question 段无法解析时仅用标志位作键
                }
            }
        }
        let (do_bit, cd_bit, rd_bit) = Self::dnssec_flags(query);
        key.push(do_bit as u8);
        key.push(cd_bit as u8);
        key.push(rd_bit as u8);
        let (has_opt, version, payload_size) = Self::parse_opt(query)
            .map(|(_, _, version, payload_size)| (true, version, payload_size))
            .unwrap_or((false, 0, 0));
        key.push(has_opt as u8);
        key.push(version);
        key.extend_from_slice(&payload_size.to_be_bytes());
        key
    }

    /// 跳过 DNS 名称字段（支持压缩指针 0xC0 与常规定长标签），
    /// 返回名称字段之后的位置；名称非法或越界时返回 None
    fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            let len = *buf.get(pos)? as usize;
            if len == 0 {
                // 根标签（0x00）：名称结束
                return Some(pos + 1);
            }
            if len & 0xC0 == 0xC0 {
                // 压缩指针：占 2 字节，名称到此结束
                return pos.checked_add(2).filter(|&p| p <= buf.len());
            }
            if len & 0xC0 != 0 {
                return None; // 0x40/0x80 标签在 DNS 中未使用
            }
            pos = pos.checked_add(1 + len)?;
            if pos > buf.len() {
                return None;
            }
        }
    }

    /// 从原始查询报文提取 DNS 语义标志：(DO bit, CD bit, RD bit)
    /// - RD bit：报文头 flags 字段（固定偏移 2..4）的 0x0100 位
    /// - CD bit：报文头 flags 字段（固定偏移 2..4）的 0x0010 位
    /// - DO bit：附加段 OPT 记录（type 41）TTL 字段低 16 位标志字段的最高位（0x0000_8000）
    ///
    /// 解析失败（报文过短/无附加段/无 OPT）按 (false, false, false) 处理
    fn dnssec_flags(query: &[u8]) -> (bool, bool, bool) {
        let cd_bit = query.len() >= 4 && (u16::from_be_bytes([query[2], query[3]]) & 0x0010) != 0;
        let rd_bit = query.len() >= 4 && (u16::from_be_bytes([query[2], query[3]]) & 0x0100) != 0;
        let do_bit = Self::parse_opt(query)
            .map(|(do_bit, _, _, _)| do_bit)
            .unwrap_or(false);
        (do_bit, cd_bit, rd_bit)
    }

    /// 判断查询是否应绕过缓存：OPT 记录含任何 RDATA 选项时都直接跳过缓存读写。
    /// NSID/ECS/Cookie 及其他选项均可能改变响应，采用保守策略避免错误复用；
    /// 无选项或仅设置 DO bit 的 EDNS 查询仍可正常缓存。
    fn is_uncacheable(query: &[u8]) -> bool {
        Self::parse_opt(query)
            .map(|(_, uncacheable, _, _)| uncacheable)
            .unwrap_or(false)
    }

    /// 遍历资源记录查找 OPT 记录（type 41），返回
    /// (DO bit, 是否含任何选项, EDNS version, UDP payload size)；
    /// 报文不含 OPT 记录或结构非法时返回 None
    fn parse_opt(buf: &[u8]) -> Option<(bool, bool, u8, u16)> {
        if buf.len() < 12 {
            return None;
        }
        let mut pos = 12; // 跳过报文头
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let total = (u16::from_be_bytes([buf[6], buf[7]]) as usize)
            .checked_add(u16::from_be_bytes([buf[8], buf[9]]) as usize)?
            .checked_add(u16::from_be_bytes([buf[10], buf[11]]) as usize)?;

        // 跳过 Question 段
        for _ in 0..qdcount {
            pos = Self::skip_name(buf, pos)?;
            pos = pos.checked_add(4)?; // QTYPE + QCLASS
        }
        // 遍历 Answer/Authority/Additional 资源记录（OPT 只可能出现在附加段，
        // 这里统一遍历三个段，找到第一个 type 41 即返回）
        for _ in 0..total {
            pos = Self::skip_name(buf, pos)?;
            let rdlen_pos = pos.checked_add(8)?; // TYPE(2) + CLASS(2) + TTL(4)
            if rdlen_pos + 2 > buf.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            let rdlen = u16::from_be_bytes([buf[rdlen_pos], buf[rdlen_pos + 1]]) as usize;
            if rtype == 41 {
                // OPT 的 CLASS 是 UDP payload size；TTL 含 extended RCODE、
                // EDNS version 与 DO bit，不能当作普通资源记录 TTL。
                let payload_size = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
                let do_bit = (ttl & 0x0000_8000) != 0;
                let version = ((ttl >> 16) & 0xFF) as u8;
                let rdata_pos = rdlen_pos.checked_add(2)?;
                let rdata_end = rdata_pos.checked_add(rdlen)?;
                if rdata_end > buf.len() {
                    return None;
                }
                // RDATA 非空即表示携带选项；无论选项类型都保守地绕过缓存。
                return Some((do_bit, rdlen > 0, version, payload_size));
            }
            pos = rdlen_pos.checked_add(2)?.checked_add(rdlen)?;
        }
        None
    }

    /// 判定上游响应是否可写入缓存，并计算缓存有效期：
    /// - 仅 NoError 与 NXDomain 响应可缓存（RFC 2308：NXDOMAIN 与 NODATA
    ///   同属负缓存语义）；其余 rcode（ServFail/Refused 等）不缓存
    /// - 无 Answer（NODATA/NXDOMAIN）时走负缓存路径，有效期从 Authority 段
    ///   SOA 记录的 MINIMUM 字段推导；无 SOA 或解析失败时不缓存
    /// - 有 Answer 时取 Answer/Authority/Additional 所有非 OPT 记录 TTL 的最小值，
    ///   避免缓存响应中的短 TTL 附加记录过期后仍被重发
    /// - 无有效记录或有效期为 0 时返回 None（不写入缓存）
    fn cacheable_ttl(res_msg: &Message, res_bytes: &[u8]) -> Option<u32> {
        if !matches!(
            res_msg.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return None;
        }
        let min_ttl = if res_msg.answers.is_empty() {
            Self::parse_negative_ttl(res_bytes)?
        } else {
            res_msg
                .all_sections()
                .filter(|r| r.record_type() != hickory_proto::rr::RecordType::OPT)
                .map(|r| r.ttl)
                .min()?
        };
        (min_ttl > 0).then_some(min_ttl)
    }

    /// 解析负缓存 TTL（RFC 2308）：解析 Authority 段中的 SOA（TYPE=6）记录，
    /// 其 RDATA 布局为 MNAME + RNAME + SERIAL(4) + REFRESH(4) + RETRY(4) +
    /// EXPIRE(4) + MINIMUM(4)，负缓存有效期 = min(SOA TTL 字段, MINIMUM)，
    /// 并 clamp 到 NEGATIVE_TTL_MAX 上限（防恶意大值）；
    /// 无 SOA 记录或报文结构非法时没有权威负缓存 TTL，返回 None 表示不缓存
    fn parse_negative_ttl(response: &[u8]) -> Option<u32> {
        /// 负缓存有效期上限（防 SOA 中恶意超大 TTL/MINIMUM）
        const NEGATIVE_TTL_MAX: u32 = 300;

        if response.len() < 12 {
            return None;
        }
        let mut pos = 12; // 跳过报文头
        let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
        let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;

        // 跳过 Question 段（NAME + QTYPE(2) + QCLASS(2)）
        for _ in 0..qdcount {
            match Self::skip_name(response, pos) {
                Some(p) if p + 4 <= response.len() => pos = p + 4,
                _ => return None,
            }
        }

        // 只遍历 Authority 段（Answer 段已在调用方确认无记录）
        for _ in 0..nscount {
            match Self::skip_name(response, pos) {
                Some(p) if p + 10 <= response.len() => pos = p,
                _ => return None,
            }
            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            let rdata_pos = pos + 10;
            if rtype == 6 {
                // SOA：跳过 MNAME、RNAME 两个域名后依次读取 5 个 u32 字段，
                // 最后一个即 MINIMUM（负缓存时长取 SOA TTL 与 MINIMUM 的较小者）
                let mname_end = Self::skip_name(response, rdata_pos)?;
                let rname_end = Self::skip_name(response, mname_end)?;
                let fields_end = match rname_end.checked_add(5 * 4) {
                    Some(e) if e <= response.len() && e <= rdata_pos + rdlen => e,
                    _ => return None,
                };
                let minimum = u32::from_be_bytes([
                    response[fields_end - 4],
                    response[fields_end - 3],
                    response[fields_end - 2],
                    response[fields_end - 1],
                ]);
                return Some(ttl.min(minimum).min(NEGATIVE_TTL_MAX));
            }
            pos = match rdata_pos.checked_add(rdlen) {
                Some(p) if p <= response.len() => p,
                _ => return None,
            };
        }
        None
    }

    /// 判断缓存条目是否仍在有效期内：
    /// 返回 Some(elapsed) 表示新鲜（elapsed 为已缓存秒数，供 TTL 扣减），
    /// 返回 None 表示 elapsed >= 原始 TTL，已过期需回源重新查询
    fn cache_freshness(inserted_at: Instant, ttl: u32) -> Option<u32> {
        let elapsed = u32::try_from(inserted_at.elapsed().as_secs()).unwrap_or(u32::MAX);
        (elapsed < ttl).then_some(elapsed)
    }

    /// 将响应报文 Answer/Authority/Additional 段所有资源记录的 TTL
    /// 统一扣减 elapsed 秒（饱和到 0），避免客户端再缓存接近一个完整 TTL。
    /// 按名称（含压缩指针）/TYPE/CLASS/TTL/RDLENGTH 步进定位每条记录的 TTL
    /// 字段并逐条改写；报文结构非法时返回 false（调用方应回源查询）
    fn adjust_response_ttl(buf: &mut [u8], elapsed: u32) -> bool {
        if buf.len() < 12 {
            return false;
        }
        let mut pos = 12; // 跳过报文头
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let total = match (u16::from_be_bytes([buf[6], buf[7]]) as usize)
            .checked_add(u16::from_be_bytes([buf[8], buf[9]]) as usize)
            .and_then(|n| n.checked_add(u16::from_be_bytes([buf[10], buf[11]]) as usize))
        {
            Some(n) => n,
            None => return false,
        };

        // 跳过 Question 段（NAME + QTYPE(2) + QCLASS(2)）
        for _ in 0..qdcount {
            match Self::skip_name(buf, pos) {
                Some(p) if p + 4 <= buf.len() => pos = p + 4,
                _ => return false,
            }
        }

        // 逐条处理资源记录：NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
        for _ in 0..total {
            match Self::skip_name(buf, pos) {
                Some(p) if p + 10 <= buf.len() => pos = p,
                _ => return false,
            }
            let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
            // OPT 记录（TYPE=41，RFC 6891）的 TTL 字段承载 extended RCODE/version/DO bit
            // 等 EDNS 标志而非真实 TTL，扣减会篡改 DO bit 导致 EDNS 语义损坏，必须整条跳过；
            // 但 RDLENGTH/RDATA 步进照常，保证后续记录定位不受影响
            if rtype != 41 {
                let ttl_pos = pos + 4;
                let ttl = u32::from_be_bytes([
                    buf[ttl_pos],
                    buf[ttl_pos + 1],
                    buf[ttl_pos + 2],
                    buf[ttl_pos + 3],
                ]);
                buf[ttl_pos..ttl_pos + 4]
                    .copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
            }
            pos = match pos.checked_add(10).and_then(|p| p.checked_add(rdlen)) {
                Some(p) if p <= buf.len() => p,
                _ => return false,
            };
        }
        true
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

                // 限制最大读取 1MB，防止异常上游响应耗尽内存
                let mut response_buf = Vec::new();
                tls_stream
                    .take(DOH_MAX_RESPONSE_BYTES)
                    .read_to_end(&mut response_buf)
                    .await?;

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
            // chunk 长度极大时 size + 2 会溢出，必须用 checked 运算
            let needed = size
                .checked_add(2)
                .ok_or_else(|| anyhow::anyhow!("chunk 长度超出可表示范围"))?;
            if rest.len() < needed {
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

    /// chunk 长度极大（接近 usize::MAX）时不得溢出 panic，也不得越界读取，
    /// 数据不足必须返回 Err
    #[test]
    fn doh_parse_rejects_huge_chunk_size() {
        // usize::MAX 的 chunk 长度：size + 2 会溢出
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nAB\r\n0\r\n\r\n";
        assert!(DnsServer::parse_doh_response(resp).is_err());
        // 超出 usize 表示范围的 chunk 长度：解析必须失败
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\nAB\r\n0\r\n\r\n";
        assert!(DnsServer::parse_doh_response(resp).is_err());
        // 大但可表示的 chunk 长度：数据不足必须报截断而非越界 panic
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\nAB\r\n0\r\n\r\n";
        assert!(DnsServer::parse_doh_response(resp).is_err());
    }

    /// Content-Length 声明与 body 实际长度不符时报错
    #[test]
    fn doh_parse_rejects_truncated_body() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        assert!(DnsServer::parse_doh_response(buf).is_err());
    }

    /// 构造 Answer/Authority/Additional 各一条、TTL 均为 ttl 的响应报文
    /// （记录名称用压缩指针指向 Question，覆盖指针跳过路径）
    fn response_with_ttl(ttl: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // 标准响应 flags
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        for label in ["www", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        for _ in 0..3 {
            buf.extend_from_slice(&[0xC0, 0x0C]); // 压缩指针指向 Question
            buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
            buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
            buf.extend_from_slice(&ttl.to_be_bytes()); // TTL
            buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            buf.extend_from_slice(&[93, 184, 216, 34]); // RDATA
        }
        buf
    }

    /// 缓存命中扣减 TTL：TTL 60 的响应缓存 2 秒后，返回报文的 TTL 应为 58，
    /// 且 Answer/Authority/Additional 三段全部扣减
    #[test]
    fn adjust_response_ttl_deducts_elapsed() {
        let mut res = response_with_ttl(60);
        assert!(DnsServer::adjust_response_ttl(&mut res, 2));
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(msg.answers[0].ttl, 58);
        assert_eq!(msg.authorities[0].ttl, 58);
        assert_eq!(msg.additionals[0].ttl, 58);
    }

    /// 扣减时长超过原始 TTL 时饱和到 0，不出现下溢
    #[test]
    fn adjust_response_ttl_saturates_at_zero() {
        let mut res = response_with_ttl(60);
        assert!(DnsServer::adjust_response_ttl(&mut res, 300));
        let msg = Message::from_vec(&res).unwrap();
        assert!(msg.answers.iter().all(|r| r.ttl == 0));
        assert!(msg.authorities.iter().all(|r| r.ttl == 0));
        assert!(msg.additionals.iter().all(|r| r.ttl == 0));
    }

    /// 非法/截断报文不得越界，返回 false
    #[test]
    fn adjust_response_ttl_rejects_malformed() {
        assert!(!DnsServer::adjust_response_ttl(&mut [], 1));
        let mut short = vec![0u8; 11];
        assert!(!DnsServer::adjust_response_ttl(&mut short, 1));
        // 声明有 Answer 但报文被截断
        let mut truncated = response_with_ttl(60);
        truncated.truncate(truncated.len() - 5);
        assert!(!DnsServer::adjust_response_ttl(&mut truncated, 1));
    }

    /// OPT 记录（TYPE=41）的 TTL 字段承载 extended RCODE/version/DO bit 等
    /// EDNS 标志（RFC 6891），扣减 TTL 时必须整条跳过不得篡改；
    /// 同报文内其他记录的 TTL 仍应正确扣减
    #[test]
    fn adjust_response_ttl_skips_opt_record() {
        // 构造：1 个 Question + 1 条 A 应答（TTL 60）+ 附加段 1 条 OPT（DO bit 置位）
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // 标准响应 flags
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        for label in ["www", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        // Answer：A 记录，TTL 60
        buf.extend_from_slice(&[0xC0, 0x0C]); // 压缩指针指向 Question
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&60u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buf.extend_from_slice(&[93, 184, 216, 34]); // RDATA
        // Additional：OPT 记录，TTL = 0x0000_8000（DO bit 置位），RDLENGTH = 0
        let opt_ttl_pos = buf.len() + 5; // NAME(1) + TYPE(2) + CLASS(2) 之后即 TTL
        buf.push(0x00); // 根名称
        buf.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        buf.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP 载荷大小
        buf.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // TTL：DO bit 置位
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

        assert!(DnsServer::adjust_response_ttl(&mut buf, 10));
        // OPT 记录的 TTL 字段（含 DO bit）必须保持原值，不得被扣减
        assert_eq!(
            &buf[opt_ttl_pos..opt_ttl_pos + 4],
            &0x0000_8000u32.to_be_bytes(),
            "OPT 记录的 TTL 字段（EDNS 标志位）不得被 TTL 扣减篡改"
        );
        // A 应答的 TTL 仍被正确扣减（60 - 10 = 50），且报文整体仍可解析
        let msg = Message::from_vec(&buf).unwrap();
        assert_eq!(msg.answers[0].ttl, 50);
    }

    /// elapsed >= 原始 TTL 时视为过期，不得再从缓存返回
    #[test]
    fn cache_entry_expires_when_elapsed_reaches_ttl() {
        let inserted = Instant::now() - Duration::from_secs(60);
        assert_eq!(DnsServer::cache_freshness(inserted, 60), None);
        // 未到期时返回 elapsed 供 TTL 扣减（TTL 58 + 已缓存 2 秒 = 原始 60）
        let fresh = Instant::now() - Duration::from_secs(2);
        assert_eq!(DnsServer::cache_freshness(fresh, 60), Some(2));
        assert_eq!(DnsServer::cache_freshness(Instant::now(), 60), Some(0));
    }

    /// 同一 Question 在不同 DO/CD 标志下必须产生不同缓存键
    #[test]
    fn cache_key_includes_do_cd_flags() {
        let base = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        let base_key = DnsServer::cache_key(&base);

        // 仅 CD 位置位（报文头 flags 偏移 3 的 0x10 位）
        let mut cd_only = base.clone();
        cd_only[3] |= 0x10;
        let cd_key = DnsServer::cache_key(&cd_only);
        assert_ne!(base_key, cd_key);

        // 仅 DO 位置位：附加段追加 OPT 记录（type 41，TTL 低 16 位标志字段最高位为 DO bit）
        let mut do_only = base.clone();
        do_only[11] = 1; // ARCOUNT = 1
        do_only.extend_from_slice(&[
            0x00, // 根名称
            0x00, 41, // TYPE = OPT (41)
            0x10, 0x00, // CLASS = UDP 载荷大小 4096
            0x00, 0x00, 0x80, 0x00, // TTL：DO bit 置位
            0x00, 0x00, // RDLENGTH = 0
        ]);
        let do_key = DnsServer::cache_key(&do_only);
        assert_ne!(base_key, do_key);
        assert_ne!(cd_key, do_key);

        // DO + CD 同时置位又是另一个键
        let mut both = cd_only;
        both[11] = 1;
        both.extend_from_slice(&[
            0x00, 0x00, 41, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        ]);
        let both_key = DnsServer::cache_key(&both);
        assert_ne!(both_key, base_key);
        assert_ne!(both_key, cd_key);
        assert_ne!(both_key, do_key);

        // 不同 Question 的键仍不同（避免回归）
        let other = build_query(0x1234, "other.example.com.").to_vec().unwrap();
        assert_ne!(DnsServer::cache_key(&other), base_key);
    }

    /// 无附加段/无 OPT 或报文截断时按 (false, false, false) 处理且不 panic
    #[test]
    fn cache_key_treats_missing_opt_as_false() {
        let q = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        assert_eq!(DnsServer::dnssec_flags(&q), (false, false, false));
        assert_eq!(DnsServer::dnssec_flags(&q[..6]), (false, false, false));
        assert_eq!(DnsServer::dnssec_flags(&[]), (false, false, false));
    }

    /// RD=1 与 RD=0 的同 Question 查询必须产生不同缓存键
    #[test]
    fn cache_key_includes_rd_flag() {
        let base = build_query(0x1234, "www.example.com.").to_vec().unwrap();

        let mut rd0 = base.clone();
        rd0[2] &= !0x01; // RD=0（flags 0x0100 的网络序高字节为字节 2）
        let mut rd1 = base.clone();
        rd1[2] |= 0x01; // RD=1

        let rd0_key = DnsServer::cache_key(&rd0);
        let rd1_key = DnsServer::cache_key(&rd1);
        assert_ne!(rd0_key, rd1_key, "RD 位不同必须产生不同缓存键");
        // 与 DO/CD 键测试一致：其他标志不变时键仍由 Question 决定
        let other = build_query(0x1234, "other.example.com.").to_vec().unwrap();
        assert_ne!(DnsServer::cache_key(&other), rd1_key);
    }

    /// 构造带指定 EDNS 元数据和 RDATA 选项列表的查询报文
    fn query_with_opt(options: &[u8], version: u8, payload_size: u16) -> Vec<u8> {
        let mut q = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        q[11] = 1; // ARCOUNT = 1
        q.push(0x00); // 根名称
        q.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT (41)
        q.extend_from_slice(&payload_size.to_be_bytes()); // CLASS = UDP 载荷大小
        q.extend_from_slice(&[0x00, version, 0x00, 0x00]); // TTL：version，无 DO bit
        q.extend_from_slice(&(options.len() as u16).to_be_bytes()); // RDLENGTH
        q.extend_from_slice(options);
        q
    }

    fn query_with_opt_options(options: &[u8]) -> Vec<u8> {
        query_with_opt(options, 0, 4096)
    }

    /// 含任意 OPT 选项的查询都必须绕过缓存；普通查询及无选项的 OPT 不受影响
    #[test]
    fn is_uncacheable_detects_all_opt_options() {
        // 普通查询和无选项的 OPT：不绕过缓存
        let plain = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        assert!(!DnsServer::is_uncacheable(&plain));
        assert!(!DnsServer::is_uncacheable(&query_with_opt_options(&[])));

        // NSID（option code 3）即使不含数据，也可能改变响应，必须绕过缓存
        let opt_nsid = query_with_opt_options(&[0x00, 3, 0x00, 0x00]);
        assert!(DnsServer::is_uncacheable(&opt_nsid));

        // ECS（option code 8）与 Cookie（option code 10）同样绕过缓存
        let opt_ecs = query_with_opt_options(&[0x00, 8, 0x00, 4, 0x00, 1, 0x18, 0x00]);
        assert!(DnsServer::is_uncacheable(&opt_ecs));
        let opt_cookie = query_with_opt_options(&[0x00, 10, 0x00, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(DnsServer::is_uncacheable(&opt_cookie));

        // 未知选项及多选项查询也采用相同的保守策略
        let opt_unknown = query_with_opt_options(&[0xFD, 0xE8, 0x00, 0x00]);
        assert!(DnsServer::is_uncacheable(&opt_unknown));
        let opt_multiple = query_with_opt_options(&[
            0x00, 3, 0x00, 0x00, // NSID
            0x00, 10, 0x00, 8, 1, 2, 3, 4, 5, 6, 7, 8, // Cookie
        ]);
        assert!(DnsServer::is_uncacheable(&opt_multiple));
    }

    /// 无 OPT 与带 NSID OPT 的查询不得共享缓存键，且 NSID 查询不读不写缓存
    #[test]
    fn nsid_query_is_separated_and_bypasses_cache() {
        let plain = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        let nsid = query_with_opt_options(&[0x00, 3, 0x00, 0x00]);
        assert_ne!(DnsServer::cache_key(&plain), DnsServer::cache_key(&nsid));
        assert!(DnsServer::is_uncacheable(&nsid));
    }

    /// 是否存在 OPT、EDNS version 和 UDP payload size 都必须参与缓存键
    #[test]
    fn cache_key_includes_edns_metadata() {
        let plain = build_query(0x1234, "www.example.com.").to_vec().unwrap();
        let opt_v0 = query_with_opt(&[], 0, 4096);
        let opt_v1 = query_with_opt(&[], 1, 4096);
        let opt_smaller_payload = query_with_opt(&[], 0, 1232);
        let base_key = DnsServer::cache_key(&plain);
        let v0_key = DnsServer::cache_key(&opt_v0);
        assert_ne!(base_key, v0_key, "有无 OPT 必须产生不同缓存键");
        assert_ne!(v0_key, DnsServer::cache_key(&opt_v1));
        assert_ne!(v0_key, DnsServer::cache_key(&opt_smaller_payload));
    }

    /// 构造 NODATA 响应（ANCOUNT=0，Authority 段一条 SOA 记录）：
    /// SOA TTL 字段为 soa_ttl，RDATA 中 MINIMUM 字段为 minimum
    fn nodata_response_with_soa(soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // 标准响应 flags
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&1u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in ["www", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        // Authority：SOA 记录，名称用压缩指针指向 Question
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&6u16.to_be_bytes()); // TYPE = SOA
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&soa_ttl.to_be_bytes()); // TTL
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH（稍后回填）
        let rdata_start = buf.len();
        for label in ["ns", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // MNAME
        for label in ["hostmaster", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // RNAME
        // SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM
        for v in [1u32, 7200, 3600, 1209600, minimum] {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
        buf
    }

    /// 含 SOA 的 NODATA 响应：负缓存有效期 = min(SOA TTL, MINIMUM)
    #[test]
    fn negative_ttl_uses_soa_minimum() {
        // MINIMUM < TTL：取 MINIMUM
        let res = nodata_response_with_soa(3600, 300);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(300));
        // TTL < MINIMUM：取 TTL
        let res = nodata_response_with_soa(120, 300);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(120));
        // 两者相等（均在 300 秒 clamp 上限以内）
        let res = nodata_response_with_soa(300, 300);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(300));
    }

    /// 负缓存有效期被 clamp 到 300 秒上限（防恶意大值）
    #[test]
    fn negative_ttl_clamps_to_max() {
        let res = nodata_response_with_soa(3600, 3600);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(300));
    }

    /// NXDOMAIN（rcode=3）+ Authority 段含 SOA 的响应必须走 RFC 2308 负缓存
    /// 路径：缓存有效期 = min(SOA TTL, MINIMUM)，与 NODATA 行为一致
    #[test]
    fn nxdomain_response_uses_soa_negative_ttl() {
        let mut res = nodata_response_with_soa(3600, 300);
        // flags 低字节置 RCODE = NXDOMAIN(3)，QR/RA 等标志保持不变
        res[3] = 0x83;
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert!(msg.answers.is_empty());
        // MINIMUM(300) < SOA TTL(3600)，缓存有效期取 300
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(300));
        // SOA TTL(120) < MINIMUM(300)，取 120
        let mut res = nodata_response_with_soa(120, 300);
        res[3] = 0x83;
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(120));
    }

    /// 负缓存门控：仅 NoError/NXDomain 可缓存；
    /// ServFail/Refused 等错误 rcode 不得写入缓存
    #[test]
    fn cacheable_ttl_gates_on_response_code() {
        // NoError + 无 Answer（NODATA）：走负缓存路径
        let res = nodata_response_with_soa(3600, 300);
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(300));

        // ServFail(2)：不缓存
        let mut res = nodata_response_with_soa(3600, 300);
        res[3] = 0x82;
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), None);

        // Refused(5)：不缓存
        let mut res = nodata_response_with_soa(3600, 300);
        res[3] = 0x85;
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), None);

        // NoError + 有 Answer：取三个记录段中所有非 OPT 记录的最小 TTL
        let res = response_with_ttl(60);
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(60));
    }

    /// 正缓存必须受短 TTL 的 Additional 记录约束，且 OPT 的伪 TTL 不参与计算
    #[test]
    fn positive_ttl_uses_all_non_opt_records() {
        let mut res = response_with_ttl(3600);
        // response_with_ttl 的最后一条是 16 字节 Additional A 记录，TTL 位于偏移 6
        let additional_ttl_pos = res.len() - 10;
        res[additional_ttl_pos..additional_ttl_pos + 4].copy_from_slice(&60u32.to_be_bytes());
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(msg.answers[0].ttl, 3600);
        assert_eq!(msg.additionals[0].ttl, 60);
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(60));

        // 追加 TTL 字段为 0 的 OPT；该字段是 EDNS 标志，不得把缓存有效期降为 0
        let mut res = response_with_ttl(3600);
        res[11] = 2; // ARCOUNT = 2
        res.extend_from_slice(&[
            0x00, // 根名称
            0x00, 41, // TYPE = OPT
            0x10, 0x00, // CLASS = UDP 载荷大小 4096
            0x00, 0x00, 0x00, 0x00, // TTL：EDNS 扩展字段
            0x00, 0x00, // RDLENGTH = 0
        ]);
        let msg = Message::from_vec(&res).unwrap();
        assert!(msg.edns.is_some());
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), Some(3600));
    }

    /// 无 SOA 记录（空 Authority 段）或报文非法时没有权威负缓存 TTL，不得缓存
    #[test]
    fn negative_ttl_returns_none_without_soa() {
        // 无 Authority 段的 NODATA 响应
        let mut res = nodata_response_with_soa(3600, 300);
        res[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        let question_end = DnsServer::skip_name(&res, 12).unwrap() + 4;
        res.truncate(question_end); // 保留完整 Question，仅去掉 Authority 记录
        assert_eq!(DnsServer::parse_negative_ttl(&res), None);
        let msg = Message::from_vec(&res).unwrap();
        assert_eq!(DnsServer::cacheable_ttl(&msg, &res), None);
        // 截断/空报文
        assert_eq!(DnsServer::parse_negative_ttl(&[]), None);
        assert_eq!(DnsServer::parse_negative_ttl(&[0u8; 11]), None);
        // 有 Authority 记录但非 SOA（TYPE=A）
        let mut res = nodata_response_with_soa(3600, 300);
        // 头(12) + Question(17) + QTYPE(2) + QCLASS(2) + 压缩指针(2)
        let an_type_pos = 12 + 17 + 4 + 2;
        res[an_type_pos] = 0;
        res[an_type_pos + 1] = 1; // TYPE = A
        assert_eq!(DnsServer::parse_negative_ttl(&res), None);
    }

    /// 构造 Authority 段为 [A 记录, SOA 记录] 的 NODATA 响应：
    /// 前置的非 SOA 记录用于验证步进跳过逻辑；
    /// SOA 的 MNAME/RNAME 均含压缩指针（指向报文前部 Question 中的域名），
    /// 用于验证 RDATA 内压缩指针的处理
    fn nodata_response_with_a_then_soa(soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // 标准响应 flags
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&2u16.to_be_bytes()); // NSCOUNT = 2
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in ["www", "example", "com"] {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        // Authority 记录 1：A 记录（非 SOA，应被步进跳过）
        buf.extend_from_slice(&[0xC0, 0x0C]); // 名称压缩指针指向 Question
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&3600u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buf.extend_from_slice(&[192, 0, 2, 1]); // RDATA
        // Authority 记录 2：SOA 记录
        buf.extend_from_slice(&[0xC0, 0x0C]); // 名称压缩指针指向 Question
        buf.extend_from_slice(&6u16.to_be_bytes()); // TYPE = SOA
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        buf.extend_from_slice(&soa_ttl.to_be_bytes()); // TTL
        let rdlen_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH（稍后回填）
        let rdata_start = buf.len();
        // MNAME：压缩指针指向 Question 中的 example.com（偏移 16）
        buf.extend_from_slice(&[0xC0, 0x10]);
        // RNAME：hostmaster 标签 + 压缩指针指向 example.com
        buf.push(10);
        buf.extend_from_slice(b"hostmaster");
        buf.extend_from_slice(&[0xC0, 0x10]);
        // SERIAL + REFRESH + RETRY + EXPIRE + MINIMUM
        for v in [1u32, 7200, 3600, 1209600, minimum] {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        let rdlen = (buf.len() - rdata_start) as u16;
        buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
        buf
    }

    /// Authority 段含 [非 SOA 记录, SOA 记录] 时，应正确步进跳过前者定位到
    /// SOA；SOA 的 MNAME/RNAME 使用压缩指针也能正确解析出 MINIMUM
    #[test]
    fn negative_ttl_skips_non_soa_and_handles_compressed_mname() {
        // MINIMUM < TTL：取 MINIMUM
        let res = nodata_response_with_a_then_soa(3600, 200);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(200));
        // TTL < MINIMUM：取 TTL
        let res = nodata_response_with_a_then_soa(100, 200);
        assert_eq!(DnsServer::parse_negative_ttl(&res), Some(100));
    }

    /// SOA 的 RDATA 声明长度过小或报文尾部被截断时，
    /// fields_end 越界校验应拒绝解析并返回 None（不缓存）
    #[test]
    fn negative_ttl_returns_none_on_truncated_soa_rdata() {
        // RDLENGTH 被改小：MINIMUM 落在声明的 RDATA 范围之外 → 不缓存
        let mut res = nodata_response_with_soa(3600, 300);
        // 用 skip_name 定位 SOA 的 RDLENGTH 字段，避免硬编码偏移
        let q_end = DnsServer::skip_name(&res, 12).unwrap() + 4; // 跳过 Question
        let name_end = DnsServer::skip_name(&res, q_end).unwrap(); // 跳过记录名
        let rdlen_pos = name_end + 8; // TYPE(2) + CLASS(2) + TTL(4)
        let rdlen = u16::from_be_bytes([res[rdlen_pos], res[rdlen_pos + 1]]);
        res[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen - 8).to_be_bytes());
        assert_eq!(DnsServer::parse_negative_ttl(&res), None);

        // 报文尾部被物理截断（EXPIRE + MINIMUM 缺失）：
        // fields_end 超出报文长度 → 不缓存
        let mut res = nodata_response_with_soa(3600, 300);
        res.truncate(res.len() - 8);
        assert_eq!(DnsServer::parse_negative_ttl(&res), None);
    }
}
