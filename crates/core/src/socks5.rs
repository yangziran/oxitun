use anyhow::{Result, anyhow};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 解析后提取出的 SOCKS5 代理目标地址抽象
pub enum TargetAddr {
    /// 目标为标准 IP (IPv4 或 IPv6) 与端口号
    Ip(std::net::IpAddr, u16),
    /// 目标为未经解析的域名与端口号
    Domain(String, u16),
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip(ip, _) => ip.to_string(),
            TargetAddr::Domain(domain, _) => domain.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(_, port) => *port,
            TargetAddr::Domain(_, port) => *port,
        }
    }
}

/// 执行与本地客户端的 SOCKS5 握手认证阶段及命令请求解析阶段。
/// 目前强制响应无需认证 (No Authentication Required)，并仅支持 `CONNECT` 代理命令。
/// 成功后返回客户端期望连接的远程目标地址封装 `TargetAddr`。
pub async fn handle_socks5_handshake(stream: &mut TcpStream) -> Result<TargetAddr> {
    // 对握手阶段的读取施加 30 秒超时，防止客户端连接后长期不发送数据而占用资源
    match tokio::time::timeout(std::time::Duration::from_secs(30), handshake_inner(stream)).await {
        Ok(result) => result,
        Err(_) => {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 握手读取超时").into())
        }
    }
}

/// SOCKS5 握手认证与请求解析的具体实现（由公开入口统一包裹超时控制）
async fn handshake_inner(stream: &mut TcpStream) -> Result<TargetAddr> {
    let mut buf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut buf).await {
        return Err(anyhow!("读取 SOCKS5 握手失败: {}", e));
    }
    if buf[0] != 0x05 {
        return Err(anyhow!("无效的 SOCKS 版本: {}", buf[0]));
    }

    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // 客户端声明的方法列表必须包含无认证 (0x00)，空列表同样视为不支持；
    // 否则回复 0xFF（无可接受的方法）并拒绝连接
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xFF]).await;
        return Err(anyhow!("客户端的认证方法列表不支持无认证 (0x00)"));
    }

    // SOCKS5 响应：无需认证
    stream.write_all(&[0x05, 0x00]).await?;

    // 读取 SOCKS5 客户端请求

    let mut req_header = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut req_header).await {
        return Err(anyhow!("读取 SOCKS5 请求头失败: {}", e));
    }

    if req_header[0] != 0x05 {
        return Err(anyhow!("请求中的 SOCKS 版本无效: {}", req_header[0]));
    }

    if req_header[1] != 0x01 {
        // 响应：不支持该命令
        let _ = stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(anyhow!(
            "不支持的 SOCKS 请求命令 (仅支持 CONNECT): {}",
            req_header[1]
        ));
    }

    // RSV 保留字节 (RFC 1928) 必须为 0x00，非零视为协议错误
    if req_header[2] != 0x00 {
        // 响应：general failure
        let _ = stream
            .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err(anyhow!("SOCKS 请求 RSV 保留字节非零: {}", req_header[2]));
    }

    let target = match req_header[3] {
        0x01 => {
            // 处理 IPv4 目标
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(
                Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into(),
                u16::from_be_bytes(port),
            )
        }
        0x03 => {
            // 处理域名目标
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Domain(String::from_utf8(domain)?, u16::from_be_bytes(port))
        }
        0x04 => {
            // 处理 IPv6 目标
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(Ipv6Addr::from(ip).into(), u16::from_be_bytes(port))
        }

        _ => {
            // 响应：不支持的地址类型
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(anyhow!("不支持的目标地址类型: {}", req_header[3]));
        }
    };

    Ok(target)
}

/// 根据底层连接的建立状态，向 SOCKS5 客户端返回标准代理应答。
/// BND.ADDR/BND.PORT 统一填 IPv4 全零 (0.0.0.0:0)：RFC 1928 并未强制要求
/// 服务端在 CONNECT 成功应答中回填真实的绑定地址，许多主流实现均返回全零，
/// 且入站连接的本地地址对客户端也没有实际意义。
pub async fn send_socks5_reply(stream: &mut TcpStream, success: bool) -> Result<()> {
    let rep = if success { 0x00 } else { 0x01 };

    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 建立一对本地互联的 TCP 流：(客户端, 服务端)
    async fn stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    /// 构造一次标准握手前缀（无认证）
    async fn write_greeting(client: &mut TcpStream) {
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn handshake_ipv4_connect() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        // CONNECT 93.184.216.34:443
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB])
            .await
            .unwrap();
        let target = task.await.unwrap().unwrap();
        assert_eq!(target.host(), "93.184.216.34");
        assert_eq!(target.port(), 443);
    }

    #[tokio::test]
    async fn handshake_domain_connect() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        let domain = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let target = task.await.unwrap().unwrap();
        match target {
            TargetAddr::Domain(d, p) => {
                assert_eq!(d, "example.com");
                assert_eq!(p, 80);
            }
            _ => panic!("应为域名目标"),
        }
    }

    #[tokio::test]
    async fn handshake_ipv6_connect() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&8080u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let target = task.await.unwrap().unwrap();
        assert_eq!(target.host(), "2001:db8::1");
        assert_eq!(target.port(), 8080);
    }

    #[tokio::test]
    async fn rejects_unsupported_command_with_reply() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        // UDP ASSOCIATE (0x03) 不支持
        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07, "不支持命令应应答 0x07");
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_nonzero_rsv_with_reply() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        // CONNECT 请求但 RSV = 0x01（保留字节必须为 0x00）
        client
            .write_all(&[0x05, 0x01, 0x01, 0x01, 93, 184, 216, 34, 0x01, 0xBB])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x01, "RSV 非零应应答 0x01 (general failure)");
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_methods_without_no_auth() {
        // 方法列表仅包含用户名/密码认证 (0x02)，不含无认证 (0x00)
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF], "不含 0x00 的方法列表应应答 0xFF");
        assert!(task.await.unwrap().is_err());

        // 空方法列表 (NMETHODS=0) 同样应被拒绝
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF], "空方法列表应应答 0xFF");
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_version() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_unknown_address_type_with_reply() {
        let (mut client, mut server) = stream_pair().await;
        let task = tokio::spawn(async move { handle_socks5_handshake(&mut server).await });
        write_greeting(&mut client).await;
        client.write_all(&[0x05, 0x01, 0x00, 0x7f]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x08, "未知地址类型应应答 0x08");
        assert!(task.await.unwrap().is_err());
    }
}
