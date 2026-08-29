use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum TargetAddr {
    Ip(std::net::IpAddr, u16),
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

pub async fn handle_socks5_handshake(stream: &mut TcpStream) -> Result<TargetAddr> {

    let mut buf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut buf).await {
        return Err(anyhow!("Read err: {}", e));
    }
    if buf[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS version: {}", buf[0]));
    }

    
    let n_methods = buf[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;
    
    // Reply: No auth required
    stream.write_all(&[0x05, 0x00]).await?;
    
    // Read request

    let mut req_header = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut req_header).await {
        return Err(anyhow!("Read err: {}", e));
    }

    if req_header[0] != 0x05 {
        return Err(anyhow!("Invalid SOCKS version in request: {}", req_header[0]));
    }
    
    if req_header[1] != 0x01 {
        // Reply with command not supported
        let _ = stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(anyhow!("Unsupported SOCKS request command: {}", req_header[1]));
    }
    
    let target = match req_header[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into(), u16::from_be_bytes(port))
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Domain(String::from_utf8(domain)?, u16::from_be_bytes(port))
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(Ipv6Addr::from(ip).into(), u16::from_be_bytes(port))
        }

        _ => {
            // Reply with address type not supported
            let _ = stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(anyhow!("Unsupported address type: {}", req_header[3]))
        }

    };
    
    Ok(target)
}

pub async fn send_socks5_reply(stream: &mut TcpStream, success: bool) -> Result<()> {
    let rep = if success { 0x00 } else { 0x01 };
    
    // Check if the stream is IPv4 or IPv6
    if let Ok(local_addr) = stream.local_addr() {
        if local_addr.is_ipv6() {
            let mut reply = vec![0x05, rep, 0x00, 0x04];
            let ip_bytes = match local_addr.ip() {
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                _ => vec![0u8; 16],
            };
            reply.extend_from_slice(&ip_bytes);
            reply.extend_from_slice(&local_addr.port().to_be_bytes());
            stream.write_all(&reply).await?;
            return Ok(());
        }
    }
    
    // Default IPv4 reply
    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    Ok(())
}
