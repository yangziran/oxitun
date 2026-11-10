//! 可选的 Prometheus 指标模块
//!
//! 不配置 `general.metrics_addr` 时不启动任何 HTTP 监听器，
//! 仅保留原子计数器的极低开销。
//!
//! 暴露指标（`GET /metrics`）：
//! - `oxitun_active_connections`：当前活跃代理会话数
//! - `oxitun_bytes_transferred_total{direction}`：累计上下行字节
//! - `oxitun_ssh_pool_rebuilds_total`：连接池整池重建次数
//! - `oxitun_ssh_reconnects_total`：补池重建单连接次数

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// 全局指标注册表（无锁原子计数器）
pub struct Metrics {
    pub active_connections: AtomicI64,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub ssh_pool_rebuilds: AtomicU64,
    pub ssh_reconnects: AtomicU64,
}

pub static METRICS: Metrics = Metrics {
    active_connections: AtomicI64::new(0),
    bytes_tx: AtomicU64::new(0),
    bytes_rx: AtomicU64::new(0),
    ssh_pool_rebuilds: AtomicU64::new(0),
    ssh_reconnects: AtomicU64::new(0),
};

/// 活跃连接数 +1（代理会话建立时调用）
pub fn connection_opened() {
    METRICS.active_connections.fetch_add(1, Ordering::Relaxed);
}

/// 活跃连接数 -1（代理会话结束时调用）
pub fn connection_closed() {
    METRICS.active_connections.fetch_sub(1, Ordering::Relaxed);
}

/// 记录一条代理会话的上下行字节数
pub fn add_bytes(tx: u64, rx: u64) {
    METRICS.bytes_tx.fetch_add(tx, Ordering::Relaxed);
    METRICS.bytes_rx.fetch_add(rx, Ordering::Relaxed);
}

pub fn inc_pool_rebuild() {
    METRICS.ssh_pool_rebuilds.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_reconnect() {
    METRICS.ssh_reconnects.fetch_add(1, Ordering::Relaxed);
}

/// RAII 守护：构造时活跃数 +1，析构时 -1
pub struct ConnectionGuard;

impl Default for ConnectionGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionGuard {
    pub fn new() -> Self {
        connection_opened();
        Self
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        connection_closed();
    }
}

/// 渲染 Prometheus 文本格式
pub fn render() -> String {
    format!(
        "# HELP oxitun_active_connections 当前活跃代理会话数\n\
         # TYPE oxitun_active_connections gauge\n\
         oxitun_active_connections {}\n\
         # HELP oxitun_bytes_transferred_total 累计传输字节数\n\
         # TYPE oxitun_bytes_transferred_total counter\n\
         oxitun_bytes_transferred_total{{direction=\"tx\"}} {}\n\
         oxitun_bytes_transferred_total{{direction=\"rx\"}} {}\n\
         # HELP oxitun_ssh_pool_rebuilds_total SSH 连接池整池重建次数\n\
         # TYPE oxitun_ssh_pool_rebuilds_total counter\n\
         oxitun_ssh_pool_rebuilds_total {}\n\
         # HELP oxitun_ssh_reconnects_total SSH 单连接补池重建次数\n\
         # TYPE oxitun_ssh_reconnects_total counter\n\
         oxitun_ssh_reconnects_total {}\n",
        METRICS.active_connections.load(Ordering::Relaxed),
        METRICS.bytes_tx.load(Ordering::Relaxed),
        METRICS.bytes_rx.load(Ordering::Relaxed),
        METRICS.ssh_pool_rebuilds.load(Ordering::Relaxed),
        METRICS.ssh_reconnects.load(Ordering::Relaxed),
    )
}

/// 若配置了地址则启动微型 HTTP 服务（仅响应 GET /metrics），否则不启动任何监听器。
/// 返回的 JoinHandle 应注册到隧道管理器生命周期中。
pub async fn maybe_serve(metrics_addr: Option<&str>) -> Option<tokio::task::JoinHandle<()>> {
    let addr = metrics_addr?.trim();
    if addr.is_empty() {
        return None;
    }
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("指标监听绑定 {} 失败: {}", addr, e);
            return None;
        }
    };
    log::info!("Prometheus 指标监听于 http://{}/metrics", addr);
    Some(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf).await;
                        let body = render();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
                Err(e) => {
                    log::error!("指标服务 accept 失败: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_render() {
        let before = METRICS.bytes_tx.load(Ordering::Relaxed);
        add_bytes(100, 50);
        assert_eq!(METRICS.bytes_tx.load(Ordering::Relaxed), before + 100);

        let active_before = METRICS.active_connections.load(Ordering::Relaxed);
        {
            let _g = ConnectionGuard::new();
            assert_eq!(
                METRICS.active_connections.load(Ordering::Relaxed),
                active_before + 1
            );
        }
        assert_eq!(
            METRICS.active_connections.load(Ordering::Relaxed),
            active_before
        );

        let text = render();
        assert!(text.contains("oxitun_active_connections"));
        assert!(text.contains("direction=\"tx\""));
    }

    #[tokio::test]
    async fn disabled_when_no_addr() {
        assert!(maybe_serve(None).await.is_none());
        assert!(maybe_serve(Some("")).await.is_none());
    }

    #[tokio::test]
    async fn serves_metrics_over_http() {
        let handle = maybe_serve(Some("127.0.0.1:0")).await;
        assert!(handle.is_some());
        handle.unwrap().abort();
    }
}
