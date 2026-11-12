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

/// RAII 守护：指标服务顶层任务被 abort 时 Drop 随之触发，关闭连接任务追踪器。
/// 这样即便调用方只持有 JoinHandle 并直接 abort，tracker 也会被 close()，
/// 等待方（tracker.wait()）不再无限挂起；连接任务随请求自然结束或 10 秒读超时退出
struct CloseTrackerOnDrop(tokio_util::task::TaskTracker);

impl Drop for CloseTrackerOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// 若配置了地址则启动微型 HTTP 服务（仅响应 GET /metrics），否则不启动任何监听器。
/// 返回的 JoinHandle 应注册到隧道管理器生命周期中；
/// 顶层任务被 abort 时内部 RAII 守卫会自动关闭连接任务追踪器
pub async fn maybe_serve(metrics_addr: Option<&str>) -> Option<tokio::task::JoinHandle<()>> {
    serve_http(metrics_addr).await.map(|(handle, _)| handle)
}

/// maybe_serve 的内部实现：除服务任务句柄外还返回连接任务追踪器，
/// 便于测试直接断言「abort 后 tracker 被关闭」
async fn serve_http(
    metrics_addr: Option<&str>,
) -> Option<(tokio::task::JoinHandle<()>, tokio_util::task::TaskTracker)> {
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
    // 连接任务统一追踪：即便服务任务异常退出，也能 wait() 确保连接任务收尾，
    // 避免半开连接派生的任务永久游离在管理器生命周期之外
    let tracker = tokio_util::task::TaskTracker::new();
    let serve_tracker = tracker.clone();
    let handle = tokio::spawn(async move {
        // 顶层任务被杀（abort）时关闭追踪器，连接任务不再永久游离
        let _guard = CloseTrackerOnDrop(tracker.clone());
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tracker.spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = [0u8; 2048];
                        // 单连接读取加 10 秒超时：客户端只连不发时任务也必定退出，
                        // 防止连接任务永久挂起（拒绝服务面）
                        let n = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            stream.read(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) => n,
                            Ok(Err(_)) => return,
                            Err(_) => return,
                        };
                        // 解析请求行：仅放行 GET /metrics，其余一律 404
                        let request = String::from_utf8_lossy(&buf[..n]);
                        let request_line = request.lines().next().unwrap_or("");
                        let mut parts = request_line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let path = parts.next().unwrap_or("");
                        let resp = if method == "GET" && path == "/metrics" {
                            let body = render();
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                        } else {
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_string()
                        };
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
                Err(e) => {
                    log::error!("指标服务 accept 失败: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    Some((handle, serve_tracker))
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 先临时绑定获取一个空闲端口再释放，供指标服务使用
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let handle = maybe_serve(Some(&addr.to_string()))
            .await
            .expect("指标服务应成功启动");

        // 用真实 TcpStream 发请求并读取完整响应
        async fn request(addr: std::net::SocketAddr, req: &str) -> String {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).await.unwrap();
            resp
        }

        // GET /metrics → 200 且包含指标文本
        let resp = request(
            addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{}", resp);
        assert!(resp.contains("oxitun_active_connections"), "{}", resp);

        // 其他路径 → 404
        let resp = request(
            addr,
            "GET /other HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 404"), "{}", resp);

        // 非 GET 方法 → 404
        let resp = request(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 404"), "{}", resp);

        handle.abort();
    }

    /// 停止（abort）顶层服务任务后，内部 RAII 守卫应关闭连接任务追踪器，
    /// 连接任务随之退出，tracker.wait() 不再无限挂起
    #[tokio::test]
    async fn tracker_closed_and_connections_exit_on_abort() {
        // 先临时绑定获取一个空闲端口再释放，供指标服务使用
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let (handle, tracker) = serve_http(Some(&addr.to_string()))
            .await
            .expect("指标服务应成功启动");

        // 建立一条空闲连接：只连接不发请求，连接任务阻塞在读上
        let idle = tokio::net::TcpStream::connect(addr).await.unwrap();
        // 确定性等待：轮询 tracker（500ms 上限、每 10ms 检查一次），
        // 直至 accept 循环把该连接派生为连接任务，替代固定 sleep 启发式，
        // 保证慢 CI 上也能稳定等到任务派生后再进入 abort 断言
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while tracker.is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "500ms 内应派生出连接任务"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // 模拟停止：abort 顶层任务（内部 RAII 守卫随之关闭 tracker）
        handle.abort();
        let _ = handle.await;

        // 客户端断开 → 服务端读立即返回 EOF → 连接任务退出；
        // 若 RAII 守卫未生效（tracker 未 close），wait() 将永久挂起而触发超时
        drop(idle);
        tokio::time::timeout(std::time::Duration::from_secs(2), tracker.wait())
            .await
            .expect("abort 后 tracker 应关闭且连接任务应退出");
    }
}
