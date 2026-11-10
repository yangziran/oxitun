//! 主机密钥确认协调模块（TOFU 交互层）
//!
//! `check_server_key` 在握手线程内运行，无法直接弹出 UI。
//! 本模块提供 `HostKeyBroker`：当遇到未知主机密钥时挂起握手，
//! 通过 broadcast 事件通知前端（GUI 弹窗 / CLI 交互），
//! 等待用户决策后再放行或拒绝。
//!
//! 关键语义：
//! - 同一 host:port 的并发连接合并为一个待确认请求
//! - 无事件订阅者（无人值守场景）时不得挂起，应立即失败
//! - 确认超时/拒绝/进程退出后必须清理 pending 状态

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, watch};

/// 待用户确认的主机密钥信息
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingHostKey {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub fingerprint: String,
}

struct PendingEntry {
    info: PendingHostKey,
    decision: watch::Sender<Option<bool>>,
}

struct BrokerInner {
    pending: Mutex<HashMap<String, PendingEntry>>,
    events: broadcast::Sender<PendingHostKey>,
}

/// 主机密钥决策协调器（GUI/CLI 各持有一份克隆）
#[derive(Clone)]
pub struct HostKeyBroker {
    inner: Arc<BrokerInner>,
}

impl Default for HostKeyBroker {
    fn default() -> Self {
        Self::new()
    }
}

fn pending_key(host: &str, port: u16) -> String {
    let (h, p) = crate::known_hosts::normalize_host(host, port);
    format!("{h}:{p}")
}

impl HostKeyBroker {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            inner: Arc::new(BrokerInner {
                pending: Mutex::new(HashMap::new()),
                events,
            }),
        }
    }

    /// 是否有前端/交互端正在监听确认事件。
    /// 无监听者时握手不应挂起等待（无人值守场景必须明确失败）。
    pub fn has_subscribers(&self) -> bool {
        self.inner.events.receiver_count() > 0
    }

    /// 订阅“新的待确认主机密钥”事件（仅对去重后新创建的请求广播）
    pub fn subscribe(&self) -> broadcast::Receiver<PendingHostKey> {
        self.inner.events.subscribe()
    }

    /// 当前所有待确认请求（供前端启动时补拉）
    pub fn pending_list(&self) -> Vec<PendingHostKey> {
        self.inner
            .pending
            .lock()
            .expect("host key broker lock")
            .values()
            .map(|e| e.info.clone())
            .collect()
    }

    /// 发起或加入一个待确认请求。
    /// 返回 `(决策接收端, 是否为新创建)`；同一主机的并发请求共享同一决策。
    pub fn request(&self, info: PendingHostKey) -> (watch::Receiver<Option<bool>>, bool) {
        let key = pending_key(&info.host, info.port);
        let mut map = self.inner.pending.lock().expect("host key broker lock");
        if let Some(entry) = map.get(&key) {
            return (entry.decision.subscribe(), false);
        }
        let (tx, rx) = watch::channel(None);
        map.insert(
            key,
            PendingEntry {
                info: info.clone(),
                decision: tx,
            },
        );
        // 广播失败（无订阅者）不影响流程，调用方会按超时/失败处理
        let _ = self.inner.events.send(info);
        (rx, true)
    }

    /// 用户决策：accept=true 表示信任并持久化，false 表示拒绝。
    /// 返回是否存在对应 pending 请求。
    pub fn resolve(&self, host: &str, port: u16, accept: bool) -> bool {
        let key = pending_key(host, port);
        let entry = self
            .inner
            .pending
            .lock()
            .expect("host key broker lock")
            .remove(&key);
        if let Some(entry) = entry {
            // send_replace 不依赖接收端存活，保证值一定写入
            entry.decision.send_replace(Some(accept));
            true
        } else {
            false
        }
    }

    /// 拒绝并清理全部 pending（停止隧道/退出时调用）
    pub fn reject_all(&self) {
        let pending =
            std::mem::take(&mut *self.inner.pending.lock().expect("host key broker lock"));
        for (_, entry) in pending {
            entry.decision.send_replace(Some(false));
        }
    }

    /// 清理某个 pending（超时路径使用）；若存在则广播拒绝给所有等待方
    pub fn expire(&self, host: &str, port: u16) {
        self.resolve(host, port, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(host: &str) -> PendingHostKey {
        PendingHostKey {
            host: host.to_string(),
            port: 22,
            key_type: "ssh-ed25519".to_string(),
            fingerprint: "SHA256:test".to_string(),
        }
    }

    #[test]
    fn dedup_same_host_concurrent_requests() {
        let broker = HostKeyBroker::new();
        let (_rx1, new1) = broker.request(info("Example.COM"));
        let (_rx2, new2) = broker.request(info("example.com"));
        assert!(new1);
        assert!(!new2, "同一主机第二次请求应去重");
        assert_eq!(broker.pending_list().len(), 1);
    }

    #[test]
    fn resolve_notifies_all_waiters() {
        let broker = HostKeyBroker::new();
        let (mut rx1, _) = broker.request(info("a.com"));
        let (mut rx2, _) = broker.request(info("a.com"));
        assert!(broker.resolve("a.com", 22, true));
        assert_eq!(*rx1.borrow_and_update(), Some(true));
        assert_eq!(*rx2.borrow_and_update(), Some(true));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn reject_all_clears_pending() {
        let broker = HostKeyBroker::new();
        let (mut rx1, _) = broker.request(info("a.com"));
        let (mut rx2, _) = broker.request(info("b.com"));
        broker.reject_all();
        assert_eq!(*rx1.borrow_and_update(), Some(false));
        assert_eq!(*rx2.borrow_and_update(), Some(false));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn subscriber_count_drives_headless_detection() {
        let broker = HostKeyBroker::new();
        assert!(!broker.has_subscribers());
        let _sub = broker.subscribe();
        assert!(broker.has_subscribers());
    }

    #[tokio::test]
    async fn subscriber_receives_new_request_event() {
        let broker = HostKeyBroker::new();
        let mut sub = broker.subscribe();
        let (_rx, _) = broker.request(info("a.com"));
        let got = sub.recv().await.unwrap();
        assert_eq!(got.host, "a.com");
    }
}
