//! 主机密钥确认协调模块（TOFU 交互层）
//!
//! `check_server_key` 在握手线程内运行，无法直接弹出 UI。
//! 本模块提供 `HostKeyBroker`：当遇到未知主机密钥时挂起握手，
//! 通过 broadcast 事件通知前端（GUI 弹窗 / CLI 交互），
//! 等待用户决策后再放行或拒绝。
//!
//! 关键语义：
//! - 同一 host:port 且指纹/类型一致的并发连接合并为一个待确认请求
//! - 同一 host:port 但指纹/类型不同的并发请求被拒绝（严禁“搭车”复用他人决策，
//!   保证用户确认的指纹与实际放行并持久化的指纹严格一致）
//! - 每次新建请求生成唯一不可复用的 request_id：A 请求超时移除后 B 请求
//!   （同主机不同指纹）建立时，旧弹窗携带的 request_id 已失效，无法批准 B
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
    /// 本次待确认请求的唯一标识：由 broker 在创建请求时生成并回填，
    /// 用户决策必须携带同一 request_id 才生效（前端事件与补拉列表均携带该字段）
    pub request_id: String,
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

/// 生成不可复用的请求 ID（随机 u64，十六进制表示）。
/// 同一 host:port 同一时刻最多一个 pending，但 A 超时移除后 B 会复用该主机槽位，
/// 随机 ID 保证旧弹窗残留的 request_id 不会命中新请求。
fn new_request_id() -> String {
    // rand 0.10 中 random() 由 RngExt 提供
    use rand::RngExt as _;
    format!("{:016x}", rand::rng().random::<u64>())
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
    /// 返回 `Ok((决策接收端, request_id, 是否为新创建))`；
    /// 同一主机且指纹/类型一致的并发请求共享同一决策与同一 request_id。
    /// 若同一 host:port 已存在指纹或类型不同的待确认请求，返回 `Err(已在等待的密钥信息)`：
    /// 可能是中间人攻击或密钥轮换，调用方必须拒绝本次连接，
    /// 严禁搭车复用他人决策（否则用户批准 A 指纹会连带放行 B 指纹并互相覆盖信任记录）。
    pub fn request(
        &self,
        mut info: PendingHostKey,
    ) -> Result<(watch::Receiver<Option<bool>>, String, bool), PendingHostKey> {
        let key = pending_key(&info.host, info.port);
        let mut map = self.inner.pending.lock().expect("host key broker lock");
        if let Some(entry) = map.get(&key) {
            if entry.info.fingerprint == info.fingerprint && entry.info.key_type == info.key_type {
                return Ok((
                    entry.decision.subscribe(),
                    entry.info.request_id.clone(),
                    false,
                ));
            }
            return Err(entry.info.clone());
        }
        // 每次新建请求生成全新 request_id，并回填进待广播/待补拉的信息中，
        // 保证前端决策时能精确对回本次请求
        info.request_id = new_request_id();
        let (tx, rx) = watch::channel(None);
        map.insert(
            key,
            PendingEntry {
                info: info.clone(),
                decision: tx,
            },
        );
        // 广播失败（无订阅者）不影响流程，调用方会按超时/失败处理
        let _ = self.inner.events.send(info.clone());
        Ok((rx, info.request_id, true))
    }

    /// 用户决策（精确路径）：按 request_id 定位 pending，accept=true 表示信任并持久化，
    /// false 表示拒绝。仅当请求仍存在且 ID 完全匹配时生效，返回是否命中。
    pub fn resolve_by_id(&self, request_id: &str, accept: bool) -> bool {
        let mut map = self.inner.pending.lock().expect("host key broker lock");
        let key = map
            .iter()
            .find(|(_, e)| e.info.request_id == request_id)
            .map(|(k, _)| k.clone());
        match key.and_then(|k| map.remove(&k)) {
            Some(entry) => {
                // send_replace 不依赖接收端存活，保证值一定写入
                entry.decision.send_replace(Some(accept));
                true
            }
            None => false,
        }
    }

    /// 用户决策（兼容包装）：按 host:port 定位 pending，再以其 request_id 决策。
    /// 返回是否存在对应 pending 请求。
    /// 注意：仅保留给无法获取 request_id 的旧调用路径；新代码应携带 request_id
    /// 调用 `resolve_by_id`，避免 A 请求超时后由 B 请求顶替时被旧决策误批准。
    pub fn resolve(&self, host: &str, port: u16, accept: bool) -> bool {
        let request_id = self
            .inner
            .pending
            .lock()
            .expect("host key broker lock")
            .get(&pending_key(host, port))
            .map(|e| e.info.request_id.clone());
        match request_id {
            Some(id) => self.resolve_by_id(&id, accept),
            None => false,
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
            request_id: String::new(), // 由 broker.request 创建请求时回填
        }
    }

    #[test]
    fn dedup_same_host_concurrent_requests() {
        let broker = HostKeyBroker::new();
        let (_rx1, id1, new1) = broker.request(info("Example.COM")).unwrap();
        let (_rx2, id2, new2) = broker.request(info("example.com")).unwrap();
        assert!(new1);
        assert!(!new2, "同一主机第二次请求应去重");
        assert_eq!(id1, id2, "去重的并发请求必须共享同一 request_id");
        assert!(!id1.is_empty(), "request_id 必须由 broker 生成");
        assert_eq!(broker.pending_list().len(), 1);
    }

    #[test]
    fn conflicting_fingerprint_is_rejected_not_deduped() {
        let broker = HostKeyBroker::new();
        let (mut rx_a, id_a, new_a) = broker.request(info("a.com")).unwrap();
        assert!(new_a);
        // 同 host:port 但指纹不同：不得搭车，直接拒绝
        let mut other = info("a.com");
        other.fingerprint = "SHA256:other".to_string();
        let conflict = broker
            .request(other)
            .expect_err("不同指纹的并发请求必须被拒绝");
        assert_eq!(conflict.fingerprint, "SHA256:test");
        // 同 host:port 但 key_type 不同（同指纹换算法）同样拒绝
        let mut other_type = info("a.com");
        other_type.key_type = "ssh-rsa".to_string();
        assert!(broker.request(other_type).is_err());
        assert_eq!(
            broker.pending_list().len(),
            1,
            "冲突请求不得产生新的 pending"
        );
        // 用户批准的是 A 的指纹与请求 ID，只有 A 的等待者被放行
        assert!(broker.resolve_by_id(&id_a, true));
        assert_eq!(*rx_a.borrow_and_update(), Some(true));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn resolve_notifies_all_waiters() {
        let broker = HostKeyBroker::new();
        let (mut rx1, id1, _) = broker.request(info("a.com")).unwrap();
        let (mut rx2, id2, _) = broker.request(info("a.com")).unwrap();
        assert_eq!(id1, id2);
        assert!(broker.resolve_by_id(&id1, true));
        assert_eq!(*rx1.borrow_and_update(), Some(true));
        assert_eq!(*rx2.borrow_and_update(), Some(true));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn stale_request_id_cannot_resolve_after_expire_and_replacement() {
        let broker = HostKeyBroker::new();
        // A 建立 pending 后超时移除
        let (mut rx_a, id_a, _) = broker.request(info("a.com")).unwrap();
        broker.expire("a.com", 22);
        assert_eq!(*rx_a.borrow_and_update(), Some(false));
        // B（同主机不同指纹）随后建立新的 pending，拿到全新 request_id
        let mut b = info("a.com");
        b.fingerprint = "SHA256:rotated".to_string();
        let (mut rx_b, id_b, new_b) = broker.request(b).unwrap();
        assert!(new_b);
        assert_ne!(id_a, id_b, "同一主机的新请求必须生成不同 request_id");
        // 旧弹窗携带的 A request_id 已失效：不得批准 B
        assert!(
            !broker.resolve_by_id(&id_a, true),
            "已超时的旧 request_id 不得再命中新 pending"
        );
        assert_eq!(*rx_b.borrow_and_update(), None, "B 不得因旧请求 ID 被放行");
        // 用 B 自己的 request_id 决策才生效
        assert!(broker.resolve_by_id(&id_b, true));
        assert_eq!(*rx_b.borrow_and_update(), Some(true));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn different_request_ids_cannot_approve_each_other() {
        let broker = HostKeyBroker::new();
        // 不同主机各建一个 pending：request_id 互不通用
        let (mut rx_a, id_a, _) = broker.request(info("a.com")).unwrap();
        let (mut rx_b, id_b, _) = broker.request(info("b.com")).unwrap();
        assert_ne!(id_a, id_b);
        // A 的请求 ID 只命中并批准 A 自己的 pending
        assert!(
            broker.resolve_by_id(&id_a, true),
            "A 的请求 ID 应批准 A 自己的请求"
        );
        assert_eq!(*rx_a.borrow_and_update(), Some(true));
        assert_eq!(
            *rx_b.borrow_and_update(),
            None,
            "A 的请求 ID 不得批准 B 的请求"
        );
        assert_eq!(broker.pending_list().len(), 1, "B 的 pending 必须保留");
        assert!(broker.resolve_by_id(&id_b, true));
        assert_eq!(*rx_b.borrow_and_update(), Some(true));
        assert!(broker.pending_list().is_empty());
    }

    #[test]
    fn resolve_by_host_wrapper_still_works() {
        let broker = HostKeyBroker::new();
        let (mut rx, _id, _) = broker.request(info("a.com")).unwrap();
        assert!(broker.resolve("a.com", 22, true));
        assert_eq!(*rx.borrow_and_update(), Some(true));
        assert!(
            !broker.resolve("a.com", 22, true),
            "已清理的 pending 不得重复决策"
        );
    }

    #[test]
    fn reject_all_clears_pending() {
        let broker = HostKeyBroker::new();
        let (mut rx1, _, _) = broker.request(info("a.com")).unwrap();
        let (mut rx2, _, _) = broker.request(info("b.com")).unwrap();
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
        let (_rx, request_id, _) = broker.request(info("a.com")).unwrap();
        let got = sub.recv().await.unwrap();
        assert_eq!(got.host, "a.com");
        assert_eq!(
            got.request_id, request_id,
            "事件必须携带本次请求的 request_id"
        );
    }
}
