//! known_hosts 持久化模块
//!
//! 实现 SSH 主机密钥的 TOFU（Trust On First Use）信任存储：
//! - 键为规范化后的 `host:port`（DNS 名小写、IPv6 去括号、默认端口补 22）
//! - 记录密钥类型、SHA256 指纹与首次信任时间
//! - 写入采用“跨进程文件锁 + 锁内重读合并 + 唯一临时文件原子替换”，
//!   多实例/多进程并发写不丢数据

use crate::crypto::{FileLockGuard, lock_path_for};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// 单条主机密钥信任记录
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownHost {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    /// 形如 `SHA256:xxxx` 的指纹（base64 无填充）
    pub fingerprint: String,
    /// 首次信任的 Unix 时间戳（秒）
    pub trusted_at: u64,
}

/// 规范化主机地址：
/// - 去除 IPv6 方括号
/// - DNS 名转小写
/// - 端口缺省补 22
pub fn normalize_host(host: &str, port: u16) -> (String, u16) {
    let h = host.trim();
    let h = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h);
    let h = if h.parse::<std::net::IpAddr>().is_ok() {
        h.to_string()
    } else {
        h.to_ascii_lowercase()
    };
    let p = if port == 0 { 22 } else { port };
    (h, p)
}

fn entry_key(host: &str, port: u16) -> String {
    let (h, p) = normalize_host(host, port);
    format!("{h}:{p}")
}

/// 实例内部状态：内存 map 是本实例的缓存视图；
/// `removed` 记录本实例已删除的键（删除墓碑），持久化合并时从磁盘结果中剔除，
/// 避免删除的记录在本实例后续的写入中“复活”；
/// `dirty` 记录本实例真正修改过的键——持久化时只覆盖这些键，
/// 未经本实例触碰的陈旧快照条目绝不写回磁盘（否则会把其他实例刚删掉的记录复活）
struct StoreState {
    map: HashMap<String, KnownHost>,
    removed: HashSet<String>,
    dirty: HashSet<String>,
}

/// known_hosts 存储（内存索引 + 文件持久化，持锁合并写，跨实例/跨进程安全）
pub struct KnownHostsStore {
    path: PathBuf,
    state: Mutex<StoreState>,
}

/// 进程内注册表：同一路径复用同一实例（Weak 避免妨碍析构），
/// 防止 ServerPool、测试池、CLI/GUI 在同进程内对同一路径 open 出多个独立实例
static STORE_REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Weak<KnownHostsStore>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<PathBuf, Weak<KnownHostsStore>>> {
    STORE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

impl KnownHostsStore {
    /// 打开指定路径的存储文件（不存在则按空存储处理）。
    /// 每次调用返回独立实例；仅保留给真正需要实例隔离的场景（如测试），
    /// 生产代码必须使用 [`Self::open_shared`]，避免同进程内存视图分裂。
    /// 无论实例是否共享，写入都会经文件锁 + 锁内重读合并，不会互相覆盖丢数据
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let map = match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str::<HashMap<String, KnownHost>>(&content)
                .map_err(|e| anyhow::anyhow!("known_hosts 文件损坏: {}", e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            state: Mutex::new(StoreState {
                map,
                removed: HashSet::new(),
                dirty: HashSet::new(),
            }),
        })
    }

    /// 打开（或复用）指定路径的共享存储实例。
    /// 同进程内同一路径返回同一个 `Arc` 实例：内存视图唯一，
    /// 删除墓碑准确，配合持锁合并写实现“同进程并发写不丢数据”
    pub fn open_shared(path: PathBuf) -> anyhow::Result<Arc<KnownHostsStore>> {
        // 注册表键使用绝对路径，避免相对/绝对写法混用导致同一文件出现多个实例
        let key = std::path::absolute(&path).unwrap_or(path.clone());
        let mut registry = registry().lock().expect("known_hosts registry lock");
        if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        // 清理已失效的 Weak 条目，避免注册表只增不减
        registry.retain(|_, w| w.strong_count() > 0);
        let store = Arc::new(Self::open(path)?);
        registry.insert(key, Arc::downgrade(&store));
        Ok(store)
    }

    /// 默认存储路径：系统数据目录下 `OxiTun/known_hosts.json`
    pub fn default_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("OxiTun")
            .join("known_hosts.json")
    }

    /// 查找指定主机的信任记录
    pub fn lookup(&self, host: &str, port: u16) -> Option<KnownHost> {
        self.state
            .lock()
            .expect("known_hosts lock")
            .map
            .get(&entry_key(host, port))
            .cloned()
    }

    /// 记录（或覆盖）一条信任记录并立即持久化
    pub fn trust(
        &self,
        host: &str,
        port: u16,
        key_type: &str,
        fingerprint: &str,
    ) -> anyhow::Result<()> {
        let (h, p) = normalize_host(host, port);
        let entry = KnownHost {
            host: h.clone(),
            port: p,
            key_type: key_type.to_string(),
            fingerprint: fingerprint.to_string(),
            trusted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let key = format!("{h}:{p}");
        let mut state = self.state.lock().expect("known_hosts lock");
        let prev = state.map.insert(key.clone(), entry);
        // 重新信任需清除删除墓碑，否则 persist 合并时会按墓碑把刚写入的键剔除
        let had_removed = state.removed.remove(&key);
        // 只有本实例真正写入过的键才允许覆盖磁盘，陈旧快照条目不得写回
        let had_dirty = !state.dirty.insert(key.clone());
        if let Err(e) = self.persist_locked(&mut state) {
            // 持久化失败时回滚内存修改，避免内存与磁盘状态分裂
            match prev {
                Some(old) => {
                    state.map.insert(key.clone(), old);
                }
                None => {
                    state.map.remove(&key);
                }
            }
            if had_removed {
                state.removed.insert(key.clone());
            }
            if !had_dirty {
                state.dirty.remove(&key);
            }
            return Err(e);
        }
        Ok(())
    }

    /// 删除一条信任记录
    pub fn remove(&self, host: &str, port: u16) -> anyhow::Result<()> {
        let mut state = self.state.lock().expect("known_hosts lock");
        let key = entry_key(host, port);
        // 无条件记录删除墓碑：多实例场景下本实例内存快照可能比磁盘旧
        // （另一实例在本实例 open 之后才写入该键），若仅当内存含键才记墓碑，
        // 该键会在磁盘上残留而 remove 却"成功"返回；墓碑对不存在键的合并
        // （merged.remove）本就是 no-op，无条件记录安全无副作用
        let old = state.map.remove(&key);
        state.removed.insert(key.clone());
        if let Err(e) = self.persist_locked(&mut state) {
            // 持久化失败时回滚内存修改（含删除墓碑），避免内存与磁盘状态分裂
            if let Some(old) = old {
                state.map.insert(key.clone(), old);
            }
            state.removed.remove(&key);
            return Err(e);
        }
        Ok(())
    }

    /// 列出全部记录（按 host:port 排序）
    pub fn list(&self) -> Vec<KnownHost> {
        let mut v: Vec<_> = self
            .state
            .lock()
            .expect("known_hosts lock")
            .map
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| format!("{}:{}", a.host, a.port).cmp(&format!("{}:{}", b.host, b.port)));
        v
    }

    /// 原子写入：跨进程文件锁内以磁盘为权威重读合并（内存仅为缓存），
    /// 再写进程唯一命名的临时文件并 rename 覆盖目标文件。
    /// 成功后把内存同步为合并结果并清除删除墓碑（已全部反映到磁盘）；
    /// 失败时内存保持调用前的修改，由调用方负责回滚
    fn persist_locked(&self, state: &mut StoreState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // 跨进程互斥：另一进程可能正持有旧快照准备写入，
        // 必须串行化后再以磁盘为权威合并，杜绝“后写覆盖先写丢数据”
        let _guard = FileLockGuard::acquire(&lock_path_for(&self.path))?;
        // 锁内重读：磁盘是权威，内存只是缓存；捕获 NotFound 以外的读取/解析错误
        let disk = match std::fs::read_to_string(&self.path) {
            Ok(content) => serde_json::from_str::<HashMap<String, KnownHost>>(&content)
                .map_err(|e| anyhow::anyhow!("known_hosts 文件损坏: {}", e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        // 合并：磁盘为权威底稿；先应用本实例的删除墓碑，
        // 再只覆盖本实例真正写入过的键（dirty），
        // 内存里未经触碰的陈旧快照条目绝不写回，避免把其他实例刚删除的记录复活
        let mut merged = disk;
        for k in &state.removed {
            merged.remove(k);
        }
        for k in &state.dirty {
            if let Some(v) = state.map.get(k) {
                merged.insert(k.clone(), v.clone());
            }
        }
        let content = serde_json::to_string_pretty(&merged)?;
        let tmp = unique_tmp_path(&self.path);
        std::fs::write(&tmp, content)?;
        persist_rename(&tmp, &self.path)?;
        // 权限收紧：仅当前用户可读写
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        // 成功后内存与磁盘对齐：其他实例/进程写入的记录也并入本实例视图，
        // 墓碑与脏标记已全部落到磁盘，可以清除
        state.map = merged;
        state.removed.clear();
        state.dirty.clear();
        Ok(())
    }
}

/// 生成进程唯一的临时文件路径：`known_hosts.json.tmp.{pid}.{随机u64}`。
/// pid + 随机数双因子避免多进程/多线程固定名 `json.tmp` 互相覆盖
fn unique_tmp_path(path: &Path) -> PathBuf {
    let mut rand_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut rand_bytes);
    path.with_extension(format!(
        "json.tmp.{}.{:016x}",
        std::process::id(),
        u64::from_le_bytes(rand_bytes)
    ))
}

/// 跨平台原子替换（Windows 上 rename 不允许覆盖已存在文件）
fn persist_rename(tmp: &Path, target: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            #[link_name = "MoveFileExW"]
            fn move_file_ex_w(
                existing_file_name: *const u16,
                new_file_name: *const u16,
                flags: u32,
            ) -> i32;
        }

        let tmp_wide: Vec<u16> = tmp
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target_wide: Vec<u16> = target
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: 两个缓冲区均以 NUL 结尾，且在整个系统调用期间保持存活；
        // 临时文件与目标同目录、同卷，允许原子替换已存在的目标并等待写入落盘。
        let replaced = unsafe {
            move_file_ex_w(
                tmp_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            // 不删除旧目标；失败时旧文件保持不动，临时文件也保留供诊断和清理。
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        // Unix rename 原子替换已存在的目标文件
        std::fs::rename(tmp, target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, KnownHostsStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = KnownHostsStore::open(dir.path().join("known_hosts.json")).unwrap();
        (dir, store)
    }

    #[test]
    fn normalize_host_handles_case_brackets_and_default_port() {
        assert_eq!(
            normalize_host("Example.COM", 0),
            ("example.com".to_string(), 22)
        );
        assert_eq!(
            normalize_host("[2402:4e00::1]", 2222),
            ("2402:4e00::1".to_string(), 2222)
        );
        assert_eq!(
            normalize_host(" 192.168.1.1 ", 22),
            ("192.168.1.1".to_string(), 22)
        );
    }

    #[test]
    fn trust_lookup_remove_roundtrip() {
        let (_dir, store) = temp_store();
        store
            .trust("Example.COM", 22, "ssh-ed25519", "SHA256:abc")
            .unwrap();

        let hit = store.lookup("example.com", 22).unwrap();
        assert_eq!(hit.fingerprint, "SHA256:abc");
        assert_eq!(hit.key_type, "ssh-ed25519");
        assert!(store.lookup("other.com", 22).is_none());

        store.remove("EXAMPLE.com", 22).unwrap();
        assert!(store.lookup("example.com", 22).is_none());
    }

    #[test]
    fn persists_to_disk_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        {
            let store = KnownHostsStore::open(path.clone()).unwrap();
            store.trust("a.com", 22, "ssh-rsa", "SHA256:one").unwrap();
        }
        let store = KnownHostsStore::open(path).unwrap();
        assert_eq!(store.lookup("a.com", 22).unwrap().fingerprint, "SHA256:one");
    }

    #[test]
    fn overwrite_existing_entry() {
        let (_dir, store) = temp_store();
        store.trust("a.com", 22, "ssh-rsa", "SHA256:old").unwrap();
        store
            .trust("a.com", 22, "ssh-ed25519", "SHA256:new")
            .unwrap();
        let hit = store.lookup("a.com", 22).unwrap();
        assert_eq!(hit.fingerprint, "SHA256:new");
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn corrupted_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        std::fs::write(&path, "not-json").unwrap();
        assert!(KnownHostsStore::open(path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_permission_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let store = KnownHostsStore::open(path.clone()).unwrap();
        store.trust("a.com", 22, "ssh-rsa", "SHA256:x").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// 同进程两个独立实例并发 trust 不同主机：
    //  持锁合并写必须保证最终两条记录都在文件里，谁都不丢
    #[test]
    fn concurrent_instances_do_not_lose_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let s1 = KnownHostsStore::open(path.clone()).unwrap();
        let s2 = KnownHostsStore::open(path.clone()).unwrap();

        let mut handles = Vec::new();
        for (store, host) in [(s1, "host-a.com"), (s2, "host-b.com")] {
            handles.push(std::thread::spawn(move || {
                for i in 0..20 {
                    store
                        .trust(host, 22, "ssh-ed25519", &format!("SHA256:{host}-{i}"))
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // 以磁盘为权威校验：两实例写入的全部记录都在
        let store = KnownHostsStore::open(path).unwrap();
        for host in ["host-a.com", "host-b.com"] {
            assert!(
                store.lookup(host, 22).is_some(),
                "{host} 的记录不得在并发写入中丢失"
            );
        }
    }

    /// 实例 1 删除记录后，实例 2（持有含该记录的陈旧快照）写其他主机：
    /// 被删记录不得被陈旧快照“复活”
    #[test]
    fn remove_is_not_resurrected_by_stale_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let s1 = KnownHostsStore::open(path.clone()).unwrap();
        s1.trust("gone.com", 22, "ssh-rsa", "SHA256:old").unwrap();
        // s2 在删除前打开，快照里仍含 gone.com
        let s2 = KnownHostsStore::open(path.clone()).unwrap();
        s1.remove("gone.com", 22).unwrap();
        // s2 用陈旧快照写另一条记录
        s2.trust("other.com", 22, "ssh-rsa", "SHA256:other")
            .unwrap();

        let store = KnownHostsStore::open(path).unwrap();
        assert!(
            store.lookup("gone.com", 22).is_none(),
            "已删除的记录不得复活"
        );
        assert!(store.lookup("other.com", 22).is_some());
    }

    /// 多实例场景：实例 A 打开后，另一实例（模拟另一进程）trust 写入新键，
    /// A 的内存快照不含该键，但 A.remove 仍必须真正删除磁盘上的该键并返回成功
    #[test]
    fn remove_deletes_key_written_by_other_instance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        // A 先打开（此时存储为空，快照不含任何键）
        let a = KnownHostsStore::open(path.clone()).unwrap();
        // 另一实例（模拟另一进程）在 A 打开之后写入该键
        let b = KnownHostsStore::open(path.clone()).unwrap();
        b.trust("late.com", 22, "ssh-rsa", "SHA256:late").unwrap();
        // 前置条件：A 的内存快照确实不含该键
        assert!(a.lookup("late.com", 22).is_none());
        // 内存快照不含该键也不得导致 remove 静默无操作
        a.remove("late.com", 22).unwrap();
        // 以磁盘为权威校验：该键确实被删除
        let store = KnownHostsStore::open(path).unwrap();
        assert!(
            store.lookup("late.com", 22).is_none(),
            "其他实例后写入的键必须能被本实例 remove 真正删除"
        );
    }

    /// 删除后由同实例重新信任：墓碑必须被清除，记录要能写回
    #[test]
    fn retrust_after_remove_roundtrip() {
        let (_dir, store) = temp_store();
        store.trust("a.com", 22, "ssh-rsa", "SHA256:one").unwrap();
        store.remove("a.com", 22).unwrap();
        store.trust("a.com", 22, "ssh-rsa", "SHA256:two").unwrap();
        assert_eq!(store.lookup("a.com", 22).unwrap().fingerprint, "SHA256:two");
    }

    /// 写入结束后锁文件应立即清理，不得残留
    #[test]
    fn lock_file_is_cleaned_up_after_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let store = KnownHostsStore::open(path.clone()).unwrap();
        store.trust("a.com", 22, "ssh-rsa", "SHA256:x").unwrap();
        assert!(!lock_path_for(&path).exists(), "写入结束后锁文件应立即清理");
    }

    /// 同进程 open_shared 同一路径必须复用同一实例（Arc 指针相等）
    #[test]
    fn open_shared_reuses_instance_for_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let s1 = KnownHostsStore::open_shared(path.clone()).unwrap();
        let s2 = KnownHostsStore::open_shared(path.clone()).unwrap();
        assert!(Arc::ptr_eq(&s1, &s2), "同进程同路径应复用同一实例");
        s1.trust("a.com", 22, "ssh-rsa", "SHA256:x").unwrap();
        // 共享实例：s2 立即可见，无需重开
        assert_eq!(s2.lookup("a.com", 22).unwrap().fingerprint, "SHA256:x");
        // 不同路径必须是不同实例
        let other = KnownHostsStore::open_shared(dir.path().join("other.json")).unwrap();
        assert!(!Arc::ptr_eq(&s1, &other));
    }
}
