//! known_hosts 持久化模块
//!
//! 实现 SSH 主机密钥的 TOFU（Trust On First Use）信任存储：
//! - 键为规范化后的 `host:port`（DNS 名小写、IPv6 去括号、默认端口补 22）
//! - 记录密钥类型、SHA256 指纹与首次信任时间
//! - 写入采用“临时文件 + 原子替换”，避免并发/崩溃导致文件损坏

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

/// known_hosts 存储（内存索引 + 文件持久化，原子写入）
pub struct KnownHostsStore {
    path: PathBuf,
    entries: Mutex<HashMap<String, KnownHost>>,
}

impl KnownHostsStore {
    /// 打开指定路径的存储文件（不存在则按空存储处理）
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let entries = match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str::<HashMap<String, KnownHost>>(&content)
                .map_err(|e| anyhow::anyhow!("known_hosts 文件损坏: {}", e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
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
        self.entries
            .lock()
            .expect("known_hosts lock")
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
        {
            let mut map = self.entries.lock().expect("known_hosts lock");
            map.insert(format!("{h}:{p}"), entry);
            self.persist_locked(&map)?;
        }
        Ok(())
    }

    /// 删除一条信任记录
    pub fn remove(&self, host: &str, port: u16) -> anyhow::Result<()> {
        let mut map = self.entries.lock().expect("known_hosts lock");
        if map.remove(&entry_key(host, port)).is_some() {
            self.persist_locked(&map)?;
        }
        Ok(())
    }

    /// 列出全部记录（按 host:port 排序）
    pub fn list(&self) -> Vec<KnownHost> {
        let mut v: Vec<_> = self
            .entries
            .lock()
            .expect("known_hosts lock")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| format!("{}:{}", a.host, a.port).cmp(&format!("{}:{}", b.host, b.port)));
        v
    }

    /// 原子写入：先写临时文件，再 rename 覆盖目标文件
    fn persist_locked(&self, map: &HashMap<String, KnownHost>) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(map)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, content)?;
        persist_rename(&tmp, &self.path)?;
        // 权限收紧：仅当前用户可读写
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// 跨平台原子替换（Windows 上 rename 不允许覆盖已存在文件）
fn persist_rename(tmp: &Path, target: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if target.exists() {
            std::fs::remove_file(target)?;
        }
    }
    std::fs::rename(tmp, target)?;
    Ok(())
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
}
