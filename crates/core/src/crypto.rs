use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use fs2::FileExt;
use rand::Rng;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static MASTER_KEY: OnceLock<[u8; 32]> = OnceLock::new();
/// 串行化首次主密钥初始化，避免并发场景生成两个不同密钥（只有一个能与密钥文件保持一致）
static MASTER_KEY_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 将密钥文件权限收紧为仅当前用户可读写（Unix 0600）。
/// 读取既有密钥文件时也确保权限为 0600。
fn tighten_key_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            log::warn!("无法收紧主密钥文件权限 {:?}: {}", path, e);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// ==================== 跨进程文件锁（crypto 与 known_hosts 共用） ====================

/// 轮询获取操作系统文件锁的间隔与总超时。
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(20);
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// 计算目标文件对应的跨进程锁文件路径：同目录下 `.<文件名>.lock`
pub(crate) fn lock_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.lock"))
}

/// 跨进程互斥锁：锁文件仅作为操作系统文件锁的载体，不保存业务数据。
///
/// Unix 使用 `flock`，Windows 使用 `LockFile`；进程崩溃后操作系统会自动释放锁，
/// 因此无需也不允许通过时间戳判断“过期锁”并删除抢占。
pub(crate) struct FileLockGuard {
    handle: same_file::Handle,
    path: PathBuf,
}

impl FileLockGuard {
    pub(crate) fn acquire(lock_path: &Path) -> anyhow::Result<Self> {
        let deadline = Instant::now() + LOCK_TIMEOUT;
        'acquire: loop {
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|e| anyhow::anyhow!("无法打开锁文件 {:?}: {}", lock_path, e))?;
            loop {
                match file.try_lock_exclusive() {
                    Ok(()) => {
                        let handle = same_file::Handle::from_file(file).map_err(|e| {
                            anyhow::anyhow!("无法读取锁文件 {:?} 的身份信息: {}", lock_path, e)
                        })?;
                        match same_file::Handle::from_path(lock_path) {
                            Ok(current) if current == handle => {
                                return Ok(Self {
                                    handle,
                                    path: lock_path.to_path_buf(),
                                });
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => {
                                return Err(anyhow::anyhow!(
                                    "无法校验锁文件 {:?} 的身份: {}",
                                    lock_path,
                                    e
                                ));
                            }
                        }
                        // 锁路径已被释放者删除或替换：当前句柄对应旧文件，不能进入临界区。
                        let _ = FileExt::unlock(handle.as_file());
                        if Instant::now() >= deadline {
                            return Err(anyhow::anyhow!(
                                "获取文件锁 {:?} 超时（{} 秒），可能存在未及时释放锁的进程",
                                lock_path,
                                LOCK_TIMEOUT.as_secs()
                            ));
                        }
                        std::thread::sleep(LOCK_POLL_INTERVAL);
                        continue 'acquire;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(anyhow::anyhow!(
                                "获取文件锁 {:?} 超时（{} 秒），可能存在未及时释放锁的进程",
                                lock_path,
                                LOCK_TIMEOUT.as_secs()
                            ));
                        }
                        std::thread::sleep(LOCK_POLL_INTERVAL);
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("获取文件锁 {:?} 失败: {}", lock_path, e));
                    }
                }
            }
        }
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // 持锁时先删路径再解锁；已打开旧文件的等待者获锁后会校验身份并重新打开，
        // 避免旧、新 inode 各自持有操作系统锁而同时进入临界区。清理失败可忽略。
        let _ = fs::remove_file(&self.path);
        let _ = FileExt::unlock(self.handle.as_file());
    }
}

pub fn get_key_path() -> anyhow::Result<PathBuf> {
    // 允许通过环境变量覆盖（测试与自定义部署）
    if let Ok(custom) = std::env::var("OXITUN_MASTER_KEY_PATH") {
        let path = PathBuf::from(custom);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        return Ok(path);
    }
    let mut path = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("找不到系统的配置目录 (Config Directory)"))?;
    path.push("OxiTun");
    fs::create_dir_all(&path)?;
    path.push("master.key");
    Ok(path)
}

/// 读取既有密钥文件；内容损坏（非 Base64、长度非 32 字节）时报错，绝不覆盖。
/// 历史密文全部依赖该密钥，静默生成新密钥会导致全部密文不可恢复。
fn read_existing_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let b64_str = fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("无法读取主密钥文件 {:?}: {}", path, e))?;
    let bytes = general_purpose::STANDARD
        .decode(b64_str.trim())
        .map_err(|e| {
            anyhow::anyhow!(
                "主密钥文件 {:?} 内容损坏（Base64 解码失败）: {}。请从备份恢复，切勿直接删除",
                path,
                e
            )
        })?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "主密钥文件 {:?} 长度无效（期望 32 字节，实际 {} 字节）。请从备份恢复，切勿直接删除",
            path,
            bytes.len()
        ));
    }
    tighten_key_permissions(path);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn init_master_key() -> anyhow::Result<[u8; 32]> {
    // 无法确定密钥存储路径（配置目录不存在或无权限）时直接失败。
    // 调用方应使启动失败，并提示用户检查配置目录权限。
    let path = get_key_path().map_err(|e| {
        anyhow::anyhow!(
            "无法确定主密钥存储路径: {}。请检查配置目录权限，或设置 OXITUN_MASTER_KEY_PATH 环境变量",
            e
        )
    })?;

    if !path.exists() {
        // 跨进程互斥：进程内互斥锁无法阻止两个进程同时检测到“文件不存在”
        // 各自生成不同密钥（后写者 rename 覆盖先写者，导致先写者加密的配置无法解密）
        let _guard = FileLockGuard::acquire(&lock_path_for(&path))?;
        // 持锁后重新检查：竞争失败的进程必须改走读取路径，复用胜者已落盘的密钥，
        // 绝不能用本进程新生成的密钥覆盖
        if path.exists() {
            return read_existing_key(&path);
        }

        // 仅文件不存在时才生成新密钥
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let b64_str = general_purpose::STANDARD.encode(key);
        if write_key_file_atomic(&path, b64_str.as_bytes())? {
            log::info!("生成了全新的强主密钥并保存在 {:?}", path);
            return Ok(key);
        }
        // 防御性兜底：持有操作系统锁且已完成锁内二次检查，正常路径不会触发。
        // 若 rename 异常失败且目标已存在，仍读取已落盘密钥，绝不改用本进程的新密钥。
        return read_existing_key(&path);
    }

    read_existing_key(&path)
}

/// 生成进程唯一的临时文件路径：`key.tmp.{pid}.{随机u64}`。
/// pid + 随机数双因子避免多进程/多线程固定名 `key.tmp` 互相覆盖。
fn unique_tmp_path(path: &std::path::Path) -> PathBuf {
    let mut rand_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut rand_bytes);
    path.with_extension(format!(
        "key.tmp.{}.{:016x}",
        std::process::id(),
        u64::from_le_bytes(rand_bytes)
    ))
}

/// 原子写入密钥文件：先写同目录临时文件（pid + 随机后缀，避免多进程固定名冲突），
/// 再 rename 到目标文件；正常持锁路径下目标不存在，Unix 不会发生覆盖竞争。
/// Unix 上创建临时文件时即以 0600 权限打开，消除“先写后收紧”的权限暴露窗口。
/// 返回 Ok(false) 仅用于“rename 失败且目标已存在”的防御性兜底，正常持锁路径不会触发。
fn write_key_file_atomic(path: &std::path::Path, content: &[u8]) -> anyhow::Result<bool> {
    let tmp = unique_tmp_path(path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow::anyhow!("无法创建主密钥临时文件 {:?}: {}", tmp, e))?;
        file.write_all(content)
            .map_err(|e| anyhow::anyhow!("无法写入主密钥临时文件 {:?}: {}", tmp, e))?;
        // 覆盖复用旧临时文件时 mode() 不生效，显式收紧一次
        tighten_key_permissions(&tmp);
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp, content)
            .map_err(|e| anyhow::anyhow!("无法写入主密钥临时文件 {:?}: {}", tmp, e))?;
    }

    match fs::rename(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            // 正常持锁路径不会走到这里；若异常失败时目标已存在，
            // 仍交由调用方读取既有密钥，避免内存与磁盘使用不同密钥。
            if path.exists() {
                return Ok(false);
            }
            Err(anyhow::anyhow!("无法将主密钥写入至 {:?}: {}", path, e))
        }
    }
}

pub fn get_master_key() -> anyhow::Result<&'static [u8; 32]> {
    if let Some(key) = MASTER_KEY.get() {
        return Ok(key);
    }
    let _guard = MASTER_KEY_INIT_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("主密钥初始化锁状态异常"))?;
    if let Some(key) = MASTER_KEY.get() {
        return Ok(key);
    }
    let key = init_master_key()?;
    Ok(MASTER_KEY.get_or_init(|| key))
}

pub fn encrypt(plaintext: &str) -> anyhow::Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let cipher = Aes256Gcm::new(get_master_key()?.into());

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| anyhow::anyhow!("加密过程失败"))?;

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(&combined))
}

pub fn decrypt(encoded: &str) -> anyhow::Result<String> {
    if encoded.is_empty() {
        return Ok(String::new());
    }
    let combined = general_purpose::STANDARD.decode(encoded)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("密文长度无效"));
    }

    let nonce_bytes: [u8; 12] = combined[..12]
        .try_into()
        .map_err(|_| anyhow::anyhow!("无效的 nonce 格式"))?;
    let nonce = Nonce::from(nonce_bytes);
    let cipher = Aes256Gcm::new(get_master_key()?.into());
    let plaintext = cipher
        .decrypt(&nonce, &combined[12..])
        .map_err(|_| anyhow::anyhow!("使用当前主密钥解密失败"))?;
    Ok(String::from_utf8(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    /// 串行化对进程级环境变量 OXITUN_MASTER_KEY_PATH 的修改，避免并行测试互相干扰
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 在持有环境变量锁的前提下临时指向自定义密钥路径，执行后恢复原状。
    /// 直接调用 init_master_key()（而非 get_master_key()），避免污染进程内 OnceLock 缓存。
    fn with_key_path(path: &std::path::Path, f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        // edition 2024 起 set_var/remove_var 为 unsafe（进程级状态，可能与其他线程竞争）；
        // 此处已用 ENV_LOCK 串行化本模块内的访问
        unsafe { std::env::set_var("OXITUN_MASTER_KEY_PATH", path) };
        f();
        unsafe { std::env::remove_var("OXITUN_MASTER_KEY_PATH") };
    }

    #[test]
    fn generates_key_only_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        with_key_path(&path, || {
            let k1 = init_master_key().unwrap();
            assert!(path.exists(), "文件不存在时应生成新密钥并落盘");
            let k2 = init_master_key().unwrap();
            assert_eq!(k1, k2, "已存在的密钥文件必须读取复用，不得重新生成");
        });
    }

    #[test]
    fn corrupted_key_file_errors_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let broken = "!!!not-valid-base64!!!";
        fs::write(&path, broken).unwrap();
        with_key_path(&path, || {
            let err = init_master_key().unwrap_err();
            assert!(
                format!("{:#}", err).contains("损坏"),
                "非法 Base64 应报内容损坏: {err:#}"
            );
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                broken,
                "损坏的密钥文件绝不能被覆盖"
            );
        });
    }

    #[test]
    fn lock_file_is_cleaned_up_after_init() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let lock = lock_path_for(&path);
        with_key_path(&path, || {
            init_master_key().unwrap();
            assert!(path.exists());
            assert!(!lock.exists(), "初始化结束后锁文件应立即清理");
        });
    }

    #[test]
    fn file_lock_excludes_threads_using_same_path() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 5;

        let dir = tempfile::tempdir().unwrap();
        let lock = Arc::new(dir.path().join("shared.lock"));
        let barrier = Arc::new(Barrier::new(THREADS));
        let active = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let entered = Arc::clone(&entered);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..ROUNDS {
                    let _guard = FileLockGuard::acquire(&lock).unwrap();
                    assert_eq!(
                        active.fetch_add(1, Ordering::SeqCst),
                        0,
                        "同一路径不得同时进入临界区"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                    assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    entered.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(entered.load(Ordering::SeqCst), THREADS * ROUNDS);
    }

    #[test]
    fn file_locks_on_independent_paths_do_not_block_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let first = FileLockGuard::acquire(&dir.path().join("first.lock")).unwrap();
        let second = FileLockGuard::acquire(&dir.path().join("second.lock")).unwrap();
        drop(first);
        drop(second);
    }

    #[test]
    fn file_lock_can_be_reacquired_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("master.lock");
        let guard = FileLockGuard::acquire(&lock).unwrap();
        assert!(lock.exists());
        drop(guard);
        assert!(!lock.exists(), "释放后应清理锁文件");

        let guard = FileLockGuard::acquire(&lock).unwrap();
        drop(guard);
        assert!(!lock.exists(), "重新获取并释放后仍应清理锁文件");
    }

    #[test]
    fn wrong_length_key_file_errors_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        // 合法 Base64，但解码后只有 16 字节（期望 32）
        let short = general_purpose::STANDARD.encode([0u8; 16]);
        fs::write(&path, &short).unwrap();
        with_key_path(&path, || {
            let err = init_master_key().unwrap_err();
            assert!(
                format!("{:#}", err).contains("长度无效"),
                "长度不为 32 应报长度无效: {err:#}"
            );
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                short,
                "长度无效的密钥文件绝不能被覆盖"
            );
        });
    }
}
