use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

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

fn init_master_key() -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];

    // 无法确定密钥存储路径（配置目录不存在或无权限）时直接失败。
    // 调用方应使启动失败，并提示用户检查配置目录权限。
    let path = get_key_path().map_err(|e| {
        anyhow::anyhow!(
            "无法确定主密钥存储路径: {}。请检查配置目录权限，或设置 OXITUN_MASTER_KEY_PATH 环境变量",
            e
        )
    })?;

    if path.exists()
        && let Ok(b64_str) = fs::read_to_string(&path)
        && let Ok(bytes) = general_purpose::STANDARD.decode(b64_str.trim())
        && bytes.len() == 32
    {
        tighten_key_permissions(&path);
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    rand::rng().fill_bytes(&mut key);

    let b64_str = general_purpose::STANDARD.encode(key);
    fs::write(&path, b64_str)
        .map_err(|e| anyhow::anyhow!("无法将主密钥写入至 {:?}: {}", path, e))?;
    tighten_key_permissions(&path);
    log::info!("生成了全新的强主密钥并保存在 {:?}", path);
    Ok(key)
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
