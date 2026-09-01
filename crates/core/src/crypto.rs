use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

static MASTER_KEY: OnceLock<[u8; 32]> = OnceLock::new();
const DEFAULT_LEGACY_KEY: &[u8; 32] = b"OxiTun_SecretKey_1234567890_ABCD";

pub fn get_key_path() -> anyhow::Result<PathBuf> {
    let mut path = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("找不到系统的配置目录 (Config Directory)"))?;
    path.push("OxiTun");
    fs::create_dir_all(&path)?;
    path.push("master.key");
    Ok(path)
}

fn init_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    
    // 尝试获取保存的密钥
    if let Ok(path) = get_key_path() {
        if path.exists() {
            if let Ok(b64_str) = fs::read_to_string(&path) {
                if let Ok(bytes) = general_purpose::STANDARD.decode(b64_str.trim()) {
                    if bytes.len() == 32 {
                        key.copy_from_slice(&bytes);
                        return key;
                    }
                }
            }
        }
        
        // 生成强随机密钥 (向后兼容由 decrypt 函数的 fallback 机制保证)
        rand::rng().fill_bytes(&mut key);
        log::info!("生成了全新的强主密钥并保存在 {:?}", path);
        
        let b64_str = general_purpose::STANDARD.encode(key);
        if let Err(e) = fs::write(&path, b64_str) {
            log::error!("严重错误: 无法将主密钥写入至 {:?}: {}", path, e);
        }
        return key;
    }
    
    log::warn!("获取配置目录失败，回退使用内置的旧版主密钥。");
    key.copy_from_slice(DEFAULT_LEGACY_KEY);
    key
}

pub fn get_master_key() -> &'static [u8; 32] {
    MASTER_KEY.get_or_init(init_master_key)
}

pub fn encrypt(plaintext: &str) -> anyhow::Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let cipher = Aes256Gcm::new(get_master_key().into());
    
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
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
    
    let nonce_bytes: [u8; 12] = combined[..12].try_into().map_err(|_| anyhow::anyhow!("无效的 nonce 格式"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &combined[12..];
    
    // 1. 先尝试用当前的 Master Key 解密
    let cipher_main = Aes256Gcm::new(get_master_key().into());
    if let Ok(plaintext) = cipher_main.decrypt(&nonce, ciphertext) {
        if let Ok(s) = String::from_utf8(plaintext) {
            return Ok(s);
        }
    }
    
    // 2. 如果失败，尝试用旧的硬编码 Legacy Key 解密（完美向后兼容已保存的节点密码）
    let cipher_legacy = Aes256Gcm::new(DEFAULT_LEGACY_KEY.into());
    if let Ok(plaintext) = cipher_legacy.decrypt(&nonce, ciphertext) {
        if let Ok(s) = String::from_utf8(plaintext) {
            return Ok(s);
        }
    }
    
    Err(anyhow::anyhow!("使用当前密钥及历史遗留密钥均解密失败"))
}
