use crate::config::ServerConfig;
use anyhow::Result;
use russh::client::{self, Handler};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use russh::keys::{PublicKeyOrCertificate, decode_secret_key, key::PrivateKeyWithHashAlg};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
pub struct ClientHandler;

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct ServerPool {
    connections: RwLock<HashMap<String, Vec<Arc<russh::client::Handle<ClientHandler>>>>>,
    configs: HashMap<String, ServerConfig>,
    counter: AtomicUsize,
}

impl ServerPool {
    pub fn new(servers: Vec<ServerConfig>) -> Self {
        let mut configs = HashMap::new();
        for server in servers {
            configs.insert(server.name.clone(), server);
        }
        Self {
            connections: RwLock::new(HashMap::new()),
            configs,
            counter: AtomicUsize::new(0),
        }
    }

    pub async fn disconnect_all(&self) {
        let mut conns = self.connections.write().await;
        conns.clear();
        log::info!("All SSH connections closed.");
    }

    pub async fn get_connection(&self, name: &str) -> Result<Arc<russh::client::Handle<ClientHandler>>> {
        
        {
            let conns = self.connections.read().await;
            if let Some(handles) = conns.get(name) {
                // Skip dead connections in the pool
                for _ in 0..handles.len() {
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % handles.len();
                    let handle = &handles[idx];
                    if !handle.is_closed() {
                        return Ok(handle.clone());
                    }
                }
                log::warn!("All SSH connections to {} are closed. Reconnecting pool...", name);
            }
        }

        let mut conns = self.connections.write().await;
        // Double-check
        if let Some(handles) = conns.get(name) {
            for _ in 0..handles.len() {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % handles.len();
                let handle = &handles[idx];
                if !handle.is_closed() {
                    return Ok(handle.clone());
                }
            }
        }

        let config = self.configs.get(name).ok_or_else(|| anyhow::anyhow!("Server {} not found in config", name))?;
        let pool_size = config.pool_size as usize;
        
        log::info!("Establishing SSH connection pool (size {}) to {}...", pool_size, name);
        
        let mut new_handles = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            log::info!("Connecting SSH session {}/{} for {}", i+1, pool_size, name);
            let handle = self.create_connection(config).await?;
            new_handles.push(Arc::new(handle));
        }

        log::info!("SSH connection pool to {} established successfully.", name);
        conns.insert(name.to_string(), new_handles.clone());

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % new_handles.len();
        Ok(new_handles[idx].clone())
    }

    async fn create_connection(&self, config: &ServerConfig) -> Result<russh::client::Handle<ClientHandler>> {
        let russh_config = russh::client::Config::default();
        let host = config.host.clone();
        let port = config.port;

        let connect_future = async {
            let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            let _ = stream.set_nodelay(true);
            client::connect_stream(
                Arc::new(russh_config),
                stream,
                ClientHandler,
            ).await
        };

        let mut session = match tokio::time::timeout(
            std::time::Duration::from_secs(config.timeout_seconds as u64),
            connect_future,
        ).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow::anyhow!("SSH connect error: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("SSH connect timeout")),
        };

        // Auth
        let key_path_opt = config.key_path.as_deref().filter(|s| !s.trim().is_empty());
        let pwd_opt = config.password.as_deref().filter(|s| !s.trim().is_empty());

        let auth_res = if let Some(key_path) = key_path_opt {
            let key_str = std::fs::read_to_string(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read private key from {}: {}", key_path, e))?;
            let key = decode_secret_key(&key_str, pwd_opt)
                .map_err(|e| anyhow::anyhow!("Failed to decode private key: {}", e))?;
            let key_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
            session.authenticate_publickey(&config.user, key_alg).await?
        } else if let Some(pwd) = pwd_opt {
            session.authenticate_password(&config.user, pwd).await?
        } else {
            return Err(anyhow::anyhow!("No authentication method provided"));
        };

        if !auth_res.success() {
            return Err(anyhow::anyhow!("Authentication failed"));
        }

        Ok(session)
    }
}
