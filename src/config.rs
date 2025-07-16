use serde::Deserialize;
use std::{fs, path::Path};
use once_cell::sync::Lazy;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub jwt_secret: String,
    pub hmac_secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PoWConfig {
    pub difficulty: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrapConfig {
    pub paths: Vec<String>,
    pub ttl_seconds: u64,
    pub purge_interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub pow: PoWConfig,
    pub traps: TrapConfig,
}

fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str::<Config>(&content)?;
    Ok(config)
}

pub static CONFIG: Lazy<Arc<Config>> = Lazy::new(|| {
    let cfg = load_config("config.toml").expect("failed to load config");
    Arc::new(cfg)
});
