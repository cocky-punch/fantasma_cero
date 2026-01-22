use once_cell::sync::Lazy;
use serde::Deserialize;
use std::sync::Arc;
use std::{fs, path::Path};

// Argon2 - time cost
const BASE_DIFFICULTY: u64 = 2; // ~5-10 seconds
const MAX_DIFFICULTY: u64 = 6; // ~30-60 seconds

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub jwt_secret: String,
    pub hmac_secret: String,
    pub operation_mode: OperationMode,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowChallendgeAlgorithm {
    Sha256,
    Argon2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PowChallendgeConfig {
    // pub check_js_enabled: bool,
    // pub require_pow_challenge: bool
    pub algorithm: PowChallendgeAlgorithm,

    //TODO remove
    pub difficulty: u8,
    //
    pub base_difficulty: u8,
    pub max_difficulty: u8,
    pub cookie_duration_days: u8,
    pub rate_limit_window_minutes: u8,
    pub max_requests_per_window: u8,
    pub suspicion_threshold: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrapConfig {
    pub paths: Vec<String>,
    pub ttl_seconds: u64,
    pub purge_interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub origin_url: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OperationMode {
    Proxy,          // WAF proxies
    ValidationOnly, // Only validate, web server proxies
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistenceConfigBackend {
    Memory,
    Sqlite,
}

#[derive(Debug, Deserialize, Clone)]
struct PersistenceConfig {
    backend: PersistenceConfigBackend,
    sqlite_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub pow_challenge: PowChallendgeConfig,
    pub traps: TrapConfig,
    pub target: TargetConfig,
    pub persistence: PersistenceConfig,
}

fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str::<Config>(&content)?;
    Ok(config)
}

// pub static CONFIG: Lazy<Arc<Config>> = Lazy::new(|| {
//     let cfg = load_config("config.toml").expect("failed to load config");
//     Arc::new(cfg)
// });

//DEBUG
pub static CONFIG: Lazy<Arc<Config>> = Lazy::new(|| {
    let cfg = load_config("config.toml").unwrap_or_else(|e| {
        eprintln!("ERROR loading config: {}", e);
        eprintln!("Current dir: {:?}", std::env::current_dir());
        panic!("Config load failed");
    });
    Arc::new(cfg)
});
