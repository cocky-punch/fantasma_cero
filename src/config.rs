use once_cell::sync::Lazy;
use serde::Deserialize;
use std::sync::Arc;
use std::{fs, path::Path};

// Argon2 - time cost
const BASE_DIFFICULTY: u64 = 2; // ~5-10 seconds
const MAX_DIFFICULTY: u64 = 6; // ~30-60 seconds

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub port: Option<u16>,
    pub js_check_enabled: bool,
    pub js_token_secret: String, //FIXME - make it <redacted>
    pub operation_mode: OperationMode,

    //these URL-s must not be checked
    pub skip_paths: Vec<String>,
    pub skip_extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowChallendgeAlgorithm {
    Sha256,
    Argon2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PowChallendgeConfig {
    pub algorithm: PowChallendgeAlgorithm,

    //TODO remove
    pub difficulty: u8,
    //
    pub base_difficulty: u8,
    pub max_difficulty: u8,
    pub cookie_duration_days: u64,
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
    ValidationWithProxy,    // WAF proxies
    Validation,             // Only validate, web server proxies
}

#[derive(Debug, Deserialize, Clone)]
pub struct PersistenceConfig {
    pub sqlite_path: String,
}

#[derive(Clone, Deserialize)]
pub struct AdminConfig {
    pub user_name: String,
    pub password: String,
    pub cookie_validity_in_days: Option<u64>,
    pub base_path_prefix: String,
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("user_name", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub pow_challenge: PowChallendgeConfig,
    pub traps: TrapConfig,
    pub target: TargetConfig,
    pub persistence: PersistenceConfig,
    pub admin: AdminConfig,
}

fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str::<Config>(&content)?;
    Ok(config)
}

pub static CONFIG: Lazy<Arc<Config>> = Lazy::new(|| {
    //let cfg = load_config("config.toml").expect("failed to load config");
    //DEBUG
    let cfg = load_config("config.toml").unwrap_or_else(|e| {
        eprintln!("ERROR loading config: {}", e);
        eprintln!("Current dir: {:?}", std::env::current_dir());
        panic!("Config load failed");
    });

    Arc::new(cfg)
});
