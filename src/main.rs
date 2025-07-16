use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    difficulty: u8,
    token_ttl_secs: u64,
    enable_traps: bool,
    trap_paths: Vec<String>,
}

#[derive(Deserialize)]
struct SolveRequest {
    salt: String,
    nonce: u64,
    difficulty: u8,
}

fn load_config(path: &str) -> Config {
    let content = fs::read_to_string(path).expect("Failed to read config file");
    toml::from_str(&content).expect("Invalid TOML format")
}

#[derive(Serialize)]
struct Challenge {
    salt: String,
    difficulty: u8,
    timestamp: u64,
}

fn generate_salt() -> String {
    rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

async fn challenge_handler(config: axum::extract::Extension<Config>) -> Json<Challenge> {
    let salt = generate_salt();
    let ts = current_unix_timestamp();

    let challenge = Challenge {
        salt,
        difficulty: config.difficulty,
        timestamp: ts,
    };

    Json(challenge)
}

fn has_leading_zero_bits(hash: &[u8], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;

    // Check full zero bytes
    if !hash.iter().take(full_bytes).all(|&b| b == 0) {
        return false;
    }

    // Check remaining bits
    if remaining_bits > 0 {
        let next_byte = hash[full_bytes];
        let mask = 0xFF << (8 - remaining_bits);
        if next_byte & mask != 0 {
            return false;
        }
    }

    true
}

async fn solve_handler(
    Json(payload): Json<SolveRequest>,
    //TODO
    // axum::extract::Extension(config): axum::extract::Extension<Arc<Config>>,
) -> StatusCode {
    let input = format!("{}{}", payload.nonce, payload.salt);
    let hash = Sha256::digest(input.as_bytes());

    if has_leading_zero_bits(&hash, payload.difficulty) {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    }
}

async fn root() -> &'static str {
    "Howdy?"
}

#[tokio::main]
async fn main() {
    let config = load_config("config.toml");

    let app = Router::new()
        .route("/", get(root))
        .route("/challenge", get(challenge_handler))
        .route("/solve", post(solve_handler))
        .layer(axum::extract::Extension(config));

    let server_addr = "0.0.0.0:13050";
    let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
    println!("Listening on http://{}", server_addr);
    axum::serve(listener, app).await.unwrap();
}
