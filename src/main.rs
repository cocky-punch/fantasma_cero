use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use jsonwebtoken::{encode, EncodingKey, Header};

mod config;
use config::{Config, CONFIG};

type HmacSha256 = Hmac<Sha256>;
static TRAP_IPS: Lazy<Arc<Mutex<HashMap<String, u64>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

async fn challenge_handler(config: axum::extract::Extension<Config>) -> impl IntoResponse {
    let salt = generate_salt();
    let ts = current_unix_ts();

    let challenge = Challenge {
        salt,
        difficulty: config.pow.difficulty,
        timestamp: ts,
    };

    (StatusCode::OK, Json(challenge))
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

#[derive(Deserialize)]
struct SolveRequest {
    salt: String,
    nonce: u64,
    difficulty: u8,
}

#[derive(Serialize)]
struct SolveResponse {
    jwt: String,
    hmac_token: String,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn solve_handler(
    Json(payload): Json<SolveRequest>,
) -> impl IntoResponse {
    let input = format!("{}{}", payload.nonce, payload.salt);
    let hash = Sha256::digest(input.as_bytes());

    if has_leading_zero_bits(&hash, payload.difficulty) {
        let jwt = encode(
            &Header::default(),
            &Claims {
                sub: "client".to_string(),
                exp: (current_unix_ts() + 15 * 60) as usize,
            },
            &EncodingKey::from_secret(CONFIG.server.jwt_secret.as_bytes()),
        )
        .unwrap();

        // let mut mac = HmacSha256::new_from_slice(config.server.hmac_secret.as_bytes()).unwrap();
        let mut mac = HmacSha256::new_from_slice(CONFIG.server.hmac_secret.as_bytes()).unwrap();
        mac.update(format!("{}:{}", payload.salt, payload.nonce).as_bytes());
        let result = mac.finalize().into_bytes();
        let hmac_token = base64::encode(&result[..]);

        // let response = SolveResponse { jwt, hmac_token };
        let response = serde_json::json!({ "jwt": jwt, "hmac_token": hmac_token });
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::OK, Json(serde_json::json!({ "status": "ok", "hmac_token": null })))
    }
}

async fn root() -> &'static str {
    "Howdy?"
}

async fn purge_trap_ips_periodically() {
    loop {
        tokio::time::sleep(Duration::from_secs(CONFIG.traps.purge_interval)).await;
        let now = current_unix_ts();
        let mut map = TRAP_IPS.lock().unwrap();
        map.retain(|_, &mut t| now - t < CONFIG.traps.ttl_seconds);
    }
}

async fn trap_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    let now = current_unix_ts();

    TRAP_IPS.lock().unwrap().insert(ip.clone(), now);

    println!("⚠️ Trap triggered by IP: {ip}");

    // decoy response
    Json(serde_json::json!({
        "status": "ok",
        "data": "nothing to see here"
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/challenge", get(challenge_handler))
        .route("/solve", post(solve_handler))
    ;

    let server_addr = "0.0.0.0:13050";
    let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
    println!("Listening on http://{}", server_addr);
    axum::serve(listener, app).await.unwrap();
}
