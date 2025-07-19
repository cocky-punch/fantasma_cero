use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Extension},
    http::{Request, StatusCode}, //{HeaderMap, HeaderName, HeaderValue}
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

use hmac::{Hmac, Mac};
use jsonwebtoken;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod config;
use config::{CONFIG, Config};
mod helpers;

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

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn solve_handler(Json(payload): Json<SolveRequest>) -> impl IntoResponse {
    let input = format!("{}{}", payload.nonce, payload.salt);
    let hash = Sha256::digest(input.as_bytes());

    if has_leading_zero_bits(&hash, payload.difficulty) {
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &Claims {
                sub: "client".to_string(),
                exp: (current_unix_ts() + 15 * 60) as usize,
            },
            &jsonwebtoken::EncodingKey::from_secret(CONFIG.server.jwt_secret.as_bytes()),
        )
        .unwrap();

        // let mut mac = HmacSha256::new_from_slice(config.server.hmac_secret.as_bytes()).unwrap();
        let mut mac = HmacSha256::new_from_slice(CONFIG.server.hmac_secret.as_bytes()).unwrap();
        mac.update(format!("{}:{}", payload.salt, payload.nonce).as_bytes());
        let result = mac.finalize().into_bytes();
        let hmac_token = base64::encode(&result[..]);

        //TODO
        // let response = SolveResponse { jwt, hmac_token };
        let response = serde_json::json!({ "jwt": jwt, "hmac_token": hmac_token });

        (StatusCode::OK, Json(response))
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ok", "hmac_token": null })),
        )
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

pub async fn proxy_handler(request: Request<Body>) -> impl IntoResponse {
    use reqwest::Client;

    let (parts, body) = request.into_parts();
    if let Err(_err) = verify_authorization(&parts.headers) {
        return Html(helpers::get_challenge_bootstrap_html()).into_response();
    }

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response(),
    };

    let target_url = format!(
        "{}{}",
        CONFIG.target.origin.trim_end_matches('/'),
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    let client = Client::new();
    let mut req_builder = client.request(parts.method, &target_url);
    for (name, value) in &parts.headers {
        let name_str = name.as_str().to_lowercase();
        if helpers::is_hop_by_hop_http_header(&name_str) {
            continue;
        }

        req_builder = req_builder.header(name, value);
    }

    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes);
    }

    let response = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Proxy request failed: {}", e);
            return (StatusCode::BAD_GATEWAY, "Failed to proxy request").into_response();
        }
    };

    // response from the target
    let status = response.status();
    match response.bytes().await {
        Ok(bytes) => (status, bytes).into_response(),
        Err(_) => (StatusCode::BAD_GATEWAY, "Failed to read response").into_response(),
    }
}

fn verify_authorization(headers: &axum::http::HeaderMap) -> Result<(), (StatusCode, &str)> {
    // Extract token from Authorization header (Bearer) or Cookie
    let maybe_token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| {
            headers
                .get("cookie")
                .and_then(|h| h.to_str().ok())
                .and_then(|cookies| extract_token_from_cookie(cookies))
        });

    let is_valid = match maybe_token {
        Some(token) => validate_token(token),
        None => false,
    };

    if is_valid {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "Invalid or missing authorization token",
        ))
    }
}

fn extract_token_from_cookie(cookies: &str) -> Option<&str> {
    for cookie in cookies.split(';') {
        let trimmed = cookie.trim();
        if let Some(val) = trimmed.strip_prefix("jwt=") {
            return Some(val);
        }
        if let Some(val) = trimmed.strip_prefix("hmac=") {
            return Some(val);
        }
    }
    None
}

pub fn validate_token(token: &str) -> bool {
    let decoding_key = jsonwebtoken::DecodingKey::from_secret(CONFIG.server.jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    match jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/challenge", get(challenge_handler))
        .route("/solve", post(solve_handler));

    tokio::spawn(purge_trap_ips_periodically());

    let server_addr = "0.0.0.0:13050";
    let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
    println!("Listening on http://{}", server_addr);
    axum::serve(listener, app).await.unwrap();
}
