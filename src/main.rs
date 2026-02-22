use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use tera::{Context, Tera};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing_subscriber;
use uuid::Uuid;

mod admin;
mod config;
mod health;
mod helpers;
mod metrics;
mod security;

use crate::security::js_token::JsToken;
use crate::security::pow_token::PowToken;

const POW_COOKIE_NAME: &str = "fantasma0_verified";
const JS_ENABLED_COOKIE_NAME: &str = "fantasma0_js_ok";
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

//TODO
const RATE_LIMIT_WINDOW_MINUTES: u64 = 999;
//TODO
const MAX_REQUESTS_PER_WINDOW: u32 = 999;

const BASE_DIFFICULTY: u32 = 4;
const MAX_DIFFICULTY: u32 = 7;
const DEFAULT_TARGET_URL: &'static str = "example.com";
const SUSPICION_THRESHOLD: u32 = 40;
const DEFAULT_PORT: u16 = 8080;
const APPLICATION_NAME: &'static str = "fantasma0";
const ADMIN_BACKEND_URL_PREFIX: &'static str = "/fantasma0";

#[derive(Clone)]
pub struct AppState {
    challenges: Arc<RwLock<HashMap<String, PowChallenge>>>,
    ip_tracking: Arc<RwLock<HashMap<IpAddr, IpBehavior>>>,
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimit>>>,
    honeypots: Arc<RwLock<HashMap<String, u64>>>,
    concurrent_usage: Arc<RwLock<HashMap<String, Vec<ActiveSession>>>>,
    target_url: String,
    html_templates: Tera,

    //URL-s and paths that get skipped by PoW, any checks
    skip_exact_urls: Vec<String>,
    skip_prefix_urls: Vec<String>,
    skip_extention_urls: Vec<String>,
    //
    waf_metrics: Arc<metrics::WafMetrics>,
    db_pool: sqlx::SqlitePool,
}

#[derive(Clone, Debug)]
struct PowChallenge {
    attempt_id: Uuid,
    nonce: String,
    difficulty: u32,
    timestamp: u64,
    client_ip: IpAddr,
}

#[derive(Clone, Debug)]
struct IpBehavior {
    first_seen: u64,
    last_seen: u64,
    request_count: u32,
    challenge_failures: u32,
    user_agents: Vec<String>,
    suspicious_score: u32,
    honeypot_hits: u32,
}

#[derive(Clone, Debug)]
struct RateLimit {
    count: u32,
    window_start: u64,
}

#[derive(Clone, Debug)]
struct ActiveSession {
    ip_addr: IpAddr,
    user_agent: String,
    tls_fingerprint: String,
    last_request: u64,
    request_count: u32,
}

#[derive(Deserialize)]
struct PoWSubmission {
    nonce: String,
    solution: u64,
    // mouse_movements: Option<String>,
    // timing_data: Option<String>,
    browser_fingerprint: Option<String>,
    honeypot_field: Option<String>,
}

#[derive(Deserialize)]
pub struct JsVerifyRequest {
    pub token: String,
}

impl AppState {
    fn new(
        target_url: String,
        db_pool: sqlx::SqlitePool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut tera = Tera::new("html_templates/**/*")?;
        tera.autoescape_on(vec!["html"]);

        // URLs to skip
        let mut skip_exact_urls = Vec::new();
        let mut skip_prefix_urls = Vec::new();
        let mut skip_extention_urls = Vec::new();

        for p in &config::CONFIG.server.skip_paths {
            if p.ends_with('/') {
                skip_prefix_urls.push(p.clone());
            } else {
                skip_exact_urls.push(p.clone());
            }
        }

        for ext in &config::CONFIG.server.skip_extensions {
            let e = if ext.starts_with('.') {
                ext.clone()
            } else {
                format!(".{}", ext)
            };

            skip_extention_urls.push(e.to_ascii_lowercase());
        }

        Ok(Self {
            challenges: Default::default(),
            ip_tracking: Default::default(),
            rate_limits: Default::default(),
            honeypots: Default::default(),
            concurrent_usage: Default::default(),
            target_url,
            html_templates: tera,

            //TODO - load the historical data from the Db
            waf_metrics: Default::default(),

            skip_exact_urls,
            skip_prefix_urls,
            skip_extention_urls,

            db_pool,
        })
    }

    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut rate_limits = self.rate_limits.write().unwrap();
        let now = helpers::current_ts();
        let rate_limit = rate_limits.entry(ip).or_insert(RateLimit {
            count: 0,
            window_start: now,
        });

        if now - rate_limit.window_start > RATE_LIMIT_WINDOW_MINUTES * 60 {
            rate_limit.count = 0;
            rate_limit.window_start = now;
        }

        rate_limit.count += 1;
        rate_limit.count <= MAX_REQUESTS_PER_WINDOW
    }

    fn calculate_dynamic_difficulty(&self, ip: IpAddr) -> u32 {
        let ip_tracking = self.ip_tracking.read().unwrap();

        if let Some(behavior) = ip_tracking.get(&ip) {
            let mut difficulty = BASE_DIFFICULTY;

            if behavior.challenge_failures > 2 {
                difficulty += 1;
            }
            if behavior.user_agents.len() > 3 {
                difficulty += 1;
            }
            if behavior.honeypot_hits > 0 {
                difficulty += 2;
            }
            if behavior.suspicious_score > 50 {
                difficulty += 1;
            }

            std::cmp::min(difficulty, MAX_DIFFICULTY)
        } else {
            BASE_DIFFICULTY
        }
    }

    fn update_ip_behavior(&self, ip: IpAddr, user_agent: &str, suspicious_activity: bool) {
        let mut ip_tracking = self.ip_tracking.write().unwrap();
        let now = helpers::current_ts();
        let behavior = ip_tracking.entry(ip).or_insert(IpBehavior {
            first_seen: now,
            last_seen: now,
            request_count: 0,
            challenge_failures: 0,
            user_agents: Vec::new(),
            suspicious_score: 0,
            honeypot_hits: 0,
        });

        behavior.last_seen = now;
        behavior.request_count += 1;

        if !behavior.user_agents.contains(&user_agent.to_string()) {
            behavior.user_agents.push(user_agent.to_string());
        }

        if suspicious_activity {
            behavior.suspicious_score += 10;
        }

        if user_agent.to_lowercase().contains("bot")
            || user_agent.to_lowercase().contains("spider")
            || user_agent.to_lowercase().contains("crawl")
        {
            behavior.suspicious_score += 20;
        }

        if behavior.request_count > 50 && (now - behavior.first_seen) < 300 {
            behavior.suspicious_score += 15;
        }

        if behavior.user_agents.len() > 5 {
            behavior.suspicious_score += 25;
        }
    }

    fn generate_challenge(&self, client_ip: IpAddr, user_agent: &str) -> PowChallenge {
        let timestamp = helpers::current_ts();
        let difficulty = self.calculate_dynamic_difficulty(client_ip);
        // let attempt_id = Uuid::new_v4().to_string();
        let attempt_id = Uuid::new_v4();

        //TODO: too long for Argon2; must not exceed 64 chars
        // let nonce = format!("{}-{}-{}", client_ip, timestamp, Uuid::new_v4());
        let nonce = Uuid::new_v4().to_string();

        let challenge = PowChallenge {
            attempt_id: attempt_id,
            nonce: nonce.clone(),
            difficulty,
            timestamp,
            client_ip,
        };

        self.challenges
            .write()
            .unwrap()
            .insert(nonce.clone(), challenge.clone());

        self.update_ip_behavior(client_ip, user_agent, false);
        challenge
    }

    fn verify_pow_sha256(&self, nonce: &str, solution: u64, submission: &PoWSubmission) -> bool {
        let mut challenges = self.challenges.write().unwrap();

        if let Some(challenge) = challenges.remove(nonce) {
            let now = helpers::current_ts();
            if now - challenge.timestamp > 600 {
                self.update_ip_behavior(challenge.client_ip, "", true);
                return false;
            }

            if let Some(honeypot) = &submission.honeypot_field {
                if !honeypot.is_empty() {
                    self.record_honeypot_hit(challenge.client_ip);
                    return false;
                }
            }

            let input = format!("{}-{}", nonce, solution);
            let hash = Sha256::digest(input.as_bytes());
            let hash_hex = hex::encode(hash);

            let required_zeros = "0".repeat(challenge.difficulty as usize);
            let valid = hash_hex.starts_with(&required_zeros);

            if !valid {
                let mut ip_tracking = self.ip_tracking.write().unwrap();
                if let Some(behavior) = ip_tracking.get_mut(&challenge.client_ip) {
                    behavior.challenge_failures += 1;
                    behavior.suspicious_score += 5;
                }
            }

            valid
        } else {
            false
        }
    }

    fn verify_pow_argon2(&self, nonce: &str, solution: u64, submission: &PoWSubmission) -> bool {
        use argon2::{Algorithm, Argon2, Params, Version};

        let mut challenges = self.challenges.write().unwrap();
        if let Some(challenge) = challenges.remove(nonce) {
            let now = helpers::current_ts();
            //FIXME: const
            if now - challenge.timestamp > 600 {
                self.update_ip_behavior(challenge.client_ip, "", true);
                return false;
            }

            // honeypot
            if let Some(honeypot) = &submission.honeypot_field {
                if !honeypot.is_empty() {
                    self.record_honeypot_hit(challenge.client_ip);
                    return false;
                }
            }

            // argon2 PoW
            let input = format!("{}-{}", nonce, solution);

            //FIXME: const
            let params = Params::new(
                65536,                // Memory cost (64MB)
                challenge.difficulty, // Time cost (iterations)
                1,                    // Parallelism
                Some(32),             // Output length
            )
            .unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            // Hash with raw bytes (same as JavaScript)
            let mut output = [0u8; 32];

            match argon2.hash_password_into(
                input.as_bytes(), // password
                nonce.as_bytes(), // salt - raw bytes
                &mut output,      // output buffer
            ) {
                Ok(_) => {
                    // output to hex
                    let hash_hex = hex::encode(output);

                    // verify leading zeros
                    let required_zeros = challenge.difficulty as usize / 2;
                    let valid = hash_hex.starts_with(&"0".repeat(required_zeros));

                    if !valid {
                        let mut ip_tracking = self.ip_tracking.write().unwrap();
                        if let Some(behavior) = ip_tracking.get_mut(&challenge.client_ip) {
                            behavior.challenge_failures += 1;
                            behavior.suspicious_score += 5;
                        }
                    }

                    valid
                }
                Err(e) => {
                    eprintln!("❌ [POW] Argon2 error: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    fn record_honeypot_hit(&self, ip: IpAddr) {
        let mut honeypots = self.honeypots.write().unwrap();
        *honeypots.entry(ip.to_string()).or_insert(0) += 1;

        let mut ip_tracking = self.ip_tracking.write().unwrap();
        if let Some(behavior) = ip_tracking.get_mut(&ip) {
            behavior.honeypot_hits += 1;
            behavior.suspicious_score += 50;
        }
    }

    fn check_concurrent_usage(
        &self,
        token: &str,
        ip_addr: IpAddr,
        user_agent: &str,
        tls_fp: &str,
    ) -> u32 {
        let mut concurrent = self.concurrent_usage.write().unwrap();
        let now = helpers::current_ts();
        let sessions = concurrent.entry(token.to_string()).or_insert_with(Vec::new);
        sessions.retain(|s| now - s.last_request < 300);

        let mut found_session = false;
        for session in sessions.iter_mut() {
            if session.ip_addr == ip_addr
                && session.user_agent == user_agent
                && session.tls_fingerprint == tls_fp
            {
                session.last_request = now;
                session.request_count += 1;
                found_session = true;
                break;
            }
        }

        if !found_session {
            sessions.push(ActiveSession {
                ip_addr,
                user_agent: user_agent.to_string(),
                tls_fingerprint: tls_fp.to_string(),
                last_request: now,
                request_count: 1,
            });
        }

        let unique_sessions = sessions.len() as u32;
        match unique_sessions {
            1 => 0,
            2..=3 => 10,
            4..=10 => 25,
            _ => 60,
        }
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        let ip_tracking = self.ip_tracking.read().unwrap();

        if let Some(behavior) = ip_tracking.get(&ip) {
            behavior.suspicious_score > 100 || behavior.honeypot_hits > 2
        } else {
            false
        }
    }

    pub fn is_url_path_skipped(&self, path: &str) -> bool {
        let lowered_path = path.to_ascii_lowercase();
        if self.skip_exact_urls.iter().any(|p| *p == lowered_path) {
            return true;
        }

        if self
            .skip_prefix_urls
            .iter()
            .any(|p| lowered_path.starts_with(p))
        {
            return true;
        }

        self.skip_extention_urls
            .iter()
            .any(|ext| lowered_path.ends_with(ext))
    }
}

fn get_client_ip(headers: &HeaderMap) -> IpAddr {
    let ip_headers = [
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "x-client-ip",
    ];

    for header_name in &ip_headers {
        if let Some(header_value) = headers.get(*header_name) {
            if let Ok(header_str) = header_value.to_str() {
                let first_ip = header_str.split(',').next().unwrap_or("").trim();
                if let Some(ip) = first_ip.parse().ok() {
                    return ip;
                }
            }
        }
    }

    "127.0.0.1".parse().unwrap()
}

fn get_tls_fingerprint(headers: &HeaderMap) -> String {
    let mut fingerprint_parts = Vec::new();

    // Try Client Hints first (Chromium only)
    let has_client_hints = headers.contains_key("sec-ch-ua");

    if has_client_hints {
        // Chromium-based browsers - use stable Client Hints
        if let Some(ua) = headers.get("sec-ch-ua") {
            if let Ok(s) = ua.to_str() {
                fingerprint_parts.push(format!("ch-ua:{}", s));
            }
        }

        if let Some(platform) = headers.get("sec-ch-ua-platform") {
            if let Ok(s) = platform.to_str() {
                fingerprint_parts.push(format!("ch-platform:{}", s));
            }
        }

        if let Some(mobile) = headers.get("sec-ch-ua-mobile") {
            if let Ok(s) = mobile.to_str() {
                fingerprint_parts.push(format!("ch-mobile:{}", s));
            }
        }
    }

    // Always include User-Agent (universal fallback)
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(s) = user_agent.to_str() {
            // Normalize: extract browser name and major version only
            // This makes fingerprint stable across minor updates
            let normalized = helpers::normalize_user_agent(s);
            fingerprint_parts.push(format!("ua:{}", normalized));
        }
    }

    // Accept-Encoding is quite stable (gzip, deflate, br)
    if let Some(encoding) = headers.get("accept-encoding") {
        if let Ok(s) = encoding.to_str() {
            // Sort to handle order variations
            let mut encodings: Vec<&str> = s.split(',').map(|e| e.trim()).collect();
            encodings.sort();
            fingerprint_parts.push(format!("enc:{}", encodings.join(",")));
        }
    }

    if fingerprint_parts.is_empty() {
        return String::new();
    }

    let combined = fingerprint_parts.join("|");
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)[..16].to_string()
}

//more relaxed
fn get_tls_fingerprint2(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();

    // Normalized User-Agent (browser + major version + OS)
    if let Some(ua) = headers.get("user-agent") {
        if let Ok(s) = ua.to_str() {
            parts.push(helpers::normalize_user_agent(s));
        }
    }

    // Accept-Encoding (stable compression support)
    if let Some(enc) = headers.get("accept-encoding") {
        if let Ok(s) = enc.to_str() {
            let mut encodings: Vec<&str> = s.split(',').map(|e| e.trim()).collect();
            encodings.sort();
            parts.push(encodings.join(","));
        }
    }

    if parts.is_empty() {
        return String::new();
    }

    let combined = parts.join("|");
    let hash = Sha256::digest(combined.as_bytes());
    hex::encode(hash)[..16].to_string()
}

fn get_user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn extract_cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == cookie_name {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
        })
}

fn render_template(html_templates: &Tera, template_name: &str, context: &Context) -> Response {
    match html_templates.render(template_name, context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("Template error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

fn compare_browser_fingerprints(stored: &str, current: &str) -> u32 {
    // Parse both fingerprints
    let stored_fp: Result<Value, _> = serde_json::from_str(stored);
    let current_fp: Result<Value, _> = serde_json::from_str(current);

    if stored_fp.is_err() || current_fp.is_err() {
        return 0; // Can't compare, no penalty
    }

    let stored = stored_fp.unwrap();
    let current = current_fp.unwrap();

    let mut suspicion = 0;

    // Critical unchangeable characteristics (high suspicion if different)

    // Canvas fingerprint - very stable, hardware-specific
    if stored.get("canvas") != current.get("canvas") {
        suspicion += 30; // High - indicates different GPU/rendering
    }

    // WebGL fingerprint - hardware-specific
    if stored.get("webgl") != current.get("webgl") {
        suspicion += 30; // High - indicates different graphics card
    }

    // Platform - OS shouldn't change often
    if stored.get("platform") != current.get("platform") {
        suspicion += 25; // High - different OS
    }

    // Medium-stability characteristics (moderate suspicion)

    // Screen resolution - can change but uncommon
    if let (Some(stored_screen), Some(current_screen)) =
        (stored.get("screen"), current.get("screen"))
    {
        if stored_screen.get("width") != current_screen.get("width")
            || stored_screen.get("height") != current_screen.get("height")
        {
            suspicion += 10; // Moderate - monitor change or window resize
        }

        if stored_screen.get("colorDepth") != current_screen.get("colorDepth") {
            suspicion += 15; // Moderate-high - unusual to change
        }
    }

    // Hardware concurrency - CPU cores, rarely changes
    if stored.get("hardwareConcurrency") != current.get("hardwareConcurrency") {
        suspicion += 15; // Different CPU
    }

    // Available fonts - relatively stable
    if stored.get("fonts") != current.get("fonts") {
        suspicion += 8; // Minor - fonts can be installed/removed
    }

    // Low-stability characteristics (low/no suspicion - expected to change)

    // Timezone - ALLOWED TO CHANGE (travel, DST, manual change)
    // No penalty

    // Language - ALLOWED TO CHANGE (user preference)
    // No penalty

    // Device memory - ALLOWED TO CHANGE (RAM upgrade)
    // No penalty

    // Cookie enabled - browser setting, can change
    // No penalty

    // DoNotTrack - privacy setting, can change
    // No penalty

    suspicion
}

async fn verify_pow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(params): Form<PoWSubmission>,
) -> impl IntoResponse {
    // TODO
    eprintln!("[DEBUG] [verify_pow] #1");
    //

    let client_ip = get_client_ip(&headers);
    let user_agent = get_user_agent(&headers);
    let tls_fingerprint = get_tls_fingerprint(&headers);

    let pow_res = match config::CONFIG.pow_challenge.algorithm {
        config::PowChallendgeAlgorithm::Sha256 => {
            state.verify_pow_sha256(&params.nonce, params.solution, &params)
        }
        config::PowChallendgeAlgorithm::Argon2 => {
            state.verify_pow_argon2(&params.nonce, params.solution, &params)
        }
    };

    // TODO
    eprintln!(
        "[DEBUG] [verify_pow] pow_challenge.algorithm: {:?}",
        config::CONFIG.pow_challenge.algorithm
    );
    eprintln!("[DEBUG] [verify_pow] pow_res: {:?}", pow_res);

    if pow_res {
        let ttl_seconds = config::CONFIG.pow_challenge.cookie_duration_days * 24 * 3600;
        let cookie = PowToken::issue_cookie(
            config::CONFIG.server.pow_token_secret.as_bytes(),
            &client_ip,
            POW_COOKIE_NAME,
            ttl_seconds,
        );

        state
            .waf_metrics
            .pow_passed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut response = StatusCode::OK.into_response();
        response
            .headers_mut()
            .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());

        response
    } else {
        //update the metrics
        state
            .waf_metrics
            .pow_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        state.update_ip_behavior(client_ip, &user_agent, true);
        StatusCode::BAD_REQUEST.into_response()
    }
}

async fn honeypot_route(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers);
    state.record_honeypot_hit(client_ip);

    let mut context = Context::new();
    context.insert("message", "Page Not Found");
    render_template(&state.html_templates, "404.html", &context)
}

async fn admin_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ip_tracking = state.ip_tracking.read().unwrap();
    let honeypots = state.honeypots.read().unwrap();

    let stats = format!(
        r#"{{
    "tracked_ips": {},
    "honeypot_hits": {},
    "total_suspicious_score": {}
}}"#,
        ip_tracking.len(),
        honeypots.len(),
        ip_tracking
            .values()
            .map(|b| b.suspicious_score)
            .sum::<u32>()
    );

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        stats,
    )
}

async fn validate_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers);
    let user_agent = get_user_agent(&headers);
    let tls_fingerprint = get_tls_fingerprint(&headers);
    eprintln!("🔍 [VALIDATE] Request from {}", client_ip);

    if config::CONFIG.server.js_check_enabled {
        if let Some(cookie_value) = extract_cookie_value(&headers, JS_ENABLED_COOKIE_NAME) {
            let js_token_secret = config::CONFIG.server.js_token_secret.as_bytes();
            let js_ok = JsToken::verify(
                &js_token_secret,
                &cookie_value,
                &client_ip,
                &user_agent,
                120,
            );
            if !js_ok {
                let mut resp = StatusCode::UNAUTHORIZED.into_response();
                let header_name = axum::http::HeaderName::from_bytes(
                    format!("x-{}-challenge", APPLICATION_NAME).as_bytes(),
                )
                .unwrap();

                resp.headers_mut()
                    .insert(header_name, HeaderValue::from_static("js"));

                return resp;
            }
        }
    }

    if let Some(cookie_value) = extract_cookie_value(&headers, POW_COOKIE_NAME) {
        // let is_valid = verification_token::validate_pow_token(
        let is_valid = PowToken::verify(
            config::CONFIG.server.pow_token_secret.as_bytes(),
            &cookie_value,
            &client_ip,
        );

        if is_valid {
            // Return 200 - Nginx allows request through
            let mut resp = StatusCode::OK.into_response();
            let header_name = axum::http::HeaderName::from_bytes(
                format!("x-{}-verified", APPLICATION_NAME).as_bytes(),
            )
            .unwrap();

            resp.headers_mut().insert(
                header_name,
                // FIXME
                // HeaderValue::from_str(&suspicion_score.to_string()).unwrap(),
                HeaderValue::from_str("ok").unwrap(),
            );

            return resp;
        } else {
            eprintln!("❌ [VALIDATE] No cookie found");
        }
    }

    // Return 401 - Nginx returns the PoW challenge page
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    let header_name =
        axum::http::HeaderName::from_bytes(format!("x-{}-challenge", APPLICATION_NAME).as_bytes())
            .unwrap();

    resp.headers_mut()
        .insert(header_name, HeaderValue::from_static("pow"));

    resp
}

async fn robots_txt() -> impl IntoResponse {
    "User-agent: *\nDisallow: /secret-admin-link\n"
}

async fn proxy_to_target(mut req: Request<Body>) -> Response<Body> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let target_url = format!("{}{}", config::CONFIG.target.origin_url, path_and_query);
    let body = match to_bytes(std::mem::take(req.body_mut()), usize::MAX).await {
        Ok(x) => x,
        Err(_) => {
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let client = reqwest::Client::new();
    let mut out = client.request(req.method().clone(), target_url).body(body);

    // forward headers
    for (name, value) in req.headers().iter() {
        out = out.header(name, value);
    }

    // let resp = out.send().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let resp = match out.send().await {
        Ok(x) => x,
        Err(_) => {
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = resp.status();
    let headers = resp.headers().clone();

    // let bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    let bytes = match resp.bytes().await {
        Ok(x) => x,
        Err(_) => {
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let mut response = Body::from(bytes).into_response();
    *response.status_mut() = status;

    for (k, v) in headers {
        if let Some(k) = k {
            response.headers_mut().insert(k, v);
        }
    }

    response
}

fn cli_port() -> Option<u16> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--port" {
            return args.next().and_then(|p| p.parse().ok());
        }
    }
    None
}

fn env_port() -> Option<u16> {
    std::env::var("PORT").ok()?.parse().ok()
}

fn build_validation_router() -> Router<AppState> {
    Router::new()
        .route("/validate", get(validate_handler))
        //challenges
        .route("/js_challenge", get(js_challenge_handler))
        .route("/pow_challenge", get(pow_challenge_handler))
        // verifications
        .route("/verify_js", post(verify_js))
        .route("/verify_pow", post(verify_pow))
}

fn build_validation_with_proxy_router() -> Router<AppState> {
    Router::new()
        // verifications
        .route("/verify_js", post(verify_js))
        .route("/verify_pow", post(verify_pow))
        // others
        .route("/robots.txt", get(robots_txt))
        // TODO: with "poison bots" option; to be implemented
        // .route("/wp-admin", get(honeypot_route))
        .route("/", axum::routing::any(main_handler))
        .route("/{*path}", axum::routing::any(main_handler))
}

#[derive(Debug)]
enum ValidationDecision {
    Allow,
    JsChallenge,
    PowChallenge,
    Blocked(&'static str),
    Suspicious(u32),
    RateLimited,
}

fn decide_request(state: &AppState, req: &axum::http::Request<Body>) -> ValidationDecision {
    let path = req.uri().path();
    tracing::debug!("[decide_request] for {}", path);

    if state.is_url_path_skipped(path) {
        return ValidationDecision::Allow;
    }

    let headers = req.headers();
    let client_ip = get_client_ip(headers);
    let user_agent = get_user_agent(headers);
    let tls_fingerprint = get_tls_fingerprint(headers);
    let browser_fp = headers
        .get("x-browser-fingerprint")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    //update the metrics
    state
        .waf_metrics
        .total_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    if state.is_ip_blocked(client_ip) {
        return ValidationDecision::Blocked("Your IP has been blocked due to suspicious activity.");
    }

    // ── JS gate (optional) ──────────────────────────────
    if config::CONFIG.server.js_check_enabled {
        tracing::debug!(
            "[DEBUG] [js_check_enabled] #2; config.js_check_enabled: {}",
            config::CONFIG.server.js_check_enabled
        );

        let Some(cookie_value) = extract_cookie_value(&headers, JS_ENABLED_COOKIE_NAME) else {
            return ValidationDecision::JsChallenge;
        };

        let js_token_secret = config::CONFIG.server.js_token_secret.as_bytes();
        let js_ok = JsToken::verify(
            &js_token_secret,
            &cookie_value,
            &client_ip,
            &user_agent,
            120,
        );
        if !js_ok {
            return ValidationDecision::JsChallenge;
        }
    }

    // ── PoW ──────────────────────────────
    if let Some(cookie_value) = extract_cookie_value(headers, POW_COOKIE_NAME) {
        let is_valid = PowToken::verify(
            config::CONFIG.server.pow_token_secret.as_bytes(),
            &cookie_value,
            &client_ip,
        );

        if is_valid {
            return ValidationDecision::Allow;
        }
    }

    if !state.check_rate_limit(client_ip) {
        return ValidationDecision::RateLimited;
    }

    //update the metrics
    state
        .waf_metrics
        .pow_challenges
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    ValidationDecision::PowChallenge
}

async fn main_handler(
    State(state): State<AppState>,
    req: axum::http::Request<Body>,
) -> Response<Body> {
    tracing::debug!("[main_handler] #1");

    let decision = decide_request(&state, &req);
    handle_proxy_mode(&state, decision, req).await
}

async fn handle_proxy_mode(
    state: &AppState,
    decision: ValidationDecision,
    req: axum::http::Request<Body>,
) -> Response<Body> {
    match decision {
        ValidationDecision::Allow => proxy_to_target(req).await,

        ValidationDecision::JsChallenge => {
            js_challenge_handler(State(state.clone()), req.headers().clone()).await
        }

        ValidationDecision::PowChallenge => render_challenge(state, req.headers()),
        ValidationDecision::Blocked(msg) => {
            let mut ctx = Context::new();
            ctx.insert("message", msg);
            render_template(&state.html_templates, "blocked.html", &ctx)
        }
        ValidationDecision::Suspicious(score) => {
            let mut ctx = Context::new();
            ctx.insert("suspicion_score", &score);
            render_template(&state.html_templates, "suspicious.html", &ctx)
        }
        ValidationDecision::RateLimited => {
            let mut ctx = Context::new();
            ctx.insert("message", "Too many requests. Please try again later.");
            render_template(&state.html_templates, "rate_limited.html", &ctx)
        }
    }
}

async fn pow_challenge_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response<Body> {
    render_challenge(&state, &headers)
}

fn render_challenge(state: &AppState, headers: &HeaderMap) -> Response<Body> {
    let client_ip = get_client_ip(headers);
    let user_agent = get_user_agent(headers);

    let challenge = state.generate_challenge(client_ip, &user_agent);

    let mut context = Context::new();
    context.insert("nonce", &challenge.nonce);
    context.insert("difficulty", &challenge.difficulty);
    context.insert("expected_time", "10-60 seconds");
    context.insert("algorithm", &config::CONFIG.pow_challenge.algorithm);

    render_template(&state.html_templates, "pow_challenge.html", &context)
}

async fn js_challenge_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let client_ip = get_client_ip(&headers);
    let ua = get_user_agent(&headers);
    let js_token_secret = config::CONFIG.server.js_token_secret.as_bytes();
    let token = JsToken::issue(js_token_secret, &client_ip, &ua);
    let mut ctx = Context::new();
    ctx.insert("js_token", &token);

    render_template(&state.html_templates, "js_challenge.html", &ctx)
}

async fn verify_js(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<JsVerifyRequest>,
) -> Response {
    let ip_addr = get_client_ip(&headers);
    let ua = get_user_agent(&headers);
    let js_token_secret = config::CONFIG.server.js_token_secret.as_bytes();

    if !JsToken::verify(js_token_secret, &req.token, &ip_addr, &ua, 120) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let cookie = JsToken::issue_cookie(
        js_token_secret,
        &ip_addr,
        &ua,
        JS_ENABLED_COOKIE_NAME,
        86400,
    );
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());

    resp
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_new(&config::CONFIG.server.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tracing_subscriber::fmt::init();

    let _ = dotenvy::dotenv();
    let db_pool = helpers::init_db().await;
    init_tracing();

    let app_state = match AppState::new(config::CONFIG.target.origin_url.clone(), db_pool) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to initialize templates: {}", e);
            std::process::exit(1);
        }
    };

    let waf_metrics = app_state.waf_metrics.clone();
    let (waf_routes, listen_interface) = match config::CONFIG.server.operation_mode {
        config::OperationMode::ValidationWithProxy => {
            (build_validation_with_proxy_router(), "0.0.0.0")
        }
        config::OperationMode::Validation => (build_validation_router(), "127.0.0.1"),
    };

    let additional_routes = Router::new()
        .route("/health", get(health::health))
        .route("/metrics", get(metrics::metrics))
        // TODO
        // .route("/feedback_report", post(submit_feedback_report))
    ;

    // FIXME
    let admin_state = admin::state::AdminState::new(admin::types::ConfigSnapshot {
        js_check_enabled: false,
        pow_difficulty: 5,
        cookie_ttl_sec: 999,
        rate_limit_rps: 999,
    });

    let admin_ctx = admin::router::AdminCtx {
        admin: admin_state,
        html_templates: admin::helpers::init_tera_html_templates(),
        waf_metrics: waf_metrics,
        mode: format!("{:?}", config::CONFIG.server.operation_mode),
        version: env!("CARGO_PKG_VERSION").into(),
    };

    //
    //TODO - run the admin bg task: "clean-up old session"
    // let admin_state_clone = admin_state.clone();
    // tokio::spawn(async move {
    //     let mut interval = tokio::time::interval(Duration::from_secs(300));
    //     loop {
    //         interval.tick().await;
    //         admin_state_clone.cleanup();
    //     }
    // });
    //

    let admin_router = admin::router::build_router(admin_ctx);
    let app = Router::new()
        .merge(waf_routes)
        .with_state(app_state)
        .nest(ADMIN_BACKEND_URL_PREFIX, admin_router)
        .nest(ADMIN_BACKEND_URL_PREFIX, additional_routes);

    let port = cli_port()
        .or_else(env_port)
        .or(config::CONFIG.server.port)
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("{}:{}", listen_interface, port);

    println!("Fantasma0 running on http://{}", addr);
    println!(
        "Admin dashboard: http://{}{}",
        addr,
        config::CONFIG.admin.base_path_prefix
    );

    println!("Target URL: {}", config::CONFIG.target.origin_url);
    println!("Operation mode: {:?}", config::CONFIG.server.operation_mode);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
