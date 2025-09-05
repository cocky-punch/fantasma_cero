use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tera::{Tera, Context};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use uuid::Uuid;
use tracing_subscriber;


const COOKIE_NAME: &str = "waf1a_verified";
const COOKIE_DURATION_DAYS: u64 = 14;
const RATE_LIMIT_WINDOW_MINUTES: u64 = 15;
const MAX_REQUESTS_PER_WINDOW: u32 = 10;
const BASE_DIFFICULTY: u32 = 4;
const MAX_DIFFICULTY: u32 = 7;
const DEFAULT_TARGET_URL: &'static str = "example.com";


#[derive(Clone)]
struct AppState {
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
    verified_tokens: Arc<RwLock<HashMap<String, VerifiedClient>>>,
    ip_tracking: Arc<RwLock<HashMap<IpAddr, IpBehavior>>>,
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateLimit>>>,
    honeypots: Arc<RwLock<HashMap<String, u64>>>,
    concurrent_usage: Arc<RwLock<HashMap<String, Vec<ActiveSession>>>>,
    target_url: String,
    templates: Tera,
}

#[derive(Clone, Debug)]
struct Challenge {
    nonce: String,
    difficulty: u32,
    timestamp: u64,
    client_ip: IpAddr,
}

#[derive(Clone, Debug)]
struct VerifiedClient {
    token: String,
    ip: IpAddr,
    user_agent: String,
    tls_fingerprint: String,
    browser_fingerprint: String,
    created_at: u64,
    last_seen: u64,
    request_count: u32,
    suspicious_score: u32,
    ip_changes: u32,
    user_agent_changes: u32,
    concurrent_sessions: u32,
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
    ip: IpAddr,
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

impl AppState {
    fn new(target_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut tera = Tera::new("templates/**/*")?;
        tera.autoescape_on(vec!["html"]);

        Ok(Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            verified_tokens: Arc::new(RwLock::new(HashMap::new())),
            ip_tracking: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            honeypots: Arc::new(RwLock::new(HashMap::new())),
            concurrent_usage: Arc::new(RwLock::new(HashMap::new())),
            target_url,
            templates: tera,
        })
    }

    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut rate_limits = self.rate_limits.write().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

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

        if user_agent.to_lowercase().contains("bot") ||
           user_agent.to_lowercase().contains("spider") ||
           user_agent.to_lowercase().contains("crawl") {
            behavior.suspicious_score += 20;
        }

        if behavior.request_count > 50 && (now - behavior.first_seen) < 300 {
            behavior.suspicious_score += 15;
        }

        if behavior.user_agents.len() > 5 {
            behavior.suspicious_score += 25;
        }
    }

    fn generate_challenge(&self, client_ip: IpAddr, user_agent: &str) -> Challenge {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let difficulty = self.calculate_dynamic_difficulty(client_ip);
        let nonce = format!("{}-{}-{}", client_ip, timestamp, Uuid::new_v4());

        let challenge = Challenge {
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

    fn verify_pow(&self, nonce: &str, solution: u64, submission: &PoWSubmission) -> bool {
        let mut challenges = self.challenges.write().unwrap();

        if let Some(challenge) = challenges.remove(nonce) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

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

    fn record_honeypot_hit(&self, ip: IpAddr) {
        let mut honeypots = self.honeypots.write().unwrap();
        *honeypots.entry(ip.to_string()).or_insert(0) += 1;

        let mut ip_tracking = self.ip_tracking.write().unwrap();
        if let Some(behavior) = ip_tracking.get_mut(&ip) {
            behavior.honeypot_hits += 1;
            behavior.suspicious_score += 50;
        }
    }

    fn is_verified_by_cookie(&self, cookie_value: &str, ip: IpAddr, user_agent: &str, tls_fp: &str) -> (bool, u32) {
        let mut verified = self.verified_tokens.write().unwrap();

        if let Some(client) = verified.get_mut(cookie_value) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now - client.created_at > COOKIE_DURATION_DAYS * 24 * 3600 {
                return (false, 0);
            }

            let mut suspicion_added = 0;

            if client.ip != ip {
                client.ip_changes += 1;
                if client.ip_changes > 3 {
                    suspicion_added += 30;
                }
                client.ip = ip;
            }

            if client.user_agent != user_agent {
                client.user_agent_changes += 1;
                if client.user_agent_changes > 2 {
                    suspicion_added += 40;
                }
            }

            if !client.tls_fingerprint.is_empty() && client.tls_fingerprint != tls_fp {
                suspicion_added += 50;
            }

            let concurrent_suspicion = self.check_concurrent_usage(cookie_value, ip, user_agent, tls_fp);
            suspicion_added += concurrent_suspicion;

            client.suspicious_score += suspicion_added;
            client.last_seen = now;
            client.request_count += 1;

            if client.suspicious_score > 80 {
                return (false, client.suspicious_score);
            }

            (true, client.suspicious_score)
        } else {
            (false, 0)
        }
    }

    fn check_concurrent_usage(&self, token: &str, ip: IpAddr, user_agent: &str, tls_fp: &str) -> u32 {
        let mut concurrent = self.concurrent_usage.write().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let sessions = concurrent.entry(token.to_string()).or_insert_with(Vec::new);

        sessions.retain(|s| now - s.last_request < 300);

        let mut found_session = false;
        for session in sessions.iter_mut() {
            if session.ip == ip && session.user_agent == user_agent && session.tls_fingerprint == tls_fp {
                session.last_request = now;
                session.request_count += 1;
                found_session = true;
                break;
            }
        }

        if !found_session {
            sessions.push(ActiveSession {
                ip,
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

    fn create_verified_token(&self, ip: IpAddr, user_agent: &str, tls_fp: &str, browser_fp: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let client = VerifiedClient {
            token: token.clone(),
            ip,
            user_agent: user_agent.to_string(),
            tls_fingerprint: tls_fp.to_string(),
            browser_fingerprint: browser_fp.to_string(),
            created_at: timestamp,
            last_seen: timestamp,
            request_count: 1,
            suspicious_score: 0,
            ip_changes: 0,
            user_agent_changes: 0,
            concurrent_sessions: 1,
        };

        self.verified_tokens
            .write()
            .unwrap()
            .insert(token.clone(), client);

        token
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        let ip_tracking = self.ip_tracking.read().unwrap();

        if let Some(behavior) = ip_tracking.get(&ip) {
            behavior.suspicious_score > 100 || behavior.honeypot_hits > 2
        } else {
            false
        }
    }
}

fn parse_ip(ip_str: &str) -> Option<IpAddr> {
    ip_str.parse().ok()
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
                if let Some(ip) = parse_ip(first_ip) {
                    return ip;
                }
            }
        }
    }

    "127.0.0.1".parse().unwrap()
}

fn get_tls_fingerprint(headers: &HeaderMap) -> String {
    let mut fingerprint_parts = Vec::new();

    if let Some(accept) = headers.get("accept") {
        if let Ok(s) = accept.to_str() {
            fingerprint_parts.push(s);
        }
    }

    if let Some(accept_encoding) = headers.get("accept-encoding") {
        if let Ok(s) = accept_encoding.to_str() {
            fingerprint_parts.push(s);
        }
    }

    if let Some(accept_language) = headers.get("accept-language") {
        if let Ok(s) = accept_language.to_str() {
            fingerprint_parts.push(s);
        }
    }

    let combined = fingerprint_parts.join("|");
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
            cookies
                .split(';')
                .find_map(|cookie| {
                    let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                    if parts.len() == 2 && parts[0] == cookie_name {
                        Some(parts[1].to_string())
                    } else {
                        None
                    }
                })
        })
}

fn render_template(templates: &Tera, template_name: &str, context: &Context) -> Response {
    match templates.render(template_name, context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("Template error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

async fn main_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers);
    let user_agent = get_user_agent(&headers);
    let tls_fingerprint = get_tls_fingerprint(&headers);

    if state.is_ip_blocked(client_ip) {
        let mut context = Context::new();
        context.insert("message", "Your IP has been blocked due to suspicious activity.");
        return render_template(&state.templates, "blocked.html", &context);
    }

    if !state.check_rate_limit(client_ip) {
        let mut context = Context::new();
        context.insert("message", "Too many requests. Please try again later.");
        return render_template(&state.templates, "rate_limited.html", &context);
    }

    if let Some(cookie_value) = extract_cookie_value(&headers, COOKIE_NAME) {
        let (is_valid, suspicion_score) = state.is_verified_by_cookie(
            &cookie_value,
            client_ip,
            &user_agent,
            &tls_fingerprint
        );

        if is_valid {
            if suspicion_score > 40 {
                let mut context = Context::new();
                context.insert("suspicion_score", &suspicion_score);
                return render_template(&state.templates, "suspicious.html", &context);
            }
            let mut context = Context::new();
            context.insert("target_url", &state.target_url);
            return render_template(&state.templates, "success.html", &context);
        } else if suspicion_score > 0 {
            let mut context = Context::new();
            context.insert("suspicion_score", &suspicion_score);
            return render_template(&state.templates, "invalidated.html", &context);
        }
    }

    let challenge = state.generate_challenge(client_ip, &user_agent);
    let mut context = Context::new();
    context.insert("nonce", &challenge.nonce);
    context.insert("difficulty", &challenge.difficulty);
    context.insert("expected_time", "10-60 seconds");

    render_template(&state.templates, "challenge.html", &context)
}

async fn verify_pow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<PoWSubmission>,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers);
    let user_agent = get_user_agent(&headers);
    let tls_fingerprint = get_tls_fingerprint(&headers);

    if state.verify_pow(&params.nonce, params.solution, &params) {
        let browser_fp = params.browser_fingerprint.as_deref().unwrap_or("unknown");
        let token = state.create_verified_token(client_ip, &user_agent, &tls_fingerprint, browser_fp);

        let cookie_value = format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Strict",
            COOKIE_NAME,
            token,
            COOKIE_DURATION_DAYS * 24 * 3600
        );

        let mut response = StatusCode::OK.into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie_value).unwrap(),
        );

        response
    } else {
        state.update_ip_behavior(client_ip, &user_agent, true);
        StatusCode::BAD_REQUEST.into_response()
    }
}

async fn honeypot_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = get_client_ip(&headers);
    state.record_honeypot_hit(client_ip);

    let mut context = Context::new();
    context.insert("message", "Page Not Found");
    render_template(&state.templates, "404.html", &context)
}

async fn health_check() -> impl IntoResponse {
    "Waf-1a is running"
}

async fn admin_stats(State(state): State<AppState>) -> impl IntoResponse {
    let ip_tracking = state.ip_tracking.read().unwrap();
    let verified_tokens = state.verified_tokens.read().unwrap();
    let honeypots = state.honeypots.read().unwrap();

    let stats = format!(
        r#"{{
    "tracked_ips": {},
    "verified_clients": {},
    "honeypot_hits": {},
    "total_suspicious_score": {}
}}"#,
        ip_tracking.len(),
        verified_tokens.len(),
        honeypots.len(),
        ip_tracking.values().map(|b| b.suspicious_score).sum::<u32>()
    );

    (StatusCode::OK, [("content-type", "application/json")], stats)
}

async fn robots_txt() -> impl IntoResponse {
    "User-agent: *\nDisallow: /secret-admin-link\n"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //TODO
    // tracing_subscriber::init();
    tracing_subscriber::fmt::init();

    let target_url: String = std::env::var("TARGET_URL")
        .unwrap_or_else(|_| format!("https://{}", DEFAULT_TARGET_URL));


    let state = match AppState::new(target_url) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Failed to initialize templates: {}", e);
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .route("/", get(main_handler))
        .route("/verify-pow", post(verify_pow))
        .route("/health", get(health_check))
        .route("/admin/stats", get(admin_stats))
        .route("/secret-admin-link", get(honeypot_route))
        .route("/wp-admin", get(honeypot_route))
        .route("/robots.txt", get(robots_txt))
        .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    println!("🛡️ Waf-1a Enhanced starting on {}", addr);
    println!("Target URL: {}",
        std::env::var("TARGET_URL").unwrap_or_else(|_|  format!("https://{}", DEFAULT_TARGET_URL)));
    println!("Features enabled:");
    println!("  - Dynamic PoW difficulty (base: {})", BASE_DIFFICULTY);
    println!("  - Cookie-based tracking (14 days)");
    println!("  - Behavioral analysis & honeypots");
    println!("  - Rate limiting ({} req/{}min)", MAX_REQUESTS_PER_WINDOW, RATE_LIMIT_WINDOW_MINUTES);
    println!("  - IP reputation tracking");
    println!("Admin stats: http://localhost:{}/admin/stats", port);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
