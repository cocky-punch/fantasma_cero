use axum::{http::StatusCode, response::IntoResponse};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct WafMetrics {
    pub total_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub allowed_requests: AtomicU64,

    pub pow_challenges: AtomicU64,
    pub pow_passed: AtomicU64,
    pub pow_failed: AtomicU64,
}

pub async fn metrics() -> impl IntoResponse {
    // TODO
    let body = "\
# HELP app_requests_total Total requests
# TYPE app_requests_total counter
app_requests_total 666
";

    (StatusCode::OK, body)
}
