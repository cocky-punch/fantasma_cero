use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::Serialize;

use super::api_types::{JsResp, MetricsResp, PowResp, StatusResp};
use super::auth;
use super::state::AdminState;
use super::types::{ConfigSnapshot, RecentEvent, SuspiciousIp};

#[derive(Clone)]
pub struct AdminCtx {
    pub admin: AdminState,
    pub waf_metrics: Arc<crate::metrics::WafMetrics>,
    pub mode: String,
    pub version: String,
}

const ADMIN_INDEX: &str = include_str!("../web_ui/admin/index.html");
const ADMIN_STYLE: &str = include_str!("../web_ui/admin/style.css");
const ADMIN_APP_JS: &str = include_str!("../web_ui/admin/app.js");
const ADMIN_URL_PREFIX: &str = "/admin";

pub fn build_router(ctx: AdminCtx) -> Router {
    //
    // public
    //
    let public_inner = Router::new()
        .route("/sign_in", get(auth::sign_in_page))
        .route("/sign_in", post(auth::sign_in_post));

    //
    // protected
    //
    let protected_inner = Router::new()
        // UI
        .route("/", get(ui_index))
        // assets
        .route("/style.css", get(ui_style))
        .route("/app.js", get(ui_js))
        // APIs
        .route("/api/status", get(status))
        .route("/api/metrics", get(metrics))
        .route("/api/recent", get(recent))
        .route("/api/suspicious", get(suspicious))
        .route("/api/config", get(config))
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            auth::require_admin,
        ));

    let admin_inner = Router::new().merge(public_inner).merge(protected_inner);
    Router::new()
        .nest(ADMIN_URL_PREFIX, admin_inner)
        .with_state(ctx)
}

async fn status(State(ctx): State<AdminCtx>) -> Json<StatusResp> {
    let uptime = ctx.admin.started_at.elapsed().as_secs();
    Json(StatusResp {
        mode: ctx.mode,
        uptime_seconds: uptime,
        version: ctx.version,
    })
}

async fn metrics(State(ctx): State<AdminCtx>) -> Json<MetricsResp> {
    use std::sync::atomic::Ordering;

    let m = &ctx.waf_metrics;

    let total = m.total_requests.load(Ordering::Relaxed);
    let allowed = m.allowed_requests.load(Ordering::Relaxed);
    let blocked = m.blocked_requests.load(Ordering::Relaxed);

    let pow_challenges = m.pow_challenges.load(Ordering::Relaxed);
    let pow_passed = m.pow_passed.load(Ordering::Relaxed);
    let pow_failed = m.pow_failed.load(Ordering::Relaxed);

    let allowed_pct = if total == 0 {
        100
    } else {
        ((allowed * 100) / total) as u32
    };

    let pow_fail_pct = if pow_challenges == 0 {
        0
    } else {
        ((pow_failed * 100) / pow_challenges) as u32
    };

    Json(MetricsResp {
        total,
        allowed,
        blocked,
        allowed_pct,
        pow: PowResp {
            challenges: pow_challenges,
            passed: pow_passed,
            failed: pow_failed,
            fail_pct: pow_fail_pct,
        },
    })
}

async fn recent(State(ctx): State<AdminCtx>) -> Json<Vec<RecentEvent>> {
    let g = ctx.admin.inner.read().await;
    Json(g.recent.iter().cloned().collect())
}

async fn suspicious(State(ctx): State<AdminCtx>) -> Json<Vec<SuspiciousIp>> {
    let g = ctx.admin.inner.read().await;
    Json(g.suspicious.clone())
}

async fn config(State(ctx): State<AdminCtx>) -> Json<ConfigSnapshot> {
    let g = ctx.admin.inner.read().await;
    Json(g.config_snapshot.clone())
}

async fn ui_index() -> Html<&'static str> {
    Html(ADMIN_INDEX)
}

async fn ui_js() -> impl IntoResponse {
    ([("Content-Type", "application/javascript")], ADMIN_APP_JS)
}

async fn ui_style() -> impl IntoResponse {
    ([("Content-Type", "text/css")], ADMIN_STYLE)
}
