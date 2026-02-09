use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::Serialize;
use std::time::Instant;

use super::api_types::{JsResp, MetricsResp, PowResp, StatusResp};
use super::auth;
use super::state::AdminState;
use super::types::{ConfigSnapshot, Metrics, RecentEvent, SuspiciousIp};

#[derive(Clone)]
pub struct AdminCtx {
    pub admin: AdminState,
    pub mode: String,
    pub version: String,
}

const ADMIN_INDEX: &str = include_str!("../web_ui/admin//index.html");
const ADMIN_STYLE: &str = include_str!("../web_ui/admin//style.css");
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
    let g = ctx.admin.inner.read().await;
    let m = &g.metrics;

    let total = m.allowed + m.blocked + m.rate_limited;
    let allowed_pct = if total == 0 {
        100
    } else {
        ((m.allowed * 100) / total) as u32
    };

    let js_fail_pct = pct(m.js_fail, m.js_hits);
    let pow_fail_pct = pct(m.pow_fail, m.pow_hits);

    Json(MetricsResp {
        rps: m.rps,
        allowed_pct,
        js: JsResp {
            hits: m.js_hits,
            fail_pct: js_fail_pct,
        },
        pow: PowResp {
            hits: m.pow_hits,
            fail_pct: pow_fail_pct,
        },
        blocked: m.blocked,
        rate_limited: m.rate_limited,
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

fn pct(fail: u64, total: u64) -> u32 {
    if total == 0 {
        0
    } else {
        ((fail * 100) / total) as u32
    }
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
