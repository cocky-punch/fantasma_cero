use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Form, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use std::{
    sync::{Arc, RwLock},
    time::Instant,
};
use tera::{Context, Tera};
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::services::ServeDir;

use super::api_types::{JsResp, MetricsResp, PowResp, StatusResp};
use super::auth;
use super::state::AdminState;
use super::types::{ConfigSnapshot, RecentEvent, SuspiciousIp};
use super::helpers;

#[derive(Clone)]
pub struct AdminCtx {
    pub admin: AdminState,
    pub html_templates: Arc<Tera>,
    pub waf_metrics: Arc<crate::metrics::WafMetrics>,
    pub mode: String,
    pub version: String,
}

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
        .route("/index", get(ui_index))
        .route("/config", get(ui_config))
        // APIs
        .route("/api/status", get(status))
        .route("/api/metrics", get(metrics))
        .route("/api/recent", get(recent))
        .route("/api/suspicious", get(suspicious))
        .route("/api/config", get(config))
        .layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            auth::require_admin,
        ))
        // assets
        // FIXME - more appropriate location
        .nest_service("/assets", ServeDir::new("./src/web_ui/admin/assets"));

    let admin_inner = Router::new().merge(public_inner).merge(protected_inner);
    Router::new()
        .nest(ADMIN_URL_PREFIX, admin_inner)
        // .layer(NormalizePathLayer::trim_trailing_slash())
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

//TODO
async fn config(State(ctx): State<AdminCtx>) -> Json<ConfigSnapshot> {
    let g = ctx.admin.inner.read().await;
    Json(g.config_snapshot.clone())
}

//TODO
pub async fn ui_config(State(state): State<AdminCtx>) -> Html<String> {
    let mut ctx = helpers::tera_new_custom_context();
    ctx.insert("config_str", &format!("{:#?}", &*crate::config::CONFIG));
    let rendered = state
        .html_templates
        .render("config.html", &ctx)
        .unwrap_or_else(|e| format!("template error: {}", e));

    Html(rendered)
}

async fn ui_index(State(state): State<AdminCtx>) -> impl IntoResponse {
    let mut tctx = helpers::tera_new_custom_context();
    tctx.insert("mode", &state.mode);
    tctx.insert("version", &state.version);

    let html = state
        .html_templates
        .render("index.html", &tctx)
        .expect("template render failed");

    Html(html)
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
