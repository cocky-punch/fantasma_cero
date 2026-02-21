use axum::{Json, http::StatusCode, response::IntoResponse};
use axum::extract::State;
use serde::Serialize;
use crate::AppState;


#[derive(Serialize)]
struct Health {
    status: &'static str,
}

pub async fn health() -> impl IntoResponse {
    let h = Health { status: "ok" };
    (StatusCode::OK, Json(h))
}
