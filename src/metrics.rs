use axum::{http::StatusCode, response::IntoResponse};

pub async fn metrics() -> impl IntoResponse {
    // TODO
    let body = "\
# HELP app_requests_total Total requests
# TYPE app_requests_total counter
app_requests_total 666
";

    (StatusCode::OK, body)
}
