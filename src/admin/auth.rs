use super::router;
use crate::config::CONFIG;
use axum::{
    body::{Body, to_bytes},
    extract::Form,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use time::Duration;

pub const COOKIE_NAME: &str = "admin_auth";

#[derive(Deserialize)]
pub struct SignInForm {
    pub user: String,
    pub pass: String,
}

static SIGN_IN_HTML: &str = include_str!("../web_ui/admin/sign_in.html");

fn render_sign_in(error: Option<&str>) -> axum::response::Html<String> {
    let err_block = match error {
        Some(msg) => format!(r#"<div class="err">{}</div>"#, msg),
        None => String::new(),
    };

    axum::response::Html(SIGN_IN_HTML.replace("{{error}}", &err_block))
}

pub async fn sign_in_page() -> Html<String> {
    render_sign_in(None)
}

pub async fn sign_in_post(jar: CookieJar, Form(form): Form<SignInForm>) -> impl IntoResponse {
    // if form.user == ADMIN_USER && form.pass == ADMIN_PASS {
    if form.user == CONFIG.admin.user_name && form.pass == CONFIG.admin.password {
        let cookie = Cookie::build((COOKIE_NAME, "1"))
            .path("/fantasma0/admin") // TODO: config
            .max_age(Duration::days(3)) // TODO: config
            .same_site(SameSite::Lax)
            .http_only(true)
            .finish();

        return (jar.add(cookie), Redirect::to("/fantasma0/admin")).into_response();
    }

    // invalid credentials
    (
        StatusCode::UNAUTHORIZED,
        render_sign_in(Some("Invalid credentials")),
    )
        .into_response()
}

pub async fn require_admin(
    axum::extract::State(ctx): axum::extract::State<router::AdminCtx>,
    jar: CookieJar,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    if jar.get(COOKIE_NAME).is_some() {
        next.run(req).await
    } else {
        Redirect::to("/fantasma0/admin/sign_in").into_response()
    }
}
