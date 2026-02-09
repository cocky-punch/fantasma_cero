use axum::{Router, extract::State, response::Html, routing::get};
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    templates: Arc<Tera>,
}

async fn home(State(state): State<AppState>) -> Html<String> {
    let mut context = Context::new();
    context.insert("page", "home");
    let html = state.templates.render("home.html", &context).unwrap();
    Html(html)
}

async fn about(State(state): State<AppState>) -> Html<String> {
    let mut context = Context::new();
    context.insert("page", "about");
    let html = state.templates.render("about.html", &context).unwrap();
    Html(html)
}

async fn contacts(State(state): State<AppState>) -> Html<String> {
    let mut context = Context::new();
    context.insert("page", "contacts");
    let html = state.templates.render("contacts.html", &context).unwrap();
    Html(html)
}

#[tokio::main]
async fn main() {
    let mut tera = Tera::new("html_templates/**/*").expect("Failed to load templates");
    tera.autoescape_on(vec!["html"]);

    let state = AppState {
        templates: Arc::new(tera),
    };

    let app = Router::new()
        .route("/", get(home))
        .route("/about", get(about))
        .route("/contacts", get(contacts))
        .with_state(state);

    let addr = "127.0.0.1:8080";

    println!("🌐 Test website running on http://{}", addr);
    println!();
    println!("🔒 SECURITY: Localhost binding (127.0.0.1)");
    println!("   ✅ Not accessible from internet directly");
    println!("   ✅ Only accessible through Fantasma-Cero proxy");
    println!();
    println!("📝 Access via: http://localhost:3000 (through Fantasma-Cero)");

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
