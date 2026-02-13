use std::sync::Arc;
use tera::{Context, Tera};

pub fn init_tera_html_templates() -> Arc<Tera> {
    // FIXME - more appropriate location
    Arc::new(Tera::new("src/web_ui/admin/**/*").expect("admin tera init failed"))
}

pub fn tera_new_custom_context() -> Context {
    let mut c = Context::new();
    c.insert("app_version", env!("CARGO_PKG_VERSION"));

    //append /
    let bpp = format!("{}/", crate::config::CONFIG.admin.base_path_prefix);
    c.insert("admin_base_path_prefix", &bpp);

    c
}
