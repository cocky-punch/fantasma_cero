use serde::Serialize;

#[derive(Serialize)]
pub struct StatusResp {
    pub mode: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Serialize)]
pub struct MetricsResp {
    pub rps: u32,
    pub allowed_pct: u32,
    pub js: JsResp,
    pub pow: PowResp,
    pub blocked: u64,
    pub rate_limited: u64,
}

#[derive(Serialize)]
pub struct JsResp {
    pub hits: u64,
    pub fail_pct: u32,
}

#[derive(Serialize)]
pub struct PowResp {
    pub hits: u64,
    pub fail_pct: u32,
}
