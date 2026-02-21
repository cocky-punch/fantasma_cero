use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct StatusResp {
    pub mode: String,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Serialize)]
pub struct MetricsResp {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub allowed_pct: u32,

    pub pow: PowResp,
}

#[derive(Serialize)]
pub struct PowResp {
    pub challenges: u64,
    pub passed: u64,
    pub failed: u64,
    pub fail_pct: u32,
}

#[derive(Serialize)]
pub struct JsResp {
    pub hits: u64,
    pub fail_pct: u32,
}
