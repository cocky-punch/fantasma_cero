use serde::Serialize;
use std::net::IpAddr;

#[derive(Serialize, Clone)]
pub struct RecentEvent {
    pub ts: String,
    pub ip: IpAddr,
    pub decision: String,
    pub reason: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct SuspiciousIp {
    pub ip: IpAddr,
    pub score: u32,
    pub last_seen: String,
}

#[derive(Serialize, Clone)]
pub struct ConfigSnapshot {
    pub js_check_enabled: bool,
    pub pow_difficulty: u32,
    pub cookie_ttl_sec: u64,
    pub rate_limit_rps: u32,
}
