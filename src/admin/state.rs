use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,

    // sync::{Arc, RwLock},
    sync::Arc,

    time::{Duration, Instant},
};

use super::types;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AdminState {
    pub auth_sessions: Arc<RwLock<HashMap<String, Instant>>>,
    pub started_at: Instant,
    pub inner: Arc<RwLock<AdminInner>>,
}

pub struct AdminInner {
    pub metrics: types::Metrics,
    pub recent: VecDeque<types::RecentEvent>,
    pub suspicious: Vec<types::SuspiciousIp>,
    pub config_snapshot: types::ConfigSnapshot,
}

impl AdminState {
    pub fn new(config_snapshot: types::ConfigSnapshot) -> Self {
        Self {
            started_at: Instant::now(),
            inner: Arc::new(RwLock::new(AdminInner {
                metrics: types::Metrics::default(),
                recent: VecDeque::with_capacity(100),
                suspicious: Vec::new(),
                config_snapshot,
            })),

            auth_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn push_event(&self, ev: types::RecentEvent) {
        let mut g = self.inner.write().await;
        if g.recent.len() >= 100 {
            g.recent.pop_front();
        }
        g.recent.push_back(ev);
    }

    pub async fn insert_auth_session(&self, token: String, ttl: Duration) {
        // let mut map = self.auth_sessions.write().unwrap();
        let mut map = self.auth_sessions.write().await;
        map.insert(token, Instant::now() + ttl);
    }

    pub async fn is_valid(&self, token: &str) -> bool {
        // let map = self.auth_sessions.read().unwrap();
        let map = self.auth_sessions.read().await;

        if let Some(expiry) = map.get(token) {
            *expiry > Instant::now()
        } else {
            false
        }
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        // let mut map = self.auth_sessions.write().unwrap();
        let mut map = self.auth_sessions.write().await;

        map.retain(|_, exp| *exp > now);
    }
}
