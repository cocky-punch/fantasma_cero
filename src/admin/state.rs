use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use super::types;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AdminState {
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
        }
    }

    pub async fn push_event(&self, ev: types::RecentEvent) {
        let mut g = self.inner.write().await;
        if g.recent.len() >= 100 {
            g.recent.pop_front();
        }
        g.recent.push_back(ev);
    }
}
