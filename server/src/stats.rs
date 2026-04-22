use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct DnsStats {
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub domain_counts: Mutex<HashMap<String, u64>>,
}

impl DnsStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            domain_counts: Mutex::new(HashMap::new()),
        }
    }
    
    pub fn record_domain(&self, domain: String) {
        let mut counts = self.domain_counts.lock().unwrap();
        *counts.entry(domain).or_insert(0) += 1;
    }
}
