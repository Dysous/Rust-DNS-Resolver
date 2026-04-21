use std::sync::atomic::AtomicU64;

pub struct DnsStats {
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
}

impl DnsStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        }
    }
}
