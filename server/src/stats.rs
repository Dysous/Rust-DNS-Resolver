use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use serde::Serialize;

const LOG_BUFFER_SIZE: usize = 1000;    //ring buffer for logs

//log struct for ring buffer
#[derive(Serialize, Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,
    pub source_ip: String,
    pub domain: String,
    pub response_code: u8, //DNS RCODEs:
        /*
         0 (NOERROR) no error completed successfully,
         1 (FORMERR) format error server cannot interpret query,
         2 (SERVFAIL) server-side failure to process the request,
         3 (NXDOMAIN) non-existent query domain name,
         4 (NOTIMP) not implemented server doesn't support query type,
         5 (REFUSED) server refused process
        */
    pub latency_ms: u64,
    pub protocol: String, // UDP or DoH
}

//cache view struct
#[derive(Serialize, Clone, Debug)]
pub struct CacheEntryView {
    pub key: String,
    pub expires_in_secs: u64,
}

//stats engine struct
pub struct DnsStats {
    //counters (atomic, no locking needed)
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub upstream_forwards: AtomicU64,
    pub latency_samples: AtomicU64,

    //timing
    pub start_time: Instant,

    //data (mutexes locking required)
    pub domain_counts: Mutex<HashMap<String, u64>>,
    pub logs: Mutex<VecDeque<LogEntry>>, //ring buffer for logs
}

impl DnsStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            domain_counts: Mutex::new(HashMap::new()),
            upstream_forwards: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            start_time: Instant::now(),
            logs: Mutex::new(VecDeque::with_capacity(LOG_BUFFER_SIZE)),    //ring buffer capacity can change if needed
        }
    }

    //counters
    pub fn increment_queries(&self) { self.total_queries.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_cache_hits(&self) { self.cache_hits.fetch_add(1, Ordering::Relaxed); }
    pub fn increment_upstream(&self) { self.upstream_forwards.fetch_add(1, Ordering::Relaxed); }
    pub fn add_latency(&self, latency_ms: u64) {
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed); // Track the sample
    }
    //domain stats
    pub fn record_domain(&self, domain: String) {
        let mut counts = self.domain_counts.lock().unwrap();
        *counts.entry(domain).or_insert(0) += 1;
    }

    //ring buffer logging
    pub fn log_request(
        &self,
        source_ip: String,
        domain: String,
        response_code: u8,
        latency_ms: u64,
        protocol: String,
    ) {
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= LOG_BUFFER_SIZE {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            timestamp: Self::now(),
            source_ip,
            domain,
            response_code,
            latency_ms,
            protocol,
        });
    }

    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.logs.lock().unwrap().clone().into()
        //self.logs.lock().unwrap().iter().cloned().collect()
    }

    //helper functions
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn queries_per_second(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return 0.0;
        }
        self.total_queries.load(Ordering::Relaxed) as f64 / elapsed
    }

    pub fn avg_latency(&self) -> u64 {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 { return 0; }
        self.total_latency_ms.load(Ordering::Relaxed) / samples
    }
}