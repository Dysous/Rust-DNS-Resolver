use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use serde::Serialize;
//use crate::threat::{ThreatResult, TunnelEvidence};
use crate::threat::ThreatResult;

const LOG_BUFFER_SIZE: usize = 1000;    //ring buffer for logs

//log struct for ring buffer
#[derive(Serialize, Clone, Debug)]
pub struct LogEntry {       //this is the storage format version
    pub timestamp: u64,
    pub source_ip: String,
    pub domain: String,
    pub response_code: u8, //DNS RCODEs
    pub latency_ms: u64,
    pub protocol: String, // UDP or DoH
}
#[derive(Serialize, Clone, Debug)]
pub struct LogEntryView {       //this is the presentation format version
    pub timestamp: u64,
    pub source_ip: String,
    pub domain: String,
    pub response_code: u8,
    pub status: String,         // "SAFE", "BLOCKED", etc
    pub latency_ms: u64,
    pub protocol: String,
}

impl LogEntry {
    // helper to map RCODE to a human-readable string
    pub fn get_status_label(&self) -> String {
        match self.response_code {
            0 => "SAFE".to_string(),      // NOERROR - no error completed successfully
            1 => "BAD_QUERY".to_string(), // FORMERR - format error server cannot interpret query
            2 => "SERV_FAIL".to_string(), // SERVFAIL - server-side failure to process the request
            3 => "BLOCKED".to_string(),   // NXDOMAIN - non-existent query domain name
            4 => "NOT_IMPL".to_string(),  // NOTIMP - not implemented server doesn't support query type
            5 => "REFUSED".to_string(),   // REFUSED - server refused process
            _ => "UNKNOWN".to_string(),
        }
    }
}

//cache view struct
#[derive(Serialize, Clone, Debug)]
pub struct CacheEntryView {
    pub key: String,
    pub expires_in_secs: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct ThreatEvent {
    pub timestamp: u64,
    pub source_ip: String,
    pub domain: String,
    pub score: u32,
    pub reasons: Vec<String>,
    pub likely_tunneling: bool,
}

//stats engine struct
pub struct DnsStats {
    //counters (atomic, no locking needed)
    pub total_queries: AtomicU64,
    pub cache_hits: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub upstream_forwards: AtomicU64,
    pub latency_samples: AtomicU64,
    pub blocked_total: AtomicU64,
    pub dnssec_success: AtomicU64,      //validations
    pub dnssec_failure: AtomicU64,

    //timing
    pub start_time: Instant,

    //data (mutexes locking required)
    pub domain_counts: Mutex<HashMap<String, u64>>,     //total domain count
    pub blocked_domains: Mutex<HashMap<String, u64>>,   //total blocked domain count
    pub logs: Mutex<VecDeque<LogEntry>>, //ring buffer for logs


    // Week 4: Metrics for the Dashboard Gauges
    pub threat_score_total: AtomicU64,
    pub threat_samples: AtomicU64,
    // Week 4: The "Security Feed" for the UI Table
    pub threat_events: Mutex<VecDeque<ThreatEvent>>,
}

impl DnsStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            upstream_forwards: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            dnssec_success: AtomicU64::new(0),
            dnssec_failure: AtomicU64::new(0),
            start_time: Instant::now(),
            domain_counts: Mutex::new(HashMap::new()),
            blocked_domains: Mutex::new(HashMap::new()),
            logs: Mutex::new(VecDeque::with_capacity(LOG_BUFFER_SIZE)),    //ring buffer capacity can change if needed

            threat_score_total: AtomicU64::new(0),
            threat_samples: AtomicU64::new(0),
            threat_events: Mutex::new(VecDeque::with_capacity(1000)),


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
    pub fn increment_blocked(&self, domain: &str) {
        self.blocked_total.fetch_add(1, Ordering::Relaxed);

        let mut blocked = self.blocked_domains.lock().unwrap();
        *blocked.entry(domain.to_string()).or_insert(0) += 1;
    }
    pub fn increment_dnssec_success(&self) {
        self.dnssec_success.fetch_add(1, Ordering::Relaxed);
    }
    pub fn increment_dnssec_failure(&self) {
        self.dnssec_failure.fetch_add(1, Ordering::Relaxed);
    }

    //domain stats
    pub fn record_domain(&self, domain: String) {
        let mut counts = self.domain_counts.lock().unwrap();
        *counts.entry(domain).or_insert(0) += 1;
    }

    //ring buffer logging
    pub fn log_request(     //there is a lot of cloning strings here which might affect server under extreme load
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

    pub fn get_logs(&self) -> Vec<LogEntryView> {
        let logs = self.logs.lock().unwrap();
        logs.iter()
            .map(|log| LogEntryView {
                timestamp: log.timestamp,
                source_ip: log.source_ip.clone(),
                domain: log.domain.clone(),
                response_code: log.response_code,
                status: log.get_status_label(), // Using our helper
                latency_ms: log.latency_ms,
                protocol: log.protocol.clone(),
            })
            .collect()
    }

    // --- ADD THE NEW WEEK 4 METHODS HERE ---

    /// Ingests a threat result from the detector and stores it for the UI.
    pub fn record_threat_result(&self, source_ip: String, domain: String, result: &ThreatResult) {
        // Update Averages (for the dashboard gauges)
        self.threat_score_total.fetch_add(result.score as u64, Ordering::Relaxed);
        self.threat_samples.fetch_add(1, Ordering::Relaxed);

        // Filter: Only store in the "Security Feed" if it's actually suspicious
        if result.score > 10 || result.likely_tunneling {
            let mut events = self.threat_events.lock().unwrap();
            if events.len() >= 1000 {
                events.pop_front();
            }

            events.push_back(ThreatEvent {
                timestamp: Self::now(),
                source_ip,
                domain,
                score: result.score,
                reasons: result.reasons.clone(),
                likely_tunneling: result.likely_tunneling,
            });
        }
    }

    /// Returns the average threat score across all queries
    pub fn get_avg_threat_score(&self) -> f64 {
        let samples = self.threat_samples.load(Ordering::Relaxed);
        if samples == 0 { return 0.0; }
        self.threat_score_total.load(Ordering::Relaxed) as f64 / samples as f64
    }

    /// Helper to get all threat events for the frontend table
    pub fn get_threat_events(&self) -> Vec<ThreatEvent> {
        let events = self.threat_events.lock().unwrap();
        events.iter().cloned().collect()
    }

    // --- END NEW METHODS ---

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