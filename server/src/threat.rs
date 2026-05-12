// Threat detection module for DNS monitoring
// This file analyzes incoming DNS queries and assigns a threat score based on
// patterns commonly seen in DNS tunneling, malware beaconing, and data exfiltration
// The detector does not block traffic directly. It flags suspicious queries and
// maintains a watchlist so the dashboard/logging layer can show evidence.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use serde_json;

#[derive(Debug)]
pub struct ThreatResult {
    pub score: u32,
    pub reasons: Vec<String>,
    pub flagged: bool,
    pub likely_tunneling: bool,
}

#[derive(Debug, Clone)]
pub struct TunnelEvidence {
    pub domain: String,
    pub sample_queries: Vec<String>,
    pub entropy_scores: Vec<f64>,
    pub unique_subdomain_count: usize,
    pub last_seen: Instant,
}

#[derive(Debug)]
struct DomainQueryEvent {
    full_query: String,
    subdomain: String,
    entropy: f64,
    seen_at: Instant,
}

// stores rolling state used to detect suspicious DNS behavior over time
// HashMaps allow tracking activity per IP and per base domain
// VecDeque is used for domain_events so old queries can be removed efficiently
// from the front of the queue during the 60-second sliding window
#[derive(Debug)]
pub struct ThreatDetector {
    query_times_by_ip: HashMap<IpAddr, Vec<Instant>>,
    subdomains_by_domain: HashMap<String, HashSet<String>>,
    // per domain history for tunneling recognition
    domain_events: HashMap<String, VecDeque<DomainQueryEvent>>,
    tunneling_watchlist: HashMap<String, TunnelEvidence>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            query_times_by_ip: HashMap::new(),
            subdomains_by_domain: HashMap::new(),
            domain_events: HashMap::new(),
            tunneling_watchlist: HashMap::new(),
        }
    }

    // runs all threat checks for a single DNS query
    // each suspicious signal adds to the score. If the score reaches the threshold,
    // the query is flagged and the reason list explains what triggered it
    pub fn analyze(&mut self, src_ip: IpAddr, domain: &str) -> ThreatResult {
        let mut score = 0;
        let mut reasons = Vec::new();
        let entropy = shannon_entropy(domain);
        if entropy > 3.8 {
            score += 30;
            reasons.push(format!("high entropy domain ({:.2})", entropy));
        }

        let longest_label = domain.split('.').map(|s| s.len()).max().unwrap_or(0);
        if longest_label > 30 {
            score += 30;
            reasons.push(format!("long label length ({})", longest_label));
        }

        let recent_count = self.track_frequency(src_ip);
        if recent_count > 20 {
            score += 25;
            reasons.push(format!("high query frequency from IP ({}/60s)", recent_count));
        }

        let diversity = self.track_subdomain_diversity(domain);
        if diversity > 15 {
            score += 25;
            reasons.push(format!("high subdomain diversity ({})", diversity));
        }

        let likely_tunneling = self.track_tunneling_pattern(domain);
        if likely_tunneling {
            score += 50;
            reasons.push("likely DNS tunneling pattern".to_string());
        }

        ThreatResult {
            score,
            flagged: score >= 50,
            reasons,
            likely_tunneling,
        }
    }

    pub fn watchlist(&self) -> Vec<serde_json::Value> {
        self.tunneling_watchlist
            .values()
            .map(|ev| {
                serde_json::json!({
                "domain": ev.domain,
                "sample_queries": ev.sample_queries,
                "entropy_scores": ev.entropy_scores,
                "unique_subdomain_count": ev.unique_subdomain_count,
                "last_seen_secs_ago": ev.last_seen.elapsed().as_secs(),
            })
            })
            .collect()
    }

    // tracks how many DNS queries a source IP has made in the last 60 seconds
    //high number of recent queries can indicate automated traffic or beaconing
    fn track_frequency(&mut self, src_ip: IpAddr) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let entries = self.query_times_by_ip.entry(src_ip).or_default();
        entries.push(now);
        entries.retain(|t| now.duration_since(*t) <= window);
        entries.len()
    }

    // tracks how many unique subdomains appear under the same base domain
    // DNS tunneling often creates many different subdomains to carry encoded data
    fn track_subdomain_diversity(&mut self, domain: &str) -> usize {
        let Some((base_domain, subdomain)) = split_base_and_subdomain(domain) else {
            return 0;
        };

        let entry = self.subdomains_by_domain.entry(base_domain).or_default();

        if !subdomain.is_empty() {
            entry.insert(subdomain);
        }

        entry.len()
    }
    // detects likely DNS tunneling by looking at behavior over a 60-second window
    // if one base domain receives many unique, high-entropy subdomains quickly,
    // it is added to the tunneling watchlist with evidence for later review
    fn track_tunneling_pattern(&mut self, domain: &str) -> bool {
        let Some((base_domain, subdomain)) = split_base_and_subdomain(domain) else {
            return false;
        };

        if subdomain.is_empty() {
            return false;
        }

        let now = Instant::now();
        let window = Duration::from_secs(60);

        let entropy = shannon_entropy(&subdomain);

        let events = self.domain_events.entry(base_domain.clone()).or_default();

        events.push_back(DomainQueryEvent {
            full_query: domain.to_string(),
            subdomain,
            entropy,
            seen_at: now,
        });

        while let Some(front) = events.front() {
            if now.duration_since(front.seen_at) > window {
                events.pop_front();
            } else {
                break;
            }
        }

        let unique_subdomains: HashSet<String> =
            events.iter().map(|e| e.subdomain.clone()).collect();

        let high_entropy_count = events.iter().filter(|e| e.entropy > 3.5).count();

        let likely_tunneling =
            unique_subdomains.len() >= 10 && high_entropy_count >= 8 && events.len() >= 10;

        if likely_tunneling {
            let sample_queries = events
                .iter()
                .take(5)
                .map(|e| e.full_query.clone())
                .collect();

            let entropy_scores = events
                .iter()
                .take(5)
                .map(|e| e.entropy)
                .collect();

            self.tunneling_watchlist.insert(
                base_domain.clone(),
                TunnelEvidence {
                    domain: base_domain,
                    sample_queries,
                    entropy_scores,
                    unique_subdomain_count: unique_subdomains.len(),
                    last_seen: now,
                },
            );
        }
        likely_tunneling
    }
}
fn split_base_and_subdomain(domain: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();

    if parts.len() < 3 {
        return None;
    }

    let base_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    let subdomain = parts[..parts.len() - 2].join(".");

    Some((base_domain, subdomain))
}

// Shannon entropy measures how random a domain looks.
// Normal domains are predictable (low entropy), while encoded/tunneled data
// appears random (high entropy). We use this as a signal to detect
// suspicious queries like DNS tunneling
fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::new();

    for c in input.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }

    let len = input.len() as f64;

    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
