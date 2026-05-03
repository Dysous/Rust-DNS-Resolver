use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ThreatResult {
    pub score: u32,
    pub reasons: Vec<String>,
    pub flagged: bool,
}

#[derive(Debug)]
pub struct ThreatDetector {
    query_times_by_ip: HashMap<IpAddr, Vec<Instant>>,
    subdomains_by_domain: HashMap<String, HashSet<String>>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            query_times_by_ip: HashMap::new(),
            subdomains_by_domain: HashMap::new(),
        }
    }

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

        ThreatResult {
            score,
            flagged: score >= 50,
            reasons,
        }
    }

    fn track_frequency(&mut self, src_ip: IpAddr) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let entries = self.query_times_by_ip.entry(src_ip).or_default();
        entries.push(now);
        entries.retain(|t| now.duration_since(*t) <= window);
        entries.len()
    }
    fn track_subdomain_diversity(&mut self, domain: &str) -> usize {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 3 {
            return 0;
        }

        let base_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        let subdomain = parts[..parts.len() - 2].join(".");
        let entry = self.subdomains_by_domain.entry(base_domain).or_default();

        if !subdomain.is_empty() {
            entry.insert(subdomain);
        }
        entry.len()
    }
}

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