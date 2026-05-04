mod packet;
mod stats;
mod blocklist;
mod threat;
use threat::ThreatDetector;
mod doh;
mod dnssec;
//dns packet file

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, };
// use std::net::{SocketAddr, UdpSocket};
use std::time::*;
use std::collections::HashMap;

use std::sync::{Arc};
use std::sync::atomic::{ Ordering};
use tokio::net::UdpSocket;
use axum::{extract::State, routing::get, Router, Json};
use axum::routing::post;
use tower_http::services::{ServeDir, ServeFile};
use crate::blocklist::Blocklist;
use crate::doh::DoHState;
use tokio::sync::Mutex;
use crate::dnssec::DnssecSigner;

#[derive(Clone)]
pub struct CacheEntry {
    pub response: Vec<u8>,
    pub expires_at: Instant,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rng = ring::rand::SystemRandom::new();
    let pk8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("Failed to generate PKCS8 BYTES");
    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, pk8_bytes.as_ref(), &rng)
        .expect("Failed to create key pair from PKCS8");
    let signer = Arc::new(dnssec::DnssecSigner::new(key_pair));

    //website stats/domain
    let shared_stats = Arc::new(stats::DnsStats::new());
    let shared_cache = Arc::new(Mutex::new(HashMap::new()));


    let domain = "group8-monitor";
    let token = "960d0d55-e9ce-4846-83c9-188350fde697";
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let url = format!("http://www.duckdns.org/update?domains={}&token={}", domain, token);

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {//update duck dns binding loop
            //TODO pfsense creates an warning that takes down the actual server website
            interval.tick().await;
            match client.get(&url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        if body.contains("OK") {
                            println!("DuckDNS: Update successful." );
                        } else {
                            println!("DuckDNS: Update failed." );
                        }
                    }
                }
                Err(e) => eprintln!("DuckDNS: Error while sending request to DuckDNS: {}", e),
            }
        }
    });

    let shared_blocklist = Arc::new(Blocklist::load("hosts.txt"));
    let dns_stats = Arc::clone(&shared_stats);
    let dns_blocklist = Arc::clone(&shared_blocklist);

    //shared cache for udp listener and the DoH handling
    let dns_cache = Arc::clone(&shared_cache);
    let dns_signer = Arc::clone(&signer);

    tokio::spawn(async move {
        if let Err(e) = run_udp_listener("0.0.0.0:53", "dns_requests.log", dns_stats, dns_blocklist, dns_cache, dns_signer).await {
            eprintln!("Error: {}", e);
        }
    });

    //website routing
    let web_stats = Arc::clone(&shared_stats);
    let static_dir = "static";
    let index_file = "static/index.html";

    let doh_state = DoHState {
        stats: Arc::clone(&shared_stats),
        blocklist: Arc::clone(&shared_blocklist),
        cache: Arc::clone(&shared_cache),
        signer: Arc::clone(&signer),
    };

    let app = Router::new()
        .route_service("/", ServeFile::new(index_file))
        .route("/api/stats", get(move | State(s): State<Arc<stats::DnsStats>> | async move {
            let domain_map = s.domain_counts.lock().unwrap();
            Json(serde_json::json!({
                "queries": s.total_queries.load(Ordering::Relaxed),
                "cache_hits": s.cache_hits.load(Ordering::Relaxed),
                "avg_latency_ms": if s.total_queries.load(Ordering::Relaxed) > 0 {
                    s.total_latency_ms.load(Ordering::Relaxed) / s.total_queries.load(Ordering::Relaxed)
                } else { 0 },
                "top_domains": *domain_map,
            }))
        }))
        .with_state(web_stats)
        .nest(//dns-query endpoint handles DNS over HTTPS requests (encrypted DNS)
            "/dns-query",
            Router::new().route("/", post(doh::doh_query_handler))
                .with_state(doh_state),
        )
        .fallback_service(ServeDir::new(static_dir));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Web Monitor Live At https://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    //getting http connection info now for /dns-query integration with stats later
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())

}

async fn run_udp_listener(bind_addr: &str,
                          log: &str,
                          stats: Arc<stats::DnsStats>,
                          blocklist: Arc<Blocklist>,
                          cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
                          signer: Arc<DnssecSigner>,

) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    println!("UDP listener running on {}", bind_addr);

    let mut buf = [0u8; 512];
    let mut threat_detector = ThreatDetector::new();

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let request = &buf[..size];

        log_request(log,src, request)?;
        println!("\nreceived {} bytes from {}", size, src);
        print_hex(request);

        stats.total_queries.fetch_add(1, Ordering::Relaxed);
        let response = {//quickly lock shared resource
            let mut guard = cache.lock().await;
            handle_request(request, src, &mut guard, &stats, &blocklist,&mut threat_detector, &signer).await?
        };
        // print_hex(&response);
        socket.send_to(&response, src).await?;
    }
}

pub async fn handle_request(
    request: &[u8], src: SocketAddr,
    cache: &mut HashMap<String, CacheEntry>,
    stats: &stats::DnsStats,
    blocklist: &Blocklist,
    threat_detector: &mut ThreatDetector,
    signer: &DnssecSigner,
)-> Result<Vec<u8>, Box<dyn Error>> {
    evict_expired(cache);

    let packet = packet::DnsPacket::from_bytes(request);
    if packet.questions.is_empty() {
        return forward_to_upstream(request, "8.8.8.8:53").await;
    }

    let question = &packet.questions[0];
    let domain_name = question.name.clone();
    let domain_wire = dnssec::name_to_wire(&domain_name);

    if question.qtype == 48 {
        return Ok(signer.build_dnskey_answer(request, &domain_wire));
    }

    stats.record_domain(domain_name.clone());

    let threat_result = threat_detector.analyze(src.ip(), &domain_name);
    if threat_result.flagged {
        println!(
            "THREAT FLAGGED: {} score={} reasons={:?}",
            domain_name,
            threat_result.score,
            threat_result.reasons
        );
        log_threat(
            "flagged_queries.log",
            src,
            &domain_name,
            threat_result.score,
            &threat_result.reasons,
        )?;
    }

    //check if blocked here
    if blocklist.is_blocked(&domain_name) {
        println!("Blocked domain: {}", domain_name);
        //send NXDOMAIN to claim it doesn't exist instead of not returning
        return Ok (build_nxdomain_response(request));
    }

    let cache_key = format!("{}|{}|{}", question.name, question.qtype, question.qclass);

    if let Some(entry) = cache.get(&cache_key) {
        if Instant::now() < entry.expires_at {
            println!("cache hit: {}", cache_key);
            stats.cache_hits.fetch_add(1, Ordering::Relaxed);

            let mut cached_response = entry.response.clone();
            if request.len() >= 2 && cached_response.len() >= 2 {
                cached_response[0] = request[0];
                cached_response[1] = request[1];
            }
            return Ok(signer.sign_response(cached_response, &domain_wire));
        }
    }
    println!("cache miss: {}", cache_key);

    let start = Instant::now();
    let response = forward_to_upstream(request, "8.8.8.8:53").await?;
    let duration = start.elapsed().as_millis() as u64;

    stats.total_latency_ms.fetch_add(duration, Ordering::Relaxed);

    if let Some(ttl) = extract_min_ttl(&response) {
        if ttl > 0 {
            cache.insert(
                cache_key,
                CacheEntry {
                    response: response.clone(),
                    expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                },
            );
            println!("cached response for {} seconds", ttl);
        }
    }
    Ok(response)
}

fn evict_expired(cache: &mut HashMap<String, CacheEntry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
}

fn extract_min_ttl(response: &[u8]) -> Option<u32> {
    if response.len() < 12 {
        return None;
    }
    let packet = packet::DnsPacket::from_bytes(response);
    if packet.answers.is_empty() {
        return None;
    }
    packet.answers.iter().map(|r| r.ttl).min()
}

fn build_notimpl_response(request: &[u8]) -> Vec<u8> {
    if request.len() < 12 {
        return Vec::new();
    }

    let mut response = Vec::with_capacity(request.len());

    // transaction ID
    response.extend_from_slice(&request[0..2]);
    response.push(0x81);
    response.push(0x84);
    response.extend_from_slice(&request[4..6]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&request[12..]);
    response
}

//log helper to debug received requests
fn log_request(log_path: &str, src: SocketAddr, request: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().create(true).append(true).open(log_path)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    writeln!(file, "timestamp: {}", ts)?;
    writeln!(file, "source: {}", src)?;
    writeln!(file, "size: {}", request.len())?;
    writeln!(file, "hex: {}", to_hex(request))?;
    writeln!(file, "----")?;

    Ok(())
}

fn log_threat(
    log_path: &str,
    src: SocketAddr,
    domain: &str,
    score: u32,
    reasons: &[String],
) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().create(true).append(true).open(log_path)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    writeln!(file, "timestamp: {}", ts)?;
    writeln!(file, "source: {}", src)?;
    writeln!(file, "domain: {}", domain)?;
    writeln!(file, "threat_score: {}", score)?;
    writeln!(file, "reasons: {:?}", reasons)?;
    writeln!(file, "----")?;
    Ok(())
}

async fn forward_to_upstream(request: &[u8], upstream: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(request, upstream).await?;
    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await;
    match result {
        Ok(Ok((size, _))) => Ok(buf[..size].to_vec()),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => Err("Upstream connection timed out".into()),
    }
}

fn build_nxdomain_response(request: &[u8]) -> Vec<u8> {
    if request.len() < 12 {
        return Vec::new();
    }

    let mut response = request.to_vec();
    // QR=1 (response), Opcode=0 (std query), AA=0, TC=0, RD=1, RA=1, RCODE=3 (this sets NXDOMAIN)
    response[2] = 0x81; //QR + RD
    response[3] = 0x83; //RA + RCODE (3)

    //zero out the answer/authority/additional field counts, there is no answers
    response[6] = 0x00; response[7] = 0x00;
    response[8] = 0x00; response[9] = 0x00;
    response[10] = 0x00; response[11] = 0x00;

    response
}

//helpers
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_hex(bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n{:04x}: ", i);
        }
        print!("{:02x} ", b);
    }
    println!("\n");
}
