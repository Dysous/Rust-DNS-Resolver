mod packet;
mod stats;
mod blocklist;
//dns packet file

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, };
// use std::net::{SocketAddr, UdpSocket};
use std::time::*;
use std::collections::HashMap;

use std::sync::Arc;
use std::sync::atomic::{ Ordering};
use tokio::net::UdpSocket;
use axum::{extract::State, routing::get, Router, Json};
use tower_http::services::{ServeDir, ServeFile};
use crate::blocklist::Blocklist;

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    //website stats/domain
    let shared_stats = Arc::new(stats::DnsStats::new());
    let domain = "group8-monitor";
    let token = "960d0d55-e9ce-4846-83c9-188350fde697";
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let url = format!("http://www.duckdns.org/update?domains={}&token={}", domain, token);

        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {//update duckdns binding loop
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

    let blocklist = Arc::new(blocklist::Blocklist::load("hosts.txt"));
    let dns_stats = Arc::clone(&shared_stats);
    let dns_blocklist = Arc::clone(&blocklist);


    tokio::spawn(async move {
        if let Err(e) = run_udp_listener("0.0.0.0:53", "dns_requests.log", dns_stats, dns_blocklist).await {
            eprintln!("Error: {}", e);
        }
    });

    //website routing
    let web_stats = Arc::clone(&shared_stats);
    let static_dir = "static";
    let index_file = "static/index.html";
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
        .fallback_service(ServeDir::new(static_dir));

    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    println!("Web Monitor Live At http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())

}

async fn run_udp_listener(bind_addr: &str, log: &str, stats: Arc<stats::DnsStats>, blocklist: Arc<Blocklist>) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    println!("UDP listener running on {}", bind_addr);

    let mut buf = [0u8; 512];
    let mut cache: HashMap<String, CacheEntry> = HashMap::new();

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let request = &buf[..size];

        log_request(log,src, request)?;
        println!("\nreceived {} bytes from {}", size, src);
        print_hex(request);

        stats.total_queries.fetch_add(1, Ordering::Relaxed);
        let response = handle_request(request, src, &mut cache, &stats, &blocklist).await?;
        socket.send_to(&response, src).await?;
    }
}

async fn handle_request(
    request: &[u8], _src: SocketAddr,
    cache: &mut HashMap<String, CacheEntry>,
    stats: &stats::DnsStats,
    blocklist: &blocklist::Blocklist
)-> Result<Vec<u8>, Box<dyn Error>> {
    evict_expired(cache);

    let packet = packet::DnsPacket::from_bytes(request);
    if packet.questions.is_empty() {
        return forward_to_upstream(request, "8.8.8.8:53").await;
    }

    let question = &packet.questions[0];
    let domain_name = question.name.clone();
    stats.record_domain(domain_name.clone());

    //check if blocked here
    if blocklist.is_blocked(&domain_name) {
        println!("Blocked domain: {}", domain_name);
        //send NXDOMAIN to claim it doesn't exist instead of not returning
        return Ok (build_notimpl_response(request));
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
            return Ok(cached_response);
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
fn log_request(log_path: &str, src: std::net::SocketAddr, request: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().create(true).append(true).open(log_path)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    writeln!(file, "timestamp: {}", ts)?;
    writeln!(file, "source: {}", src)?;
    writeln!(file, "size: {}", request.len())?;
    writeln!(file, "hex: {}", to_hex(request))?;
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
