mod packet; //dns packet file

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::time::*;
use std::collections::HashMap;

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}


fn main() -> Result<(), Box<dyn Error>> {
    run_udp_listener("0.0.0.0:2053", "dns_requests.log")
}

fn run_udp_listener(bind_addr: &str, log: &str) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(bind_addr)?;
    println!("UDP listener running on {}", bind_addr);

    let mut buf = [0u8; 512];
    let mut cache: HashMap<String, CacheEntry> = HashMap::new();

    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        let request = &buf[..size];

        log_request(log,src, request)?;
        println!("\nreceived {} bytes from {}", size, src);
        print_hex(request);

        let response = handle_request(request, src, &mut cache)?;
        socket.send_to(&response, src)?;
    }
}

fn handle_request(
    request: &[u8], _src: SocketAddr,
    cache: &mut HashMap<String, CacheEntry>,
)-> Result<Vec<u8>, Box<dyn Error>> {
    evict_expired(cache);

    let packet = packet::DnsPacket::from_bytes(request);
    if packet.questions.is_empty() {
        return Ok(forward_to_upstream(request, "8.8.8.8:53")?);
    }
    let question = &packet.questions[0];
    let cache_key = format!("{}|{}|{}", question.name, question.qtype, question.qclass);

    if let Some(entry) = cache.get(&cache_key) {
        if Instant::now() < entry.expires_at {
            println!("cache hit: {}", cache_key);

            let mut cached_response = entry.response.clone();
            if request.len() >= 2 && cached_response.len() >= 2{
                cached_response[0] = request[0];
                cached_response[1] = request[1];
            }
            return Ok(entry.response.clone());
        }
    }
    println!("cache miss: {}", cache_key);
    let response = forward_to_upstream(request, "8.8.8.8:53")?;

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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
#[allow(dead_code)]
fn forward_to_upstream(request: &[u8], upstream: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.send_to(request, upstream)?;

    let mut buf = [0u8; 512];
    let (size, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..size].to_vec())
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