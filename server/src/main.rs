use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::time::*;

fn main() -> Result<(), Box<dyn Error>> {
    run_udp_listener("0.0.0.0:2053", "dns_requests.log")
}

fn run_udp_listener(bind_addr: &str, log: &str) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(bind_addr)?;
    println!("UDP listener running on {}", bind_addr);

    let mut buf = [0u8; 512];

    loop {
        let (size, src) = socket.recv_from(&mut buf)?;
        let request = &buf[..size];

        log_request(log,src, request)?;
        println!("\nreceived {} bytes from {}", size, src);
        print_hex(request);

        let response = handle_request(request, src);
        socket.send_to(&response, src)?;
    }
}

fn handle_request(request: &[u8], _src: SocketAddr) -> Vec<u8> {
    build_notimpl_response(request)
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