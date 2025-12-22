use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
pub struct BandwidthResult {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u32,
    pub throughput_mbps: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn bandwidth_test(target: &str, port: u16, proto: &str, duration_ms: u32) -> String {
    let duration = Duration::from_millis(duration_ms as u64);
    let address = format!("{}:{}", target, port);
    let start = Instant::now();
    let mut bytes_sent = 0u64;
    let mut bytes_received = 0u64;

    if proto == "udp" {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
                if socket.connect(&address).is_ok() {
                    let payload: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
                    while start.elapsed() < duration {
                        if socket.send(&payload).is_ok() {
                            bytes_sent += payload.len() as u64;
                        }
                        let mut buf = [0u8; 1024];
                        if socket.recv(&mut buf).is_ok() {
                            bytes_received += buf.len() as u64;
                        }
                    }
                }
            }
            Err(_) => {}
        }
    } else {
        // TCP
        match TcpStream::connect(&address) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(100))).ok();
                let payload: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
                while start.elapsed() < duration {
                    if stream.write_all(&payload).is_ok() {
                        bytes_sent += payload.len() as u64;
                    }
                    let mut buf = [0u8; 1024];
                    if stream.read(&mut buf).is_ok() {
                        bytes_received += buf.len() as u64;
                    }
                }
            }
            Err(_) => {}
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u32;
    let total_bytes = bytes_sent + bytes_received;
    let throughput_mbps = if elapsed_ms > 0 {
        (total_bytes as f64 * 8.0) / (elapsed_ms as f64 / 1000.0) / 1_000_000.0
    } else {
        0.0
    };

    let result = BandwidthResult {
        target: target.to_string(),
        port,
        protocol: proto.to_string(),
        bytes_sent,
        bytes_received,
        duration_ms: elapsed_ms,
        throughput_mbps,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

