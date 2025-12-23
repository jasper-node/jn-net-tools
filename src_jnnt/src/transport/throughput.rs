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
    let mut error_msg: Option<String> = None;

    if proto == "udp" {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                // Set non-blocking mode
                socket.set_nonblocking(true).ok();
                
                if socket.connect(&address).is_ok() {
                    let payload: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
                    while start.elapsed() < duration {
                        let mut did_work = false;
                        
                        // Try to send
                        match socket.send(&payload) {
                            Ok(n) => {
                                bytes_sent += n as u64;
                                did_work = true;
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                                           e.kind() == std::io::ErrorKind::Interrupted => {
                                // Buffer full or interrupted, skip
                            }
                            Err(_) => {} // Other errors, continue (UDP is connectionless)
                        }
                        
                        // Try to receive
                        let mut buf = [0u8; 1024];
                        match socket.recv(&mut buf) {
                            Ok(n) => {
                                bytes_received += n as u64;
                                did_work = true;
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                                           e.kind() == std::io::ErrorKind::Interrupted => {
                                // No data or interrupted, skip
                            }
                            Err(_) => {} // Other errors, continue
                        }
                        
                        if !did_work {
                            std::thread::yield_now();
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
                // Set non-blocking mode
                stream.set_nonblocking(true).ok();
                stream.set_nodelay(true).ok();
                
                let payload: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
                let mut consecutive_eof = 0;
                let mut conn_active = true;
                
                while start.elapsed() < duration && conn_active {
                    let mut did_work = false;

                    // Try to write
                    match stream.write(&payload) {
                        Ok(n) => {
                            bytes_sent += n as u64;
                            did_work = true;
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                                       e.kind() == std::io::ErrorKind::Interrupted => {
                            // Write buffer full, try again later
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe || 
                                       e.kind() == std::io::ErrorKind::ConnectionReset ||
                                       e.kind() == std::io::ErrorKind::ConnectionAborted => {
                            // Connection died
                            conn_active = false;
                            // Don't set error_msg here as it might be expected for some servers
                        },
                        Err(_) => {
                            // Other errors - treat as fatal for the connection
                            conn_active = false;
                        }
                    }
                    
                    if !conn_active { break; }

                    // Try to read
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            // EOF - connection closed by peer
                            consecutive_eof += 1;
                            if consecutive_eof > 20 {
                                // Peer closed connection persistently
                                conn_active = false;
                            }
                        },
                        Ok(n) => {
                            consecutive_eof = 0;
                            if n > 0 {
                                bytes_received += n as u64;
                                did_work = true;
                            }
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || 
                                       e.kind() == std::io::ErrorKind::Interrupted => {
                            consecutive_eof = 0;
                        },
                        Err(ref e) if e.kind() == std::io::ErrorKind::BrokenPipe || 
                                       e.kind() == std::io::ErrorKind::ConnectionReset ||
                                       e.kind() == std::io::ErrorKind::ConnectionAborted => {
                            conn_active = false;
                        },
                        Err(_) => {
                            conn_active = false;
                        },
                    }
                    
                    if !did_work && conn_active {
                        std::thread::yield_now();
                    }
                }
            }
            Err(e) => {
                error_msg = Some(format!("Connection failed: {}", e));
            }
        }
    }

    let elapsed_ms = start.elapsed().as_millis() as u32;
    // Prevent division by zero if duration is extremely small
    let effective_duration_ms = if elapsed_ms == 0 { 1 } else { elapsed_ms };
    
    let total_bytes = bytes_sent + bytes_received;
    let throughput_mbps = (total_bytes as f64 * 8.0) / (effective_duration_ms as f64 / 1000.0) / 1_000_000.0;

    let result = BandwidthResult {
        target: target.to_string(),
        port,
        protocol: proto.to_string(),
        bytes_sent,
        bytes_received,
        duration_ms: effective_duration_ms,
        throughput_mbps,
        error: error_msg,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}
