use serde::{Deserialize, Serialize};
use serde_json;
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
pub struct PortCheckResult {
    pub port: u16,
    pub open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn check_port(target: &str, port: u16, proto: &str, timeout_ms: u32) -> String {
    let timeout = Duration::from_millis(timeout_ms as u64);
    let address = format!("{}:{}", target, port);

    let open = if proto == "udp" {
        // UDP is harder to check - we'll try to connect
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                socket.set_read_timeout(Some(timeout)).ok();
                socket.connect(&address).is_ok()
            }
            Err(_) => false,
        }
    } else {
        // TCP
        match TcpStream::connect_timeout(
            &address.parse().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
            timeout,
        ) {
            Ok(_) => true,
            Err(_) => false,
        }
    };

    let result = PortCheckResult {
        port,
        open,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

