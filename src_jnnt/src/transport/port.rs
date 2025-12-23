use serde::{Deserialize, Serialize};
use serde_json;
use std::net::{TcpStream, UdpSocket, ToSocketAddrs};
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
        // Resolve DNS first
        let addr = match address.to_socket_addrs() {
            Ok(mut addrs) => addrs.next(),
            Err(_) => None,
        };

        match addr {
            Some(socket_addr) => match TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(_) => true,
                Err(_) => false,
            },
            None => false,
        }
    };

    let result = PortCheckResult {
        port,
        open,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

