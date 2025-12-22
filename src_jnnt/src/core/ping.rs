use serde::{Deserialize, Serialize};
use serde_json;
use libc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
pub struct PingPacketResult {
    pub seq: u16,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
}

#[derive(Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub alive: bool,
    pub loss_percent: f64,
    pub avg_rtt_ms: f64,
    pub packets: Vec<PingPacketResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn create_icmp_echo_request(seq: u16, id: u16) -> Vec<u8> {
    const PAYLOAD_SIZE: usize = 56;
    let mut packet = vec![0u8; 8 + PAYLOAD_SIZE];
    // ICMP Type: Echo Request (8)
    packet[0] = 8;
    // ICMP Code: 0
    packet[1] = 0;
    // Checksum (will be calculated)
    packet[2] = 0;
    packet[3] = 0;
    // Identifier
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xFF) as u8;
    // Sequence number
    packet[6] = (seq >> 8) as u8;
    packet[7] = (seq & 0xFF) as u8;

    // Fill payload
    for i in 0..PAYLOAD_SIZE {
        packet[8 + i] = (i % 256) as u8;
    }

    // Calculate checksum
    let mut sum: u32 = 0;
    for i in (0..packet.len()).step_by(2) {
        let mut word = (packet[i] as u32) << 8;
        if i + 1 < packet.len() {
            word |= packet[i + 1] as u32;
        }
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xFF) as u8;

    packet
}


fn parse_icmp_echo_reply(buf: &[u8], expected_id: u16, expected_seq: u16) -> bool {
    // Need at least IP header (20 bytes) + ICMP header (8 bytes)
    if buf.len() < 28 {
        return false;
    }
    
    // IP header length is in the first 4 bits of the first byte (in 32-bit words)
    let ip_header_len = (buf[0] & 0x0F) as usize * 4;
    if buf.len() < ip_header_len + 8 {
        return false;
    }
    
    // ICMP header starts after IP header
    let icmp_type = buf[ip_header_len];
    let icmp_code = buf[ip_header_len + 1];

    // Must be Echo Reply (type 0, code 0)
    if icmp_type != 0 || icmp_code != 0 {
        return false;
    }
    
    // Extract ID and sequence number from ICMP header
    // ID is at offset +4, +5
    let id = ((buf[ip_header_len + 4] as u16) << 8) | (buf[ip_header_len + 5] as u16);
    // Sequence is at offset +6, +7
    let seq = ((buf[ip_header_len + 6] as u16) << 8) | (buf[ip_header_len + 7] as u16);
    
    // Must match our expected ID and sequence
    id == expected_id && seq == expected_seq
}

pub fn ping(target: &str, count: u32, timeout_ms: u32) -> String {

    let target_ip: std::net::Ipv4Addr = match crate::core::dns::resolve_v4(target) {
        Ok(ip) => ip,
        Err(e) => {
            return serde_json::to_string(&PingResult {
                target: target.to_string(),
                alive: false,
                loss_percent: 100.0,
                avg_rtt_ms: 0.0,
                packets: Vec::new(),
                error: Some(format!("Invalid target address: {}", e)),
            }).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), 0);
    let timeout = Duration::from_millis(timeout_ms as u64);
    
    // Create raw socket for ICMP using libc
    // Note: Raw sockets require root/admin privileges
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if sockfd < 0 {
        return serde_json::to_string(&PingResult {
            target: target.to_string(),
            alive: false,
            loss_percent: 100.0,
            avg_rtt_ms: 0.0,
            packets: Vec::new(),
            error: Some("Failed to create socket (root privileges required?)".to_string()),
        }).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }
    
    // Set standard TTL to 64
    let ttl: libc::c_int = 64;
    unsafe {
        libc::setsockopt(
            sockfd,
            libc::IPPROTO_IP,
            libc::IP_TTL,
            &ttl as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    
    // Set socket timeout
    let timeout_tv = libc::timeval {
        tv_sec: timeout.as_secs() as i64,
        tv_usec: timeout.subsec_micros() as i32,
    };
    unsafe {
        libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout_tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut rtts = Vec::new();
    let mut packets = Vec::new();
    let mut received = 0;
    let id = rand::random::<u16>();

    for seq in 0..count {
        let seq_u16 = seq as u16;
        let start = Instant::now();
        let packet = create_icmp_echo_request(seq_u16, id);

        // Send packet using libc
        let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sockaddr.sin_family = libc::AF_INET as u8;
        if let std::net::SocketAddr::V4(addr) = target_addr {
            sockaddr.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
        }
        sockaddr.sin_port = 0;

        let send_result = unsafe {
            libc::sendto(
                sockfd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if send_result > 0 {
            // Try to receive reply - keep trying until timeout or we get our packet
            let mut buf = [0u8; 1024];
            let mut got_response = false;
            
            // Keep receiving until timeout or we get a matching response
            while start.elapsed() < timeout && !got_response {
                let recv_result = unsafe {
                    libc::recvfrom(
                        sockfd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if recv_result > 0 {
                    // Validate that this is our ICMP Echo Reply
                    if parse_icmp_echo_reply(&buf[..recv_result as usize], id, seq_u16) {
                        let rtt = start.elapsed().as_millis() as f64;
                        rtts.push(rtt);
                        received += 1;
                        got_response = true;
                        
                        packets.push(PingPacketResult {
                            seq: seq_u16,
                            status: "OK".to_string(),
                            rtt_ms: Some(rtt),
                        });
                    }
                } else {
                    // recvfrom failed (likely timeout), break out
                    break;
                }
            }
            
            if !got_response {
                packets.push(PingPacketResult {
                    seq: seq_u16,
                    status: "Timeout".to_string(),
                    rtt_ms: None,
                });
            }
        } else {
            packets.push(PingPacketResult {
                seq: seq_u16,
                status: "SendFailed".to_string(),
                rtt_ms: None,
            });
        }
        
        // Add a small delay between pings (e.g. 200ms) to avoid flooding and allow for responses
        if seq < count - 1 {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    unsafe {
        libc::close(sockfd);
    }

    let alive = received > 0;
    let loss_percent = if count > 0 {
        ((count - received) as f64 / count as f64) * 100.0
    } else {
        100.0
    };
    let avg_rtt_ms = if !rtts.is_empty() {
        rtts.iter().sum::<f64>() / rtts.len() as f64
    } else {
        0.0
    };

    let result = PingResult {
        target: target.to_string(),
        alive,
        loss_percent,
        avg_rtt_ms,
        packets,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}
