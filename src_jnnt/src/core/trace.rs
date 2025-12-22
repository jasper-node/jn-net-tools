use serde::{Deserialize, Serialize};
use serde_json;
use libc;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
pub struct ProbeResult {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub latency_ms: f64,
}

#[derive(Serialize, Deserialize)]
pub struct Hop {
    pub hop: i32,
    pub probes: Vec<ProbeResult>,
}

#[derive(Serialize, Deserialize)]
pub struct TraceRouteResult {
    pub target: String,
    pub hops: Vec<Hop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn create_icmp_echo_request(seq: u16, id: u16) -> Vec<u8> {
    const PAYLOAD_SIZE: usize = 32;
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

fn extract_ip_from_ip_header(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 20 {
        return None;
    }
    // IP header is at least 20 bytes
    // Source IP is at offset 12-15
    let ip_bytes = [buf[12], buf[13], buf[14], buf[15]];
    Some(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
}

fn parse_icmp_response(buf: &[u8], expected_id: u16, expected_seq: u16) -> Option<(u8, Ipv4Addr)> {
    if buf.len() < 28 {
        return None;
    }
    
    // IP header is 20 bytes (minimum)
    let ip_header_len = (buf[0] & 0x0F) as usize * 4;
    // Need IP header + 8 bytes of ICMP header
    if buf.len() < ip_header_len + 8 {
        return None;
    }
    
    // Extract source IP from IP header (this is the router that replied)
    let src_ip = extract_ip_from_ip_header(buf)?;
    
    // ICMP header starts after IP header
    let icmp_type = buf[ip_header_len];
    let _icmp_code = buf[ip_header_len + 1];
    
    // For ICMP_TIME_EXCEEDED (11) or ICMP_ECHOREPLY (0)
    if icmp_type == 11 || icmp_type == 0 {
        // For ECHOREPLY, check if it matches our request
        if icmp_type == 0 {
            // Check if this is our echo reply
            // ID at +4, Seq at +6 relative to ICMP header
            let embedded_id = ((buf[ip_header_len + 4] as u16) << 8) | (buf[ip_header_len + 5] as u16);
            let embedded_seq = ((buf[ip_header_len + 6] as u16) << 8) | (buf[ip_header_len + 7] as u16);
            if embedded_id == expected_id && embedded_seq == expected_seq {
                return Some((icmp_type, src_ip));
            }
        } else {
            // TIME_EXCEEDED (11)
            // The original packet is embedded after the ICMP header (8 bytes)
            // Format: [Outer IP] [Outer ICMP (8 bytes)] [Inner IP] [Inner ICMP (8 bytes)...]
            
            let inner_ip_offset = ip_header_len + 8;
            if buf.len() < inner_ip_offset + 20 {
                 return None;
            }
            
            // Inner IP header length
            let inner_ip_header_len = (buf[inner_ip_offset] & 0x0F) as usize * 4;
            let inner_icmp_offset = inner_ip_offset + inner_ip_header_len;
            
            // Need at least 8 bytes of Inner ICMP header to check ID/Seq
            if buf.len() < inner_icmp_offset + 8 {
                return None;
            }
            
            // Check Inner ICMP type, should be 8 (Echo Request)
            let inner_icmp_type = buf[inner_icmp_offset];
            if inner_icmp_type != 8 {
                return None;
            }
            
            // Check Inner ID and Seq
            // ID at +4, Seq at +6 relative to Inner ICMP header
            let inner_id = ((buf[inner_icmp_offset + 4] as u16) << 8) | (buf[inner_icmp_offset + 5] as u16);
            let inner_seq = ((buf[inner_icmp_offset + 6] as u16) << 8) | (buf[inner_icmp_offset + 7] as u16);
            
            if inner_id == expected_id && inner_seq == expected_seq {
                return Some((icmp_type, src_ip));
            }
        }
    }
    
    None
}

pub fn trace_route(target: &str, max_hops: i32, timeout_ms: u32) -> String {
    let target_ip: Ipv4Addr = match crate::core::dns::resolve_v4(target) {
        Ok(ip) => ip,
        Err(e) => {
            let result = TraceRouteResult {
                target: target.to_string(),
                hops: vec![],
                error: Some(e),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let timeout = Duration::from_millis(timeout_ms as u64);
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), 0);

    // Create raw socket for ICMP
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    #[cfg(target_os = "windows")]
    if sockfd == libc::INVALID_SOCKET {
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to create raw socket (may need root privileges)".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }
    #[cfg(not(target_os = "windows"))]
    if sockfd < 0 {
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to create raw socket (may need root privileges)".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }

    // Set socket timeout
    #[cfg(target_os = "windows")]
    let timeout_val: u32 = timeout.as_millis() as u32;
    #[cfg(not(target_os = "windows"))]
    let timeout_tv = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    unsafe {
        #[cfg(target_os = "windows")]
        libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout_val as *const _ as *const i8,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
        #[cfg(not(target_os = "windows"))]
        libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout_tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sockaddr.sin_family = libc::AF_INET as _;
    if let std::net::SocketAddr::V4(addr) = target_addr {
        sockaddr.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
    }
    sockaddr.sin_port = 0;

    let mut hops = Vec::new();
    const PROBES_PER_HOP: i32 = 3;
    let id = rand::random::<u16>();
    let mut reached_destination = false;

    for ttl in 1..=max_hops {
        if reached_destination {
            break;
        }

        // Set TTL for this hop
        let ttl_val = ttl as i32;
        unsafe {
            #[cfg(target_os = "windows")]
            libc::setsockopt(
                sockfd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl_val as *const _ as *const i8,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            #[cfg(not(target_os = "windows"))]
            libc::setsockopt(
                sockfd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &ttl_val as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }

        let mut probes = Vec::new();

        for probe_num in 0..PROBES_PER_HOP {
            let start = Instant::now();
            let seq = (ttl * PROBES_PER_HOP + probe_num) as u16;
            let packet = create_icmp_echo_request(seq, id);

            // Send packet
            let send_result = unsafe {
                #[cfg(target_os = "windows")]
                {
                    libc::sendto(
                        sockfd,
                        packet.as_ptr() as *const i8,
                        packet.len() as i32,
                        0,
                        &sockaddr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
                #[cfg(not(target_os = "windows"))]
                {
                    libc::sendto(
                        sockfd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &sockaddr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
            };

            if send_result > 0 {
                // Try to receive reply
                let mut buf = [0u8; 1024];
                let recv_result = unsafe {
                    #[cfg(target_os = "windows")]
                    {
                        libc::recvfrom(
                            sockfd,
                            buf.as_mut_ptr() as *mut i8,
                            buf.len() as i32,
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        libc::recvfrom(
                            sockfd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        )
                    }
                };

                if recv_result > 0 {
                    let elapsed = start.elapsed();
                    if elapsed < timeout {
                        if let Some((icmp_type, ip)) = parse_icmp_response(&buf[..recv_result as usize], id, seq) {
                            let rtt = elapsed.as_millis() as f64;
                            probes.push(ProbeResult {
                                ip: ip.to_string(),
                                hostname: None,
                                latency_ms: rtt,
                            });

                            // If we got an ECHO REPLY (type 0), we reached the destination
                            if icmp_type == 0 && ip == target_ip {
                                reached_destination = true;
                            }
                        }
                    }
                }
            }

            // If no response, add timeout probe
            if probes.len() == probe_num as usize {
                probes.push(ProbeResult {
                    ip: "*".to_string(),
                    hostname: None,
                    latency_ms: 0.0,
                });
            }
        }

        hops.push(Hop {
            hop: ttl,
            probes,
        });

        // Small delay between hops
        std::thread::sleep(Duration::from_millis(10));
    }

    unsafe {
        #[cfg(target_os = "windows")]
        libc::closesocket(sockfd);
        #[cfg(not(target_os = "windows"))]
        libc::close(sockfd);
    }

    let result = TraceRouteResult {
        target: target.to_string(),
        hops,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

