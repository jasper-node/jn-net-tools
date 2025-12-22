use serde::{Deserialize, Serialize};
use serde_json;
use libc;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, Clone)]
pub struct HopStats {
    pub hop: i32,
    pub ip: String,
    pub sent: i32,
    pub received: i32,
    pub loss_percent: f64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub jitter_ms: f64,
}

#[derive(Serialize, Deserialize)]
pub struct MtrResult {
    pub target: String,
    pub hops: Vec<HopStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn create_icmp_echo_request(seq: u16, id: u16) -> Vec<u8> {
    const PAYLOAD_SIZE: usize = 32;
    let mut packet = vec![0u8; 8 + PAYLOAD_SIZE];
    packet[0] = 8; // ICMP Type: Echo Request
    packet[1] = 0; // ICMP Code: 0
    packet[2] = 0;
    packet[3] = 0;
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xFF) as u8;
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

pub fn mtr(target: &str, duration_ms: u32) -> String {
    let target_ip: Ipv4Addr = match crate::core::dns::resolve_v4(target) {
        Ok(ip) => ip,
        Err(e) => {
            let result = MtrResult {
                target: target.to_string(),
                hops: vec![],
                error: Some(e),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), 0);

    let duration = Duration::from_millis(duration_ms as u64);
    let stats: Arc<Mutex<HashMap<i32, HopStats>>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn thread for continuous probing
    let stats_clone = Arc::clone(&stats);
    let target_ip_clone = target_ip;
    let target_addr_clone = target_addr;
    let handle = thread::spawn(move || {
        // Create raw socket for ICMP
        let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
        #[cfg(target_os = "windows")]
        if sockfd == libc::INVALID_SOCKET {
            return;
        }
        #[cfg(not(target_os = "windows"))]
        if sockfd < 0 {
            return;
        }

        // Set socket timeout
        let timeout = Duration::from_millis(1000);
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
        if let std::net::SocketAddr::V4(addr) = target_addr_clone {
            sockaddr.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
        }
        sockaddr.sin_port = 0;

        let id = rand::random::<u16>();
        let start = Instant::now();
        let mut seq_counter = 0u16;
        let mut last_latencies: HashMap<i32, f64> = HashMap::new();

        while start.elapsed() < duration {
            for ttl in 1..=30 {
                if start.elapsed() >= duration {
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

                let probe_start = Instant::now();
                seq_counter = seq_counter.wrapping_add(1);
                let packet = create_icmp_echo_request(seq_counter, id);

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
                        if let Some((icmp_type, ip)) = parse_icmp_response(&buf[..recv_result as usize], id, seq_counter) {
                            let latency = probe_start.elapsed().as_millis() as f64;
                            
                            let mut stats_guard = stats_clone.lock().unwrap();
                            let hop_stat = stats_guard.entry(ttl).or_insert_with(|| HopStats {
                                hop: ttl,
                                ip: ip.to_string(),
                                sent: 0,
                                received: 0,
                                loss_percent: 0.0,
                                avg_latency_ms: 0.0,
                                min_latency_ms: f64::MAX,
                                max_latency_ms: 0.0,
                                jitter_ms: 0.0,
                            });

                            hop_stat.sent += 1;
                            hop_stat.received += 1;
                            
                            // Update IP if we got a response (might change)
                            if !ip.to_string().is_empty() {
                                hop_stat.ip = ip.to_string();
                            }

                            // Update latency statistics
                            hop_stat.avg_latency_ms = (hop_stat.avg_latency_ms * (hop_stat.received - 1) as f64 + latency) / hop_stat.received as f64;
                            hop_stat.min_latency_ms = hop_stat.min_latency_ms.min(latency);
                            hop_stat.max_latency_ms = hop_stat.max_latency_ms.max(latency);

                            // Calculate jitter (difference from last latency)
                            if let Some(last_lat) = last_latencies.get(&ttl) {
                                let jitter = (latency - last_lat).abs();
                                hop_stat.jitter_ms = (hop_stat.jitter_ms * (hop_stat.received - 1) as f64 + jitter) / hop_stat.received as f64;
                            }
                            last_latencies.insert(ttl, latency);

                            hop_stat.loss_percent = ((hop_stat.sent - hop_stat.received) as f64 / hop_stat.sent as f64) * 100.0;

                            // If we got an ECHO REPLY, we reached destination
                            if icmp_type == 0 && ip == target_ip_clone {
                                // Continue probing but mark that we reached destination
                            }
                        } else {
                            // No valid response
                            let mut stats_guard = stats_clone.lock().unwrap();
                            let hop_stat = stats_guard.entry(ttl).or_insert_with(|| HopStats {
                                hop: ttl,
                                ip: "*".to_string(),
                                sent: 0,
                                received: 0,
                                loss_percent: 0.0,
                                avg_latency_ms: 0.0,
                                min_latency_ms: f64::MAX,
                                max_latency_ms: 0.0,
                                jitter_ms: 0.0,
                            });
                            hop_stat.sent += 1;
                            hop_stat.loss_percent = ((hop_stat.sent - hop_stat.received) as f64 / hop_stat.sent as f64) * 100.0;
                        }
                    } else {
                        // Timeout - no response
                        let mut stats_guard = stats_clone.lock().unwrap();
                        let hop_stat = stats_guard.entry(ttl).or_insert_with(|| HopStats {
                            hop: ttl,
                            ip: "*".to_string(),
                            sent: 0,
                            received: 0,
                            loss_percent: 0.0,
                            avg_latency_ms: 0.0,
                            min_latency_ms: f64::MAX,
                            max_latency_ms: 0.0,
                            jitter_ms: 0.0,
                        });
                        hop_stat.sent += 1;
                        hop_stat.loss_percent = ((hop_stat.sent - hop_stat.received) as f64 / hop_stat.sent as f64) * 100.0;
                    }
                } else {
                    // Send failed
                    let mut stats_guard = stats_clone.lock().unwrap();
                    let hop_stat = stats_guard.entry(ttl).or_insert_with(|| HopStats {
                        hop: ttl,
                        ip: "*".to_string(),
                        sent: 0,
                        received: 0,
                        loss_percent: 0.0,
                        avg_latency_ms: 0.0,
                        min_latency_ms: f64::MAX,
                        max_latency_ms: 0.0,
                        jitter_ms: 0.0,
                    });
                    hop_stat.sent += 1;
                    hop_stat.loss_percent = ((hop_stat.sent - hop_stat.received) as f64 / hop_stat.sent as f64) * 100.0;
                }
            }

            // Small delay between cycles
            thread::sleep(Duration::from_millis(100));
        }

        unsafe {
            #[cfg(target_os = "windows")]
            libc::closesocket(sockfd);
            #[cfg(not(target_os = "windows"))]
            libc::close(sockfd);
        }
    });

    handle.join().ok();

    let stats_guard = stats.lock().unwrap();
    let mut hops: Vec<HopStats> = stats_guard.values().cloned().collect();
    hops.sort_by_key(|h| h.hop);

    // Fix min_latency_ms if it's still MAX (no responses)
    for hop in &mut hops {
        if hop.min_latency_ms == f64::MAX {
            hop.min_latency_ms = 0.0;
        }
    }

    let result = MtrResult {
        target: target.to_string(),
        hops,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

