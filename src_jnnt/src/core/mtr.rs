use serde::{Deserialize, Serialize};
use serde_json;
#[cfg(not(target_os = "windows"))]
use libc;
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(not(target_os = "windows"))]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

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

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
fn extract_ip_from_ip_header(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 20 {
        return None;
    }
    let ip_bytes = [buf[12], buf[13], buf[14], buf[15]];
    Some(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(target_os = "windows")]
pub fn mtr(target: &str, duration_ms: u32) -> String {
    mtr_windows(target, duration_ms)
}

#[cfg(not(target_os = "windows"))]
pub fn mtr(target: &str, duration_ms: u32) -> String {
    mtr_unix(target, duration_ms)
}

#[cfg(target_os = "windows")]
fn mtr_windows(target: &str, duration_ms: u32) -> String {
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

    let duration = Duration::from_millis(duration_ms as u64);
    let stats: Arc<Mutex<HashMap<i32, HopStats>>> = Arc::new(Mutex::new(HashMap::new()));

    // Spawn thread for continuous probing
    let stats_clone = Arc::clone(&stats);
    let target_ip_clone = target_ip;

    let handle = thread::spawn(move || {
        // Create ICMP handle
        let icmp_handle = unsafe { iphlp::IcmpCreateFile() };
        if icmp_handle == 0 || icmp_handle == -1isize {
            return;
        }

        let start = Instant::now();
        let mut last_latencies: HashMap<i32, f64> = HashMap::new();

        // Prepare send data and reply buffer
        let send_data = vec![0u8; 32];
        let reply_size = std::mem::size_of::<iphlp::ICMP_ECHO_REPLY>() + send_data.len() + 8;
        let mut reply_buffer = vec![0u8; reply_size];

        let dest_addr = u32::from_ne_bytes(target_ip_clone.octets());
        let timeout_ms = 1000u32;

        let mut max_ttl_reached = 1i32;

        while start.elapsed() < duration {
            for ttl in 1i32..=max_ttl_reached.min(30) {
                if start.elapsed() >= duration {
                    break;
                }

                let probe_start = Instant::now();

                // Set IP options with TTL
                let mut ip_options = iphlp::IP_OPTION_INFORMATION {
                    Ttl: ttl as u8,
                    Tos: 0,
                    Flags: 0,
                    OptionsSize: 0,
                    OptionsData: std::ptr::null_mut(),
                };

                let result = unsafe {
                    iphlp::IcmpSendEcho(
                        icmp_handle,
                        dest_addr,
                        send_data.as_ptr() as *const _,
                        send_data.len() as u16,
                        &mut ip_options,
                        reply_buffer.as_mut_ptr() as *mut _,
                        reply_size as u32,
                        timeout_ms,
                    )
                };

                let mut stats_guard = stats_clone.lock().unwrap();
                let hop_stat = stats_guard.entry(ttl).or_insert_with(|| HopStats {
                    hop: ttl,
                    ip: "*".to_string(),
                    sent: 0,
                    received: 0,
                    loss_percent: 0.0,
                    avg_latency_ms: 0.0,
                    min_latency_ms: 0.0,
                    max_latency_ms: 0.0,
                    jitter_ms: 0.0,
                });

                hop_stat.sent += 1;

                if result > 0 {
                    let reply = unsafe { &*(reply_buffer.as_ptr() as *const iphlp::ICMP_ECHO_REPLY) };
                    let reply_addr = Ipv4Addr::from(reply.Address.to_ne_bytes());
                    let status = reply.Status;

                    // Status 0 = Success (reached destination)
                    // Status 11010 (0x2B02) = TTL expired (TIME_EXCEEDED)
                    if status == 0 || status == 11010 {
                        let latency = probe_start.elapsed().as_millis() as f64;
                        
                        hop_stat.ip = reply_addr.to_string();
                        hop_stat.received += 1;

                        // Update latency stats
                        if hop_stat.min_latency_ms == 0.0 || latency < hop_stat.min_latency_ms {
                            hop_stat.min_latency_ms = latency;
                        }
                        if latency > hop_stat.max_latency_ms {
                            hop_stat.max_latency_ms = latency;
                        }

                        // Calculate jitter
                        if let Some(&last_latency) = last_latencies.get(&ttl) {
                            let jitter = (latency - last_latency).abs();
                            hop_stat.jitter_ms = (hop_stat.jitter_ms + jitter) / 2.0;
                        }
                        last_latencies.insert(ttl, latency);

                        // Update average
                        let total_latency = hop_stat.avg_latency_ms * (hop_stat.received - 1) as f64 + latency;
                        hop_stat.avg_latency_ms = total_latency / hop_stat.received as f64;

                        // If we reached destination, update max_ttl_reached
                        if status == 0 && reply_addr == target_ip_clone && ttl > max_ttl_reached {
                            max_ttl_reached = ttl;
                        }
                    }
                }

                // Update loss percentage
                hop_stat.loss_percent = ((hop_stat.sent - hop_stat.received) as f64 / hop_stat.sent as f64) * 100.0;

                drop(stats_guard);

                // Small delay between probes
                thread::sleep(Duration::from_millis(10));
            }

            // Increment max_ttl if we haven't found the destination yet
            if max_ttl_reached < 30 {
                max_ttl_reached += 1;
            }
        }

        unsafe {
            iphlp::IcmpCloseHandle(icmp_handle);
        }
    });

    handle.join().unwrap();

    // Collect results
    let stats_guard = stats.lock().unwrap();
    let mut hops: Vec<HopStats> = stats_guard.values().cloned().collect();
    hops.sort_by_key(|h| h.hop);

    let result = MtrResult {
        target: target.to_string(),
        hops,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

#[cfg(not(target_os = "windows"))]
fn mtr_unix(target: &str, duration_ms: u32) -> String {
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

        if sockfd < 0 {
            return;
        }

        // Set socket timeout
        let timeout = Duration::from_millis(1000);
        let timeout_tv = libc::timeval {
            tv_sec: timeout.as_secs() as _,
            tv_usec: timeout.subsec_micros() as _,
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
                let send_res = unsafe {
                    libc::sendto(
                        sockfd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                        0,
                        &sockaddr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    ) as i32
                };

                if send_res > 0 {
                    // Try to receive reply
                    let mut buf = [0u8; 1024];
                    let n = unsafe {
                        libc::recvfrom(
                            sockfd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        ) as i32
                    };

                    if n > 0 {
                        if let Some((icmp_type, ip)) = parse_icmp_response(&buf[..n as usize], id, seq_counter) {
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

