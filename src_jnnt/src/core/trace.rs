use serde::{Deserialize, Serialize};
use serde_json;
#[cfg(not(target_os = "windows"))]
use libc;
use std::net::Ipv4Addr;
#[cfg(not(target_os = "windows"))]
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

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
    pub     error: Option<String>,
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
fn extract_ip_from_ip_header(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 20 {
        return None;
    }
    // IP header is at least 20 bytes
    // Source IP is at offset 12-15
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
pub fn trace_route(target: &str, max_hops: i32, timeout_ms: u32) -> String {
    trace_route_windows(target, max_hops, timeout_ms)
}

#[cfg(not(target_os = "windows"))]
pub fn trace_route(target: &str, max_hops: i32, timeout_ms: u32) -> String {
    trace_route_unix(target, max_hops, timeout_ms)
}

#[cfg(target_os = "windows")]
fn trace_route_windows(target: &str, max_hops: i32, timeout_ms: u32) -> String {
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

    // Create ICMP handle
    let icmp_handle = unsafe { iphlp::IcmpCreateFile() };
    if icmp_handle == 0 || icmp_handle == -1isize {
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to create ICMP handle".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }

    let mut hops = Vec::new();
    const PROBES_PER_HOP: i32 = 3;
    let mut reached_destination = false;

    // Prepare send data
    let send_data = vec![0u8; 32];
    let reply_size = std::mem::size_of::<iphlp::ICMP_ECHO_REPLY>() + send_data.len() + 8;
    let mut reply_buffer = vec![0u8; reply_size];

    for ttl in 1..=max_hops {
        if reached_destination {
            break;
        }

        let mut probes = Vec::new();

        for _probe_num in 0..PROBES_PER_HOP {
            let start = Instant::now();

            // Set IP options with TTL
            let mut ip_options = iphlp::IP_OPTION_INFORMATION {
                Ttl: ttl as u8,
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: std::ptr::null_mut(),
            };

            let dest_addr = u32::from_ne_bytes(target_ip.octets());

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

            let elapsed = start.elapsed();

            if result > 0 {
                let reply = unsafe { &*(reply_buffer.as_ptr() as *const iphlp::ICMP_ECHO_REPLY) };
                let reply_addr = Ipv4Addr::from(reply.Address.to_ne_bytes());
                let status = reply.Status;

                // Status 0 = Success (reached destination)
                // Status 11010 (0x2B02) = TTL expired (TIME_EXCEEDED)
                if status == 0 || status == 11010 {
                    probes.push(ProbeResult {
                        ip: reply_addr.to_string(),
                        hostname: None,
                        latency_ms: elapsed.as_millis() as f64,
                    });

                    if status == 0 && reply_addr == target_ip {
                        reached_destination = true;
                    }
                } else {
                    probes.push(ProbeResult {
                        ip: "*".to_string(),
                        hostname: None,
                        latency_ms: 0.0,
                    });
                }
            } else {
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

        std::thread::sleep(Duration::from_millis(10));
    }

    unsafe {
        iphlp::IcmpCloseHandle(icmp_handle);
    }

    let result = TraceRouteResult {
        target: target.to_string(),
        hops,
        error: None,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

#[cfg(not(target_os = "windows"))]
fn trace_route_unix(target: &str, max_hops: i32, timeout_ms: u32) -> String {
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
    #[cfg(target_os = "windows")]
    let sockfd = unsafe { winsock::socket(winsock::AF_INET as i32, winsock::SOCK_RAW as i32, winsock::IPPROTO_ICMP as i32) };
    #[cfg(not(target_os = "windows"))]
    let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };

    #[cfg(target_os = "windows")]
    if sockfd == winsock::INVALID_SOCKET {
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

    // Bind socket to INADDR_ANY to receive ICMP messages (especially needed on Windows)
    #[cfg(target_os = "windows")]
    let mut bind_addr: winsock::SOCKADDR_IN = unsafe { std::mem::zeroed() };
    #[cfg(not(target_os = "windows"))]
    let mut bind_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "windows")]
    {
        bind_addr.sin_family = winsock::AF_INET as _;
        bind_addr.sin_addr.S_un.S_addr = 0; // INADDR_ANY
        bind_addr.sin_port = 0;
    }
    #[cfg(not(target_os = "windows"))]
    {
        bind_addr.sin_family = libc::AF_INET as _;
        bind_addr.sin_addr.s_addr = libc::INADDR_ANY;
        bind_addr.sin_port = 0;
    }

    let bind_result = unsafe {
        #[cfg(target_os = "windows")]
        {
            winsock::bind(
                sockfd as _,
                &bind_addr as *const _ as *const winsock::SOCKADDR,
                std::mem::size_of::<winsock::SOCKADDR_IN>() as i32,
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            libc::bind(
                sockfd,
                &bind_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    };

    #[cfg(target_os = "windows")]
    if bind_result == winsock::SOCKET_ERROR {
        unsafe {
            winsock::closesocket(sockfd as _);
        }
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to bind socket".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }
    #[cfg(not(target_os = "windows"))]
    if bind_result < 0 {
        unsafe {
            libc::close(sockfd);
        }
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to bind socket".to_string()),
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
    let timeout_result = unsafe {
        #[cfg(target_os = "windows")]
        {
            winsock::setsockopt(
                sockfd as _,
                winsock::SOL_SOCKET as i32,
                winsock::SO_RCVTIMEO as i32,
                &timeout_val as *const _ as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            libc::setsockopt(
                sockfd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout_tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        }
    };

    #[cfg(target_os = "windows")]
    if timeout_result == winsock::SOCKET_ERROR {
        unsafe {
            winsock::closesocket(sockfd as _);
        }
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to set socket timeout".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }
    #[cfg(not(target_os = "windows"))]
    if timeout_result < 0 {
        unsafe {
            libc::close(sockfd);
        }
        let result = TraceRouteResult {
            target: target.to_string(),
            hops: vec![],
            error: Some("Failed to set socket timeout".to_string()),
        };
        return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
    }

    #[cfg(target_os = "windows")]
    let mut sockaddr: winsock::SOCKADDR_IN = unsafe { std::mem::zeroed() };
    #[cfg(not(target_os = "windows"))]
    let mut sockaddr: libc::sockaddr_in = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "windows")]
    {
        sockaddr.sin_family = winsock::AF_INET as _;
    }
    #[cfg(not(target_os = "windows"))]
    {
        sockaddr.sin_family = libc::AF_INET as _;
    }
    if let std::net::SocketAddr::V4(addr) = target_addr {
        #[cfg(target_os = "windows")]
        {
            let ip_u32 = u32::from_ne_bytes(addr.ip().octets());
            unsafe {
                std::ptr::write(&mut sockaddr.sin_addr as *mut _ as *mut u32, ip_u32);
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            sockaddr.sin_addr.s_addr = u32::from_ne_bytes(addr.ip().octets());
        }
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
        let ttl_result = unsafe {
            #[cfg(target_os = "windows")]
            {
                winsock::setsockopt(
                    sockfd as _,
                    winsock::IPPROTO_IP as i32,
                    winsock::IP_TTL as i32,
                    &ttl_val as *const _ as *const u8,
                    std::mem::size_of::<i32>() as i32,
                )
            }
            #[cfg(not(target_os = "windows"))]
            {
                libc::setsockopt(
                    sockfd,
                    libc::IPPROTO_IP,
                    libc::IP_TTL,
                    &ttl_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<i32>() as libc::socklen_t,
                )
            }
        };

        #[cfg(target_os = "windows")]
        let ttl_set_failed = ttl_result == winsock::SOCKET_ERROR;
        #[cfg(not(target_os = "windows"))]
        let ttl_set_failed = ttl_result < 0;

        if ttl_set_failed {
            continue;
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
                    winsock::sendto(
                        sockfd as _,
                        packet.as_ptr() as *const u8,
                        packet.len() as i32,
                        0,
                        &sockaddr as *const _ as *const winsock::SOCKADDR,
                        std::mem::size_of::<winsock::SOCKADDR_IN>() as i32,
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
                    ) as i32
                }
            };

            #[cfg(target_os = "windows")]
            let send_failed = send_result == winsock::SOCKET_ERROR;
            #[cfg(not(target_os = "windows"))]
            let send_failed = send_result < 0;

            if !send_failed {
                // Try to receive reply - loop until we get the right packet or timeout
                loop {
                    let mut buf = [0u8; 1024];
                    let recv_result = unsafe {
                        #[cfg(target_os = "windows")]
                        {
                            winsock::recvfrom(
                                sockfd as _,
                                buf.as_mut_ptr() as *mut u8,
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
                            ) as i32
                        }
                    };

                    #[cfg(target_os = "windows")]
                    let recv_failed = recv_result == winsock::SOCKET_ERROR || recv_result <= 0;
                    #[cfg(not(target_os = "windows"))]
                    let recv_failed = recv_result <= 0;

                    let elapsed = start.elapsed();
                    
                    if recv_failed || elapsed >= timeout {
                        break;
                    }

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
                        break;
                    }
                    // If we got a packet but it wasn't ours, continue receiving
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
        winsock::closesocket(sockfd as _);
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

