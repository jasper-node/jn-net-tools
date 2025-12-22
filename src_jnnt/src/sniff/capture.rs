use crate::ll::RawSocket;
use crate::runtime::block_on;
use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::arp::ArpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use serde_json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct PacketSummary {
    pub ts: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SniffResult {
    pub captured: i32,
    pub packets: Vec<PacketSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn process_packet(packet: &[u8], include_data: bool) -> Option<PacketSummary> {
    let ethernet = EthernetPacket::new(packet)?;
    
    // Hex encode packet data if requested
    let data_hex = if include_data {
        Some(packet.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "))
    } else {
        None
    };
    
    let mut summary = PacketSummary {
        ts: format!("{:?}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
        src: "".to_string(),
        dst: "".to_string(),
        proto: "Unknown".to_string(),
        info: "".to_string(),
        data: data_hex,
    };

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                summary.src = ipv4.get_source().to_string();
                summary.dst = ipv4.get_destination().to_string();
                summary.proto = "IP".to_string();

                match ipv4.get_next_level_protocol() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            summary.proto = "TCP".to_string();
                            let mut flags = Vec::new();
                            if tcp.get_flags() & 0x02 != 0 { flags.push("SYN"); }
                            if tcp.get_flags() & 0x10 != 0 { flags.push("ACK"); }
                            if tcp.get_flags() & 0x01 != 0 { flags.push("FIN"); }
                            if tcp.get_flags() & 0x04 != 0 { flags.push("RST"); }
                            summary.info = format!("{} -> {} [{}]", tcp.get_source(), tcp.get_destination(), flags.join(" "));
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            summary.proto = "UDP".to_string();
                            summary.info = format!("{} -> {} len={}", udp.get_source(), udp.get_destination(), udp.get_length());
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                        if let Some(_icmp) = IcmpPacket::new(ipv4.payload()) {
                            summary.proto = "ICMP".to_string();
                            summary.info = "ICMP packet".to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                summary.src = ipv6.get_source().to_string();
                summary.dst = ipv6.get_destination().to_string();
                summary.proto = "IPv6".to_string();
            }
        }
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                summary.proto = "ARP".to_string();
                summary.src = format!("{:?}", arp.get_sender_hw_addr());
                summary.dst = format!("{:?}", arp.get_target_hw_addr());
                summary.info = if arp.get_operation() == pnet::packet::arp::ArpOperations::Request {
                    "Request".to_string()
                } else {
                    "Reply".to_string()
                };
            }
        }
        _ => {
            summary.proto = format!("Ethernet (0x{:04X})", ethernet.get_ethertype().0);
            summary.src = ethernet.get_source().to_string();
            summary.dst = ethernet.get_destination().to_string();
        }
    }

    Some(summary)
}

/// Check if a packet matches the given filter
fn matches_filter(packet: &PacketSummary, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }

    let filter_lower = filter.to_lowercase();
    let parts: Vec<&str> = filter_lower.split_whitespace().collect();

    match parts.as_slice() {
        // Protocol-only filters
        ["tcp"] => packet.proto == "TCP",
        ["udp"] => packet.proto == "UDP",
        ["arp"] => packet.proto == "ARP",
        ["icmp"] => packet.proto == "ICMP",
        ["ipv6"] | ["ip6"] => packet.proto == "IPv6",
        
        // TCP port filters
        ["tcp", "port", port] => {
            if packet.proto != "TCP" {
                return false;
            }
            // Check if port appears in info field
            packet.info.contains(&format!(" {} ", port)) ||
            packet.info.contains(&format!("-> {} ", port)) ||
            packet.info.contains(&format!(" {} [", port))
        }
        
        // UDP port filters
        ["udp", "port", port] => {
            if packet.proto != "UDP" {
                return false;
            }
            packet.info.contains(&format!(" {} ", port)) ||
            packet.info.contains(&format!("-> {} ", port))
        }
        
        // Host filters
        ["host", ip] => {
            packet.src.to_lowercase().contains(ip) || packet.dst.to_lowercase().contains(ip)
        }
        
        // Port filter (any protocol)
        ["port", port] => {
            packet.info.contains(&format!(" {} ", port)) ||
            packet.info.contains(&format!("-> {} ", port)) ||
            packet.info.contains(&format!(" {} [", port))
        }
        
        _ => true // Unknown filter, let all packets through
    }
}

pub fn sniff_packets(iface_name: &str, filter: &str, duration_ms: u32, max_packets: i32, include_data: bool) -> String {
    let interfaces = datalink::interfaces();
    let _iface = match interfaces.iter().find(|i| i.name == iface_name) {
        Some(i) => i,
        None => {
            let result = SniffResult {
                captured: 0,
                packets: vec![],
                error: Some(format!("Interface {} not found", iface_name)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return SniffResult {
                    captured: 0,
                    packets: vec![],
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(iface_name).await {
            return SniffResult {
                captured: 0,
                packets: vec![],
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        // Apply filter if provided
        if !filter.is_empty() {
            if let Err(e) = socket.set_filter(filter).await {
                return SniffResult {
                    captured: 0,
                    packets: vec![],
                    error: Some(format!("Failed to set filter '{}': {}", filter, e)),
                };
            }
        }

        let duration = Duration::from_millis(duration_ms as u64);
        let deadline = std::time::Instant::now() + duration;
        let mut packets = Vec::new();
        let mut buffer = vec![0u8; 2048];

        while std::time::Instant::now() < deadline && packets.len() < max_packets as usize {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, tokio::io::AsyncReadExt::read(&mut socket, &mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    if let Some(summary) = process_packet(&buffer[..n], include_data) {
                        // Apply userspace filter
                        if matches_filter(&summary, filter) {
                            packets.push(summary);
                            if packets.len() >= max_packets as usize {
                                break;
                            }
                        }
                    }
                }
                Ok(Ok(_)) => break,
                Err(_) => break,
                _ => continue,
            }
        }

        SniffResult {
            captured: packets.len() as i32,
            packets,
            error: None,
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

