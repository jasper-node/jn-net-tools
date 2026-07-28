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
    // Port filters compare these, never the formatted `info` text. Skipped by
    // serde so the JSON handed back over FFI is unchanged.
    #[serde(skip)]
    pub src_port: Option<u16>,
    #[serde(skip)]
    pub dst_port: Option<u16>,
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
        src_port: None,
        dst_port: None,
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
                            summary.src_port = Some(tcp.get_source());
                            summary.dst_port = Some(tcp.get_destination());
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
                            summary.src_port = Some(udp.get_source());
                            summary.dst_port = Some(udp.get_destination());
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
        _ if ethernet.get_ethertype().0 == 0x88CC => {
            summary.proto = "LLDP".to_string();
            summary.src = ethernet.get_source().to_string();
            summary.dst = ethernet.get_destination().to_string();

            let payload = ethernet.payload();
            let mut info_parts = Vec::new();
            let mut offset = 0;
            while offset + 2 <= payload.len() {
                let type_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let tlv_type = (type_len >> 9) as u8;
                let tlv_len = (type_len & 0x01FF) as usize;
                offset += 2;
                if tlv_type == 0 || offset + tlv_len > payload.len() { break; }
                match tlv_type {
                    5 => {
                        if let Ok(name) = std::str::from_utf8(&payload[offset..offset + tlv_len]) {
                            info_parts.push(format!("name={}", name.trim_end_matches('\0')));
                        }
                    }
                    3 if tlv_len >= 2 => {
                        let ttl = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                        info_parts.push(format!("ttl={}", ttl));
                    }
                    _ => {}
                }
                offset += tlv_len;
            }
            summary.info = if info_parts.is_empty() {
                "LLDP frame".to_string()
            } else {
                info_parts.join(" ")
            };
        }
        _ if ethernet.get_ethertype().0 == 0x8892 => {
            summary.proto = "PROFINET-DCP".to_string();
            summary.src = ethernet.get_source().to_string();
            summary.dst = ethernet.get_destination().to_string();

            let payload = ethernet.payload();
            if payload.len() >= 12 {
                let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
                let service_id = payload[2];
                let service_type = payload[3];
                let svc_name = match service_id {
                    3 => "Get",
                    4 => "Set",
                    5 => "Identify",
                    _ => "Unknown",
                };
                let svc_type_name = match service_type {
                    0 => "Request",
                    1 => "Response OK",
                    5 => "Response Error",
                    _ => "Unknown",
                };
                summary.info = format!("FrameID=0x{:04X} {} {}", frame_id, svc_name, svc_type_name);
            } else {
                summary.info = "PROFINET-DCP frame".to_string();
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

#[cfg(target_os = "windows")]
const INTERFACE_NOT_FOUND_HINT: &str = " (Ensure Npcap is installed in WinPcap-compatible mode and the interface exists)";
#[cfg(not(target_os = "windows"))]
const INTERFACE_NOT_FOUND_HINT: &str = " (check the name against net_get_interfaces() output and that the interface is up)";

/// A capture filter this library can actually enforce.
#[derive(Debug, PartialEq)]
enum Filter {
    All,
    Proto(&'static str),
    Port { proto: Option<&'static str>, port: u16 },
    Host(String),
}

/// Every form the matcher enforces, spelled as a caller types it. Kept in step
/// with `getSupportedFilters()` in `src/filters.ts` and the README table.
const SUPPORTED_FILTERS: &str = "tcp, udp, arp, icmp, ipv6 (or ip6), lldp, dcp, \
    \"tcp port <n>\", \"udp port <n>\", \"port <n>\", \"host <ip>\"";

fn refuse(filter: &str, cause: &str) -> String {
    let lowered = filter.to_lowercase();
    let compound_hint = if lowered.split_whitespace().any(|t| matches!(t, "and" | "or" | "not")) {
        " Terms cannot be combined with \"and\", \"or\" or \"not\" — use the single closest form \
         (Modbus TCP is \"tcp port 502\")."
    } else {
        ""
    };
    format!(
        "Unsupported packet filter '{}': {}. Capture filtering runs in userspace here and \
         enforces only these forms: {}.{} Leave the filter empty to capture every packet.",
        filter, cause, SUPPORTED_FILTERS, compound_hint
    )
}

fn parse_port(filter: &str, token: &str) -> Result<u16, String> {
    token.parse::<u16>().map_err(|_| {
        refuse(
            filter,
            &format!("\"port\" takes a number from 0 to 65535, and '{}' is not one", token),
        )
    })
}

/// A literal the matcher can compare against. `process_packet` writes IPs for
/// IPv4/IPv6 frames and MAC addresses for LLDP, DCP and other ethertypes;
/// names are never resolved, so a hostname could only ever match nothing.
fn is_literal_address(token: &str) -> bool {
    if token.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let mut octets = token.split(':');
    octets.clone().count() == 6
        && octets.all(|octet| octet.len() == 2 && octet.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Parse a filter expression, or say why this library cannot enforce it.
///
/// Refusing is the point: before the kernel BPF pre-filter was dropped, an
/// expression outside this grammar was compiled and enforced by libpcap. Now
/// nothing else narrows the capture, so accepting one would hand back every
/// packet on the interface dressed up as a filtered capture.
fn parse_filter(filter: &str) -> Result<Filter, String> {
    let lowered = filter.to_lowercase();
    let parts: Vec<&str> = lowered.split_whitespace().collect();

    match parts.as_slice() {
        [] => Ok(Filter::All),
        ["tcp"] => Ok(Filter::Proto("TCP")),
        ["udp"] => Ok(Filter::Proto("UDP")),
        ["arp"] => Ok(Filter::Proto("ARP")),
        ["icmp"] => Ok(Filter::Proto("ICMP")),
        ["ipv6"] | ["ip6"] => Ok(Filter::Proto("IPv6")),
        ["lldp"] => Ok(Filter::Proto("LLDP")),
        ["dcp"] => Ok(Filter::Proto("PROFINET-DCP")),
        ["tcp", "port", port] => {
            parse_port(filter, port).map(|port| Filter::Port { proto: Some("TCP"), port })
        }
        ["udp", "port", port] => {
            parse_port(filter, port).map(|port| Filter::Port { proto: Some("UDP"), port })
        }
        ["port", port] => parse_port(filter, port).map(|port| Filter::Port { proto: None, port }),
        ["host", address] if is_literal_address(address) => Ok(Filter::Host(address.to_string())),
        ["host", address] => Err(refuse(
            filter,
            &format!(
                "\"host\" takes a literal IP or MAC address and names are never resolved, so \
                 '{}' would match no packets at all",
                address
            ),
        )),
        _ => Err(refuse(filter, "nothing here narrows the capture")),
    }
}

/// Check if a packet matches an already-parsed filter.
fn matches_filter(packet: &PacketSummary, filter: &Filter) -> bool {
    match filter {
        Filter::All => true,
        Filter::Proto(proto) => packet.proto == *proto,
        // Ports are compared as parsed numbers, never as substrings of the
        // formatted `info` text. A port matches in either direction, as kernel
        // BPF `port N` did, and a bare `port N` stays limited to TCP/UDP — the
        // protocols that have ports at all.
        Filter::Port { proto, port } => {
            let proto_ok = match proto {
                Some(expected) => packet.proto == *expected,
                None => packet.proto == "TCP" || packet.proto == "UDP",
            };
            proto_ok && (packet.src_port == Some(*port) || packet.dst_port == Some(*port))
        }
        Filter::Host(address) => {
            packet.src.to_lowercase() == *address || packet.dst.to_lowercase() == *address
        }
    }
}

pub fn sniff_packets(iface_name: &str, filter: &str, duration_ms: u32, max_packets: i32, include_data: bool) -> String {
    // Resolve friendly name to system name on Windows
    let resolved_name = crate::l2::interfaces::resolve_interface_name(iface_name);
    
    // Parsed before the socket is opened: an expression this library cannot
    // enforce is a caller error, not a capture that quietly returns everything.
    let parsed_filter = match parse_filter(filter) {
        Ok(f) => f,
        Err(message) => {
            let result = SniffResult { captured: 0, packets: vec![], error: Some(message) };
            return serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let interfaces = datalink::interfaces();

    let _iface = match interfaces.iter().find(|i| i.name == resolved_name) {
        Some(i) => i,
        None => {
            let result = SniffResult {
                captured: 0,
                packets: vec![],
                error: Some(format!("Interface {} not found{}", iface_name, INTERFACE_NOT_FOUND_HINT)),
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

        if let Err(e) = socket.bind(&resolved_name).await {
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
                        if matches_filter(&summary, &parsed_filter) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(proto: &str, src_port: Option<u16>, dst_port: Option<u16>) -> PacketSummary {
        let info = match (src_port, dst_port) {
            (Some(s), Some(d)) => format!("{} -> {} [SYN]", s, d),
            _ => String::new(),
        };
        PacketSummary {
            ts: "0".to_string(),
            src: "192.168.1.10".to_string(),
            dst: "192.168.1.20".to_string(),
            proto: proto.to_string(),
            info,
            data: None,
            src_port,
            dst_port,
        }
    }

    fn parsed(filter: &str) -> Filter {
        parse_filter(filter).expect("filter should be supported")
    }

    /// Ethernet + IPv4 + TCP, the shortest frame `process_packet` will parse.
    fn tcp_frame(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 54];
        frame[0..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 168, 1, 10]);
        frame[30..34].copy_from_slice(&[192, 168, 1, 20]);
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
        frame[46] = 0x50;
        frame[47] = 0x02;
        frame
    }

    #[test]
    fn every_documented_form_is_accepted() {
        for filter in [
            "tcp", "udp", "arp", "icmp", "ipv6", "ip6", "lldp", "dcp", "tcp port 502",
            "udp port 53", "port 80", "host 192.168.1.1", "host aa:bb:cc:dd:ee:ff",
        ] {
            assert!(parse_filter(filter).is_ok(), "{filter} should be supported");
        }
    }

    #[test]
    fn an_empty_filter_captures_everything() {
        assert_eq!(parse_filter("").unwrap(), Filter::All);
        assert_eq!(parse_filter("   ").unwrap(), Filter::All);
        assert!(matches_filter(&packet("ARP", None, None), &Filter::All));
    }

    #[test]
    fn a_compound_pcap_expression_is_refused_not_ignored() {
        let error = parse_filter("tcp and port 502").expect_err("compound must not be accepted");
        assert!(error.contains("tcp port <n>"), "error must name the supported forms: {error}");
        assert!(error.contains("tcp and port 502"), "error must quote the filter: {error}");
    }

    #[test]
    fn an_unknown_keyword_is_refused() {
        for filter in ["http", "modbus", "not arp", "src host 1.1.1.1", "port 80 tcp"] {
            assert!(parse_filter(filter).is_err(), "{filter} must be refused");
        }
    }

    #[test]
    fn a_port_outside_the_16_bit_range_is_refused() {
        for filter in ["port 99999", "tcp port 70000", "udp port -1", "port 80abc", "port"] {
            assert!(parse_filter(filter).is_err(), "{filter} must be refused");
        }
    }

    #[test]
    fn a_host_that_is_not_a_literal_address_is_refused() {
        assert!(parse_filter("host example.com").is_err());
        assert!(parse_filter("host").is_err());
    }

    #[test]
    fn protocol_filters_match_only_their_own_protocol() {
        assert!(matches_filter(&packet("TCP", Some(1), Some(2)), &parsed("tcp")));
        assert!(!matches_filter(&packet("UDP", Some(1), Some(2)), &parsed("tcp")));
        assert!(matches_filter(&packet("PROFINET-DCP", None, None), &parsed("dcp")));
        assert!(matches_filter(&packet("IPv6", None, None), &parsed("ip6")));
        assert!(matches_filter(&packet("LLDP", None, None), &parsed("LLDP")));
    }

    #[test]
    fn a_port_filter_matches_either_direction() {
        assert!(matches_filter(&packet("TCP", Some(49152), Some(502)), &parsed("tcp port 502")));
        assert!(matches_filter(&packet("TCP", Some(502), Some(49152)), &parsed("tcp port 502")));
    }

    #[test]
    fn a_port_filter_ignores_a_port_that_merely_contains_the_digits() {
        let filter = parsed("tcp port 502");
        // Source 5021 formats as "5021 -> 80 [SYN]", which the old substring
        // match on `info` accepted.
        assert!(!matches_filter(&packet("TCP", Some(5021), Some(80)), &filter));
        assert!(!matches_filter(&packet("TCP", Some(49152), Some(5020)), &filter));
        assert!(!matches_filter(&packet("TCP", Some(1502), Some(80)), &filter));
    }

    #[test]
    fn a_port_filter_holds_its_protocol_guard() {
        assert!(!matches_filter(&packet("UDP", Some(1), Some(502)), &parsed("tcp port 502")));
        assert!(!matches_filter(&packet("TCP", Some(1), Some(53)), &parsed("udp port 53")));
    }

    #[test]
    fn a_bare_port_filter_matches_tcp_and_udp_only() {
        assert!(matches_filter(&packet("TCP", Some(1), Some(502)), &parsed("port 502")));
        assert!(matches_filter(&packet("UDP", Some(502), Some(1)), &parsed("port 502")));
        // Kernel BPF `port N` never matched a protocol without ports.
        assert!(!matches_filter(&packet("ICMP", None, None), &parsed("port 502")));
        assert!(!matches_filter(&packet("ARP", None, None), &parsed("port 502")));
    }

    #[test]
    fn a_host_filter_matches_the_whole_address() {
        let filter = parsed("host 192.168.1.1");
        let mut hit = packet("TCP", Some(1), Some(2));
        hit.src = "192.168.1.1".to_string();
        assert!(matches_filter(&hit, &filter));
        // Regression for 2acae21: `.1` must not match `.10` or `.100`.
        assert!(!matches_filter(&packet("TCP", Some(1), Some(2)), &filter));
    }

    #[test]
    fn filters_are_case_insensitive_and_tolerate_padding() {
        assert!(matches_filter(&packet("TCP", Some(1), Some(502)), &parsed("  TCP  PORT  502 ")));
    }

    #[test]
    fn process_packet_extracts_tcp_ports() {
        let summary = process_packet(&tcp_frame(49152, 502), false).expect("frame should parse");
        assert_eq!(summary.proto, "TCP");
        assert_eq!(summary.src_port, Some(49152));
        assert_eq!(summary.dst_port, Some(502));
    }
}

