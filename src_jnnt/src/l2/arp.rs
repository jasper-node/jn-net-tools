use crate::ll::RawSocket;
use crate::runtime::block_on;
use pnet::packet::arp::{ArpPacket, ArpOperations};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::datalink;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize)]
pub struct ArpDevice {
    pub ip: String,
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
pub struct ArpScanResult {
    pub interface: String,
    pub devices: Vec<ArpDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn build_arp_request(src_mac: &[u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0u8; 42];
    
    let mut ethernet = MutableEthernetPacket::new(&mut packet[..]).unwrap();
    ethernet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    ethernet.set_source(MacAddr::new(src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]));
    ethernet.set_ethertype(EtherTypes::Arp);
    
    let arp_offset = 14;
    packet[arp_offset] = 0x00; packet[arp_offset + 1] = 0x01;
    packet[arp_offset + 2] = 0x08; packet[arp_offset + 3] = 0x00;
    packet[arp_offset + 4] = 0x06;
    packet[arp_offset + 5] = 0x04;
    packet[arp_offset + 6] = 0x00; packet[arp_offset + 7] = 0x01;
    
    packet[arp_offset + 8..arp_offset + 14].copy_from_slice(src_mac);
    packet[arp_offset + 14..arp_offset + 18].copy_from_slice(&src_ip.octets());
    packet[arp_offset + 18..arp_offset + 24].copy_from_slice(&[0u8; 6]);
    packet[arp_offset + 24..arp_offset + 28].copy_from_slice(&dst_ip.octets());
    
    packet
}

pub fn arp_scan(iface_name: &str, timeout_ms: u32) -> String {
    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == iface_name) {
        Some(i) => i,
        None => {
            let result = ArpScanResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some(format!("Interface {} not found", iface_name)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let src_mac = match iface.mac {
        Some(mac) => mac.octets(),
        None => {
            let result = ArpScanResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some("No MAC address found on interface".to_string()),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let src_ip = match iface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => {
                let result = ArpScanResult {
                    interface: iface_name.to_string(),
                    devices: vec![],
                    error: Some("No IPv4 address found on interface".to_string()),
                };
                return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
            }
        },
        None => {
            let result = ArpScanResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some("No IP address found on interface".to_string()),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };




    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return ArpScanResult {
                    interface: iface_name.to_string(),
                    devices: vec![],
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(iface_name).await {
            return ArpScanResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        // Small delay to ensure socket is ready
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Use a channel to send packets from the sender task to the writer
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        
        let mut devices: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
        let timeout = Duration::from_millis(timeout_ms as u64);
        let base_ip = Ipv4Addr::from(u32::from_be_bytes(src_ip.octets()) & 0xFFFFFF00);

        // Spawn Sender Task - generates ARP requests and sends them via channel
        let sender_task = tokio::spawn(async move {
            for i in 1..255 {
                let target_ip = Ipv4Addr::from(u32::from_be_bytes(base_ip.octets()) | i);
                if target_ip == src_ip {
                    continue;
                }

                let packet = build_arp_request(&src_mac, src_ip, target_ip);
                if tx.send(packet).is_err() {
                    // Receiver dropped, exit
                    break;
                }
                // Faster sending: 200 micros is usually safe for local LAN
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
        });

        // Main task: Handle both reading from socket and writing packets from channel
        let mut buffer = vec![0u8; 2048];
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                // Try to read a packet from the socket
                read_result = tokio::time::timeout(remaining, socket.read(&mut buffer)) => {
                    match read_result {
                        Ok(Ok(n)) => {
                            if n == 0 {
                                break; // EOF
                            }
                            if let Some(ethernet) = EthernetPacket::new(&buffer[..n]) {
                                let pkt_src_mac = ethernet.get_source().octets();
                                // Filter out our own sent packets
                                if pkt_src_mac != src_mac {
                                    if ethernet.get_ethertype() == EtherTypes::Arp {
                                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                            if arp.get_operation() == ArpOperations::Reply {
                                                let ip = Ipv4Addr::from(arp.get_sender_proto_addr());
                                                let mac = arp.get_sender_hw_addr();
                                                devices.insert(ip, mac.octets());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(_)) => break, // Read Error
                        Err(_) => break,     // Timeout
                    }
                }
                // Try to write a packet from the channel
                packet_opt = rx.recv() => {
                    match packet_opt {
                        Some(packet) => {
                            if socket.write_all(&packet).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            // Channel closed, sender finished
                            // Continue reading until timeout
                        }
                    }
                }
            }
        }
        
        // Ensure sender finishes
        let _ = sender_task.await;

        let mut dev_list: Vec<ArpDevice> = devices
            .iter()
            .map(|(ip, mac)| ArpDevice {
                ip: ip.to_string(),
                mac: format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
            })
            .collect();

        dev_list.sort_by_key(|d| d.ip.clone());

        ArpScanResult {
            interface: iface_name.to_string(),
            devices: dev_list,
            error: None,
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}





#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::arp::ArpPacket;

    #[test]
    fn test_build_arp_request() {
        let src_mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

        let packet = build_arp_request(&src_mac, src_ip, dst_ip);

        // Check total length (Ethernet + ARP)
        // Ethernet header = 14 bytes
        // ARP packet = 28 bytes
        // Min buffer size might be 42 bytes (0-41)
        assert!(packet.len() >= 42);

        // Verify Ethernet Header
        let ethernet = EthernetPacket::new(&packet).expect("Failed to parse Ethernet packet");
        assert_eq!(ethernet.get_destination(), MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        assert_eq!(ethernet.get_source(), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);

        // Verify ARP Header
        let arp = ArpPacket::new(ethernet.payload()).expect("Failed to parse ARP packet");
        assert_eq!(arp.get_hardware_type(), pnet::packet::arp::ArpHardwareTypes::Ethernet);
        assert_eq!(arp.get_protocol_type(), EtherTypes::Ipv4);
        assert_eq!(arp.get_hw_addr_len(), 6);
        assert_eq!(arp.get_proto_addr_len(), 4);
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_hw_addr(), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));
        assert_eq!(arp.get_sender_proto_addr(), src_ip);
        assert_eq!(arp.get_target_hw_addr(), MacAddr::new(0, 0, 0, 0, 0, 0));
        assert_eq!(arp.get_target_proto_addr(), dst_ip);
    }
}
