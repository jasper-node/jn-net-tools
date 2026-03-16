use crate::ll::RawSocket;
use crate::runtime::block_on;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::datalink;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LLDP_ETHERTYPE: u16 = 0x88CC;
const LLDP_MULTICAST_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

// TLV type constants
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESCRIPTION: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_SYSTEM_CAPABILITIES: u8 = 7;
const TLV_MANAGEMENT_ADDRESS: u8 = 8;
const TLV_ORG_SPECIFIC: u8 = 127;

// Chassis ID subtypes
const CHASSIS_SUBTYPE_MAC_ADDRESS: u8 = 4;
const CHASSIS_SUBTYPE_NETWORK_ADDRESS: u8 = 5;
const CHASSIS_SUBTYPE_IFACE_NAME: u8 = 6;

// Port ID subtypes
const PORT_SUBTYPE_MAC_ADDRESS: u8 = 3;
const PORT_SUBTYPE_NETWORK_ADDRESS: u8 = 4;
const PORT_SUBTYPE_IFACE_NAME: u8 = 5;

// Org-specific OUIs
const OUI_IEEE_802_1: [u8; 3] = [0x00, 0x80, 0xC2];
const OUI_IEEE_802_3: [u8; 3] = [0x00, 0x12, 0x0F];

#[derive(Serialize, Deserialize, Clone)]
pub struct LldpCapabilities {
    pub available: Vec<String>,
    pub enabled: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LldpManagementAddress {
    pub address_type: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_number: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LldpOrgSpecific {
    pub oui: String,
    pub subtype: u8,
    pub info: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LldpNeighbor {
    pub chassis_id: String,
    pub chassis_id_subtype: String,
    pub port_id: String,
    pub port_id_subtype: String,
    pub ttl: u16,
    pub source_mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_capabilities: Option<LldpCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management_addresses: Option<Vec<LldpManagementAddress>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_specific: Option<Vec<LldpOrgSpecific>>,
}

#[derive(Serialize, Deserialize)]
pub struct LldpDiscoverResult {
    pub interface: String,
    pub neighbors: Vec<LldpNeighbor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LldpSendResult {
    pub interface: String,
    pub sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct RawTlv {
    tlv_type: u8,
    value: Vec<u8>,
}

fn build_tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
    let len = value.len();
    let type_len: u16 = ((tlv_type as u16) << 9) | (len as u16 & 0x01FF);
    let mut result = Vec::with_capacity(2 + len);
    result.extend_from_slice(&type_len.to_be_bytes());
    result.extend_from_slice(value);
    result
}

fn parse_tlvs(payload: &[u8]) -> Vec<RawTlv> {
    let mut tlvs = Vec::new();
    let mut offset = 0;

    while offset + 2 <= payload.len() {
        let type_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_type = (type_len >> 9) as u8;
        let tlv_len = (type_len & 0x01FF) as usize;
        offset += 2;

        if tlv_type == TLV_END {
            break;
        }

        if offset + tlv_len > payload.len() {
            break;
        }

        tlvs.push(RawTlv {
            tlv_type,
            value: payload[offset..offset + tlv_len].to_vec(),
        });

        offset += tlv_len;
    }

    tlvs
}

fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

fn chassis_id_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        1 => "Chassis Component",
        2 => "Interface Alias",
        3 => "Port Component",
        CHASSIS_SUBTYPE_MAC_ADDRESS => "MAC Address",
        CHASSIS_SUBTYPE_NETWORK_ADDRESS => "Network Address",
        CHASSIS_SUBTYPE_IFACE_NAME => "Interface Name",
        7 => "Local",
        _ => "Unknown",
    }
}

fn port_id_subtype_name(subtype: u8) -> &'static str {
    match subtype {
        1 => "Interface Alias",
        2 => "Port Component",
        PORT_SUBTYPE_MAC_ADDRESS => "MAC Address",
        PORT_SUBTYPE_NETWORK_ADDRESS => "Network Address",
        PORT_SUBTYPE_IFACE_NAME => "Interface Name",
        6 => "Agent Circuit ID",
        7 => "Local",
        _ => "Unknown",
    }
}

fn parse_id_value(subtype: u8, data: &[u8], mac_subtype: u8, net_subtype: u8) -> String {
    if subtype == mac_subtype && data.len() == 6 {
        format_mac(data)
    } else if subtype == net_subtype && !data.is_empty() {
        parse_network_address(data)
    } else {
        String::from_utf8_lossy(data).trim_end_matches('\0').to_string()
    }
}

fn parse_network_address(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let addr_family = data[0];
    let addr_bytes = &data[1..];
    match addr_family {
        1 if addr_bytes.len() >= 4 => {
            format!("{}.{}.{}.{}", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3])
        }
        2 if addr_bytes.len() >= 16 => {
            let parts: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([addr_bytes[i * 2], addr_bytes[i * 2 + 1]])))
                .collect();
            parts.join(":")
        }
        _ => format!("type={} {}", addr_family, format_mac(addr_bytes)),
    }
}

fn parse_system_capabilities(value: &[u8]) -> Option<LldpCapabilities> {
    if value.len() < 4 {
        return None;
    }
    let available_bits = u16::from_be_bytes([value[0], value[1]]);
    let enabled_bits = u16::from_be_bytes([value[2], value[3]]);

    let cap_names = [
        (0, "Other"),
        (1, "Repeater"),
        (2, "Bridge"),
        (3, "WLAN AP"),
        (4, "Router"),
        (5, "Telephone"),
        (6, "DOCSIS"),
        (7, "Station Only"),
        (8, "C-VLAN"),
        (9, "S-VLAN"),
        (10, "Two-Port MAC Relay"),
    ];

    let available: Vec<String> = cap_names.iter()
        .filter(|(bit, _)| available_bits & (1 << bit) != 0)
        .map(|(_, name)| name.to_string())
        .collect();

    let enabled: Vec<String> = cap_names.iter()
        .filter(|(bit, _)| enabled_bits & (1 << bit) != 0)
        .map(|(_, name)| name.to_string())
        .collect();

    Some(LldpCapabilities { available, enabled })
}

fn parse_management_address(value: &[u8]) -> Option<LldpManagementAddress> {
    if value.is_empty() {
        return None;
    }
    let addr_str_len = value[0] as usize;
    if value.len() < 1 + addr_str_len || addr_str_len < 2 {
        return None;
    }

    let addr_subtype = value[1];
    let addr_bytes = &value[2..1 + addr_str_len];

    let (address_type, address) = match addr_subtype {
        1 if addr_bytes.len() >= 4 => {
            ("IPv4".to_string(), format!("{}.{}.{}.{}", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]))
        }
        2 if addr_bytes.len() >= 16 => {
            let parts: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([addr_bytes[i * 2], addr_bytes[i * 2 + 1]])))
                .collect();
            ("IPv6".to_string(), parts.join(":"))
        }
        6 if addr_bytes.len() >= 6 => {
            ("MAC".to_string(), format_mac(addr_bytes))
        }
        _ => {
            (format!("Type {}", addr_subtype), format_mac(addr_bytes))
        }
    };

    let mut mgmt = LldpManagementAddress {
        address_type,
        address,
        interface_subtype: None,
        interface_number: None,
    };

    let iface_offset = 1 + addr_str_len;
    if value.len() >= iface_offset + 5 {
        let iface_subtype = value[iface_offset];
        let iface_number = u32::from_be_bytes([
            value[iface_offset + 1],
            value[iface_offset + 2],
            value[iface_offset + 3],
            value[iface_offset + 4],
        ]);
        mgmt.interface_subtype = Some(match iface_subtype {
            1 => "Unknown".to_string(),
            2 => "ifIndex".to_string(),
            3 => "System Port Number".to_string(),
            _ => format!("Subtype {}", iface_subtype),
        });
        mgmt.interface_number = Some(iface_number);
    }

    Some(mgmt)
}

fn parse_org_specific(value: &[u8]) -> Option<LldpOrgSpecific> {
    if value.len() < 4 {
        return None;
    }
    let oui = [value[0], value[1], value[2]];
    let subtype = value[3];
    let data = &value[4..];

    let oui_str = format!("{:02x}:{:02x}:{:02x}", oui[0], oui[1], oui[2]);

    let info = if oui == OUI_IEEE_802_1 {
        match subtype {
            1 if data.len() >= 2 => {
                let vlan_id = u16::from_be_bytes([data[0], data[1]]);
                format!("Port VLAN ID: {}", vlan_id)
            }
            3 if data.len() >= 3 => {
                let vlan_id = u16::from_be_bytes([data[0], data[1]]);
                let name_len = data[2] as usize;
                let name = if data.len() >= 3 + name_len {
                    String::from_utf8_lossy(&data[3..3 + name_len]).to_string()
                } else {
                    String::new()
                };
                format!("VLAN Name: {} (ID {})", name, vlan_id)
            }
            _ => format_mac(data),
        }
    } else if oui == OUI_IEEE_802_3 {
        match subtype {
            1 => "MAC/PHY Configuration".to_string(),
            3 if data.len() >= 3 => {
                let status = data[0];
                let agg_id = u32::from_be_bytes([0, 0, data[1], data[2]]);
                format!("Link Aggregation: status={} id={}", status, agg_id)
            }
            4 if data.len() >= 2 => {
                let max_frame = u16::from_be_bytes([data[0], data[1]]);
                format!("Max Frame Size: {}", max_frame)
            }
            _ => format_mac(data),
        }
    } else {
        format_mac(data)
    };

    Some(LldpOrgSpecific { oui: oui_str, subtype, info })
}

fn parse_lldp_frame(frame: &[u8]) -> Option<LldpNeighbor> {
    let ethernet = EthernetPacket::new(frame)?;

    if ethernet.get_ethertype().0 != LLDP_ETHERTYPE {
        return None;
    }

    let source_mac = format_mac(&ethernet.get_source().octets());
    let payload = ethernet.payload();
    let tlvs = parse_tlvs(payload);

    let mut chassis_id = String::new();
    let mut chassis_id_subtype = String::new();
    let mut port_id = String::new();
    let mut port_id_subtype = String::new();
    let mut ttl: u16 = 0;
    let mut port_description = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut system_capabilities = None;
    let mut management_addresses: Vec<LldpManagementAddress> = Vec::new();
    let mut org_specific: Vec<LldpOrgSpecific> = Vec::new();

    for tlv in &tlvs {
        match tlv.tlv_type {
            TLV_CHASSIS_ID if !tlv.value.is_empty() => {
                let subtype = tlv.value[0];
                chassis_id_subtype = chassis_id_subtype_name(subtype).to_string();
                chassis_id = parse_id_value(subtype, &tlv.value[1..], CHASSIS_SUBTYPE_MAC_ADDRESS, CHASSIS_SUBTYPE_NETWORK_ADDRESS);
            }
            TLV_PORT_ID if !tlv.value.is_empty() => {
                let subtype = tlv.value[0];
                port_id_subtype = port_id_subtype_name(subtype).to_string();
                port_id = parse_id_value(subtype, &tlv.value[1..], PORT_SUBTYPE_MAC_ADDRESS, PORT_SUBTYPE_NETWORK_ADDRESS);
            }
            TLV_TTL if tlv.value.len() >= 2 => {
                ttl = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
            }
            TLV_PORT_DESCRIPTION => {
                port_description = Some(String::from_utf8_lossy(&tlv.value).trim_end_matches('\0').to_string());
            }
            TLV_SYSTEM_NAME => {
                system_name = Some(String::from_utf8_lossy(&tlv.value).trim_end_matches('\0').to_string());
            }
            TLV_SYSTEM_DESCRIPTION => {
                system_description = Some(String::from_utf8_lossy(&tlv.value).trim_end_matches('\0').to_string());
            }
            TLV_SYSTEM_CAPABILITIES => {
                system_capabilities = parse_system_capabilities(&tlv.value);
            }
            TLV_MANAGEMENT_ADDRESS => {
                if let Some(mgmt) = parse_management_address(&tlv.value) {
                    management_addresses.push(mgmt);
                }
            }
            TLV_ORG_SPECIFIC => {
                if let Some(org) = parse_org_specific(&tlv.value) {
                    org_specific.push(org);
                }
            }
            _ => {}
        }
    }

    if chassis_id.is_empty() && port_id.is_empty() {
        return None;
    }

    Some(LldpNeighbor {
        chassis_id,
        chassis_id_subtype,
        port_id,
        port_id_subtype,
        ttl,
        source_mac,
        port_description,
        system_name,
        system_description,
        system_capabilities,
        management_addresses: if management_addresses.is_empty() { None } else { Some(management_addresses) },
        org_specific: if org_specific.is_empty() { None } else { Some(org_specific) },
    })
}

fn build_lldp_frame(
    src_mac: &[u8; 6],
    chassis_id: &[u8; 6],
    port_id: &str,
    ttl: u16,
    system_name: Option<&str>,
    system_description: Option<&str>,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Chassis ID TLV (subtype 4 = MAC Address)
    let mut chassis_value = vec![CHASSIS_SUBTYPE_MAC_ADDRESS];
    chassis_value.extend_from_slice(chassis_id);
    payload.extend(build_tlv(TLV_CHASSIS_ID, &chassis_value));

    // Port ID TLV (subtype 5 = Interface Name)
    let mut port_value = vec![PORT_SUBTYPE_IFACE_NAME];
    port_value.extend_from_slice(port_id.as_bytes());
    payload.extend(build_tlv(TLV_PORT_ID, &port_value));

    // TTL TLV
    payload.extend(build_tlv(TLV_TTL, &ttl.to_be_bytes()));

    // System Name TLV (optional)
    if let Some(name) = system_name {
        payload.extend(build_tlv(TLV_SYSTEM_NAME, name.as_bytes()));
    }

    // System Description TLV (optional)
    if let Some(desc) = system_description {
        payload.extend(build_tlv(TLV_SYSTEM_DESCRIPTION, desc.as_bytes()));
    }

    // End of LLDPDU TLV
    payload.extend(build_tlv(TLV_END, &[]));

    // Build Ethernet frame
    let frame_len = 14 + payload.len();
    let mut frame = vec![0u8; frame_len];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut frame[..]).unwrap();
        ethernet.set_destination(MacAddr::new(
            LLDP_MULTICAST_ADDR[0], LLDP_MULTICAST_ADDR[1], LLDP_MULTICAST_ADDR[2],
            LLDP_MULTICAST_ADDR[3], LLDP_MULTICAST_ADDR[4], LLDP_MULTICAST_ADDR[5],
        ));
        ethernet.set_source(MacAddr::new(src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]));
        ethernet.set_ethertype(pnet::packet::ethernet::EtherType(LLDP_ETHERTYPE));
    }
    frame[14..].copy_from_slice(&payload);

    frame
}

pub fn lldp_discover(iface_name: &str, timeout_ms: u32) -> String {
    let resolved_name = crate::l2::interfaces::resolve_interface_name(iface_name);

    let interfaces = datalink::interfaces();
    let _iface = match interfaces.iter().find(|i| i.name == resolved_name) {
        Some(i) => i,
        None => {
            let result = LldpDiscoverResult {
                interface: iface_name.to_string(),
                neighbors: vec![],
                error: Some(format!("Interface {} not found", iface_name)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return LldpDiscoverResult {
                    interface: iface_name.to_string(),
                    neighbors: vec![],
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(&resolved_name).await {
            return LldpDiscoverResult {
                interface: iface_name.to_string(),
                neighbors: vec![],
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let mut neighbors: HashMap<(String, String), LldpNeighbor> = HashMap::new();
        let timeout = Duration::from_millis(timeout_ms as u64);
        let mut buffer = vec![0u8; 2048];
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, socket.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    if let Some(neighbor) = parse_lldp_frame(&buffer[..n]) {
                        let key = (neighbor.chassis_id.clone(), neighbor.port_id.clone());
                        neighbors.insert(key, neighbor);
                    }
                }
                Ok(Ok(_)) => break,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        let mut neighbor_list: Vec<LldpNeighbor> = neighbors.into_values().collect();
        neighbor_list.sort_by(|a, b| a.chassis_id.cmp(&b.chassis_id));

        LldpDiscoverResult {
            interface: iface_name.to_string(),
            neighbors: neighbor_list,
            error: None,
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

pub fn lldp_send(iface_name: &str, ttl: u16) -> String {
    let resolved_name = crate::l2::interfaces::resolve_interface_name(iface_name);

    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == resolved_name) {
        Some(i) => i,
        None => {
            let result = LldpSendResult {
                interface: iface_name.to_string(),
                sent: false,
                error: Some(format!("Interface {} not found", iface_name)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let src_mac = match iface.mac {
        Some(mac) => mac.octets(),
        None => {
            let result = LldpSendResult {
                interface: iface_name.to_string(),
                sent: false,
                error: Some("No MAC address found on interface".to_string()),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let hostname = get_hostname().unwrap_or_else(|| "unknown".to_string());

    let frame = build_lldp_frame(
        &src_mac,
        &src_mac,
        iface_name,
        ttl,
        Some(&hostname),
        Some("jn-net-tools LLDP agent"),
    );

    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return LldpSendResult {
                    interface: iface_name.to_string(),
                    sent: false,
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(&resolved_name).await {
            return LldpSendResult {
                interface: iface_name.to_string(),
                sent: false,
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        match socket.write_all(&frame).await {
            Ok(_) => LldpSendResult {
                interface: iface_name.to_string(),
                sent: true,
                error: None,
            },
            Err(e) => LldpSendResult {
                interface: iface_name.to_string(),
                sent: false,
                error: Some(format!("Failed to send LLDP frame: {}", e)),
            },
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

fn get_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..len]).to_string())
        } else {
            None
        }
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tlv() {
        // Type 5 (System Name), length 4, value "test"
        let tlv = build_tlv(5, b"test");
        assert_eq!(tlv.len(), 6); // 2 header + 4 value
        let type_len = u16::from_be_bytes([tlv[0], tlv[1]]);
        assert_eq!((type_len >> 9) as u8, 5); // type
        assert_eq!((type_len & 0x01FF) as usize, 4); // length
        assert_eq!(&tlv[2..], b"test");
    }

    #[test]
    fn test_parse_tlvs() {
        let mut data = Vec::new();
        data.extend(build_tlv(5, b"myswitch")); // System Name
        data.extend(build_tlv(3, &120u16.to_be_bytes())); // TTL
        data.extend(build_tlv(0, &[])); // End

        let tlvs = parse_tlvs(&data);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].tlv_type, 5);
        assert_eq!(&tlvs[0].value, b"myswitch");
        assert_eq!(tlvs[1].tlv_type, 3);
        assert_eq!(tlvs[1].value.len(), 2);
    }

    #[test]
    fn test_build_and_parse_lldp_frame() {
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_lldp_frame(
            &src_mac,
            &src_mac,
            "eth0",
            120,
            Some("TestSwitch"),
            Some("Test Description"),
        );

        let neighbor = parse_lldp_frame(&frame).expect("Failed to parse LLDP frame");
        assert_eq!(neighbor.chassis_id, "aa:bb:cc:dd:ee:ff");
        assert_eq!(neighbor.chassis_id_subtype, "MAC Address");
        assert_eq!(neighbor.port_id, "eth0");
        assert_eq!(neighbor.port_id_subtype, "Interface Name");
        assert_eq!(neighbor.ttl, 120);
        assert_eq!(neighbor.system_name, Some("TestSwitch".to_string()));
        assert_eq!(neighbor.system_description, Some("Test Description".to_string()));
    }

    #[test]
    fn test_parse_system_capabilities() {
        // Available: Bridge + Router (bits 2 and 4), Enabled: Bridge only (bit 2)
        let value = [0x00, 0x14, 0x00, 0x04]; // bits: 0b10100 available, 0b00100 enabled
        let caps = parse_system_capabilities(&value).unwrap();
        assert!(caps.available.contains(&"Bridge".to_string()));
        assert!(caps.available.contains(&"Router".to_string()));
        assert!(caps.enabled.contains(&"Bridge".to_string()));
        assert!(!caps.enabled.contains(&"Router".to_string()));
    }

    #[test]
    fn test_parse_chassis_id_mac() {
        let subtype = CHASSIS_SUBTYPE_MAC_ADDRESS;
        let mac_bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let result = parse_id_value(subtype, &mac_bytes, CHASSIS_SUBTYPE_MAC_ADDRESS, CHASSIS_SUBTYPE_NETWORK_ADDRESS);
        assert_eq!(result, "00:11:22:33:44:55");
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(format_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), "aa:bb:cc:dd:ee:ff");
    }
}
