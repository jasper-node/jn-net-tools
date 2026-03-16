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

const PROFINET_ETHERTYPE: u16 = 0x8892;
const DCP_MULTICAST_ADDR: [u8; 6] = [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00];

// DCP Frame IDs
const FRAME_ID_IDENTIFY_REQUEST: u16 = 0xFEFE;
const FRAME_ID_IDENTIFY_RESPONSE: u16 = 0xFEFF;
const FRAME_ID_GET_SET: u16 = 0xFEFD;

// DCP Service IDs
const SERVICE_ID_GET: u8 = 3;
const SERVICE_ID_IDENTIFY: u8 = 5;

// DCP Service Types
const SERVICE_TYPE_REQUEST: u8 = 0;
const SERVICE_TYPE_RESPONSE_SUCCESS: u8 = 1;

// DCP Block Options
const OPTION_IP: u8 = 1;
const OPTION_DEVICE: u8 = 2;

// IP Suboptions
const SUBOPTION_IP_MAC: u8 = 1;
const SUBOPTION_IP_PARAM: u8 = 2;

// Device Suboptions
const SUBOPTION_DEVICE_VENDOR: u8 = 1;
const SUBOPTION_DEVICE_NAME: u8 = 2;
const SUBOPTION_DEVICE_ID: u8 = 3;
const SUBOPTION_DEVICE_ROLE: u8 = 4;
const SUBOPTION_DEVICE_OPTIONS: u8 = 5;
const SUBOPTION_DEVICE_ALIAS: u8 = 6;

#[derive(Serialize, Deserialize, Clone)]
pub struct DcpDevice {
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_of_station: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_of_station: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct DcpIdentifyResult {
    pub interface: String,
    pub devices: Vec<DcpDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DcpGetResult {
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<DcpDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn format_mac(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

fn format_ip(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        String::new()
    }
}

fn parse_mac_address(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

fn option_description(option: u8, suboption: u8) -> String {
    match (option, suboption) {
        (OPTION_IP, SUBOPTION_IP_MAC) => "IP/MAC Address".to_string(),
        (OPTION_IP, SUBOPTION_IP_PARAM) => "IP/IP Parameter".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_VENDOR) => "Device/Type of Station".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_NAME) => "Device/Name of Station".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_ID) => "Device/Device ID".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_ROLE) => "Device/Device Role".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_OPTIONS) => "Device/Device Options".to_string(),
        (OPTION_DEVICE, SUBOPTION_DEVICE_ALIAS) => "Device/Alias Name".to_string(),
        _ => format!("Option {}/Suboption {}", option, suboption),
    }
}

fn device_role_name(role: u8) -> &'static str {
    match role {
        1 => "IO Device",
        2 => "IO Controller",
        4 => "IO Multidevice",
        8 => "IO Supervisor",
        _ => "Unknown",
    }
}

struct DcpBlock {
    option: u8,
    suboption: u8,
    data: Vec<u8>,
}

fn parse_dcp_blocks(data: &[u8]) -> Vec<DcpBlock> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let option = data[offset];
        let suboption = data[offset + 1];
        let block_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + block_len > data.len() {
            break;
        }

        blocks.push(DcpBlock {
            option,
            suboption,
            data: data[offset..offset + block_len].to_vec(),
        });

        // DCP blocks are padded to even length
        let padded_len = if block_len % 2 != 0 { block_len + 1 } else { block_len };
        offset += padded_len;
    }

    blocks
}

fn apply_blocks_to_device(device: &mut DcpDevice, blocks: &[DcpBlock]) {
    for block in blocks {
        match (block.option, block.suboption) {
            (OPTION_IP, SUBOPTION_IP_MAC) if block.data.len() >= 6 => {
                device.mac = format_mac(&block.data[..6]);
            }
            (OPTION_IP, SUBOPTION_IP_PARAM) if block.data.len() >= 14 => {
                // First 2 bytes are block info (padding/flags), then IP data
                let ip_offset = if block.data.len() >= 14 { 2 } else { 0 };
                device.ip = Some(format_ip(&block.data[ip_offset..ip_offset + 4]));
                device.subnet_mask = Some(format_ip(&block.data[ip_offset + 4..ip_offset + 8]));
                device.gateway = Some(format_ip(&block.data[ip_offset + 8..ip_offset + 12]));
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_VENDOR) => {
                // First 2 bytes are block info
                let text_offset = if block.data.len() > 2 { 2 } else { 0 };
                device.type_of_station = Some(
                    String::from_utf8_lossy(&block.data[text_offset..])
                        .trim_end_matches('\0')
                        .to_string()
                );
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_NAME) => {
                let text_offset = if block.data.len() > 2 { 2 } else { 0 };
                device.name_of_station = Some(
                    String::from_utf8_lossy(&block.data[text_offset..])
                        .trim_end_matches('\0')
                        .to_string()
                );
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_ID) if block.data.len() >= 6 => {
                // First 2 bytes are block info, then vendor_id (2) + device_id (2)
                let id_offset = 2;
                device.vendor_id = Some(u16::from_be_bytes([block.data[id_offset], block.data[id_offset + 1]]));
                device.device_id = Some(u16::from_be_bytes([block.data[id_offset + 2], block.data[id_offset + 3]]));
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_ROLE) if block.data.len() >= 3 => {
                let role_offset = 2;
                device.device_role = Some(device_role_name(block.data[role_offset]).to_string());
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_OPTIONS) if block.data.len() >= 4 => {
                let mut opts = Vec::new();
                let opt_offset = 2; // skip block info
                let mut i = opt_offset;
                while i + 2 <= block.data.len() {
                    opts.push(option_description(block.data[i], block.data[i + 1]));
                    i += 2;
                }
                device.options = Some(opts);
            }
            (OPTION_DEVICE, SUBOPTION_DEVICE_ALIAS) => {
                let text_offset = if block.data.len() > 2 { 2 } else { 0 };
                device.alias_name = Some(
                    String::from_utf8_lossy(&block.data[text_offset..])
                        .trim_end_matches('\0')
                        .to_string()
                );
            }
            _ => {}
        }
    }
}

fn parse_dcp_response(frame: &[u8], expected_xid: u32) -> Option<DcpDevice> {
    let ethernet = EthernetPacket::new(frame)?;

    if ethernet.get_ethertype().0 != PROFINET_ETHERTYPE {
        return None;
    }

    let source_mac = format_mac(&ethernet.get_source().octets());
    let payload = ethernet.payload();

    // DCP header: Frame ID (2) + Service ID (1) + Service Type (1) + Xid (4) + Response Delay (2) + Data Length (2)
    if payload.len() < 12 {
        return None;
    }

    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    // Accept Identify Response (0xFEFF) or Get/Set Response (0xFEFD)
    if frame_id != FRAME_ID_IDENTIFY_RESPONSE && frame_id != FRAME_ID_GET_SET {
        return None;
    }

    let service_id = payload[2];
    let service_type = payload[3];

    if service_type != SERVICE_TYPE_RESPONSE_SUCCESS {
        return None;
    }
    if service_id != SERVICE_ID_IDENTIFY && service_id != SERVICE_ID_GET {
        return None;
    }

    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if xid != expected_xid {
        return None;
    }

    let data_length = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    let dcp_data = if payload.len() >= 12 + data_length {
        &payload[12..12 + data_length]
    } else {
        &payload[12..]
    };

    let blocks = parse_dcp_blocks(dcp_data);

    let mut device = DcpDevice {
        mac: source_mac,
        name_of_station: None,
        type_of_station: None,
        ip: None,
        subnet_mask: None,
        gateway: None,
        vendor_id: None,
        device_id: None,
        device_role: None,
        alias_name: None,
        options: None,
    };

    apply_blocks_to_device(&mut device, &blocks);

    Some(device)
}

fn build_dcp_identify_request(src_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    // DCP payload: Frame ID (2) + Service ID (1) + Service Type (1) + Xid (4) + Response Delay (2) + Data Length (2) + Block (4)
    let mut dcp_payload = Vec::new();

    // Frame ID: Identify Request multicast
    dcp_payload.extend_from_slice(&FRAME_ID_IDENTIFY_REQUEST.to_be_bytes());
    // Service ID: Identify
    dcp_payload.push(SERVICE_ID_IDENTIFY);
    // Service Type: Request
    dcp_payload.push(SERVICE_TYPE_REQUEST);
    // Xid
    dcp_payload.extend_from_slice(&xid.to_be_bytes());
    // Response Delay: 1 second (in units of 10ms = 100)
    dcp_payload.extend_from_slice(&100u16.to_be_bytes());
    // Data Length: 4 bytes (one "all" block)
    dcp_payload.extend_from_slice(&4u16.to_be_bytes());

    // Identify All block: Option 0xFF, Suboption 0xFF, Length 0
    dcp_payload.push(0xFF); // Option: All
    dcp_payload.push(0xFF); // Suboption: All
    dcp_payload.extend_from_slice(&0u16.to_be_bytes()); // Length: 0

    // Build Ethernet frame
    let frame_len = 14 + dcp_payload.len();
    let mut frame = vec![0u8; frame_len];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut frame[..]).unwrap();
        ethernet.set_destination(MacAddr::new(
            DCP_MULTICAST_ADDR[0], DCP_MULTICAST_ADDR[1], DCP_MULTICAST_ADDR[2],
            DCP_MULTICAST_ADDR[3], DCP_MULTICAST_ADDR[4], DCP_MULTICAST_ADDR[5],
        ));
        ethernet.set_source(MacAddr::new(src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]));
        ethernet.set_ethertype(pnet::packet::ethernet::EtherType(PROFINET_ETHERTYPE));
    }
    frame[14..].copy_from_slice(&dcp_payload);

    frame
}

fn build_dcp_get_request(src_mac: &[u8; 6], dst_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    // Build a Get request that asks for all common options
    let mut blocks_data = Vec::new();

    // Request IP parameters
    blocks_data.push(OPTION_IP);
    blocks_data.push(SUBOPTION_IP_PARAM);
    blocks_data.extend_from_slice(&0u16.to_be_bytes());

    // Request Name of Station
    blocks_data.push(OPTION_DEVICE);
    blocks_data.push(SUBOPTION_DEVICE_NAME);
    blocks_data.extend_from_slice(&0u16.to_be_bytes());

    // Request Type of Station
    blocks_data.push(OPTION_DEVICE);
    blocks_data.push(SUBOPTION_DEVICE_VENDOR);
    blocks_data.extend_from_slice(&0u16.to_be_bytes());

    // Request Device ID
    blocks_data.push(OPTION_DEVICE);
    blocks_data.push(SUBOPTION_DEVICE_ID);
    blocks_data.extend_from_slice(&0u16.to_be_bytes());

    // Request Device Role
    blocks_data.push(OPTION_DEVICE);
    blocks_data.push(SUBOPTION_DEVICE_ROLE);
    blocks_data.extend_from_slice(&0u16.to_be_bytes());

    let mut dcp_payload = Vec::new();

    // Frame ID: Get/Set
    dcp_payload.extend_from_slice(&FRAME_ID_GET_SET.to_be_bytes());
    // Service ID: Get
    dcp_payload.push(SERVICE_ID_GET);
    // Service Type: Request
    dcp_payload.push(SERVICE_TYPE_REQUEST);
    // Xid
    dcp_payload.extend_from_slice(&xid.to_be_bytes());
    // Response Delay: 0 (unicast)
    dcp_payload.extend_from_slice(&0u16.to_be_bytes());
    // Data Length
    dcp_payload.extend_from_slice(&(blocks_data.len() as u16).to_be_bytes());
    // Blocks
    dcp_payload.extend_from_slice(&blocks_data);

    // Build Ethernet frame
    let frame_len = 14 + dcp_payload.len();
    let mut frame = vec![0u8; frame_len];
    {
        let mut ethernet = MutableEthernetPacket::new(&mut frame[..]).unwrap();
        ethernet.set_destination(MacAddr::new(dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]));
        ethernet.set_source(MacAddr::new(src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]));
        ethernet.set_ethertype(pnet::packet::ethernet::EtherType(PROFINET_ETHERTYPE));
    }
    frame[14..].copy_from_slice(&dcp_payload);

    frame
}

fn generate_xid() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    nanos ^ 0xDEADBEEF
}

pub fn dcp_identify(iface_name: &str, timeout_ms: u32) -> String {
    let resolved_name = crate::l2::interfaces::resolve_interface_name(iface_name);

    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == resolved_name) {
        Some(i) => i,
        None => {
            let result = DcpIdentifyResult {
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
            let result = DcpIdentifyResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some("No MAC address found on interface".to_string()),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let xid = generate_xid();

    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return DcpIdentifyResult {
                    interface: iface_name.to_string(),
                    devices: vec![],
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(&resolved_name).await {
            return DcpIdentifyResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Send Identify request
        let request = build_dcp_identify_request(&src_mac, xid);
        if let Err(e) = socket.write_all(&request).await {
            return DcpIdentifyResult {
                interface: iface_name.to_string(),
                devices: vec![],
                error: Some(format!("Failed to send DCP Identify request: {}", e)),
            };
        }

        let mut devices: HashMap<String, DcpDevice> = HashMap::new();
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
                    if let Some(device) = parse_dcp_response(&buffer[..n], xid) {
                        devices.insert(device.mac.clone(), device);
                    }
                }
                Ok(Ok(_)) => break,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        let mut device_list: Vec<DcpDevice> = devices.into_values().collect();
        device_list.sort_by(|a, b| a.mac.cmp(&b.mac));

        DcpIdentifyResult {
            interface: iface_name.to_string(),
            devices: device_list,
            error: None,
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

pub fn dcp_get(iface_name: &str, target_mac_str: &str, timeout_ms: u32) -> String {
    let resolved_name = crate::l2::interfaces::resolve_interface_name(iface_name);

    let target_mac = match parse_mac_address(target_mac_str) {
        Some(mac) => mac,
        None => {
            let result = DcpGetResult {
                interface: iface_name.to_string(),
                device: None,
                error: Some(format!("Invalid MAC address: {}", target_mac_str)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let interfaces = datalink::interfaces();
    let iface = match interfaces.iter().find(|i| i.name == resolved_name) {
        Some(i) => i,
        None => {
            let result = DcpGetResult {
                interface: iface_name.to_string(),
                device: None,
                error: Some(format!("Interface {} not found", iface_name)),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let src_mac = match iface.mac {
        Some(mac) => mac.octets(),
        None => {
            let result = DcpGetResult {
                interface: iface_name.to_string(),
                device: None,
                error: Some("No MAC address found on interface".to_string()),
            };
            return serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string());
        }
    };

    let xid = generate_xid();

    let result = block_on(async {
        let mut socket = match RawSocket::new().await {
            Ok(s) => s,
            Err(e) => {
                return DcpGetResult {
                    interface: iface_name.to_string(),
                    device: None,
                    error: Some(format!("Failed to create raw socket: {}", e)),
                };
            }
        };

        if let Err(e) = socket.bind(&resolved_name).await {
            return DcpGetResult {
                interface: iface_name.to_string(),
                device: None,
                error: Some(format!("Failed to bind socket: {}", e)),
            };
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Send Get request
        let request = build_dcp_get_request(&src_mac, &target_mac, xid);
        if let Err(e) = socket.write_all(&request).await {
            return DcpGetResult {
                interface: iface_name.to_string(),
                device: None,
                error: Some(format!("Failed to send DCP Get request: {}", e)),
            };
        }

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
                    if let Some(device) = parse_dcp_response(&buffer[..n], xid) {
                        return DcpGetResult {
                            interface: iface_name.to_string(),
                            device: Some(device),
                            error: None,
                        };
                    }
                }
                Ok(Ok(_)) => break,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        DcpGetResult {
            interface: iface_name.to_string(),
            device: None,
            error: Some(format!("No response from {}", target_mac_str)),
        }
    });

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        assert!(parse_mac_address("invalid").is_none());
        assert!(parse_mac_address("aa:bb:cc").is_none());
    }

    #[test]
    fn test_format_ip() {
        assert_eq!(format_ip(&[192, 168, 1, 100]), "192.168.1.100");
        assert_eq!(format_ip(&[0, 0, 0, 0]), "0.0.0.0");
    }

    #[test]
    fn test_parse_dcp_blocks() {
        let mut data = Vec::new();
        // Block: Option 2 (Device), Suboption 2 (Name), Length 10, block_info (2) + "testdev\0"
        data.push(OPTION_DEVICE);
        data.push(SUBOPTION_DEVICE_NAME);
        data.extend_from_slice(&10u16.to_be_bytes()); // length
        data.extend_from_slice(&[0x00, 0x00]); // block info
        data.extend_from_slice(b"testdev\0");

        let blocks = parse_dcp_blocks(&data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].option, OPTION_DEVICE);
        assert_eq!(blocks[0].suboption, SUBOPTION_DEVICE_NAME);
    }

    #[test]
    fn test_apply_blocks_to_device() {
        let blocks = vec![
            DcpBlock {
                option: OPTION_DEVICE,
                suboption: SUBOPTION_DEVICE_NAME,
                data: vec![0x00, 0x00, b'm', b'y', b'p', b'l', b'c'],
            },
            DcpBlock {
                option: OPTION_IP,
                suboption: SUBOPTION_IP_PARAM,
                data: vec![
                    0x00, 0x00, // block info
                    192, 168, 1, 100, // IP
                    255, 255, 255, 0, // Subnet
                    192, 168, 1, 1, // Gateway
                ],
            },
        ];

        let mut device = DcpDevice {
            mac: "00:00:00:00:00:00".to_string(),
            name_of_station: None,
            type_of_station: None,
            ip: None,
            subnet_mask: None,
            gateway: None,
            vendor_id: None,
            device_id: None,
            device_role: None,
            alias_name: None,
            options: None,
        };

        apply_blocks_to_device(&mut device, &blocks);
        assert_eq!(device.name_of_station, Some("myplc".to_string()));
        assert_eq!(device.ip, Some("192.168.1.100".to_string()));
        assert_eq!(device.subnet_mask, Some("255.255.255.0".to_string()));
        assert_eq!(device.gateway, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_build_dcp_identify_request() {
        let src_mac = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let xid = 0x12345678;
        let frame = build_dcp_identify_request(&src_mac, xid);

        // Verify Ethernet header
        let ethernet = EthernetPacket::new(&frame).expect("Failed to parse Ethernet packet");
        assert_eq!(ethernet.get_ethertype().0, PROFINET_ETHERTYPE);
        assert_eq!(ethernet.get_destination(), MacAddr::new(0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00));
        assert_eq!(ethernet.get_source(), MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC));

        // Verify DCP header
        let payload = ethernet.payload();
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(frame_id, FRAME_ID_IDENTIFY_REQUEST);
        assert_eq!(payload[2], SERVICE_ID_IDENTIFY);
        assert_eq!(payload[3], SERVICE_TYPE_REQUEST);

        let parsed_xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        assert_eq!(parsed_xid, xid);
    }

    #[test]
    fn test_device_role_name() {
        assert_eq!(device_role_name(1), "IO Device");
        assert_eq!(device_role_name(2), "IO Controller");
        assert_eq!(device_role_name(8), "IO Supervisor");
    }
}
