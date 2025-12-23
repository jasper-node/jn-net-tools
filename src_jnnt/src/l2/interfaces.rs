use pnet::datalink;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::ERROR_BUFFER_OVERFLOW,
    NetworkManagement::{IpHelper, Ndis},
    Networking::WinSock::{AF_UNSPEC, AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6},
};

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *const std::ffi::c_void,
        adapter_addresses: *mut IpHelper::IP_ADAPTER_ADDRESSES_LH,
        size: *mut u32,
    ) -> u32;
}

#[derive(Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub subnet_masks: Vec<String>,
    pub is_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct InterfaceDetail {
    pub name: String,
    pub system_name: String,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub is_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(target_os = "windows")]
fn get_windows_interface_info() -> HashMap<String, (String, bool)> {
    let mut map = HashMap::new();
    
    unsafe {
        let mut buffer_size = 0u32;
        let flags = IpHelper::GAA_FLAG_INCLUDE_PREFIX;
        
        // First call to get required buffer size
        let result = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut buffer_size,
        );
        
        if result == ERROR_BUFFER_OVERFLOW as u32 {
            let mut buffer = vec![0u8; buffer_size as usize];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IpHelper::IP_ADAPTER_ADDRESSES_LH;
            
            let result = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                adapter_addresses,
                &mut buffer_size,
            );
            
            if result == 0 {
                let mut current = adapter_addresses;
                while !current.is_null() {
                    let adapter = *current;
                    
                    // Get adapter name (GUID)
                    let adapter_name = if adapter.AdapterName.is_null() {
                        String::new()
                    } else {
                        std::ffi::CStr::from_ptr(adapter.AdapterName as *const i8)
                            .to_string_lossy()
                            .to_string()
                    };
                    
                    // Get friendly name (wide string)
                    let friendly_name = if adapter.FriendlyName.is_null() {
                        String::new()
                    } else {
                        let mut len = 0;
                        let mut ptr = adapter.FriendlyName;
                        while *ptr != 0 {
                            len += 1;
                            ptr = ptr.add(1);
                        }
                        String::from_utf16_lossy(std::slice::from_raw_parts(adapter.FriendlyName, len))
                    };
                    
                    // Get operational status (IfOperStatusUp = 1)
                    let is_up = adapter.OperStatus == Ndis::IfOperStatusUp as i32;
                    
                    if !adapter_name.is_empty() {
                        // Store both the GUID and the NPF format
                        let npf_name = format!("\\Device\\NPF_{}", adapter_name);
                        map.insert(adapter_name.clone(), (friendly_name.clone(), is_up));
                        map.insert(npf_name, (friendly_name, is_up));
                    }
                    
                    current = adapter.Next;
                }
            }
        }
    }
    
    map
}

#[cfg(target_os = "windows")]
pub fn resolve_interface_name(name: &str) -> String {
    let info_map = get_windows_interface_info();
    
    // Check if it's already a system name (GUID or NPF format)
    if name.starts_with("\\Device\\NPF_") || name.starts_with("{") {
        return name.to_string();
    }
    
    // Try to find by friendly name - prefer NPF format
    let mut found_npf: Option<String> = None;
    let mut found_guid: Option<String> = None;
    
    for (system_name, (friendly, _)) in &info_map {
        if friendly == name {
            if system_name.starts_with("\\Device\\NPF_") {
                found_npf = Some(system_name.clone());
            } else if found_guid.is_none() {
                found_guid = Some(system_name.clone());
            }
        }
    }
    
    // Prefer NPF format, fallback to GUID
    if let Some(npf) = found_npf {
        return npf;
    }
    if let Some(guid) = found_guid {
        return guid;
    }
    
    // If not found, return as-is (might be a valid name we don't know about)
    name.to_string()
}

#[cfg(not(target_os = "windows"))]
pub fn resolve_interface_name(name: &str) -> String {
    name.to_string()
}

#[cfg(target_os = "windows")]
fn get_windows_interface_details() -> Vec<InterfaceDetail> {
    let mut result = Vec::new();
    
    unsafe {
        let mut buffer_size = 0u32;
        let flags = IpHelper::GAA_FLAG_INCLUDE_PREFIX | IpHelper::GAA_FLAG_INCLUDE_GATEWAYS | IpHelper::GAA_FLAG_INCLUDE_ALL_INTERFACES;
        
        // First call to get required buffer size
        let status = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut buffer_size,
        );
        
        if status == ERROR_BUFFER_OVERFLOW as u32 {
            let mut buffer = vec![0u8; buffer_size as usize];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IpHelper::IP_ADAPTER_ADDRESSES_LH;
            
            let status = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                adapter_addresses,
                &mut buffer_size,
            );
            
            if status == 0 {
                let mut current = adapter_addresses;
                while !current.is_null() {
                    let adapter = *current;
                    
                    // Get adapter name (GUID)
                    let adapter_name = if adapter.AdapterName.is_null() {
                        String::new()
                    } else {
                        std::ffi::CStr::from_ptr(adapter.AdapterName as *const i8)
                            .to_string_lossy()
                            .to_string()
                    };
                    
                    // Get friendly name (wide string)
                    let friendly_name = if adapter.FriendlyName.is_null() {
                        String::new()
                    } else {
                        let mut len = 0;
                        let mut ptr = adapter.FriendlyName;
                        while *ptr != 0 {
                            len += 1;
                            ptr = ptr.add(1);
                        }
                        String::from_utf16_lossy(std::slice::from_raw_parts(adapter.FriendlyName, len))
                    };
                    
                    // Get description (wide string)
                    let description = if adapter.Description.is_null() {
                        None
                    } else {
                        let mut len = 0;
                        let mut ptr = adapter.Description;
                        while *ptr != 0 {
                            len += 1;
                            ptr = ptr.add(1);
                        }
                        Some(String::from_utf16_lossy(std::slice::from_raw_parts(adapter.Description, len)))
                    };
                    
                    // Get operational status
                    let is_up = adapter.OperStatus == Ndis::IfOperStatusUp as i32;
                    
                    // Get system name (NPF format)
                    let system_name = if adapter_name.is_empty() {
                        friendly_name.clone()
                    } else {
                        format!("\\Device\\NPF_{}", adapter_name)
                    };
                    
                    // Extract gateways
                    let mut gateways = Vec::new();
                    let mut gateway_current = adapter.FirstGatewayAddress;
                    while !gateway_current.is_null() {
                        let gateway = *gateway_current;
                        let sockaddr = gateway.Address.lpSockaddr;
                        if !sockaddr.is_null() {
                            let sa = *sockaddr;
                            if sa.sa_family == AF_INET as u16 {
                                let sin = &*(sockaddr as *const SOCKADDR_IN);
                                let ip_u32 = sin.sin_addr.S_un.S_addr;
                                let ip_bytes = ip_u32.to_ne_bytes();
                                let ip = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                                gateways.push(ip);
                            } else if sa.sa_family == AF_INET6 as u16 {
                                let sin6 = &*(sockaddr as *const SOCKADDR_IN6);
                                let ip_bytes = sin6.sin6_addr.u.Byte;
                                let ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                                    ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                                    ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                                    ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
                                gateways.push(ip);
                            }
                        }
                        gateway_current = gateway.Next;
                    }
                    
                    // Extract DNS servers
                    let mut dns_servers = Vec::new();
                    let mut dns_current = adapter.FirstDnsServerAddress;
                    while !dns_current.is_null() {
                        let dns = *dns_current;
                        let sockaddr = dns.Address.lpSockaddr;
                        if !sockaddr.is_null() {
                            let sa = *sockaddr;
                            if sa.sa_family == AF_INET as u16 {
                                let sin = &*(sockaddr as *const SOCKADDR_IN);
                                let ip_u32 = sin.sin_addr.S_un.S_addr;
                                let ip_bytes = ip_u32.to_ne_bytes();
                                let ip = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                                dns_servers.push(ip);
                            } else if sa.sa_family == AF_INET6 as u16 {
                                let sin6 = &*(sockaddr as *const SOCKADDR_IN6);
                                let ip_bytes = sin6.sin6_addr.u.Byte;
                                let ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                                    ip_bytes[4], ip_bytes[5], ip_bytes[6], ip_bytes[7],
                                    ip_bytes[8], ip_bytes[9], ip_bytes[10], ip_bytes[11],
                                    ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15]);
                                dns_servers.push(ip);
                            }
                        }
                        dns_current = dns.Next;
                    }
                    
                    // Use friendly name as the join key, fallback to system name
                    let name = if friendly_name.is_empty() {
                        system_name.clone()
                    } else {
                        friendly_name.clone()
                    };
                    
                    result.push(InterfaceDetail {
                        name,
                        system_name,
                        gateways,
                        dns_servers,
                        is_up,
                        description,
                    });
                    
                    current = adapter.Next;
                }
            }
        }
    }
    
    result
}

#[cfg(target_os = "linux")]
fn get_linux_interface_details() -> Vec<InterfaceDetail> {
    let mut result = Vec::new();
    let interfaces = datalink::interfaces();
    
    // Read DNS servers from /etc/resolv.conf (global)
    let dns_servers = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            content.lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.starts_with("nameserver ") {
                        Some(line[11..].trim().to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        }
        Err(_) => Vec::new(),
    };
    
    // Read gateways from /proc/net/route
    let mut gateway_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let iface = parts[0].to_string();
                let dest = parts[1];
                let gateway = parts[2];
                
                // Default route (destination 00000000)
                if dest == "00000000" && gateway != "00000000" {
                    // Convert hex gateway to IP
                    if let Ok(gw_u32) = u32::from_str_radix(gateway, 16) {
                        let gw_bytes = gw_u32.to_ne_bytes();
                        let gw_ip = format!("{}.{}.{}.{}", gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3]);
                        gateway_map.entry(iface).or_insert_with(Vec::new).push(gw_ip);
                    }
                }
            }
        }
    }
    
    for iface in interfaces {
        let name = iface.name.clone();
        let system_name = name.clone();
        let is_up = iface.is_up();
        let gateways = gateway_map.get(&name).cloned().unwrap_or_default();
        
        result.push(InterfaceDetail {
            name,
            system_name,
            gateways,
            dns_servers: dns_servers.clone(),
            is_up,
            description: None,
        });
    }
    
    result
}

#[cfg(target_os = "macos")]
fn get_macos_interface_details() -> Vec<InterfaceDetail> {
    let mut result = Vec::new();
    let interfaces = datalink::interfaces();
    
    // Read DNS servers from /etc/resolv.conf (global)
    let dns_servers = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(content) => {
            content.lines()
                .filter_map(|line| {
                    let line = line.trim();
                    if line.starts_with("nameserver ") {
                        Some(line[11..].trim().to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
        }
        Err(_) => Vec::new(),
    };
    
    // Get gateways from netstat -rn
    let mut gateway_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    if let Ok(output) = std::process::Command::new("netstat")
        .args(&["-rn"])
        .output()
    {
        if let Ok(output_str) = String::from_utf8(output.stdout) {
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[0] == "default" {
                    let gateway = parts[1];
                    // Try to find which interface this gateway belongs to
                    // This is a simplified approach - we'll assign to the first non-loopback interface
                    for iface in &interfaces {
                        if !iface.is_loopback() && !iface.ips.is_empty() {
                            gateway_map.entry(iface.name.clone()).or_insert_with(Vec::new).push(gateway.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
    
    for iface in interfaces {
        let name = iface.name.clone();
        let system_name = name.clone();
        let is_up = iface.is_up();
        let gateways = gateway_map.get(&name).cloned().unwrap_or_default();
        
        result.push(InterfaceDetail {
            name,
            system_name,
            gateways,
            dns_servers: dns_servers.clone(),
            is_up,
            description: None,
        });
    }
    
    result
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_other_interface_details() -> Vec<InterfaceDetail> {
    let mut result = Vec::new();
    let interfaces = datalink::interfaces();
    
    for iface in interfaces {
        result.push(InterfaceDetail {
            name: iface.name.clone(),
            system_name: iface.name.clone(),
            gateways: Vec::new(),
            dns_servers: Vec::new(),
            is_up: iface.is_up(),
            description: None,
        });
    }
    
    result
}

pub fn get_interface_details() -> String {
    #[cfg(target_os = "windows")]
    let details = get_windows_interface_details();
    
    #[cfg(target_os = "linux")]
    let details = get_linux_interface_details();
    
    #[cfg(target_os = "macos")]
    let details = get_macos_interface_details();
    
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let details = get_other_interface_details();
    
    serde_json::to_string(&details).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

pub fn get_interfaces() -> String {
    let interfaces = datalink::interfaces();
    let mut result = Vec::new();

    #[cfg(target_os = "windows")]
    let windows_info = get_windows_interface_info();

    for iface in interfaces {
        let mut ips = Vec::new();
        let mut subnet_masks = Vec::new();
        let name = iface.name.clone();
        let mac = iface.mac.map(|m| m.to_string()).unwrap_or_else(|| "".to_string());

        for ip in &iface.ips {
            ips.push(ip.ip().to_string());
            subnet_masks.push(ip.mask().to_string());
        }

        #[cfg(target_os = "windows")]
        let (is_up, friendly_name) = {
            if let Some((friendly, status)) = windows_info.get(&name) {
                (*status, Some(friendly.clone()))
            } else {
                // Fallback to pnet's is_up if not found in Windows info
                (iface.is_up(), None)
            }
        };

        #[cfg(not(target_os = "windows"))]
        let (is_up, friendly_name) = (iface.is_up(), None);

        result.push(InterfaceInfo {
            name,
            mac,
            ips,
            subnet_masks,
            is_up,
            friendly_name,
        });
    }

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

#[derive(Serialize, Deserialize)]
pub struct DefaultLocalIpResult {
    pub local_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn get_default_local_ip() -> String {
    use std::net::UdpSocket;
    
    // Connect to a public IP to determine which local interface is used
    // We use UDP and don't actually send data - just connect to get the local address
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            // Try to connect to a public DNS server (8.8.8.8:53)
            // This doesn't send data, but it tells the OS to route through the default interface
            match socket.connect("8.8.8.8:53") {
                Ok(_) => {
                    match socket.local_addr() {
                        Ok(addr) => {
                            let result = DefaultLocalIpResult {
                                local_ip: addr.ip().to_string(),
                                error: None,
                            };
                            serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
                        }
                        Err(e) => {
                            let result = DefaultLocalIpResult {
                                local_ip: String::new(),
                                error: Some(format!("Failed to get local address: {}", e)),
                            };
                            serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
                        }
                    }
                }
                Err(e) => {
                    let result = DefaultLocalIpResult {
                        local_ip: String::new(),
                        error: Some(format!("Failed to connect to determine default interface: {}", e)),
                    };
                    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
                }
            }
        }
        Err(e) => {
            let result = DefaultLocalIpResult {
                local_ip: String::new(),
                error: Some(format!("Failed to bind socket: {}", e)),
            };
            serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
        }
    }
}

