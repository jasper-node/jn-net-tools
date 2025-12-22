use pnet::datalink;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub subnet_masks: Vec<String>,
    pub is_up: bool,
}

pub fn get_interfaces() -> String {
    let interfaces = datalink::interfaces();
    let mut result = Vec::new();

    for iface in interfaces {
        let mut ips = Vec::new();
        let mut subnet_masks = Vec::new();
        let is_up = iface.is_up();
        let name = iface.name.clone();
        let mac = iface.mac.map(|m| m.to_string()).unwrap_or_else(|| "".to_string());

        for ip in &iface.ips {
            ips.push(ip.ip().to_string());
            subnet_masks.push(ip.mask().to_string());
        }

        result.push(InterfaceInfo {
            name,
            mac,
            ips,
            subnet_masks,
            is_up,
        });
    }

    serde_json::to_string(&result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
}

