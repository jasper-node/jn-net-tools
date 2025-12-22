use serde::{Deserialize, Serialize};
use serde_json;
use std::time::Instant;
use hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use hickory_resolver::TokioAsyncResolver;
use std::net::SocketAddr;
use crate::runtime::block_on;

#[derive(Serialize, Deserialize)]
pub struct DnsResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn dns_lookup(domain: &str, server: Option<&str>, record_type: Option<&str>) -> String {
    let start = Instant::now();
    
    let result: Result<Vec<String>, String> = block_on(async {
        let resolver = if let Some(srv) = server {
            if srv.is_empty() {
                 match TokioAsyncResolver::tokio_from_system_conf() {
                    Ok(r) => r,
                    Err(e) => return Err(format!("Failed to load system config: {}", e)),
                }
            } else {
                let mut config = ResolverConfig::new();
                let socket_addr: SocketAddr = if srv.contains(':') {
                    srv.parse().map_err(|e| format!("Invalid server address: {}", e))?
                } else {
                    format!("{}:53", srv).parse().map_err(|e| format!("Invalid server address: {}", e))?
                };
                
                config.add_name_server(NameServerConfig::new(
                    socket_addr,
                    Protocol::Udp,
                ));
                
                TokioAsyncResolver::tokio(config, ResolverOpts::default())
            }
        } else {
             match TokioAsyncResolver::tokio_from_system_conf() {
                Ok(r) => r,
                Err(e) => return Err(format!("Failed to load system config: {}", e)),
            }
        };

        let rtype = match record_type.unwrap_or("A").to_uppercase().as_str() {
             "A" => hickory_resolver::proto::rr::RecordType::A,
             "AAAA" => hickory_resolver::proto::rr::RecordType::AAAA,
             "MX" => hickory_resolver::proto::rr::RecordType::MX,
             "TXT" => hickory_resolver::proto::rr::RecordType::TXT,
             "NS" => hickory_resolver::proto::rr::RecordType::NS,
             "CNAME" => hickory_resolver::proto::rr::RecordType::CNAME,
             "PTR" => hickory_resolver::proto::rr::RecordType::PTR,
             "SOA" => hickory_resolver::proto::rr::RecordType::SOA,
             "SRV" => hickory_resolver::proto::rr::RecordType::SRV,
             _ => hickory_resolver::proto::rr::RecordType::A,
        };

        match resolver.lookup(domain, rtype).await {
            Ok(response) => {
                 let records: Vec<String> = response.iter()
                    .map(|r| r.to_string())
                    .collect();
                Ok(records)
            }
            Err(e) => Err(format!("Lookup failed: {}", e)),
        }
    });

    match result {
        Ok(records) => {
             let dns_result = DnsResult {
                status: "OK".to_string(),
                time_ms: Some(start.elapsed().as_millis() as f64),
                records: Some(records),
                error: None,
            };
            serde_json::to_string(&dns_result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
        }
        Err(e) => {
             let dns_result = DnsResult {
                status: "Error".to_string(),
                time_ms: Some(start.elapsed().as_millis() as f64),
                records: None,
                error: Some(e),
            };
            serde_json::to_string(&dns_result).unwrap_or_else(|_| r#"{"error":"JSON serialization failed"}"#.to_string())
        }
    }
}

pub fn resolve_v4(target: &str) -> Result<std::net::Ipv4Addr, String> {
    use std::net::ToSocketAddrs;
    
    // Fast path: try to parse as IPv4 address directly
    if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
        return Ok(ip);
    }
    
    // Append port 0 to make it a valid socket address string for ToSocketAddrs
    let target_with_port = format!("{}:0", target);
    
    match target_with_port.to_socket_addrs() {
        Ok(addrs) => {
            // Find the first IPv4 address
            for addr in addrs {
                if let SocketAddr::V4(v4_addr) = addr {
                    return Ok(*v4_addr.ip());
                }
            }
            Err(format!("No IPv4 address found for {}", target))
        },
        Err(e) => Err(format!("Failed to resolve {}: {}", target, e))
    }
}

