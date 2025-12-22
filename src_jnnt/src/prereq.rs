use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PrerequisitesResult {
    pub status: String,
    pub error: Option<String>,
}

#[cfg(target_os = "windows")]
pub fn check_prerequisites() -> String {
    // On Windows, check if Npcap (wpcap.dll) is available
    // We can do this by trying to list devices using pcap
    match pcap::Device::list() {
        Ok(_) => {
            serde_json::to_string(&PrerequisitesResult {
                status: "OK".to_string(),
                error: None,
            })
            .unwrap_or_else(|_| r#"{"status":"OK"}"#.to_string())
        }
        Err(e) => {
            serde_json::to_string(&PrerequisitesResult {
                status: "Error".to_string(),
                error: Some(format!(
                    "Npcap (wpcap.dll) not found or not accessible. Please install Npcap with 'WinPcap API-compatible mode' enabled. Error: {}",
                    e
                )),
            })
            .unwrap_or_else(|_| r#"{"status":"Error","error":"Failed to serialize error"}"#.to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_prerequisites() -> String {
    // On Linux and macOS, no special prerequisites are required
    // (Linux uses AF_PACKET, macOS uses BPF devices)
    serde_json::to_string(&PrerequisitesResult {
        status: "OK".to_string(),
        error: None,
    })
    .unwrap_or_else(|_| r#"{"status":"OK"}"#.to_string())
}

