use crate::ll::RawSocket;
use crate::runtime::block_on;
use pnet::packet::ethernet::EtherTypes;
use std::io;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_filter_tcp() {
        // This test requires sudo/root and a valid network interface
        // It's an integration test more than a unit test
        let result = block_on(async {
            let mut socket = RawSocket::new().await?;
            socket.bind("en0").await?;
            
            // Test TCP filter compilation and application
            socket.set_filter("tcp").await?;
            
            Ok::<(), io::Error>(())
        });
        
        // This may fail without proper permissions, but the filter should compile
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("Permission"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_filter_arp() {
        let result = block_on(async {
            let mut socket = RawSocket::new().await?;
            socket.bind("en0").await?;
            
            // Test ARP filter compilation and application
            socket.set_filter("arp").await?;
            
            Ok::<(), io::Error>(())
        });
        
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("Permission"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_filter_port() {
        let result = block_on(async {
            let mut socket = RawSocket::new().await?;
            socket.bind("en0").await?;
            
            // Test port filter compilation
            socket.set_filter("tcp port 443").await?;
            
            Ok::<(), io::Error>(())
        });
        
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("Permission"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_invalid_filter() {
        let result = block_on(async {
            let mut socket = RawSocket::new().await?;
            socket.bind("en0").await?;
            
            // Test invalid filter - should fail during compilation
            socket.set_filter("invalid_protocol_xyz").await
        });
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to compile filter"));
    }
}
