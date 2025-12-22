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
