use hex_literal::hex;
use nom_derive::Parse;
use ospf_parser::*;
use std::net::Ipv4Addr;

#[test]
pub fn test_hello_packet() {
    // packet 6 of "ospf.cap" (wireshark samples)
    const OSPF_HELLO: &[u8] = &hex!(
        "
02 01 00 2c c0 a8 aa 08 00 00 00 01 27 3b 00 00
00 00 00 00 00 00 00 00 ff ff ff 00 00 0a 02 01
00 00 00 28 c0 a8 aa 08 00 00 00 00"
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_HELLO).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::Hello(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::Hello);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.network_mask(), Ipv4Addr::new(255, 255, 255, 0));
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_db_description_packet() {
    // packet 10 of "ospf.cap" (wireshark samples)
    const OSPF_DBDESC: &[u8] = &hex!(
        "
        02 02 00 20 c0 a8 aa 08 00 00 00 01 a0 52 00 00
        00 00 00 00 00 00 00 00 05 dc 02 07 41 77 a9 7e
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x4177_a97e);
        assert_eq!(pkt.lsa_headers.len(), 0);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_db_description_packet_with_lsa() {
    // packet 12 of "ospf.cap" (wireshark samples)
    const OSPF_DBDESC: &[u8] = &hex!(
        "
        02 02 00 ac c0 a8 aa 03 00 00 00 01 f0 67 00 00
        00 00 00 00 00 00 00 00 05 dc 02 02 41 77 a9 7e
        00 01 02 01 c0 a8 aa 03 c0 a8 aa 03 80 00 00 01
        3a 9c 00 30 00 02 02 05 50 d4 10 00 c0 a8 aa 02
        80 00 00 01 2a 49 00 24 00 02 02 05 94 79 ab 00
        c0 a8 aa 02 80 00 00 01 34 a5 00 24 00 02 02 05
        c0 82 78 00 c0 a8 aa 02 80 00 00 01 d3 19 00 24
        00 02 02 05 c0 a8 00 00 c0 a8 aa 02 80 00 00 01
        37 08 00 24 00 02 02 05 c0 a8 01 00 c0 a8 aa 02
        80 00 00 01 2c 12 00 24 00 02 02 05 c0 a8 ac 00
        c0 a8 aa 02 80 00 00 01 33 41 00 24
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv2Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x4177_a97e);
        assert_eq!(pkt.lsa_headers.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_request() {
    // packet 17 of "ospf.cap" (wireshark samples)
    const OSPF_LSREQ: &[u8] = &hex!(
        "
        02 03 00 24 c0 a8 aa 03 00 00 00 01 bd c7 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 08
        c0 a8 aa 08
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSREQ).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateRequest(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateRequest);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.requests.len(), 1);
        let req0 = &pkt.requests[0];
        assert_eq!(req0.link_state_type, 1);
        assert_eq!(req0.link_state_id(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(req0.advertising_router(), Ipv4Addr::new(192, 168, 170, 8));
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_request_multiple_lsa() {
    // packet 18 of "ospf.cap" (wireshark samples)
    const OSPF_LSREQ_WITH_LSA: &[u8] = &hex!(
        "
        02 03 00 6c c0 a8 aa 08 00 00 00 01 75 95 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 03
        c0 a8 aa 03 00 00 00 05 50 d4 10 00 c0 a8 aa 02
        00 00 00 05 94 79 ab 00 c0 a8 aa 02 00 00 00 05
        c0 82 78 00 c0 a8 aa 02 00 00 00 05 c0 a8 00 00
        c0 a8 aa 02 00 00 00 05 c0 a8 01 00 c0 a8 aa 02
        00 00 00 05 c0 a8 ac 00 c0 a8 aa 02
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSREQ_WITH_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateRequest(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateRequest);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.requests.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_update() {
    // packet 19 of "ospf.cap" (wireshark samples)
    const OSPF_LSUPD: &[u8] = &hex!(
        "
        02 04 00 40 c0 a8 aa 08 00 00 00 01 96 1f 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 03 e2 02 01
        c0 a8 aa 08 c0 a8 aa 08 80 00 0d c3 25 06 00 24
        02 00 00 01 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSUPD).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateUpdate(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateUpdate);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.lsa.len(), 1);
        let lsa0 = &pkt.lsa[0];
        if let OspfLinkStateAdvertisement::RouterLinks(lsa) = lsa0 {
            assert_eq!(lsa.header.link_state_type, OspfLinkStateType::RouterLinks);
            assert_eq!(
                lsa.header.advertising_router(),
                Ipv4Addr::new(192, 168, 170, 8)
            );
            assert_eq!(lsa.links.len(), 1);
            let link0 = &lsa.links[0];
            assert_eq!(link0.link_id(), Ipv4Addr::new(192, 168, 170, 0));
            assert_eq!(link0.link_data(), Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(link0.link_type, OspfRouterLinkType::Stub);
            assert_eq!(link0.tos_list.len(), 0);
        } else {
            panic!("wrong LSA type");
        }
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_ack() {
    // packet 26 of "ospf.cap" (wireshark samples)
    const OSPF_LSACK: &[u8] = &hex!(
        "
        02 05 00 2c c0 a8 aa 08 00 00 00 01 02 f2 00 00
        00 00 00 00 00 00 00 00 00 01 02 01 c0 a8 aa 03
        c0 a8 aa 03 80 00 00 02 38 9d 00 30

        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSACK).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateAcknowledgment(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(
            pkt.header.packet_type,
            OspfPacketType::LinkStateAcknowledgment
        );
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(pkt.lsa_headers.len(), 1);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_ls_update_multiple_lsa() {
    // packet 26 of "ospf.cap" (wireshark samples)
    const OSPF_LSA: &[u8] = &hex!(
        "
02 04 01 24 c0 a8 aa 03 00 00 00 01 36 6b 00 00
00 00 00 00 00 00 00 00 00 00 00 07 00 02 02 01
c0 a8 aa 03 c0 a8 aa 03 80 00 00 01 3a 9c 00 30
02 00 00 02 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
c0 a8 aa 00 ff ff ff 00 03 00 00 0a 00 03 02 05
50 d4 10 00 c0 a8 aa 02 80 00 00 01 2a 49 00 24
ff ff ff ff 80 00 00 14 00 00 00 00 00 00 00 00
00 03 02 05 94 79 ab 00 c0 a8 aa 02 80 00 00 01
34 a5 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 01
00 00 00 00 00 03 02 05 c0 82 78 00 c0 a8 aa 02
80 00 00 01 d3 19 00 24 ff ff ff 00 80 00 00 14
00 00 00 00 00 00 00 00 00 03 02 05 c0 a8 00 00
c0 a8 aa 02 80 00 00 01 37 08 00 24 ff ff ff 00
80 00 00 14 00 00 00 00 00 00 00 00 00 03 02 05
c0 a8 01 00 c0 a8 aa 02 80 00 00 01 2c 12 00 24
ff ff ff 00 80 00 00 14 00 00 00 00 00 00 00 00
00 03 02 05 c0 a8 ac 00 c0 a8 aa 02 80 00 00 01
33 41 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 0a
00 00 00 00
        "
    );

    let (rem, res) = parse_ospfv2_packet(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv2Packet::LinkStateUpdate(pkt) = res {
        assert_eq!(pkt.header.version, 2);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateUpdate);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(192, 168, 170, 3));
        assert_eq!(pkt.lsa.len(), 7);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_lsa_summary() {
    // packet 12 of "OSPF_LSA_types.cap" (packetlife)
    const OSPF_LSA: &[u8] = &hex!(
        "
00 0b 22 03 c0 a8 0a 00 04 04 04 04 80 00 00 01
1e 7d 00 1c ff ff ff 00 00 00 00 1e
        "
    );

    let (rem, res) = OspfLinkStateAdvertisement::parse(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let OspfLinkStateAdvertisement::SummaryLinkIpNetwork(lsa) = res {
        assert_eq!(lsa.header.link_state_id(), Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(lsa.header.advertising_router(), Ipv4Addr::new(4, 4, 4, 4));
        assert_eq!(lsa.metric, 30);
        assert_eq!(lsa.tos_routes.len(), 0);
    } else {
        panic!("wrong lsa type");
    }
}

#[test]
pub fn test_lsa_type7() {
    // packet 11 of "OSPF_type7_LSA.cap" (packetlife)
    const OSPF_LSA: &[u8] = &hex!(
        "
00 66 28 07 ac 10 00 00 02 02 02 02 80 00 00 01
63 ac 00 24 ff ff ff fc 80 00 00 64 c0 a8 0a 01
00 00 00 00
        "
    );

    let (rem, res) = OspfLinkStateAdvertisement::parse(OSPF_LSA).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let OspfLinkStateAdvertisement::NSSAASExternal(lsa) = res {
        assert_eq!(lsa.header.link_state_id(), Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(lsa.header.advertising_router(), Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(lsa.metric, 100);
        assert_eq!(lsa.forwarding_address(), Ipv4Addr::new(192, 168, 10, 1));
        assert_eq!(lsa.tos_list.len(), 0);
    } else {
        panic!("wrong lsa type");
    }
}
