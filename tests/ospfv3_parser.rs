use hex_literal::hex;
use ospf_parser::*;
use std::net::Ipv4Addr;

#[test]
pub fn test_v3_hello_packet() {
    // packet 1 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_HELLO: &[u8] = &hex!(
        "
03 01 00 24 01 01 01 01 00 00 00 01 fb 86 00 00
00 00 00 05 01 00 00 13 00 0a 00 28 00 00 00 00
00 00 00 00
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_HELLO).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv3Packet::Hello(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(pkt.header.packet_type, OspfPacketType::Hello);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(1, 1, 1, 1));
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_v3_db_description_packet() {
    // packet 8 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_DBDESC: &[u8] = &hex!(
        "
03 02 00 1c 01 01 01 01 00 00 00 01 e4 71 00 00
00 00 00 13 05 dc 00 07 00 00 12 fd
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv3Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x0000_12fd);
        assert_eq!(pkt.lsa_headers.len(), 0);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_v3_db_description_packet_with_lsa() {
    // packet 14 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_DBDESC: &[u8] = &hex!(
        "
03 02 01 48 01 01 01 01 00 00 00 01 7d ca 00 00
00 00 00 13 05 dc 00 02 00 00 0b 91 00 0e 20 01
00 00 00 00 01 01 01 01 80 00 00 0b bf 43 00 18
00 45 20 01 00 00 00 00 02 02 02 02 80 00 00 08
7f 54 00 28 00 4a 20 02 00 00 00 05 02 02 02 02
80 00 00 03 f4 f8 00 20 00 36 20 03 00 00 00 05
01 01 01 01 80 00 00 01 db ea 00 24 00 36 20 03
00 00 00 06 01 01 01 01 80 00 00 01 b9 cd 00 24
00 36 20 03 00 00 00 07 01 01 01 01 80 00 00 01
88 24 00 24 00 36 20 03 00 00 00 08 01 01 01 01
80 00 00 01 30 86 00 24 03 fb 20 03 00 00 00 01
02 02 02 02 80 00 00 01 e5 e0 00 24 03 69 20 03
00 00 00 02 02 02 02 02 80 00 00 01 c3 c3 00 24
03 69 20 03 00 00 00 03 02 02 02 02 80 00 00 01
92 1a 00 24 03 69 20 03 00 00 00 04 02 02 02 02
80 00 00 01 3a 7c 00 24 00 31 00 08 00 00 00 05
01 01 01 01 80 00 00 02 3d 08 00 38 04 3a 00 08
00 00 00 05 02 02 02 02 80 00 00 02 35 0b 00 38
00 31 20 09 00 00 00 00 01 01 01 01 80 00 00 01
e8 d2 00 2c 00 4a 20 09 00 00 14 00 02 02 02 02
80 00 00 03 9f 02 00 2c
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_DBDESC).expect("parsing failed");
    assert!(rem.is_empty());
    if let Ospfv3Packet::DatabaseDescription(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(pkt.header.packet_type, OspfPacketType::DatabaseDescription);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(pkt.if_mtu, 1500);
        assert_eq!(pkt.dd_sequence_number, 0x0000_0b91);
        assert_eq!(pkt.lsa_headers.len(), 15);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_v3_ls_request() {
    // packet 18 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_LSREQ: &[u8] = &hex!(
        "
03 03 00 ac 02 02 02 02 00 00 00 01 3f b7 00 00
00 00 20 01 00 00 00 00 01 01 01 01 00 00 20 02
00 00 00 05 02 02 02 02 00 00 20 03 00 00 00 04
02 02 02 02 00 00 20 03 00 00 00 03 02 02 02 02
00 00 20 03 00 00 00 02 02 02 02 02 00 00 20 03
00 00 00 01 02 02 02 02 00 00 20 03 00 00 00 08
01 01 01 01 00 00 20 03 00 00 00 07 01 01 01 01
00 00 20 03 00 00 00 06 01 01 01 01 00 00 20 03
00 00 00 05 01 01 01 01 00 00 00 08 00 00 00 05
01 01 01 01 00 00 20 09 00 00 14 00 02 02 02 02
00 00 20 09 00 00 00 00 01 01 01 01
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_LSREQ).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv3Packet::LinkStateRequest(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateRequest);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(pkt.requests.len(), 13);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_v3_ls_update() {
    // packet 21 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_LSUPD: &[u8] = &hex!(
        "
03 04 01 fc 01 01 01 01 00 00 00 01 67 f8 00 00
00 00 00 0d 00 0f 20 01 00 00 00 00 01 01 01 01
80 00 00 0b bf 43 00 18 01 00 00 33 00 4b 20 02
00 00 00 05 02 02 02 02 80 00 00 03 f4 f8 00 20
00 00 00 33 02 02 02 02 01 01 01 01 03 6a 20 03
00 00 00 04 02 02 02 02 80 00 00 01 3a 7c 00 24
00 00 00 4a 40 00 00 00 20 01 0d b8 00 00 00 03
03 6a 20 03 00 00 00 03 02 02 02 02 80 00 00 01
92 1a 00 24 00 00 00 54 40 00 00 00 20 01 0d b8
00 00 00 04 03 6a 20 03 00 00 00 02 02 02 02 02
80 00 00 01 c3 c3 00 24 00 00 00 4a 40 00 00 00
20 01 0d b8 00 00 00 34 03 fc 20 03 00 00 00 01
02 02 02 02 80 00 00 01 e5 e0 00 24 00 00 00 40
40 00 00 00 20 01 0d b8 00 00 00 00 00 37 20 03
00 00 00 08 01 01 01 01 80 00 00 01 30 86 00 24
00 00 00 4a 40 00 00 00 20 01 0d b8 00 00 00 03
00 37 20 03 00 00 00 07 01 01 01 01 80 00 00 01
88 24 00 24 00 00 00 54 40 00 00 00 20 01 0d b8
00 00 00 04 00 37 20 03 00 00 00 06 01 01 01 01
80 00 00 01 b9 cd 00 24 00 00 00 4a 40 00 00 00
20 01 0d b8 00 00 00 34 00 37 20 03 00 00 00 05
01 01 01 01 80 00 00 01 db ea 00 24 00 00 00 40
40 00 00 00 20 01 0d b8 00 00 00 00 00 32 00 08
00 00 00 05 01 01 01 01 80 00 00 02 3d 08 00 38
01 00 00 33 fe 80 00 00 00 00 00 00 00 00 00 00
00 00 00 01 00 00 00 01 40 00 00 00 20 01 0d b8
00 00 00 12 00 4b 20 09 00 00 14 00 02 02 02 02
80 00 00 03 9f 02 00 2c 00 01 20 02 00 00 00 05
02 02 02 02 40 00 00 00 20 01 0d b8 00 00 00 12
00 32 20 09 00 00 00 00 01 01 01 01 80 00 00 01
e8 d2 00 2c 00 01 20 01 00 00 00 00 01 01 01 01
40 00 00 0a 20 01 0d b8 00 00 00 12
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_LSUPD).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv3Packet::LinkStateUpdate(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(pkt.header.packet_type, OspfPacketType::LinkStateUpdate);
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(pkt.lsa.len(), 13);
        let lsa0 = &pkt.lsa[0];
        if let Ospfv3LinkStateAdvertisement::Router(lsa) = lsa0 {
            assert_eq!(lsa.header.link_state_type, Ospfv3LinkStateType::RouterLSA);
            assert_eq!(lsa.header.advertising_router(), Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(lsa.links.len(), 0);
        } else {
            panic!("wrong LSA type");
        }
    } else {
        panic!("wrong packet type");
    }
}

#[test]
pub fn test_v3_ls_ack() {
    // packet 26 of "OSPFv3_with_AH.cap" (packetlife)
    const OSPF_V3_LSACK: &[u8] = &hex!(
        "
03 05 01 14 02 02 02 02 00 00 00 01 6e 7c 00 00
00 0f 20 01 00 00 00 00 01 01 01 01 80 00 00 0b
bf 43 00 18 00 4b 20 02 00 00 00 05 02 02 02 02
80 00 00 03 f4 f8 00 20 03 6a 20 03 00 00 00 04
02 02 02 02 80 00 00 01 3a 7c 00 24 03 6a 20 03
00 00 00 03 02 02 02 02 80 00 00 01 92 1a 00 24
03 6a 20 03 00 00 00 02 02 02 02 02 80 00 00 01
c3 c3 00 24 03 fc 20 03 00 00 00 01 02 02 02 02
80 00 00 01 e5 e0 00 24 00 37 20 03 00 00 00 08
01 01 01 01 80 00 00 01 30 86 00 24 00 37 20 03
00 00 00 07 01 01 01 01 80 00 00 01 88 24 00 24
00 37 20 03 00 00 00 06 01 01 01 01 80 00 00 01
b9 cd 00 24 00 37 20 03 00 00 00 05 01 01 01 01
80 00 00 01 db ea 00 24 00 32 00 08 00 00 00 05
01 01 01 01 80 00 00 02 3d 08 00 38 00 4b 20 09
00 00 14 00 02 02 02 02 80 00 00 03 9f 02 00 2c
00 32 20 09 00 00 00 00 01 01 01 01 80 00 00 01
e8 d2 00 2c
        "
    );

    let (rem, res) = parse_ospfv3_packet(OSPF_V3_LSACK).expect("parsing failed");
    // println!("res:{:#?}", res);
    assert!(rem.is_empty());
    if let Ospfv3Packet::LinkStateAcknowledgment(pkt) = res {
        assert_eq!(pkt.header.version, 3);
        assert_eq!(
            pkt.header.packet_type,
            OspfPacketType::LinkStateAcknowledgment
        );
        assert_eq!(pkt.header.source_router(), Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(pkt.lsa_headers.len(), 13);
    } else {
        panic!("wrong packet type");
    }
}
