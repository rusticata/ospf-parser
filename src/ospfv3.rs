use crate::ospfv2::*;
use crate::parser::{parse_ospf_vec_u32, parse_ospfv3_router_links, take_vec_u8};
use nom::combinator::cond;
use nom::number::streaming::{be_u24, be_u32};
use nom_derive::Nom;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

/// An OSPF version 3 packet
#[derive(Debug)]
pub enum Ospfv3Packet {
    Hello(OspfHellov3Packet),
    DatabaseDescription(Ospfv3DatabaseDescriptionPacket),
    LinkStateRequest(Ospfv3LinkStateRequestPacket),
    LinkStateUpdate(Ospfv3LinkStateUpdatePacket),
    LinkStateAcknowledgment(Ospfv3LinkStateAcknowledgmentPacket),
}

/// The OSPF v3 packet header
///
/// Every OSPF packet starts with a standard 16-byte header.  Together
/// with the encapsulating IPv6 headers, the OSPF header contains all the
/// information necessary to determine whether the packet should be
/// accepted for further processing.  This determination is described in
/// Section 4.2.2.
#[derive(Debug, Nom)]
pub struct Ospfv3PacketHeader {
    #[nom(Verify = "*version == 3")]
    pub version: u8,
    pub packet_type: OspfPacketType,
    pub packet_length: u16,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: u16,
    pub instance_id: u8,
    pub reserved: u8,
}

impl Ospfv3PacketHeader {
    pub fn source_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.router_id)
    }
}

/// The Hello packet (v3)
///
/// Hello packets are OSPF packet type 1.  These packets are sent
/// periodically on all interfaces (including virtual links) in order to
/// establish and maintain neighbor relationships.  In addition, Hello
/// packets are multicast on those links having a multicast or broadcast
/// capability, enabling dynamic discovery of neighboring routers.
///
/// All routers connected to a common link must agree on certain
/// parameters (HelloInterval and RouterDeadInterval).  These parameters
/// are included in Hello packets allowing differences to inhibit the
/// forming of neighbor relationships.  The Hello packet also contains
/// fields used in Designated Router election (Designated Router ID and
/// Backup Designated Router ID), and fields used to detect bidirectional
/// communication (the Router IDs of all neighbors whose Hellos have been
/// recently received).
#[derive(Debug, Nom)]
pub struct OspfHellov3Packet {
    #[nom(Verify = "header.packet_type == OspfPacketType::Hello")]
    pub header: Ospfv3PacketHeader,
    pub interface_id: u32,
    pub router_priority: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    pub hello_interval: u16,
    pub router_dead_interval: u16,
    pub designated_router: u32,
    pub backup_designated_router: u32,
    // limit parsing to (length-xxx) bytes
    #[nom(Parse = "parse_ospf_vec_u32(header.packet_length, 36)")]
    pub neighbor_list: Vec<u32>,
}

impl OspfHellov3Packet {
    pub fn designated_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.designated_router)
    }

    pub fn backup_designated_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.backup_designated_router)
    }
}

/// The Database Description packet (v3)
///
/// Database Description packets are OSPF packet type 2.  These packets
/// are exchanged when an adjacency is being initialized.  They describe
/// the contents of the link-state database.  Multiple packets may be
/// used to describe the database.  For this purpose, a poll-response
/// procedure is used.  One of the routers is designated to be the master
/// and the other is the slave.  The master sends Database Description
/// packets (polls) that are acknowledged by Database Description packets
/// sent by the slave (responses).  The responses are linked to the polls
/// via the packets' DD sequence numbers.
#[derive(Debug, Nom)]
pub struct Ospfv3DatabaseDescriptionPacket {
    #[nom(Verify = "header.packet_type == OspfPacketType::DatabaseDescription")]
    pub header: Ospfv3PacketHeader,
    pub reserved0: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    pub if_mtu: u16,
    pub reserved: u8,
    pub db_description: u8,
    pub dd_sequence_number: u32,
    pub lsa_headers: Vec<Ospfv3LinkStateAdvertisementHeader>,
}

/// The Link State Request packet (v3)
///
/// Link State Request packets are OSPF packet type 3.  After exchanging
/// Database Description packets with a neighboring router, a router may
/// find that parts of its link-state database are out-of-date.  The Link
/// State Request packet is used to request the pieces of the neighbor's
/// database that are more up-to-date.  Multiple Link State Request
/// packets may need to be used.
///
/// A router that sends a Link State Request packet has in mind the
/// precise instance of the database pieces it is requesting.  Each
/// instance is defined by its LS sequence number, LS checksum, and LS
/// age, although these fields are not specified in the Link State
/// Request packet itself.  The router may receive even more recent LSA
/// instances in response.
///
/// The sending of Link State Request packets is documented in Section
/// 10.9 of [OSPFV2].  The reception of Link State Request packets is
/// documented in Section 10.7 of [OSPFV2].
#[derive(Debug, Nom)]
pub struct Ospfv3LinkStateRequestPacket {
    #[nom(Verify = "header.packet_type == OspfPacketType::LinkStateRequest")]
    pub header: Ospfv3PacketHeader,
    pub requests: Vec<OspfLinkStateRequest>,
}

/// The Link State Update packet
///
/// Link State Update packets are OSPF packet type 4.  These packets
/// implement the flooding of LSAs.  Each Link State Update packet
/// carries a collection of LSAs one hop further from their origin.
/// Several LSAs may be included in a single packet.
///
/// Link State Update packets are multicast on those physical networks
/// that support multicast/broadcast.  In order to make the flooding
/// procedure reliable, flooded LSAs are acknowledged in Link State
/// Acknowledgment packets.  If retransmission of certain LSAs is
/// necessary, the retransmitted LSAs are always carried by unicast Link
/// State Update packets.  For more information on the reliable flooding
/// of LSAs, consult Section 4.5.
#[derive(Debug, Nom)]
pub struct Ospfv3LinkStateUpdatePacket {
    #[nom(Verify = "header.packet_type == OspfPacketType::LinkStateUpdate")]
    pub header: Ospfv3PacketHeader,
    pub num_advertisements: u32,
    #[nom(Count = "num_advertisements")]
    pub lsa: Vec<Ospfv3LinkStateAdvertisement>,
}

/// The Link State Acknowledgment packet
///
/// Link State Acknowledgment packets are OSPF packet type 5.  To make
/// the flooding of LSAs reliable, flooded LSAs are explicitly or
/// implicitly acknowledged.  Explicit acknowledgment is accomplished
/// through the sending and receiving of Link State Acknowledgment
/// packets.  The sending of Link State Acknowledgment packets is
/// documented in Section 13.5 of [OSPFV2].  The reception of Link State
/// Acknowledgment packets is documented in Section 13.7 of [OSPFV2].
///
/// Multiple LSAs MAY be acknowledged in a single Link State
/// Acknowledgment packet.  Depending on the state of the sending
/// interface and the sender of the corresponding Link State Update
/// packet, a Link State Acknowledgment packet is sent to the multicast
/// address AllSPFRouters, the multicast address AllDRouters, or to a
/// neighbor's unicast address (see Section 13.5 of [OSPFV2] for
/// details).
#[derive(Debug, Nom)]
pub struct Ospfv3LinkStateAcknowledgmentPacket {
    #[nom(Verify = "header.packet_type == OspfPacketType::LinkStateAcknowledgment")]
    pub header: Ospfv3PacketHeader,
    pub lsa_headers: Vec<Ospfv3LinkStateAdvertisementHeader>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Nom)]
pub struct Ospfv3LinkStateType(pub u16);

newtype_enum! {
impl display Ospfv3LinkStateType {
    RouterLSA = 0x2001,
    NetworkLSA = 0x2002,
    InterAreaPrefixLSA = 0x2003,
    InterAreaRouterLSA = 0x2004,
    ASExternalLSA = 0x4005,
    NSSALSA = 0x2007,
    LinkLSA = 0x0008,
    IntraAreaPrefixLSA = 0x2009,
}
}

/// The Link State Advertisement header
///
/// All LSAs begin with a common 20-byte header.  This header contains
/// enough information to uniquely identify the LSA (LS type, Link State
/// ID, and Advertising Router).  Multiple instances of the LSA may exist
/// in the routing domain at the same time.  It is then necessary to
/// determine which instance is more recent.  This is accomplished by
/// examining the LS age, LS sequence number, and LS checksum fields that
/// are also contained in the LSA header.
#[derive(Debug, Nom)]
pub struct Ospfv3LinkStateAdvertisementHeader {
    pub ls_age: u16,
    pub link_state_type: Ospfv3LinkStateType,
    pub link_state_id: u32,
    pub advertising_router: u32,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl Ospfv3LinkStateAdvertisementHeader {
    pub fn link_state_id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.link_state_id)
    }

    pub fn advertising_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.advertising_router)
    }
}

/// Link state advertisements (v3)
#[derive(Debug)]
pub enum Ospfv3LinkStateAdvertisement {
    Router(Ospfv3RouterLSA),
    Network(Ospfv3NetworkLSA),
    InterAreaPrefix(Ospfv3InterAreaPrefixLSA),
    InterAreaRouter(Ospfv3InterAreaRouterLSA),
    ASExternal(Ospfv3ASExternalLSA),
    NSSA(Ospfv3NSSALSA),
    Link(Ospfv3LinkLSA),
    IntraAreaPrefix(Ospfv3IntraAreaPrefixLSA),
}

/// Router links advertisements (v3)
///
/// Router links advertisements are the Type 1 link state
/// advertisements.  Each router in an area originates a router links
/// advertisement.  The advertisement describes the state and cost of
/// the router's links (i.e., interfaces) to the area.  All of the
/// router's links to the area must be described in a single router
/// links advertisement.  For details concerning the construction of
/// router links advertisements, see Section 12.4.1.
#[derive(Debug, Nom)]
pub struct Ospfv3RouterLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::RouterLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    // limit parsing to (length-xxx) bytes
    #[nom(Parse = "parse_ospfv3_router_links(header.length)")]
    pub links: Vec<Ospfv3RouterLink>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Nom)]
pub struct Ospfv3RouterLinkType(pub u8);

newtype_enum! {
impl display Ospfv3RouterLinkType {
    PointToPoint = 1,
    Transit = 2,
    Virtual = 4,
}
}

/// OSPF router link (i.e., interface)
#[derive(Debug, Nom)]
pub struct Ospfv3RouterLink {
    pub link_type: Ospfv3RouterLinkType,
    pub reserved: u8,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router_id: u32,
}

impl Ospfv3RouterLink {
    pub fn interface_id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.interface_id)
    }

    pub fn neighbor_interface_id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.neighbor_interface_id)
    }

    pub fn neighbor_router_id(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.neighbor_router_id)
    }
}

/// Network links advertisements (v3)
///
/// Network-LSAs have LS type equal to 0x2002.  A network-LSA is
/// originated for each broadcast and NBMA link in the area that includes
/// two or more adjacent routers.  The network-LSA is originated by the
/// link's Designated Router.  The LSA describes all routers attached to
/// the link including the Designated Router itself.  The LSA's Link
/// State ID field is set to the Interface ID that the Designated Router
/// has been advertising in Hello packets on the link.
///
/// The distance from the network to all attached routers is zero.  This
/// is why the Metric fields need not be specified in the network-LSA.
/// For details concerning the construction of network-LSAs, see
/// Section 4.4.3.3.
#[derive(Debug, Nom)]
pub struct Ospfv3NetworkLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::NetworkLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub reserved: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    // limit parsing to (length-xxx) bytes
    #[nom(Parse = "parse_ospf_vec_u32(header.length, 24)")]
    pub attached_routers: Vec<u32>,
}

impl Ospfv3NetworkLSA {
    pub fn iter_attached_routers(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.attached_routers.iter().map(|&u| Ipv4Addr::from(u))
    }
}

/// Inter-Area-Prefix-LSAs (v3)
///
/// Inter-area-prefix-LSAs have LS type equal to 0x2003.  These LSAs are
/// the IPv6 equivalent of OSPF for IPv4's type 3 summary-LSAs (see
/// Section 12.4.3 of [OSPFV2]).  Originated by area border routers, they
/// describe routes to IPv6 address prefixes that belong to other areas.
/// A separate inter-area-prefix-LSA is originated for each IPv6 address
/// prefix.  For details concerning the construction of inter-area-
/// prefix-LSAs, see Section 4.4.3.4.
///
/// For stub areas, inter-area-prefix-LSAs can also be used to describe a
/// (per-area) default route.  Default summary routes are used in stub
/// areas instead of flooding a complete set of external routes.  When
/// describing a default summary route, the inter-area-prefix-LSA's
/// PrefixLength is set to 0.
#[derive(Debug, Nom)]
pub struct Ospfv3InterAreaPrefixLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::InterAreaPrefixLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub reserved0: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub prefix: Ospfv3IPv6AddressPrefix,
}

#[derive(Debug, Nom)]
pub struct Ospfv3IPv6AddressPrefix {
    pub prefix_length: u8,
    pub prefix_options: u8,
    pub reserved: u16,
    #[nom(Parse = "take_vec_u8(prefix_length / 8)")]
    pub address_prefix: Vec<u8>,
}

/// Inter-Area-Router-LSAs (v3)
///
/// Inter-area-router-LSAs have LS type equal to 0x2004.  These LSAs are
/// the IPv6 equivalent of OSPF for IPv4's type 4 summary-LSAs (see
/// Section 12.4.3 of [OSPFV2]).  Originated by area border routers, they
/// describe routes to AS boundary routers in other areas.  To see why it
/// is necessary to advertise the location of each ASBR, consult Section
/// 16.4 in [OSPFV2].  Each LSA describes a route to a single router.
/// For details concerning the construction of inter-area-router-LSAs,
/// see Section 4.4.3.5.
#[derive(Debug, Nom)]
pub struct Ospfv3InterAreaRouterLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::InterAreaRouterLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub reserved0: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    pub reserved1: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub destination_router_id: u32,
}

/// AS-External-LSAs
///
/// AS-external-LSAs have LS type equal to 0x4005.  These LSAs are
/// originated by AS boundary routers and describe destinations external
/// to the AS.  Each LSA describes a route to a single IPv6 address
/// prefix.  For details concerning the construction of AS-external-LSAs,
/// see Section 4.4.3.6.
///
/// AS-external-LSAs can be used to describe a default route.  Default
/// routes are used when no specific route exists to the destination.
/// When describing a default route, the AS-external-LSA's PrefixLength
/// is set to 0.
#[derive(Debug, Nom)]
pub struct Ospfv3ASExternalLSA {
    #[nom(
        Verify = "header.link_state_type == Ospfv3LinkStateType::ASExternalLSA ||
             header.link_state_type == Ospfv3LinkStateType::NSSALSA"
    )]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub address_prefix: Ospfv3IPv6AddressPrefix,
    #[nom(Parse = "cond(flags & 0b10 != 0, take_vec_u8(16))")]
    pub forwarding_address: Option<Vec<u8>>,
    #[nom(Parse = "cond(flags & 0b01 != 0, be_u32)")]
    pub external_route_tag: Option<u32>,
    #[nom(Parse = "cond(address_prefix.reserved != 0, be_u32)")]
    pub referenced_link_state_id: Option<u32>,
}

/// NSSA-LSAs
///
/// NSSA-LSAs have LS type equal to 0x2007.  These LSAs are originated by
/// AS boundary routers within an NSSA and describe destinations external
/// to the AS that may or may not be propagated outside the NSSA (refer
/// to [NSSA]).  Other than the LS type, their format is exactly the same
/// as AS-external LSAs as described in Appendix A.4.7.
///
/// A global IPv6 address MUST be selected as forwarding address for
/// NSSA-LSAs that are to be propagated by NSSA area border routers.  The
/// selection should proceed the same as OSPFv2 NSSA support [NSSA] with
/// additional checking to ensure IPv6 link-local address are not
/// selected.
type Ospfv3NSSALSA = Ospfv3ASExternalLSA;

/// Link-LSAs
///
/// Link-LSAs have LS type equal to 0x0008.  A router originates a
/// separate link-LSA for each attached physical link.  These LSAs have
/// link-local flooding scope; they are never flooded beyond the
/// associated link.  Link-LSAs have three purposes:
///
/// 1.  They provide the router's link-local address to all other routers
///     attached to the link.
///
/// 2.  They inform other routers attached to the link of a list of IPv6
///     prefixes to associate with the link.
///
/// 3.  They allow the router to advertise a collection of Options bits
///     in the network-LSA originated by the Designated Router on a
///     broadcast or NBMA link.
///
/// For details concerning the construction of links-LSAs, see
/// Section 4.4.3.8.
///
/// A link-LSA's Link State ID is set equal to the originating router's
/// Interface ID on the link.
#[derive(Debug, Nom)]
pub struct Ospfv3LinkLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::LinkLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub router_priority: u8,
    #[nom(Parse = "be_u24")]
    pub options: u32,
    #[nom(Parse = "take_vec_u8(16)")]
    pub link_local_interface_address: Vec<u8>,
    pub num_prefixes: u32,
    #[nom(Count = "num_prefixes")]
    pub address_prefixes: Vec<Ospfv3IPv6AddressPrefix>,
}

/// Intra-Area-Prefix-LSAs
///
/// Intra-area-prefix-LSAs have LS type equal to 0x2009.  A router uses
/// intra-area-prefix-LSAs to advertise one or more IPv6 address prefixes
/// that are associated with a local router address, an attached stub
/// network segment, or an attached transit network segment.  In IPv4,
/// the first two were accomplished via the router's router-LSA and the
/// last via a network-LSA.  In OSPF for IPv6, all addressing information
/// that was advertised in router-LSAs and network-LSAs has been removed
/// and is now advertised in intra-area-prefix-LSAs.  For details
/// concerning the construction of intra-area-prefix-LSA, see
/// Section 4.4.3.9.
///
/// A router can originate multiple intra-area-prefix-LSAs for each
/// router or transit network.  Each such LSA is distinguished by its
/// unique Link State ID.
#[derive(Debug, Nom)]
pub struct Ospfv3IntraAreaPrefixLSA {
    #[nom(Verify = "header.link_state_type == Ospfv3LinkStateType::IntraAreaPrefixLSA")]
    pub header: Ospfv3LinkStateAdvertisementHeader,
    pub num_prefixes: u16,
    pub referenced_ls_type: u16,
    pub referenced_link_state_id: u32,
    pub referenced_advertising_router: u32,
    #[nom(Count = "num_prefixes")]
    pub address_prefixes: Vec<Ospfv3IPv6AddressPrefix>,
}
