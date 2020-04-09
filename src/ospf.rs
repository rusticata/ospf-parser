use nom::number::streaming::{be_u16, be_u24, be_u32, be_u64, be_u8};
use nom::{call, complete, count, do_parse, many0, IResult};
use nom_derive::Nom;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Nom)]
pub struct OspfPacketType(pub u8);

newtype_enum! {
impl display OspfPacketType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAcknowledgment = 5,
}
}

/// An OSPF version 2 packet
#[derive(Debug)]
pub enum OspfPacket {
    Hello(OspfHelloPacket),
    DatabaseDescription(OspfDatabaseDescriptionPacket),
    LinkStateRequest(OspfLinkStateRequestPacket),
    LinkStateUpdate(OspfLinkStateUpdatePacket),
    LinkStateAcknowledgment(OspfLinkStateAcknowledgmentPacket),
}

/// The OSPF packet header
///
/// Every OSPF packet starts with a common 24 byte header.  This header
/// contains all the necessary information to determine whether the
/// packet should be accepted for further processing.  This
/// determination is described in Section 8.2 of the specification.
#[derive(Debug, Nom)]
pub struct OspfPacketHeader {
    pub version: u8,
    pub packet_type: OspfPacketType,
    pub packet_length: u16,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: u16,
    pub au_type: u16,
    pub authentication: u64,
}

impl OspfPacketHeader {
    pub fn source_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.router_id)
    }
}

/// The Hello packet
///
/// Hello packets are OSPF packet type 1.  These packets are sent
/// periodically on all interfaces (including virtual links) in order to
/// establish and maintain neighbor relationships.  In addition, Hello
/// Packets are multicast on those physical networks having a multicast
/// or broadcast capability, enabling dynamic discovery of neighboring
/// routers.
///
/// All routers connected to a common network must agree on certain
/// parameters (Network mask, HelloInterval and RouterDeadInterval).
/// These parameters are included in Hello packets, so that differences
/// can inhibit the forming of neighbor relationships. A detailed
/// explanation of the receive processing for Hello packets is presented
/// in Section 10.5.  The sending of Hello packets is covered in Section
/// 9.5.
#[derive(Debug, Nom)]
pub struct OspfHelloPacket {
    #[Verify(header.packet_type == OspfPacketType::Hello)]
    pub header: OspfPacketHeader,
    pub network_mask: u32,
    pub hello_interval: u16,
    pub options: u8,
    pub rtr_pri: u8,
    pub router_dead_interval: u32,
    pub designated_router: u32,
    pub backup_designated_router: u32,
    pub neighbor_list: Vec<u32>,
}

impl OspfHelloPacket {
    pub fn network_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network_mask)
    }

    pub fn designated_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.designated_router)
    }

    pub fn backup_designated_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.backup_designated_router)
    }
}

/// The Database Description packet
///
/// Database Description packets are OSPF packet type 2.  These packets
/// are exchanged when an adjacency is being initialized.  They describe
/// the contents of the topological database.  Multiple packets may be
/// used to describe the database.  For this purpose a poll-response
/// procedure is used.  One of the routers is designated to be master,
/// the other a slave.  The master sends Database Description packets
/// (polls) which are acknowledged by Database Description packets sent
/// by the slave (responses).  The responses are linked to the polls via
/// the packets' DD sequence numbers.
#[derive(Debug, Nom)]
pub struct OspfDatabaseDescriptionPacket {
    #[Verify(header.packet_type == OspfPacketType::DatabaseDescription)]
    pub header: OspfPacketHeader,
    pub if_mtu: u16,
    pub options: u8,
    pub flags: u8,
    pub dd_sequence_number: u32,
    pub link_state_advertisement: Vec<OspfLinkStateAdvertisementHeader>,
}

/// The Link State Request packet
///
/// Link State Request packets are OSPF packet type 3.  After exchanging
/// Database Description packets with a neighboring router, a router may
/// find that parts of its topological database are out of date.  The
/// Link State Request packet is used to request the pieces of the
/// neighbor's database that are more up to date.  Multiple Link State
/// Request packets may need to be used.  The sending of Link State
/// Request packets is the last step in bringing up an adjacency.
///
/// A router that sends a Link State Request packet has in mind the
/// precise instance of the database pieces it is requesting, defined by
/// LS sequence number, LS checksum, and LS age, although these fields
/// are not specified in the Link State Request Packet itself.  The
/// router may receive even more recent instances in response.
///
/// The sending of Link State Request packets is documented in Section
/// 10.9.  The reception of Link State Request packets is documented in
/// Section 10.7.
#[derive(Debug, Nom)]
pub struct OspfLinkStateRequestPacket {
    #[Verify(header.packet_type == OspfPacketType::LinkStateRequest)]
    pub header: OspfPacketHeader,
    pub ls_type: u32,
    pub ls_id: u32,
    pub advertising_router: u32,
}

impl OspfLinkStateRequestPacket {
    pub fn advertising_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.advertising_router)
    }
}

/// The Link State Update packet
///
/// Link State Update packets are OSPF packet type 4.  These packets
/// implement the flooding of link state advertisements.  Each Link
/// State Update packet carries a collection of link state
/// advertisements one hop further from its origin.  Several link state
/// advertisements may be included in a single packet.
///
/// Link State Update packets are multicast on those physical networks
/// that support multicast/broadcast.  In order to make the flooding
/// procedure reliable, flooded advertisements are acknowledged in Link
/// State Acknowledgment packets.  If retransmission of certain
/// advertisements is necessary, the retransmitted advertisements are
/// always carried by unicast Link State Update packets.  For more
/// information on the reliable flooding of link state advertisements,
/// consult Section 13.
#[derive(Debug, Nom)]
pub struct OspfLinkStateUpdatePacket {
    #[Verify(header.packet_type == OspfPacketType::LinkStateUpdate)]
    pub header: OspfPacketHeader,
    pub num_advertisements: u32,
    #[Count = "num_advertisements"]
    pub advertisements: Vec<OspfLinkStateAdvertisement>,
}

/// The Link State Acknowledgment packet
///
/// Link State Acknowledgment Packets are OSPF packet type 5.  To make
/// the flooding of link state advertisements reliable, flooded
/// advertisements are explicitly acknowledged.  This acknowledgment is
/// accomplished through the sending and receiving of Link State
/// Acknowledgment packets.  Multiple link state advertisements can be
/// acknowledged in a single Link State Acknowledgment packet.
///
/// Depending on the state of the sending interface and the source of
/// the advertisements being acknowledged, a Link State Acknowledgment
/// packet is sent either to the multicast address AllSPFRouters, to the
/// multicast address AllDRouters, or as a unicast.  The sending of Link
/// State Acknowledgement packets is documented in Section 13.5.  The
/// reception of Link State Acknowledgement packets is documented in
/// Section 13.7.
///
/// The format of this packet is similar to that of the Data Description
/// packet.  The body of both packets is simply a list of link state
/// advertisement headers.
#[derive(Debug, Nom)]
pub struct OspfLinkStateAcknowledgmentPacket {
    #[Verify(header.packet_type == OspfPacketType::LinkStateAcknowledgment)]
    pub header: OspfPacketHeader,
    pub ls_header: Vec<OspfLinkStateAdvertisementHeader>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Nom)]
pub struct OspfLinkStateType(pub u8);

newtype_enum! {
impl display OspfLinkStateType {
    RouterLinks = 1,
    NetworkLinks = 2,
    SummaryLinkIpNetwork = 3,
    SummaryLinkAsbr = 4,
    ASExternalLink = 5,
}
}

/// The Link State Advertisement header
///
/// All link state advertisements begin with a common 20 byte header.
/// This header contains enough information to uniquely identify the
/// advertisement (LS type, Link State ID, and Advertising Router).
/// Multiple instances of the link state advertisement may exist in the
/// routing domain at the same time.  It is then necessary to determine
/// which instance is more recent.  This is accomplished by examining
/// the LS age, LS sequence number and LS checksum fields that are also
/// contained in the link state advertisement header.
#[derive(Debug, Nom)]
pub struct OspfLinkStateAdvertisementHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: OspfLinkStateType,
    pub ls_id: u32,
    pub advertising_router: u32,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl OspfLinkStateAdvertisementHeader {
    pub fn advertising_router(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.advertising_router)
    }
}

/// Link state advertisements
#[derive(Debug)]
pub enum OspfLinkStateAdvertisement {
    RouterLinks(OspfRouterLinksAdvertisement),
    NetworkLinks(OspfNetworkLinksAdvertisement),
    SummaryLinkIpNetwork(OspfSummaryLinkAdvertisement),
    SummaryLinkAsbr(OspfSummaryLinkAdvertisement),
    ASExternalLink(OspfASExternalLinkAdvertisement),
}

/// Router links advertisements
///
/// Router links advertisements are the Type 1 link state
/// advertisements.  Each router in an area originates a router links
/// advertisement.  The advertisement describes the state and cost of
/// the router's links (i.e., interfaces) to the area.  All of the
/// router's links to the area must be described in a single router
/// links advertisement.  For details concerning the construction of
/// router links advertisements, see Section 12.4.1.
#[derive(Debug, Nom)]
pub struct OspfRouterLinksAdvertisement {
    #[Verify(header.ls_type == OspfLinkStateType::RouterLinks)]
    pub header: OspfLinkStateAdvertisementHeader,
    pub flags: u16,
    pub num_links: u16,
    #[Count = "num_links"]
    pub links: Vec<OspfRouterLink>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Nom)]
pub struct OspfRouterLinkType(pub u8);

newtype_enum! {
impl display OspfRouterLinkType {
    PointToPoint = 1,
    Transit = 2,
    Stub = 3,
    Virtual = 4,
}
}

/// OSPF router link (i.e., interface)
#[derive(Debug, Nom)]
pub struct OspfRouterLink {
    pub link_id: u32,
    pub link_data: u32,
    pub link_type: OspfRouterLinkType,
    pub num_tos: u8,
    pub tos_0_metric: u16,
    #[Count = "num_tos"]
    pub tos_list: Vec<OspfRouterTOS>,
}

/// OSPF Router Type Of Service (TOS)
#[derive(Debug, Nom)]
pub struct OspfRouterTOS {
    pub tos: u8,
    pub reserved: u8,
    pub metric: u16,
}

/// Network links advertisements
///
/// Network links advertisements are the Type 2 link state
/// advertisements.  A network links advertisement is originated for
/// each transit network in the area.  A transit network is a multi-
/// access network that has more than one attached router.  The network
/// links advertisement is originated by the network's Designated
/// Router.  The advertisement describes all routers attached to the
/// network, including the Designated Router itself.  The
/// advertisement's Link State ID field lists the IP interface address
/// of the Designated Router.
///
/// The distance from the network to all attached routers is zero, for
/// all Types of Service.  This is why the TOS and metric fields need
/// not be specified in the network links advertisement.  For details
/// concerning the construction of network links advertisements, see
/// Section 12.4.2.
#[derive(Debug, Nom)]
pub struct OspfNetworkLinksAdvertisement {
    #[Verify(header.ls_type == OspfLinkStateType::NetworkLinks)]
    pub header: OspfLinkStateAdvertisementHeader,
    pub network_mask: u32,
    pub attached_routers: Vec<u32>,
}

impl OspfNetworkLinksAdvertisement {
    pub fn network_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network_mask)
    }
}

/// Summary link advertisements
///
/// Summary link advertisements are the Type 3 and 4 link state
/// advertisements.  These advertisements are originated by area border
/// routers.  A separate summary link advertisement is made for each
/// destination (known to the router) which belongs to the AS, yet is
/// outside the area.  For details concerning the construction of
/// summary link advertisements, see Section 12.4.3.
///
/// Type 3 link state advertisements are used when the destination is an
/// IP network.  In this case the advertisement's Link State ID field is
/// an IP network number (if necessary, the Link State ID can also have
/// one or more of the network's "host" bits set; see Appendix F for
/// details). When the destination is an AS boundary router, a Type 4
/// advertisement is used, and the Link State ID field is the AS
/// boundary router's OSPF Router ID.  (To see why it is necessary to
/// advertise the location of each ASBR, consult Section 16.4.)  Other
/// than the difference in the Link State ID field, the format of Type 3
/// and 4 link state advertisements is identical.
#[derive(Debug, Nom)]
pub struct OspfSummaryLinkAdvertisement {
    #[Verify(header.ls_type == OspfLinkStateType::SummaryLinkIpNetwork ||
        header.ls_type == OspfLinkStateType::SummaryLinkAsbr)]
    pub header: OspfLinkStateAdvertisementHeader,
    pub network_mask: u32,
    pub tos_routes: Vec<OspfTosRoute>,
}

impl OspfSummaryLinkAdvertisement {
    pub fn network_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network_mask)
    }
}

#[derive(Debug, Nom)]
pub struct OspfTosRoute {
    pub tos: u8,
    #[Parse = "be_u24"]
    pub metric: u32,
}

/// AS external link advertisements
///
/// AS external link advertisements are the Type 5 link state
/// advertisements.  These advertisements are originated by AS boundary
/// routers.  A separate advertisement is made for each destination
/// (known to the router) which is external to the AS.  For details
/// concerning the construction of AS external link advertisements, see
/// Section 12.4.3.
///
/// AS external link advertisements usually describe a particular
/// external destination.  For these advertisements the Link State ID
/// field specifies an IP network number (if necessary, the Link State
/// ID can also have one or more of the network's "host" bits set; see
/// Appendix F for details).  AS external link advertisements are also
/// used to describe a default route.  Default routes are used when no
/// specific route exists to the destination.  When describing a default
/// route, the Link State ID is always set to DefaultDestination
/// (0.0.0.0) and the Network Mask is set to 0.0.0.0.
#[derive(Debug, Nom)]
pub struct OspfASExternalLinkAdvertisement {
    #[Verify(header.ls_type == OspfLinkStateType::ASExternalLink)]
    pub header: OspfLinkStateAdvertisementHeader,
    pub network_mask: u32,
    pub tos_list: Vec<OspfExternalTosRoute>,
}

impl OspfASExternalLinkAdvertisement {
    pub fn network_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network_mask)
    }
}

#[derive(Debug, Nom)]
pub struct OspfExternalTosRoute {
    pub tos: u8,
    #[Parse = "be_u24"]
    pub metric: u32,
    pub forwarding_address: u32,
    pub external_route_tag: u32,
}

impl OspfExternalTosRoute {
    pub fn forwarding_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.forwarding_address)
    }
}
