use crate::ospfv2::*;
use crate::ospfv3::*;
use nom::bytes::streaming::take;
use nom::combinator::{complete, map, peek};
use nom::error::{make_error, ErrorKind};
use nom::multi::many0;
use nom::number::complete::be_u32 as be_u32_complete;
use nom::number::streaming::{be_u16, be_u32};
pub use nom::IResult;

pub fn parse_ospfv2_packet(input: &[u8]) -> IResult<&[u8], Ospfv2Packet> {
    let (_, word) = peek(be_u16)(input)?;
    let b0 = (word >> 8) as u8;
    let b1 = (word & 0xff) as u8;
    if b0 != 2 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    match OspfPacketType(b1) {
        OspfPacketType::Hello => map(OspfHelloPacket::parse, Ospfv2Packet::Hello)(input),
        OspfPacketType::DatabaseDescription => map(
            OspfDatabaseDescriptionPacket::parse,
            Ospfv2Packet::DatabaseDescription,
        )(input),
        OspfPacketType::LinkStateRequest => map(
            OspfLinkStateRequestPacket::parse,
            Ospfv2Packet::LinkStateRequest,
        )(input),
        OspfPacketType::LinkStateUpdate => map(
            OspfLinkStateUpdatePacket::parse,
            Ospfv2Packet::LinkStateUpdate,
        )(input),
        OspfPacketType::LinkStateAcknowledgment => map(
            OspfLinkStateAcknowledgmentPacket::parse,
            Ospfv2Packet::LinkStateAcknowledgment,
        )(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

pub fn parse_ospfv3_packet(input: &[u8]) -> IResult<&[u8], Ospfv3Packet> {
    let (_, word) = peek(be_u16)(input)?;
    let b0 = (word >> 8) as u8;
    let b1 = (word & 0xff) as u8;
    if b0 != 3 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    match OspfPacketType(b1) {
        OspfPacketType::Hello => map(OspfHellov3Packet::parse, Ospfv3Packet::Hello)(input),
        OspfPacketType::DatabaseDescription => map(
            Ospfv3DatabaseDescriptionPacket::parse,
            Ospfv3Packet::DatabaseDescription,
        )(input),
        OspfPacketType::LinkStateRequest => map(
            Ospfv3LinkStateRequestPacket::parse,
            Ospfv3Packet::LinkStateRequest,
        )(input),
        OspfPacketType::LinkStateUpdate => map(
            Ospfv3LinkStateUpdatePacket::parse,
            Ospfv3Packet::LinkStateUpdate,
        )(input),
        OspfPacketType::LinkStateAcknowledgment => map(
            Ospfv3LinkStateAcknowledgmentPacket::parse,
            Ospfv3Packet::LinkStateAcknowledgment,
        )(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

pub fn parse_ospfv2_packet_header(input: &[u8]) -> IResult<&[u8], Ospfv2PacketHeader> {
    Ospfv2PacketHeader::parse(input)
}

pub fn parse_ospfv2_hello_packet(input: &[u8]) -> IResult<&[u8], OspfHelloPacket> {
    OspfHelloPacket::parse(input)
}

pub fn parse_ospfv2_database_description_packet(
    input: &[u8],
) -> IResult<&[u8], OspfDatabaseDescriptionPacket> {
    OspfDatabaseDescriptionPacket::parse(input)
}

pub fn parse_ospfv2_link_state_request_packet(
    input: &[u8],
) -> IResult<&[u8], OspfLinkStateRequestPacket> {
    OspfLinkStateRequestPacket::parse(input)
}

impl OspfLinkStateAdvertisement {
    pub fn parse(input: &[u8]) -> IResult<&[u8], OspfLinkStateAdvertisement> {
        let (_, word) = peek(be_u32)(input)?;
        let ls_type = (word & 0xff) as u8;
        match OspfLinkStateType(ls_type) {
            OspfLinkStateType::RouterLinks => map(
                OspfRouterLinksAdvertisement::parse,
                OspfLinkStateAdvertisement::RouterLinks,
            )(input),
            OspfLinkStateType::NetworkLinks => map(
                OspfNetworkLinksAdvertisement::parse,
                OspfLinkStateAdvertisement::NetworkLinks,
            )(input),
            OspfLinkStateType::SummaryLinkIpNetwork => map(
                OspfSummaryLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::SummaryLinkIpNetwork,
            )(input),
            OspfLinkStateType::SummaryLinkAsbr => map(
                OspfSummaryLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::SummaryLinkAsbr,
            )(input),
            OspfLinkStateType::ASExternalLink => map(
                OspfASExternalLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::ASExternalLink,
            )(input),
            OspfLinkStateType::NSSAASExternal => map(
                OspfNSSAExternalLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::NSSAASExternal,
            )(input),
            OspfLinkStateType::OpaqueLinkLocalScope => map(
                OspfOpaqueLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::OpaqueLinkLocalScope,
            )(input),
            OspfLinkStateType::OpaqueAreaLocalScope => map(
                OspfOpaqueLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::OpaqueAreaLocalScope,
            )(input),
            OspfLinkStateType::OpaqueASWideScope => map(
                OspfOpaqueLinkAdvertisement::parse,
                OspfLinkStateAdvertisement::OpaqueASWideScope,
            )(input),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
        }
    }
}

impl Ospfv3LinkStateAdvertisement {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Ospfv3LinkStateAdvertisement> {
        let (_, word) = peek(be_u32)(input)?;
        let ls_type = (word & 0xffff) as u16;
        match Ospfv3LinkStateType(ls_type) {
            Ospfv3LinkStateType::RouterLSA => {
                map(Ospfv3RouterLSA::parse, Ospfv3LinkStateAdvertisement::Router)(input)
            }
            Ospfv3LinkStateType::NetworkLSA => map(
                Ospfv3NetworkLSA::parse,
                Ospfv3LinkStateAdvertisement::Network,
            )(input),
            Ospfv3LinkStateType::InterAreaPrefixLSA => map(
                Ospfv3InterAreaPrefixLSA::parse,
                Ospfv3LinkStateAdvertisement::InterAreaPrefix,
            )(input),
            Ospfv3LinkStateType::InterAreaRouterLSA => map(
                Ospfv3InterAreaRouterLSA::parse,
                Ospfv3LinkStateAdvertisement::InterAreaRouter,
            )(input),
            Ospfv3LinkStateType::ASExternalLSA => map(
                Ospfv3ASExternalLSA::parse,
                Ospfv3LinkStateAdvertisement::ASExternal,
            )(input),
            Ospfv3LinkStateType::NSSALSA => map(
                Ospfv3ASExternalLSA::parse,
                Ospfv3LinkStateAdvertisement::NSSA,
            )(input),
            Ospfv3LinkStateType::LinkLSA => {
                map(Ospfv3LinkLSA::parse, Ospfv3LinkStateAdvertisement::Link)(input)
            }
            Ospfv3LinkStateType::IntraAreaPrefixLSA => map(
                Ospfv3IntraAreaPrefixLSA::parse,
                Ospfv3LinkStateAdvertisement::IntraAreaPrefix,
            )(input),
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
        }
    }
}

pub(crate) fn parse_ospf_vec_u32(
    packet_length: u16,
    offset: usize,
) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<u32>> {
    move |input: &[u8]| parse_ospf_vec_u32_f(input, packet_length, offset)
}

fn parse_ospf_vec_u32_f(
    input: &[u8],
    packet_length: u16,
    offset: usize,
) -> IResult<&[u8], Vec<u32>> {
    if packet_length as usize == offset {
        return Ok((input, Vec::new()));
    }
    if (packet_length as usize) < offset || packet_length as usize - offset > input.len() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (data, rem) = input.split_at(packet_length as usize - offset);
    let (_, routers) = many0(be_u32_complete)(data)?;
    Ok((rem, routers))
}

pub(crate) fn parse_ospf_external_tos_routes(
    packet_length: u16,
) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<OspfExternalTosRoute>> {
    move |input: &[u8]| parse_ospf_external_tos_routes_f(input, packet_length)
}

fn parse_ospf_external_tos_routes_f(
    input: &[u8],
    packet_length: u16,
) -> IResult<&[u8], Vec<OspfExternalTosRoute>> {
    if packet_length == 36 {
        return Ok((input, Vec::new()));
    }
    // 36 is the offset of the first external TOS Route
    if packet_length < 36 || packet_length as usize - 36 > input.len() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (data_routes, rem) = input.split_at(packet_length as usize - 36);
    let (_, routes) = many0(complete(OspfExternalTosRoute::parse))(data_routes)?;
    Ok((rem, routes))
}

pub(crate) fn parse_ospf_tos_routes(
    packet_length: u16,
) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<OspfTosRoute>> {
    move |input: &[u8]| parse_ospf_tos_routes_f(input, packet_length)
}

fn parse_ospf_tos_routes_f(input: &[u8], packet_length: u16) -> IResult<&[u8], Vec<OspfTosRoute>> {
    if packet_length == 28 {
        return Ok((input, Vec::new()));
    }
    // 28 is the offset of the first TOS Route
    if packet_length < 28 || packet_length as usize - 28 > input.len() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (data_routes, rem) = input.split_at(packet_length as usize - 28);
    let (_, routes) = many0(complete(OspfTosRoute::parse))(data_routes)?;
    Ok((rem, routes))
}

pub(crate) fn parse_ospfv3_router_links(
    packet_length: u16,
) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<Ospfv3RouterLink>> {
    move |input: &[u8]| parse_ospfv3_router_links_f(input, packet_length)
}

fn parse_ospfv3_router_links_f(
    input: &[u8],
    packet_length: u16,
) -> IResult<&[u8], Vec<Ospfv3RouterLink>> {
    if packet_length == 24 {
        return Ok((input, Vec::new()));
    }
    if packet_length < 24 || packet_length as usize - 24 > input.len() {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    let (data, rem) = input.split_at(packet_length as usize - 24);
    let (_, v) = many0(complete(Ospfv3RouterLink::parse))(data)?;
    Ok((rem, v))
}

pub(crate) fn take_vec_u8(length: u8) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<u8>> {
    move |input: &[u8]| map(take(length), |b: &[u8]| b.to_vec())(input)
}
