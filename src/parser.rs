use crate::ospf::*;
use nom::combinator::{map, peek};
use nom::error::{make_error, ErrorKind};
use nom::number::streaming::{be_u16, be_u32};
pub use nom::IResult;

pub fn parse_ospf_packet(input: &[u8]) -> IResult<&[u8], OspfPacket> {
    let (_, word) = peek(be_u16)(input)?;
    let b0 = (word >> 8) as u8;
    let b1 = (word & 0xff) as u8;
    if b0 != 2 {
        return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
    }
    match OspfPacketType(b1) {
        OspfPacketType::Hello => map(OspfHelloPacket::parse, OspfPacket::Hello)(input),
        OspfPacketType::DatabaseDescription => map(
            OspfDatabaseDescriptionPacket::parse,
            OspfPacket::DatabaseDescription,
        )(input),
        OspfPacketType::LinkStateRequest => map(
            OspfLinkStateRequestPacket::parse,
            OspfPacket::LinkStateRequest,
        )(input),
        OspfPacketType::LinkStateUpdate => map(
            OspfLinkStateUpdatePacket::parse,
            OspfPacket::LinkStateUpdate,
        )(input),
        OspfPacketType::LinkStateAcknowledgment => map(
            OspfLinkStateAcknowledgmentPacket::parse,
            OspfPacket::LinkStateAcknowledgment,
        )(input),
        _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
    }
}

pub fn parse_ospf_packet_header(input: &[u8]) -> IResult<&[u8], OspfPacketHeader> {
    OspfPacketHeader::parse(input)
}

pub fn parse_ospf_hello_packet(input: &[u8]) -> IResult<&[u8], OspfHelloPacket> {
    OspfHelloPacket::parse(input)
}

pub fn parse_ospf_database_description_packet(
    input: &[u8],
) -> IResult<&[u8], OspfDatabaseDescriptionPacket> {
    OspfDatabaseDescriptionPacket::parse(input)
}

pub fn parse_ospf_link_state_request_packet(
    input: &[u8],
) -> IResult<&[u8], OspfLinkStateRequestPacket> {
    OspfLinkStateRequestPacket::parse(input)
}

// pub(crate) fn parse_ospf_count_lsa(input: &[u8], count: u32) -> IResult<&[u8], Vec<OspfRouterLinksAdvertisement>> {

// }

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
            _ => Err(nom::Err::Error(make_error(input, ErrorKind::Tag))),
        }
    }
}
