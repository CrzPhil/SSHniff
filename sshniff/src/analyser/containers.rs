use rtshark::Packet;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Debug, Serialize)]
pub struct Keystroke {
    pub k_type: KeystrokeType,
    pub timestamp: i64,
    pub response_size: Option<u128>,
    pub seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum KeystrokeType {
    Keystroke,
    Delete,
    Tab,
    Enter,
    ArrowHorizontal,
    ArrowVertical,
    Unknown,
}

// Things that we are looking for before successful login.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    WrongPassword,
    CorrectPassword,
    OfferRSAKey,
    OfferECDSAKey,
    OfferED25519Key,
    OfferUnknownKey,
    RejectedKey,
    AcceptedKey,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug)]
pub struct PacketInfo<'a> {
    pub index: usize,
    pub seq: i64,
    pub length: i32,    // We use i32 to allow for negative values, indicating server packets
    pub packet: &'a Packet,
    pub description: Option<String>,   // For later printing (?)
}

impl<'a> PacketInfo<'a> {
    pub fn new(packet: &'a Packet, index: usize, description: Option<String>) -> Self {
        let tcp_layer = packet.layer_name("tcp").unwrap();
        let seq = tcp_layer.metadata("tcp.seq").unwrap().value().parse::<i64>().unwrap();
        let mut length = tcp_layer.metadata("tcp.len").unwrap().value().parse::<i32>().unwrap();

        let srcport: u32 = tcp_layer.metadata("tcp.srcport").unwrap().value().parse().unwrap();
        let dstport: u32 = tcp_layer.metadata("tcp.dstport").unwrap().value().parse().unwrap();

        // Server-to-Client indicated by negative length
        if dstport > srcport {
            length = -length;
        }

        Self {
            index,
            seq,
            length,
            packet,
            description,
        }
    }
}

