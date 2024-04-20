//! Contains custom structs, enums, and impls.
use rtshark::Packet;
use serde::{ser::SerializeStruct, Serialize};
use std::fmt;

/// Keystroke implementation
#[derive(Clone, Debug, Serialize)]
pub struct Keystroke {
    /// Inferred type of keystroke
    pub k_type: KeystrokeType,
    /// UNIX timestamp taken from [rtshark] [Packet]
    pub timestamp: i64,
    /// Returned bytes; `None` for typical keystrokes, `Some()` for [Enter](KeystrokeType::Enter)
    pub response_size: Option<u128>,
    /// tcp.seq
    pub seq: i64,
}

/// Types of Keystroke
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum KeystrokeType {
    /// Regular Keystroke
    Keystroke,
    /// Backspace/Delete Keystroke
    Delete,
    /// Tab-completion Keystroke
    Tab,
    /// Return/Enter Keystroke
    Enter,
    /// Left/Right arrow key 
    ArrowHorizontal,
    /// Up/Down arrow key
    ArrowVertical,
    /// Unknown Keystroke
    Unknown,
}

/// Things that we are looking for before successful login.
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

/// Packet representation for easier access.
#[derive(Clone, Debug)]
pub struct PacketInfo<'a> {
    /// Index in the stream array/slice.
    pub index: usize,
    /// tcp.seq.
    pub seq: i64,
    /// tcp.len - We use [i32] to indicate STC packets with a negative length.
    pub length: i32,    
    /// Reference to "original" [Packet].
    pub packet: &'a Packet,
    /// Optional description for later printing.
    pub description: Option<String>,  
}

impl<'a> PacketInfo<'a> {
    /// Constructor that does most of the heavy lifting using an existing [Packet].
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

/// [Serde](serde) serialiser for output/saving.
impl Serialize for PacketInfo<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        let mut state = serializer.serialize_struct("PacketInfo", 3)?;
        state.serialize_field("tcp.seq", &self.index)?;
        state.serialize_field("tcp.len", &self.length)?;
        state.serialize_field("description", &self.description.clone().unwrap_or("".to_string()))?;
        state.end()
    }
}

