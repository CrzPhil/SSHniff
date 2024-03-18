use rtshark::Packet;

#[derive(Clone, Debug)]
pub enum KeystrokeType {
    Keystroke,
    Delete,
    Tab,
    Enter,
}

// Things that we are looking for before successful login.
#[derive(Debug, PartialEq)]
pub enum Event {
    WrongPassword,
    CorrectPassword,
    RejectedKey,
    AcceptedKey,
}

#[derive(Clone, Copy, Debug)]
pub struct PacketInfo<'a> {
    pub index: usize,
    pub seq: i64,
    pub length: i32,    // We use i32 to allow for negative values, indicating server packets
    pub packet: &'a Packet,
    pub description: Option<&'a str>,   // For later printing (?)
}

impl<'a> PacketInfo<'a> {
    pub fn new(packet: &'a Packet, index: usize, description: Option<&'a str>) -> Self {
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

#[derive(Clone, Debug)]
pub struct Keystroke {
    pub k_type: KeystrokeType,
    pub timestamp: i64,
    pub response_size: Option<u128>,
}


