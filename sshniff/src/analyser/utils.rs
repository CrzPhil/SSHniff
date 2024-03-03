use rtshark::{Packet, RTShark};
use core::panic;
use std::{collections::HashMap, string::FromUtf8Error};
use md5::{Md5, Digest};
use hex;


#[derive(Clone, Copy, Debug)]
pub struct PacketInfo<'a> {
    index: usize,
    pub seq: i64,
    pub length: i32,    // We use i32 to allow for negative values, indicating server packets
    packet: &'a Packet,
}

// If nstreams is not set, we need to iterate through the file and return all the streams to
// iterate through.
pub fn get_streams(rtshark: &mut RTShark, stream: i32) -> HashMap<u32, Vec<Packet>> {
    log::info!("Collecting streams.");
    let mut stream_map: HashMap<u32, Vec<Packet>> = HashMap::new();


    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
    log::error!("Error parsing TShark output when collecting streams: {e}");
    None 
    }) 
    {
        // TODO: Is this really the cleanest/fastest way to discern between all streams and N
        // stream?
        match stream {
            -1 => {
                if let Some(tcp) = packet.layer_name("tcp") {
                    let meta = tcp.metadata("tcp.stream").unwrap();
                    let stream_id: u32 = meta.value().parse().expect("Metadata stream value assumed to be parseable digit.");
        
                    if !stream_map.contains_key(&stream_id) {
                        stream_map.insert(stream_id, vec![packet]);
                    } else {
                        match stream_map.get_mut(&stream_id) {
                            Some(packets) => packets.push(packet),
                            None => continue,
                        };
                    }
                }
            },
            _ => {
                if let Some(tcp) = packet.layer_name("tcp") {
                    let meta = tcp.metadata("tcp.stream").unwrap();
                    let stream_id: u32 = meta.value().parse().expect("Metadata stream value assumed to be parseable digit.");
        
                    // Only add N stream to map
                    if stream_id != stream.try_into().unwrap() {
                        continue;
                    }

                    if !stream_map.contains_key(&stream_id) {
                        stream_map.insert(stream_id, vec![packet]);
                    } else {
                        match stream_map.get_mut(&stream_id) {
                            Some(packets) => packets.push(packet),
                            None => continue,
                        };
                    }
                }
            }
        }
    }

    stream_map
}

pub fn load_file(filepath: String, stream: i32) -> HashMap<u32, Vec<Packet>> {
    log::info!("Loading capture file.");

    let filter = String::from("\
        ssh &&\
        !tcp.analysis.spurious_retransmission &&\
        !tcp.analysis.retransmission &&\
        !tcp.analysis.fast_retransmission\
    ");

    let builder = rtshark::RTSharkBuilder::builder()
        .input_path(&filepath)
        .display_filter(&filter);
    
    let mut rtshark = match builder.spawn() {
        Err(err) => {
            log::error!("Error spawning tshark: {err}"); 
            panic!();
        }
        Ok(rtshark) => {
            log::info!("Reading from {}", filepath);
            rtshark
        }
    };
    
    let streams = get_streams(&mut rtshark, stream);
    rtshark.kill();

    streams
}

pub fn get_md5_hash(string_in: String) -> String {
    let mut hasher = Md5::new();
    hasher.update(string_in);
    let result = hasher.finalize();
    
    hex::encode(result)
}

pub fn create_size_matrix(packets: &Vec<Packet>) -> Vec<PacketInfo> {
    packets.iter().enumerate().map(|(index, packet)| { 
        let tcp_layer = packet.layer_name("tcp").unwrap();
        let length: i32 = tcp_layer.metadata("tcp.len").unwrap().value().parse().unwrap();
        let is_server_packet = tcp_layer.metadata("tcp.dstport").unwrap().value() > tcp_layer.metadata("tcp.srcport").unwrap().value();
        let adjusted_length = if is_server_packet { -length } else { length };

        let seq = tcp_layer.metadata("tcp.seq").unwrap().value().parse().unwrap();
        PacketInfo {
            index,
            seq,
            length: adjusted_length,
            packet,
        }
    }).collect()
}

pub fn order_keystrokes<'a>(packet_infos: &mut Vec<PacketInfo<'a>>, keystroke_size: i32) -> Vec<PacketInfo<'a>> {
    log::info!("Ordering keystrokes.");
    let mut ordered_packets: Vec<PacketInfo<'a>> = Vec::new();
    let size = packet_infos.len();

    let curr: usize = 0;
    let mut found_match;

    while ordered_packets.len() < size {
        found_match = false;

        if pinfo_is_keystroke(&packet_infos[curr], keystroke_size) {
            ordered_packets.push(packet_infos.remove(curr));
            let mut itr: usize = 0;
            while !found_match && itr < packet_infos.len() && itr < 10 {
                // Found server echo of keystroke
                if packet_infos[curr+itr].length == -(keystroke_size as i32) {
                    // We remove it from the original vec and add it to ordered.
                    // This is done so we don't match the same response to multiple forward packets
                    // that might have been sent successively before the first resposne is
                    // intercepted.
                    ordered_packets.push(packet_infos.remove(curr+itr));
                    found_match = true;
                } else if packet_infos[curr+itr].length == -(keystroke_size as i32 + 8) {
                    // TODO
                    // Why the +8? When is a keystroke response 8 bytes larger?
                    // Maybe with RET or TAB completion, i've definitely seen this happen.
                    ordered_packets.push(packet_infos.remove(curr+itr));
                    found_match = true;
                }
                itr += 1;
            }
            if !found_match {
                ordered_packets.push(packet_infos.remove(curr));
            }
        } else {
            // If non-keystroke, just add to the ordered vector
            ordered_packets.push(packet_infos.remove(curr));
        }
    }

    ordered_packets
}

fn is_keystroke(packet: &Packet, keystroke_size: u32) -> bool {
    let tcp_layer = packet.layer_name("tcp").expect("TCP layer not found");
    tcp_layer.metadata("tcp.len").unwrap().value().parse::<u32>().unwrap() == keystroke_size
}

fn pinfo_is_keystroke(packet: &PacketInfo, keystroke_size: i32) -> bool {
    packet.length == keystroke_size
}



