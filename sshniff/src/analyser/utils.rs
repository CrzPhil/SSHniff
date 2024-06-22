//! Contains utilities and helper functions that aid in Packet processing.
use rtshark::{Packet, RTShark};
use core::panic;
use std::{collections::HashMap, usize};
use md5::{Digest, Md5};
use super::containers::PacketInfo;
use hex;

/// Constant upper boundary for what might be considered a keystroke.
/// Important to keep track of this because it pops up in comparison operations 
/// and needs to be uniform, especially when sorting the initial stream.
pub const KEYSTROKE_UPPER_BOUND: i32 = 16;

/// Iterates through rtshark packets, checking for streams and adding them to a hashmap.
///
/// Packets are added per-stream into the map. If the nstreams argument is set, only add that
/// stream to the map for further processing.
pub fn get_streams(rtshark: &mut RTShark, stream: i32) -> HashMap<u32, Vec<Packet>> {
    log::info!("Collecting streams.");
    let mut stream_map: HashMap<u32, Vec<Packet>> = HashMap::new();

    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        log::error!("Error parsing TShark output when collecting streams: {e}");
        None 
    }) {
        if let Some(tcp) = packet.layer_name("tcp") {
            let stream_id = tcp.metadata("tcp.stream").expect("tcp.stream expected in TCP packet").value();

            match stream_id.parse::<u32>() {
                Ok(stream_id) => {
                    if stream != -1 && stream_id != u32::try_from(stream).expect("Stream ID conversion error") {
                        continue;
                    }

                    stream_map.entry(stream_id).or_insert_with(Vec::new).push(packet);
                },
                Err(_) => log::warn!("Failed to parse tcp.stream metadata as u32"),
            }
        }
    }

    stream_map
}

/// Loads PCAP/PCAPNG file via rtshark.
///
/// Display filters used (adapted from Packet Strider):
/// `ssh && !tcp.analysis.spurious_retransmission && !tcp.analysis.retransmission &&
/// !tcp.analysis.fast_retransmission`
/// Calls get_streams() after loading packets.
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

/// Checks is a [Packet] is a server packet.
/// Helper function that does some onion peeling on [Packet]s.
pub fn is_server_packet(packet: &Packet) -> bool {
        let tcp_layer = packet.layer_name("tcp").unwrap();
        tcp_layer.metadata("tcp.dstport").unwrap().value().parse::<u32>().unwrap() > tcp_layer.metadata("tcp.srcport").unwrap().value().parse::<u32>().unwrap()
}

/// Transform an rtshark packet slice into a vector of PacketInfo objects.
///
/// Saves us the constant unwrapping of tcp and ssh layers / metadata to access the info we want.
/// STC packets' lengths are negative, indicating the Server -> Client direction.
pub fn create_size_matrix(packets: &[Packet]) -> Vec<PacketInfo> {
    log::info!("Creating PacketInfo matrix.");
    packets.iter().enumerate().map(|(index, packet)| { 
        let tcp_layer = packet.layer_name("tcp").unwrap();
        let length: i32 = tcp_layer.metadata("tcp.len").unwrap().value().parse().unwrap();
        let is_server_packet = is_server_packet(&packet);
        let adjusted_length = if is_server_packet { -length } else { length };

        let seq = tcp_layer.metadata("tcp.seq").unwrap().value().parse().unwrap();
        PacketInfo {
            index,
            seq,
            length: adjusted_length,
            packet,
            description: None,
        }
    }).collect()
}

/// Orders [PacketInfo]s into their inferred order of being sent. 
///
/// To do so, for every keystroke-length packet, we look ahead a few packets for a server echo,
/// which may have been sent out-of-order. We add both to the ordered vector. 
/// Rinse and repeat until all packets are ordered.
/// There's some nuance to this as server echoes sometimes differ in size. 
/// We account for that by checking up to keystroke_size + [KEYSTROKE_UPPER_BOUND] as possible responses.
pub fn order_keystrokes<'a>(packet_infos: &mut Vec<PacketInfo<'a>>, keystroke_size: u32) -> Vec<PacketInfo<'a>> {
    log::info!("Ordering keystrokes.");
    let mut ordered_packets: Vec<PacketInfo<'a>> = Vec::new();
    let size = packet_infos.len();

    let curr: usize = 0;
    let mut found_match;

    while ordered_packets.len() < size {
        found_match = false;

        if is_keystroke(&packet_infos[curr], keystroke_size) {
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
                } 
                // Echoes are sometimes slightly larger (see scan.rs), so we need to account for that.
                else if packet_infos[curr+itr].length == -(keystroke_size as i32 + 8) || packet_infos[curr+itr].length == -(keystroke_size as i32 + KEYSTROKE_UPPER_BOUND) {
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

pub fn order_obfuscated_keystrokes<'a>(packet_infos: &mut Vec<PacketInfo<'a>>, keystroke_size: u32) -> Vec<PacketInfo<'a>> {
    log::info!("Ordering obfuscated keystrokes.");
    let mut ordered_packets: Vec<PacketInfo<'a>> = Vec::new();
    //let size = packet_infos.len();

    let curr: usize = 0;
    let mut found_match;

    log::debug!("{} total packets.", packet_infos.len());

    let mut fat_packets = Vec::new();

    while !packet_infos.is_empty() {
        found_match = false;

        // Will catch initial keystroke and all the chaff
        if is_keystroke(&packet_infos[curr], keystroke_size / 2) {
            ordered_packets.push(packet_infos.remove(curr));
            let mut itr: usize = 0;
            while !found_match && itr < packet_infos.len() && itr < 10 {
                // Found server echo of keystroke
                if packet_infos[curr+itr].length == -(keystroke_size as i32  / 2) {
                    // We remove it from the original vec and add it to ordered.
                    // This is done so we don't match the same response to multiple forward packets
                    // that might have been sent successively before the first resposne is
                    // intercepted.
                    ordered_packets.push(packet_infos.remove(curr+itr));
                    found_match = true;
                } 
                // Echoes are sometimes slightly larger (see scan.rs), so we need to account for that.
                else if packet_infos[curr+itr].length == -((keystroke_size as i32 / 2) + 8) || packet_infos[curr+itr].length == -((keystroke_size as i32 / 2) + KEYSTROKE_UPPER_BOUND) {
                    ordered_packets.push(packet_infos.remove(curr+itr));
                    found_match = true;
                }
                itr += 1;
            }
            if !found_match {
                ordered_packets.push(packet_infos.remove(curr));
            }
        } else if is_keystroke(&packet_infos[curr], keystroke_size) {

            // dbg
            if packet_infos[curr].seq == 9238 {
                log::warn!("Packet spotted.");
            }

            // Will catch fat packets
            ordered_packets.push(packet_infos.remove(curr));
            fat_packets.push(ordered_packets.len());

            // This is zero because we removed the curr so we are looking at the first packet after curr at itr=0
            // Itr basically only increments when we are dealing with consecutive client packets.
            let mut itr: usize = 0;
            while !found_match && itr < packet_infos.len() && itr < 10 {
                if packet_infos[curr+itr].length == -(keystroke_size as i32 / 2) {

                    // PROBABLY a RET because 3 consecutive stc packets, so don't delete consecutive server-side packets
                    if packet_infos[curr+1].length < 0 && packet_infos[curr+2].length < 0 {
                        log::debug!("Probably a RET"); 
                        while packet_infos[curr+itr].length < 0 {
                            log::debug!("Adding ret response: {}", packet_infos[curr+itr].seq);
                            // shifts remaining elements left so we don't increment itr
                            ordered_packets.push(packet_infos.remove(curr+itr));
                            //packet_infos.remove(curr+itr);
                        }
                        found_match = true; 
                        break;
                    }
                    // look ahead 4 packets to ensure we aren't skipping the actual echo in lieu of chaff
                    // this should actually always just be a +1 lookahead maximum, but better safe, I guess
                    for j in 1..=4 {
                        if packet_infos[curr+itr+j].length == -((keystroke_size as i32 / 2) + 8) || packet_infos[curr+itr+j].length == -((keystroke_size as i32 / 2) + KEYSTROKE_UPPER_BOUND) {
                            ordered_packets.push(packet_infos.remove(curr+itr+j));
                            packet_infos.remove(curr+itr);
                            found_match = true;
                            break;
                        }
                    } 
                    if !found_match {
                        // We remove the echo from the original array, but also the second chaff echo, without adding it to the ordered array.
                        ordered_packets.push(packet_infos.remove(curr+itr));
                        packet_infos.remove(curr+itr);
                        found_match = true;
                    }
                } 
                // Echoes are sometimes slightly larger (see scan.rs), so we need to account for that.
                else if packet_infos[curr+itr].length == -((keystroke_size as i32 / 2) + 8) || packet_infos[curr+itr].length == -((keystroke_size as i32 / 2) + KEYSTROKE_UPPER_BOUND) {
                    ordered_packets.push(packet_infos.remove(curr+itr));
                    packet_infos.remove(curr+itr);
                    found_match = true;
                }
                itr += 1;
            }
            if !found_match {
                ordered_packets.push(packet_infos.remove(curr));
            }
        }
        
        else {
            // If non-keystroke, just add to the ordered vector
            ordered_packets.push(packet_infos.remove(curr));
        }
    }
    log::debug!("{} ordered packets.", ordered_packets.len());
    log::debug!("{} fat packets.", fat_packets.len());
    log::debug!("{:?}", fat_packets);

    ordered_packets
}

/// Unpacks an rtshark Packet to check for- and return the ssh.message_code, if it exists.
pub fn get_message_code(packet: &Packet) -> Option<u32> {
    let ssh_layer = packet.layer_name("ssh").expect("No ssh layer found when seeking message code");

    let message_code = match ssh_layer.metadata("ssh.message_code") {
        Some(message_code) => Some(message_code.value().parse::<u32>().unwrap()),
        None => None,
    };

    message_code
}

/// Checks if a [PacketInfo] is a keystroke.
/// Probably a stupid method now that I look at it... only used once.
fn is_keystroke(packet: &PacketInfo, keystroke_size: u32) -> bool {
    packet.length == keystroke_size as i32
}

/// MD5 Hash for HASSSH calculations. 
pub fn get_md5_hash(string_in: String) -> String {
    let mut hasher = Md5::new();
    hasher.update(string_in);
    let result = hasher.finalize();
    
    hex::encode(result)
}

/// Given two comma-separated lists of arbitrary entries, but in this case KEX or ENC algorithms, find the negotiated one.
/// 
/// The transmitted lists are already in 'preferred' order (see RFC-4253), so we just find the first mutual option.
pub fn find_common_algorithm(first: &str, second: &str) -> Option<String> {
    let entries_a: Vec<&str> = first.split(',').collect();
    let entries_b: Vec<&str> = second.split(',').collect();
    let set_b: std::collections::HashSet<&str> = entries_b.into_iter().collect();

    for entry in entries_a {
        if set_b.contains(entry) {
            return Some(entry.to_string());
        }
    }

    None
}

/// Determine if protocol version indicates post-patch version of OpenSSH
/// 
/// Of course, clients might have the version but disabled Obfuscation. 
/// This is a temporary hacky fix to showcase the bypass as a PoC.
pub fn is_obfuscated(client: &str, server: &str) -> bool {
    let versions = ["9.5", "9.6", "9.7", "9.8"];
    let mut clientv = false;
    let mut serverv = false;
    for &version in versions.iter() {
        if client.contains(version) {
            clientv = true;
        }
        if server.contains(version) {
            serverv = true;
        }
    }
    return clientv && serverv;
}