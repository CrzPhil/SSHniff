use rtshark::{Packet, RTShark};
use core::panic;
use std::{collections::HashMap, u128};
use md5::{Digest, Md5};
use hex;

#[derive(Clone, Debug)]
pub enum KeystrokeType {
    Keystroke,
    Delete,
    Tab,
    Enter,
}

#[derive(Clone, Copy, Debug)]
pub struct PacketInfo<'a> {
    pub index: usize,
    pub seq: i64,
    pub length: i32,    // We use i32 to allow for negative values, indicating server packets
    packet: &'a Packet,
}

#[derive(Clone, Debug)]
pub struct Keystroke {
    pub k_type: KeystrokeType,
    pub timestamp: i64,
    pub response_size: Option<u128>,
}

// If nstreams is not set, we need to iterate through the file and return all the streams to
// iterate through.
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
                    // TODO - investigate/improve
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

// Returns timestamp of -R initiation (or None)
pub fn scan_for_reverse_session_r_option(ordered_packets: &Vec<PacketInfo>, prompt_size: i32) -> Option<i64> {
    let size = ordered_packets.len();
    let first_timestamp = ordered_packets[0].packet.timestamp_micros().unwrap();

    for (index, packet_info) in ordered_packets.iter().take(40).enumerate() {
        let packet = packet_info.packet;
        let ssh_layer = packet.layer_name("ssh").unwrap();
        // TODO: What if we store message codes in PacketInfo as Options?
        let message_code = match ssh_layer.metadata("ssh.message_code") {
            Some(message_code) => message_code.value().parse::<u32>().unwrap(),
            None => continue,
        };
        // TODO: Even better, what if we keep track of index of essential New Keys and other such
        // packets?
        if message_code != 21 {
            continue;
        }

        // Look ahead for -R signature (7 packets)
        // Initial offset at 4, because NewKeys+4 = login prompt size
        let mut offset = 4;

        while (index + offset + 7) < size && offset < 20 {
            // We're looking for a successful login sequence.
            if ordered_packets[index+offset].length != prompt_size {
                //log::debug!("Expected login prompt size at New Keys + 4 but found length: {}", ordered_packets[index+offset].length);
                offset += 1;
                continue;
            }
            // If the second-to-next packet is a login prompt, too, it means login failed and we can skip
            // to the next login
            if ordered_packets[index+offset+2].length == prompt_size {
                offset += 2;
                continue;
            }
            
            // If we reach this point, index + offset is pointing to the login prompt of a
            // successful login sequence. We now analyse the next 7 packets for the -R signature.
            
            // TODO: fact-check/improve this. It's not always accurate. Also we need to find out
            // why these signatures exist.

            // This signature is "often but not always exhibited by mac clients when -R is used".
            if ordered_packets[index + offset + 3].length > 0 &&
            ordered_packets[index + offset + 4].length < 0 && 
            ordered_packets[index + offset + 4].length != prompt_size && 
            ordered_packets[index + offset + 5].length > 0 && 
            ordered_packets[index + offset + 6].length < 0 && 
            ordered_packets[index + offset + 6].length != prompt_size &&
            (ordered_packets[index + offset + 6].length.abs() < ordered_packets[index + offset + 5].length.abs())
            {
                // TODO: Why +10?
                let relative_timestamp = ordered_packets[index + 10].packet.timestamp_micros().unwrap() - first_timestamp;
                return Some(relative_timestamp);
            }

            // This signature is "often exhibited by ubuntu clients when -R is used".
            // Core differences:
            // 4 -> CTS
            // 5 -> STC
            // 5 != prompt_size
            // 7 -> CTS
            if ordered_packets[index + offset + 3].length > 0 &&
            ordered_packets[index + offset + 4].length > 0 && 
            ordered_packets[index + offset + 5].length != prompt_size && 
            ordered_packets[index + offset + 5].length < 0 && 
            ordered_packets[index + offset + 6].length < 0 && 
            ordered_packets[index + offset + 6].length != prompt_size &&
            (ordered_packets[index + offset + 6].length.abs() < ordered_packets[index + offset + 5].length.abs()) &&
            ordered_packets[index + offset + 7].length > 0
            {
                let relative_timestamp = ordered_packets[index + 10].packet.timestamp_micros().unwrap() - first_timestamp;
                return Some(relative_timestamp);
            }

            offset += 1;
        }
    }
    None
}

pub fn scan_for_keystrokes<'a>(packet_infos: &'a[PacketInfo<'a>], keystroke_size: i32, logged_in_at: usize) -> Vec<Keystroke> {
    let mut index = logged_in_at;
    let mut keystrokes: Vec<Keystroke> = Vec::new();

    while index < packet_infos.len() - 2 {
        if packet_infos[index].length != keystroke_size {
            index += 1;
            continue;
        }

        let next_packet = packet_infos[index+1];
        let next_next_packet = packet_infos[index+2];

        // Check for keystroke -> response (echo) -> keystroke
        if next_packet.length == -keystroke_size && next_next_packet.length == keystroke_size {
            log::debug!("Keystroke: {}", packet_infos[index].seq);
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Keystroke,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
            });
        } else if next_packet.length == -(keystroke_size + 8) && next_next_packet.length == keystroke_size {
            log::debug!("Delete: {}", packet_infos[index].seq);
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Delete,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
            });
        } else if next_packet.length < -(keystroke_size + 8) && next_next_packet.length == keystroke_size {
            log::debug!("Tab: {}", packet_infos[index].seq);

            // TODO: refer to observation in notes -> I suspect this is far from fine-tuned.
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Tab,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
            });
        } else if next_packet.length <= -keystroke_size && next_next_packet.length <= -keystroke_size && !keystrokes.is_empty() {
            log::debug!("Return: {}", packet_infos[index].seq);
            // After running a command (by sending enter/return), the return is echoed (but not -keystroke_size length, interestingly)
            // We then iterate through the next packets until a Client packet, which indicates the end of the response (at least for typical commands).
            let mut end: usize = index + 2;
            let mut response_size: u128 = 0;

            while end < packet_infos.len() {
                // Client packet indicates end of server block
                if packet_infos[end].length > 0 {
                    index = end;
                    break;
                }
                
                // TODO: In ciphers with known payload length, this can be optimised.
                // Currently this is just the length of the padded TCP packet(s)
                response_size += packet_infos[end].length.abs() as u128;
                end += 1;
            }
            
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Enter,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: Some(response_size),
            });

            // We already set index = end in the loop, so no increment needed.
            continue;
        }

        index += 2;
    }

    keystrokes
}

// Scan for packet signature of Agent forwarding
// TODO: Testing has shown this as inconclusive. 
// I cannot verify the described behaviour; the Server-Client sandwich is found, but also in non-agent-forwarding connections.
// Further, the sizings are off and inconsistent. As this is low-priority, I will postpone implementation and research. 
pub fn scan_for_agent_forwarding(packet_infos: &[PacketInfo]) {
    let mut ctr = 0;

    // According to Packet Strider, tell-tale client packet occurs between packets 18-22
    // TODO: verify/investigate this claim; fine-tune accordingly.
    for (index, packet_info) in packet_infos.iter().take(40).enumerate() {
        // Once again, only look after New Keys. Further argument to keep track of New Keys index.
        // TODO ^ 
        match get_message_code(&packet_info.packet) {
            Some(code) => {
                if code != 21 {
                    continue;
                }
            },
            None => continue,
        };
        // The New Keys (21) packet is *not* followed by message_code
        let next_packet = packet_infos[index+1].packet;
        match get_message_code(&next_packet) {
            Some(_) => continue,
            None => {}
        };

        // Tell-tale packet "is always surrounded by 2 Server packets before and 2 Server packets after"
        todo!("See comment above function definition.")        
    }
}

// Look for client's acceptance of server's SSH host key 
// Happens when pubkey is in known_hosts.
pub fn scan_for_host_key_accepts<'a>(packet_infos: &'a[PacketInfo<'a>], logged_in_at: usize) {
    let mut result: PacketInfo;

    for (index, packet_info) in packet_infos.iter().take(100).enumerate() {
        if index == logged_in_at {
            break;
        }

        let packet = packet_info.packet;
        let message_code = match get_message_code(&packet) {
            Some(code) => code,
            None => continue,
        };

        if message_code != 21 {
            continue;
        }

        let next_packet = packet_infos[index+1].packet;

        // The New Keys (21) packet is *not* followed by message_code
        match get_message_code(&next_packet) {
            Some(_) => continue,
            None => {}
        };

        // This is the packet containing the server's key fingerprint.
        // TODO: In packet strider this is simply logged, but I think it's worth keeping track of
        // this packet and actually outputting the fingerprint; maybe make it optional.
        let previous_packet = packet_infos[index-1].packet;
        let ssh_layer = previous_packet.layer_name("ssh");
    }
}

fn get_message_code(packet: &Packet) -> Option<u32> {
    let ssh_layer = packet.layer_name("ssh").unwrap();

    let message_code = match ssh_layer.metadata("ssh.message_code") {
        Some(message_code) => Some(message_code.value().parse::<u32>().unwrap()),
        None => None,
    };

    message_code
}

pub fn scan_for_key_login<'a>(packet_infos: &'a[PacketInfo<'a>], prompt_size: i32) -> bool {
    for (index, packet_info) in packet_infos.iter().take(40).enumerate() {
        // New Keys (21)
        match get_message_code(packet_info.packet) {
            Some(code) => {
                if code != 21 {
                    continue;
                }
            },
            None => continue,
        };

        // The New Keys (21) packet is *not* followed by message_code
        let next_packet = packet_infos[index+1].packet;
        match get_message_code(&next_packet) {
            Some(_) => continue,
            None => {}
        };

        assert!(index+8 <= packet_infos.len());

        // Check New Keys +4 == prompt_size, for redundancy (TODO?)
        if packet_infos[index + 4].length != prompt_size {
            // _Should_ never happen
            log::error!("Inconsistent login prompt detected.");
            return false;
        }

        // If a password prompt appears, it does so at NewKeys +8. 
        // If not, we only see prompt_size at +4, and +8 is differently sized. 
        return packet_infos[index + 8].length != prompt_size;
    }

    log::error!("Escaped the loop while looking for key-based login. _Should_ not happen.");
    false
}

// TODO: (verify) Looks like key offer sizes are static for each key:
// RSA: 492 (560 in wireshark view)
// ED25519: 140 (208 in wireshark view)
// ECDSA: 196 (264 in wireshark view)
// DSA: TBD
//
pub fn scan_for_key_offers<'a>(packet_infos: &'a[PacketInfo<'a>], prompt_size: i32) -> Vec<(&'a PacketInfo<'a>, bool)> {
    log::info!("Looking for key offers.");
    // TODO: (decide on standard)
    // I know at some spots we use the negative size as indication of STC packets, but here it
    // seems too cumbersome and counter-intuitive, as the stuff happening here can already be confusing.
    assert!(prompt_size > 0);

    // packet - was_accepted
    let mut offers: Vec<(&PacketInfo, bool)> = Vec::new();
    // Skip Kex init
    let offset = 8;

    for (index, packet_info) in packet_infos.iter().skip(offset).take(100).enumerate() {
        // Look for login prompt
        if packet_info.length.abs() != prompt_size {
            continue;
        }

        // If we get a login prompt, check next-next (current +2) packet for prompt_size
        // If prompt_size, it means a public key was offered (but not used to authenticate, either
        // because it was rejected or no private key was found/used to authenticate).
        let packet_after_next = &packet_infos[offset+index+2];

        if packet_after_next.length.abs() == prompt_size {
            // This is the client either offering a pubkey, or the client typing a wrong password.
            // We compare it to the known sizes; there might be a small probability of a
            // false-positive, if the password is buffered to the same size as a key. TODO
            let packet_next = &packet_infos[offset+index+1];
            // TODO 
            // Take this further and create an Enum; include in the output what keys were offered,
            // etc.
            match packet_next.length {
                492 => {
                    // RSA
                    log::debug!("Found RSA rejected key offer.");
                },
                140 => {
                    // ED25519
                    log::debug!("Found ED25519 rejected key offer.");
                },
                196 => {
                    // ECDSA
                    log::debug!("Found ECDSA rejected key offer.");
                },
                _ => {
                    // If it doesn't match a known keysize, then it was _most likely_ a wrong
                    // password.
                    log::debug!("Found wrong password attempt, sized {}", packet_next.length);
                    continue;
                }
            }
            // PubKey offered, rejected
            log::debug!("Found offered key of length {}, (rejected)", packet_next.length);
            offers.push((packet_after_next, false));
        } else if packet_after_next.length.abs() > prompt_size {
            // If the packet after next is larger in size, client either logged in, or, offered a
            // valid key

            // If the packet after next of the current packet after next (so current packet +4) is a login
            // prompt, then the client opted not to authenticate using the valid key.
            let packet_after_four = &packet_infos[offset+index+4];

            if packet_after_four.length.abs() == prompt_size {
                // This means a key was offered, accepted, but not used to authenticate.
                // i.e.: id_rsa.pub is in server's authorized_keys, but id_rsa was not used/found by
                // client to auth.
                // packet_after_four therefore indicates another prompt, either for another key
                // offer or for the actual password.
                let packet_next = &packet_infos[offset+index+1];

                log::debug!("Found offered key of length {}, (accepted)", packet_next.length);
                offers.push((packet_after_next, true));
            } else {
                // Not sure what else indicates. shouldn't happen, I guess.
                break;
            }
        } 
    }

    offers
}

// The first prompt occurs at New Keys +4. Whether the user actually sees it (gets prompted for a
// password) depends on whether there are any *public* keys in the ~/.ssh/ directory, as those will
// be offered first (if key auth is enabled on server). Pubkey is offered (Client -> Server), and
// if invalid, we get another prompt (Server -> Client). If the pubkey is accepted by the server, it will be
// caught by scan_for_key_login.
// Side-note, when offering a pubkey that is accepted by server, server sends a large packet that
// also contains the login prompt; debug message is "Server accepts key: ".
// This could be interesting for forensics.
pub fn scan_for_login_attempts<'a>(packet_infos: &'a[PacketInfo<'a>], prompt_size: i32) -> Vec<(&'a PacketInfo<'a>, bool)> {
    let mut attempts: Vec<(&PacketInfo, bool)> = Vec::new();

    let mut seen_first_prompt = false;
    // Skip Kex negotiation packets
    let offset = 8;
    // TODO (fix)
    // We have an edge case where if you log in after offering a valid key (but not using the
    // privkey to auth), the login prompt size is larger.
    // I suspect we can fix this when combining this function with the other login-related ones.
    // Reference: see offer_ed25519_acc.pcapng
    for (index, packet_info) in packet_infos.iter().skip(offset).take(300).enumerate() {
        if packet_info.length == prompt_size {
            if !seen_first_prompt {
                seen_first_prompt = true;
                continue;
            }
            if is_successful_login(&[packet_info, &packet_infos[index+offset+1], &packet_infos[index+offset+2]], prompt_size) {
                log::debug!("Sucessful login at {}", packet_info.seq);
                attempts.push((packet_info, true));
                break;
            }
            log::debug!("Failed login at {}", packet_info.seq);
            attempts.push((packet_info, false));
        }
    }

    attempts
}

fn is_successful_login(packet_triplet: &[&PacketInfo; 3], prompt_size: i32) -> bool {
    assert_eq!(packet_triplet[0].length, prompt_size);

    if packet_triplet[1].length > 0 && packet_triplet[2].length != prompt_size {
        return true;
    } 

    // TODO: this is in Packet Strider but I assume it's superfluous.
//    if packet_triplet[1].length > 0 && packet_triplet[2].length < 0 && packet_triplet[2].length != prompt_size {
//        return false;
//    } 

    false
}

fn is_keystroke(packet: &Packet, keystroke_size: u32) -> bool {
    let tcp_layer = packet.layer_name("tcp").expect("TCP layer not found");
    tcp_layer.metadata("tcp.len").unwrap().value().parse::<u32>().unwrap() == keystroke_size
}

fn pinfo_is_keystroke(packet: &PacketInfo, keystroke_size: i32) -> bool {
    packet.length == keystroke_size
}

pub fn get_md5_hash(string_in: String) -> String {
    let mut hasher = Md5::new();
    hasher.update(string_in);
    let result = hasher.finalize();
    
    hex::encode(result)
}

