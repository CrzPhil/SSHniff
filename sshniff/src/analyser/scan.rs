use core::panic;
use std::{u128, usize};
use crate::analyser::utils::{self, get_message_code};
use super::containers::{PacketInfo, Event, KeystrokeType, Keystroke};

/// Returns timestamp of -R initiation (or None)
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

/// Finds and classifies keystrokes from a given session. 
///
/// Determines keystroke type based on size and context.
pub fn scan_for_keystrokes<'a>(packet_infos: &'a[PacketInfo<'a>], keystroke_size: i32, logged_in_at: usize) -> Vec<Keystroke> {
    // Start after logged_in_at
    let mut index = logged_in_at;
    let mut keystrokes: Vec<Keystroke> = Vec::new();

    // We look ahead two packets at most
    while index < packet_infos.len() - 2 {
        // TODO: looks like if there are previous commands and arrow=up, the echo size can give
        // away information about how long the command is. Longer command = larger size. 
        // Also, left & right arrows seem to always echo keystroke_size, whereas up and down vary
        // in sizes; depending on failure, success, command length, etc.
        
        // Arrow keys seem to be keystroke_size + 8 from client, echo may be keystroke_size-
        // depends on what arrow key and if there are previous commands. Setting 16 as bound.
        // TODO !!! : This 16 is also set in ordered_packets, better to set a const somewhere to ensure
        // parity
        if packet_infos[index].length > keystroke_size && packet_infos[index].length <= (keystroke_size + 16) { 
            let next_packet = &packet_infos[index+1];
            // Problem:
            // If the cursor is not at the end of the command and a character is typed/deleted, the
            // returned echo is larger (+8) than keystroke_size. How do we stop it from being
            // interpreted as a Return? probably need to loop inside this match until Return, then
            // skip the sequence.
            
            // Left arrow seems to echo keystroke_size, Right arrow (if before end of command)
            // seems to echo same size (> keystroke_size)
            if next_packet.length == -keystroke_size || next_packet.length == packet_infos[index].length {
                log::debug!("Horizontal Arrow: {}", packet_infos[index].seq);
                keystrokes.push(Keystroke {
                    k_type: KeystrokeType::ArrowHorizontal,
                    timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                    response_size: None,
                    seq: packet_infos[index].seq,
                });

                let arrow_length = packet_infos[index].length;

                // We move forward two packets; We now loop through packets that could be
                // keystrokes or backspaces, until we hit a return, indicated by multiple
                // sequential server packets.
                index += 2;

                // Problem: 
                // Packet ordering breaks important sequences that allow us to infer the arrow
                // keys and subsequent actions.
                loop {
                    if utils::is_server_packet(packet_infos[index+2].packet) {
                        break;
                    }
                    // Deletion echoes are same size, but we can't reliably distinguish between
                    // keystrokes and deletions after moving into the command with arrows.
                    if packet_infos[index].length == keystroke_size && packet_infos[index+1].length == -arrow_length {
                        log::debug!("Delete OR Keystroke: {}", packet_infos[index].seq);
                        keystrokes.push(Keystroke {
                            k_type: KeystrokeType::Unknown,
                            timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                            response_size: None,
                            seq: packet_infos[index].seq,
                        });
                    }
                    // interestingly, it looks like keystroke echoes can be larger if in the middle
                    // of the command. But not always.
                    else if packet_infos[index].length == keystroke_size && packet_infos[index+1].length < -arrow_length {
                        log::debug!("Delete OR Keystroke: {}", packet_infos[index].seq);
                        keystrokes.push(Keystroke {
                            k_type: KeystrokeType::Unknown,
                            timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                            response_size: None,
                            seq: packet_infos[index].seq,
                        });
                    }
                    // Check for further arrow keys
                    else if packet_infos[index].length == arrow_length { //&& packet_infos[index+1].length == -keystroke_size 
                        log::debug!("Horizontal Arrow: {}", packet_infos[index].seq);
                        keystrokes.push(Keystroke {
                            k_type: KeystrokeType::ArrowHorizontal,
                            timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                            response_size: None,
                            seq: packet_infos[index].seq,
                        });
                    }
                    // If we are back to Client/Server echos of keystroke_size, we must be at the
                    // end of the command and can exit this loop.
                    // I am not sure if we can reach this point, though.
                    else if packet_infos[index].length == keystroke_size && packet_infos[index+1].length == -keystroke_size {
                        todo!("Reachable?")
                    } 

                    index += 2;
                }
                continue;
            } else {
                log::debug!("Vertical Arrow: {}", packet_infos[index].seq);
                keystrokes.push(Keystroke {
                    k_type: KeystrokeType::ArrowVertical,
                    timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                    response_size: None,
                            seq: packet_infos[index].seq,
                });
            }
            index += 2;
            continue;
        } else if packet_infos[index].length != keystroke_size {
            index += 1;
            continue;
        }

        let next_packet = &packet_infos[index+1];
        let next_next_packet = &packet_infos[index+2];

        // Check for keystroke -> response (echo) -> keystroke 
        // Edge case in OR statement: normal keystroke followed by arrow key (larger size)
        if next_packet.length == -keystroke_size && next_next_packet.length == keystroke_size || next_next_packet.length == keystroke_size + 8 {
            log::debug!("Keystroke: {}", packet_infos[index].seq);
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Keystroke,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
                            seq: packet_infos[index].seq,
            });
        } 
        // Backspace/Delete results in an echo that is keystroke_size + 8
        // Problem: Ctrl+a (jump to start) and Ctrl+e also fulfill this condition.
        else if next_packet.length == -(keystroke_size + 8) && next_next_packet.length == keystroke_size {
            log::debug!("Delete: {}", packet_infos[index].seq);
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Delete,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
                            seq: packet_infos[index].seq,
            });
        } 
        // Tab, TBD if feasible
        else if next_packet.length < -(keystroke_size + 8) && next_next_packet.length == keystroke_size {
            log::debug!("Tab: {}", packet_infos[index].seq);

            // TODO: refer to observation in notes -> I suspect this is far from fine-tuned.
            keystrokes.push(Keystroke {
                k_type: KeystrokeType::Tab,
                timestamp: packet_infos[index].packet.timestamp_micros().unwrap(),
                response_size: None,
                            seq: packet_infos[index].seq,
            });
        } 
        // Returns are also keystroke_size, but we can distinguish them from the additional data
        // packets returned. 
        else if next_packet.length <= -keystroke_size && next_next_packet.length <= -keystroke_size && !keystrokes.is_empty() {
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
                            seq: packet_infos[index].seq,
            });

            // We already set index = end in the loop, so no increment needed.
            continue;
        }

        index += 2;
    }

    keystrokes
}

/// Scans for packet signature of Agent forwarding
///
/// TODO: Testing has shown this as inconclusive. 
/// I cannot verify the described behaviour; the Server-Client sandwich is found, but also in non-agent-forwarding connections.
/// Further, the sizings are off and inconsistent. As this is low-priority, I will postpone implementation and research. 
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

/// Looks for client's acceptance of server's SSH host key.
///
/// Happens when pubkey is in known_hosts.
pub fn scan_for_host_key_accepts<'a>(packet_infos: &[PacketInfo<'a>], logged_in_at: usize) -> Option<PacketInfo<'a>> {
    log::info!("Looking for host key acceptance by Client.");
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
        result = packet_infos[index-1].clone();
        result.description = Some("Server hostkey accepted".to_string());
        
        return Some(result); 
    }

    None
}

// TODO (feature)
// We can add a check for when a stream's last packet is prompt_size, pretty sure this indicates a
// rejected login and connection termination.
// TODO: (verify) Looks like key offer sizes are static for each key:
// checked -> similar- yes, static- no. Testing with other server showed a disparity by a few bytes. So
// padding/algorithm-dependent? The former maybe, the latter definitely. Guess we'll have to go
// through all algorithms, on different servers, and see if we can create a spectrum to classify
// these properly. In the test the encryption was the same, but Kex algs were different;
// curve25519-sha256 for the "smaller" packets, sntrup761x25519-sha512@openssh.com with +8 bytes.
// Set same KexAlgorithm where sntrup was used; same byte disparity, so likely unrelated.
// I get the impression that this is more server-dependant rather than on the client side. 
//
// Note that server response sizes seem to also grow- and shrink accordingly to the variance in the
// client packet:
// e.g.,            ECDSA -> 264 (wireshark), accepted key responds with 232 (wireshark).
// On another day,  ECDSA -> 262 (wireshark), accepted key responds with 230 (wireshark).

// 
// RSA: 492-500 (558-560-568 in wireshark view) -> NOTE! 558/560 in WS are both tcp=492 bytes.
// ED25519: 140-148 (206-208-216 in wireshark view)
// ECDSA: 188-196-204-212 (256-264-272-280 (280 seen with aes256-gcm@openssh.com cipher) in wireshark view)
// DSA: TBD
//
// TODO: With ETM ciphers with known length, we can have a separate classification, perhaps even
// more precise.
pub fn _scan_for_key_offers<'a>(packet_infos: &'a[PacketInfo<'a>], prompt_size: i32) -> Vec<(&'a PacketInfo<'a>, bool)> {
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

/// Scans for login-related findings, such as key offers, key accepts/rejects, password attempts.
///
/// Uses research findings of packet length ranges to classify key types (RSA, ED25519, ECDSA).
pub fn scan_login_data<'a>(packet_infos: &[PacketInfo<'a>], prompt_size: i32, new_keys_index: usize, logged_in_at: usize) -> Vec<PacketInfo<'a>> {
    let offset = new_keys_index;
    // We only care about the slice of packets between the first login prompt and up to the
    // successful logon.
    let initial_prompt = packet_infos
                            .iter()
                            .skip(offset)
                            .take(logged_in_at - offset)
                            .find(|packet_info| packet_info.length == prompt_size)
                            .unwrap_or_else(|| {
                                log::error!("Failed to find initial login prompt.");
                                panic!("Initial login prompt not found.");
                            }).index;

    //let mut events: Vec<Event> = Vec::new();
    let mut event_packets: Vec<PacketInfo> = Vec::new();

    let mut ptr: usize = initial_prompt;

    let mut curr_packet: &PacketInfo = &packet_infos[ptr];
    let mut next_packet: &PacketInfo;
    let mut next_next_packet: &PacketInfo;
    let mut event_packet: PacketInfo;
    while (ptr + 2)  < packet_infos.len() && curr_packet.index != logged_in_at {
        curr_packet = &packet_infos[ptr];
        next_packet = &packet_infos[ptr+1];
        next_next_packet = &packet_infos[ptr+2];

        // A client packet sandwiched between prompt_size'd packets means either of two things:
        // 1. A wrong password attempt 
        // 2. A key was offered and rejected
        if next_next_packet.length == prompt_size {
            // To distinguish between these two options, we must compare the client packet's size
            // to known pubkey offerings' sizes
            
            // RSA: 492-500 (558-560-568 in wireshark view) -> NOTE! 558/560 in WS are both tcp=492 bytes.
            // ED25519: 140-148 (206-208-216 in wireshark view)
            // ECDSA: 188-196-204-212 (256-264-272-280 (280 seen with aes256-gcm@openssh.com cipher) in wireshark view)
            let event = match next_packet.length {
                492..=500 => {
                    log::debug!("RSA key offered and rejected.");
                    //events.push(Event::OfferRSAKey);
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferRSAKey.to_string());
                    event_packets.push(event_packet);
                    Event::RejectedKey
                },
                140..=148 => {
                    log::debug!("ED25519 key offered and rejected.");
                    //events.push(Event::OfferED25519Key);
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferED25519Key.to_string());
                    event_packets.push(event_packet);
                    Event::RejectedKey
                },
                188..=212 => {
                    log::debug!("ECDSA key offered and rejected.");
                    //events.push(Event::OfferECDSAKey);
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferECDSAKey.to_string());
                    event_packets.push(event_packet);
                    Event:: RejectedKey
                },
                _ => {
                    log::debug!("Wrong password attempt detected.");
                    Event::WrongPassword
                },
            };

            event_packet = next_next_packet.clone();
            event_packet.description = Some(event.to_string());
            event_packets.push(event_packet);
        } 
        // This MUST be a successful login. 
        // if ptr=prompt_size, then it must have been via a valid password:
        // prompt_size -> <password> -> SSH2_MSG_USERAUTH_SUCCESS
        else if next_next_packet.index == logged_in_at {
            if curr_packet.length == prompt_size {
                event_packet = next_next_packet.clone();
                event_packet.description = Some(Event::CorrectPassword.to_string());
                event_packets.push(event_packet);
                break;
            }
        }
        // If the packet-after-next is not prompt-sized, it means a key was offered and accepted 
        else {
            // Again, the distinguishing factor will be the client packet's size.
            // However, there is the edge case of an accepted key that is NOT used to authenticate.
            // In that case, the prompt will be larger, indicating an accepted key, but if the
            // private key is not found, or not specified, then the user is still prompted for a
            // password. 
            // The only distinguishing factor I can see is that with a password-protected key, the
            // packet size is much larger than on password-based authentication.
            // Otherwise, of course, latencies can be used to infer key-based vs password-based,
            // especially with unencrypted private keys.
            let event = match next_packet.length {
                492..=500 => {
                    log::debug!("RSA key offered and accepted.");
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferRSAKey.to_string());
                    event_packets.push(event_packet);
                    Event::AcceptedKey
                },
                140..=148 => {
                    log::debug!("ED25519 key offered and accepted.");
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferED25519Key.to_string());
                    event_packets.push(event_packet);
                    Event::AcceptedKey
                },
                188..=212 => {
                    log::debug!("ECDSA key offered and accepted.");
                    event_packet = next_packet.clone();
                    event_packet.description = Some(Event::OfferECDSAKey.to_string());
                    event_packets.push(event_packet);
                    Event::AcceptedKey 
                },
                _ => {
                    log::debug!("Correct password detected.");
                    Event::CorrectPassword
                },
            };

            event_packet = next_next_packet.clone();
            event_packet.description = Some(event.to_string());
            event_packets.push(event_packet);

            // The next packet after the accept key offer may be a password, or another key offer.
            // (at curr_packet + 4)
            if packet_infos[ptr+4].index == logged_in_at {
                break;
            }
        }

        // Increment twice because we only want server packets
        ptr += 2;
    }

    log::debug!("{event_packets:?}");
    event_packets
}

/// Looks for signature SSH2_MSG_USERAUTH_SUCCESS server response packet.
pub fn find_successful_login(packet_infos: &[PacketInfo]) -> Option<usize> {
    // Maybe, if the SshSession struct comes to fruition, we can use the Cipher field to tailor
    // this comparison to the current session, instead of comparing it to "all" possibilities (yes,
    // currently only two, but there could be more- now, and in future.)
    
    for (index, packet_info) in packet_infos.iter().take(40).enumerate() {
        // See `notes.md` for how we get to these two lengths for the current common ciphers.
        if packet_info.length == -28 || packet_info.length == -36 {
            log::debug!("Successful login at packet {index}, sequence number {}", packet_info.seq);
            return Some(index);
        }
    }

    None
}

