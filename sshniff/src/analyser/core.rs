use crate::analyser::utils;
use std::collections::HashMap;
use rtshark::{Packet, RTShark, RTSharkBuilder};


pub fn analyse(streams: &HashMap<u32, Packet>) {
    log::info!("Starting analysis.");

    for stream in streams {

    }
}

// Looks at first 50 packets
// Finds (21) New Keys packet (Client)
// Gets lengths of next four packets
// Performs dark magic calculation that actually determines TCP length of keystrokes.
// TODO: Maybe more useful to return a hashmap of: "keystroke_size": xyz, "login_size": xyz, so I
// don't have to keep coming back to decipher what index is what item...
// Temporarily:
// 0: Stream
// 1: Reverse Keystroke Size
// 2: New_Keys_1
// 3: New_Keys_2
// 4: New_Keys_3
// 5: Login Size
pub fn find_meta_size(stream: u32, packets: &Vec<Packet>) -> Result<[u32; 6], &'static str> {
    log::info!("Determining keystroke sizings");
    let meta_size: [u32; 6];
    let new_keys_code: u8 = 21;
//    let size_newkeys_next: u32;
//    let size_newkeys_next2: u32;
//    let size_newkeys_next3: u32;
//    let size_login_prompt: u32;
//    let size_reverse_keystroke: u32;


    // Looking at the first 50 packets should be sufficient (taken from PacketStrider)
    for (i, packet) in packets.iter().enumerate().take(50) {
        
        // Can we just unwrap?
        let ssh_layer = match packet.layer_name("ssh") {
            Some(layer) => layer,
            None => continue,
        };

        let message_code = match ssh_layer.metadata("ssh.message_code") {
            Some(meta) => meta.value().parse::<u8>().unwrap(),
            None => continue,
        };

        if message_code == new_keys_code {
            // TODO: This is neat but unreadable once I came back to it. 
            // We look ahead to the next four packets following the New Keys (21) packet.
            // We get the packets' respective TCP lengths.
            // Packet i+1 to i+3: "new keys x"
            // Packet i+4: Size of login prompt
            // These sizes are used to perform a calculation that reveals the keystroke packets'
            // TCP length.
            let sizes = (1..=4)
                .map(|offset| {
                    packets.get(i + offset)
                        .and_then(|p| p.layer_name("tcp"))
                        .and_then(|tcp_layer| tcp_layer.metadata("tcp.len"))
                        .map(|meta| meta.value().parse::<u32>())
                        .ok_or("TCP layer or length metadata not found")
                        .and_then(|res| res.map_err(|_| "Parsing TCP length failed")) 
                }).collect::<Result<Vec<u32>, _>>()?;

            if sizes.len() == 4 {
                // This is the "magic observation" that somehow predicts the "reverse" keystroke TCP len. 
                // Explanation TBD, I have read a bunch of OpenSSH source code and can still not figure out
                // why this works.
                // Clarification: it does not predict the "forward" keystroke len. Forward is just
                // New Keys +1 -8, apparently.
                let size_reverse_keystroke = sizes[0] - 8 + 40;

                meta_size = [
                    stream,
                    size_reverse_keystroke,
                    sizes[0],
                    sizes[1],
                    sizes[2],
                    sizes[3],
                ];

                return Ok(meta_size);
            }

            return Err("Not enough packets following the New Keys packet");
        }
    }

    Err("New Keys packet not found within the first 50 packets")
//        // Check if message_code == 21 --> New Keys
//        match ssh_layer.metadata("ssh.message_code") {
//            Some(meta) => {
//                if meta.value().parse::<u8>().expect("Message code is always a digit.") == new_keys_code {
//                    // Look ahead one packet to get size_newkeys_next
//                    let next_packet = &packets[i+1];
//                    size_newkeys_next = next_packet.layer_name("tcp").unwrap()
//                        .metadata("tcp.len").unwrap()
//                        .value().parse::<u32>().expect("TCP length is always a digit.");
//
//                    // Look ahead two packets to get size_newkeys_next2
//                    let next_packet = &packets[i+2];
//                    size_newkeys_next2 = next_packet.layer_name("tcp").unwrap()
//                        .metadata("tcp.len").unwrap()
//                        .value().parse::<u32>().expect("TCP length is always a digit.");
//
//                    // Look ahead three packets to get size_newkeys_next3
//                    let next_packet = &packets[i+3];
//                    size_newkeys_next3 = next_packet.layer_name("tcp").unwrap()
//                        .metadata("tcp.len").unwrap()
//                        .value().parse::<u32>().expect("TCP length is always a digit.");
//
//                    // Look ahead four packets to get login prompt size
//                    let next_packet = &packets[i+4];
//                    size_login_prompt = next_packet.layer_name("tcp").unwrap()
//                        .metadata("tcp.len").unwrap()
//                        .value().parse::<u32>().expect("TCP length is always a digit.");
//
//                    // "Magical Observation" 
//                    // No idea how he figured this out, but it actually correctly calculates the
//                    // size of each keystroke's TCP length. 
//                    size_reverse_keystroke = size_newkeys_next - 8 + 40;
//
//                    meta_size[0] = stream;
//                    meta_size[1] = size_reverse_keystroke;
//                    meta_size[2] = size_newkeys_next;
//                    meta_size[3] = size_newkeys_next2;
//                    meta_size[4] = size_newkeys_next3;
//                    meta_size[5] = size_login_prompt;
//
//                    break;
//                } 
//            }
//            None => continue,
//        }
//    }
//
//    Ok(meta_size)
}

pub fn find_meta_hassh(packets: &Vec<Packet>) -> Result<[String; 2], &'static str> {
    log::info!("Calculating hassh");

    let mut hassh_client_found: bool = false;
    let mut hassh_server_found: bool = false;
    let mut sport: u32;
    let mut dport: u32;

    // TODO:
    // All of these can be IMMUTABLE but the compiler is too dumb to see that the if statement does
    // not allow them to be assigned multiple times, or there's somehow an edge case that I am
    // missing. Fix the muts, because it is giving me heartache. FFS

    // Client to Server (cts) -> hassh
    let mut client_kex: &str;
    let mut client_enc_algs_cts: &str;
    let mut client_mac_algs_cts: &str;
    let mut client_cmp_algs_cts: &str;
    let mut hassh_algorithms: String;
    let mut hassh = None;

    // Server to Client (stc) -> hassh_server
    let mut server_kex: &str;
    let mut server_enc_algs_stc: &str;
    let mut server_mac_algs_stc: &str;
    let mut server_cmp_algs_stc: &str;
    let mut hassh_server_algorithms: String;
    let mut hassh_server = None;

    for packet in packets.iter().take(50) {
        if hassh_client_found && hassh_server_found {
            break;
        }
        
        let ssh_layer = packet.layer_name("ssh").ok_or("SSH layer not found")?;
        
        let message_code = match ssh_layer.metadata("ssh.message_code") {
            Some(metadata) => metadata.value().parse::<u32>().unwrap(),
            None => continue,
        };

        // Check for Key Exchange Init (20)
        if message_code != 20 {
            continue;
        }

        let tcp_layer = packet.layer_name("tcp").unwrap();

        // TODO: There has GOT to be a nicer way of doing these operations. 
        sport = tcp_layer.metadata("tcp.srcport").unwrap().value().parse().unwrap();
        dport = tcp_layer.metadata("tcp.dstport").unwrap().value().parse().unwrap();


        if (sport > dport) && !hassh_client_found {
            client_kex = ssh_layer.metadata("ssh.kex_algorithms")
                .ok_or("ssh.kex_algorithms not found")?.value();
            client_enc_algs_cts = ssh_layer.metadata("ssh.encryption_algorithms_client_to_server")
                .ok_or("ssh.encryption_algorithms_client_to_server not found")?.value();
            client_mac_algs_cts = ssh_layer.metadata("ssh.mac_algorithms_client_to_server")
                .ok_or("ssh.mac_algorithms_client_to_server not found")?.value();
            client_cmp_algs_cts = ssh_layer.metadata("ssh.compression_algorithms_client_to_server")
                .ok_or("ssh.compression_algorithms_client_to_server not found")?.value();

            hassh_algorithms = [client_kex, client_enc_algs_cts, client_mac_algs_cts, client_cmp_algs_cts].join(";");
            hassh = Some(utils::get_md5_hash(hassh_algorithms));
            hassh_client_found = true;
        } else if (dport > sport) && !hassh_server_found {
            server_kex = ssh_layer.metadata("ssh.kex_algorithms")
                .ok_or("ssh.kex_algorithms not found")?.value();
            server_enc_algs_stc = ssh_layer.metadata("ssh.encryption_algorithms_server_to_client")
                .ok_or("ssh.encryption_algorithms_server_to_client not found")?.value();
            server_mac_algs_stc = ssh_layer.metadata("ssh.mac_algorithms_server_to_client")
                .ok_or("ssh.mac_algorithms_server_to_client not found")?.value();
            server_cmp_algs_stc = ssh_layer.metadata("ssh.compression_algorithms_server_to_client")
                .ok_or("ssh.compression_algorithms_server_to_client not found")?.value();

            hassh_server_algorithms = [server_kex, server_enc_algs_stc, server_mac_algs_stc, server_cmp_algs_stc].join(";");
            hassh_server = Some(utils::get_md5_hash(hassh_server_algorithms));
            hassh_server_found = true;
        }
    }
    // TODO:
    // Here, he adds a check for sport < dport, saying kex packets may arrive out-of-order, so they
    // sip, dip, sport, dport are switched. Not sure how this can happen or affect our
    // implementation, but something to watch out for during testing.
    
    Ok([hassh.ok_or("Failed to get hassh")?, hassh_server.ok_or("Failed to get hassh_server")?])
}

pub fn find_meta_protocol(packets: &Vec<Packet>) -> Result<[String; 6], &'static str> {
    assert!(packets.len() > 0);

    let mut protocol_client = None;
    let mut protocol_server = None;

    // We hAvE to initialise sip and dip to stop the compiler from yapping about uninitialised
    // variables, despite ASSERTING that the loop will run at least once.
    // Yes, now writing this I see that even if the loop runs we can hit continues that would cause
    // the variables to remain uninited, but leave me be I've been coding for a long time.
    let mut sport = 0;
    let mut dport = 0;
    let mut sip: &str = "";
    let mut dip: &str = "";

    for packet in packets.iter().take(50) {
        if protocol_server.is_some() && protocol_client.is_some() {
            break;
        }

        let ssh_layer = packet.layer_name("ssh").ok_or("SSH layer not found")?;
        
        // Looking for ssh.protocol packet
        let protocol = match ssh_layer.metadata("ssh.protocol") {
            Some(protocol) => protocol.value(),
            None => continue,
        };

        let ip_layer = packet.layer_name("ip").unwrap();
        let tcp_layer = packet.layer_name("tcp").unwrap();

        // Get source/dest IP/port
        sip = ip_layer.metadata("ip.src").ok_or("Source IP not found")?.value();
        dip = ip_layer.metadata("ip.dst").ok_or("Destination IP not found")?.value();
        sport = tcp_layer.metadata("tcp.srcport").ok_or("Source port not found")?.value()
            .parse().map_err(|_| "Parsing source port failed")?;
        dport = tcp_layer.metadata("tcp.dstport").ok_or("Destination port not found")?.value()
            .parse().map_err(|_| "Parsing destination port failed")?;

        if sport > dport && protocol_client.is_none() {
            protocol_client = Some(protocol.to_string());
        } else if dport > sport && protocol_server.is_none() {
            protocol_server = Some(protocol.to_string());
        }
    }

    // Under the assumption that the Client Protocol packet always comes before the Server Protocol
    // packet, the final sip/dip sport/dport will be swapped, since they will be assigned from the
    // Server packet. Hence, we swap the values.

    let tmp_ip = sip;
    let tmp_port = sport;
    sip = dip;
    sport = dport;
    dip = tmp_ip;
    dport = tmp_port;

    Ok([
        protocol_client.ok_or("Failed to get client protocol")?,
        protocol_server.ok_or("Failed to get server protocol")?,
        sip.to_string(),
        sport.to_string(),
        dip.to_string(),
        dport.to_string()
    ])
}

//pub fn extract_core_info(stream:u32, packets: &Vec<Packet>) -> Result<[u32; 12], &'static str> {
//    let kex_init_code = 20;
//    let new_keys_code = 21;
//
//    let mut meta_size: [u32; 5];
//
//    for (i, packet) in packets.iter().enumerate().take(50) {
//        
//        // Can we just unwrap?
//        let ssh_layer = match packet.layer_name("ssh") {
//            Some(layer) => layer,
//            None => continue,
//        };
//
//        let message_code = match ssh_layer.metadata("ssh.message_code") {
//            Some(meta) => meta.value().parse::<u8>().unwrap(),
//            None => continue,
//        };
//        
//        match message_code {
//            kex_init_code => {
//                let packets_after = [packets.get(i+1).unwrap(), packets.get(i+2).unwrap(), packets.get(i+3).unwrap(), packets.get(i+4).unwrap()];
//                meta_size = get_sizes(packets_after)?;
//            },
//            new_keys_code => {
//
//            }
//        };
//
//        if message_code == new_keys_code {
//            // We look ahead to the next four packets following the New Keys (21) packet.
//            // We get the packets' respective TCP lengths.
//            // Packet i+1 to i+3: "new keys x"
//            // Packet i+4: Size of login prompt
//            // These sizes are used to perform a calculation that reveals the keystroke packets'
//            // TCP length.
//            let sizes = (1..=4)
//                .map(|offset| {
//                    packets.get(i + offset)
//                        .and_then(|p| p.layer_name("tcp"))
//                        .and_then(|tcp_layer| tcp_layer.metadata("tcp.len"))
//                        .map(|meta| meta.value().parse::<u32>())
//                        .ok_or("TCP layer or length metadata not found")
//                        .and_then(|res| res.map_err(|_| "Parsing TCP length failed")) 
//                }).collect::<Result<Vec<u32>, _>>()?;
//
//            if sizes.len() == 4 {
//                // This is the "magic observation" that somehow predicts the keystroke TCP len. 
//                // Explanation TBD, I have read a bunch of OpenSSH source code and can still not figure out
//                // why this works.
//                let size_reverse_keystroke = sizes[0] - 8 + 40;
//
//                let meta_size = [
//                    stream,
//                    size_reverse_keystroke,
//                    sizes[0],
//                    sizes[1],
//                    sizes[2],
//                    sizes[3],
//                    0,
//                    0,
//                    0,
//                    0,
//                    0,
//                    0
//                ];
//
//                return Ok(meta_size);
//            }
//
//            return Err("Not enough packets following the New Keys packet");
//        }
//    }
//
//    Err("New Keys packet not found within the first 50 packets")
//}
//
//// TODO: this can be refactored to much simpler code. 
//// Currently just a PoC to see if we can have one function iterating the packets and outsourcing to
//// sub-functions wherever necessary to handle codes and extract the necessary information.
//fn get_sizes(packets_after: [&Packet; 4]) -> Result<[u32; 5], &'static str> {
//    // We look ahead to the next four packets following the New Keys (21) packet.
//    // We get the packets' respective TCP lengths.
//    // Packet +1 to +3: "new keys x"
//    // Packet +4: Size of login prompt
//    // These sizes are used to perform a calculation that reveals the keystroke packets'
//    // TCP length.
//    let sizes = (1..=4)
//        .map(|offset| {
//            packets_after.get(offset)
//                .and_then(|p| p.layer_name("tcp"))
//                .and_then(|tcp_layer| tcp_layer.metadata("tcp.len"))
//                .map(|meta| meta.value().parse::<u32>())
//                .ok_or("TCP layer or length metadata not found")
//                .and_then(|res| res.map_err(|_| "Parsing TCP length failed")) 
//        }).collect::<Result<Vec<u32>, _>>()?;
//
//    if sizes.len() == 4 {
//        // This is the "magic observation" that somehow predicts the keystroke TCP len. 
//        // Explanation TBD, I have read a bunch of OpenSSH source code and can still not figure out
//        // why this works.
//        let size_reverse_keystroke = sizes[0] - 8 + 40;
//
//        let meta_size = [
//            size_reverse_keystroke,
//            sizes[0],
//            sizes[1],
//            sizes[2],
//            sizes[3],
//        ];
//
//        return Ok(meta_size);
//    }
//
//    Err("Not enough packets following the New Keys packet")
//}

// TODO: 
// Populate with more pcaps, for each scenario.
// Kept the monolith, but maybe do away with file-loading (except for a single test) and then just
// use serialised vector objects with the state? 
#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    lazy_static!(
        static ref STREAMS: HashMap<u32, Vec<Packet>> = {
            utils::load_file("/home/outlaw/Desktop/Code/Rust/SSHniff/sshniff/test_captures/known_pass_lsal_id_exit.pcapng".to_string(), -1)
        };
    );

    #[test]
    fn test_meta_sizes() {
        let meta_size = find_meta_size(0, &STREAMS.get(&0).unwrap()).unwrap();
        // Reverse Keystroke Size
        assert_eq!(76, meta_size[1]);
        // Actual keystroke size 
        assert_eq!(36, meta_size[2]-8);
        // Prompt size
        assert_eq!(52, meta_size[5]);
    }

    #[test]
    fn test_hassh() {
        // hassh and hassh_server
        let meta_hassh = find_meta_hassh(&STREAMS.get(&0).unwrap()).unwrap();
        let hassh = meta_hassh[0].clone();
        let hassh_server = meta_hassh[1].clone();
        assert_eq!("aae6b9604f6f3356543709a376d7f657", hassh);
        assert_eq!("779664e66160bf75999f091fce5edb5a", hassh_server);
    }

    #[test]
    fn test_protocol() {
        // Protocols and source/destination
        let meta_protocol = find_meta_protocol(&STREAMS.get(&0).unwrap()).unwrap();
        let c_proto = meta_protocol[0].clone();
        let s_proto = meta_protocol[1].clone();
        let src = format!("{}:{}", meta_protocol[2], meta_protocol[3]);
        let dst = format!("{}:{}", meta_protocol[4], meta_protocol[5]);
        assert_eq!("SSH-2.0-OpenSSH_9.6", c_proto);
        assert_eq!("SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3", s_proto);
        assert_eq!("192.168.0.212:50502", src);
        assert_eq!("192.168.0.45:22", dst);
    }

    #[test]
    fn test_ordering() {
        // Ordered packets are as many as before sorting
        let mut size_matrix = utils::create_size_matrix(&STREAMS.get(&0).unwrap());
        let original_size = size_matrix.len();
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);
        assert_eq!(original_size, ordered.len());
    }

    #[test]
    fn test_reverse_r() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&STREAMS.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // No -R was used
        let reverse_r = utils::scan_for_reverse_session_r_option(&ordered, -52);
        assert!(reverse_r.is_none());
    }

    #[test]
    fn test_login() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&STREAMS.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // One login attempt- login successful
        let login = utils::scan_for_login_attempts(&ordered, -52);

        // Server login prompt preceding successful login
        let logged_in_at = login[0].0;
        assert_eq!(2163, logged_in_at.seq);
    }

    #[test]
    fn test_keystrokes() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&STREAMS.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // TODO: better keystroke checking (check for type?)
        let keystrokes = utils::scan_for_keystrokes(&ordered, 36, 20);
        assert_eq!(15, keystrokes.len());
    }

    #[test]
    fn test_key_login() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&STREAMS.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // No key was used
        let key_log = utils::scan_for_key_login(&ordered, -52);
        assert!(!key_log);
    }

    #[test]
    fn test_monolith() {
        let streams = utils::load_file("/home/outlaw/Desktop/Code/Rust/SSHniff/sshniff/test_captures/known_pass_lsal_id_exit.pcapng".to_string(), -1);
        let stream_id = streams.keys().into_iter().next().unwrap();

        assert_eq!(0, *stream_id);
        assert_eq!(1, streams.len());

        let meta_size = find_meta_size(*stream_id, &streams.get(stream_id).unwrap()).unwrap();
        // Reverse Keystroke Size
        assert_eq!(76, meta_size[1]);
        // Actual keystroke size 
        assert_eq!(36, meta_size[2]-8);
        // Prompt size
        assert_eq!(52, meta_size[5]);

        // hassh and hassh_server
        let meta_hassh = find_meta_hassh(&streams.get(stream_id).unwrap()).unwrap();
        let hassh = meta_hassh[0].clone();
        let hassh_server = meta_hassh[1].clone();
        assert_eq!("aae6b9604f6f3356543709a376d7f657", hassh);
        assert_eq!("779664e66160bf75999f091fce5edb5a", hassh_server);

        // Protocols and source/destination
        let meta_protocol = find_meta_protocol(&streams.get(stream_id).unwrap()).unwrap();
        let c_proto = meta_protocol[0].clone();
        let s_proto = meta_protocol[1].clone();
        let src = format!("{}:{}", meta_protocol[2], meta_protocol[3]);
        let dst = format!("{}:{}", meta_protocol[4], meta_protocol[5]);
        assert_eq!("SSH-2.0-OpenSSH_9.6", c_proto);
        assert_eq!("SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3", s_proto);
        assert_eq!("192.168.0.212:50502", src);
        assert_eq!("192.168.0.45:22", dst);

        // Ordered packets are as many as before sorting
        let mut size_matrix = utils::create_size_matrix(&streams.get(stream_id).unwrap());
        let original_size = size_matrix.len();
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);
        assert_eq!(original_size, ordered.len());

        // No -R was used
        let reverse_r = utils::scan_for_reverse_session_r_option(&ordered, -52);
        assert!(reverse_r.is_none());

        // One login attempt- login successful
        let login = utils::scan_for_login_attempts(&ordered, -52);
        assert_eq!(1, login.len());
        assert!(login[0].1);

        // let hostkey_acc = utils::scan_for_host_key_accepts(&vv, login[2].0.index);
        
        // Server login prompt preceding successful login
        let logged_in_at = login[0].0;
        assert_eq!(2163, logged_in_at.seq);

        // TODO: better keystroke checking (check for type?)
        let keystrokes = utils::scan_for_keystrokes(&ordered, 36, logged_in_at.index);
        assert_eq!(15, keystrokes.len());

        // No key was used
        let key_log = utils::scan_for_key_login(&ordered, -52);
        assert!(!key_log);
    }
}
