//! Core of SSHniff.
//! Calls all [scan](super::scan) functions and aggregates them into a single [SshSession]. 
use crate::analyser::utils::is_server_packet;

use super::scan::{scan_for_host_key_accepts, scan_for_keystrokes, scan_login_data, find_successful_login, scan_for_reverse_session_r_option, scan_for_obfuscated_keystrokes};
use super::containers;
use super::utils;
use core::{panic, fmt};
use rtshark::Packet;
use serde::Serialize;
use chrono::{DateTime, TimeZone, Utc};

/// Struct containing the core characteristrics of a given SSH session.
///
/// Contains markers to optimise packet iteration as well as containers for results and keystroke
/// data. Passed from function to function during analysis and aggregates data.
#[derive(Debug, Serialize)]
pub struct SshSession<'a> {
    pub stream: u32,
    pub new_keys_at: usize,
    pub keystroke_size: u32,
    pub prompt_size: i32,
    pub protocols: (String, String),
    pub src: String,
    pub dst: String,
    pub hassh_s: String,
    pub hassh_c: String,
    pub algorithms: (String, String, String, String),
    pub logged_in_at: usize,
    pub start_utc: String,
    pub end_utc: String,
    pub results: Vec<containers::PacketInfo<'a>>,
    pub keystroke_data: Vec<Vec<containers::Keystroke>>,
}

impl<'a> fmt::Display for SshSession<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SshSession '{}' SRC '{}' DST '{}' HASSH_C '{}' HASSH_S '{}' KEX '{}' ENC '{}' MAC '{}' CMP '{}' NK '{}' KS '{}' PS '{}' LIA '{}' Protocols '{:?}'", self.stream, self.src, self.dst, self.hassh_c, self.hassh_s, self.algorithms.0, self.algorithms.1, self.algorithms.2, self.algorithms.3,  self.new_keys_at, self.keystroke_size, self.prompt_size, self.logged_in_at, self.protocols)
    }
}

/// Core analysis function creating the SshSession object with all extracted data.
///
/// Operates on a single packet stream; will have to be called iteratively for multiple streams.
/// The `only_meta` parameter allows the caller to skip keystroke analysis.
///     By default, the full analysis will run, unless only_meta = true.
pub fn analyse(stream_id: u32, packet_stream: &[Packet], only_meta: bool) -> SshSession {
    log::info!("Starting analysis.");

    let mut session = SshSession {
        stream: stream_id,
        new_keys_at: 0,
        keystroke_size: 0,
        prompt_size: 0,
        protocols: (String::new(), String::new()),
        src: String::new(),
        dst: String::new(),
        hassh_s: String::new(),
        hassh_c: String::new(),
        algorithms: (String::new(), String::new(), String::new(), String::new()),
        logged_in_at: 0,
        start_utc: String::new(),
        end_utc: String::new(),
        results: vec![],
        keystroke_data: vec![],
    };

    // Get start and end
    let timeframe = get_start_and_end(&packet_stream);
    session.start_utc = timeframe.0;
    session.end_utc = timeframe.1;

    // Get NewKeys, Keystroke Indicator, Login Prompt
    let kex = match find_meta_size(&packet_stream) {
        Ok(infos) => infos,
        Err(err) => {
            log::error!("{err}");
            panic!();
        },
    };

    session.results.push(kex[0].clone());
    session.results.push(kex[1].clone());
    session.results.push(kex[2].clone());
    session.new_keys_at = kex[0].index;
    //session.keystroke_size = kex[1].length as u32 - 8;
    session.prompt_size = kex[2].length;
    log::debug!("{session}");

    // Temporary measure to identify other ciphers
    let verify = alt_find_keystroke_size(&packet_stream);
    if verify == kex[1].length as u32 - 8 {
        session.keystroke_size = verify;
    } else {
        log::warn!("Disagreement when finding keystroke size. Relying on alternative method.");
        log::debug!("Alternative size: {}", verify);
        session.keystroke_size = verify;
    }

    let hassh_server: String;
    let hassh_client: String;
    let algorithms: (String, String, String, String);
    match find_meta_hassh(&packet_stream) {
        Ok(vals) => {
            hassh_server = String::from(&vals[0]);
            hassh_client = String::from(&vals[1]);
            algorithms = (String::from(&vals[2]), String::from(&vals[3]), String::from(&vals[4]), String::from(&vals[5]))
        }
        Err(err) => {
            log::error!("{err}");
            panic!();
        }
    }

    session.hassh_s = hassh_server;
    session.hassh_c = hassh_client;
    session.algorithms = algorithms;
    log::debug!("{session}");

    let protocols = match find_meta_protocol(packet_stream) {
        Ok(protocols) => protocols,
        Err(err) => {
            log::error!("{err}");
            panic!();
        }
    };
    log::debug!("{protocols:?}");
    session.protocols = (String::from(protocols[0].clone()), String::from(protocols[1].clone()));
    session.src = String::from(format!("{}:{}", protocols[2], protocols[3]));
    session.dst = String::from(format!("{}:{}", protocols[4], protocols[5]));

    let mut size_matrix = utils::create_size_matrix(packet_stream);

    // Hacky fix to accommodate Patch Bypass PoC
    // Once we know the protocol versions, we can account for chaff and find spikes
    let is_obfuscated = utils::is_obfuscated(&session.protocols.0,  &session.protocols.1);
    let ordered: Vec<containers::PacketInfo>;

    if  is_obfuscated {
        log::warn!("Session uses obfuscation! Metadata extraction is experimental.");
        session.keystroke_size *= 2;
        ordered = utils::order_obfuscated_keystrokes(&mut size_matrix, session.keystroke_size);
    } else {
        ordered = utils::order_keystrokes(&mut size_matrix, session.keystroke_size);
    }

    let logged_in_at = match find_successful_login(&ordered) {
        Some(index) => index,
        None => {
            log::error!("Failed to find login packet.");
            panic!();
        }
    };

    session.logged_in_at = logged_in_at;

    let login_events = scan_login_data(&ordered, session.prompt_size, session.new_keys_at, session.logged_in_at);
    session.results.extend(login_events);

    match scan_for_host_key_accepts(&ordered, session.logged_in_at) {
        Some(pinfo) => {
            // Hostkey acceptance occurs before the other events, so we set it first.
            session.results.insert(0, pinfo);
        },
        None => {
            log::error!("Failed to find Hostkey Acceptance.");
        }
    };

    // Skip keystroke analysis and processing if `only_meta` is true.
    if only_meta {
        return session;
    }

    let keystrokes;

    if is_obfuscated {
        keystrokes = scan_for_obfuscated_keystrokes(&ordered, session.keystroke_size as i32, session.logged_in_at);
    } else {
        keystrokes = scan_for_keystrokes(&ordered, session.keystroke_size as i32, session.logged_in_at);
    
    }

    if keystrokes.len() == 0 {
        log::warn!("Failed to find keystrokes using conventional method.");
        let keystroke_size = alt_find_keystroke_size(&packet_stream);
        let keystrokes_2 = scan_for_keystrokes(&ordered, keystroke_size as i32, session.logged_in_at);
        let processed = process_keystrokes(keystrokes);
        session.keystroke_data = processed;
    } else {
        let processed = process_keystrokes(keystrokes);
        session.keystroke_data = processed;
    }

    session
}

/// Gets the start and end datetime (UTC) of a packet stream as a tuple of Strings.
pub fn get_start_and_end(packets: &[Packet]) -> (String, String) {
    log::info!("Getting start and end time of session.");

    let start = packets.first();
    let last = packets.last();

    // I mean.. they have to be, right?
    assert!(start.is_some());
    assert!(last.is_some());

    let start_timestamp = start.unwrap().timestamp_micros().unwrap();
    let end_timestamp = last.unwrap().timestamp_micros().unwrap();

    let start_datetime: DateTime<Utc> = Utc.timestamp_micros(start_timestamp).unwrap();
    let end_datetime: DateTime<Utc> = Utc.timestamp_micros(end_timestamp).unwrap();

    (start_datetime.format("%Y-%m-%d %H:%M:%S").to_string(), end_datetime.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// Finds keystrokes via an alternative brute-forcy method.
/// 
/// When NewKeys+1 cannot be used to find keystroke len, this ought to do the trick.
pub fn alt_find_keystroke_size(packets: &[Packet]) -> u32 {
    log::info!("Employing alternative method to find keystroke size.");
    let mut keystroke_size: u32 = 0;
    let offset = 20;
    for (i, packet) in packets.iter().enumerate().skip(offset) {
        if !is_server_packet(packet) {
            let tcp_layer = packet.layer_name("tcp").unwrap();
            keystroke_size = tcp_layer.metadata("tcp.len").unwrap().value().parse::<u32>().unwrap();
        } 

        let sizes = (1..=4)
            .map(|offset| {
                packets.get(i + offset)
                    .and_then(|p| p.layer_name("tcp"))
                    .and_then(|tcp_layer| tcp_layer.metadata("tcp.len"))
                    .map(|meta| meta.value().parse::<u32>())
                    .ok_or("TCP layer or length metadata not found")
                    .and_then(|res| res.map_err(|_| "Parsing TCP length failed")) 
            }).collect::<Result<Vec<u32>, _>>().unwrap();
        
        if sizes[0] == sizes[1] && sizes[1] == sizes[2] && sizes[2] == sizes[3] {
            return sizes[0];
        }
    }

    keystroke_size
}

/// Finds the three core characteristrics of the session: New Keys Packet, Keystroke indicator
/// Packet, Login Prompt Packet.
///
/// Looks at first 50 packets,
/// Finds (21) New Keys packet (Client),
/// Gets lengths of next four packets,
/// Returns: New Keys, Keystroke indicator, Login Prompt
pub fn find_meta_size(packets: &[Packet]) -> Result<[containers::PacketInfo; 3], &'static str> {
    log::info!("Determining keystroke sizings");

    // Looking at the first 50 packets should be sufficient (taken from PacketStrider)
    for (i, packet) in packets.iter().enumerate().take(50) {
        // Check if New Keys (21)
        // Note! some sloppiness on the `rtshark` devs' part. The server reply in the kex includes
        // a New Keys message with code 21, but it comes after KEX reply 31, so when we access the
        // packet's metadata, we only get the first one (31) and skip the packet. here it works in
        // our favour, but we might get issues later, so noteworthy.
        match utils::get_message_code(&packet) {
            Some(code) => {
                if code != 21 {
                    continue;
                }
            },
            None => continue,
        };

        // TODO: This is neat but unreadable once I came back to it. 
        // We look ahead to the next four packets following the New Keys (21) packet.
        // We get the packets' respective TCP lengths.
        // Packet i+1 to i+3: "new keys x"
        // Packet i+4: Size of login prompt
        // These sizes are used to perform a calculation that reveals the keystroke packets'
        // TCP length.
        // Get the TCP sizes of the next four packets
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
            // NewKeys+1 is our indicator for keystroke size, so we need to ensure this holds, else
            // the implementation might have changed.
            assert_eq!(sizes[0], sizes[1]);

//            // This is the "magic observation" that somehow predicts the "reverse" keystroke TCP len. 
//            // Explanation TBD, I have read a bunch of OpenSSH source code and can still not figure out
//            // why this works.
//            // Clarification: it does not predict the "forward" keystroke len. Forward is just
//            // New Keys +1 -8, apparently.
//            let size_reverse_keystroke = sizes[0] - 8 + 40;
//
//            meta_size = [
//                stream,
//                size_reverse_keystroke,
//                sizes[0],
//                sizes[1],
//                sizes[2],
//                sizes[3],
//            ];

            // i:   New Keys (21)
            // i+1: Keystroke indicator (length - 8 = keystroke_size)
            // i+4: First login prompt (size indicator)
            let out: [containers::PacketInfo; 3] = [
                containers::PacketInfo::new(&packet, i, Some("New Keys (21)".to_string())),
                containers::PacketInfo::new(packets.get(i+1).unwrap(), i+1, Some("Keystroke Size Indicator".to_string())),
                containers::PacketInfo::new(packets.get(i+4).unwrap(), i+4, Some("First login prompt".to_string())),
            ];

            return Ok(out);
        }

        return Err("Not enough packets following the New Keys packet");
        
    }

    Err("New Keys packet not found within the first 50 packets")
}


/// Iterates through KEX and calculates server and client HASSH, finds the negotiated KEX and encryption ciphers used.
/// 
/// Returns 6 strings: Client Protocol, Server Protocol, KEX Algorith, ENC Algorithm, MAC Algorithm, CMP Algorithm.
/// We assume the same algorithm is used STC-CTS. (TODO?)
pub fn find_meta_hassh(packets: &[Packet]) -> Result<[String; 6], &'static str> {
    log::info!("Calculating hassh");

    let mut hassh_client_found: bool = false;
    let mut hassh_server_found: bool = false;
    let mut sport: u32;
    let mut dport: u32;

    // Client to Server (cts) -> hassh
    let mut client_kex: &str = "";
    let mut client_enc_algs_cts: &str = "";
    let mut client_mac_algs_cts: &str = "";
    let mut client_cmp_algs_cts: &str = "";
    let mut hassh_algorithms: String;
    let mut hassh = None;

    // Server to Client (stc) -> hassh_server
    let mut server_kex: &str = "";
    let mut server_enc_algs_stc: &str = "";
    let mut server_mac_algs_stc: &str = "";
    let mut server_cmp_algs_stc: &str = "";
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

        // Get Source/Destination port to determine if client (>22) or server (22) 
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

    Ok([
        hassh.ok_or("Failed to get hassh")?, 
        hassh_server.ok_or("Failed to get hassh_server")?, 
        utils::find_common_algorithm(&client_kex, &server_kex).ok_or("Failed to find common KEX")?, 
        utils::find_common_algorithm(&client_enc_algs_cts, &server_enc_algs_stc).ok_or("Failed to find common ENC")?, 
        //utils::find_common_algorithm(&client_mac_algs_cts, &server_mac_algs_stc).ok_or("Failed to find common MAC")?, 
        utils::find_common_algorithm(&client_mac_algs_cts, &server_mac_algs_stc).unwrap_or("No common mac found".to_string()),
        utils::find_common_algorithm(&client_cmp_algs_cts, &server_cmp_algs_stc).ok_or("Failed to find common CMP")?
    ])
}

/// Find the protocols in use by server and client. Protocol means version/type of SSH
/// client/server, as well as source IP:PORT, destination IP:PORT.
pub fn find_meta_protocol(packets: &[Packet]) -> Result<[String; 6], &'static str> {
    assert!(packets.len() > 0);

    let mut protocol_client = None;
    let mut protocol_server = None;

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
    if dport > sport {
        let tmp_ip = sip;
        let tmp_port = sport;
        sip = dip;
        sport = dport;
        dip = tmp_ip;
        dport = tmp_port;
    }

    Ok([
        protocol_client.ok_or("Failed to get client protocol")?,
        protocol_server.ok_or("Failed to get server protocol")?,
        sip.to_string(),
        sport.to_string(),
        dip.to_string(),
        dport.to_string()
    ])
}

/// Orders collected keystrokes into sequence groups and relativises their timestamps into a
/// processable format.
///
/// To produce the output, group keystroke sequences together.
/// A sequence is the first keystroke up to the return, including the returned size.
pub fn process_keystrokes(keystrokes: Vec<containers::Keystroke>) -> Vec<Vec<containers::Keystroke>> {
    log::info!("Grouping keystroke sequences.");
    let mut out: Vec<Vec<containers::Keystroke>> = Vec::new();
    let mut itr = 0;

    let mut tmp_vec: Vec<containers::Keystroke> = Vec::new();
    let mut curr: &containers::Keystroke;

    while itr < keystrokes.len() {
        curr = &keystrokes[itr];
        tmp_vec.push(curr.clone());

        // Sequences are delimited by Enter (Return), or in edge cases if we reach the last
        // keystroke without encountering a Return.
        if curr.k_type == containers::KeystrokeType::Enter || itr == keystrokes.len()-1 {
            make_relative(&mut tmp_vec);
            out.push(tmp_vec.clone());
            tmp_vec.clear();
        }

        itr += 1;
    }

    out
}

/// Transform timestamps into latencies for a given sequence
fn make_relative(sequence: &mut Vec<containers::Keystroke>) {
    let mut prev_time = sequence[0].timestamp;

    for keystroke in sequence.iter_mut().skip(1) {
        let tmp = keystroke.timestamp;
        keystroke.timestamp = tmp - prev_time;
        prev_time = tmp;
    }

    sequence[0].timestamp = 0;
}

// TODO: 
// Populate with more pcaps, for each scenario.
// Kept the monolith, but maybe do away with file-loading (except for a single test) and then just
// use serialised vector objects with the state? 
#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::env;

    lazy_static!(
        static ref LSAL_STREAM: HashMap<u32, Vec<Packet>> = {
            let base = env!("CARGO_MANIFEST_DIR");
            utils::load_file(format!("{base}/test_captures/known_pass_lsal_id_exit.pcapng").to_string(), -1)
        };
        static ref ARROW_STREAM: HashMap<u32, Vec<Packet>> = {
            let base = env!("CARGO_MANIFEST_DIR");
            utils::load_file(format!("{base}/test_captures/lstlpn_to_ss_tlpn_nopass_exit.pcapng").to_string(), -1)
        };
    );

    #[test]
    fn test_meta_sizes() {
        let meta_size = find_meta_size(&LSAL_STREAM.get(&0).unwrap()).unwrap();
        let newkeys = &meta_size[0];
        let keysize = &meta_size[1];
        let prompt = &meta_size[2];

        // newkeys sequence number
        assert_eq!(1606, newkeys.seq);
        // keystroke size 
        assert_eq!(36, keysize.length-8);
        // Prompt size
        assert_eq!(-52, prompt.length);
    }

    #[test]
    fn test_hassh() {
        // hassh and hassh_server
        let meta_hassh = find_meta_hassh(&LSAL_STREAM.get(&0).unwrap()).unwrap();
        let hassh = meta_hassh[0].clone();
        let hassh_server = meta_hassh[1].clone();
        assert_eq!("aae6b9604f6f3356543709a376d7f657", hassh);
        assert_eq!("779664e66160bf75999f091fce5edb5a", hassh_server);
    }

    #[test]
    fn test_protocol() {
        // Protocols and source/destination
        let meta_protocol = find_meta_protocol(&LSAL_STREAM.get(&0).unwrap()).unwrap();
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
        let mut size_matrix = utils::create_size_matrix(&LSAL_STREAM.get(&0).unwrap());
        let original_size = size_matrix.len();
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);
        assert_eq!(original_size, ordered.len());
    }

    #[test]
    fn test_reverse_r() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&LSAL_STREAM.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // No -R was used
        let reverse_r = scan_for_reverse_session_r_option(&ordered, -52);
        assert!(reverse_r.is_none());
    }

    #[test]
    fn test_login() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&LSAL_STREAM.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // One login attempt- login successful
        let login_index = find_successful_login(&ordered);
        assert!(login_index.is_some());

        // Server login prompt preceding successful login
        let logged_in_at = &ordered[login_index.unwrap()];
        assert_eq!(2215, logged_in_at.seq);
    }

    #[test]
    fn test_keystrokes() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&LSAL_STREAM.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // TODO: better keystroke checking (check for type?)
        let keystrokes = scan_for_keystrokes(&ordered, 36, 20);
        assert_eq!(15, keystrokes.len());
    }

    #[test]
    fn test_arrows() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&ARROW_STREAM.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        let keystrokes = scan_for_keystrokes(&ordered, 36, 20);
        let mut typevec: Vec<containers::KeystrokeType> = Vec::new();
        for keystroke in &keystrokes {
            typevec.push(keystroke.k_type.clone());
        }

        assert_eq!(vec![
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::ArrowHorizontal,
            containers::KeystrokeType::Unknown,
            containers::KeystrokeType::Unknown,
            containers::KeystrokeType::Enter,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Keystroke,
            containers::KeystrokeType::Enter
            ], typevec);
        assert_eq!(23, keystrokes.len());
    }

    #[test]
    fn test_key_login() {
        // Needs ordered packets
        let mut size_matrix = utils::create_size_matrix(&LSAL_STREAM.get(&0).unwrap());
        let ordered = utils::order_keystrokes(&mut size_matrix, 36);

        // No key was used
        let key_log = scan_login_data(&ordered, -52, 7, 17);
        let events: Vec<String> = vec![key_log[0].description.clone().unwrap(), key_log[1].description.clone().unwrap(), key_log[2].description.clone().unwrap(), key_log[3].description.clone().unwrap(), key_log[4].description.clone().unwrap()];
        assert_eq!(events, vec![containers::Event::OfferRSAKey.to_string(), containers::Event::AcceptedKey.to_string(), containers::Event::OfferED25519Key.to_string(), containers::Event::RejectedKey.to_string(), containers::Event::CorrectPassword.to_string()]);
    }
}
