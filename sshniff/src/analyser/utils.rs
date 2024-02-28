use rtshark::{Packet, RTShark};
use core::panic;
use std::collections::HashMap;

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
