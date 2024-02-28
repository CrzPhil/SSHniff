use std::collections::HashSet;
use rtshark::{RTShark, RTSharkBuilder};

pub fn analyse(capture_file: String, streams: &HashSet<u32>) {
    log::info!("Starting analysis.");

    let mut filter = String::from("\
        ssh &&\
        !tcp.analysis.spurious_retransmission &&\
        !tcp.analysis.retransmission &&\
        !tcp.analysis.fast_retransmission\
    ");

    for stream in streams {
        log::info!("Analysing stream {stream}");

        filter.push_str(&format!("tcp.stream=={}", stream));

        let builder = rtshark::RTSharkBuilder::builder()
            .input_path(&capture_file)
            .display_filter(&filter);
        
        let mut rtshark = match builder.spawn() {
            Err(err) => {
                log::error!("Error running tshark: {err}"); 
                return;
            }
            Ok(rtshark) => {
                log::info!("Reading {}", &capture_file);
                rtshark
            }
        };
 
    }
}

fn find_meta_size(rtshark: &mut RTShark) {
    // Looking at the first 50 packets should be sufficient (taken from PacketStrider)
    let mut ctr = 0;
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        log::error!("Failed reading packets when finding meta size.");
        None
    })
    {
        if ctr == 50 {
            break;
        }

        ctr += 1;
    }
}
