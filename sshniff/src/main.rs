mod analyser;

use clap::{Parser, ArgAction};
use simple_logger::SimpleLogger;
use std::{collections::HashMap, fs};
use rtshark::RTSharkBuilder;

use crate::analyser::core::analyse;

/// SSHniff is a packet forensics tool for SSH
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// pcap/pcapng file to analyze
    #[arg(short = 'f', long, value_parser)]
    file: String,

    /// Perform analysis only on stream n
    #[arg(short, long, default_value_t = -1, value_parser)]
    nstream: i32,

    /// Display stream metadata only
    #[arg(short = 'm', long, action = ArgAction::SetTrue)]
    metaonly: bool,

    /// Perform keystroke prediction
    #[arg(short = 'k', long, action = ArgAction::SetTrue)]
    keystrokes: bool,

    /// Plot data movement and keystrokes
    #[arg(short = 'p', long, action = ArgAction::SetTrue)]
    predict_plot: bool,

    /// Narrow down/zoom the analysis and plotting to only packets "x-y"
    #[arg(short = 'z', long, default_value_t = String::from("0"), value_parser)]
    zoom: String,

    /// Perform analysis on SSH direction: "forward", "reverse" OR "both"
    #[arg(short = 'd', long, default_value_t = String::from("both"), value_parser)]
    direction: String,

    /// Directory to output plots
    #[arg(short = 'o', long, value_parser)]
    output_dir: Option<String>,

    /// Sliding window size, # of packets to side of window center packet, default is 2
    #[arg(short = 'w', long, default_value_t = 2, value_parser)]
    window: i32,

    /// Stride between sliding windows, default is 1
    #[arg(short = 's', long, default_value_t = 1, value_parser)]
    stride: i32,
}

fn main() {
    SimpleLogger::new().init().unwrap();

    let args = Args::parse();

    if let Some(out_dir) = args.output_dir.as_deref() {
        log::info!("Output directory {out_dir}");
        let _ = fs::create_dir_all(out_dir);
    } else {
        log::warn!("No output directory specified.")
    }

    let streams = analyser::utils::load_file(args.file, args.nstream);
    let key = streams.keys().into_iter().next().unwrap();

    let x = analyser::core::find_meta_size(3, &streams.get(key).unwrap()).unwrap();
 //   println!("{x:?}");
    let y = analyser::core::find_meta_hassh(&streams.get(key).unwrap());
//    println!("{y:?}");
    let z = analyser::core::find_meta_protocol(&streams.get(key).unwrap());
//    println!("{z:?}");
    let mut k = analyser::utils::create_size_matrix(&streams.get(key).unwrap());
//    println!("{k:?}");
    let vv = analyser::utils::order_keystrokes(&mut k, 36);
    //let vz = analyser::utils::scan_for_reverse_session_r_option(&vv, -52);
    let login = analyser::utils::scan_for_login_attempts(&vv, -52);
    //let asdf = analyser::utils::scan_for_host_key_accepts(&vv, login[2].0.index);
}

