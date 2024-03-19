mod analyser;
mod ui;

use clap::{Parser, ArgAction};
use simple_logger::SimpleLogger;
use ui::output;
use std::fs;

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

    let session = analyser::core::analyse(streams.get(key).unwrap());
    output::print_results(&session);
    let _ = output::save_keystroke_sequences(&session.keystroke_data, std::path::Path::new(&format!("{}/keystrokes.json", args.output_dir.unwrap()).to_string()));
}

