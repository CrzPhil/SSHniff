mod analyser;
mod ui;

use clap::{Parser, ArgAction};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use ui::output;
use std::fs;

/// SSHniff is a packet forensics tool for SSH
#[derive(Parser, Debug)]
#[command(
    name = "SSHniff",
    author = "Philippos Giavridis <philippos.giavridis@city.ac.uk>", 
    version = "alpha", 
    about = "Analyses SSH traffic metadata", 
    long_about = "todo",
    before_help = "GNU General Public License v3.0",
)]
struct Args {
    /// pcap/pcapng file to analyze
    #[arg(short = 'f', long, value_parser)]
    file: String,

    /// Perform analysis only on stream n
    #[arg(short, long, default_value_t = -1, value_parser)]
    nstream: i32,

    /// Only output session metadata (no keystrokes)
    #[arg(short = 'm', long, action = ArgAction::SetTrue)]
    metaonly: bool,

    /// Only output keystroke data
    #[arg(short = 'k', long, action = ArgAction::SetTrue)]
    keystrokes: bool,

    /// Directory to output aggregated data
    #[arg(short = 'o', long, value_parser)]
    output_dir: Option<String>,

    /// Display output as formatted JSON
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    json: bool,

    /// Set the debug level (Off, Error, Warn, Info, Debug, Trace)
    #[arg(short = 'd', long, default_value_t = LevelFilter::Info, value_parser = parse_level_filter)]
    debug: LevelFilter, 
}

fn parse_level_filter(s: &str) -> Result<LevelFilter, String> {
    s.parse::<LevelFilter>().map_err(|_| format!("Invalid log level: {}", s))
}

fn main() {
    let args = Args::parse();
    SimpleLogger::new().with_level(args.debug).init().unwrap();

    let out;

    if let Some(out_dir) = args.output_dir.as_deref() {
        log::info!("Output directory {out_dir}");
        let _ = fs::create_dir_all(out_dir);
        out = Some(out_dir);
    } else {
        log::warn!("No output directory specified.");
        out = None;
    }

    // Load file into stream map: <stream_id> -> <packets>
    let streams = analyser::utils::load_file(args.file.clone(), args.nstream);
    let key = streams.keys().into_iter().next().unwrap();

    // Todo: iterate streams properly 
    let session = analyser::core::analyse(streams.get(key).unwrap(), args.metaonly);

    // ---- Output ----
    if args.json {
        let json = output::data_as_json(&session);
        if out.is_some() {
            let stem = std::path::Path::new(&args.file).file_stem().unwrap();
            let _ = output::data_to_file(json.unwrap(), std::path::Path::new(&format!("{}/{}_ssh_session.json", args.output_dir.unwrap(), stem.to_owned().into_string().unwrap()).to_string()));
        } else {
            println!("{}", json.unwrap());
        }
    } else {
        output::print_results(&session);
        if out.is_some() {
            let _ = output::save_keystroke_sequences(&session.keystroke_data, std::path::Path::new(&format!("{}/keystrokes.json", args.output_dir.unwrap()).to_string()));
        }
    }
}

