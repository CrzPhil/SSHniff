mod analyser;
mod ui;

use analyser::core::{analyse, SshSession};
use clap::{Parser, ArgAction};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use ui::output;
use std::{collections::HashMap, fs};

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

    /// Only save keystroke-related data. No effect on STDOUT unless `--json` is used. 
    #[arg(short = 'k', long, action = ArgAction::SetTrue)]
    keystrokes: bool,

    /// Directory to save aggregated data as JSON (Depending on use of -m or -k, only saves relevant data)
    #[arg(short = 'o', long, value_parser)]
    output_dir: Option<String>,

    /// Display output as JSON (prints to STDOUT)
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
    let debug_level: LevelFilter;

    // `--json` needs to disable any logging, else it breaks intended piping behaviour (i.e. | jq)
    if args.json {
        debug_level = LevelFilter::Off;
    } else {
        debug_level = args.debug;
    }

    SimpleLogger::new().with_level(debug_level).init().unwrap();

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

    // Iterate through all sessions (or just session n)
    let mut sessions: HashMap<u32, SshSession> = HashMap::new();
    for stream_id in streams.keys() {
        sessions.insert(*stream_id, analyse(*stream_id, streams.get(stream_id).unwrap(), args.metaonly));
    }

    // ---- Output ----

    // No pretty-printing to STDOUT, only print JSON data (feedable to `jq` is the idea).
    if args.json {
        let json: String;
        // Only output keystroke data
        if args.keystrokes {
            json = output::keystrokes_as_json(&sessions).unwrap();
        } else {
            json = output::data_as_json(&sessions).unwrap();
        }
        println!("{}", json);
    } 
    // Pretty-print to STDOUT
    else {
        output::print_results(&sessions);
    }

    // Write to output directory
    if out.is_some() {
        let stem = std::path::Path::new(&args.file).file_stem().unwrap();
        // Only write keystroke data
        if args.keystrokes {
            let json = output::keystrokes_as_json(&sessions);
            let _ = output::data_to_file(json.unwrap(), std::path::Path::new(&format!("{}/{}_session_keystrokes.json", args.output_dir.unwrap(), stem.to_owned().into_string().unwrap()).to_string()));
        } else {
            let json = output::data_as_json(&sessions);
            let _ = output::data_to_file(json.unwrap(), std::path::Path::new(&format!("{}/{}_sessions.json", args.output_dir.unwrap(), stem.to_owned().into_string().unwrap()).to_string()));
        }
    }
}

