//! ANSII, UNICODE, and FUN! 
//! 
//! (it was not fun doing this bit. unicode tables drove me mad).
use crate::analyser::core::SshSession;
use crate::analyser::containers::{self, Keystroke, KeystrokeType};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use ansi_term::Colour;

/// Prints all the human-readable output to console.
pub fn print_results(sessions: &HashMap<u32, SshSession>) {
    println!("\n\u{250F}\u{2501}\u{2501}\u{2501}\u{2501} Results");
    for session in sessions.values() {
        print_core(session);
        print_result_sequence(session);
        
        // Only print if keystrokes were analysed.
        if !&session.keystroke_data.is_empty() {
            print_keystrokes(session);
        }
        println!("\u{2523}\u{2501}\u{2501}\u{2501}\u{2501}");
    }
}

/// Prints the core metadata to console. 
///
/// Core consists of Stream number, client/server protocols and HASSH values.
fn print_core(session: &SshSession) {
    let line = "\u{2500}";
    println!("\u{2503} Stream {}", Colour::Red.paint(session.stream.to_string()));
    println!("\u{2503} Duration (UTC): {} - {}", session.start_utc, session.end_utc);
    println!("\u{2503} KEX         {}", Colour::Yellow.paint(&session.algorithms.0));
    println!("\u{2503} Encryption  {}", Colour::Yellow.paint(&session.algorithms.1));
    println!("\u{2503} MAC         {}", Colour::Yellow.paint(&session.algorithms.2));
    println!("\u{2503} Compression {}", Colour::Yellow.paint(&session.algorithms.3));

   // === Row 1 ===
    print!("\u{2503}{}", Colour::Green.paint("\u{256D}"));
    print!("{}", Colour::Green.paint(format!("{:\u{2500}^40}\u{256E}", "Client")));
    print!("      ");
    print!("{}", Colour::Cyan.paint("\u{256D}"));
    println!("{}", Colour::Cyan.paint(format!("{:\u{2500}^40}\u{256E}", "Server")));

    // === Row 2 === 
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.src)));
    print!("      ");
    println!("{}", Colour::Cyan.paint(format!("\u{2502}{:^40}\u{2502}", &session.dst)));

    // === Row 3 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.hassh_c)));
    print!("{}", Colour::Yellow.paint("----->"));
    println!("{}", Colour::Cyan.paint(format!("\u{2502}{:^40}\u{2502}", &session.hassh_s)));

    // === Row 4 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.protocols.0)));
    print!("      ");
    println!("{}", Colour::Cyan.paint(format!("\u{2502}{:^40}\u{2502}", &session.protocols.1)));

    // === Row 5 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2570}{}\u{256F}", line.repeat(40))));
    print!("      ");
    println!("{}", Colour::Cyan.paint(format!("\u{2570}{}\u{256F}", line.repeat(40))));

    println!("\u{2503}");
}

/// Prints a [session](SshSession)'s [results](SshSession::results).
/// 
/// [Results](SshSession::results) consist of [PacketInfos](containers::PacketInfo), whose descriptions are printed out sequentially.
/// Assumes that all [PacketInfos](containers::PacketInfo) added contain [descriptions](containers::PacketInfo::description).
fn print_result_sequence(session: &SshSession) {
    let results = &session.results;

    println!("\u{2523}\u{2501} Timeline of Events");

    for pinfo in results {
        println!("\u{2523} [{}] {}", pinfo.seq, pinfo.description.clone().expect("Result with no description"));
    }

    println!("\u{2503}");
}

/// Prints keystroke sequences and their respective response sizes.
///
/// Prints keystroke types and sequence IDs of each keystroke packet, should the user wish to
/// investigate the capture themselves. 
fn print_keystrokes(session: &SshSession) {
    let keystroke_sequences = &session.keystroke_data;
    println!("\u{2523}\u{2501} Keystroke Sequences");
    println!("\u{2523}\u{2501} {} \u{2500} {} \u{2500} {}", Colour::Red.paint("tcp.seq"), Colour::Red.paint("Latency μs"), Colour::Red.paint("Type"));

    for sequence in keystroke_sequences {
        for keystroke in sequence {
            if keystroke.k_type == KeystrokeType::Enter {
                println!("\u{2523}\u{256E} [{}]  \u{2500} ({:>8}) \u{2500} {:?}", keystroke.seq, keystroke.timestamp, keystroke.k_type);
                println!("\u{2503}\u{2570}\u{2500}\u{257C}[{}]", keystroke.response_size.expect("enter keystroke without response size"));
            } else {
                println!("\u{2523}  [{}]  \u{2500} ({:>8}) \u{2500} {:?}", keystroke.seq, keystroke.timestamp, keystroke.k_type);
            }
        }
        println!("\u{2523}\u{2501}");
    }
    println!("\u{2503}");
}

/// Saves the keystroke sequences to a specified file as JSON data.
///
/// Data is saved as a simple JSON array of keystroke objects.
/// Currently not used. Maybe if we add a flag to save sessions separately, this will be useful again. 
pub fn _save_keystroke_sequences(sequences: &Vec<Vec<Keystroke>>, file_path: &Path) -> Result<(), serde_json::Error> {
    // Serialize the data to JSON string
    let serialized_data = serde_json::to_string(&sequences)?;

    // Create or truncate the file
    let mut file = File::create(file_path)
        .map_err(serde_json::Error::io)?;

    // Write the serialized data to the file
    file.write_all(serialized_data.as_bytes())
        .map_err(serde_json::Error::io)?;

    Ok(())
}

/// Returns all data as JSON, which can be directly piped to jq, if printed. 
///
/// Triggered by the `--json` flag.
pub fn data_as_json(sessions: &HashMap<u32, SshSession>) -> Result<String, serde_json::Error> {
    // Serialize the data to JSON string
    let serialized = serde_json::to_string(&sessions)?;
    Ok(serialized)
}

/// Returns all keystroke-related data as JSON.
/// 
/// Triggered by combination of `--json` and `-k`.
pub fn keystrokes_as_json(sessions: &HashMap<u32, SshSession>) -> Result<String, serde_json::Error> {
    // Bypass the SshSession struct and only collect the keystroke sequences.
    let keystroke_only_map: HashMap<u32, &Vec<Vec<containers::Keystroke>>> = sessions
        .iter()
        .map(|(&stream_id, session)| (stream_id, &session.keystroke_data))
        .collect();

    // Serialize the data to JSON string
    let serialized = serde_json::to_string(&keystroke_only_map)?;
    Ok(serialized)
}

/// Saves JSON data to a given file
pub fn data_to_file(data: String, file_path: &Path) -> Result<(), io::Error> {
    let mut file = File::create(file_path)?;
    file.write_all(data.as_bytes())?;

    Ok(())
}

pub fn print_banner() {
    println!(r"                                                          ,._ ");
    println!(r"                                                 ,--.    |   `-. ");
    println!(r"                                              ,-'    \   :      `-. ");
    println!(r"                                             /__,.    \  ;  `--.___) ");
    println!(r"                                            ,'    \    \/   /       ,-\`. ");
    println!(r"                \ d \                      __,-' - /   '\      '   ,' ");
    println!(r"                 \ e \                  ,-'              `-._ ,---^. ");
    println!(r"                  \ a \                 \   ,                `-|    | ");
    println!(r"                   \ d \                 \,(o                  ;    | ");
    println!(r"                    \ b \            _,-'   `-'                |    | ");
    println!(r"                     \ e \        ,-'                          |    | ");
    println!(r"                      \ e \   ,###'                            ;    ; ");
    println!(r#"                       \ f \  `"" `           ,         ,--   /    : "#);
    println!(r"                        \ d \  \      .   ___/|       ,'\   ,' ,'  ; ");
    println!(r"                         \ e \  `.     ;-' ___|     ,'  |\   ,'   / ");
    println!(r"                          \ a \   `---'  __\ /    ,'    | `-'   ,' ");
    println!(r"                           \ d \         \ ,'   ,'      `--.__,' ");
    println!(r"                            \ b \        ,'    / ");
    println!(r"                             \ e \       `----'    -hrr- ");
    println!(r"                              \ e \ ");
    println!(r"                               \ f \");
}
