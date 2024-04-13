use crate::analyser::core::SshSession;
use crate::analyser::containers::{Keystroke, KeystrokeType};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use ansi_term::Colour;

/// Prints all the human-readable output to console.
pub fn print_results(session: &SshSession) {
    println!("\n\u{250F}\u{2501}\u{2501}\u{2501}\u{2501} Results");
    print_core(session);
    print_result_sequence(session);
    print_keystrokes(session);
}

/// Prints the core metadata to console. 
///
/// Core consists of Stream number, client/server protocols and HASSH values.
fn print_core(session: &SshSession) {
    // TODO: Add first packet UTC time, etc.
    // TODO: Make the boxes horizontally aligned?
    let line = "\u{2500}";
    println!("\u{2503} Stream {}", Colour::Red.paint(session.stream.to_string()));
    println!("\u{2503} Timeframe UTC: {} - {}", session.start_utc, session.end_utc);

    // Stacked:
    
//    println!("\u{2503}");
//    print!("\u{2503}\u{256D}");
//    println!("{:\u{2500}^40}\u{256E}", "Client");
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.src);
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.hassh_c);
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.protocols.0);
//    println!("\u{2503}\u{2570}{}\u{256F}", line.repeat(40));
//
//    print!("\u{2503}\u{256D}");
//    println!("{:\u{2500}^40}\u{256E}", "Server");
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.dst);
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.hassh_s);
//    println!("\u{2503}\u{2502}{:^40}\u{2502}", &session.protocols.1);
//    println!("\u{2503}\u{2570}{}\u{256F}", line.repeat(40));

    // Horizontal:

    // === Row 1 ===
    print!("\u{2503}{}", Colour::Green.paint("\u{256D}"));
    print!("{}", Colour::Green.paint(format!("{:\u{2500}^40}\u{256E}", "Client")));
    print!("      ");
    print!("\u{256D}");
    println!("{:\u{2500}^40}\u{256E}", "Server");
    // === Row 2 === 
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.src)));
    print!("      ");
    println!("\u{2502}{:^40}\u{2502}", &session.dst);
    // === Row 3 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.hassh_c)));
    print!("{}", Colour::Green.paint("----->"));
    println!("\u{2502}{:^40}\u{2502}", &session.hassh_s);
    // === Row 4 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2502}{:^40}\u{2502}", &session.protocols.0)));
    print!("      ");
    println!("\u{2502}{:^40}\u{2502}", &session.protocols.1);
    // === Row 5 ===
    print!("\u{2503}{}", Colour::Green.paint(format!("\u{2570}{}\u{256F}", line.repeat(40))));
    print!("      ");
    println!("\u{2570}{}\u{256F}", line.repeat(40));

//    println!("\u{2503} Client      : {:<24} - {}", Colour::Blue.paint(&session.src), Colour::Fixed(226).paint(&session.protocols.0));
//    println!("\u{2503} hassh       : {}", Colour::Fixed(226).paint(&session.hassh_c));
//    println!("\u{2503} Server      : {:<24} - {}", Colour::Red.paint(&session.dst), Colour::Fixed(226).paint(&session.protocols.1));
//    println!("\u{2503} hasshServer : {}", Colour::Fixed(226).paint(&session.hassh_s));
    println!("\u{2503}");
}

fn print_result_sequence(session: &SshSession) {
    let results = &session.results;

    println!("\u{2523}\u{2501} Timeline of Results");

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
pub fn save_keystroke_sequences(sequences: &Vec<Vec<Keystroke>>, file_path: &Path) -> Result<(), serde_json::Error> {
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
pub fn data_as_json(session: &SshSession) -> Result<String, serde_json::Error> {
    // Serialize the data to JSON string
    let serialized = serde_json::to_string(session)?;
    Ok(serialized)
}

/// Saves json data to a given file
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
    println!(r"                 \   \                  ,-'              `-._ ,---^. ");
    println!(r"                  \ e \                 \   ,                `-|    | ");
    println!(r"                   \   \                 \,(o                  ;    | ");
    println!(r"                    \ a \            _,-'   `-'                |    | ");
    println!(r"                     \   \        ,-'                          |    | ");
    println!(r"                      \ d \   ,###'                            ;    ; ");
    println!(r#"                       \   \  `"" `           ,         ,--   /    : "#);
    println!(r"                        \ b \  \      .   ___/|       ,'\   ,' ,'  ; ");
    println!(r"                         \   \  `.     ;-' ___|     ,'  |\   ,'   / ");
    println!(r"                          \ e \   `---'  __\ /    ,'    | `-'   ,' ");
    println!(r"                           \   \         \ ,'   ,'      `--.__,' ");
    println!(r"                            \ e \        ,'    / ");
    println!(r"                             \   \       `----'    -hrr- ");
    println!(r"                              \ f \ ");
    println!(r"                               \   \");
}
