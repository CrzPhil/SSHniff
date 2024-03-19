use crate::analyser::core::SshSession;
use crate::analyser::containers::Keystroke;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use ansi_term::Colour;

pub fn print_results(session: &SshSession) {
    println!("\n\u{250F}\u{2501}\u{2501}\u{2501}\u{2501} Results");
    print_core(session);
}

pub fn print_core(session: &SshSession) {
    println!("\u{2503}");
    println!("\u{2503} Stream {}", Colour::Red.paint(session.stream.to_string()));
    println!("\u{2503} Client Protocol  : {}", Colour::Fixed(226).paint(&session.protocols.0));
    println!("\u{2503} hassh            : {}", Colour::Fixed(226).paint(&session.hassh_c));
    println!("\u{2503} Server Protocol  : {}", Colour::Fixed(226).paint(&session.protocols.1));
    println!("\u{2503} hasshServer      : {}", Colour::Fixed(226).paint(&session.hassh_s));
    println!("\u{2503} ");
}

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
