# SSHniff - An SSH Metadata Harvester

## Overview

This tool was written as a part of my Bachelor thesis, which was a research project on the SSH protocol and specifically its susceptibility to a metadata-based attack, where keystroke latencies are used to obtain information about the underlying command, breaching confidentiality. 

This attack was first introduced in 2002, in a [paper](https://www.researchgate.net/publication/2907598_Timing_Analysis_of_Keystrokes_and_Timing_Attacks_on_SSH) by Song, Wagner, and Dawn, targeting the SSH-1 protocol. My research and this tool revive the attack, focusing on recent OpenSSH versions.  

## Installation

The tool is found in the `sshniff` directory and is a `cargo` project. All you need to compile and run it is a working Rust installation; [rustup](https://rustup.rs/) is recommended.

```bash
cd sshniff
cargo build --release
./target/release/sshniff 
```

## Usage

The tool uses a `PCAP/NG` file containing SSH session(s) to extract the metadata. A few such demo captures are included in the repository, under `analysis/test_sessions/` and `sshniff/test_captures/`. 

Here is what running the tool looks like:

> Note: In this session, I typed `ls -tlpn`, then navigated back using the arrow keys, deleted the `l` character and replaced it with `s`, before pressing Enter. This was to showcase one part of keystroke identification, where even horizontal arrow keys can be identified via their packet sizes. 

```bash
[melo@frostvee sshniff]$ ./target/release/sshniff -f test_captures/lstlpn_to_ss_tlpn_nopass_exit.pcapng 

2024-05-12T08:39:13.773Z WARN [sshniff] No output directory specified.
2024-05-12T08:39:13.773Z INFO [sshniff::analyser::utils] Loading capture file.
2024-05-12T08:39:13.773Z INFO [sshniff::analyser::utils] Reading from test_captures/lstlpn_to_ss_tlpn_nopass_exit.pcapng
2024-05-12T08:39:13.773Z INFO [sshniff::analyser::utils] Collecting streams.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Starting analysis.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Getting start and end time of session.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Determining keystroke sizings
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Employing alternative method to find keystroke size.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Calculating hassh
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::utils] Creating PacketInfo matrix.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::utils] Ordering keystrokes.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::scan] Looking for host key acceptance by Client.
2024-05-12T08:39:13.931Z INFO [sshniff::analyser::core] Grouping keystroke sequences.

┏━━━━ Results
┃ Stream 0
┃ Duration (UTC): 2024-03-19 12:13:08 - 2024-03-19 12:13:19
┃ KEX         curve25519-sha256
┃ Encryption  chacha20-poly1305@openssh.com
┃ MAC         umac-64-etm@openssh.com
┃ Compression none
┃╭─────────────────Client─────────────────╮      ╭─────────────────Server─────────────────╮
┃│          192.168.0.205:36652           │      │            192.168.0.45:22             │
┃│    779664e66160bf75999f091fce5edb5a    │----->│    aae6b9604f6f3356543709a376d7f657    │
┃│          SSH-2.0-OpenSSH_9.7           │      │SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3│
┃╰────────────────────────────────────────╯      ╰────────────────────────────────────────╯
┃
┣━ Timeline of Events
┣ [1123] Server hostkey accepted
┣ [1606] New Keys (21)
┣ [1622] Keystroke Size Indicator
┣ [1651] First login prompt
┣ [1726] OfferRSAKey
┣ [1703] AcceptedKey
┃
┣━ Keystroke Sequences
┣━ tcp.seq─ Latency μs─ Type
┣  [4098]  ─ (       0) ─ Keystroke
┣  [4134]  ─ (  195931) ─ Keystroke
┣  [4170]  ─ (  136312) ─ Keystroke
┣  [4206]  ─ (  230226) ─ Keystroke
┣  [4242]  ─ (  394865) ─ Keystroke
┣  [4278]  ─ (  191915) ─ Keystroke
┣  [4314]  ─ (  197263) ─ Keystroke
┣  [4350]  ─ (  294079) ─ Keystroke
┣  [4386]  ─ ( 1008154) ─ ArrowHorizontal
┣  [4430]  ─ (  213627) ─ ArrowHorizontal
┣  [4474]  ─ (  234413) ─ ArrowHorizontal
┣  [4518]  ─ (  217691) ─ ArrowHorizontal
┣  [4562]  ─ (  212794) ─ ArrowHorizontal
┣  [4606]  ─ (  197948) ─ ArrowHorizontal
┣  [4650]  ─ (  274622) ─ ArrowHorizontal
┣  [4694]  ─ (  530056) ─ Unknown
┣  [4730]  ─ (  215173) ─ Unknown
┣╮ [4802]  ─ ( 1621927) ─ Enter
┃╰─╼[1488]
┣━
┣  [4802]  ─ (       0) ─ Keystroke
┣  [4838]  ─ (  215858) ─ Keystroke
┣  [4874]  ─ (  118015) ─ Keystroke
┣  [4910]  ─ (  135291) ─ Keystroke
┣╮ [4982]  ─ (  157785) ─ Enter
┃╰─╼[264]
┣━
┃
┣━━━━
```

We can see two command sequences were run in this session. The aforementioned `ss -tlpn`, and the `exit` command, closing the session. Also, in the "Timeline of Events" section, we can see that an RSA key was used to authenticate. The `Client` and `Server` bubbles contain the [hassh](https://github.com/salesforce/hassh) of the respective devices. 

## Explanation

Once my thesis is graded, I will make sure to reference it here, as it goes into full detail of the findings and how we can discern and identify the keystroke packets. Until then, the codebase is also heavily commented with the assumptions we make, so those interested can refer to it, too. 

## Keystroke Latency Analysis

To check out how the metadata is leveraged to breach confidentiality, consult [analysis.ipynb](./analysis/analysis.ipynb); it is written as a sort of walkthrough, containing the sequential steps of my research. Its final section details how I found a bypass against the obfuscation measures introduced in OpenSSH patch 9.5. 

For a more condensed output of keystroke analysis techniques, you can refer to [shellbust.ipynb](./analysis/shellbust.ipynb), which just contains the functions and a few subroutines to play around with observed keystrokes. 

## To-do

> Most `TODO`'s are in the codebase, as comments. The rest, more general ones, are here, so that I don't forget.
- [ ] Refactor functions to public / private, as needed
- [X] Write documentation
- [ ] More test cases with serialised packet data from PCAPs 
- [ ] Coverage test (?) 
- [ ] Detect interactive session (?)
- [X] Test multiple sessions in one pcap support 
- [ ] Use Packet Length for ETM ciphers (!)
- [ ] Add option to output pure Keystrokes without classifying them at all 
- [ ] Add option to manually set certain packet sizes or indeces ?
- [ ] Support direct monitoring to cut out need for PCAP files
- [ ] Clean up repository

## Acknowledgements

The research idea was suggested by my Networking lecturer Martin Nyx Brain, at City, University of London. I appreciate the time he took to discuss ideas and approaches for this research, as well as how he motivated me to dig deep and not get discouraged at the start of the journey.

Finally, a significant part of this implementation has been adopted from [packetStrider](https://github.com/benjeems/packetStrider), by Ben Reardon. The tool is built in Python, but has not been worked on in five years. Nevertheless, it does a lot of the heavy lifting and served as a baseline/blueprint for this tool. 