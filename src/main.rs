mod cli;
mod pcap;

use cli::argument_parser::parse_args;
use pcap::reader::PcapReader;
use std::process;

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1)
        }
    };

    let pcap_reader = PcapReader::new(&args);
    let result = pcap_reader.read_pcap_file().expect("Didnt work");
    println!("{}", result);
}
