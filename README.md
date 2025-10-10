# Pcap analyzer

This is recreation of old university project in Rust. It's personal project for learning rust language.
It's my first experience with Rust so it's probably buggy and not optimal.
Also, the implementation is a little naive and does not cover every pcap. Could be enhanced in the future.

## What it does

This application can analyze pcap file with filter and print how many packets and bytes was captured in the file.
It can filter on MAC, IPv4 and IPv6 address or on protocol (only TCP or UDP).

## How to run

`pcap_analyzer --file <FILE> --filter-type <FILTER_TYPE> --value <VALUE> <--source|--dst>`

Where:

- FILE: Path to the pcap file to be analyzed.
- FILTER TYPE - mac, ipv4, ipv6, tcp or udp.
- VALUE - MAC address, IP address, port number.

