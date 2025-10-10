use crate::cli::argument_parser::{CliArguments, FilterType};
use crate::pcap::headers::eth::{ETH_HEADER_SIZE, EthHdr, EthType};
use crate::pcap::headers::ip::{
    IPV4_HEADER_SIZE, IPV6_HEADER_SIZE, IPv4Header, IPv6Header, Protocol,
};
use crate::pcap::headers::pcap::{PacketHeader, PcapFileHeader};
use crate::pcap::headers::tcp::{TCP_HEADER_SIZE, TcpHdr};
use crate::pcap::headers::udp::{UDP_HEADER_SIZE, UdpHdr};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct AnalyzeResult {
    pub packet_number: u64,
    pub total_packets: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
}

impl fmt::Display for AnalyzeResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Total number of packets: {}\n\
            Packets matched the filter: {}\n\
            Total bytes captured in file for filter: {}\n\
            Original bytes size for filter: {}",
            self.total_packets, self.packet_number, self.captured_bytes, self.original_bytes
        )
    }
}

impl AnalyzeResult {
    fn new() -> Self {
        AnalyzeResult {
            packet_number: 0,
            total_packets: 0,
            captured_bytes: 0,
            original_bytes: 0,
        }
    }

    pub fn increment(&mut self, captured_bytes: u64, original_bytes: u64) {
        self.packet_number += 1;
        self.captured_bytes += captured_bytes;
        self.original_bytes += original_bytes;
    }
}

pub struct PcapReader<'a> {
    args: &'a CliArguments,
}

impl<'a> PcapReader<'a> {
    pub fn new(args: &'a CliArguments) -> Self {
        Self { args }
    }

    pub fn read_pcap_file(&self) -> std::io::Result<AnalyzeResult> {
        let fh = File::open(&self.args.file)?;
        let mut reader = BufReader::new(fh);
        PcapFileHeader::read(&mut reader)?; // Just read it to skip it. May be useful in the future.
        let mut result = AnalyzeResult::new();

        loop {
            match self.read_packet(&mut reader, &mut result) {
                Ok(to_shift) => {
                    reader.seek_relative(to_shift)?;
                    result.total_packets += 1;
                }
                Err(_) => break,
            };
        }

        Ok(result)
    }

    fn read_packet(
        &self,
        reader: &mut BufReader<File>,
        result: &mut AnalyzeResult,
    ) -> std::io::Result<i64> {
        let packet_header = PacketHeader::read(reader)?;
        let mut seek_shift = packet_header.incl_len as i64;
        let eth_header = EthHdr::read(reader)?;
        seek_shift -= ETH_HEADER_SIZE as i64;

        if self.args.filter.filter_type == FilterType::MAC {
            if self.cmp_eth(&eth_header) {
                result.increment(packet_header.incl_len as u64, packet_header.orig_len as u64);
            }
            return Ok(seek_shift);
        }

        let (mut to_add, mut read_bytes, protocol) = self.process_l3_hdr(&eth_header, reader)?;
        seek_shift -= read_bytes;
        if to_add {
            result.increment(packet_header.incl_len as u64, packet_header.orig_len as u64);
            return Ok(seek_shift);
        }

        if protocol.is_none() {
            return Ok(seek_shift);
        }
        println!("L4 HEADER");
        (to_add, read_bytes) = self.process_l4_hdr(protocol.unwrap(), reader)?;
        seek_shift -= read_bytes;
        if to_add {
            result.increment(packet_header.orig_len as u64, packet_header.incl_len as u64);
            return Ok(seek_shift);
        }

        Ok(seek_shift)
    }

    fn cmp_eth(&self, eth_hdr: &EthHdr) -> bool {
        if self.args.direction.source && self.args.filter.value == eth_hdr.src {
            return true;
        }

        if self.args.direction.dst && self.args.filter.value == eth_hdr.dst {
            return true;
        }

        false
    }

    fn process_l3_hdr(
        &self,
        eth_hdr: &EthHdr,
        reader: &mut BufReader<File>,
    ) -> std::io::Result<(bool, i64, Option<Protocol>)> {
        match eth_hdr.ether_type {
            EthType::ARP => Ok((false, 0, None)),
            EthType::ATA => Ok((false, 0, None)),
            EthType::IPv4 => Ok(self.process_ipv4(reader)?),
            EthType::IPv6 => Ok(self.process_ipv6(reader)?),
        }
    }

    fn process_ipv4(
        &self,
        reader: &mut BufReader<File>,
    ) -> std::io::Result<(bool, i64, Option<Protocol>)> {
        let header = IPv4Header::read(reader)?;
        let mut protocol: Option<Protocol> = Some(header.protocol);

        if self.args.filter.filter_type == FilterType::IPv4 {
            protocol = None; // Return None so it will break the packer computation.
            let value_address = match Ipv4Addr::from_str(&self.args.filter.value) {
                Ok(addr) => addr,
                Err(_) => return Ok((false, IPV6_HEADER_SIZE as i64, protocol)),
            };

            if (self.args.direction.source && value_address == header.source_addr)
                || (self.args.direction.dst && value_address == header.dst_addr)
            {
                return Ok((true, IPV4_HEADER_SIZE as i64, protocol));
            }
        }

        Ok((false, IPV4_HEADER_SIZE as i64, protocol))
    }

    fn process_ipv6(
        &self,
        reader: &mut BufReader<File>,
    ) -> std::io::Result<(bool, i64, Option<Protocol>)> {
        let header = IPv6Header::read(reader)?;
        let mut protocol: Option<Protocol> = Some(header.protocol);

        if self.args.filter.filter_type == FilterType::IPv6 {
            protocol = None; // Return None so it will break the packer computation.
            let value_address = match Ipv6Addr::from_str(&self.args.filter.value) {
                Ok(addr) => addr,
                Err(_) => return Ok((false, IPV6_HEADER_SIZE as i64, protocol)),
            };

            if (self.args.direction.source && value_address == header.source_addr)
                || (self.args.direction.dst && value_address == header.dst_addr)
            {
                return Ok((true, IPV6_HEADER_SIZE as i64, protocol));
            }
        }

        Ok((false, IPV6_HEADER_SIZE as i64, protocol))
    }

    fn process_l4_hdr(
        &self,
        protocol: Protocol,
        reader: &mut BufReader<File>,
    ) -> std::io::Result<(bool, i64)> {
        let length: i64;
        let source_port: u16;
        let dst_port: u16;
        let check: bool;

        match protocol {
            Protocol::TCP => {
                length = TCP_HEADER_SIZE as i64;
                let header = TcpHdr::read(reader)?;
                source_port = header.source_port;
                dst_port = header.dst_port;
                check = self.check_proto(FilterType::TCP);
            }
            Protocol::UDP => {
                length = UDP_HEADER_SIZE as i64;
                let header = UdpHdr::read(reader)?;
                source_port = header.source_port;
                dst_port = header.dst_port;
                check = self.check_proto(FilterType::UDP);
            }
            _ => return Ok((false, 0)),
        }

        let filter_value: u16 = self.args.filter.value.parse().unwrap();
        if check {
            if (self.args.direction.source && filter_value == source_port)
                || (self.args.direction.dst && filter_value == dst_port)
            {
                return Ok((true, length));
            }
        }

        Ok((false, length))
    }

    fn check_proto(&self, proto: FilterType) -> bool {
        if self.args.filter.filter_type == proto {
            return true;
        }

        false
    }
}
