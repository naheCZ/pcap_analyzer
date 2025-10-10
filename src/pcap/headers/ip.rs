use byteorder::{NetworkEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const IPV4_HEADER_SIZE: u8 = 20;
pub const IPV6_HEADER_SIZE: u8 = 40;

#[repr(u8)]
#[derive(Debug)]
pub enum Protocol {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
}

impl TryFrom<u8> for Protocol {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Protocol::ICMP as u8 => Ok(Protocol::ICMP),
            x if x == Protocol::IGMP as u8 => Ok(Protocol::IGMP),
            x if x == Protocol::TCP as u8 => Ok(Protocol::TCP),
            x if x == Protocol::UDP as u8 => Ok(Protocol::UDP),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IPv4Header {
    version: u8,
    ts: u8,
    total_length: u16,
    id: u16,
    flags: u16,
    ttl: u8,
    pub protocol: Protocol,
    csum: u16,
    pub source_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
}

impl IPv4Header {
    pub fn read(reader: &mut BufReader<File>) -> std::io::Result<Self> {
        let version = reader.read_u8()?;
        let ts = reader.read_u8()?;
        let total_length = reader.read_u16::<NetworkEndian>()?;
        let id = reader.read_u16::<NetworkEndian>()?;
        let flags = reader.read_u16::<NetworkEndian>()?;
        let ttl = reader.read_u8()?;
        let protocol_number = reader.read_u8()?;
        let csum = reader.read_u16::<NetworkEndian>()?;
        let src_ip = Self::read_ip_address(reader)?;
        let dst_ip = Self::read_ip_address(reader)?;

        let protocol = match Protocol::try_from(protocol_number) {
            Ok(p) => p,
            Err(_) => {
                println!("CANNOT PARSE {}", protocol_number);
                return Err(std::io::Error::other("Cannot parse protocol number"));
            }
        };

        Ok(Self {
            version,
            ts,
            total_length,
            id,
            flags,
            ttl,
            protocol,
            csum,
            source_addr: src_ip,
            dst_addr: dst_ip,
        })
    }

    fn read_ip_address(reader: &mut BufReader<File>) -> std::io::Result<Ipv4Addr> {
        let mut ip_buffer = [0u8; 4];
        reader.read_exact(&mut ip_buffer)?;
        let ip_address = Ipv4Addr::from(ip_buffer);
        Ok(ip_address)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IPv6Header {
    vcf: u32,
    payload_length: u16,
    pub protocol: Protocol,
    hop_limit: u8,
    pub source_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
}

impl IPv6Header {
    pub fn read(reader: &mut BufReader<File>) -> std::io::Result<Self> {
        let vcf = reader.read_u32::<NetworkEndian>()?;
        let payload_length = reader.read_u16::<NetworkEndian>()?;
        let protocol_number = reader.read_u8()?;
        let hop_limit = reader.read_u8()?;
        let source_addr = Self::read_ip_address(reader)?;
        let dst_addr = Self::read_ip_address(reader)?;

        let protocol = match Protocol::try_from(protocol_number) {
            Ok(p) => p,
            Err(_) => return Err(std::io::Error::other("Cannot parse protocol number")),
        };

        Ok(Self {
            vcf,
            payload_length,
            protocol,
            hop_limit,
            source_addr,
            dst_addr,
        })
    }

    fn read_ip_address(reader: &mut BufReader<File>) -> std::io::Result<Ipv6Addr> {
        let mut ip_buffer = [0u8; 16];
        reader.read_exact(&mut ip_buffer)?;
        let ip_address = Ipv6Addr::from(ip_buffer);
        Ok(ip_address)
    }
}
