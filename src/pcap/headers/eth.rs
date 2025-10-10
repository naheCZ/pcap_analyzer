use byteorder::{NetworkEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read};

pub const ETH_HEADER_SIZE: u8 = 14;

#[repr(u16)]
#[derive(Debug)]
pub enum EthType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    ATA = 0x88a2,
}

impl TryFrom<u16> for EthType {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == EthType::IPv4 as u16 => Ok(EthType::IPv4),
            x if x == EthType::ARP as u16 => Ok(EthType::ARP),
            x if x == EthType::IPv6 as u16 => Ok(EthType::IPv6),
            x if x == EthType::ATA as u16 => Ok(EthType::ATA),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct EthHdr {
    pub dst: String,
    pub src: String,
    pub ether_type: EthType,
}

impl EthHdr {
    pub fn read(reader: &mut BufReader<File>) -> std::io::Result<Self> {
        let dst = Self::read_mac_addr(reader)?;
        let src = Self::read_mac_addr(reader)?;
        let ether_type = match EthType::try_from(reader.read_u16::<NetworkEndian>()?) {
            Ok(ether_type) => ether_type,
            Err(_) => return Err(std::io::Error::other("Cannot parse EthType")),
        };

        Ok(Self {
            dst,
            src,
            ether_type,
        })
    }

    fn read_mac_addr(reader: &mut BufReader<File>) -> std::io::Result<String> {
        let mut mac_buffer = [0; 6];
        reader.read_exact(&mut mac_buffer)?;
        let mac_addr = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac_buffer[0],
            mac_buffer[1],
            mac_buffer[2],
            mac_buffer[3],
            mac_buffer[4],
            mac_buffer[5]
        );
        Ok(mac_addr)
    }
}
