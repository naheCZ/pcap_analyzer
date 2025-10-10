use byteorder::{NetworkEndian, ReadBytesExt};
use std::fs::File;
use std::io::BufReader;

pub const UDP_HEADER_SIZE: u8 = 8;

#[repr(C)]
#[derive(Debug)]
pub struct UdpHdr {
    pub source_port: u16,
    pub dst_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHdr {
    pub fn read(reader: &mut BufReader<File>) -> Result<UdpHdr, std::io::Error> {
        let source_port = reader.read_u16::<NetworkEndian>()?;
        let dst_port = reader.read_u16::<NetworkEndian>()?;
        let length = reader.read_u16::<NetworkEndian>()?;
        let checksum = reader.read_u16::<NetworkEndian>()?;

        Ok(Self {
            source_port,
            dst_port,
            length,
            checksum,
        })
    }
}
