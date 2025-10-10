use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::BufReader;

#[repr(C)]
#[derive(Debug)]
pub struct PcapFileHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

impl PcapFileHeader {
    pub fn read(reader: &mut BufReader<File>) -> std::io::Result<Self> {
        let magic_number = reader.read_u32::<LittleEndian>()?;
        let version_major = reader.read_u16::<LittleEndian>()?;
        let version_minor = reader.read_u16::<LittleEndian>()?;
        let thiszone = reader.read_i32::<LittleEndian>()?;
        let sigfigs = reader.read_u32::<LittleEndian>()?;
        let snaplen = reader.read_u32::<LittleEndian>()?;
        let network = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            magic_number,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        })
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}

impl PacketHeader {
    pub fn read(reader: &mut BufReader<File>) -> std::io::Result<Self> {
        let ts_sec = reader.read_u32::<LittleEndian>()?;
        let ts_usec = reader.read_u32::<LittleEndian>()?;
        let incl_len = reader.read_u32::<LittleEndian>()?;
        let orig_len = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        })
    }
}
