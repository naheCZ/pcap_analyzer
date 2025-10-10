use byteorder::{NetworkEndian, ReadBytesExt};
use std::fs::File;
use std::io::BufReader;

pub const TCP_HEADER_SIZE: u8 = 20;

#[repr(C)]
#[derive(Debug)]
pub struct TcpHdr {
    pub source_port: u16,
    pub dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    do_rsv_flags: u16,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
}

impl TcpHdr {
    pub fn read(reader: &mut BufReader<File>) -> Result<TcpHdr, std::io::Error> {
        let source_port = reader.read_u16::<NetworkEndian>()?;
        let dst_port = reader.read_u16::<NetworkEndian>()?;
        let seq_num = reader.read_u32::<NetworkEndian>()?;
        let ack_num = reader.read_u32::<NetworkEndian>()?;
        let do_rsv_flags = reader.read_u16::<NetworkEndian>()?;
        let window = reader.read_u16::<NetworkEndian>()?;
        let checksum = reader.read_u16::<NetworkEndian>()?;
        let urgent_ptr = reader.read_u16::<NetworkEndian>()?;

        Ok(Self {
            source_port,
            dst_port,
            seq_num,
            ack_num,
            do_rsv_flags,
            window,
            checksum,
            urgent_ptr,
        })
    }
}
