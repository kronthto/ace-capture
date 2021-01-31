use byteorder::{ReadBytesExt, LittleEndian};
use std::io::Cursor;

pub fn read_i32(data: &[u8]) -> i32 {
    let mut rdr =Cursor::new(data);
    return rdr.read_i32::<LittleEndian>().unwrap();
}

pub fn read_u16(data: &[u8]) -> u16 {
    let mut rdr =Cursor::new(data);
    return rdr.read_u16::<LittleEndian>().unwrap();
}
