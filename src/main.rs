extern crate byteorder;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::io::Write;
use std::net::TcpStream;

use bincode;
use serde::{Deserialize, Serialize};

//#[repr(C, packed)] // This tells the compiler to represent the struct in memory exactly
// with the order below, instead of shuffling things around for efficiency
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetKeyReq {
    nid: [u8; 7],
    new_key: [u8; 16],
}

impl SetKeyReq {
    pub fn new(nid: [u8; 7], new_key: [u8; 16]) -> Self {
        SetKeyReq { nid, new_key }
    }
    fn write_to_buffer<T: ByteOrder>(self, buffer: &mut [u8; 44]) {
        let mut buffer = &mut buffer[..];
        buffer.write(&self.nid);
        buffer.write(&self.new_key);
    }
}

fn main() {
    let set_key_req = SetKeyReq::new([0x33, 0xaa, 0xaa, 0x11, 0xdd, 0xbb, 0x00], [0x00; 16]);
    //println!("SetKeyReq nid {:#04x?}", set_key_req.nid);
    let set_key_ser = bincode::serialize(&set_key_req).unwrap();
    println!("SetKeyReq nid {:x?}", set_key_req.nid);
    println!("SetKeyReq nmk: {:x?}", set_key_req.new_key);
    println!(
        "struct SetKeyReq serializes into byte array {:x?}",
        set_key_ser
    );
    let set_key_req_des: SetKeyReq = bincode::deserialize(&set_key_ser).unwrap();
    println!("SetKeyReq Deserialized: {:x?}", set_key_req_des);
}
