extern crate byteorder;
extern crate errno;
extern crate libc;

use std::io::ErrorKind;
use std::io::{self, Error as Errorr};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use libc::recv;
use std::{convert::TryFrom, convert::TryInto, io::Write};

use bincode;
use hex_literal::hex;
use serde::{Deserialize, Serialize};

use std::mem;
use std::{error::Error, net::TcpListener, os::unix::io::AsRawFd};

use std::thread;
use std::time::Duration;

use nix::sys::{socket::recv as nix_recv, socket::recvfrom, socket::send, socket::MsgFlags};

const NETWORK_IFACE: &str = "eth0";

const CM_SET_KEY_TYPE: u8 = b'\x01';
//According to 15118-3 this value should be 0x00 and not 0xAA
const CM_SET_KEY_MY_NONCE: [u8; 4] = hex!("aa aa aa aa");
const CM_SET_KEY_YOUR_NONCE: [u8; 4] = hex!("00 00 00 00");
const CM_SET_KEY_PID: u8 = b'\x04';
const CM_SET_KEY_PRN: [u8; 2] = hex!("00 00");
const CM_SET_KEY_PMN: u8 = b'\x00';
const CM_SET_KEY_NEW_EKS: u8 = b'\x01';
const CM_SET_CCO_CAPAB: u8 = b'\x00';

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_ARP: u16 = 0x0806; // from if_ether.h for SOCK_RAW
const SIOCGIFADDR: ioctl_request_t = 0x8915;
const SIOCGIFINDEX: ioctl_request_t = 0x8933;
const IFNAMSIZ: usize = 16; // net/if.h
const SIOCGIFHWADDR: ioctl_request_t = 0x8927;

#[allow(non_camel_case_types)]
type ioctl_request_t = libc::c_ulong;

type MacAddr = [u8; 6];

// An ARP packet with ethernet headers still attached
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
struct RawArpFrame {
    // Ethernet frame headers
    destination_mac: MacAddr,
    source_mac: MacAddr,
    ether_type: u16, // should be 0x0806 BE for an ARP payload
    // ARP Payload
    hardware_type: u16, // expect 0x0001 for ethernet
    protocol_type: u16, // expect 0x0800 for IPv4
    hw_addr_len: u8,    // expect 6 [octets] for MAC addresses
    proto_addr_len: u8, // expect 4 [octets] for IPv4 addresses
    operation: u16,     // 1 for request, 2 for reply
    sender_hw_addr: MacAddr,
    sender_proto_addr: [u8; 4],
    target_hw_addr: MacAddr,
    target_proto_addr: [u8; 4],
}

//#[repr(C, packed)] // This tells the compiler to represent the struct in memory exactly
// with the order below, instead of shuffling things around for efficiency
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetKeyReq {
    key_type: u8,
    my_nonce: [u8; 4],
    your_nonce: [u8; 4],
    pid: u8,
    prn: [u8; 2],
    pmn: u8,
    cco_cap: u8,
    nid: [u8; 7],
    new_eks: u8,
    new_key: [u8; 16],
}

impl SetKeyReq {
    pub fn new(nid: [u8; 7], new_key: [u8; 16]) -> Self {
        SetKeyReq {
            key_type: CM_SET_KEY_TYPE,
            my_nonce: CM_SET_KEY_MY_NONCE,
            your_nonce: CM_SET_KEY_YOUR_NONCE,
            pid: CM_SET_KEY_PID,
            prn: CM_SET_KEY_PRN,
            pmn: CM_SET_KEY_PMN,
            cco_cap: CM_SET_CCO_CAPAB,
            nid,
            new_eks: CM_SET_KEY_NEW_EKS,
            new_key,
        }
    }
    fn write_to_buffer<T: ByteOrder>(self, buffer: &mut [u8; 44]) {
        let mut buffer = &mut buffer[..];
        buffer.write(&self.nid);
        buffer.write(&self.new_key);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

#[derive(Debug)]
struct SocketError {
    action: &'static str,
    err: errno::Errno,
}

macro_rules! sockerr {
    ($action:expr, $res:expr) => {
        if $res == -1 {
            return Err(SocketError {
                action: $action,
                err: errno::errno(),
            });
        }
    };
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_ifindex {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifindex: libc::c_int,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_ifhwaddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifhwaddr: libc::sockaddr,
}

fn ifhwaddr_from_ifname(ifname: &str, sock: libc::c_int) -> Result<MacAddr, SocketError> {
    let mut ifr = ifreq_ifhwaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifhwaddr: unsafe { std::mem::zeroed() },
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFHWADDR.try_into().unwrap(), &ifr) };
    sockerr!("getting ifhwaddr", res);
    unsafe {
        let slice_converted: &[u8] = std::mem::transmute(&ifr.ifr_ifhwaddr.sa_data[0..6]);
        let hw_addr: MacAddr = slice_converted.try_into().unwrap();
        return Ok(hw_addr);
    }
}

fn ifindex_from_ifname(ifname: &str, sock: libc::c_int) -> Result<libc::c_int, SocketError> {
    let mut ifr = ifreq_ifindex {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifindex: 0,
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFINDEX.try_into().unwrap(), &ifr) };
    sockerr!("getting ifindex", res);
    return Ok(ifr.ifr_ifindex);
}

pub fn socket_send_frame(socket: i32, frame: &[u8], ifindex: i32) -> io::Result<()> {
    let sa = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ARP.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    match unsafe {
        let sa_ptr = &sa as *const libc::sockaddr_ll as *const libc::sockaddr;
        libc::sendto(
            socket,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            sa_ptr,
            mem::size_of_val(&sa) as libc::socklen_t,
        )
    } {
        -1 => Err(Errorr::last_os_error()),
        _ => Ok(()),
    }
}

pub fn bind_to_iface(socket: i32, ifindex: i32) -> Result<String, String> {
    let sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let addr_ptr = &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr;
    match unsafe {
        libc::bind(
            socket,
            addr_ptr,
            std::mem::size_of_val(&sockaddr) as libc::socklen_t,
        )
    } {
        -1 => Err("Bind to socket failed".to_string()),
        _ => Ok("Error on socket bind".to_string()),
    }
}

pub fn rcv_frame(socket: i32) {
    loop {
        unsafe {
            let ifindex = ifindex_from_ifname(NETWORK_IFACE, socket).unwrap();

            let mut listen_sockaddr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: ETH_P_ALL.to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };

            let mut buf: [u8; 1024] = [0; 1024];
            let mut len: usize = 0;
            println!("Start waiting for a frame...");
            let addr_ptr = &mut listen_sockaddr as *mut libc::sockaddr_ll as *mut libc::sockaddr;
            let len_i: isize;
            //len_i = libc::recvfrom(
            //socket,
            //buf.as_mut_ptr() as *mut libc::c_void,
            //buf.len(),
            //0,
            //addr_ptr,
            //mem::size_of_val(&listen_sockaddr) as *mut libc::socklen_t,
            //);

            len = match libc::recv(socket, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) {
                d if d < 0 => {println!("Error receiving");d as usize}
                len => {println!("Received {:?} bytes", len);println!("Buffer content: {:x?}", &buf[..len as usize]);len as usize}
            };

        }
    }
}

fn main() {
    let listen_socket = unsafe {
        match libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ARP.to_be() as i32) {
            -1 => Err("Opening socket error"),
            fd => Ok(fd),
        }
    }
    .unwrap();

    println!("opening socket {:?}", listen_socket);

    let ifindex = ifindex_from_ifname(NETWORK_IFACE, listen_socket).unwrap();

    println!("Interface address is {:?}", ifindex);

    let if_hwaddr = ifhwaddr_from_ifname(NETWORK_IFACE, listen_socket).unwrap();
    println!("IF HW addr is {:x?}", if_hwaddr);

    let listen_sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ARP.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };


    match bind_to_iface(listen_socket, ifindex) {
        Err(why) => panic!("{:?}", why),
        _ => (),
    }

    //thread::spawn(move || rcv_frame(listen_socket));
    //thread::sleep(Duration::from_millis(10));
    let mut buf: [u8; 1024] = [0; 1024];
    let mut len: usize = 0;


    //len = nix_recv(listen_socket, &mut buf, MsgFlags::empty()).unwrap();

    rcv_frame(listen_socket);
    //println!("Received {:?} bytes", len);
    //println!("Buffer content: {:x?}", buf);
}
