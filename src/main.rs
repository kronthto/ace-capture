use std::net::{Ipv4Addr};

use etherparse::PacketHeaders;
use etherparse::IpHeader::{Version4, Version6};
use pcap::{Capture, Device};
use std::str;
use std::fs::{OpenOptions, File};
use std::io::Write;

mod atum;
mod conv;

const OSR: Ipv4Addr = Ipv4Addr::new(91, 134, 12, 104);

const XOR_BYTES : &str = "fewoiroqbfweotui29854f09qwe0213hrf0a89wq0re902149dujaosdjfapwetu2fadq1234fsacdfzdxczfsdgbhtrytrgw563fwsjkpqertgvxhteertw3512ga\0\0";
const SIZE_XOR_BYTES: i32 = 128;

fn main() {
    assert_eq!(SIZE_XOR_BYTES, XOR_BYTES.len() as i32);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("packets.txt")
        .unwrap();

  //  dbg!(Device::list().unwrap());

    let mut cap = Capture::from_device("\\Device\\NPF_{FE0812B0-2161-4903-B212-4717833FB8EA}").unwrap()
        .promisc(true)
        .open().unwrap();
    // TODO: Filter, Eingabe IP für Filter + match check
    // Input Network Device + Server key

    loop {
        if let Ok(packet) = cap.next() {
            match PacketHeaders::from_ethernet_slice(&packet) {
                Err(value) => println!("Err {:?}", value),
                Ok(value) => {
                    if value.transport.is_some() {
                        let tcp_header = value.transport.unwrap().tcp();
                        if tcp_header.is_some() && value.ip.is_some() {
                            let ip = value.ip.unwrap();
                            match ip {
                                Version4(ipv4) => {
                                    let parsed_ip = Ipv4Addr::new(ipv4.destination[0], ipv4.destination[1], ipv4.destination[2], ipv4.destination[3]);
                                    let parsed_ip_source = Ipv4Addr::new(ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3]);
                                    if parsed_ip.eq(&OSR) || parsed_ip_source.eq(&OSR) {
                                        parse_payload(value.payload, &mut file, parsed_ip.eq(&OSR));
                                    }
                                }
                                Version6(_ipv6) => {}
                            }
                        }
                    }
                }
            }
        }
    }

}

const ENCODE_MASK : u8 = 0x80;
const XOR_N_MASK : u8 = 0x7F;
const SIZE_CHECKSUM: i32 = 1;

fn parse_payload(payload: &[u8], out_stream: &mut File, client: bool) {

    if payload.len() < 6 {
        return;
    }

    let header = &payload[0 .. 4];
    let body = &payload[4..];

    let encode_flag = header[2];

    if ENCODE_MASK & encode_flag == ENCODE_MASK {

        let n_xor_n = encode_flag & XOR_N_MASK;

        let mut woffset = 0i32;
        let mut roffset = 0i32;
        let mut xoffset = n_xor_n as i32;

        let n_seq_number = header[3] ^ XOR_BYTES.bytes().nth((xoffset-1) as usize).unwrap();

        let n_dummy_len = n_seq_number as i32 % 4;

        let n_end_value = ((body.len() as i32 - n_dummy_len - SIZE_CHECKSUM) / 4 )*4;

        let mut decoded = vec![0u8; body.len()];

        while roffset < n_end_value
        {
            for i in 0..4 {
                decoded[(woffset + i) as usize] = body[(roffset + i) as usize] ^ XOR_BYTES.bytes().nth((xoffset+i) as usize).unwrap();
            }
            woffset += 4;
            roffset += 4;
            xoffset = (xoffset + 4) % SIZE_XOR_BYTES;
        }

        out_stream.write_all(decoded.as_slice());
        out_stream.write_all("\n".as_bytes());

        let opcode = conv::read_u16(&decoded[0..2]);
        let mode = match client {
            true => "C",
            false => "S",
        };

        if opcode != 0 && opcode != 14850 && opcode != 15104 {
            println!("{}: {}", mode, atum::get_protocol_type_string(opcode));
            atum::packet_content(opcode, &decoded[2..]);
        }

    } else {
        let _n_seq_number = header[3];

    }

}
