use crate::domain::value_objects::{ipv4_address::Ipv4Addr, mac_address::MacAddr};
use crate::infrastructure::serialization::packet_serializer::{add_to_buffer, Deserialize, Serialize};
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::IResult;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct Arp {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub opcode: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl Arp {
    pub fn new(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Arp {
        Arp {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_size: 6,
            protocol_size: 4,
            opcode: 1,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::broadcast(),
            target_ip,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Arp> {
        let (input, hardware_type) = le_u16(bytes)?;
        let (input, protocol_type) = le_u16(input)?;
        let (input, hardware_size) = le_u8(input)?;
        let (input, protocol_size) = le_u8(input)?;
        let (input, opcode) = le_u16(input)?;
        let (input, sender_mac) = le_u32(input)?;
        let (input, sender_mac_2) = le_u16(input)?;
        let (input, sender_ip) = le_u32(input)?;
        let (input, target_mac) = le_u32(input)?;
        let (input, target_mac_2) = le_u16(input)?;
        let (input, target_ip) = le_u32(input)?;
        let sender_mac = [
            sender_mac as u8,
            (sender_mac >> 8) as u8,
            (sender_mac >> 16) as u8,
            (sender_mac >> 24) as u8,
            sender_mac_2 as u8,
            (sender_mac_2 >> 8) as u8,
        ];
        let sender_mac = MacAddr::new(&sender_mac);
        let target_mac = [
            target_mac as u8,
            (target_mac >> 8) as u8,
            (target_mac >> 16) as u8,
            (target_mac >> 24) as u8,
            target_mac_2 as u8,
            (target_mac_2 >> 8) as u8,
        ];
        let target_mac = MacAddr::new(&target_mac);
        let sender_ip = [
            sender_ip as u8,
            (sender_ip >> 8) as u8,
            (sender_ip >> 16) as u8,
            (sender_ip >> 24) as u8,
        ];
        let sender_ip = Ipv4Addr::new(sender_ip);
        let target_ip = [
            target_ip as u8,
            (target_ip >> 8) as u8,
            (target_ip >> 16) as u8,
            (target_ip >> 24) as u8,
        ];
        let target_ip = Ipv4Addr::new(target_ip);
        Ok((
            input,
            Arp {
                hardware_type,
                protocol_type,
                hardware_size,
                protocol_size,
                opcode,
                sender_mac,
                sender_ip,
                target_mac,
                target_ip,
            },
        ))
    }
}

impl Serialize for Arp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        add_to_buffer(&mut buf, self.hardware_type.to_be_bytes());
        add_to_buffer(&mut buf, self.protocol_type.to_be_bytes());
        buf.push(self.hardware_size);
        buf.push(self.protocol_size);
        add_to_buffer(&mut buf, self.opcode.to_be_bytes());
        add_to_buffer(&mut buf, self.sender_mac);
        add_to_buffer(&mut buf, self.sender_ip);
        add_to_buffer(&mut buf, self.target_mac);
        add_to_buffer(&mut buf, self.target_ip);
        buf
    }
}

impl Deserialize for Arp {
    fn from_bytes(bytes: &[u8]) -> Arp {
        let (_, arp) = Arp::from_bytes(bytes).expect("Failed to parse ARP packet");
        arp
    }
}