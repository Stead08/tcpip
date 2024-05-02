use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::infrastructure::serialization::packet_serializer::Serialize;

pub struct PseudoHeader {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    zero: u8,
    protocol: u8,
    pub length: u16,
}

impl PseudoHeader {
    pub fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, length: u16, protocol: u8) -> Self {
        PseudoHeader {
            source_ip,
            dest_ip,
            zero: 0,
            protocol,
            length,
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.source_ip.to_bytes());
        buffer.extend(&self.dest_ip.to_bytes());
        buffer.push(self.zero);
        buffer.push(self.protocol);
        buffer.extend(&self.length.to_be_bytes());
        buffer
    }
}
