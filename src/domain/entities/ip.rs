use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::infrastructure::serialization::packet_serializer::Serialize;
use crate::domain::enums::ip_type::Protocol;
use crate::domain::common::checksum::calculate_checksum;

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet {
    header: Ipv4Header,
    payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(header: Ipv4Header, payload: Vec<u8>) -> Ipv4Packet {
        let total_length = header.to_bytes().len() + payload.len();
        let header = Ipv4Header {
            total_length: total_length as u16,
            ..header
        };
        let checksum = calculate_checksum(&header.to_bytes());
        let header = Ipv4Header {
            header_checksum: checksum,
            ..header
        };
        Ipv4Packet {
            header,
            payload,
        }
    }
}

impl Serialize for Ipv4Packet {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(self.header.to_bytes());
        buffer.extend(&self.payload);
        buffer
    }
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub header_checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}





impl Ipv4Header {
    pub fn new(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: Protocol
    ) -> Ipv4Header {
         Ipv4Header{
            protocol,
            source,
            destination,
            ..Default::default()
        }
    }
    
}

impl Default for Ipv4Header {
    fn default() -> Ipv4Header {
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: Protocol::IP,
            header_checksum: 0,
            source: Ipv4Addr::new([0, 0, 0, 0]),
            destination: Ipv4Addr::new([0, 0, 0, 0]),
        }
    }
}

impl Serialize for Ipv4Header {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push((self.version << 4) | self.ihl);
        buffer.push((self.dscp << 2) | self.ecn);
        buffer.extend(&self.total_length.to_be_bytes());
        buffer.extend(&self.identification.to_be_bytes());
        buffer.push((self.flags << 5) | (self.fragment_offset >> 8) as u8);
        buffer.push((self.fragment_offset & 0xFF) as u8);
        buffer.push(self.ttl);
        buffer.push(self.protocol.to_u8());
        buffer.extend(&self.header_checksum.to_be_bytes());
        buffer.extend(self.source.as_ref());
        buffer.extend(self.destination.as_ref());
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::ipv4_address::Ipv4Addr;
    use crate::infrastructure::serialization::packet_serializer::Serialize;

    #[test]
    fn test_ipv4_header_to_bytes() {
        let source = Ipv4Addr::new([192, 168, 0, 1]);
        let destination = Ipv4Addr::new([192, 168, 0, 2]);
        let header = Ipv4Header::new(source, destination, Protocol::Tcp);
        let bytes = header.to_bytes();
        assert_eq!(bytes, vec![69, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2]);
    }
    #[test]
    fn test_ipv4_header_size() {
        let source = Ipv4Addr::new([192, 168, 0, 1]);
        let destination = Ipv4Addr::new([192, 168, 0, 2]);
        let header = Ipv4Header::new(source, destination, Protocol::Tcp);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 20);
    }
}