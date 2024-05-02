use crate::domain::common::checksum::calculate_checksum;
use crate::domain::enums::ip_type::Protocol;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::infrastructure::serialization::packet_serializer::Serialize;
use anyhow::anyhow;

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet {
    header: Ipv4Header,
    pub(crate) payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Ipv4Packet> {
        // protocolが不正な場合はエラーを返す
        if Protocol::from_u8(bytes[9]).is_none() {
            return Err(anyhow!("Invalid protocol : {}", bytes[9]));
        }
        let header = Ipv4Header {
            version: bytes[0] >> 4,
            ihl: bytes[0] & 0x0F,
            dscp: bytes[1] >> 2,
            ecn: bytes[1] & 0x03,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags: bytes[6] >> 5,
            fragment_offset: u16::from_be_bytes([bytes[6] & 0x1F, bytes[7]]),
            ttl: bytes[8],
            protocol: Protocol::from_u8(bytes[9]).ok_or(anyhow!("Invalid protocol"))?,
            header_checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
            source: Ipv4Addr::new([bytes[12], bytes[13], bytes[14], bytes[15]]),
            destination: Ipv4Addr::new([bytes[16], bytes[17], bytes[18], bytes[19]]),
        };
        let payload = bytes[header.ihl as usize * 4..].to_vec();
        Ok(Ipv4Packet { header, payload })
    }
    pub fn get_protocol(&self) -> Protocol {
        self.header.protocol
    }

    pub fn get_source_ip(&self) -> Ipv4Addr {
        self.header.source
    }

    pub fn get_destination_ip(&self) -> Ipv4Addr {
        self.header.destination
    }
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
        Ipv4Packet { header, payload }
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
    pub fn new(source: Ipv4Addr, destination: Ipv4Addr, protocol: Protocol) -> Ipv4Header {
        Ipv4Header {
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
        assert_eq!(
            bytes,
            vec![69, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2]
        );
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
