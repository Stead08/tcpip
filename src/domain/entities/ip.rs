use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::infrastructure::serialization::packet_serializer::Serialize;

enum Ip {
    V4(String),
    V6(String),
}

enum Protocol {
    Icmp = 1,
    IP = 4,
    Tcp = 6,
    Udp = 17,
}

impl Protocol {
    pub fn from_u8(value: u8) -> Option<Protocol> {
        match value {
            1 => Some(Protocol::Icmp),
            4 => Some(Protocol::IP),
            6 => Some(Protocol::Tcp),
            17 => Some(Protocol::Udp),
            _ => None,
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::IP => 4,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        }
    }

}

struct Ipv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: Protocol,
    header_checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}





impl Ipv4Header {
    pub fn default() -> Ipv4Header {
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: Protocol::IP,
            header_checksum: 0,
            source: Ipv4Addr::new([0, 0, 0, 0]),
            destination: Ipv4Addr::new([0, 0, 0, 0]),
        }
    }
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
    fn default() -> Self {
        Self::default()
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
        assert_eq!(bytes[0], 0x45);
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[4], 0);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[6], 0);
        assert_eq!(bytes[7], 0);
        assert_eq!(bytes[8], 0);
        assert_eq!(bytes[9], 6);
        assert_eq!(bytes[10], 0);
        assert_eq!(bytes[11], 0);
        assert_eq!(bytes[12], 192);
        assert_eq!(bytes[13], 168);
        assert_eq!(bytes[14], 0);
        assert_eq!(bytes[15], 1);
        assert_eq!(bytes[16], 192);
        assert_eq!(bytes[17], 168);
        assert_eq!(bytes[18], 0);
        assert_eq!(bytes[19], 2);
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