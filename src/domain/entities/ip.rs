use crate::domain::value_objects::ipv4_address::Ipv4Addr;
enum Ip {
    V4(String),
    V6(String),
}

enum Protocol {
    ICMP = 1,
    IP = 4,
    TCP = 6,
    UDP = 17,
}

impl Protocol {
    pub fn from_u8(value: u8) -> Option<Protocol> {
        match value {
            1 => Some(Protocol::ICMP),
            4 => Some(Protocol::IP),
            6 => Some(Protocol::TCP),
            17 => Some(Protocol::UDP),
            _ => None,
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Protocol::ICMP => 1,
            Protocol::IP => 4,
            Protocol::TCP => 6,
            Protocol::UDP => 17,
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