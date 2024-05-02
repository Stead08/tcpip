pub enum Ip {
    V4(String),
    V6(String),
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Protocol {
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
