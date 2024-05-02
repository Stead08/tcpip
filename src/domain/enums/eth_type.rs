#[derive(Copy, Clone, PartialEq)]
pub enum EthType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
}

impl EthType {
    pub fn from_u16(value: u16) -> Option<EthType> {
        match value {
            0x0800 => Some(EthType::IPv4),
            0x0806 => Some(EthType::ARP),
            0x86DD => Some(EthType::IPv6),
            _ => None,
        }
    }
}
