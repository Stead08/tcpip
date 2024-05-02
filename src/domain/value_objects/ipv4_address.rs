use crate::infrastructure::serialization::packet_serializer::Serialize;

const IPV4_ADDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; IPV4_ADDR_SIZE]);

impl Ipv4Addr {
    pub fn new(addr: [u8; IPV4_ADDR_SIZE]) -> Ipv4Addr {
        Ipv4Addr(addr)
    }
}

impl Serialize for Ipv4Addr {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl std::convert::AsRef<[u8]> for Ipv4Addr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
