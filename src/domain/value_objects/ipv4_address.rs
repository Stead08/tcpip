const IPV4_ADDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; IPV4_ADDR_SIZE]);

impl Ipv4Addr {
    pub fn new(addr: [u8; IPV4_ADDR_SIZE]) -> Ipv4Addr {
        Ipv4Addr(addr)
    }
}

impl std::convert::AsRef<[u8]> for Ipv4Addr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}