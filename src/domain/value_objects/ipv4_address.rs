const IPV4_ADDR_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; IPV4_ADDR_SIZE]);

impl Ipv4Addr {
    pub fn new(addr: [u8; IPV4_ADDR_SIZE]) -> Ipv4Addr {
        Ipv4Addr(addr)
    }
}