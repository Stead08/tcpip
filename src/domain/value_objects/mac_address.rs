const MAC_ADDR_SIZE: usize = 6;

// MACアドレスの構造体, structの定義
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; MAC_ADDR_SIZE]);

impl MacAddr {
    // MACアドレスの生成
    pub fn new(addr: &[u8]) -> MacAddr {
        let mut mac_addr = [0; MAC_ADDR_SIZE];
        mac_addr.copy_from_slice(addr);
        MacAddr(mac_addr)
    }
    
    pub fn broadcast() -> MacAddr {
        MacAddr([0xFF; MAC_ADDR_SIZE])
    }
    
    // 00:00:00:00:00:00のMACアドレスを生成
    pub fn zero() -> MacAddr {
        MacAddr([0; MAC_ADDR_SIZE])
    }
    
}

impl std::convert::AsRef<[u8]> for MacAddr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
