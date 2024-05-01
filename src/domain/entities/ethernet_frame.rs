use nom::AsBytes;
use crate::domain::enums::eth_type::EthType;
use crate::domain::value_objects::mac_address::MacAddr;
use crate::infrastructure::serialization::packet_serializer::{add_to_buffer, Deserialize, Serialize};

#[derive(Clone)]
pub struct EthernetFrame {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub eth_type: EthType,
    pub payload: Vec<u8>,
}
impl EthernetFrame {
    pub fn new(src: MacAddr, dst: MacAddr, eth_type: EthType, payload: Vec<u8>) -> EthernetFrame {
        EthernetFrame {
            src,
            dst,
            eth_type,
            payload,
        }
    }
    
    pub fn get_ethertype(&self) -> EthType {
        self.eth_type
    }
}

impl Serialize for EthernetFrame {

    fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Vec::new();
            add_to_buffer(&mut buf, &self.dst);
            add_to_buffer(&mut buf, &self.src);
            add_to_buffer(&mut buf, (self.eth_type as u16).to_be_bytes());
            add_to_buffer(&mut buf, &self.payload);
            buf

        
    }
}

impl Deserialize for EthernetFrame {
    fn from_bytes(bytes: &[u8]) -> EthernetFrame {
        let dst = MacAddr::new(&bytes[0..6]);
        let src = MacAddr::new(&bytes[6..12]);
        let eth_type = u16::from_be_bytes([bytes[12], bytes[13]]);
        let payload = bytes[14..].to_vec();
        if let Some(eth_type) = EthType::from_u16(eth_type) {
            EthernetFrame {
                src,
                dst,
                eth_type,
                payload,
            }
        } else {
            panic!("Invalid eth type");
        }
    }
}