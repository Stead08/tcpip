use crate::infrastructure::serialization::packet_serializer::{Deserialize, Serialize};

#[derive(Copy, Debug, Clone, PartialEq)]
pub struct Port(pub u16);
impl Port {
    pub fn new(port: u16) -> Self {
        Port(port)
    }
    pub fn to_port_number(&self) -> u16 {
        self.0
    }
}

impl Serialize for Port {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl Deserialize for Port {
    fn from_bytes(bytes: &[u8]) -> Self {
        Port(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}
