use crate::infrastructure::serialization::packet_serializer::Serialize;

#[derive(Copy,Debug, Clone, PartialEq)]
pub struct Port(pub u16);
impl Port {
    pub fn new(port: u16) -> Self {
        Port(port)
    }
}

impl Serialize for Port {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}