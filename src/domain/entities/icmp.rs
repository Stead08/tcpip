use crate::domain::common::checksum::calculate_checksum;
use crate::domain::enums::icmp_type::IcmpType;
use crate::infrastructure::serialization::packet_serializer::Serialize;

pub struct Icmp {
    icmp_type: IcmpType,
    code: u8,
    checksum: u16,
    data: IcmpData,
}

pub enum IcmpData {
    EchoRequest(EchoRequestPacket),
    // EchoReply(EchoReply),
    // DestinationUnreachable(DestinationUnreachable),
    // SourceQuench(SourceQuench),
}
pub struct EchoRequestPacket {
    identifier: u16,
    sequence_number: u16,
    data: Vec<u8>,
}

impl EchoRequestPacket {
    pub fn new(identifier: u16, sequence_number: u16, data: Vec<u8>) -> EchoRequestPacket {
        EchoRequestPacket {
            identifier,
            sequence_number,
            data,
        }
    }
}

impl Serialize for EchoRequestPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.identifier.to_be_bytes());
        buffer.extend(&self.sequence_number.to_be_bytes());
        buffer.extend(&self.data);
        buffer
    }
}

impl Icmp {
    pub fn new(icmp_type: IcmpType, code: u8, data: IcmpData) -> Icmp {
        let checksum = 0;
        let mut icmp = Icmp {
            icmp_type,
            code,
            checksum,
            data,
        };
        icmp.checksum = calculate_checksum(&icmp.to_bytes());
        icmp
    }
}

impl Serialize for Icmp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.icmp_type.to_u8());
        buffer.push(self.code);
        buffer.extend(&self.checksum.to_be_bytes());
        match &self.data {
            IcmpData::EchoRequest(echo_request) => {
                buffer.extend(&echo_request.to_bytes());
            }
        }
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
