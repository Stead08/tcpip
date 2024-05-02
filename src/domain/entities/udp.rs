use crate::domain::common::checksum::calculate_checksum;
use crate::domain::common::pseudo_header::PseudoHeader;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::transport_layer::Port;
use crate::infrastructure::serialization::packet_serializer::Serialize;

pub struct UdpPacket {
    header: UdpHeader,
    data: Vec<u8>,
}

pub struct UdpHeader {
    source_port: Port,
    destination_port: Port,
    length: u16,
    checksum: u16,
}

impl Serialize for UdpHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.source_port.to_bytes());
        buffer.extend(&self.destination_port.to_bytes());
        buffer.extend(&self.length.to_be_bytes());
        buffer.extend(&self.checksum.to_be_bytes());
        buffer
    }
}

impl UdpPacket {
    pub fn new(
        source_port: Port,
        destination_port: Port,
        data: Vec<u8>,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) -> Self {
        let length = (data.len() + 8) as u16; // 8 bytes for the UDP header
        let mut udp_packet = UdpPacket {
            header: UdpHeader {
                source_port,
                destination_port,
                length,
                checksum: 0,
            },
            data,
        };

        let pseudo_header = PseudoHeader::new(source_ip, dest_ip, length, 17);
        let mut checksum_data = pseudo_header.to_bytes();
        checksum_data.extend(udp_packet.to_bytes());

        let checksum = calculate_checksum(&checksum_data);
        udp_packet.header.checksum = checksum;

        udp_packet
    }
}

impl Serialize for UdpPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.to_bytes());
        buffer.extend(&self.data);
        buffer
    }
}
