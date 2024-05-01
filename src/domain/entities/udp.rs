use crate::domain::common::checksum::calculate_checksum;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::transport_layer::Port;
use crate::infrastructure::serialization::packet_serializer::Serialize;


pub struct UdpPacket {
    header: UdpHeader,
    data: Vec<u8>,
}


struct PseudoHeader {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    zero: u8,
    protocol: u8,
    udp_length: u16,
}

impl PseudoHeader {

    fn new(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, udp_length: u16) -> Self {
        PseudoHeader {
            source_ip,
            dest_ip,
            zero: 0,
            protocol: 17, 
            udp_length,
        }
    }


    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.source_ip.to_bytes());
        buffer.extend(&self.dest_ip.to_bytes());
        buffer.push(self.zero);
        buffer.push(self.protocol);
        buffer.extend(&self.udp_length.to_be_bytes());
        buffer
    }
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

    pub fn new(source_port: Port, destination_port: Port, data: Vec<u8>, source_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Self {
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
        
        let pseudo_header = PseudoHeader::new(source_ip, dest_ip, length);
        let mut checksum_data = pseudo_header.to_bytes();
        checksum_data.extend(udp_packet.to_bytes());


        let checksum = calculate_checksum(&checksum_data);
        udp_packet.header.checksum = checksum;

        udp_packet
    }
}

impl Serialize for UdpPacket {
    // Serialize the UDP packet to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.to_bytes());
        buffer.extend(&self.data);
        buffer
    }
}
