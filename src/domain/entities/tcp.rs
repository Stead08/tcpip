use crate::domain::common::checksum::calculate_checksum;
use crate::domain::common::pseudo_header::PseudoHeader;
use crate::domain::enums::tcp_type::ControlFlag;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::transport_layer::Port;
use crate::infrastructure::serialization::packet_serializer::{Deserialize, Serialize};

#[derive(Debug)]
pub struct TcpPacket {
    pub header: TcpHeader,
    data: Option<Vec<u8>>,
}

impl TcpPacket {
    pub fn new(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: Port,
        destination_port: Port,
        sequence_number: u32,
        ack_number: u32,
        flags: Vec<ControlFlag>,
        data: Option<Vec<u8>>,
    ) -> Self {
        let mut tcp_packet = TcpPacket {
            header: TcpHeader::new(
                source_port,
                destination_port,
                sequence_number,
                ack_number,
                ControlFlags::new(flags),
            ),
            data,
        };

        // 一時的にチェックサムを0で初期化
        tcp_packet.header.checksum = 0;

        let packet_bytes = tcp_packet.to_bytes();
        // lengthは擬似ヘッダ + TCPヘッダ + TCPデータの長さ
        let length = packet_bytes.len() as u16;
        let pseudo_header = PseudoHeader::new(source_ip, dest_ip, length, 6);
        let mut checksum_data = pseudo_header.to_bytes();
        checksum_data.extend(&packet_bytes);
        let checksum = calculate_checksum(&checksum_data);

        // 正しいチェックサムをセット
        tcp_packet.header.checksum = checksum;
        tcp_packet
    }
}

impl Deserialize for TcpPacket {
    fn from_bytes(bytes: &[u8]) -> Self {
        let source_port = Port::from_bytes(&bytes[0..2]);
        let destination_port = Port::from_bytes(&bytes[2..4]);
        let sequence_number = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let acknowledgment_number = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let data_offset = bytes[12] >> 4;
        let reserved = bytes[12] & 0x0F;
        let flags_byte = u16::from_be_bytes([bytes[12], bytes[13]]);
        let flags = ControlFlags::from_bits((flags_byte & 0x1FF) as u16); // 9ビットのフラグ部分
        let window_size = u16::from_be_bytes([bytes[14], bytes[15]]);
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent_pointer = u16::from_be_bytes([bytes[18], bytes[19]]);
        let data = if bytes.len() > 20 {
            Some(bytes[20..].to_vec())
        } else {
            None
        };
        TcpPacket {
            header: TcpHeader {
                source_port,
                destination_port,
                sequence_number,
                acknowledgment_number,
                data_offset,
                reserved,
                flags,
                window_size,
                checksum,
                urgent_pointer,
            },
            data,
        }
    }
}

impl ControlFlags {
    fn from_bits(bits: u16) -> Self {
        ControlFlags {
            ns: bits & 0x100 != 0,
            cwr: bits & 0x080 != 0,
            ece: bits & 0x040 != 0,
            urg: bits & 0x020 != 0,
            ack: bits & 0x010 != 0,
            psh: bits & 0x008 != 0,
            rst: bits & 0x004 != 0,
            syn: bits & 0x002 != 0,
            fin: bits & 0x001 != 0,
        }
    }
}

impl TcpPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(&self.header.source_port.to_bytes());
        buffer.extend(&self.header.destination_port.to_bytes());
        buffer.extend(&self.header.sequence_number.to_be_bytes());
        buffer.extend(&self.header.acknowledgment_number.to_be_bytes());
        buffer.push(self.header.data_offset << 4 | self.header.reserved);
        buffer.push(self.header.flags.to_bytes() as u8);
        buffer.extend(&self.header.window_size.to_be_bytes());
        buffer.extend(&self.header.checksum.to_be_bytes());
        buffer.extend(&self.header.urgent_pointer.to_be_bytes());
        if let Some(data) = &self.data {
            buffer.extend(data);
        }
        buffer
    }
}

#[derive(Debug)]
pub struct TcpHeader {
    pub source_port: Port,
    pub destination_port: Port,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: ControlFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn new(
        source_port: Port,
        destination_port: Port,
        sequence_num: u32,
        ack_num: u32,
        flags: ControlFlags,
    ) -> Self {
        TcpHeader {
            source_port,
            destination_port,
            flags,
            sequence_number: sequence_num,
            acknowledgment_number: ack_num,
            ..Default::default()
        }
    }
}

impl Default for TcpHeader {
    fn default() -> Self {
        TcpHeader {
            source_port: Port(0),
            destination_port: Port(0),
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 5,
            reserved: 0,
            flags: ControlFlags::default(),
            window_size: 1500,
            checksum: 0,
            urgent_pointer: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct ControlFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl ControlFlags {
    pub fn new(true_flags: Vec<ControlFlag>) -> Self {
        let mut flags = ControlFlags::default();
        for flag in true_flags {
            match flag {
                ControlFlag::NS => flags.ns = true,
                ControlFlag::CWR => flags.cwr = true,
                ControlFlag::ECE => flags.ece = true,
                ControlFlag::URG => flags.urg = true,
                ControlFlag::ACK => flags.ack = true,
                ControlFlag::PSH => flags.psh = true,
                ControlFlag::RST => flags.rst = true,
                ControlFlag::SYN => flags.syn = true,
                ControlFlag::FIN => flags.fin = true,
            }
        }
        flags
    }
    fn to_bytes(&self) -> u16 {
        let mut flags = 0u16;

        if self.fin {
            flags |= 1 << 0;
        }
        if self.syn {
            flags |= 1 << 1;
        }
        if self.rst {
            flags |= 1 << 2;
        }
        if self.psh {
            flags |= 1 << 3;
        }
        if self.ack {
            flags |= 1 << 4;
        }
        if self.urg {
            flags |= 1 << 5;
        }
        // Skipping 2 empty bits according to TCP standard
        if self.ece {
            flags |= 1 << 8;
        }
        if self.cwr {
            flags |= 1 << 9;
        }
        if self.ns {
            flags |= 1 << 10;
        }

        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::tcp_type::ControlFlag;
    use crate::domain::value_objects::ipv4_address::Ipv4Addr;
    use crate::domain::value_objects::transport_layer::Port;

    #[test]
    fn test_pseudo_header_length() {
        let source_ip = Ipv4Addr::new([192, 168, 0, 1]);
        let dest_ip = Ipv4Addr::new([192, 168, 0, 2]);
        let source_port = Port(12345);
        let dest_port = Port(80);
        let sequence_number = 12345;
        let flags = vec![ControlFlag::ACK];
        let tcp_packet = TcpPacket::new(
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            sequence_number,
            0,
            flags,
            None,
        );
        let pseudo_header = PseudoHeader::new(
            source_ip,
            dest_ip,
            tcp_packet.to_bytes().len() as u16 + 12,
            6,
        );
        assert_eq!(pseudo_header.to_bytes().len(), 12);
        assert_eq!(pseudo_header.length, 32);
    }
    // 送信元port 12345、宛先port80, src 192.168.101.5, destination_ip 192,168.101.23, seqence_numberが12345の時checksumは0xa49d

    #[test]
    // struct ControlFlagのto_bytesメソッドのテスト
    fn test_control_flags_to_bytes() {
        let flags = ControlFlags {
            ns: true,
            cwr: true,
            ece: true,
            urg: true,
            ack: true,
            psh: true,
            rst: true,
            syn: true,
            fin: true,
        };
        let bytes = flags.to_bytes();
        assert_eq!(bytes, 0b111111111);
    }
    #[test]
    fn test_control_flags_to_bytes2() {
        let flags = ControlFlags {
            ns: false,
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        };
        let bytes = flags.to_bytes();
        assert_eq!(bytes, 0);
    }
    #[test]
    fn test_control_flags_to_bytes3() {
        let flags = ControlFlags {
            ns: true,
            cwr: false,
            ece: true,
            urg: false,
            ack: true,
            psh: false,
            rst: true,
            syn: false,
            fin: true,
        };
        let bytes = flags.to_bytes();
        assert_eq!(bytes, 0b101010101);
    }
}
