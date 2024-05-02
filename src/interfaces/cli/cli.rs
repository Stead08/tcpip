use crate::domain;
use crate::domain::entities::arp::Arp;
use crate::domain::entities::ethernet_frame::EthernetFrame;
use crate::domain::entities::icmp::{Icmp, IcmpData};
use crate::domain::entities::ip::{Ipv4Header, Ipv4Packet};
use crate::domain::entities::tcp::TcpPacket;
use crate::domain::enums::eth_type::EthType;
use crate::domain::enums::icmp_type::IcmpType::EchoRequest;
use crate::domain::enums::ip_type::Protocol;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::mac_address::MacAddr;
use crate::domain::value_objects::transport_layer::Port;
use crate::infrastructure::network::datalink_operations::{
    get_interface, receive_specific_packet, send,
};
use crate::infrastructure::serialization::packet_serializer::{Deserialize, Serialize};
use crate::interfaces::cli::util::{get_ip, get_mac};
use nom::AsBytes;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use rand::random;

pub fn run() -> anyhow::Result<()> {
    // 使用するデバイスのインターフェース名
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface>", args[0]);
        std::process::exit(1);
    }

    let interface_name = args[1].as_str();

    // 自身のIPアドレスを取得
    let ip = get_ip(interface_name)?;
    let ip = ip.to_string();
    // [u8; 4]に変換
    let ip = ip
        .split('.')
        .map(|s| s.parse::<u8>().unwrap())
        .collect::<Vec<u8>>();
    let ip = [ip[0], ip[1], ip[2], ip[3]];
    let ip = Ipv4Addr::new(ip);

    //　自身のMACアドレスを取得
    let mac = get_mac(interface_name)?;
    // MacAddrに変換
    let mac = MacAddr::new(mac.as_bytes());

    let target_ip = Ipv4Addr::new([192, 168, 101, 23]);
    // ARPパケットを作成
    let arp = create_arp_packet(mac, ip, target_ip)?;
    // ethernetフレームを作成
    let eth = EthernetFrame::new(
        MacAddr::zero(),
        MacAddr::broadcast(),
        EthType::ARP,
        arp.to_bytes(),
    );
    let bytes = eth.to_bytes();
    send(interface_name, bytes.as_slice())?;
    let arp_packet = receive_specific_packet(interface_name, EthType::ARP, ip)?; // ARPパケットを受信する
    let target_mac = arp_packet.sender_mac;

    tcp_three_way_handshake(ip, target_ip, mac, target_mac, interface_name)?;

    Ok(())
}

fn create_arp_packet(
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> anyhow::Result<Arp> {
    // Send an ARP request
    let arp = Arp::new(sender_mac, sender_ip, target_ip);

    Ok(arp)
}

fn create_icmp_packet() -> anyhow::Result<Icmp> {
    // Send an ICMP request
    let icmp = Icmp::new(
        EchoRequest,
        0,
        IcmpData::EchoRequest(domain::entities::icmp::EchoRequestPacket::new(
            0,
            0,
            vec![0; 32],
        )),
    );

    Ok(icmp)
}

fn tcp_three_way_handshake(
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    interface_name: &str,
) -> anyhow::Result<()> {
    // 3-way handshake
    let sequence_number = random::<u32>();
    let src_port = Port::new(22334);
    let dest_port = Port::new(8000);
    // Synパケットを作成
    let syn_packet = domain::entities::tcp::TcpPacket::new(
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        sequence_number,
        0,
        vec![domain::enums::tcp_type::ControlFlag::SYN],
        None,
    );
    // Ipパケットを作成
    let ip_header = Ipv4Header::new(src_ip, dest_ip, domain::enums::ip_type::Protocol::Tcp);
    let ip_packet = Ipv4Packet::new(ip_header, syn_packet.to_bytes());
    // Ethernetフレームを作成
    let eth_frame = EthernetFrame::new(src_mac, dest_mac, EthType::IPv4, ip_packet.to_bytes());
    // パケットを送信
    send(interface_name, eth_frame.to_bytes().as_slice())?;
    // SYN+ACKパケットを受信
    receive_tcp_handshake(
        interface_name,
        src_mac,
        dest_mac,
        src_ip,
        dest_ip,
        src_port,
        dest_port,
    )?;

    Ok(())
}

pub fn receive_tcp_handshake(
    interface_name: &str,
    local_mac: MacAddr,  // 自身のMACアドレス
    remote_mac: MacAddr, // 対象のMACアドレス
    local_ip: Ipv4Addr,  // 自身のIPアドレス
    remote_ip: Ipv4Addr, // 対象のIPアドレス
    local_port: Port,    // 自身のポート番号
    remote_port: Port,   // 対象のポート番号
) -> anyhow::Result<()> {
    let interface = get_interface(interface_name)?;

    if let Ethernet(mut tx, mut rx) = datalink::channel(&interface, Default::default())? {
        while let Ok(packet) = rx.next() {
            let eth_frame = EthernetFrame::from_bytes(&packet);

            if eth_frame.get_ethertype() == EthType::IPv4 {
                let ip_packet = Ipv4Packet::from_bytes(&eth_frame.payload)?;

                // 受信パケットの送信元と送信先を検証
                if ip_packet.get_protocol() == Protocol::Tcp
                    && ip_packet.get_source_ip() == remote_ip
                    && ip_packet.get_destination_ip() == local_ip
                {
                    let tcp_packet = TcpPacket::from_bytes(&ip_packet.payload);

                    // SYN+ACKの確認と送信元/送信先ポートの検証
                    if tcp_packet.header.flags.syn
                        && tcp_packet.header.flags.ack
                        && tcp_packet.header.source_port.to_port_number()
                            == remote_port.to_port_number()
                        && tcp_packet.header.destination_port.to_port_number()
                            == local_port.to_port_number()
                    {
                        println!("{:?}", tcp_packet);
                        let syn_ack_packet = tcp_packet;
                        let ack_number = syn_ack_packet.header.acknowledgment_number;
                        let sequence_number = syn_ack_packet.header.sequence_number;
                        // ACKパケットを作成
                        let ack_packet = domain::entities::tcp::TcpPacket::new(
                            local_ip,
                            remote_ip,
                            local_port,
                            remote_port,
                            ack_number,
                            sequence_number + 1,
                            vec![domain::enums::tcp_type::ControlFlag::ACK],
                            None,
                        );
                        // ACKパケットを送信
                        let ip_header = Ipv4Header::new(
                            local_ip,
                            remote_ip,
                            domain::enums::ip_type::Protocol::Tcp,
                        );
                        let ip_packet = Ipv4Packet::new(ip_header, ack_packet.to_bytes());
                        let eth_frame = EthernetFrame::new(
                            local_mac,
                            remote_mac,
                            EthType::IPv4,
                            ip_packet.to_bytes(),
                        );
                        tx.send_to(eth_frame.to_bytes().as_slice(), None);
                        println!("TCP handshake completed");
                        // FINACKパケットを作成
                        let fin_ack_packet = domain::entities::tcp::TcpPacket::new(
                            local_ip,
                            remote_ip,
                            local_port,
                            remote_port,
                            ack_number,
                            sequence_number + 1,
                            vec![
                                domain::enums::tcp_type::ControlFlag::FIN,
                                domain::enums::tcp_type::ControlFlag::ACK,
                            ],
                            None,
                        );
                        // FINACKパケットを送信
                        let ip_header = Ipv4Header::new(
                            local_ip,
                            remote_ip,
                            domain::enums::ip_type::Protocol::Tcp,
                        );
                        let ip_packet = Ipv4Packet::new(ip_header, fin_ack_packet.to_bytes());
                        let eth_frame = EthernetFrame::new(
                            local_mac,
                            remote_mac,
                            EthType::IPv4,
                            ip_packet.to_bytes(),
                        );
                        tx.send_to(eth_frame.to_bytes().as_slice(), None);
                        println!("TCP connection closed");
                        // 3秒待つ
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        return Ok(());
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to open channel");
        std::process::exit(1);
    }

    Err(anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Failed to complete TCP handshake",
    )))
}
