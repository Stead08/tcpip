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
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use rand::random;
use crate::domain::enums::tcp_type::ControlFlag;
use crate::domain::enums::tcp_type::ControlFlag::{ACK, FIN, SYN};

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

    tcp_three_way_handshake_and_fin(ip, target_ip, mac, target_mac, interface_name)?;

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

pub fn tcp_three_way_handshake_and_fin(
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    interface_name: &str,
) -> anyhow::Result<()> {
    let interface = get_interface(interface_name)?;
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to create datalink channel: {}", e),
    };

    let sequence_number = random::<u32>();
    // 使えるポート番号を適当に選ぶ
    let port_number = random::<u16>();
    // well-knownや範囲外のポート番号を避ける
    let src_port = Port::new(port_number + 1024);
    let dest_port = Port::new(8000);

    // Send SYN
    send_syn_packet(
        &mut tx,
        src_ip,
        dest_ip,
        src_mac,
        dest_mac,
        src_port,
        dest_port,
        sequence_number,
    )?;

    // Receive SYN-ACK
    let syn_ack = receive_specific_flag_packet(&mut rx, src_ip, dest_ip, src_port, dest_port, vec![SYN, ACK])?;

    let acknowledgment_number = syn_ack.header.sequence_number + 1;

    // Send ACK
    send_ack_packet(
        &mut tx,
        src_ip,
        dest_ip,
        src_mac,
        dest_mac,
        src_port,
        dest_port,
        sequence_number + 1,
        acknowledgment_number,
    )?;

    // 3秒待つ
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Send FIN
    send_fin_packet(
        &mut tx,
        src_ip,
        dest_ip,
        src_mac,
        dest_mac,
        src_port,
        dest_port,
        sequence_number + 1,
        acknowledgment_number,
    )?;

    // Receive FIN/ACK
    receive_specific_flag_packet(&mut rx, src_ip, dest_ip, src_port, dest_port, vec![FIN, ACK])?;
    // Send ACK
    send_ack_packet(
        &mut tx,
        src_ip,
        dest_ip,
        src_mac,
        dest_mac,
        src_port,
        dest_port,
        sequence_number + 2,
        acknowledgment_number + 1,
    )?;

    Ok(())
}

fn send_syn_packet(
    tx: &mut Box<dyn DataLinkSender>,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_port: Port,
    dest_port: Port,
    sequence_number: u32,
) -> anyhow::Result<()> {
    let tcp = TcpPacket::new(
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        sequence_number,
        0,
        vec![SYN],
        None,
    );
    let ip_header = Ipv4Header::new(src_ip, dest_ip, Protocol::Tcp);
    let ip_packet = Ipv4Packet::new(ip_header, tcp.to_bytes());
    let eth_frame = EthernetFrame::new(src_mac, dest_mac, EthType::IPv4, ip_packet.to_bytes());
    let bytes = eth_frame.to_bytes();
    tx.send_to(bytes.as_slice(), None);
    println!("SYN packet sent.");
    Ok(())
}

fn receive_specific_flag_packet(
    rx: &mut Box<dyn DataLinkReceiver>,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: Port,
    dest_port: Port,
    flags: Vec<ControlFlag>,
) -> anyhow::Result<TcpPacket> {
    loop {
        let packet = rx.next()?;
        let eth_frame = EthernetFrame::from_bytes(&packet);
        if eth_frame.get_ethertype() != EthType::IPv4 {
            continue;
        }
        let ip_packet = Ipv4Packet::from_bytes(&eth_frame.payload)?;
        if ip_packet.get_protocol() != Protocol::Tcp {
            continue;
        }
        if ip_packet.get_source_ip() != dest_ip || ip_packet.get_destination_ip() != src_ip {
            continue;
        }
        let tcp_packet = TcpPacket::from_bytes(&ip_packet.payload);
        if tcp_packet.header.source_port.to_port_number() != dest_port.to_port_number()
            || tcp_packet.header.destination_port.to_port_number() != src_port.to_port_number()
        {
            continue;
        }
        if !flags.is_empty() {
            let mut found = false;
            for flag in flags.iter() {
                if !tcp_packet.header.flags.contains(flag) {
                    found = false;
                    break;
                }
                found = true;
            }
            if !found {
                continue;
            }
        }
        return Ok(tcp_packet);
    }
}

fn send_ack_packet(
    tx: &mut Box<dyn DataLinkSender>,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_port: Port,
    dest_port: Port,
    sequence_number: u32,
    acknowledgment_number: u32,
) -> anyhow::Result<()> {
    // Build and send an ACK packet
    let tcp = TcpPacket::new(
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        sequence_number,
        acknowledgment_number,
        vec![ACK],
        None,
    );
    let ip_header = Ipv4Header::new(src_ip, dest_ip, Protocol::Tcp);
    let ip_packet = Ipv4Packet::new(ip_header, tcp.to_bytes());
    let eth_frame = EthernetFrame::new(src_mac, dest_mac, EthType::IPv4, ip_packet.to_bytes());
    let bytes = eth_frame.to_bytes();
    tx.send_to(bytes.as_slice(), None);

    println!("ACK packet sent.");
    Ok(())
}

fn send_fin_packet(
    tx: &mut Box<dyn DataLinkSender>,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_mac: MacAddr,
    dest_mac: MacAddr,
    src_port: Port,
    dest_port: Port,
    sequence_number: u32,
    acknowledgment_number: u32,
) -> anyhow::Result<()> {
    // Build and send a FIN packet
    let tcp = TcpPacket::new(
        src_ip,
        dest_ip,
        src_port,
        dest_port,
        sequence_number,
        acknowledgment_number,
        vec![ACK, FIN],
        None,
    );
    let ip_header = Ipv4Header::new(src_ip, dest_ip, Protocol::Tcp);
    let ip_packet = Ipv4Packet::new(ip_header, tcp.to_bytes());
    let eth_frame = EthernetFrame::new(src_mac, dest_mac, EthType::IPv4, ip_packet.to_bytes());
    let bytes = eth_frame.to_bytes();
    tx.send_to(bytes.as_slice(), None);

    println!("FIN packet sent.");
    Ok(())
}
