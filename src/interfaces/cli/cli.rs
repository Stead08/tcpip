use nom::AsBytes;
use crate::domain;
use crate::domain::entities::arp::Arp;
use crate::domain::entities::ethernet_frame::EthernetFrame;
use crate::domain::entities::icmp::{Icmp, IcmpData};
use crate::domain::entities::ip::{Ipv4Header, Ipv4Packet};
use crate::domain::enums::eth_type::EthType;
use crate::domain::enums::icmp_type::IcmpType::EchoRequest;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::mac_address::MacAddr;
use crate::domain::value_objects::transport_layer::Port;
use crate::infrastructure::network::datalink_operations::{receive_specific_packet, send};
use crate::infrastructure::serialization::packet_serializer::Serialize;
use crate::interfaces::cli::util::{get_ip, get_mac};

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
    let ip = ip.split('.')
        .map(|s| s.parse::<u8>().unwrap())
        .collect::<Vec<u8>>();
    let ip = [ip[0], ip[1], ip[2], ip[3]];
    let ip = Ipv4Addr::new(ip);

    //　自身のMACアドレスを取得
    let mac = get_mac(interface_name)?;
    // MacAddrに変換
    let mac = MacAddr::new(mac.as_bytes());

    let target_ip = Ipv4Addr::new([8, 8, 8, 8]);
    // ARPパケットを作成
    let arp = create_arp_packet(mac, ip,target_ip)?;
    // ethernetフレームを作成
    let eth = EthernetFrame::new(MacAddr::zero(), MacAddr::broadcast(), EthType::ARP, arp.to_bytes());
    let bytes = eth.to_bytes();
    send(interface_name, bytes.as_slice())?;
    let arp_packet = receive_specific_packet(interface_name, EthType::ARP, ip)?; // ARPパケットを受信する
    let target_mac = arp_packet.sender_mac;

    // // ICMPパケットを作成
    // let icmp = create_icmp_packet()?;
    // let bytes = icmp.to_bytes();
    // UDPパケットを作成
    let destination_port = Port::new(33434);
    let source_port = Port::new(33434);
    let udp_packet = domain::entities::udp::UdpPacket::new(source_port, destination_port, vec![0; 32], ip, Ipv4Addr::new([8, 8, 8, 8]));
    let bytes = udp_packet.to_bytes();
    
    // ipv4パケットを作成
    let ipv4_header  = Ipv4Header::new(ip, Ipv4Addr::new([8, 8, 8, 8]), domain::enums::ip_type::Protocol::Udp);
    let ipv4_packet = Ipv4Packet::new(ipv4_header, bytes);
    let bytes = ipv4_packet.to_bytes();
    // ethernetフレームを作成
    let eth = EthernetFrame::new(mac, target_mac, EthType::IPv4, bytes);
    let bytes = eth.to_bytes();



    send(interface_name, bytes.as_slice())?;



    Ok(())
}

fn create_arp_packet(sender_mac: MacAddr,sender_ip:Ipv4Addr, target_ip: Ipv4Addr) -> anyhow::Result<Arp> {
    // Send an ARP request
    let arp = Arp::new(sender_mac, sender_ip, target_ip);

    Ok(arp)
}

fn create_icmp_packet() -> anyhow::Result<Icmp> {
    // Send an ICMP request
    let icmp = Icmp::new(EchoRequest, 0,  IcmpData::EchoRequest(domain::entities::icmp::EchoRequestPacket::new(0, 0, vec![0; 32])));

    Ok(icmp)
}

