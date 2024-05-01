use crate::domain::entities::arp::Arp;
use crate::domain::entities::ethernet_frame::EthernetFrame;
use crate::domain::enums::eth_type::EthType;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::domain::value_objects::mac_address::MacAddr;
use crate::infrastructure::network::datalink_operations::{receive_specific_packet, send};
use crate::infrastructure::serialization::packet_serializer::Serialize;
use crate::interfaces::cli::util::get_ip;

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
    

    // Send an ARP request
    let arp = Arp::new(MacAddr::zero(), ip,Ipv4Addr::new([192, 168, 101, 1]));
    let eth = EthernetFrame::new(MacAddr::zero(), MacAddr::broadcast(), EthType::ARP, arp.to_bytes());
    let bytes = eth.to_bytes();
    let slice = &bytes[..];

    send(interface_name, slice)?;

    receive_specific_packet(interface_name, pnet::packet::ethernet::EtherTypes::Arp)?; // ARPパケットを受信する

    Ok(())
}

