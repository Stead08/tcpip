use anyhow::anyhow;
use crate::domain::entities::arp::Arp;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;
use crate::domain::entities::ethernet_frame::EthernetFrame;
use crate::domain::entities::ip::Ipv4Packet;
use crate::domain::enums::eth_type::EthType;
use crate::domain::value_objects::ipv4_address::Ipv4Addr;
use crate::infrastructure::serialization::packet_serializer::{Deserialize, Serialize};

pub fn get_interface(interface_name: &str) -> anyhow::Result<datalink::NetworkInterface> {
    let Some(interface) = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
    else {
        eprintln!("Interface {} not found", interface_name);
        std::process::exit(1);
    };
    Ok(interface)
}

pub fn receive(interface_name: &str) -> anyhow::Result<()> {
    let interface = get_interface(interface_name)?;

    // イーサネットフレームを受信するためのチャンネルを開く
    if let Ethernet(_, mut rx) = datalink::channel(&interface, Default::default())? {
        // ここでチャンネルを使ってパケットの送受信を行う
        loop {
            // パケットを受信
            let packet = rx.next()?;
            // パケットを処理する
            println!("{:?}", packet);
        }
    }
    Ok(())
}



pub fn receive_specific_packet(interface_name: &str, ether_type: EthType, source_ip: Ipv4Addr) -> anyhow::Result<Arp> {
    let interface = get_interface(interface_name)?;

    // イーサネットフレームを受信するためのチャンネルを開く
    if let Ethernet(_, mut rx) = datalink::channel(&interface, Default::default())? {
        // ここでチャンネルを使ってパケットの送受信を行う
        loop {
            // パケットを受信
            let packet = rx.next()?;

            // パケットの参照をEthernetFrameに変換
            let eth_frame_ref = EthernetFrame::from_bytes(&packet);

            // イーサネットタイプが一致する場合のみ処理
            if eth_frame_ref.get_ethertype() == ether_type {
                match ether_type {
                    EthType::ARP => {
                        let arp = Arp::from_bytes(&eth_frame_ref.payload).expect("Failed to parse ARP packet");
                        let arp = arp.1;
                        if arp.target_ip == source_ip {
                            println!("{:?}", arp);
                            return Ok(arp);
                        }
                    }
                    _ => {
                        println!("Unsupported ether type");
                        return Err(anyhow!("{:?}",eth_frame_ref.payload.to_vec()));
                    }
                }
            }
        }

    } else {
        eprintln!("Failed to open channel");
        std::process::exit(1);
    }
}

pub fn send(interface_name: &str, packet: &[u8]) -> anyhow::Result<()> {
    let interface = get_interface(interface_name)?;

    // イーサネットフレームを送信するためのチャンネルを開く
    if let Ethernet(mut tx, _) = datalink::channel(&interface, Default::default())? {
        // ここでチャンネルを使ってパケットの送受信を行う
        tx.send_to(packet, None).expect("Failed to send a packet").expect("Failed to send a packet");
        println!("{:x?}", packet);
        println!("Sent a packet");
    }
    Ok(())
}

