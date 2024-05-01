use crate::domain::entities::arp::Arp;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EtherType;
use pnet::packet::Packet;
use crate::domain::entities::ethernet_frame::EthernetFrame;
use crate::domain::enums::eth_type::EthType;
use crate::infrastructure::serialization::packet_serializer::Deserialize;

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



pub fn receive_specific_packet(interface_name: &str, _ether_type: EtherType) -> anyhow::Result<()> {
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
            if eth_frame_ref.get_ethertype() == EthType::ARP {
                // パケットをEthernetFrameに変換
                let eth_frame = EthernetFrame::from_bytes(packet);
                let eth_payload = eth_frame.payload;
                let arp = Arp::from_bytes(&eth_payload).expect("Failed to parse ARP packet");
                let arp = arp.1;
                // 16進数で表示
                println!("{:?}", arp);
                break;
            }
        }
    }
    Ok(())
}
pub fn send(interface_name: &str, packet: &[u8]) -> anyhow::Result<()> {
    let interface = get_interface(interface_name)?;

    // イーサネットフレームを送信するためのチャンネルを開く
    if let Ethernet(mut tx, _) = datalink::channel(&interface, Default::default())? {
        // ここでチャンネルを使ってパケットの送受信を行う
        tx.send_to(packet, None);
        println!("{:?}", packet);
        println!("Sent a packet");
    }
    Ok(())
}
