use std::net::IpAddr;
use pnet::datalink;

pub fn get_ip(interface_name: &str) -> anyhow::Result<IpAddr> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;
    let ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("IP address not found"))?;
    Ok(ip.ip())
}

pub fn get_mac(interface_name: &str) -> anyhow::Result<[u8; 6]> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;
    let mac = interface.mac.ok_or_else(|| anyhow::anyhow!("MAC address not found"))?;
    Ok(mac.octets())
}