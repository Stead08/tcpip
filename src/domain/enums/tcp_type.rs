pub enum ControlFlag {
    NS,
    CWR,
    ECE,
    URG,
    ACK,
    PSH,
    RST,
    SYN,
    FIN,
}

impl ControlFlag {
    pub fn from_u8(flag: u8) -> Option<ControlFlag> {
        match flag {
            0 => Some(ControlFlag::NS),
            1 => Some(ControlFlag::CWR),
            2 => Some(ControlFlag::ECE),
            3 => Some(ControlFlag::URG),
            4 => Some(ControlFlag::ACK),
            5 => Some(ControlFlag::PSH),
            6 => Some(ControlFlag::RST),
            7 => Some(ControlFlag::SYN),
            8 => Some(ControlFlag::FIN),
            _ => None,
        }
    }
}
