pub fn calculate_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let buffer = buf.to_vec();

    for i in (0..buffer.len()).step_by(2) {
        sum += u16::from_be_bytes([buffer[i], buffer[i + 1]]) as u32;
    }

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}