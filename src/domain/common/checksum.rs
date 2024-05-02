pub fn calculate_checksum(buf: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut buffer = buf.to_vec();

    // 奇数長のバッファの場合はパディングを追加
    if buffer.len() % 2 != 0 {
        buffer.push(0);
    }

    let mut i = 0;
    while i < buffer.len() {
        // バッファの境界を超えないように安全にバイトを取得
        let word = if i + 1 < buffer.len() {
            u16::from_be_bytes([buffer[i], buffer[i + 1]])
        } else {
            u16::from_be_bytes([buffer[i], 0])
        };

        sum += word as u32;
        i += 2;
    }

    // オーバーフローを処理
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // チェックサムを取得（1の補数）
    !(sum as u16)
}
