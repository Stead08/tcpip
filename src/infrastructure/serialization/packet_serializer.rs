pub fn add_to_buffer<T: AsRef<[u8]>>(buffer: &mut Vec<u8>, item: T) {
    buffer.extend(item.as_ref());
}
