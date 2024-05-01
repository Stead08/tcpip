pub fn add_to_buffer<T: AsRef<[u8]>>(buffer: &mut Vec<u8>, item: T) {
    buffer.extend(item.as_ref());
}

pub trait Serialize {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Deserialize {
    fn from_bytes(bytes: &[u8]) -> Self;
}