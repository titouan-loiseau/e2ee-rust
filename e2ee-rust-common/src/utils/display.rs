pub fn print_slice(slice: &[u8]) -> String {
    let mut s = String::new();
    s.push_str("0x");
    for byte in slice {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
