/// Build a minimal TLS 1.2 ClientHello with SNI extension.
pub fn build_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();
    let sni_list_len = 1 + 2 + sni_bytes.len();
    let sni_ext_data_len = 2 + sni_list_len;
    let extensions_len = 2 + 2 + sni_ext_data_len;
    let ch_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions_len;
    let handshake_len = 1 + 3 + ch_body_len;
    let record_len = handshake_len;

    let mut pkt = Vec::with_capacity(5 + record_len);
    pkt.push(0x16);
    pkt.extend_from_slice(&[0x03, 0x01]);
    pkt.extend_from_slice(&(record_len as u16).to_be_bytes());
    pkt.push(0x01);
    let body_len = ch_body_len as u32;
    pkt.push((body_len >> 16) as u8);
    pkt.push((body_len >> 8) as u8);
    pkt.push(body_len as u8);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0xAA; 32]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x02]);
    pkt.extend_from_slice(&[0x00, 0x2F]);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    pkt.extend_from_slice(sni_bytes);
    pkt
}
