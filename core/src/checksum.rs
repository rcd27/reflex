fn ones_complement_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

/// RFC 1071 internet checksum — one's complement of the one's complement sum.
pub fn ip_checksum(header: &[u8]) -> u16 {
    !(ones_complement_sum(header) as u16)
}

/// TCP checksum over pseudo-header + TCP segment.
pub fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    !(ones_complement_sum(&pseudo) as u16)
}

/// UDP checksum over pseudo-header + UDP datagram.
pub fn udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_datagram: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_datagram.len());
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_datagram.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_datagram);
    !(ones_complement_sum(&pseudo) as u16)
}
