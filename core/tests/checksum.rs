use reflex_core::checksum::{ip_checksum, tcp_checksum, udp_checksum};

#[test]
fn ip_checksum_rfc1071_example() {
    let data: [u8; 8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(ip_checksum(&data), 0x220d);
}

#[test]
fn ip_checksum_real_header() {
    let mut header = [
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02,
    ];
    let csum = ip_checksum(&header);
    header[10] = (csum >> 8) as u8;
    header[11] = (csum & 0xFF) as u8;
    assert_eq!(
        ip_checksum(&header),
        0x0000,
        "checksum of checksummed header must be 0"
    );
}

#[test]
fn ip_checksum_odd_length() {
    let data: [u8; 3] = [0x00, 0x01, 0x02];
    let result = ip_checksum(&data);
    assert_eq!(result, 0xfdfe);
}

#[test]
fn tcp_checksum_syn_packet() {
    let src_ip: [u8; 4] = [10, 0, 0, 1];
    let dst_ip: [u8; 4] = [10, 0, 0, 2];
    let tcp_segment: [u8; 20] = [
        0x01, 0xBB, 0x1F, 0x90, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x72,
        0x10, 0x00, 0x00, 0x00, 0x00,
    ];
    let csum = tcp_checksum(&src_ip, &dst_ip, &tcp_segment);
    let mut seg_with_csum = tcp_segment;
    seg_with_csum[16] = (csum >> 8) as u8;
    seg_with_csum[17] = (csum & 0xFF) as u8;
    assert_eq!(tcp_checksum(&src_ip, &dst_ip, &seg_with_csum), 0x0000);
}

#[test]
fn tcp_checksum_with_payload() {
    let src_ip: [u8; 4] = [1, 2, 3, 4];
    let dst_ip: [u8; 4] = [5, 6, 7, 8];
    let mut tcp_segment = vec![
        0x00, 0x50, 0x30, 0x39, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x72,
        0x10, 0x00, 0x00, 0x00, 0x00, 0xCA, 0xFE, 0xBA, 0xBE,
    ];
    let csum = tcp_checksum(&src_ip, &dst_ip, &tcp_segment);
    tcp_segment[16] = (csum >> 8) as u8;
    tcp_segment[17] = (csum & 0xFF) as u8;
    assert_eq!(tcp_checksum(&src_ip, &dst_ip, &tcp_segment), 0x0000);
}

#[test]
fn udp_checksum_basic() {
    let src_ip: [u8; 4] = [10, 0, 0, 1];
    let dst_ip: [u8; 4] = [10, 0, 0, 2];
    let mut udp_datagram: [u8; 10] = [0x00, 0x35, 0x04, 0xD2, 0x00, 0x0A, 0x00, 0x00, 0xDE, 0xAD];
    let csum = udp_checksum(&src_ip, &dst_ip, &udp_datagram);
    udp_datagram[6] = (csum >> 8) as u8;
    udp_datagram[7] = (csum & 0xFF) as u8;
    assert_eq!(udp_checksum(&src_ip, &dst_ip, &udp_datagram), 0x0000);
}
