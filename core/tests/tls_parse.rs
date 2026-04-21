#![cfg(feature = "tls")]

use reflex_core::tls::{TlsContentType, TlsFragment, TlsRecord};

#[test]
fn parse_tls_client_hello_with_sni() {
    let domain = b"example.com";
    let sni_ext_data_len = 2 + 1 + 2 + domain.len();
    let extensions_len = 2 + 2 + sni_ext_data_len;

    let mut hello_payload = Vec::new();
    hello_payload.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    hello_payload.extend_from_slice(&[0x00; 32]); // random
    hello_payload.push(0x00); // session_id len
    hello_payload.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // cipher suites
    hello_payload.extend_from_slice(&[0x01, 0x00]); // compression
    hello_payload.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    // SNI extension
    hello_payload.extend_from_slice(&[0x00, 0x00]); // type
    hello_payload.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    hello_payload.extend_from_slice(&((sni_ext_data_len - 2) as u16).to_be_bytes());
    hello_payload.push(0x00); // name_type
    hello_payload.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    hello_payload.extend_from_slice(domain);

    let hello_len = hello_payload.len();
    let mut handshake = vec![0x01]; // ClientHello
    handshake.push(0x00);
    handshake.extend_from_slice(&(hello_len as u16).to_be_bytes());
    handshake.extend_from_slice(&hello_payload);

    let hs_len = handshake.len();
    let mut record = vec![0x16]; // handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let parsed = TlsRecord::parse(&record).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::Handshake);
    match &parsed.fragment {
        TlsFragment::ClientHello { sni } => {
            assert_eq!(sni.as_deref(), Some("example.com"));
        }
        other => panic!("expected ClientHello, got {:?}", other),
    }
}

#[test]
fn parse_tls_non_handshake() {
    let record = vec![0x17, 0x03, 0x03, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
    let parsed = TlsRecord::parse(&record).unwrap();
    assert_eq!(parsed.content_type, TlsContentType::ApplicationData);
    match parsed.fragment {
        TlsFragment::Other => {}
        other => panic!("expected Other, got {:?}", other),
    }
}

#[test]
fn parse_tls_too_short() {
    let record = vec![0x16, 0x03];
    assert!(TlsRecord::parse(&record).is_none());
}
