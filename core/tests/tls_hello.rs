#![cfg(feature = "tls")]

use reflex_core::tls::build_client_hello;

#[test]
fn client_hello_is_valid_tls_record() {
    let ch = build_client_hello("example.com");
    assert_eq!(ch[0], 0x16, "content type must be Handshake");
    assert_eq!(ch[1], 0x03, "major version");
    assert_eq!(ch[5], 0x01, "handshake type must be ClientHello");
    assert!(
        ch.windows(b"example.com".len())
            .any(|w| w == b"example.com"),
        "SNI must contain domain"
    );
}

#[test]
fn client_hello_different_domains_differ() {
    let ch1 = build_client_hello("foo.com");
    let ch2 = build_client_hello("bar.org");
    assert_ne!(ch1, ch2);
    assert!(ch1.windows(b"foo.com".len()).any(|w| w == b"foo.com"));
    assert!(ch2.windows(b"bar.org".len()).any(|w| w == b"bar.org"));
}
