use reflex_core::types::TcpFlags;

// --- Display implementation ---

#[test]
fn display_syn() {
    assert_eq!(format!("{}", TcpFlags::SYN), "S");
}

#[test]
fn display_ack() {
    assert_eq!(format!("{}", TcpFlags::ACK), "A");
}

#[test]
fn display_syn_ack() {
    let flags = TcpFlags::SYN | TcpFlags::ACK;
    assert_eq!(format!("{}", flags), "SA");
}

#[test]
fn display_psh_ack() {
    let flags = TcpFlags::PSH | TcpFlags::ACK;
    assert_eq!(format!("{}", flags), "AP");
}

#[test]
fn display_fin() {
    assert_eq!(format!("{}", TcpFlags::FIN), "F");
}

#[test]
fn display_rst() {
    assert_eq!(format!("{}", TcpFlags::RST), "R");
}

#[test]
fn display_urg() {
    assert_eq!(format!("{}", TcpFlags::URG), "U");
}

#[test]
fn display_all_flags() {
    let all = TcpFlags::SYN
        | TcpFlags::ACK
        | TcpFlags::PSH
        | TcpFlags::FIN
        | TcpFlags::RST
        | TcpFlags::URG;
    assert_eq!(format!("{}", all), "SAPFRU");
}

#[test]
fn display_empty_flags() {
    let empty = TcpFlags::empty();
    assert_eq!(format!("{}", empty), "none");
}

#[test]
fn display_fin_ack() {
    let flags = TcpFlags::FIN | TcpFlags::ACK;
    assert_eq!(format!("{}", flags), "AF");
}

// --- Flag methods ---

#[test]
fn is_syn_pure_syn() {
    assert!(TcpFlags::SYN.is_syn());
}

#[test]
fn is_syn_false_for_syn_ack() {
    let flags = TcpFlags::SYN | TcpFlags::ACK;
    assert!(!flags.is_syn());
}

#[test]
fn is_syn_ack_true() {
    let flags = TcpFlags::SYN | TcpFlags::ACK;
    assert!(flags.is_syn_ack());
}

#[test]
fn is_syn_ack_false_for_pure_syn() {
    assert!(!TcpFlags::SYN.is_syn_ack());
}

#[test]
fn is_rst_true() {
    assert!(TcpFlags::RST.is_rst());
}

#[test]
fn is_rst_false_for_ack() {
    assert!(!TcpFlags::ACK.is_rst());
}

#[test]
fn is_fin_true() {
    assert!(TcpFlags::FIN.is_fin());
}

#[test]
fn is_fin_false_for_syn() {
    assert!(!TcpFlags::SYN.is_fin());
}

#[test]
fn is_psh_ack_true() {
    let flags = TcpFlags::PSH | TcpFlags::ACK;
    assert!(flags.is_psh_ack());
}

#[test]
fn is_psh_ack_false_for_pure_psh() {
    assert!(!TcpFlags::PSH.is_psh_ack());
}

// --- Bitflag operations ---

#[test]
fn from_bits_truncate_known() {
    let flags = TcpFlags::from_bits_truncate(0x02);
    assert_eq!(flags, TcpFlags::SYN);
}

#[test]
fn from_bits_truncate_combined() {
    let flags = TcpFlags::from_bits_truncate(0x12); // SYN | ACK
    assert_eq!(flags, TcpFlags::SYN | TcpFlags::ACK);
}

#[test]
fn from_bits_truncate_unknown_bits_stripped() {
    let flags = TcpFlags::from_bits_truncate(0xFF);
    assert!(flags.contains(TcpFlags::SYN));
    assert!(flags.contains(TcpFlags::ACK));
    assert!(flags.contains(TcpFlags::FIN));
    assert!(flags.contains(TcpFlags::RST));
    assert!(flags.contains(TcpFlags::PSH));
    assert!(flags.contains(TcpFlags::URG));
}

#[test]
fn from_bits_exact() {
    let flags = TcpFlags::from_bits(0x12);
    assert_eq!(flags, Some(TcpFlags::SYN | TcpFlags::ACK));
}

#[test]
fn from_bits_invalid_returns_none() {
    // 0x80 is not a defined flag
    let flags = TcpFlags::from_bits(0x80);
    assert!(flags.is_none());
}

#[test]
fn bitwise_or_combines_flags() {
    let flags = TcpFlags::SYN | TcpFlags::FIN;
    assert!(flags.contains(TcpFlags::SYN));
    assert!(flags.contains(TcpFlags::FIN));
    assert!(!flags.contains(TcpFlags::ACK));
}

#[test]
fn bitwise_and_intersects_flags() {
    let a = TcpFlags::SYN | TcpFlags::ACK;
    let b = TcpFlags::ACK | TcpFlags::PSH;
    let intersection = a & b;
    assert_eq!(intersection, TcpFlags::ACK);
}

#[test]
fn is_empty_true_for_no_flags() {
    assert!(TcpFlags::empty().is_empty());
}

#[test]
fn is_empty_false_for_syn() {
    assert!(!TcpFlags::SYN.is_empty());
}

#[test]
fn bits_roundtrip() {
    let original = TcpFlags::SYN | TcpFlags::ACK | TcpFlags::PSH;
    let bits = original.bits();
    let reconstructed = TcpFlags::from_bits(bits).unwrap();
    assert_eq!(original, reconstructed);
}

// --- rst with ack ---

#[test]
fn is_rst_true_even_with_ack() {
    let flags = TcpFlags::RST | TcpFlags::ACK;
    assert!(flags.is_rst());
}

#[test]
fn is_fin_true_even_with_ack() {
    let flags = TcpFlags::FIN | TcpFlags::ACK;
    assert!(flags.is_fin());
}
