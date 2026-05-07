use reflex_core::types::{TcpOptions, TcpTimestamps};

#[test]
fn parse_empty_options() {
    let opts = TcpOptions::parse(&[]);
    assert_eq!(opts, TcpOptions::default());
    assert!(opts.mss.is_none());
    assert!(opts.window_scale.is_none());
    assert!(opts.timestamps.is_none());
}

#[test]
fn parse_end_of_options_marker() {
    // Kind 0 = End of Options List
    let data = [0x00, 0x02, 0x04, 0x05, 0xB4];
    let opts = TcpOptions::parse(&data);
    // Should stop at kind=0, never see MSS
    assert!(opts.mss.is_none());
}

#[test]
fn parse_nop_padding() {
    // Kind 1 = NOP (padding), then MSS option
    let data = [0x01, 0x01, 0x02, 0x04, 0x05, 0xB4];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(1460));
}

#[test]
fn parse_mss_option() {
    // Kind=2, Len=4, Value=1460 (0x05B4)
    let data = [0x02, 0x04, 0x05, 0xB4];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(1460));
}

#[test]
fn parse_mss_max_value() {
    // Kind=2, Len=4, Value=65535 (0xFFFF)
    let data = [0x02, 0x04, 0xFF, 0xFF];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(65535));
}

#[test]
fn parse_window_scale_option() {
    // Kind=3, Len=3, Value=7
    let data = [0x03, 0x03, 0x07];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.window_scale, Some(7));
}

#[test]
fn parse_timestamps_option() {
    // Kind=8, Len=10, TSval=0x01020304, TSecr=0x05060708
    let data = [0x08, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let opts = TcpOptions::parse(&data);
    assert_eq!(
        opts.timestamps,
        Some(TcpTimestamps {
            ts_val: 0x01020304,
            ts_ecr: 0x05060708,
        })
    );
}

#[test]
fn parse_multiple_options_in_sequence() {
    // MSS + NOP + Window Scale + NOP + NOP + Timestamps
    let data = [
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
        0x01, // NOP
        0x03, 0x03, 0x07, // Window Scale = 7
        0x01, // NOP
        0x01, // NOP
        0x08, 0x0A, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, // Timestamps
    ];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(1460));
    assert_eq!(opts.window_scale, Some(7));
    assert_eq!(
        opts.timestamps,
        Some(TcpTimestamps {
            ts_val: 0xAABBCCDD,
            ts_ecr: 0x11223344,
        })
    );
}

#[test]
fn parse_sack_permitted_is_ignored_gracefully() {
    // Kind=4 (SACK Permitted), Len=2 — not stored but should not break parsing
    // followed by MSS
    let data = [
        0x04, 0x02, // SACK Permitted
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
    ];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(1460));
}

#[test]
fn parse_malformed_length_zero() {
    // Kind=2, Len=0 — invalid (len < 2), should break
    let data = [0x02, 0x00, 0x05, 0xB4];
    let opts = TcpOptions::parse(&data);
    assert!(opts.mss.is_none());
}

#[test]
fn parse_malformed_length_one() {
    // Kind=2, Len=1 — invalid (len < 2), should break
    let data = [0x02, 0x01];
    let opts = TcpOptions::parse(&data);
    assert!(opts.mss.is_none());
}

#[test]
fn parse_malformed_length_exceeds_data() {
    // Kind=2, Len=4, but only 3 bytes total — should break
    let data = [0x02, 0x04, 0x05];
    let opts = TcpOptions::parse(&data);
    assert!(opts.mss.is_none());
}

#[test]
fn parse_truncated_after_kind() {
    // Only the kind byte, no length byte
    let data = [0x02];
    let opts = TcpOptions::parse(&data);
    assert!(opts.mss.is_none());
}

#[test]
fn parse_mss_wrong_length_ignored() {
    // Kind=2, Len=3 (wrong, should be 4) — MSS not parsed
    let data = [0x02, 0x03, 0x05];
    let opts = TcpOptions::parse(&data);
    assert!(opts.mss.is_none());
}

#[test]
fn parse_window_scale_wrong_length_ignored() {
    // Kind=3, Len=4 (wrong, should be 3) — window_scale not parsed
    let data = [0x03, 0x04, 0x07, 0x00];
    let opts = TcpOptions::parse(&data);
    assert!(opts.window_scale.is_none());
}

#[test]
fn parse_timestamps_wrong_length_ignored() {
    // Kind=8, Len=8 (wrong, should be 10) — timestamps not parsed
    let data = [0x08, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let opts = TcpOptions::parse(&data);
    assert!(opts.timestamps.is_none());
}

#[test]
fn parse_unknown_option_skipped() {
    // Kind=42 (unknown), Len=4, then MSS
    let data = [
        0x2A, 0x04, 0xFF, 0xFF, // Unknown kind=42, len=4
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
    ];
    let opts = TcpOptions::parse(&data);
    assert_eq!(opts.mss, Some(1460));
}

#[test]
fn default_has_no_options() {
    let opts = TcpOptions::default();
    assert!(opts.mss.is_none());
    assert!(opts.window_scale.is_none());
    assert!(opts.timestamps.is_none());
}
