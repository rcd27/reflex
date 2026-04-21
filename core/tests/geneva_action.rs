use reflex_core::geneva::{FragProtocol, GenevaAction, PacketField, TamperOp};

#[test]
fn duplicate_without_modify() {
    let action = GenevaAction::Duplicate { modify: None };
    match action {
        GenevaAction::Duplicate { modify: None } => {}
        _ => panic!("expected Duplicate without modify"),
    }
}

#[test]
fn duplicate_with_tamper() {
    let action = GenevaAction::Duplicate {
        modify: Some(Box::new(GenevaAction::Tamper {
            field: PacketField::IpTtl,
            op: TamperOp::Replace(vec![1]),
        })),
    };
    match action {
        GenevaAction::Duplicate {
            modify: Some(inner),
        } => match *inner {
            GenevaAction::Tamper {
                field: PacketField::IpTtl,
                op: TamperOp::Replace(ref val),
            } => assert_eq!(val, &[1]),
            _ => panic!("expected Tamper"),
        },
        _ => panic!("expected Duplicate with modify"),
    }
}

#[test]
fn fragment_tcp_in_order() {
    let action = GenevaAction::Fragment {
        protocol: FragProtocol::Tcp,
        offset: 8,
        in_order: true,
    };
    match action {
        GenevaAction::Fragment {
            protocol: FragProtocol::Tcp,
            offset: 8,
            in_order: true,
        } => {}
        _ => panic!("expected Fragment TCP in-order at 8"),
    }
}

#[test]
fn fragment_ip_disorder() {
    let action = GenevaAction::Fragment {
        protocol: FragProtocol::Ip,
        offset: 24,
        in_order: false,
    };
    match action {
        GenevaAction::Fragment {
            protocol: FragProtocol::Ip,
            offset: 24,
            in_order: false,
        } => {}
        _ => panic!("expected Fragment IP disorder at 24"),
    }
}

#[test]
fn tamper_corrupt() {
    let action = GenevaAction::Tamper {
        field: PacketField::TcpChecksum,
        op: TamperOp::Corrupt,
    };
    match action {
        GenevaAction::Tamper {
            field: PacketField::TcpChecksum,
            op: TamperOp::Corrupt,
        } => {}
        _ => panic!("expected Tamper Corrupt TcpChecksum"),
    }
}

#[test]
fn drop_action() {
    let action = GenevaAction::Drop;
    match action {
        GenevaAction::Drop => {}
        _ => panic!("expected Drop"),
    }
}

#[test]
fn all_packet_fields_exhaustive() {
    let fields = [
        PacketField::TcpFlags,
        PacketField::IpTtl,
        PacketField::TcpChecksum,
        PacketField::TcpSeq,
        PacketField::TcpAck,
        PacketField::TcpWindow,
        PacketField::TcpOptions,
    ];
    assert_eq!(fields.len(), 7);
}
