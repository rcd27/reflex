use crate::builder::TcpBuilder;
use crate::command::{Command, InjectablePacket};
use crate::geneva::action::{GenevaAction, PacketField, TamperOp};
use crate::geneva::strategy::{GenevaStrategy, StrategyNode};
use crate::types::{Mac, TcpFlags, TcpSegment};

fn is_tls_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

pub fn execute(
    strategy: &GenevaStrategy,
    packet: &TcpSegment,
    src_mac: &Mac,
    dst_mac: &Mac,
) -> Vec<Command> {
    let has_hello = is_tls_client_hello(&packet.payload);
    if !strategy
        .trigger
        .matches(packet.flow.protocol, packet.flags, has_hello)
    {
        return Vec::new();
    }
    let mut commands = Vec::new();
    execute_node(&strategy.tree, packet, src_mac, dst_mac, &mut commands);
    commands
}

fn execute_node(
    node: &StrategyNode,
    packet: &TcpSegment,
    src_mac: &Mac,
    dst_mac: &Mac,
    commands: &mut Vec<Command>,
) {
    match node {
        StrategyNode::Send => {
            commands.push(Command::Accept(packet.flow.clone()));
        }
        StrategyNode::Action { action, then } => {
            execute_action(action, packet, src_mac, dst_mac, then, commands);
        }
    }
}

fn execute_action(
    action: &GenevaAction,
    packet: &TcpSegment,
    src_mac: &Mac,
    dst_mac: &Mac,
    then: &[StrategyNode],
    commands: &mut Vec<Command>,
) {
    match action {
        GenevaAction::Drop => {
            commands.push(Command::DropFlow(packet.flow.clone()));
        }
        GenevaAction::Duplicate { modify } => {
            let mut copy = packet.clone();
            if let Some(tamper) = modify {
                apply_tamper_to_segment(&mut copy, tamper);
            }
            let built = build_tcp_packet(&copy, src_mac, dst_mac);
            commands.push(Command::Inject(InjectablePacket::Tcp(built)));
            if then.len() > 1 {
                execute_node(&then[1], packet, src_mac, dst_mac, commands);
            }
        }
        GenevaAction::Tamper { field, op } => {
            let mut modified = packet.clone();
            apply_tamper(field, op, &mut modified);
            let built = build_tcp_packet(&modified, src_mac, dst_mac);
            commands.push(Command::Inject(InjectablePacket::Tcp(built)));
        }
        GenevaAction::Fragment {
            protocol: _,
            offset,
            in_order,
        } => {
            let (first, second) = split_payload(packet, *offset);
            let built_first = build_tcp_packet(&first, src_mac, dst_mac);
            let built_second = build_tcp_packet(&second, src_mac, dst_mac);
            if *in_order {
                commands.push(Command::Inject(InjectablePacket::Tcp(built_first)));
                commands.push(Command::Inject(InjectablePacket::Tcp(built_second)));
            } else {
                commands.push(Command::Inject(InjectablePacket::Tcp(built_second)));
                commands.push(Command::Inject(InjectablePacket::Tcp(built_first)));
            }
            commands.push(Command::DropFlow(packet.flow.clone()));
        }
    }
}

fn apply_tamper_to_segment(segment: &mut TcpSegment, action: &GenevaAction) {
    if let GenevaAction::Tamper { field, op } = action {
        apply_tamper(field, op, segment);
    }
}

fn apply_tamper(field: &PacketField, op: &TamperOp, segment: &mut TcpSegment) {
    match (field, op) {
        (PacketField::IpTtl, TamperOp::Replace(val)) => {
            if let Some(&ttl) = val.first() {
                segment.ttl = ttl;
            }
        }
        (PacketField::IpTtl, TamperOp::Corrupt) => {
            segment.ttl = 1;
        }
        (PacketField::TcpFlags, TamperOp::Replace(val)) => {
            if let Some(&flags) = val.first() {
                segment.flags = TcpFlags::from_bits_truncate(flags);
            }
        }
        (PacketField::TcpFlags, TamperOp::Corrupt) => {
            segment.flags = TcpFlags::empty();
        }
        (PacketField::TcpSeq, TamperOp::Replace(val)) => {
            if val.len() >= 4 {
                segment.seq = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            }
        }
        (PacketField::TcpSeq, TamperOp::Corrupt) => {
            segment.seq = segment.seq.wrapping_add(99999);
        }
        (PacketField::TcpAck, TamperOp::Replace(val)) => {
            if val.len() >= 4 {
                segment.ack = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            }
        }
        (PacketField::TcpAck, TamperOp::Corrupt) => {
            segment.ack = segment.ack.wrapping_add(99999);
        }
        (PacketField::TcpWindow, TamperOp::Replace(val)) => {
            if val.len() >= 2 {
                segment.window = u16::from_be_bytes([val[0], val[1]]);
            }
        }
        (PacketField::TcpWindow, TamperOp::Corrupt) => {
            segment.window = 0;
        }
        (PacketField::TcpChecksum, _) => { /* checksum recomputed by builder */ }
        (PacketField::TcpOptions, _) => {
            segment.options = Default::default();
        }
    }
}

fn build_tcp_packet(
    segment: &TcpSegment,
    src_mac: &Mac,
    dst_mac: &Mac,
) -> crate::builder::BuiltTcpPacket {
    TcpBuilder::new()
        .flow(&segment.flow)
        .seq(segment.seq)
        .ack(segment.ack)
        .flags(segment.flags)
        .ttl(segment.ttl)
        .window(segment.window)
        .payload(&segment.payload)
        .src_mac(*src_mac)
        .dst_mac(*dst_mac)
        .build()
}

fn split_payload(packet: &TcpSegment, offset: usize) -> (TcpSegment, TcpSegment) {
    let split_at = offset.min(packet.payload.len());
    let mut first = packet.clone();
    first.payload = packet.payload[..split_at].to_vec();
    let mut second = packet.clone();
    second.payload = packet.payload[split_at..].to_vec();
    second.seq = packet.seq.wrapping_add(split_at as u32);
    (first, second)
}
