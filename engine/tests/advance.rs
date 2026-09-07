use reflex_engine::meter::Tally;
use reflex_engine::{
    advance, About, Act, Addr, Cursor, Dir, FlowKey, Noted, Noticed, Packet, Sighting, Stepped,
    Tick,
};

fn empty_tally() -> Tally {
    Tally {
        up_bytes: 0,
        down_bytes: 0,
        packets: 0,
        flows_opened: 0,
        flows_lost: 0,
        since: Tick(0),
    }
}

fn packet(payload: &[u8]) -> Packet<'_> {
    Packet {
        flow: FlowKey(1),
        dst: Addr(0x0A000001),
        dir: Dir::Down,
        opens: false,
        closes: false,
        resets: false,
        payload,
        says: reflex_engine::row::Naming::Awaited,
    }
}

fn counting(tally: Tally, packet: &Packet<'_>, _now: Tick) -> Tally {
    Tally {
        down_bytes: tally.down_bytes + packet.payload.len() as u64,
        packets: tally.packets + 1,
        ..tally
    }
}

#[test]
fn tally_advances_even_when_the_step_lost_the_flow() {
    let losing = |_cursor: Cursor, _packet: &Packet<'_>, _now: Tick| Stepped {
        act: Act::Pass,
        cursor: Cursor::Lost,
        sighting: None,
    };

    let advanced = advance(
        losing,
        counting,
        Cursor::Fresh,
        empty_tally(),
        packet(&[0u8; 700]),
        Tick(1),
    );

    assert_eq!(advanced.cursor, Cursor::Lost);
    assert_eq!(advanced.tally.packets, 1);
    assert_eq!(advanced.tally.down_bytes, 700);
}

#[test]
fn tally_advances_even_when_the_packet_is_dropped() {
    let dropping = |_cursor: Cursor, _packet: &Packet<'_>, _now: Tick| Stepped {
        act: Act::Drop,
        cursor: Cursor::Fresh,
        sighting: None,
    };

    let advanced = advance(
        dropping,
        counting,
        Cursor::Fresh,
        empty_tally(),
        packet(&[0u8; 300]),
        Tick(1),
    );

    assert_eq!(advanced.act, Act::Drop);
    assert_eq!(advanced.tally.packets, 1);
    assert_eq!(advanced.tally.down_bytes, 300);
}

/// СЧЁТ ИДЁТ И ТОГДА, КОГДА РАЗГОВОР КОНЧАЕТСЯ НАШИМ РЕШЕНИЕМ.
///
/// Прежде предметом был отвод к исполнителю; отвод снят вместе с исполнителем (#326), и роль
/// терминирующего акта играет обрыв — свойство то же: байты этого пакета сосчитаны, даже если
/// дальше разговора не будет.
#[test]
fn tally_advances_even_when_the_flow_is_severed() {
    let severing = |_cursor: Cursor, _packet: &Packet<'_>, _now: Tick| Stepped {
        act: Act::Sever,
        cursor: Cursor::Fresh,
        sighting: None,
    };

    let advanced = advance(
        severing,
        counting,
        Cursor::Fresh,
        empty_tally(),
        packet(&[0u8; 1200]),
        Tick(1),
    );

    assert_eq!(advanced.act, Act::Sever);
    assert_eq!(advanced.tally.down_bytes, 1200);
}

#[test]
fn advance_forwards_the_steps_verdict_without_inventing_anything() {
    let sighted = |_cursor: Cursor, packet: &Packet<'_>, now: Tick| Stepped {
        act: Act::Pass,
        cursor: Cursor::Fresh,
        sighting: Some(Noted {
            at: now,
            about: About::Talk(packet.flow),
            target: reflex_engine::row::Naming::Spoken(()),
            // НАБЛЮДЕНИЕ РАЗГОВОРА — под буквой разговора: пара «адресат ↔ слово» больше не
            // собирается вразнобой.
            what: Noticed::Talk(Sighting::Severed {
                dst: Addr(0x0A000001),
            }),
        }),
    };

    let advanced = advance(
        sighted,
        |tally, _packet, _now| tally,
        Cursor::Fresh,
        empty_tally(),
        packet(&[]),
        Tick(1),
    );

    assert_eq!(
        advanced.sighting.map(|noted| noted.what),
        Some(Noticed::Talk(Sighting::Severed {
            dst: Addr(0x0A000001)
        }))
    );
    // АДРЕСАТ И МОМЕНТ ДОЕЗЖАЮТ ЦЕЛИКОМ. Без этой половины `advance` мог бы пересобирать
    // наблюдение по дороге, теряя то, что шаг о нём знал, — а имя проверки обещает обратное.
    assert_eq!(
        advanced.sighting.map(|noted| (noted.about, noted.at)),
        Some((About::Talk(FlowKey(1)), Tick(1))),
        "наблюдение доехало без адресата либо без момента"
    );
    assert_eq!(advanced.tally, empty_tally());
}
