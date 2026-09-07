use reflex_engine::meter::{
    bucket_span, charged_target, expired, fresh_target, horizon, slower_than, target_pace, Charged,
    Pace, Target, BUCKET_SHIFT,
};
use reflex_engine::{Addr, Dir, FlowKey, Packet, Tick};

fn at(bucket: u64) -> Tick {
    Tick(bucket << BUCKET_SHIFT)
}

fn down(bytes: usize) -> Vec<u8> {
    vec![0u8; bytes]
}

fn feed(target: Target, bucket: u64, bytes: usize) -> Charged {
    let payload = down(bytes);
    let packet = Packet {
        flow: FlowKey(1),
        dst: Addr(1),
        dir: Dir::Down,
        opens: false,
        closes: false,
        resets: false,
        payload_len: payload.len(),
        says: reflex_engine::row::Naming::Awaited,
    };
    charged_target(target, &packet, at(bucket))
}

#[test]
fn best_is_learned_while_the_flow_is_still_running_not_when_it_closes() {
    let started = fresh_target(at(0));
    let loaded = feed(started, 0, 5000).target;
    let rolled = feed(loaded, 1, 1);

    assert_eq!(rolled.target.best.bytes, 5000);
    assert!(rolled.peaked);
}

#[test]
fn best_survives_a_later_slower_bucket() {
    let started = fresh_target(at(0));
    let loaded = feed(started, 0, 5000).target;
    let rolled = feed(loaded, 1, 10).target;
    let quiet = feed(rolled, 2, 10);

    assert_eq!(quiet.target.best.bytes, 5000);
    assert!(!quiet.peaked);
}

#[test]
fn a_target_that_went_silent_reports_no_pace_instead_of_its_last_one() {
    let started = fresh_target(at(0));
    let loaded = feed(started, 0, 5000).target;
    let rolled = feed(loaded, 1, 1).target;

    assert_eq!(target_pace(&rolled, at(1)).bytes, 5000);
    assert_eq!(target_pace(&rolled, at(2)).bytes, 1);
    assert_eq!(target_pace(&rolled, at(9)).bytes, 0);
}

#[test]
fn a_throttled_target_is_slower_than_its_own_best_and_both_use_one_window() {
    let started = fresh_target(at(0));
    let fast = feed(started, 0, 6000).target;
    let settled = feed(fast, 1, 500).target;
    let now = feed(settled, 2, 500).target;

    assert_eq!(now.best.over_nanos, bucket_span().0);
    assert_eq!(target_pace(&now, at(2)).over_nanos, bucket_span().0);
    assert!(slower_than(target_pace(&now, at(2)), now.best, 4));
}

#[test]
fn nothing_is_expired_inside_the_horizon_and_everything_is_outside_it() {
    assert!(!expired(Tick(0), Tick(horizon().0)));
    assert!(expired(Tick(0), Tick(horizon().0 + 1)));
}

#[test]
fn a_pace_of_zero_bytes_is_never_reported_as_faster_than_a_real_one() {
    let nothing = Pace {
        bytes: 0,
        over_nanos: bucket_span().0,
    };
    let real = Pace {
        bytes: 1,
        over_nanos: bucket_span().0 * 1000,
    };

    assert_eq!(reflex_engine::meter::faster(nothing, real), real);
}
