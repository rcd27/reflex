use reflex_engine::meter::{applied, charge, empty_ring, merged, slot, Bucket, Ring, BUCKET_SHIFT};
use reflex_engine::Tick;

fn at(bucket: u64) -> Tick {
    Tick(bucket << BUCKET_SHIFT)
}

fn ring_after(charges: &[(u64, u64)]) -> Ring {
    charges.iter().fold(empty_ring(), |ring, (bucket, bytes)| {
        applied(ring, charge(ring.last, at(*bucket), *bytes))
    })
}

#[test]
fn an_empty_ring_is_the_neutral_element_of_merging() {
    let one = ring_after(&[(3, 10), (5, 20)]);

    assert_eq!(merged(one, empty_ring()), one);
    assert_eq!(merged(empty_ring(), one), one);
}

#[test]
fn merging_does_not_depend_on_the_order_of_the_two_rings() {
    let one = ring_after(&[(3, 10), (5, 20)]);
    let other = ring_after(&[(4, 7), (5, 1)]);

    assert_eq!(merged(one, other), merged(other, one));
}

#[test]
fn merging_three_rings_gives_the_same_answer_however_they_are_grouped() {
    let one = ring_after(&[(3, 10)]);
    let other = ring_after(&[(4, 7)]);
    let third = ring_after(&[(5, 1)]);

    assert_eq!(
        merged(merged(one, other), third),
        merged(one, merged(other, third))
    );
}

#[test]
fn a_ring_that_fell_a_whole_lap_behind_contributes_nothing() {
    let stale = ring_after(&[(3, 100)]);
    let live = ring_after(&[(70, 7)]);

    assert_eq!(merged(stale, live).cells.iter().sum::<u64>(), 7);
}

#[test]
fn a_ring_that_fell_a_little_behind_keeps_what_is_still_inside_the_window() {
    let behind = ring_after(&[(68, 100)]);
    let live = ring_after(&[(70, 7)]);
    let both = merged(behind, live);

    assert_eq!(both.cells[slot(Bucket(68))], 100);
    assert_eq!(both.cells[slot(Bucket(70))], 7);
    assert_eq!(both.cells.iter().sum::<u64>(), 107);
}
