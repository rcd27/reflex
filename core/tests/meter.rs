//! ТЕМП ПО ОКНУ — законы кольца временны́х корзин.
//!
//! Переехало из `dataplane` невода (05.09.2026). Механизм не знает о продукте ничего: он отвечает
//! на вопрос «сколько байт прошло за последние N корзин» и «быстрее ли один поток другого».

use reflex_core::meter::{
    bucket_of, bucket_span_nanos, ceiling, charge, empty_ring, expired, faster, freshness_of,
    horizon_nanos, merged, paced, rolled, room, slot, slower_than, Bucket, Freshness, Pace,
    Pressure, Ring, BUCKETS,
};

fn at(bucket: u64) -> u64 {
    bucket * bucket_span_nanos()
}

fn charged(ring: Ring, bucket: u64, bytes: u64) -> Ring {
    reflex_core::meter::applied(ring, charge(ring.last, at(bucket), bytes))
}

// ── ТЕМП КАК ТОЧНАЯ ДРОБЬ ────────────────────────────────────────────────────────────────────

/// ГЛАВНЫЙ ЗАКОН МОДУЛЯ, и он же тот, на котором наивная реализация краснеет.
///
/// Два байта за три наносекунды быстрее одного за две (0,667 против 0,5). Целочисленное деление
/// даёт `2/3 = 0` и `1/2 = 0` — то есть объявляет их РАВНЫМИ, и всякий выбор «кто быстрее» после
/// этого случаен. Перекрёстное умножение (2·2 = 4 против 1·3 = 3) отвечает верно.
#[test]
fn a_rate_is_compared_as_an_exact_fraction_not_by_division() {
    let slow = Pace {
        bytes: 1,
        over_nanos: 2,
    };
    let quick = Pace {
        bytes: 2,
        over_nanos: 3,
    };

    assert!(
        quick > slow,
        "целочисленное деление объявило бы эти два темпа равными"
    );
}

#[test]
fn the_same_rate_written_differently_is_the_same_rate() {
    assert_eq!(
        Pace {
            bytes: 3,
            over_nanos: 6
        },
        Pace {
            bytes: 100,
            over_nanos: 200
        }
    );
}

/// ТЕМП ЗА НУЛЕВОЕ ОКНО — это бесконечность, и сравнение обязано это выдержать.
#[test]
fn any_bytes_over_no_time_outrun_any_finite_rate() {
    let boundless = Pace {
        bytes: 1,
        over_nanos: 0,
    };
    let finite = Pace {
        bytes: 1_000_000,
        over_nanos: 1,
    };

    assert!(boundless > finite);
    assert_eq!(
        boundless,
        Pace {
            bytes: 5,
            over_nanos: 0
        },
        "две бесконечности неразличимы, и это честнее, чем выдумать между ними порядок"
    );
}

#[test]
fn faster_picks_the_greater_rate() {
    let slow = Pace {
        bytes: 1,
        over_nanos: 10,
    };
    let quick = Pace {
        bytes: 9,
        over_nanos: 10,
    };
    assert_eq!(faster(slow, quick), quick);
    assert_eq!(faster(quick, slow), quick, "выбор не зависит от порядка");
}

#[test]
fn slower_than_asks_by_how_many_times() {
    let reference = Pace {
        bytes: 100,
        over_nanos: 1,
    };
    let crawling = Pace {
        bytes: 10,
        over_nanos: 1,
    };

    assert!(
        slower_than(crawling, reference, 4),
        "вчетверо медленнее эталона — да, отставание десятикратное"
    );
    assert!(
        !slower_than(crawling, reference, 20),
        "в двадцать раз медленнее — нет, отставание всего десятикратное"
    );
}

// ── КОЛЬЦО КОРЗИН ────────────────────────────────────────────────────────────────────────────

#[test]
fn bytes_charged_in_one_bucket_are_read_back_from_it() {
    let ring = charged(empty_ring(), 5, 700);
    assert_eq!(paced(&ring, 0).bytes, 700);
}

#[test]
fn a_window_of_n_buckets_covers_the_span_of_n_buckets() {
    let ring = charged(empty_ring(), 5, 700);
    assert_eq!(paced(&ring, 0).over_nanos, bucket_span_nanos());
    assert_eq!(paced(&ring, 3).over_nanos, 4 * bucket_span_nanos());
}

#[test]
fn a_window_wider_than_the_ring_is_clamped_to_the_ring() {
    let ring = charged(empty_ring(), 5, 700);
    assert_eq!(
        paced(&ring, 255).over_nanos,
        BUCKETS as u64 * bucket_span_nanos(),
        "окно шире кольца не даёт больше сведений, чем в кольце есть"
    );
}

#[test]
fn a_window_sums_the_buckets_it_reaches_and_no_others() {
    let ring = charged(charged(charged(empty_ring(), 3, 1), 4, 10), 5, 100);

    assert_eq!(paced(&ring, 0).bytes, 100, "только последняя корзина");
    assert_eq!(paced(&ring, 1).bytes, 110, "две последние");
    assert_eq!(paced(&ring, 2).bytes, 111, "три последние");
}

/// ВРЕМЯ, ПРОШЕДШЕЕ БЕЗ ТРАФИКА, ОБЯЗАНО ЧИСТИТЬ КОРЗИНЫ, а не оставлять старое под новым
/// индексом: кольцо переиспользует ячейки, и незачищенная ячейка врёт величиной прошлого круга.
#[test]
fn buckets_passed_in_silence_are_cleared_not_carried() {
    let ring = charged(empty_ring(), 1, 500);
    let long_after = charged(ring, 1 + BUCKETS as u64 + 3, 7);

    assert_eq!(
        paced(&long_after, BUCKETS as u8 - 1).bytes,
        7,
        "полкруга молчания — и старые 500 байт обязаны исчезнуть, а не всплыть"
    );
}

#[test]
fn rolling_forward_without_traffic_moves_the_head() {
    let ring = charged(empty_ring(), 2, 50);
    let later = rolled(ring, Bucket(4));

    assert_eq!(later.last, Bucket(4));
    assert_eq!(paced(&later, 0).bytes, 0, "в новой корзине трафика не было");
    assert_eq!(paced(&later, 2).bytes, 50, "но окно пошире его ещё достаёт");
}

#[test]
fn merging_two_rings_adds_them_and_does_not_depend_on_order() {
    let one = charged(empty_ring(), 3, 40);
    let other = charged(empty_ring(), 4, 2);

    assert_eq!(merged(one, other), merged(other, one));
    assert_eq!(paced(&merged(one, other), 1).bytes, 42);
}

#[test]
fn the_ceiling_is_the_fullest_single_bucket() {
    let ring = charged(charged(charged(empty_ring(), 3, 100), 4, 900), 5, 20);

    assert_eq!(ceiling(&ring).bytes, 900);
    assert_eq!(
        ceiling(&ring).over_nanos,
        bucket_span_nanos(),
        "потолок — про ОДНУ корзину, иначе это не потолок"
    );
}

// ── СВЕЖЕСТЬ И НАПОР ─────────────────────────────────────────────────────────────────────────

#[test]
fn freshness_tells_live_from_settled_from_silent() {
    assert_eq!(freshness_of(0), Freshness::Live);
    assert_eq!(freshness_of(1), Freshness::Settled);
    assert_eq!(freshness_of(2), Freshness::Silent);
}

#[test]
fn a_conversation_unseen_for_longer_than_the_horizon_has_expired() {
    assert!(!expired(at(0), horizon_nanos()));
    assert!(expired(at(0), horizon_nanos() + 1));
}

#[test]
fn room_is_what_capacity_has_left_and_never_goes_below_zero() {
    assert_eq!(
        room(&Pressure {
            held: 30,
            capacity: 100,
            evicted: 0
        }),
        70
    );
    assert_eq!(
        room(&Pressure {
            held: 120,
            capacity: 100,
            evicted: 5
        }),
        0,
        "переполнение не даёт отрицательного запаса"
    );
}

// ── ПРИЕХАЛИ ВМЕСТЕ С КОДОМ ИЗ `dataplane/tests/{pace,meter}.rs` ─────────────────────────────
//
// Тесты следуют за тем, что проверяют. Эти покрывают то, чего в первой редакции здесь не было, и
// один из них — про переполнение — есть прямое основание для `u128` внутри сравнения.

#[test]
fn two_charges_in_one_bucket_accumulate() {
    let ring = charged(charged(empty_ring(), 5, 100), 5, 40);

    assert_eq!(ring.cells[slot(Bucket(5))], 140);
    assert_eq!(ring.last, Bucket(5));
}

/// БОЛЬШЕ БАЙТ НЕ ЗНАЧИТ БЫСТРЕЕ. Тысяча за десять наносекунд медленнее трёхсот за одну —
/// сравнение идёт по темпу, а не по числителю.
#[test]
fn slower_than_compares_rates_even_when_the_slower_side_moved_more_bytes() {
    let subject = Pace {
        bytes: 1000,
        over_nanos: 10,
    };
    let reference = Pace {
        bytes: 300,
        over_nanos: 1,
    };

    assert!(slower_than(subject, reference, 2));
    assert!(!slower_than(subject, reference, 4));
}

#[test]
fn faster_is_idempotent_neutral_and_associative() {
    let quick = Pace {
        bytes: 10,
        over_nanos: 1,
    };
    let slow = Pace {
        bytes: 1000,
        over_nanos: 1000,
    };
    let nothing = Pace {
        bytes: 0,
        over_nanos: 1,
    };
    let third = Pace {
        bytes: 5,
        over_nanos: 2,
    };

    assert_eq!(faster(quick, quick), quick, "идемпотентность");
    assert_eq!(faster(nothing, slow), slow, "ноль — нейтраль");
    assert_eq!(
        faster(faster(quick, slow), third),
        faster(quick, faster(slow, third)),
        "ассоциативность: склейка трёх окон не зависит от расстановки скобок"
    );
}

/// ОСНОВАНИЕ ДЛЯ `u128` ВНУТРИ. На окнах порядка 2⁴⁰ произведение числителя на чужой знаменатель
/// не помещается в `u64`, и сравнение, посчитанное в `u64`, дало бы обратный ответ.
#[test]
fn comparing_rates_survives_windows_that_overflow_sixty_four_bits() {
    let subject = Pace {
        bytes: 1u64 << 40,
        over_nanos: 1u64 << 41,
    };
    let reference = Pace {
        bytes: 1u64 << 40,
        over_nanos: 1u64 << 40,
    };

    assert!(slower_than(subject, reference, 1));
    assert!(!slower_than(subject, reference, 2));
}

/// МГНОВЕННАЯ ПЕРЕДАЧА НЕ БЫВАЕТ МЕДЛЕННЕЕ ЧЕГО-ЛИБО, во сколько бы раз ни спрашивали.
#[test]
fn an_instant_transfer_is_never_slower_than_anything() {
    let instant = Pace {
        bytes: 1000,
        over_nanos: 0,
    };
    let ordinary = Pace {
        bytes: 1000,
        over_nanos: 1,
    };

    assert!(!slower_than(instant, ordinary, 1000));
    assert!(slower_than(ordinary, instant, 1));
}

/// ПРОКРУТКА ЧИСТИТ ТОЛЬКО ПРОПУЩЕННОЕ, а не всё кольцо: иначе одна пауза стирала бы историю,
/// которую окно ещё имеет право видеть.
#[test]
fn rolling_clears_only_the_buckets_that_were_skipped() {
    let ring = charged(charged(empty_ring(), 1, 5), 2, 9);
    let after = rolled(ring, Bucket(4));

    assert_eq!(paced(&after, 0).bytes, 0, "текущая пуста");
    assert_eq!(paced(&after, 1).bytes, 0, "и предыдущая — её проскочили");
    assert_eq!(paced(&after, 2).bytes, 9, "а вот корзина 2 уцелела");
    assert_eq!(paced(&after, 3).bytes, 14, "и корзина 1 тоже");
}

#[test]
fn a_moment_lands_in_the_bucket_that_holds_it() {
    assert_eq!(bucket_of(0), Bucket(0));
    assert_eq!(bucket_of(bucket_span_nanos() - 1), Bucket(0));
    assert_eq!(bucket_of(bucket_span_nanos()), Bucket(1));
    assert_eq!(slot(Bucket(BUCKETS as u64)), 0, "кольцо замыкается");
}
