//! ТОТАЛЬНОСТЬ РАЗБОРА CTNETLINK — то, чего живое ядро не покажет.
//!
//! Правильность НОМЕРОВ атрибутов этими тестами не устанавливается и устанавливаться не может:
//! сборщик ниже разделил бы со мной любую ошибку в константе. Номера проверяет
//! `zond/stand/ct-witness.sh` — ядром, по байтам, посланным заведомо (прогон 31.08: четвёрка
//! сошлась, 1 001 776 Б при 1 000 000 посланных). Здесь проверяется другое: что обрыв на любой
//! границе прекращает обход, а не уводит указатель в мусор.

#![cfg(feature = "conntrack")]

use reflex_linux::conntrack::{chunk_of, Chunk};

const CT_NEW: u16 = (1 << 8) | 0;
const DONE: u16 = 3;
const ERROR: u16 = 2;

fn attr(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (4 + body.len()) as u16;
    let pad = (4 - (body.len() % 4)) % 4;
    len.to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain(body.iter().copied())
        .chain(core::iter::repeat(0).take(pad))
        .collect()
}

fn nested(kind: u16, inner: Vec<u8>) -> Vec<u8> {
    attr(kind | 0x8000, &inner)
}

fn message(kind: u16, payload: Vec<u8>) -> Vec<u8> {
    let len = (16 + payload.len()) as u32;
    len.to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain(0u16.to_ne_bytes())
        .chain(1u32.to_ne_bytes())
        .chain(0u32.to_ne_bytes())
        .chain(payload)
        .collect()
}

fn nfgen() -> Vec<u8> {
    vec![2, 0, 0, 0]
}

fn tuple_orig(src: u32, dst: u32, sport: u16, dport: u16) -> Vec<u8> {
    let ip = nested(
        1,
        attr(1, &src.to_be_bytes())
            .into_iter()
            .chain(attr(2, &dst.to_be_bytes()))
            .collect::<Vec<u8>>(),
    );
    let proto = nested(
        2,
        attr(1, &[6u8])
            .into_iter()
            .chain(attr(2, &sport.to_be_bytes()))
            .chain(attr(3, &dport.to_be_bytes()))
            .collect::<Vec<u8>>(),
    );
    nested(1, ip.into_iter().chain(proto).collect())
}

fn counters(kind: u16, packets: u64, bytes: u64) -> Vec<u8> {
    nested(
        kind,
        attr(1, &packets.to_be_bytes())
            .into_iter()
            .chain(attr(2, &bytes.to_be_bytes()))
            .collect::<Vec<u8>>(),
    )
}

fn one_record() -> Vec<u8> {
    message(
        CT_NEW,
        nfgen()
            .into_iter()
            .chain(tuple_orig(0x7F000001, 0x7F000001, 37894, 9443))
            .chain(counters(9, 34, 1_001_776))
            .chain(counters(10, 32, 1688))
            .chain(attr(8, &7u32.to_be_bytes()))
            .collect(),
    )
}

#[test]
fn zapis_razbiraetsya_tselikom() {
    let done: Vec<u8> = one_record()
        .into_iter()
        .chain(message(DONE, Vec::new()))
        .collect();
    match chunk_of(&done) {
        Chunk::Done(found) => {
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].orig.src_port, 37894);
            assert_eq!(found[0].orig.dst_port, 9443);
            assert_eq!(found[0].orig.proto, 6);
            assert_eq!(found[0].orig_counts.packets, 34);
            assert_eq!(found[0].orig_counts.bytes, 1_001_776);
            assert_eq!(found[0].reply_counts.packets, 32);
            assert_eq!(found[0].mark, 7);
        }
        other => panic!("ждали Done с одной записью, вышло {:?}", other),
    }
}

/// ПОРЦИЯ БЕЗ `NLMSG_DONE` — НЕ КОНЕЦ. Дамп приходит несколькими порциями, и остановка по пустоте
/// читала бы обрыв как конец: записи, не поместившиеся в буфер, пропали бы молча.
#[test]
fn portsiya_bez_done_prosit_prodolzheniya() {
    assert!(matches!(chunk_of(&one_record()), Chunk::More(found) if found.len() == 1));
}

#[test]
fn pustoy_bufer_ne_konets_a_prodolzhenie() {
    assert_eq!(chunk_of(&[]), Chunk::More(Vec::new()));
}

#[test]
fn otkaz_yadra_ne_vydayotsya_za_pustoy_damp() {
    let refused: Vec<u8> = message(ERROR, (-1i32).to_ne_bytes().to_vec());
    assert_eq!(chunk_of(&refused), Chunk::Failed(-1));
}

/// Подтверждение (`NLMSG_ERROR` с нулём) — это конец дампа, а не отказ.
#[test]
fn podtverzhdenie_est_konets() {
    let ack: Vec<u8> = message(ERROR, 0i32.to_ne_bytes().to_vec());
    assert_eq!(chunk_of(&ack), Chunk::Done(Vec::new()));
}

#[test]
fn oborvannyy_zagolovok_ne_ronyaet_razbor() {
    let torn: Vec<u8> = one_record().into_iter().take(9).collect();
    assert_eq!(chunk_of(&torn), Chunk::More(Vec::new()));
}

/// ДЛИНА, ОБЕЩАЮЩАЯ БОЛЬШЕ, ЧЕМ ЕСТЬ, — самый опасный вход, и опасен он ИМЕННО НА `NLMSG_DONE`.
///
/// Первая редакция теста брала обрезанный `CT_NEW`, и обезоруживание её не покраснило: у записи оба
/// пути дают `More`, то есть вход НЕ РАЗЛИЧАЛ проверяемое. На `DONE` различает: без сверки длины
/// обрыв порции читается как «дамп кончился» — записи следующих порций пропадают, а прибор при этом
/// рапортует успехом.
#[test]
fn oborvannyy_done_ne_chitaetsya_kak_konets_dampa() {
    let done = message(DONE, Vec::new());
    let lying: Vec<u8> = 9999u32
        .to_ne_bytes()
        .into_iter()
        .chain(done.iter().skip(4).copied())
        .collect();
    assert_eq!(chunk_of(&lying), Chunk::More(Vec::new()));
}

/// Та же ложь на записи: за буфер разбор не уходит.
#[test]
fn dlina_bolshe_bufera_ostanavlivaet_obhod() {
    let record = one_record();
    let lying: Vec<u8> = 9999u32
        .to_ne_bytes()
        .into_iter()
        .chain(record.iter().skip(4).copied())
        .collect();
    assert_eq!(chunk_of(&lying), Chunk::More(Vec::new()));
}

#[test]
fn oborvannyy_vlozhennyy_atribut_ne_ronyaet_sosedey() {
    let torn_inside = message(
        CT_NEW,
        nfgen()
            .into_iter()
            .chain(tuple_orig(0x7F000001, 0x7F000001, 100, 443))
            .chain(vec![0xFF, 0xFF, 9, 0x80, 1, 2, 3, 0])
            .collect(),
    );
    let whole: Vec<u8> = torn_inside
        .into_iter()
        .chain(message(DONE, Vec::new()))
        .collect();
    match chunk_of(&whole) {
        Chunk::Done(found) => {
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].orig.dst_port, 443);
            assert_eq!(found[0].orig_counts.packets, 0);
        }
        other => panic!("ждали одну запись без счётчиков, вышло {:?}", other),
    }
}

#[test]
fn neznakomyy_atribut_ne_meshaet_sosedyam() {
    let with_stranger = message(
        CT_NEW,
        nfgen()
            .into_iter()
            .chain(attr(250, &[1, 2, 3, 4]))
            .chain(tuple_orig(0x0A000001, 0x0A000002, 5555, 443))
            .chain(counters(9, 3, 120))
            .collect(),
    );
    let whole: Vec<u8> = with_stranger
        .into_iter()
        .chain(message(DONE, Vec::new()))
        .collect();
    match chunk_of(&whole) {
        Chunk::Done(found) => {
            assert_eq!(found[0].orig.src_port, 5555);
            assert_eq!(found[0].orig_counts.bytes, 120);
        }
        other => panic!("ждали разобранную запись, вышло {:?}", other),
    }
}

#[test]
fn dve_zapisi_podryad_ne_slivayutsya() {
    let two: Vec<u8> = one_record()
        .into_iter()
        .chain(message(
            CT_NEW,
            nfgen()
                .into_iter()
                .chain(tuple_orig(0x0A000001, 0x0A000002, 1234, 443))
                .chain(counters(9, 1, 60))
                .collect(),
        ))
        .chain(message(DONE, Vec::new()))
        .collect();
    match chunk_of(&two) {
        Chunk::Done(found) => {
            assert_eq!(found.len(), 2);
            assert_eq!(found[1].orig.src_port, 1234);
        }
        other => panic!("ждали две записи, вышло {:?}", other),
    }
}
