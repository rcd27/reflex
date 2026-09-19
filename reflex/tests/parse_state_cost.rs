//! ЦЕНА ПАМЯТИ РАЗБОРА — числом, считающим аллокатором, а не пиком RSS.
//!
//! Весь вечер 18.09.2026 мы мерили утечку пиком RSS на переигровке — и трижды получили неверные
//! выводы, потому что у такого замера ДВЕ оси: байты провода и число разговоров. Носитель записи
//! лежал на первой (держал файл дважды) и подмешивал себя в ответ линейно, то есть неотличимо от
//! утечки. Разошлись на 4,3 против 1,5 КБ на повтор и на 2,3 против 0,8 КБ на разговор — оба числа
//! успели уехать владельцу потребителя и были отозваны.
//!
//! Здесь ось одна и закреплена: считаются БАЙТЫ, выданные аллокатором, при фиксированном входе.
//! Провода нет, файла нет, пика нет — есть разница «сколько держится сейчас» до и после.
//!
//! Что держит закон: цена разговора названа потолком, а не описана; и главное — разбор, которому
//! сказали забыть ВСЕ разговоры, не держит НИЧЕГО. Второе и есть та утечка, которую чинили сегодня:
//! `Talks::forget` существовал, звал его только его же юнит-тест, а карты росли числом виденных
//! четвёрок — 0,8 КБ на каждую, сутками, без возврата.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use reflex::*;

/// Сколько байт выдано и не возвращено. Обёртка над системным аллокатором — свой считает ровно то,
/// что нужно закону, и не зависит ни от страниц, ни от прогретости кучи (обе величины сегодня
/// объясняли нам разрыв вчетверо, которого не было).
struct Counted;

static HELD: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HELD.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        HELD.fetch_add(new_size, Ordering::Relaxed);
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counted = Counted;

fn held() -> usize {
    HELD.load(Ordering::Relaxed)
}

/// Клиентский кадр с данными: четвёрка узнаётся по порту источника.
fn client_frame(port: u16, payload: &[u8]) -> reflex_engine::parse::Wire<'_> {
    reflex_engine::parse::Wire {
        header: reflex_engine::parse::Header {
            ends: reflex_engine::parse::Ends {
                src_ip: 0x0A00_0001,
                dst_ip: 0x5DB8_D822,
                src_port: port,
                dst_port: 443,
            },
            seq: 1000,
            ack: 0,
            window: 64240,
        },
        dst: Addr(0x5DB8_D822),
        dir: reflex_core::types::Dir::Up,
        flow: Flow {
            src: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                port,
            ),
            dst: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
                443,
            ),
            protocol: reflex_core::types::Protocol::Tcp,
        },
        opens: false,
        handshakes: false,
        closes: false,
        resets: false,
        head: reflex_engine::parse::Head::Opaque,
        payload,
    }
}

const FLOWS: u16 = 5_000;

/// Приветствие без имени: разбор обязан копить куски, значит цена разговора здесь максимальная из
/// обычных.
fn nameless_hello() -> Vec<u8> {
    let mut bytes = vec![0u8; 700];
    bytes[0] = 0x16;
    bytes
}

/// ЦЕНА РАЗГОВОРА НАЗВАНА ЧИСЛОМ, а не описана словами. Сколько именно и почему столько — в теле,
/// рядом с самим порогом: два места об одной величине расходятся молча.
#[test]
fn what_the_parsing_keeps_per_conversation_has_a_named_price() {
    let hello = nameless_hello();
    let mut state = TcpState::default();

    let before = held();
    for port in 0..FLOWS {
        let _ = Tcp::observe(&mut state, Read::Tcp(client_frame(40000 + port, &hello)));
    }
    let per_flow = (held() - before) / FLOWS as usize;

    // Замерено 18.09.2026: 2116 байт на разговор при копящемся приветствии в 700 байт. Из них
    // само приветствие — треть, остальное ключ `Flow` в двух картах (68 × 2), запись разговора и
    // запас хэш-таблиц. Потолок назван с запасом в полтора раза: он сторожит не точность, а
    // ПОРЯДОК — правка, удесятерившая цену, уронит тест, а не будет найдена через сутки на машине.
    assert!(
        per_flow < 3072,
        "разговор стоит {per_flow} байт — дороже названного потолка в 3 КБ"
    );
}

/// ГЛАВНЫЙ ЗАКОН: разбор, которому сказали забыть ВСЕ разговоры, не держит ничего.
///
/// Именно он был нарушен и не замечен: уборка существовала, звали её только в тесте её же файла, и
/// карты росли числом ВИДЕННЫХ четвёрок. Сторож поставлен так, чтобы следующая потеря вызова
/// роняла приёмку, а не обнаруживалась приростом RSS на пяти живых машинах за сутки.
#[test]
fn a_parsing_told_to_forget_everything_keeps_nothing() {
    let hello = nameless_hello();
    let mut state = TcpState::default();

    let empty = held();
    let flows: Vec<Flow> = (0..FLOWS)
        .map(|port| {
            let wire = client_frame(40000 + port, &hello);
            let flow = wire.flow;
            let _ = Tcp::observe(&mut state, Read::Tcp(wire));
            flow
        })
        .collect();
    let full = held();
    assert!(
        full > empty,
        "разбор пяти тысяч разговоров обязан что-то держать, иначе тест ничего не проверяет"
    );

    for flow in &flows {
        Tcp::forget(&mut state, flow);
    }
    let after = held();

    // Проверяется ОТДАННОЕ, а не оставшееся, и это не придирка к формулировке. Оставшееся содержит
    // ёмкость самих карт: `HashMap` выделенное не возвращает, и ёмкость эта законна — она держится
    // числом ОДНОВРЕМЕННО живых разговоров (потолок 8192), а не числом виденных. Замер показал
    // около 1,1 МБ такой ёмкости на пяти тысячах ключей — порог «остаточных байт» пришлось бы
    // ставить выше неё, и он перестал бы ловить то, ради чего заведён.
    //
    // А вот ОТДАННОЕ ёмкостью не объясняется: пять тысяч приветствий по 700 байт — это 3,5 МБ
    // данных, и забвение обязано вернуть их все. Пока уборки не было, оно не возвращало НИЧЕГО.
    let released = full.saturating_sub(after);
    let fragments = 700 * flows.len();
    assert!(
        released >= fragments * 9 / 10,
        "забвение вернуло {released} байт, а накопленных приветствий было {fragments}: разбор \
         держит данные разговоров, которых для движка уже нет"
    );
}
