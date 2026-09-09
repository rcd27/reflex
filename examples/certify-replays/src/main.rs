//! # Восьмой закон на живой ленте — предъявимость, а не обещание
//!
//! Семь законов эталона свидетельствуют ЭФФЕКТ: «мир принял?». Восьмой отвечает на другой конец
//! (§10, §12.3): пере-подай записанное той же машине из того же семени — и она обязана сказать то
//! же самое. Расхождение значит, что машина читает то, чего нет в её алфавите: часы, глобальный
//! счётчик, чужую память. Это не придирка к чистоте — это приговор происхождению вывода: разобрать
//! бой становится нечем.
//!
//! ## Чем этот пример отличается от стенда
//!
//! Закон предъявляется на ТВОЁМ трафике, а не на выдуманном. Движок пишет окно наблюдений (буквы
//! провода с адресом, который знает только разбор), набрав его — пере-подаёт свежей семье машин
//! ДВАЖДЫ и сверяет не ленту, а сказанное. Реакции при этом не зовутся: они печатают, то есть
//! трогают мир, а переигровка мира не трогает.
//!
//! Вердикт печатается сам:
//!
//! * `§10: окно из N букв воспроизведено` — закон держится;
//! * `§10 НАРУШЕН: прогоны разошлись на исходе K` — у машины есть вход вне её алфавита.
//!
//! ## Цена
//!
//! Запись стоит копии слова провода на каждый пакет, потому дверь закрыта по умолчанию: платит тот,
//! кто закон просит. Окно ограничено — иначе лента росла бы, пока жив процесс.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 queue num 200'
//! cargo run -p certify-replays
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

/// Прибор со СКРЫТЫМ ВХОДОМ — нарочно испорченный. Величину берёт из счётчика, живущего вне его
/// состояния: то есть читает то, чего нет в его алфавите. Ровно это восьмой закон обязан ловить.
///
/// Живёт в примере, а не в тестах, потому что доказывает способность СТЕНДА: зелёный вердикт на
/// исправной машине ничего не стоит, пока не показано, что тот же стенд краснеет на испорченной.
#[derive(Clone, Copy, Default)]
struct Peeking;

static PEEKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl Mealy for Peeking {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: DetectorEvent<Seen>) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => {
                let ms = PEEKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (self, smallvec![Distress::Silence { ms }], ())
            }
            _ => (self, smallvec![], ()),
        }
    }
}

fn main() -> Report {
    // Мутант ставится ПЕРЕМЕННОЙ СРЕДЫ, а не правкой кода: стенд обязан уметь показать оба исхода
    // в одном прогоне, иначе «умеет краснеть» остаётся словами.
    let spoiled = std::env::var("MUTANT").is_ok();
    let mut detecting = engine(Nfqueue::queue(200))
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .detect(Silence::after(secs(5)));
    if spoiled {
        report!("СТЕНД ИСПОРЧЕН НАРОЧНО: в цепочке прибор со скрытым входом");
        detecting = detecting.detect(own(Peeking));
    }
    detecting
        // Копредел стоит НАРОЧНО: слово о цели — свежая постройка, и переигровка обязана
        // свидетельствовать о ней тоже, иначе непроверенным осталось бы ровно новое.
        .about(|words| {
            words
                .iter()
                .all(|distress| matches!(distress, Distress::NoBytes | Distress::Silence { .. }))
                .then_some(Distress::NoBytes)
        })
        .on_target(|target, voiced| {
            if voiced.since < secs(1) {
                report!("цель молчит целиком: {target}")
            }
        })
        .on(|target, distress| report!("{target}: {distress}"))
        // Единственная дверь закона. Всё остальное — обычная цепочка.
        .certifying()
        .run()
}
