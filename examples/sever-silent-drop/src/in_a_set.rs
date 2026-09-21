//! # Тот же обрыв, но ПРАВИЛОМ — форма, которая доживает до набора
//!
//! Сосед по крейту (`src/main.rs`) рвёт терминалом: `.act(…)` возвращает `Act::sever()` на
//! показание. Форма верная и единственно нужная, пока цепочка одна, — но терминал УВОДИТ цепочку в
//! свой поток и до [`together`] она не доходит. У потребителя с четырьмя проводами это значит одно
//! из двух: либо четыре нити с замками вокруг общего знания, либо обрыва нет.
//!
//! Отсюда вторая форма: `severing` — ПРАВИЛО, объявленное заранее и живущее в пути показаний
//! значением. Оно работает и в одиночной цепочке, и в наборе, а показания идут как шли: обрыв их
//! не отменяет.
//!
//! Предел назван прямо в фасаде и повторён здесь, чтобы не искали: из трёх глаголов `Act` правилом
//! выражается ОДИН — обрыв. Кому нужен вопрос к контуру (`Act::ask`) или наблюдение с решением,
//! тому терминал и своя нить.
//!
//! ## Две формы предиката, и вторая — не украшение
//!
//! * `severing(|слово| …)` — решение по РОДУ УЛИКИ. Повтор клиента при нулевом ответе есть тихий
//!   дроп, кем бы ни был разговор.
//! * `severing_addressed(|кому, слово| …)` — решение по ПРИЗНАКУ ЯДРА. Один и тот же разговор
//!   бывает то под лечением, то мимо него: беда на разговоре, идущем другим путём, есть беда того
//!   пути, и рвать там нечего.
//!
//! ## Ловушка второй формы, оплаченная полем (19.09.2026)
//!
//! `Whom::edge` пуст у ВСЯКОГО слова, рождённого узлом сетки: у времени края не бывает, и цикл
//! отдаёт `None` на буквах `Tick`/`Opaque`/`Torn` по построению. Предикат вида
//! `whom.edge.map(…) == Some(МАРКА)` на таких словах даёт `false` ВСЕГДА и читается как «чужой
//! разговор», хотя значит «не посмотрели» (Утв. 7.2: дефект наблюдателя выдан за свойство мира).
//! В первой редакции правила потребителя эта клетка оказалась не просто обитаемой, а ЕДИНСТВЕННО
//! населённой: предмет обрыва не наступал вовсе, и молчание двери было неотличимо от работы.
//!
//! КРИТЕРИЙ — БУКВА, а не род прибора: цикл снимает край С БУКВЫ (`Packet` → `Some`,
//! `Tick`/`Opaque`/`Torn` → `None`). Оттого краевая половина `Silence` (шагает только на пакете)
//! и проводной `Retransmit` (улика — совпавший `seq`, то есть тоже пакет) дают слова С КРАЕМ, а без
//! края приходит слово, сказанное НА УЗЛЕ, чьей бы машина ни была. Пара тестов ниже предъявляет это
//! на ОДНОЙ по устройству машине: сказала на узле — края нет, сказала на пакете — есть.
//!
//! Отсюда правило письма: `None` разбирается ОТДЕЛЬНОЙ ВЕТВЬЮ и считается отдельным счётом — не
//! «ложью по умолчанию».
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 meta mark and 0xc0000000 != 0x40000000 queue num 200'
//! sudo nft 'add rule inet reflex_demo out udp dport 443 meta mark and 0xc0000000 != 0x40000000 queue num 201'
//! cargo run -p sever-silent-drop --bin sever-in-a-set
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

/// Марка разговора, по которой видно, что он ИДЁТ ЧЕРЕЗ НАС. Число — довод стенда, не знание
/// фреймворка: кто ставит марку, тот и называет её значение.
const OURS: u32 = 0x0001_0000;

/// ПОД ЧЬЕЙ МАРКОЙ ИДЁТ РАЗГОВОР — алфавит этого примера, объявленный один раз.
///
/// Прежде здесь стояло `edge.mark & OURS == OURS` прямо в предикате обрыва. Так читают биты те,
/// у кого разметки нет, — и тогда каждый читатель пишет её заново. Объявленный алфавит читается
/// одной дверью (`Counted::under`), а второго закона о нём язык написать не даёт.
enum Under {
    /// Байты идут нашим путём: марка в своей области взведена.
    Ours,
    /// Чужой разговор либо непомеченный: о нём мы не судим.
    Foreign,
}

impl Meaning for Under {
    const REGION: Region = Region::declared(OURS);

    /// Область в один бит: взведён — наш. Разбор ТОТАЛЬНЫЙ и без wildcard — новое значение области
    /// не проскочит молча.
    fn read(value: u32) -> Under {
        match value {
            0 => Under::Foreign,
            1..=u32::MAX => Under::Ours,
        }
    }
}

fn main() {
    let together = together()
        .chain(
            engine(Nfqueue::queue(200))
                .from(Tcp)
                .extract(Sni)
                .detect(Retransmit::unanswered())
                // ПО РОДУ УЛИКИ: повтор клиента при нулевом ответе.
                .severing(|word: &Distress| matches!(word, Distress::Retransmit { .. })),
        )
        .chain(
            engine(Nfqueue::queue(201))
                .from(Tcp)
                .extract(Sni)
                .detect(Silence::after(secs(5)))
                // ПО ПРИЗНАКУ ЯДРА, и клетка незнания разобрана отдельно — см. шапку.
                .severing_addressed(|whom: Whom<'_>, word: &Distress| match whom.edge {
                    Some(edge) => match edge.under::<Under>() {
                        Under::Ours => matches!(word, Distress::NoBytes),
                        Under::Foreign => false,
                    },
                    // КРАЯ НЕТ — значит слово пришло узлом сетки, и о марке мы НЕ СПРАШИВАЛИ.
                    // Вернуть `false` молча значило бы объявить разговор чужим; здесь это
                    // отдельный исход, и он говорит вслух.
                    None => {
                        report!("{}: слово без края — о пути не знаем, не рву", whom.target);
                        false
                    }
                }),
        );

    for refused in together.refused() {
        report!(
            "цепочка не поднялась: {}",
            refused.why().unwrap_or("без причины")
        );
    }

    // ПОКАЗАНИЯ ИДУТ КАК ШЛИ: правило обрыва их не отменяет и потока не занимает — этим оно и
    // отличается от терминала.
    for note in together.heard() {
        report!("{}: {:?}", note.target, note.word);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex::scenario::{request, syn, Paper};

    /// ПРЕДМЕТ: правило обрыва живёт в НАБОРЕ и показаний не отнимает.
    ///
    /// Терминал (`.act`) сюда не встал бы вовсе — он уводит цепочку в свой поток. Проверяется то,
    /// ради чего вторая форма и заведена: цепочка с объявленным правилом входит в `together` и
    /// говорит оттуда.
    #[test]
    fn a_chain_with_a_severing_rule_still_speaks_from_the_set() {
        let heard: Vec<Note> = together()
            .chain(
                engine(
                    Paper::new()
                        .then_packet(syn(40101))
                        .then_packet(request(40101))
                        .silent_for(secs(6))
                        .then_stop(),
                )
                .from(Tcp)
                .extract(Sni)
                .detect(Silence::after(secs(5)))
                .severing(|word: &Distress| matches!(word, Distress::NoBytes)),
            )
            .heard()
            .collect();

        assert!(
            !heard.is_empty(),
            "показания обязаны идти как шли — правило обрыва их не отменяет"
        );
    }

    /// ПРЕДМЕТ: слово БЕЗ КРАЯ приходит в предикат, и ветвь `None` обязана быть.
    ///
    /// Клетка, стоившая потребителю молчащей двери, предъявляется прогоном: машина говорит на узле
    /// сетки, цикл отдаёт такому слову `edge = None` (у времени края нет), предикат по марке на нём
    /// вернул бы «чужой разговор» — и молчал бы вечно, выглядя исправным.
    ///
    /// Своя машина, а не парковый прибор, и это не удобство стенда: краевая половина `Silence`
    /// шагает только на пакете и слов без края не даёт вовсе — на ней эту клетку не показать.
    #[test]
    fn a_word_spoken_on_a_grid_node_arrives_without_an_edge() {
        /// Машина, говорящая РОВНО на узле сетки: предмет — время, а не пакет.
        #[derive(Clone, Copy, Default)]
        struct OnTheClock;

        impl Mealy for OnTheClock {
            type In = DetectorEvent<Seen>;
            type Out = SmallVec<[Distress; 2]>;
            type Log = ();

            fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
                match event {
                    DetectorEvent::Tick { .. } => (self, smallvec![Distress::NoBytes], ()),
                    DetectorEvent::Packet { .. }
                    | DetectorEvent::Opaque { .. }
                    | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
                }
            }
        }

        let without: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let counted = without.clone();
        let with_edge: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let counted_with = with_edge.clone();

        let _heard: Vec<Note> = together()
            .chain(
                engine(
                    Paper::new()
                        .then_packet(syn(40103))
                        .then_packet(request(40103))
                        .silent_for(secs(6))
                        .then_stop(),
                )
                .from(Tcp)
                .extract(Sni)
                .detect(own(OnTheClock))
                .severing_addressed(move |whom: Whom<'_>, _word: &Distress| match whom.edge {
                    Some(_) => {
                        counted_with.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        false
                    }
                    None => {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        false
                    }
                }),
            )
            .heard()
            .collect();

        assert!(
            without.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "слово, сказанное на узле сетки, обязано прийти БЕЗ края — иначе предикат по марке \
             молча считает такие разговоры чужими, и дверь молчит, выглядя исправной"
        );
        // Вторая половина: предикат зовётся не только с пустым краем, иначе «ветвь `None` пройдена»
        // значило бы всего лишь «края не бывает никогда».
        assert_eq!(
            with_edge.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "эта машина говорит только на узлах — слов с краем у неё быть не может"
        );
    }

    /// ПАРА К ПРЕДЫДУЩЕМУ: та же ПРОВОДНАЯ машина, сказавшая на ПАКЕТЕ, приходит С КРАЕМ.
    ///
    /// Без этой половины предыдущий закон читался бы «у проводных машин края не бывает» — и это
    /// была бы вторая ложь на том же месте, где уже жила одна. Критерий не в роде прибора и не в
    /// его доме, а в БУКВЕ: цикл снимает край с буквы (`Packet` → `Some`, `Tick`/`Opaque`/`Torn` →
    /// `None`), и проводной `Retransmit`, чья улика — совпавший `seq`, говорит именно на пакете.
    #[test]
    fn the_same_kind_of_machine_speaking_on_a_packet_arrives_with_an_edge() {
        /// Машина, говорящая РОВНО на пакете. Дом тот же, что у соседки выше, — разная только буква.
        #[derive(Clone, Copy, Default)]
        struct OnThePacket;

        impl Mealy for OnThePacket {
            type In = DetectorEvent<Seen>;
            type Out = SmallVec<[Distress; 2]>;
            type Log = ();

            fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
                match event {
                    DetectorEvent::Packet { .. } => (self, smallvec![Distress::Rst], ()),
                    DetectorEvent::Tick { .. }
                    | DetectorEvent::Opaque { .. }
                    | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
                }
            }
        }

        let with_edge: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let counted = with_edge.clone();
        let without: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
        let counted_without = without.clone();

        let _heard: Vec<Note> = together()
            .chain(
                engine(
                    Paper::new()
                        .then_packet(syn(40104))
                        .then_packet(request(40104))
                        .silent_for(secs(6))
                        .then_stop(),
                )
                .from(Tcp)
                .extract(Sni)
                .detect(own(OnThePacket))
                .severing_addressed(move |whom: Whom<'_>, _word: &Distress| match whom.edge {
                    Some(_) => {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        false
                    }
                    None => {
                        counted_without.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        false
                    }
                }),
            )
            .heard()
            .collect();

        assert!(
            with_edge.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "слово, сказанное на пакете, обязано прийти С краем — иначе предикат по марке не \
             работал бы вовсе, ни на одном приборе"
        );
        assert_eq!(
            without.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "эта машина на узлах молчит — слов без края у неё быть не может"
        );
    }
}
