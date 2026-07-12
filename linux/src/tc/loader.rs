use std::collections::VecDeque;
use std::io;

use aya::maps::lpm_trie::Key;
use aya::maps::{HashMap, LpmTrie, MapData, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use reflex_linux_common::{steer_fate, Fate, FlowAction, FlowEvent, SteerStat, STEER_STAT_SLOTS};
use tokio::io::unix::AsyncFd;

pub struct TcProgram {
    bpf: Ebpf,
    interface: String,
}

impl TcProgram {
    /// `reflex_tc` на EGRESS: Pass/Drop/Steer-заглушка (Phase 0 passthrough, транзит-safety тест).
    pub fn attach(interface: &str, bpf_bytes: &[u8]) -> Result<Self, String> {
        Self::attach_named(interface, bpf_bytes, "reflex_tc", TcAttachType::Egress)
    }

    /// `reflex_steer` на INGRESS: sk_assign-заворот целевого флоу в несущую (BL-213 Phase 1).
    /// Ingress — перехват клиентского пакета ДО форвардинга моста. Требует `set_steer_cfg`.
    pub fn attach_steer(interface: &str, bpf_bytes: &[u8]) -> Result<Self, String> {
        Self::attach_named(interface, bpf_bytes, "reflex_steer", TcAttachType::Ingress)
    }

    /// `reflex_return` на INGRESS nevod0: ОБРАТНАЯ половина круга. netstack пишет ответ в nevod0 →
    /// программа `bpf_redirect_neigh` доставляет его клиенту через br0, минуя сломанный форвард.
    pub fn attach_return(interface: &str, bpf_bytes: &[u8]) -> Result<Self, String> {
        Self::attach_named(interface, bpf_bytes, "reflex_return", TcAttachType::Ingress)
    }

    /// `reflex_observe` на КЛИЕНТ-порту (clsact ingress+egress): наблюдение проходящего флоу для
    /// witness — БЕЗ лифта/возврата (аддитивно, транзит невредим). Направление из хука: ingress =
    /// от клиента (Upstream), egress = к клиенту (Downstream). Отдаёт держатель программ (Drop
    /// отцепит, RAII) + async-поток `FlowEvents` из общего `RingBuf`. Потребитель (nevod) фолдит
    /// поток `inline_witness`'ом в `(dst, Reach)`. Тот же поток позже поедет `ByteFlow` (Правило 9).
    pub fn attach_observe(
        client_iface: &str,
        bpf_bytes: &[u8],
    ) -> Result<(Self, FlowEvents), String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;
        let _ = tc::qdisc_add_clsact(client_iface);
        Self::load_attach(
            &mut bpf,
            "reflex_observe_up",
            client_iface,
            TcAttachType::Ingress,
        )?;
        Self::load_attach(
            &mut bpf,
            "reflex_observe_down",
            client_iface,
            TcAttachType::Egress,
        )?;
        let events = FlowEvents::from_ebpf(&mut bpf)?;
        Ok((
            Self {
                bpf,
                interface: client_iface.to_string(),
            },
            events,
        ))
    }

    /// Фаза 2: ОДИН `Ebpf` под ВЕСЬ inline-датаплейн — `reflex_observe` (наблюдение, eth1 in+eg) +
    /// `reflex_steer` (лифт, eth1 ingress) + `reflex_return` (возврат, nevod0 ingress). Карты ОБЩИЕ,
    /// и это КРИТИЧНО: вердикт witness'а населяет `STEER_TARGETS` (`add_steer_target`), который читает
    /// `reflex_steer`; `CLIENT_MACS` пишет steer, читает return. Раздельная загрузка = изолированные
    /// карты, вердикт не долетит до лифта. Возвращает держатель (Drop отцепит всё) + поток `FlowEvents`.
    /// `client_iface` (eth1) несёт steer+observe; `return_iface` (nevod0) должен СУЩЕСТВОВАТЬ до вызова.
    /// ifindex'ы/MAC'и ставит вызывающий (`set_steer_*`/`set_return_*`), цели — `add_steer_target`.
    pub fn attach_inline(
        client_iface: &str,
        return_iface: &str,
        bpf_bytes: &[u8],
    ) -> Result<(Self, FlowEvents), String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;
        let _ = tc::qdisc_add_clsact(client_iface);
        let _ = tc::qdisc_add_clsact(return_iface);
        // ОДИН фильтр на eth1 ingress: `reflex_steer` САМ эмитит upstream-witness (observe встроен) —
        // TC обрывает цепочку фильтров на `TC_ACT_OK`, два фильтра на одном хуке не сосуществуют
        // (замерено: observe_up рядом со steer не давал событий). observe_down — отдельный хук
        // (egress), конфликта нет. return — на nevod0.
        Self::load_attach(
            &mut bpf,
            "reflex_steer",
            client_iface,
            TcAttachType::Ingress,
        )?;
        Self::load_attach(
            &mut bpf,
            "reflex_observe_down",
            client_iface,
            TcAttachType::Egress,
        )?;
        Self::load_attach(
            &mut bpf,
            "reflex_return",
            return_iface,
            TcAttachType::Ingress,
        )?;
        let events = FlowEvents::from_ebpf(&mut bpf)?;
        Ok((
            Self {
                bpf,
                interface: client_iface.to_string(),
            },
            events,
        ))
    }

    /// Грузит объект ОДИН раз и цепляет ОБА хука круга из ОДНОГО `Ebpf`: `reflex_steer` на INGRESS
    /// `steer_iface` (учит `CLIENT_MACS`) + `reflex_return` на INGRESS `return_iface` (читает её). Карты
    /// ОБЩИЕ — иначе (раздельная загрузка) две изолированные `CLIENT_MACS`, learned-MAC не шарится
    /// (замерено: nevod терминирует, а reflex_return промахивается по dst-MAC → SYNACK=0). `interface` =
    /// steer_iface (для стата/лога). nevod0 (return_iface) должен СУЩЕСТВОВАТЬ до вызова.
    pub fn attach_steer_and_return(
        steer_iface: &str,
        return_iface: &str,
        bpf_bytes: &[u8],
    ) -> Result<Self, String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;
        let _ = tc::qdisc_add_clsact(steer_iface);
        let _ = tc::qdisc_add_clsact(return_iface);
        Self::load_attach(&mut bpf, "reflex_steer", steer_iface, TcAttachType::Ingress)?;
        Self::load_attach(
            &mut bpf,
            "reflex_return",
            return_iface,
            TcAttachType::Ingress,
        )?;
        Ok(Self {
            bpf,
            interface: steer_iface.to_string(),
        })
    }

    fn attach_named(
        interface: &str,
        bpf_bytes: &[u8],
        prog: &str,
        at: TcAttachType,
    ) -> Result<Self, String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;
        let _ = tc::qdisc_add_clsact(interface); // add clsact qdisc (required for tc-bpf)
        Self::load_attach(&mut bpf, prog, interface, at)?;
        Ok(Self {
            bpf,
            interface: interface.to_string(),
        })
    }

    /// Загрузить (verifier) + прицепить одну TC-программу из уже открытого `Ebpf`. Вынесено, чтобы
    /// `attach_steer_and_return` цеплял оба хука из ОДНОГО объекта (общие карты).
    fn load_attach(
        bpf: &mut Ebpf,
        prog: &str,
        interface: &str,
        at: TcAttachType,
    ) -> Result<(), String> {
        let program: &mut SchedClassifier = bpf
            .program_mut(prog)
            .ok_or_else(|| format!("TC program '{prog}' not found in eBPF object"))?
            .try_into()
            .map_err(|e| format!("not a SchedClassifier: {e}"))?;
        program
            .load()
            .map_err(|e| format!("TC program '{prog}' load failed: {e}"))?;
        program
            .attach(interface, at)
            .map_err(|e| format!("TC attach '{prog}' to {interface} failed: {e}"))?;
        Ok(())
    }

    /// MAC моста (br0) для L2-доставки (BL-215 Phase 1): eBPF переписывает dst-MAC целевого кадра на
    /// него → мост отдаёт кадр наверх в локальный стек, а не форвардит по чужому MAC. Без этого
    /// sk_assign на мосту игнорится (кадр не входит в L3). 6 байт в карту `STEER_MAC`.
    pub fn set_steer_mac(&mut self, mac: [u8; 6]) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u8> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("STEER_MAC")
                .ok_or("STEER_MAC map not found")?,
        )
        .map_err(|e| format!("STEER_MAC type mismatch: {e}"))?;

        for (i, b) in mac.iter().enumerate() {
            m.set(i as u32, *b, 0)
                .map_err(|e| format!("STEER_MAC set[{i}]: {e}"))?;
        }
        Ok(())
    }

    /// Пометить dst-IP как цель заворота (BL-213): eBPF заворачивает ЛЮБОЙ TCP-флоу к этому dst в
    /// несущую (per-домен, не per-5-tuple — клиентский порт эфемерен). `dst` в HOST order → network.
    pub fn add_steer_target(&mut self, dst: std::net::Ipv4Addr) -> Result<(), String> {
        let mut targets: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("STEER_TARGETS")
                .ok_or("STEER_TARGETS map not found")?,
        )
        .map_err(|e| format!("STEER_TARGETS type mismatch: {e}"))?;

        targets
            .insert(u32::from_ne_bytes(dst.octets()), 1, 0) // octets = network order байты
            .map_err(|e| format!("STEER_TARGETS insert: {e}"))?;
        Ok(())
    }

    /// PRIOR-множество звонковых CIDR (act-on-prior, BL-235): UDP dst ∈ prefix → ПРОАКТИВНЫЙ лифт в
    /// пол (`serve_udp` политика `PriorFloor`, детерминированно Floor). `net`/`prefix_len` = CIDR
    /// (напр. 91.108.0.0/16 — звонковые релеи телеги). LPM-trie: ключ data = network-order байты (как
    /// STEER_TARGETS), матч по longest-prefix. Зеркало `add_steer_target`, но по диапазону, не /32.
    pub fn add_prior_floor(
        &mut self,
        net: std::net::Ipv4Addr,
        prefix_len: u32,
    ) -> Result<(), String> {
        let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(
            self.bpf
                .map_mut("PRIOR_FLOOR")
                .ok_or("PRIOR_FLOOR map not found")?,
        )
        .map_err(|e| format!("PRIOR_FLOOR type mismatch: {e}"))?;

        let key = Key::new(prefix_len, u32::from_ne_bytes(net.octets()));
        trie.insert(&key, 1u8, 0)
            .map_err(|e| format!("PRIOR_FLOOR insert: {e}"))?;
        Ok(())
    }

    /// Снять dst из PRIOR_FLOOR (реактивная отклейка пола, `NoLeakedFloor`): пульсар-драйвер зовёт на
    /// idle флоу → дальнейшие датаграммы к dst снова идут L2-direct (не приклеен к dst-IP навсегда).
    /// Пара к `add_prior_floor`; `prefix_len` = как при вставке (реактивный флип = /32). Промах ключа
    /// (не было записи) не ошибка — idle мог наступить до флипа.
    pub fn remove_prior_floor(
        &mut self,
        net: std::net::Ipv4Addr,
        prefix_len: u32,
    ) -> Result<(), String> {
        let mut trie: LpmTrie<_, u32, u8> = LpmTrie::try_from(
            self.bpf
                .map_mut("PRIOR_FLOOR")
                .ok_or("PRIOR_FLOOR map not found")?,
        )
        .map_err(|e| format!("PRIOR_FLOOR type mismatch: {e}"))?;

        let key = Key::new(prefix_len, u32::from_ne_bytes(net.octets()));
        match trie.remove(&key) {
            Ok(()) => Ok(()),
            Err(_) => Ok(()), // промах ключа = idle до флипа, не ошибка
        }
    }

    /// Режим лифта: `true` = лифтить ВСЕ HTTPS(443) → SNI решает ловец (домен-ключ, CDN-robust); `false`
    /// = surgical (лишь dst ∈ STEER_TARGETS). Ставится из env `STEER_ALL_443` (`inline_up`).
    pub fn set_steer_all(&mut self, on: bool) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u8> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("STEER_ALL")
                .ok_or("STEER_ALL map not found")?,
        )
        .map_err(|e| format!("STEER_ALL type mismatch: {e}"))?;
        m.set(0, on as u8, 0)
            .map_err(|e| format!("STEER_ALL set: {e}"))?;
        Ok(())
    }

    /// Исключить dst-IP из лифта (egress пола/VLESS-сервер: на :443, но не порт-мечен → в all-443
    /// зациклился бы). Тот же ключ-формат, что `add_steer_target` (network-order байты).
    pub fn add_steer_exclude(&mut self, dst: std::net::Ipv4Addr) -> Result<(), String> {
        let mut m: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("STEER_EXCLUDE")
                .ok_or("STEER_EXCLUDE map not found")?,
        )
        .map_err(|e| format!("STEER_EXCLUDE type mismatch: {e}"))?;
        m.insert(u32::from_ne_bytes(dst.octets()), 1, 0)
            .map_err(|e| format!("STEER_EXCLUDE insert: {e}"))?;
        Ok(())
    }

    /// ifindex устройства несущей (nevod0) для L2-РЕДИРЕКТА (`bpf_redirect`): eBPF отправит целевой
    /// кадр прямо в xmit устройства, минуя ip_rcv/ip_forward → обходит forward→tun дроп и
    /// conntrack-игнор лифтнутых кадров (L2-native, как AF_PACKET). 0 = fallback на MAC-lift.
    pub fn set_steer_ifindex(&mut self, ifindex: u32) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("STEER_IFINDEX")
                .ok_or("STEER_IFINDEX map not found")?,
        )
        .map_err(|e| format!("STEER_IFINDEX type mismatch: {e}"))?;
        m.set(0, ifindex, 0)
            .map_err(|e| format!("STEER_IFINDEX set: {e}"))?;
        Ok(())
    }

    /// ifindex sing-box-tun для UDP-floor (BL-235, tun-двигатель): eBPF редиректит prior-матченную
    /// UDP-датаграмму СЮДА (sing-box несёт VLESS'ом, минуя наш netstack). Ставится ПОСЛЕ старта
    /// sing-box (тот создаёт tun). 0 = tun не готов → prior-UDP не лифтится (fail-open в L2-direct).
    pub fn set_singbox_tun_ifindex(&mut self, ifindex: u32) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("SINGBOX_TUN_IFINDEX")
                .ok_or("SINGBOX_TUN_IFINDEX map not found")?,
        )
        .map_err(|e| format!("SINGBOX_TUN_IFINDEX type mismatch: {e}"))?;
        m.set(0, ifindex, 0)
            .map_err(|e| format!("SINGBOX_TUN_IFINDEX set: {e}"))?;
        Ok(())
    }

    /// Доцепить УЖЕ ЗАГРУЖЕННЫЙ `reflex_return` ко ВТОРОМУ устройству (sing-box-tun) из ТОГО ЖЕ `Ebpf`
    /// (BL-235, tun-двигатель): карты ОБЩИЕ — `CLIENT_MACS` выучен `reflex_steer` на eth1-ingress,
    /// читается возвратом по dst-IP ответа. sing-box пишет ответ пола (сырой L3) в свой tun → он
    /// приходит на INGRESS tun → `reflex_return` клеит Ethernet + `bpf_redirect(eth1)` клиенту (зеркало
    /// возврата с nevod0). Программа уже `load()`'нута (в `attach_inline`) — здесь ТОЛЬКО `attach()`,
    /// повторный `load()` нельзя. Устройство должно СУЩЕСТВОВАТЬ (sing-box поднял tun).
    pub fn attach_return_extra(&mut self, device: &str) -> Result<(), String> {
        let _ = tc::qdisc_add_clsact(device);
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("reflex_return")
            .ok_or("reflex_return not found in eBPF object")?
            .try_into()
            .map_err(|e| format!("not a SchedClassifier: {e}"))?;
        program
            .attach(device, TcAttachType::Ingress)
            .map_err(|e| format!("attach reflex_return to {device} failed: {e}"))?;
        Ok(())
    }

    /// Снапшот RETURN_STATS: [seen, ipv4, last_rc]. `last_rc`=7 → `bpf_redirect(eth1)` успешен; большое
    /// (u64 от отрицательного i64) → change_head/store_bytes вернул ошибку (не смогли склеить L2).
    pub fn return_stats_line(&self) -> Result<String, String> {
        let stats: aya::maps::Array<_, u64> = aya::maps::Array::try_from(
            self.bpf
                .map("RETURN_STATS")
                .ok_or("RETURN_STATS map not found")?,
        )
        .map_err(|e| format!("RETURN_STATS type mismatch: {e}"))?;
        let seen = stats.get(&0, 0).unwrap_or(0);
        let ipv4 = stats.get(&1, 0).unwrap_or(0);
        let rc = stats.get(&2, 0).unwrap_or(0) as i64;
        Ok(format!("return: seen={seen} ipv4={ipv4} last_rc={rc}"))
    }

    /// ifindex устройства НАЗАД к клиенту (eth1, порт клиента) для `reflex_return` (`bpf_redirect(eth1)`).
    pub fn set_return_ifindex(&mut self, ifindex: u32) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u32> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("RETURN_IFINDEX")
                .ok_or("RETURN_IFINDEX map not found")?,
        )
        .map_err(|e| format!("RETURN_IFINDEX type mismatch: {e}"))?;
        m.set(0, ifindex, 0)
            .map_err(|e| format!("RETURN_IFINDEX set: {e}"))?;
        Ok(())
    }

    /// src-MAC обратного кадра = MAC самого eth1 (userspace читает из sysfs) → карта RETURN_SRC_MAC
    /// (6 байт). dst-MAC НЕ отсюда — `reflex_return` берёт его выученным из CLIENT_MACS (портируемо за
    /// любым роутером, без конфига клиента; проекция `MacLearned`). Ставим лишь наш egress-MAC.
    pub fn set_return_src_mac(&mut self, src: [u8; 6]) -> Result<(), String> {
        let mut m: aya::maps::Array<_, u8> = aya::maps::Array::try_from(
            self.bpf
                .map_mut("RETURN_SRC_MAC")
                .ok_or("RETURN_SRC_MAC map not found")?,
        )
        .map_err(|e| format!("RETURN_SRC_MAC type mismatch: {e}"))?;

        for (i, b) in src.iter().enumerate() {
            m.set(i as u32, *b, 0)
                .map_err(|e| format!("RETURN_SRC_MAC set[{i}]: {e}"))?;
        }
        Ok(())
    }

    /// Set action for a flow in the BPF action table.
    pub fn set_flow_action(&mut self, flow_hash: u32, action: FlowAction) -> Result<(), String> {
        let mut action_table: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("ACTION_TABLE")
                .ok_or("ACTION_TABLE map not found")?,
        )
        .map_err(|e| format!("ACTION_TABLE type mismatch: {e}"))?;

        action_table
            .insert(flow_hash, action as u8, 0)
            .map_err(|e| format!("ACTION_TABLE insert failed: {e}"))?;

        Ok(())
    }

    /// Remove action for a flow.
    pub fn clear_flow_action(&mut self, flow_hash: u32) -> Result<(), String> {
        let mut action_table: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("ACTION_TABLE")
                .ok_or("ACTION_TABLE map not found")?,
        )
        .map_err(|e| format!("ACTION_TABLE type mismatch: {e}"))?;

        let _ = action_table.remove(&flow_hash);
        Ok(())
    }

    /// Guarded-заворот целевого флоу в локальную несущую — проекция
    /// `model/wire/TransparentIntercept` (`.tobe`). Ставит `Steer` ЛИШЬ когда несущая
    /// готова принять владение (`carrier_ready`); не готова → снимает запись (Pass =
    /// fail-open, кадр на прозрачном транзите, чёрной дыры нет). Решение — чистый
    /// `steer_fate` (юнит-тесты в `reflex-linux-common`), здесь лишь исполнение (Правило 5).
    /// Звать ТОЛЬКО для целевых флоу — не-цель не доходит сюда (Surgical на уровне вызова).
    ///
    /// Наблюдаемость (Правило 17): типизированный исход `Fate` ВОЗВРАЩАЕТСЯ (структурный порт,
    /// не ThreadLocal) — край мапит в спан, `spanStatusOf`: `Ok(Fate)` нейтрален (оба исхода —
    /// здоровый бизнес: `Owned`=завёрнут, `Transit`=fail-open деградация), `Err` (сбой карты
    /// eBPF) КРАСНИТ. `tracing`-фасад эмитит на месте: `Owned`=debug, fail-open `Transit`=warn
    /// (health-сигнал: цель течёт мимо движка, несущая не готова).
    pub fn steer_target(&mut self, flow_hash: u32, carrier_ready: bool) -> Result<Fate, String> {
        let fate = steer_fate(true, carrier_ready);

        match fate {
            Fate::Owned => {
                self.set_flow_action(flow_hash, FlowAction::Steer)?;
                tracing::debug!(flow_hash, "intercept: заворот в несущую (Owned)");
            }
            Fate::Transit => {
                self.clear_flow_action(flow_hash)?;
                tracing::warn!(
                    flow_hash,
                    "intercept: fail-open, несущая не готова (Transit)"
                );
            }
        }

        Ok(fate)
    }

    /// Снапшот datapath-счётчиков заворота (`STEER_STATS`, Правило 17): по значению на стадию
    /// `try_steer`, индексировано `SteerStat`. Где счётчик = 0, там конвейер обрывается — риг-поллер
    /// печатает это в лог, превращая чёрный ящик eBPF в наблюдаемый конвейер. Read-only, без блокировок.
    pub fn steer_stats(&self) -> Result<[u64; STEER_STAT_SLOTS as usize], String> {
        let stats: aya::maps::Array<_, u64> = aya::maps::Array::try_from(
            self.bpf
                .map("STEER_STATS")
                .ok_or("STEER_STATS map not found")?,
        )
        .map_err(|e| format!("STEER_STATS type mismatch: {e}"))?;

        let mut out = [0u64; STEER_STAT_SLOTS as usize];
        for stat in SteerStat::ALL {
            out[stat as usize] = stats
                .get(&(stat as u32), 0)
                .map_err(|e| format!("STEER_STATS get {}: {e}", stat.label()))?;
        }
        Ok(out)
    }

    /// Одна строка снапшота для лога — `seen=N ipv4_tcp=N … assigned=N` в порядке конвейера.
    pub fn steer_stats_line(&self) -> Result<String, String> {
        let snap = self.steer_stats()?;
        let line = SteerStat::ALL
            .iter()
            .map(|s| format!("{}={}", s.label(), snap[*s as usize]))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(line)
    }

    /// Слить+СБРОСИТЬ UDP-АПЛИНК счётчики (`UDP_FLOW_BYTES`, BL-235): per-dst(сервер) исходящие байты
    /// client→server за ОКНО. Неинвазивный observe — eBPF считает UDP на транзите (НЕ заворачивает,
    /// медиа цела L2-direct), userspace опрашивает раз в окно. `(dst __be32, байты)`; молчащий флоу
    /// исчезает (авто-эвикт). Аплинк = `client_active` сигнал EarnedFloor (шлёт ли клиент сейчас).
    pub fn drain_udp_flow_bytes(&mut self) -> Result<Vec<(u32, u64)>, String> {
        self.drain_u32_u64_map("UDP_FLOW_BYTES")
    }

    /// Слить+СБРОСИТЬ UDP-ДАУНЛИНК счётчики (`UDP_RETURN_BYTES`, BL-235): per-src(сервер) возвратные
    /// байты server→client за ОКНО (eth1-egress). Даунлинк = `sample` EarnedFloor против планки
    /// (сигнал, деградирующий под троттлом). Ключ src симметричен dst-ключу аплинка → джойн по серверу.
    pub fn drain_udp_return_bytes(&mut self) -> Result<Vec<(u32, u64)>, String> {
        self.drain_u32_u64_map("UDP_RETURN_BYTES")
    }

    /// Общий слив-и-сброс `HashMap<u32,u64>`-счётчика окна: собрать ключи ДО мутации (нельзя remove во
    /// время итерации по `keys()`), read+remove по каждому. Недо-счёт на гонке remove↔инкремент
    /// пренебрежим (throughput приблизителен). Молчащий ключ исчезает — авто-эвикт следующего окна.
    fn drain_u32_u64_map(&mut self, name: &str) -> Result<Vec<(u32, u64)>, String> {
        let mut map: aya::maps::HashMap<_, u32, u64> = aya::maps::HashMap::try_from(
            self.bpf
                .map_mut(name)
                .ok_or_else(|| format!("{name} map not found"))?,
        )
        .map_err(|e| format!("{name} type mismatch: {e}"))?;

        let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
        let out = keys
            .into_iter()
            .filter_map(|k| {
                let bytes = map.get(&k, 0).ok()?;
                let _ = map.remove(&k); // сброс окна
                Some((k, bytes))
            })
            .collect();
        Ok(out)
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }
}

/// Async-поток пакет-событий транзита из `RingBuf` FLOW_EVENTS — IO-край witness (Правило 2). eBPF
/// (`reflex_observe`) пишет `FlowEvent`'ы, здесь читаем их async через `AsyncFd` (readable → дренаж
/// кольца пачкой → отдаём по одному). Потеря события при переполнении кольца НЕ рвёт поток: witness
/// идемпотентен к пропущенному не-классифицирующему пакету.
pub struct FlowEvents {
    fd: AsyncFd<RingBuf<MapData>>,
    pending: VecDeque<FlowEvent>,
}

impl FlowEvents {
    fn from_ebpf(bpf: &mut Ebpf) -> Result<Self, String> {
        let map = bpf
            .take_map("FLOW_EVENTS")
            .ok_or("FLOW_EVENTS map not found")?;
        let ring: RingBuf<MapData> =
            RingBuf::try_from(map).map_err(|e| format!("FLOW_EVENTS not a RingBuf: {e}"))?;
        let fd = AsyncFd::new(ring).map_err(|e| format!("AsyncFd(FLOW_EVENTS): {e}"))?;
        Ok(Self {
            fd,
            pending: VecDeque::new(),
        })
    }

    /// Следующее событие транзита. Отдаёт из буфера; пусто → ждёт readable ИЛИ короткий poll-таймаут,
    /// дренит кольцо целиком. Запись короче контракта (`FlowEvent` = фикс-16-байт) игнорится.
    ///
    /// POLL-СТРАХОВКА (не чистый readable): BPF-ringbuf по умолчанию ПОДАВЛЯЕТ epoll-wakeup, если
    /// считает потребителя отстающим (adaptive notification) — чистый `readable().await` тогда спит
    /// вечно, хоть события копятся (замерено на риге: witness замирал после первого батча). Таймаут
    /// гарантирует дренаж кольца не позже `POLL`, даже когда wakeup потерян.
    pub async fn recv(&mut self) -> io::Result<FlowEvent> {
        const POLL: std::time::Duration = std::time::Duration::from_millis(100);
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Ok(ev);
            }
            match tokio::time::timeout(POLL, self.fd.readable_mut()).await {
                Ok(guard) => {
                    let mut guard = guard?;
                    Self::drain(guard.get_inner_mut(), &mut self.pending);
                    guard.clear_ready();
                }
                // Wakeup потерян/подавлен → дренируем напрямую (get_mut, без readiness).
                Err(_elapsed) => Self::drain(self.fd.get_mut(), &mut self.pending),
            }
        }
    }

    /// Дренаж кольца в буфер: все доступные записи → `FlowEvent` (read_unaligned — кольцо не
    /// гарантирует выравнивание). Короче контракта = битая запись, пропускаем.
    fn drain(ring: &mut RingBuf<MapData>, out: &mut VecDeque<FlowEvent>) {
        while let Some(item) = ring.next() {
            if item.len() >= core::mem::size_of::<FlowEvent>() {
                let ev = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const FlowEvent) };
                out.push_back(ev);
            }
        }
    }
}

/// Compute flow hash matching the eBPF program's hash_5tuple.
pub fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u32 {
    const P: u32 = 0x0100_0193;
    let mut h: u32 = 0x811c_9dc5;

    for byte in src_ip
        .to_ne_bytes()
        .iter()
        .chain(dst_ip.to_ne_bytes().iter())
        .chain(src_port.to_ne_bytes().iter())
        .chain(dst_port.to_ne_bytes().iter())
        .chain(core::slice::from_ref(&protocol).iter())
    {
        h ^= *byte as u32;
        h = h.wrapping_mul(P);
    }

    h
}
