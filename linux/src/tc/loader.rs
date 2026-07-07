use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use reflex_linux_common::{steer_fate, Fate, FlowAction, SteerStat, STEER_STAT_SLOTS};

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

    fn attach_named(
        interface: &str,
        bpf_bytes: &[u8],
        prog: &str,
        at: TcAttachType,
    ) -> Result<Self, String> {
        let mut bpf = Ebpf::load(bpf_bytes).map_err(|e| format!("eBPF load failed: {e}"))?;

        // add clsact qdisc (required for tc-bpf)
        let _ = tc::qdisc_add_clsact(interface);

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

        Ok(Self {
            bpf,
            interface: interface.to_string(),
        })
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

    /// Снапшот RETURN_STATS: [seen, ipv4, last_rc]. `last_rc`=7 → редирект успешен; большое (u64 от
    /// отрицательного i64) → bpf_redirect_neigh вернул ошибку (FIB/neigh не резолвится).
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

    /// ifindex устройства НАЗАД к клиенту (br0) для `reflex_return` (`bpf_redirect_neigh`).
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

    pub fn interface(&self) -> &str {
        &self.interface
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
