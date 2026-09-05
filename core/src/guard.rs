/// Report from cleanup_stale() — how many orphaned resources were removed.
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    pub rules_removed: usize,
    pub routes_removed: usize,
}

/// Cross-platform firewall lifecycle contract.
///
/// Implementations: NfqGuard (Linux/iptables), pf (macOS), WinDivert (Windows).
///
/// # Контракт
///
/// * `install()` ставит правила с семантикой пропуска (мёртвый страж ⟹ трафик идёт);
/// * реализация ОБЯЗАНА нести `Drop`, снимающий всё поставленное, — и это требование сделано
///   ограничением, а не прозой (см. ниже);
/// * `cleanup_stale()` снимает осиротевшие правила, ничего не устанавливая.
///
/// # Почему `Drop` стоит в супертрейтах, а не в комментарии (05.09.2026)
///
/// Здесь было написано словами: «Implementors MUST also impl `Drop`». Обе живые реализации
/// требование исполняли, так что живого дефекта не было, — но исполняли они его ВНИМАНИЕМ автора.
/// Следующая (в этом же доке названа WinDivert) могла бы не исполнить, и не сказал бы никто:
/// страж без деструктора собирается, ставит правила и оставляет их в ядре навсегда.
///
/// `Drop` в границе означает буквально «у типа есть собственный `impl Drop`» — ровно то, что
/// требовала проза. Чего оно НЕ означает: что тело деструктора действительно снимает правила.
/// Это остаётся за законом, не за типом, и разделение то же, что у способностей бэкенда: тип
/// убивает пустое заявление, закон — ложное.
///
/// # Чего не закрывает и `Drop`
///
/// `SIGKILL` не запускает деструкторов НИКОГДА, а под `docker` это штатный путь остановки:
/// `docker stop` шлёт TERM и через таймаут KILL. То же у OOM-killer'а. Оттого
/// [`cleanup_stale`](Self::cleanup_stale) — не запасной выход на экзотику, а вторая половина
/// уборки, нужная в обычном рабочем цикле.
///
/// ```compile_fail,E0277
/// use reflex_core::guard::{CleanupReport, TrafficGuard};
///
/// // Страж, который поставит правила и не снимет их никогда: `Drop` не реализован.
/// struct Leaky;
/// impl TrafficGuard for Leaky {
///     type Rules = ();
///     type Error = std::io::Error;
///     fn install(_rules: ()) -> Result<Self, Self::Error> { Ok(Leaky) }
///     fn cleanup_stale() -> Result<CleanupReport, Self::Error> { Ok(CleanupReport::default()) }
/// }
/// ```
// ЛИНТ `drop_bounds` ЗДЕСЬ НЕПРИМЕНИМ, И ЭТО РАЗБОР, А НЕ ГЛУШЕНИЕ. Он заведён против границ
// `T: Drop`, поставленных в надежде «этот тип что-то освобождает» — надежда ложная, потому что
// освобождение бывает и без собственного `impl Drop` (drop glue полей). Здесь требуется ровно
// обратное и ровно то, что граница даёт буквально: у реализации ОБЯЗАН быть СВОЙ `impl Drop`.
// Пустой он или нет — вопрос закона, а не типа.
#[allow(drop_bounds)]
pub trait TrafficGuard: Send + Sync + Sized + Drop {
    type Rules;
    type Error: std::error::Error;

    /// Install firewall rules with bypass semantics.
    /// If orphaned rules from a previous run are detected, remove them first.
    fn install(rules: Self::Rules) -> Result<Self, Self::Error>;

    /// Remove orphaned rules without installing new ones.
    /// For `--cleanup` CLI and startup recovery.
    fn cleanup_stale() -> Result<CleanupReport, Self::Error>;
}
