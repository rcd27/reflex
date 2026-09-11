// reflex/linux/src/nfqueue/preflight.rs

use std::fmt;
use std::fs;
use std::process::Command;

use tracing::info;

#[derive(Debug)]
pub enum PreflightError {
    NoCapabilities {
        has_net_admin: bool,
        has_net_raw: bool,
        is_root: bool,
    },
    NoKernelModule,
    /// Модуль `nf_conntrack` не загружен — вида края нет вовсе.
    NoConntrack,
    /// Учёт conntrack выключен: счётчики читаются нулём, и «цель не ответила» неотличимо от «мы не
    /// считали». Разные последствия с `NoTimestamps`, потому отдельная буква.
    NoAccounting,
    /// Штампы времени conntrack выключены — возраста потока нет.
    NoTimestamps,
    /// Ядро собрано БЕЗ `CONFIG_NETFILTER_NETLINK_GLUE_CT`: очередь не приложит `NFQA_CT` к пакету,
    /// и вид края не приедет НИКОГДА — сколько бы conntrack ни был загружен и настроен.
    ///
    /// Отдельная буква от [`NoConntrack`](Self::NoConntrack), потому что лечение другое и дороже:
    /// модуль догружается одной командой, а glue — опция СБОРКИ ядра, и чинится сменой ядра.
    /// Слить их значило бы отправить человека грузить модуль, который уже загружен.
    NoConntrackGlue,
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCapabilities {
                has_net_admin,
                has_net_raw,
                is_root,
            } => {
                let mut missing = Vec::new();
                if !has_net_admin {
                    missing.push("CAP_NET_ADMIN");
                }
                if !has_net_raw {
                    missing.push("CAP_NET_RAW");
                }
                write!(
                    f,
                    "insufficient privileges: missing {}. is_root={is_root}. \
                     Fix: run as root, or: sudo setcap 'cap_net_admin,cap_net_raw+ep' <binary>",
                    missing.join(", ")
                )
            }
            Self::NoKernelModule => {
                write!(
                    f,
                    "kernel module nfnetlink_queue not loaded. \
                     Fix: sudo modprobe nfnetlink_queue"
                )
            }
            Self::NoConntrack => {
                write!(
                    f,
                    "kernel module nf_conntrack not loaded — no edge view. \
                     Fix: sudo modprobe nf_conntrack"
                )
            }
            Self::NoAccounting => {
                write!(
                    f,
                    "conntrack accounting off — edge counters read zero, a silent drop is \
                     indistinguishable from 'not counted'. \
                     Fix: sudo sysctl -w net.netfilter.nf_conntrack_acct=1"
                )
            }
            Self::NoConntrackGlue => {
                write!(
                    f,
                    "kernel built without CONFIG_NETFILTER_NETLINK_GLUE_CT — NFQUEUE will never \
                     attach NFQA_CT, so edge probes stay blind no matter how conntrack is tuned. \
                     Fix: boot a kernel with that option (module reload will NOT help)"
                )
            }
            Self::NoTimestamps => {
                write!(
                    f,
                    "conntrack timestamps off — no flow age. \
                     Fix: sudo sysctl -w net.netfilter.nf_conntrack_timestamp=1"
                )
            }
        }
    }
}

impl std::error::Error for PreflightError {}

/// Годится ли МАШИНА для очереди: права, модули ядра, учёт conntrack.
///
/// Зовётся носителем при открытии (`IntoCarrier::open`), а не циклом: предпосылка проверяется до
/// первого пакета, иначе потребитель узнаёт о ней голым `errno` из `socket(2)`. Каждая ветка
/// ошибки несёт ЛЕЧЕНИЕ, а не только диагноз («Fix: sudo modprobe …»): первый запуск у нового
/// человека проваливается чаще всего именно здесь, и «Operation not permitted» ему не говорит
/// ничего.
pub fn check() -> Result<(), PreflightError> {
    check_capabilities()?;
    check_kernel_module()?;
    check_conntrack()?;
    check_conntrack_glue()?;
    check_accounting()?;
    check_timestamps()?;
    info!("NFQUEUE preflight checks passed");
    Ok(())
}

/// Модуль conntrack загружен — без него `NFQA_CT` не приедет, и весь путь края мёртв.
fn check_conntrack() -> Result<(), PreflightError> {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    match modules.lines().any(|line| line.starts_with("nf_conntrack ")) {
        true => Ok(()),
        false => Err(PreflightError::NoConntrack),
    }
}

/// ЧТО ЯДРО ГОВОРИТ О `CONFIG_NETFILTER_NETLINK_GLUE_CT` — три клетки, не две (§7).
///
/// Опция это СБОРОЧНАЯ, не sysctl: спросить работающее ядро о ней нечем, читается она из копии
/// конфига. Копии может не быть вовсе (контейнер, урезанный образ), и вот тогда честный ответ —
/// `Unknown`, а не «плохо»: «не смотрели» и «смотрели и нет» имеют разную цену, и отказывать по
/// первому значило бы не пускать на машины, где всё в порядке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glue {
    /// Конфиг прочитан, опция включена.
    On,
    /// Конфиг прочитан, опции нет или она `n` — край не приедет, и это доказано.
    Off,
    /// Конфига не нашлось. Судить не о чем; молчать об этом нельзя, потому клетка своя.
    Unknown,
}

/// Спросить ядро о glue. Публично НАРОЧНО: вызывающий вправе узнать `Unknown` и решить сам —
/// `check` на неизвестности не отказывает, а тот, кто ставит краевые приборы, может захотеть знать.
pub fn glue_ct() -> Glue {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let config = fs::read_to_string("/proc/config.gz")
        .ok()
        .or_else(|| fs::read_to_string(format!("/boot/config-{}", release.trim())).ok());
    match config {
        None => Glue::Unknown,
        Some(text) => match text
            .lines()
            .any(|line| line.trim() == "CONFIG_NETFILTER_NETLINK_GLUE_CT=y")
        {
            true => Glue::On,
            false => Glue::Off,
        },
    }
}

/// Отказ ТОЛЬКО при доказанном отсутствии. `Unknown` пропускается — и это не мягкость, а §7:
/// наказывать за то, что мы не смогли посмотреть, значит судить о подопытном по беде стенда.
///
/// Цена пропуска названа: на ядре без glue краевые приборы будут читать марку нулём и молчать, а
/// молчание читается как «беды нет». Ловится это первым же прогоном (`NFQA_CT` не приедет ни
/// разу), но не здесь.
fn check_conntrack_glue() -> Result<(), PreflightError> {
    check_glue(glue_ct())
}

/// Решение ОТДЕЛЬНО от чтения мира: так его можно предъявить всеми тремя клетками, не собирая
/// ядер без glue. Тот же приём, что у `asked` в терминале очереди (§9: выше значения, ниже мир).
fn check_glue(glue: Glue) -> Result<(), PreflightError> {
    match glue {
        Glue::Off => Err(PreflightError::NoConntrackGlue),
        Glue::On | Glue::Unknown => Ok(()),
    }
}

/// Sysctl включён (`1`). Отсутствие файла — тоже отказ: считать «включено по умолчанию» нельзя,
/// оба по умолчанию ВЫКЛЮЧЕНЫ.
fn sysctl_on(leaf: &str) -> bool {
    fs::read_to_string(format!("/proc/sys/net/netfilter/{leaf}"))
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn check_accounting() -> Result<(), PreflightError> {
    match sysctl_on("nf_conntrack_acct") {
        true => Ok(()),
        false => Err(PreflightError::NoAccounting),
    }
}

fn check_timestamps() -> Result<(), PreflightError> {
    match sysctl_on("nf_conntrack_timestamp") {
        true => Ok(()),
        false => Err(PreflightError::NoTimestamps),
    }
}

fn check_capabilities() -> Result<(), PreflightError> {
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        return Ok(());
    }

    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let eff_hex = status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .unwrap_or(0);

    let has_net_admin = eff_hex & (1 << 12) != 0;
    let has_net_raw = eff_hex & (1 << 13) != 0;

    if has_net_admin && has_net_raw {
        Ok(())
    } else {
        Err(PreflightError::NoCapabilities {
            has_net_admin,
            has_net_raw,
            is_root,
        })
    }
}

fn check_kernel_module() -> Result<(), PreflightError> {
    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    if modules.contains("nfnetlink_queue") {
        return Ok(());
    }

    let _ = Command::new("modprobe").arg("nfnetlink_queue").output();

    let modules = fs::read_to_string("/proc/modules").unwrap_or_default();
    if modules.contains("nfnetlink_queue") {
        info!("loaded nfnetlink_queue kernel module");
        Ok(())
    } else {
        Err(PreflightError::NoKernelModule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_preflight_error_readable() {
        let err = PreflightError::NoCapabilities {
            has_net_admin: false,
            has_net_raw: true,
            is_root: false,
        };
        let msg = format!("{err}");
        assert!(msg.contains("CAP_NET_ADMIN"));
        assert!(!msg.contains("CAP_NET_RAW"));
    }

    #[test]
    fn format_preflight_error_module() {
        let err = PreflightError::NoKernelModule;
        let msg = format!("{err}");
        assert!(msg.contains("nfnetlink_queue"));
    }

    /// Выключенный acct — факт о машине, и человеку говорят, ЧЕМ его включить: без счётчиков приборы
    /// края видят нули при зелёной сборке.
    #[test]
    fn accounting_error_names_the_fix() {
        let message = format!("{}", PreflightError::NoAccounting);
        assert!(message.contains("nf_conntrack_acct"));
        assert!(message.contains("sysctl"), "рецепт починки, а не констатация");
    }

    /// Оба sysctl названы РАЗДЕЛЬНО: у них разные последствия (без acct слепнут счётчики, без
    /// timestamp нет возраста), и рецепт у каждого свой.
    #[test]
    fn accounting_and_timestamps_are_named_separately() {
        assert!(format!("{}", PreflightError::NoAccounting).contains("nf_conntrack_acct"));
        assert!(format!("{}", PreflightError::NoTimestamps).contains("nf_conntrack_timestamp"));
    }

}

#[cfg(test)]
mod glue_tests {
    use super::*;

    /// ТРИ КЛЕТКИ, НЕ ДВЕ, И ТРЕТЬЯ НЕ ОТКАЗ.
    ///
    /// `Unknown` обязан пропускать: конфига ядра может не быть вовсе (контейнер, урезанный образ),
    /// и отказывать по нечитаемому файлу значило бы не пускать на машины, где всё в порядке, —
    /// судить о подопытном по беде стенда (§7).
    #[test]
    fn неизвестность_не_есть_отказ() {
        assert!(
            matches!(check_glue(Glue::Unknown), Ok(())),
            "не смогли посмотреть — не повод не пустить"
        );
        assert!(matches!(check_glue(Glue::On), Ok(())));
        assert!(
            matches!(check_glue(Glue::Off), Err(PreflightError::NoConntrackGlue)),
            "доказанное отсутствие — отказ, и отказ со СВОИМ именем"
        );
    }

    /// ЛЕЧЕНИЕ У ДВУХ БЕД РАЗНОЕ, И ТЕКСТ ОБЯЗАН ЭТО СКАЗАТЬ.
    ///
    /// `NoConntrack` чинится `modprobe`, `NoConntrackGlue` — только сменой ядра. Отправить
    /// человека грузить уже загруженный модуль значит потратить его вечер; потому сообщение
    /// прямо говорит, что перезагрузка модуля НЕ поможет.
    #[test]
    fn отказ_по_glue_называет_своё_лечение_а_не_чужое() {
        let said = format!("{}", PreflightError::NoConntrackGlue);
        assert!(said.contains("CONFIG_NETFILTER_NETLINK_GLUE_CT"), "названа опция: {said}");
        assert!(said.contains("module reload will NOT help"), "названо, чего делать НЕ надо: {said}");
        assert!(
            !format!("{}", PreflightError::NoConntrack).contains("GLUE"),
            "и соседний отказ этой опции не поминает — иначе лечения слились бы"
        );
    }

    /// На ЭТОЙ машине конфиг читается (ядро Ubuntu кладёт `/boot/config-*`), и glue включён.
    /// Тест держит не свойство мира, а то, что ЧТЕНИЕ РАБОТАЕТ: сломай путь — и `glue_ct` начнёт
    /// всегда отвечать `Unknown`, то есть проверка станет вечно зелёной и бесполезной.
    #[test]
    fn чтение_конфига_ядра_живо_а_не_всегда_unknown() {
        assert_ne!(
            glue_ct(),
            Glue::Unknown,
            "конфиг ядра не прочёлся ни по одному пути — проверка выродилась в вечное «не знаю»"
        );
    }
}
