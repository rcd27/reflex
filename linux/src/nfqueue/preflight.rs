// reflex/linux/src/nfqueue/preflight.rs

use std::fmt;
use std::fs;
use std::process::Command;

use tracing::{info, warn};

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
    /// Ключа `nf_conntrack_acct` нет ВОВСЕ: ядро собрано без `CONFIG_NF_CONNTRACK_ACCT`. Отдельно
    /// от [`NoAccounting`](Self::NoAccounting), потому что лечение РАЗНОЕ: там строка в sysctl,
    /// здесь другое ядро, и `sysctl -w` ответит «unknown key».
    NoAccountingKey,
    /// Ключа `nf_conntrack_timestamp` нет ВОВСЕ — та же развилка, что у
    /// [`NoAccountingKey`](Self::NoAccountingKey). Замерено на типичном роутере: учёт есть и
    /// включён, а этого ключа нет — ядро собрано без `CONFIG_NF_CONNTRACK_TIMESTAMP`.
    NoTimestampsKey,
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
                    "не хватает прав: нет {}. root={is_root}. \
                     Починка: запустить от root либо выдать право двоичному файлу: \
                     sudo setcap 'cap_net_admin,cap_net_raw+ep' <файл>",
                    missing.join(", ")
                )
            }
            Self::NoKernelModule => {
                write!(
                    f,
                    "модуль ядра nfnetlink_queue не загружен. \
                     Починка: sudo modprobe nfnetlink_queue"
                )
            }
            Self::NoConntrack => {
                write!(
                    f,
                    "модуль ядра nf_conntrack не загружен — края не видно вовсе. \
                     Починка: sudo modprobe nf_conntrack"
                )
            }
            Self::NoAccounting => {
                write!(
                    f,
                    "учёт conntrack выключен — счётчики края читаются нулями, и тихий дроп \
                     становится неотличим от «не считали». \
                     Починка: sudo sysctl -w net.netfilter.nf_conntrack_acct=1"
                )
            }
            Self::NoConntrackGlue => {
                write!(
                    f,
                    "ядро собрано без CONFIG_NETFILTER_NETLINK_GLUE_CT — NFQUEUE никогда не \
                     приложит NFQA_CT, и краевые приборы останутся слепы, как conntrack ни \
                     настраивай. \
                     Починка: загрузиться с ядром, где эта опция есть (перезагрузка модуля НЕ \
                     поможет)"
                )
            }
            Self::NoAccountingKey => {
                write!(
                    f,
                    "ядро собрано без CONFIG_NF_CONNTRACK_ACCT — ключа nf_conntrack_acct нет \
                     ВОВСЕ, счётчики края читаются нулями, и тихий дроп неотличим от «не считали». \
                     Починка: ядро с этой опцией (sysctl -w ответит «unknown key» и НЕ поможет)"
                )
            }
            Self::NoTimestampsKey => {
                write!(
                    f,
                    "ядро собрано без CONFIG_NF_CONNTRACK_TIMESTAMP — ключа \
                     nf_conntrack_timestamp нет ВОВСЕ, возраста потока не будет. \
                     Починка: ядро с этой опцией (sysctl -w ответит «unknown key» и НЕ поможет). \
                     Замерено на типичном роутере: ключа нет, хотя учёт (acct) есть и включён"
                )
            }
            Self::NoTimestamps => {
                write!(
                    f,
                    "отметки времени conntrack выключены — возраста потока нет. \
                     Починка: sudo sysctl -w net.netfilter.nf_conntrack_timestamp=1"
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
/// ошибки несёт ЛЕЧЕНИЕ, а не только диагноз («Починка: sudo modprobe …»): первый запуск у нового
/// человека проваливается чаще всего именно здесь, и «Operation not permitted» ему не говорит
/// ничего.
pub fn check() -> Result<(), PreflightError> {
    check_capabilities()?;
    check_kernel_module()?;
    check_conntrack()?;
    check_conntrack_glue()?;
    check_accounting()?;
    // ШТАМПЫ ВРЕМЕНИ — ПОТЕРЯ, А НЕ ОТКАЗ, И РАЗНИЦА ОПЛАЧЕНА ЖИВОЙ КОРОБКОЙ (12.09.2026).
    //
    // Прежде их отсутствие валило запуск целиком. На канарейке (OpenWrt, NanoPi R2S) ядро собрано
    // без `CONFIG_NF_CONNTRACK_TIMESTAMP` — и продукт не поднял НИ ОДНОЙ очереди: ни 250, ни 251,
    // ни 252. Заворот при этом стоял, `bypass` пропускал трафик мимо пустой очереди, и человек
    // видел ровно то, что видел бы без продукта вовсе. Отказ был полным там, где потеря частичная.
    //
    // ЧТО ИМЕННО ТЕРЯЕТСЯ: возраст потока, который conntrack проставляет сам. Его читают краевые
    // приборы (`Throttled`, `Choked`, `heard_ago` в снимке) — им без штампов сказать нечего.
    //
    // ЧТО ОСТАЁТСЯ: приборы тишины и повтора (`Silence`, `Retransmit`, `Swallowed`) меряют по
    // НАШИМ часам — моменту прихода пакета в цикл, — и conntrack им не нужен вовсе. Именно они
    // ведут лечение; краевые лишь обогащают картину.
    //
    // ЦЕНА НАЗВАНА ГРОМКО, а не проглочена: без штампов часть приборов слепа, и знать это обязан
    // тот, кто читает их молчание. Но слепой прибор — не повод отнимать у человека интернет.
    if let Err(why) = check_timestamps() {
        warn!("NFQUEUE preflight: {why} — краевые приборы будут слепы, лечение продолжается");
    }
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
/// ЧТО СКАЗАЛ КЛЮЧ. Три состояния, не два, и это тот же §7, что у приборов: «выключено» и «ключа
/// НЕТ ВОВСЕ» лечатся РАЗНЫМ, и слить их значит послать человека выполнять невыполнимое.
///
/// Замер, которым это оплачено (роутер разработчика, ядро 6.6 aarch64): `nf_conntrack_acct` есть и
/// включён, а ключа `nf_conntrack_timestamp` НЕТ — ядро собрано без `CONFIG_NF_CONNTRACK_TIMESTAMP`.
/// Прежний код схлопывал `Err(ENOENT)` и `Ok("0")` в один `false`, и лечение предлагалось одно:
/// `sysctl -w …=1`. На этой машине оно отвечает «unknown key», и человек остаётся без движка и без
/// понимания почему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Knob {
    /// Ключ есть и включён.
    On,
    /// Ключ есть и выключен — чинится одной строкой.
    Off,
    /// Ключа нет: ядро собрано без него. `sysctl -w` не поможет, нужна пересборка либо другое ядро.
    Absent,
}

fn sysctl(leaf: &str) -> Knob {
    match fs::read_to_string(format!("/proc/sys/net/netfilter/{leaf}")) {
        Err(_no_key) => Knob::Absent,
        Ok(value) => match value.trim() == "1" {
            true => Knob::On,
            false => Knob::Off,
        },
    }
}

fn check_accounting() -> Result<(), PreflightError> {
    match sysctl("nf_conntrack_acct") {
        Knob::On => Ok(()),
        Knob::Off => Err(PreflightError::NoAccounting),
        Knob::Absent => Err(PreflightError::NoAccountingKey),
    }
}

fn check_timestamps() -> Result<(), PreflightError> {
    match sysctl("nf_conntrack_timestamp") {
        Knob::On => Ok(()),
        Knob::Off => Err(PreflightError::NoTimestamps),
        Knob::Absent => Err(PreflightError::NoTimestampsKey),
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

    /// ПРЕДМЕТ: «ВЫКЛЮЧЕНО» И «КЛЮЧА НЕТ» — РАЗНЫЕ БЕДЫ, И ЛЕЧЕНИЕ У НИХ РАЗНОЕ.
    ///
    /// Прежде `Err(ENOENT)` и `Ok("0")` схлопывались в один `false`, и человеку предлагалось одно
    /// лечение — `sysctl -w …=1`. На ядре, собранном без опции, оно отвечает «unknown key»: человек
    /// остаётся без движка и без понимания почему. Замер потребителя на роутере: `acct` есть и
    /// включён, ключа `timestamp` нет вовсе.
    ///
    /// Тот же §7, что у приборов: «выключено» — наблюдение, «ключа нет» — другое наблюдение, и
    /// слить их значит выдать одно за другое.
    #[test]
    fn выключенное_и_несобранное_лечатся_разным() {
        let off = format!("{}", PreflightError::NoTimestamps);
        let absent = format!("{}", PreflightError::NoTimestampsKey);

        assert!(off.contains("sysctl -w"), "выключенное чинится строкой: {off}");
        assert!(
            absent.contains("CONFIG_NF_CONNTRACK_TIMESTAMP"),
            "несобранное называет ОПЦИЮ ЯДРА: {absent}"
        );
        assert!(
            absent.contains("НЕ поможет"),
            "и прямо говорит, что sysctl тут бесполезен: {absent}"
        );
        assert_ne!(off, absent, "два лечения — два текста");

        // Та же пара у учёта: развилка одна на оба ключа, и разойтись они не должны.
        let absent_acct = format!("{}", PreflightError::NoAccountingKey);
        assert!(absent_acct.contains("CONFIG_NF_CONNTRACK_ACCT"));
        assert!(absent_acct.contains("НЕ поможет"));
    }

    /// Тройка состояний ключа снимается ОДНИМ законом — иначе два чтения разошлись бы в том, что
    /// считать выключенным. Файла с таким именем не существует ни на одной машине, потому
    /// `Absent` здесь проверяется настоящим чтением, а не подделкой.
    #[test]
    fn ключа_которого_нет_читается_как_отсутствие() {
        assert_eq!(sysctl("nf_conntrack_нет_такого_ключа"), Knob::Absent);
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
        assert!(
            said.contains("перезагрузка модуля НЕ поможет"),
            "названо, чего делать НЕ надо: {said}"
        );
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
