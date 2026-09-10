//! Подписи WinDivert и Win32-примитивы, нужные для приёма СО СРОКОМ (`OVERLAPPED` +
//! `WaitForSingleObject` — у `WinDivertRecvEx` своего таймаута нет, это выверено чтением подписи,
//! не догадано, см. докблок крейта).
//!
//! ГЕЙТ ПО МОДУЛЮ (`lib.rs`) СТОИТ НА `carrier`, А НЕ НА ЭТОМ ФАЙЛЕ ЦЕЛИКОМ: два `extern "system"`
//! блока ниже (WinDivert.dll, kernel32.dll) — код, линковаться которому не с чем нигде, кроме
//! Windows, и они помечены `#[cfg(windows)]` сами; но раскладка `WINDIVERT_ADDRESS` — ЧИСТЫЕ ДАННЫЕ
//! (`#[repr(C)]`, ноль unsafe, ноль линковки), и оставлена ВНЕ гейта нарочно: тест модуля ниже
//! прогоняет арифметику битового поля на Linux ПРЯМО СЕЙЧАС — единственный кусок этого крейта,
//! который бежит здесь, а не только собирается под чужой таргет (докблок крейта называет это
//! прямо: свидетель формы бежит редко где, и там, где бежит, — не спрятан за гейтом заодно с FFI).
//!
//! ОТКУДА ВЗЯТО (не по памяти — по прямому чтению источника 10.09.2026, см. докблок крейта раздел
//! «что выверено, что догадано» — здесь только КООРДИНАТЫ источников, само разделение там):
//! * подписи `WinDivertOpen`/`WinDivertRecvEx`/`WinDivertSend`/`WinDivertClose`, раскладка
//!   `WINDIVERT_ADDRESS`/`WINDIVERT_DATA_NETWORK`, слои (`WINDIVERT_LAYER`) — дословно из
//!   `include/windivert.h`, репозиторий `github.com/basil00/WinDivert`, ветка `master`;
//! * имя библиотеки для линковки (`WinDivert`, без суффикса разрядности) — из `dll/windivert.def`
//!   того же снимка (`LIBRARY WinDivert`, экспорт без `@N`-декорации — актуально для x86_64, на
//!   который здесь единственно и смотрим);
//! * коды ошибок `ERROR_INSUFFICIENT_BUFFER`(122)/`ERROR_NO_DATA`(232) — из `doc/windivert.html`
//!   того же снимка (документация `WinDivertRecv`/`WinDivertShutdown`);
//! * `OVERLAPPED`, `CreateEventW`, `WaitForSingleObject` (код `WAIT_OBJECT_0`=0; `WAIT_TIMEOUT`=258
//!   сверен там же, но в объявлениях его нет — почему, сказано у `WAIT_OBJECT_0`),
//!   `GetOverlappedResult`, `CloseHandle`, `CancelIoEx`, `GetLastError`,
//!   `ERROR_IO_PENDING`=997 — из learn.microsoft.com (статьи Win32 API соответствующих функций и
//!   `debug/system-error-codes--500-999-`), не по памяти.
//!
//! СВОИ ОБЪЯВЛЕНИЯ, А НЕ ЧУЖОЙ КРЕЙТ-ОБЁРТКА (ни `windows-sys`, ни сторонний `windivert`-байндинг):
//! та же причина, по которой `linux`-крейт пишет свой сокет к очереди вместо стороннего `nfq`
//! (`linux/src/queue/mod.rs`: «крейт `nfq`... глушит `ENOBUFS`, а нам переполнение нужно буквой») —
//! WinDivert-специфика здесь ничья, кроме наша, а горстка Win32-примитивов уровня ядра (HANDLE,
//! OVERLAPPED, ожидание) не стоит внешней зависимости, когда сигнатуры стабильны с Windows XP и
//! выверены по первоисточнику.

// ЭТИ ИМЕНА — ЧУЖОЙ ПОТРЕБИТЕЛЬ НА ЭТОЙ ПЛАТФОРМЕ ОТСУТСТВУЕТ, А НЕ ИМ НЕ ПОЛЬЗУЮТСЯ: `carrier.rs`
// (единственный, кто зовёт `WinDivertOpen`/`WinDivertRecvEx`/`Overlapped`/коды ожидания) собирается
// только под `#[cfg(windows)]` (`lib.rs`). На Windows каждое из этих имён используется — проверено
// прогоном (`cargo check -p reflex-windivert --target x86_64-pc-windows-msvc` → ноль предупреждений,
// отчёт задачи 12); здесь, на Linux, `dead_code` увидел бы ровно тот код, которому здесь и положено
// быть неисполняемым (докблок крейта: «живьём здесь ничто не побежит»), и заглушить лгущее
// предупреждение — честнее, чем оставить его расти с каждым новым Win32-примитивом.
#![cfg_attr(not(windows), allow(dead_code))]

use std::ffi::c_void;

pub type Handle = *mut c_void;
pub type Bool = i32;

pub const TRUE: Bool = 1;
pub const FALSE: Bool = 0;
/// `INVALID_HANDLE_VALUE` — `(HANDLE) -1`, возврат `WinDivertOpen` при отказе.
pub const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

pub const WAIT_OBJECT_0: u32 = 0;
/// `WAIT_TIMEOUT`=258 объявления ЗДЕСЬ НЕТ НАРОЧНО. Ждущий (`carrier.rs`) разбирает по имени один
/// исход — `WAIT_OBJECT_0`; честный выход срока и отказ самого ожидания он обрабатывает ОДИНАКОВО
/// (отменить свой запрос и дождаться его завершения), и арм `ffi::WAIT_TIMEOUT | _` обещал бы
/// различение, которого нет: имя из арма прочтёт тот, кто станет их различать, и решит, что работа
/// уже сделана. Понадобится различить — константа вернётся вместе с разной работой, а не раньше.
pub const ERROR_IO_PENDING: u32 = 997;

// ─── WinDivert (include/windivert.h) ──────────────────────────────────────────────────────────

/// `WINDIVERT_LAYER` — дословно из заголовка. Этот носитель открывается только на `Network`:
/// единственный слой (вместе с `NetworkForward`, который сюда не нужен), поддерживающий и захват,
/// и инъекцию (`doc/windivert.html` §5.7 WinDivertSend: «Only the WINDIVERT_LAYER_NETWORK and
/// WINDIVERT_LAYER_NETWORK_FORWARD layers support packet injection»); прочие варианты перечислены
/// ради полноты подписи, носитель их не использует — отсюда `#[allow(dead_code)]` на неиспользуемых
/// вариантах: они называют полный словарь `WINDIVERT_LAYER`, а не то, чем пользуется этот крейт.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDivertLayer {
    Network = 0,
    #[allow(dead_code)]
    NetworkForward = 1,
    #[allow(dead_code)]
    Flow = 2,
    #[allow(dead_code)]
    Socket = 3,
    #[allow(dead_code)]
    Reflect = 4,
}

/// Флаги `WinDivertOpen`. Этому носителю (захват И инъекция через один хэндл, докблок
/// `carrier.rs`) не нужен ни один — полный список см. в заголовке (`WINDIVERT_FLAG_SNIFF` и др.).
pub const WINDIVERT_FLAG_NONE: u64 = 0;

/// Наибольший пакет, который в принципе может прийти (`WINDIVERT_MTU_MAX` заголовка: `40 +
/// 0xFFFF`) — размер буфера приёма, чтобы `ERROR_INSUFFICIENT_BUFFER` не мог возникнуть по нашей
/// вине (усечение буфера — не то же самое, что дыра провода, докблок `carrier.rs`).
pub const WINDIVERT_MTU_MAX: usize = 40 + 0xFFFF;

/// `WINDIVERT_DATA_NETWORK` — данные слоя `Network` внутри union'а `WINDIVERT_ADDRESS`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinDivertDataNetwork {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}

/// `WINDIVERT_ADDRESS` — раскладка байт ДОСЛОВНО по заголовку:
/// `INT64 Timestamp; UINT32 Layer:8,Event:8,Sniffed:1,Outbound:1,Loopback:1,Impostor:1,IPv6:1,
/// IPChecksum:1,TCPChecksum:1,UDPChecksum:1,Reserved1:8; UINT32 Reserved2; union{...}[64 байта]` —
/// итого 80 байт (8+4+4+64), это же число и проверяет `size_of` в тесте модуля.
///
/// БИТОВОЕ ПОЛЕ ЗАМЕНЕНО ПЛОСКИМ `u32` (`flags`): Rust не даёт `#[repr(C)]`-совместимых битовых
/// полей языком. Раскладка бит внутри `flags` — МСВ-упаковка смежных битовых полей ОДНОГО целого
/// типа: младший бит вперёд, поля занимают биты в порядке объявления (свойство АВС компилятора,
/// которым собран сам драйвер, а не гарантия языка Си, но именно оно и определяет ABI, с которым
/// нужно совпасть). Раскладка НИГДЕ не прогнана (свидетель формы бежит только под `cargo check`,
/// докблок крейта) — единственный бит, которым этот крейт пользуется (`Outbound`, №17,
/// `set_outbound`/`outbound`), не лежит на пути, который называет доктест, поэтому и не входит в
/// «предъявлено мутацией»; назван в «что догадано» докблока крейта отдельно от ВЫВЕРЕННЫХ полей.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    flags: u32,
    reserved2: u32,
    /// `union { Network; Flow; Socket; Reflect; Reserved3: [u8;64] }`. Слой этого носителя всегда
    /// `Network` — храним как непрозрачные байты и читаем/пишем ТОЛЬКО первые 8 (`WinDivertDataNetwork`)
    /// через `network`/`set_network`; конструировать `Flow`/`Socket`/`Reflect` незачем, носитель их
    /// не открывает.
    union_data: [u8; 64],
}

impl WinDivertAddress {
    /// Обнулённый адрес — стартовая точка для КАЖДОГО приёма (`WinDivertRecvEx` пишет его сам) и
    /// для синтетического адреса инъекции (`Sink::emit`, `carrier.rs`), где заполнить приходится
    /// вручную.
    pub fn zeroed() -> Self {
        WinDivertAddress {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            union_data: [0u8; 64],
        }
    }

    /// Бит 17 (`flags`) — направление пакета. Читается у ПРИНЯТОГО адреса (для симметрии с
    /// `set_outbound`; сегодня этим носителем не используется — направление принятого пакета в
    /// `serve` не читается, докблок `carrier.rs`).
    #[allow(dead_code)]
    pub fn outbound(&self) -> bool {
        (self.flags >> 17) & 1 != 0
    }

    /// Задать направление для СИНТЕТИЧЕСКОГО адреса (инъекция, не изъятый пакет — у изъятого
    /// направление уже стоит тем, каким его увидел драйвер, и трогать его незачем).
    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.flags |= 1 << 17;
        } else {
            self.flags &= !(1u32 << 17);
        }
    }

    /// Данные слоя `Network` — копия первых 8 байт union'а, не ссылка: `repr(C)`-union Rust'а
    /// потребовал бы `unsafe` на каждое чтение поля, а копия 8 байт дешева и не расширяет
    /// unsafe-поверхность (ту же цену называет докблок `core::local` про разбор пятёрки).
    #[allow(dead_code)]
    pub fn network(&self) -> WinDivertDataNetwork {
        WinDivertDataNetwork {
            if_idx: u32::from_ne_bytes(self.union_data[0..4].try_into().unwrap()),
            sub_if_idx: u32::from_ne_bytes(self.union_data[4..8].try_into().unwrap()),
        }
    }

    #[allow(dead_code)]
    pub fn set_network(&mut self, net: WinDivertDataNetwork) {
        self.union_data[0..4].copy_from_slice(&net.if_idx.to_ne_bytes());
        self.union_data[4..8].copy_from_slice(&net.sub_if_idx.to_ne_bytes());
    }
}

#[cfg(windows)]
#[link(name = "WinDivert")]
extern "system" {
    pub fn WinDivertOpen(
        filter: *const std::ffi::c_char,
        layer: WinDivertLayer,
        priority: i16,
        flags: u64,
    ) -> Handle;

    pub fn WinDivertRecvEx(
        handle: Handle,
        p_packet: *mut c_void,
        packet_len: u32,
        p_recv_len: *mut u32,
        flags: u64,
        p_addr: *mut WinDivertAddress,
        p_addr_len: *mut u32,
        lp_overlapped: *mut Overlapped,
    ) -> Bool;

    pub fn WinDivertSend(
        handle: Handle,
        p_packet: *const c_void,
        packet_len: u32,
        p_send_len: *mut u32,
        p_addr: *const WinDivertAddress,
    ) -> Bool;

    pub fn WinDivertClose(handle: Handle) -> Bool;
}

// ─── Win32: OVERLAPPED I/O и синхронизация (minwinbase.h / synchapi.h / ioapiset.h) ───────────

/// `OVERLAPPED` — раскладка дословно по `learn.microsoft.com/.../ns-minwinbase-overlapped`:
/// `ULONG_PTR Internal; ULONG_PTR InternalHigh; union{struct{DWORD Offset,OffsetHigh;} Pointer;}
/// HANDLE hEvent;`. Используем ветку `Offset`/`OffsetHigh` union'а (не `Pointer`) — те же 8 байт,
/// но полям есть плоские имена; оба поля здесь всегда нулевые (не файловый сдвиг — WinDivert
/// оффсетов не знает, докблок MS: «Otherwise, this member must be zero»).
#[repr(C)]
pub struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    pub h_event: Handle,
}

impl Overlapped {
    /// Ручной сброс (`bManualReset = TRUE` у `CreateEventW`) обязателен: `GetOverlappedResult`
    /// сбрасывает авто-сброс событие сам, и MS предупреждает ровно об этой ловушке (докблок
    /// `OVERLAPPED::hEvent`) — здесь она не встречается, потому что событие ручного сброса
    /// закрывается сразу за ЕДИНСТВЕННЫМ использованием (докблок `carrier.rs::attempt_recv`), но
    /// названа, раз уж выбор небезразличен.
    pub fn zeroed(event: Handle) -> Self {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: event,
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    pub fn CreateEventW(
        lp_event_attributes: *mut c_void,
        b_manual_reset: Bool,
        b_initial_state: Bool,
        lp_name: *const u16,
    ) -> Handle;

    pub fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: u32) -> u32;

    pub fn GetOverlappedResult(
        h_file: Handle,
        lp_overlapped: *mut Overlapped,
        lp_number_of_bytes_transferred: *mut u32,
        b_wait: Bool,
    ) -> Bool;

    pub fn CloseHandle(h_object: Handle) -> Bool;

    pub fn CancelIoEx(h_file: Handle, lp_overlapped: *mut Overlapped) -> Bool;

    pub fn GetLastError() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Раскладка `WINDIVERT_ADDRESS` обязана остаться 80 байт (8 `Timestamp` + 4 `flags` + 4
    /// `Reserved2` + 64 union) — число, которое даёт сам заголовок, не наше изобретение. Единственная
    /// проверка формы, которую можно прогнать НЕ на Windows (арифметика `size_of`, не FFI-вызов) —
    /// см. докблок крейта: доктесты и cross-check `cargo check` этого не ловят, а этот тест ловит,
    /// причём на ЛЮБОЙ платформе (структура — просто данные, `#[repr(C)]` детерминирован).
    #[test]
    fn windivert_address_is_eighty_bytes() {
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);
    }

    /// Бит `Outbound` — №17 по раскладке заголовка. Мутация числа сдвига здесь покраснела бы
    /// молча в бою (флаг встал бы не туда) и НЕ покраснела бы под `cargo check` (тип тот же,
    /// значение другое) — эта проверка единственная, что её ловит.
    #[test]
    fn outbound_bit_is_seventeen() {
        let mut addr = WinDivertAddress::zeroed();
        assert!(!addr.outbound());
        addr.set_outbound(true);
        assert_eq!(addr.flags, 1 << 17);
        assert!(addr.outbound());
        addr.set_outbound(false);
        assert_eq!(addr.flags, 0);
    }
}
