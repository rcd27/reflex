/// Geneva primitive action — один шаг обработки пакета.
#[derive(Debug, Clone, PartialEq)]
pub enum GenevaAction {
    /// Создать копию пакета, опционально модифицировать копию.
    Duplicate { modify: Option<Box<GenevaAction>> },
    /// Разрезать пакет на части (TCP segmentation / IP fragmentation).
    Fragment {
        protocol: FragProtocol,
        offset: usize,
        in_order: bool,
    },
    /// Изменить поле пакета.
    Tamper { field: PacketField, op: TamperOp },
    /// Не отправлять пакет.
    Drop,
}

/// Протокол фрагментации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragProtocol {
    Tcp,
    Ip,
}

/// Поле пакета для tamper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketField {
    TcpFlags,
    IpTtl,
    TcpChecksum,
    TcpSeq,
    TcpAck,
    TcpWindow,
    TcpOptions,
}

/// Операция модификации.
#[derive(Debug, Clone, PartialEq)]
pub enum TamperOp {
    /// Заменить значение поля.
    Replace(Vec<u8>),
    /// Испортить значение (невалидная checksum, случайные данные).
    Corrupt,
}
