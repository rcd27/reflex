// Command types will be completed when builders are available (Task 8)
// For now, placeholder to establish module structure.

/// Типизированная команда — терминальный морфизм категории.
pub enum Command {
    /// Инжектировать пакет в сеть.
    Inject(InjectablePacket),
    /// Дропнуть flow через backend (TC-BPF / XDP).
    DropFlow(()), // Flow type will come from types module
    /// Снять drop с flow.
    ClearFlow(()), // Flow type will come from types module
}

/// Пакет, готовый к инжекции. Фреймворк сериализует в байты.
pub enum InjectablePacket {
    /// Escape hatch — explicit opt-out из типизации.
    Raw(Vec<u8>),
    // Tcp(TcpBuilder) and Udp(UdpBuilder) will be added in Task 8
}
