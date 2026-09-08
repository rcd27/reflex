use std::io;
use std::net::Ipv4Addr;

pub struct RawSender {
    fd: i32,
    fwmark: u32,
}

// SAFETY: RawSender owns the fd exclusively.
unsafe impl Send for RawSender {}
unsafe impl Sync for RawSender {}

impl RawSender {
    /// Open AF_INET raw socket with IP_HDRINCL.
    /// `fwmark` is set on every sent packet via SO_MARK — used to prevent
    /// NFQUEUE from re-capturing our injected packets.
    pub fn open(fwmark: u32) -> Result<Self, io::Error> {
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_RAW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // IP_HDRINCL: we provide the full IP header
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // SO_MARK: tag packets so iptables can skip NFQUEUE for them
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &fwmark as *const u32 as *const libc::c_void,
                size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(Self { fd, fwmark })
    }

    pub fn fwmark(&self) -> u32 {
        self.fwmark
    }

    /// Send a raw IP packet (IP header + TCP/UDP payload, no ethernet).
    /// Destination is extracted from the IP header dst field.
    pub fn send(&self, ip_packet: &[u8]) -> Result<(), io::Error> {
        if ip_packet.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too short for IP header",
            ));
        }

        let dst_ip = Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from(dst_ip).to_be();

        let ret = unsafe {
            libc::sendto(
                self.fd,
                ip_packet.as_ptr() as *const libc::c_void,
                ip_packet.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for RawSender {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// СТОК КАТЕГОРИИ — И ЭТО ЗАЯВЛЕНИЕ, А НЕ ОБЁРТКА (#326, 05.09.2026).
///
/// # Что этим чинится
///
/// До этого дня единственный боевой инжектор продукта стоял ВНЕ категории: сертифицированным был
/// `AfPacketBackend`, которым потребитель не пользуется, а всё, что продукт кладёт на провод
/// своими руками — приманки обхода и извещения об обрыве, — уходило вызовом `send`, о котором ни
/// один закон не знал. Тот же класс, что оплачен очередью двумя днями раньше: проверяли не то,
/// что работает.
///
/// # Команда — ГОТОВЫЕ БАЙТЫ, а не пакет
///
/// Сериализацию делает [`CanInject::inject`], и потому она видна в типе: сток принимает то, что
/// уже есть на проводе. Принимай он [`InjectablePacket`], выбор формы (канальная или IP) прятался
/// бы внутри `emit`, и закон не мог бы снять отпечаток тем же способом, каким носитель отправляет.
impl reflex_core::backend::Sink for RawSender {
    type Command = Vec<u8>;
    type Error = io::Error;

    fn emit(&mut self, command: Vec<u8>) -> Result<(), io::Error> {
        self.send(&command)
    }
}

/// ВВОД СВОЕГО ПАКЕТА — IP-ФОРМОЙ, потому что сокет открыт с `IP_HDRINCL`.
///
/// Канальная форма здесь была бы ложью на четырнадцать байт: ethernet-заголовок ядро дописывает
/// само, и отдай мы его вместе с пакетом — он уехал бы в тело IP-заголовка.
impl reflex_core::CanInject for RawSender {
    fn inject(packet: reflex_core::InjectablePacket) -> Vec<u8> {
        packet.serialize_ip()
    }
}
