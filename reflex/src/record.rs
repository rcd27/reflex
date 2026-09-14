//! ЗАПИСЬ ПРОВОДА САМИМ НОСИТЕЛЕМ: движок пишет то, что получил, и прогон читает ровно это.
//!
//! # Зачем писать самому, когда есть `tcpdump`
//!
//! Замер 14.09.2026 на коробке Игоря: прибор темпа объявил троттлингом служебные соединения PSN, их
//! увод в контур выкинул человека из игры. Проверить прибор можно только прогоном ПОЛЕВОЙ записи
//! через тот же движок, а `tcpdump` на коробке нет — и смотрел бы он другим глазом: на мост до
//! правил `nft`, со склеенными кадрами USB-сетевухи. Запись носителя видит то же, что видел движок:
//! пакеты после правил, из той же очереди.
//!
//! # Что остаётся от пакета
//!
//! Час TCP коробки — около 1,2 ГБ, и почти весь объём составляют тела ответов (видео). Содержимое
//! их не читает никто: голову разговора разбирают только у клиента (`ClientHello`), а приборы
//! ответа цели смотрят на длину. Поэтому у ответов цели пишутся одни заголовки, длина на проводе
//! уходит в `orig_len` записи, и прогон доращивает тело нулями
//! ([`reflex_core::pcap::Frame::restored`]). Выходит около 120 МБ в час.
//!
//! ЦЕНА НАЗВАНА: прибор, который начнёт читать ТЕЛО ответа цели, на такой записи увидит нули.
//!
//! # Потеря названа, а не спрятана
//!
//! Нить записи не должна тормозить очередь, поэтому между ними канал с границей: переполнился —
//! кадр не записан. Дыра в записи есть ложь прогона (пропавший ответ читается молчанием цели),
//! потому потерянное считается и печатается при каждой смене поколения.
//!
//! Хвост текущего поколения живёт в буфере до 8 КБ: файл, снятый с коробки на ходу, может кончаться
//! оборванной записью. Читатель это переживает (`Broken::Truncated`) и называет.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;

use reflex_engine::parse::Framed;

/// Сколько кадров ждут нить записи, прежде чем очередь начнёт их терять. Кадр — до полутора КБ,
/// то есть граница держит в памяти не больше ~24 МБ даже на самых толстых кадрах.
const WAITING: usize = 16_384;

/// Длина заголовка файла: поколение, в котором нет ничего сверх него, сменять бессмысленно.
const OPENING: u64 = 24;

/// Рецепт записи: куда, какой потолок у поколения, сколько поколений хранить, на каком порту цель.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    path: PathBuf,
    ceiling: u64,
    generations: usize,
    server_port: u16,
}

impl Record {
    /// Запись по пути. Умолчание — четыре поколения по 32 МБ (около часа TCP коробки), цель на 443.
    pub fn at(path: impl AsRef<Path>) -> Record {
        Record {
            path: path.as_ref().to_path_buf(),
            ceiling: 32 * 1024 * 1024,
            generations: 4,
            server_port: 443,
        }
    }

    /// Потолок одного поколения в байтах.
    pub fn capped(self, bytes: u64) -> Record {
        Record {
            ceiling: bytes,
            ..self
        }
    }

    /// Сколько поколений хранить, считая текущее. Не меньше одного: без поколения писать некуда.
    pub fn keeping(self, generations: usize) -> Record {
        Record {
            generations: generations.max(1),
            ..self
        }
    }

    /// Порт цели — по нему запись отличает ответ цели, у которого тело не пишется.
    pub fn toward(self, port: u16) -> Record {
        Record {
            server_port: port,
            ..self
        }
    }

    /// Путь поколения: текущее — сам путь, старшие — с номером через точку.
    fn generation(&self, n: usize) -> PathBuf {
        match n {
            0 => self.path.clone(),
            older => PathBuf::from(format!("{}.{older}", self.path.display())),
        }
    }
}

/// СКОЛЬКО БАЙТ ПАКЕТА ПИСАТЬ. У ответа цели по TCP — до конца заголовков, у всего прочего —
/// целиком: пакет клиента несёт голову разговора, а непонятый кадр урезать не по чему.
pub fn kept(packet: &[u8], server_port: u16) -> usize {
    match reflex_engine::parse::framed(packet) {
        Framed::Tcp(segment) => match segment.header.ends.src_port == server_port {
            true => packet.len() - segment.payload.len(),
            false => packet.len(),
        },
        Framed::Udp(_) | Framed::NotIpv4 | Framed::NotOurProtocol | Framed::Truncated => {
            packet.len()
        }
    }
}

/// Поднятая запись: канал к нити, счёт потерь и сама нить — её `JoinHandle` хранится, чтобы
/// падение нити было наблюдаемо ([`Recorder::finish`]).
pub struct Recorder {
    entries: SyncSender<Vec<u8>>,
    lost: Arc<AtomicU64>,
    server_port: u16,
    writer: std::thread::JoinHandle<std::io::Result<()>>,
}

impl Recorder {
    /// Поднять нить записи. Файл открывает нить, а не вызывающий: отказ записи не валит носитель —
    /// запись есть прибор наблюдения, а не условие работы, и очередь без неё обязана жить. Отказ
    /// печатается по имени пути.
    pub fn start(record: Record) -> Recorder {
        let (entries, waiting) = std::sync::mpsc::sync_channel(WAITING);
        let lost = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&lost);
        let server_port = record.server_port;
        let writer = std::thread::spawn(move || {
            let written = write(&record, waiting, &counted);
            match &written {
                Ok(()) => (),
                Err(why) => crate::report!("запись {} остановлена: {why}", record.path.display()),
            }
            written
        });
        Recorder {
            entries,
            lost,
            server_port,
            writer,
        }
    }

    /// Записать пакет таким, каким его видит носитель. Не ждёт: полный канал есть потерянный
    /// кадр, и он сосчитан.
    pub fn note(&self, packet: &[u8]) {
        let entry = reflex_core::pcap::entry(
            std::time::SystemTime::now(),
            &packet[..kept(packet, self.server_port)],
            packet.len(),
        );
        match self.entries.try_send(entry) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Закрыть запись, дождаться нити и сказать, сколько кадров потеряно. Упавшая нить — ошибка, а
    /// не ноль потерь.
    pub fn finish(self) -> std::io::Result<u64> {
        let Recorder {
            entries,
            lost,
            writer,
            ..
        } = self;
        drop(entries);
        writer
            .join()
            .map_err(|_panicked| std::io::Error::other("нить записи упала"))??;
        Ok(lost.load(Ordering::Relaxed))
    }
}

/// Работа нити: пока канал открыт, класть кадры в текущее поколение.
fn write(record: &Record, waiting: Receiver<Vec<u8>>, lost: &AtomicU64) -> std::io::Result<()> {
    waiting
        .iter()
        .try_fold(Generation::open(record)?, |generation, entry| {
            generation.append(record, lost, &entry)
        })
        .and_then(Generation::close)
}

/// Текущее поколение: буфер над файлом и сколько в него уже легло.
struct Generation {
    out: std::io::BufWriter<std::fs::File>,
    written: u64,
}

impl Generation {
    /// Сдвинуть старшие поколения и начать текущее с заголовка.
    fn open(record: &Record) -> std::io::Result<Generation> {
        (1..record.generations)
            .rev()
            .try_for_each(|older| shift(record, older))?;
        let out = std::io::BufWriter::new(std::fs::File::create(&record.path)?);
        Generation { out, written: 0 }.put(&reflex_core::pcap::opening())
    }

    /// Положить запись; если она не влезает под потолок, сперва сменить поколение.
    fn append(
        self,
        record: &Record,
        lost: &AtomicU64,
        entry: &[u8],
    ) -> std::io::Result<Generation> {
        let over = self.written > OPENING && self.written + entry.len() as u64 > record.ceiling;
        match over {
            false => self.put(entry),
            true => {
                self.close()?;
                crate::report!(
                    "запись {}: новое поколение, потеряно кадров за всё время: {}",
                    record.path.display(),
                    lost.load(Ordering::Relaxed)
                );
                Generation::open(record)?.put(entry)
            }
        }
    }

    fn put(mut self, bytes: &[u8]) -> std::io::Result<Generation> {
        self.out.write_all(bytes)?;
        Ok(Generation {
            written: self.written + bytes.len() as u64,
            ..self
        })
    }

    fn close(mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// Поколение `older - 1` становится `older`. Отсутствующее сдвигать нечем — это не ошибка, а
/// молодая запись.
fn shift(record: &Record, older: usize) -> std::io::Result<()> {
    match std::fs::rename(record.generation(older - 1), record.generation(older)) {
        Ok(()) => Ok(()),
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(why) => Err(why),
    }
}
