use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug)]
pub enum PidError {
    /// Замок держит живой процесс. Номер — `Option`, а не число: PID из файла мог не прочитаться
    /// (файл пуст, обрезан, занят на запись), и ноль вместо него был бы выдуманным номером —
    /// читатель принял бы его за настоящий и пошёл искать несуществующий процесс. «Чей замок,
    /// неизвестно» — своя клетка (§7), и отказ от этого не перестаёт быть отказом.
    AlreadyRunning(Option<u32>),
    Io(io::Error),
}

impl fmt::Display for PidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning(Some(pid)) => write!(f, "демон уже работает (pid {pid})"),
            Self::AlreadyRunning(None) => {
                write!(f, "демон уже работает, номер процесса не прочитан")
            }
            Self::Io(e) => write!(f, "pid file error: {e}"),
        }
    }
}

impl std::error::Error for PidError {}

impl From<io::Error> for PidError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// ЕДИНСТВЕННОСТЬ ЭКЗЕМПЛЯРА ДЕРЖИТ ЗАМОК ЯДРА (`flock`), А НЕ СОДЕРЖИМОЕ ФАЙЛА. Замок привязан к
/// открытому дескриптору и снимается ядром при завершении процесса — в том числе по SIGKILL и при
/// крахе, когда убрать за собой некому. Оттого guard невосприимчив к переиспользованию PID и к
/// сбросу pid-namespace при рестарте контейнера.
///
/// `kill(pid, 0)` отвергнут как свидетель: он свидетельствует о СУЩЕСТВОВАНИИ номера, а спрошено о
/// ВЛАДЕНИИ, и чужой процесс, занявший освободившийся номер, читался бы как «демон уже запущен».
///
/// PID в файле — ИНФОРМАЦИОННЫЙ (подсказка для `kill -TERM <pid>`): на корректность не влияет и
/// источником истины не служит, истину держит замок.
#[derive(Debug)]
pub struct PidGuard {
    path: PathBuf,
    // Держим файл открытым на всё время жизни guard'а: закрытие дескриптора
    // (при drop) снимает flock.
    _file: File,
}

impl PidGuard {
    pub fn acquire(path: PathBuf) -> Result<Self, PidError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Открываем без truncate: если замок держит живой демон, мы не должны
        // затирать его pidfile до того, как убедимся, что замок свободен.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        if !try_lock_exclusive(&file)? {
            // Замок занят живым процессом — читаем PID для понятного сообщения. Не прочли —
            // так и скажем: номер неизвестен.
            return Err(PidError::AlreadyRunning(read_pid(&mut &file)));
        }

        // Замок наш — записываем свой PID (информационно).
        let mut f = &file;
        f.set_len(0)?;
        f.seek(SeekFrom::Start(0))?;
        write!(f, "{}", std::process::id())?;
        f.flush()?;

        Ok(Self { path, _file: file })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// КТО ВЛАДЕЕТ ЗАМКОМ НА `path` ПРЯМО СЕЙЧАС: `Some(pid)` — замок держит живой демон, `None` —
    /// живого держателя нет. Спрашивается замок, не число в файле (докблок [`PidGuard`]).
    ///
    /// Дверь для админских подкоманд, которым запрещено трогать состояние живого демона (уборка
    /// nft). Осиротевший pid-файл мёртвого демона даёт `None` честно: замок ядро сняло при смерти
    /// процесса, и уборка безопасна — отсутствие владельца здесь ЗАМЕРЕНО попыткой взять замок, а
    /// не выведено из того, что файл остался.
    pub fn live_owner(path: &PathBuf) -> Option<u32> {
        let mut file = OpenOptions::new().read(true).write(true).open(path).ok()?;
        match try_lock_exclusive(&file) {
            // Замок взяли — живого держателя нет; сразу отпускаем.
            Ok(true) => {
                let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                None
            }
            // Замок занят — демон жив; читаем его PID.
            Ok(false) => read_pid(&mut file),
            Err(_) => None,
        }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        // Удаляем файл; flock снимется при закрытии дескриптора (drop `_file`).
        let _ = fs::remove_file(&self.path);
    }
}

/// Пытается взять эксклюзивный неблокирующий flock. `Ok(true)` — замок наш,
/// `Ok(false)` — занят другим живым процессом, `Err` — системная ошибка.
fn try_lock_exclusive(file: &File) -> Result<bool, io::Error> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(false),
        _ => Err(err),
    }
}

fn read_pid(mut reader: impl Read + Seek) -> Option<u32> {
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf).ok()?;
    buf.trim().parse::<u32>().ok()
}
