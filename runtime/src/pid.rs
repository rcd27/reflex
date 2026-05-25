use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

#[derive(Debug)]
pub enum PidError {
    AlreadyRunning(u32),
    Io(io::Error),
}

impl fmt::Display for PidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning(pid) => write!(f, "daemon already running (pid {pid})"),
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

/// Single-instance guard built on an advisory file lock (`flock`).
///
/// Взаимное исключение держится на замке ядра, а не на содержимом файла:
/// замок привязан к открытому дескриптору и снимается ядром при завершении
/// процесса (в т.ч. по SIGKILL/краху). Поэтому guard невосприимчив к
/// переиспользованию PID и к сбросу PID-namespace при рестарте контейнера —
/// в отличие от прежней проверки `kill(pid, 0)`, которая принимала чужой/свой
/// переиспользованный PID за «уже запущенный демон».
///
/// PID в файле — чисто информационный (для подсказки `kill -TERM <pid>`),
/// на корректность не влияет.
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
            // Замок занят живым процессом — читаем PID для понятного сообщения.
            let pid = read_pid(&mut &file).unwrap_or(0);
            return Err(PidError::AlreadyRunning(pid));
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

    /// Inspects whether a *running* daemon currently owns the lock on `path`.
    /// Returns the owning pid if the lock is held, `None` otherwise.
    ///
    /// Use this from admin subcommands that must refuse to mutate state owned
    /// by a running daemon (e.g. an nft-cleanup tool). A stale pidfile left by
    /// a dead daemon reports `None` — its lock was released by the kernel on
    /// process death, so cleanup is safe.
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
