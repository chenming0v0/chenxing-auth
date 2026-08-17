use super::{io, Path, KEY_STORAGE_LOCK_FILE};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LOCK_OWNER_FILE: &str = "owner";
const STALE_LOCK_AGE: Duration = Duration::from_secs(60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LeaseIdentity {
    host: String,
    pid: u32,
    process_start: u128,
    nonce: String,
}

impl LeaseIdentity {
    fn current() -> Self {
        Self {
            host: host_id(),
            pid: std::process::id(),
            process_start: process_start(),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    fn same_process(&self, other: &Self) -> bool {
        self.host == other.host
            && self.pid == other.pid
            && self.process_start == other.process_start
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseRecord {
    identity: LeaseIdentity,
    released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ObservedLock {
    record: Option<LeaseRecord>,
    last_heartbeat: Option<SystemTime>,
}

#[derive(Debug)]
pub(super) struct DirectoryLock {
    path: PathBuf,
    identity: LeaseIdentity,
    heartbeat: Heartbeat,
}

impl DirectoryLock {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn release(&mut self) {
        self.heartbeat.stop();
        // Do not unlink by path: a paused predecessor may resume after a successor has replaced
        // the directory. Marking the matching open owner file keeps that successor untouched.
        let _ = mark_released_if_owner(&self.path, &self.identity);
    }
}

pub(super) fn acquire(directory: &Path, blocking: bool) -> io::Result<DirectoryLock> {
    let path = directory.join(KEY_STORAGE_LOCK_FILE);
    let identity = LeaseIdentity::current();
    let deadline = SystemTime::now() + ACQUIRE_TIMEOUT;
    loop {
        match fs::create_dir(&path) {
            Ok(()) => {
                if let Err(error) = write_record(
                    &path,
                    &LeaseRecord {
                        identity: identity.clone(),
                        released: false,
                    },
                ) {
                    let _ = fs::remove_file(owner_file(&path));
                    let _ = fs::remove_dir(&path);
                    return Err(error);
                }
                let heartbeat = Heartbeat::start(
                    path.join(LOCK_OWNER_FILE),
                    identity.clone(),
                    HEARTBEAT_INTERVAL,
                );
                return Ok(DirectoryLock {
                    path,
                    identity,
                    heartbeat,
                });
            }
            Err(error) if error.kind() != ErrorKind::AlreadyExists => return Err(error),
            Err(error) => {
                if reclaim_if_stale(&path, SystemTime::now())? {
                    continue;
                }
                if !blocking || SystemTime::now() >= deadline {
                    return Err(error);
                }
                thread::sleep(RETRY_INTERVAL);
            }
        }
    }
}

fn process_start() -> u128 {
    static START: OnceLock<u128> = OnceLock::new();
    *START.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    })
}

fn host_id() -> String {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        let raw = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("unknown-{}", uuid::Uuid::new_v4().simple()));
        raw.chars()
            .map(|ch| match ch {
                '|' | '\n' | '\r' => '_',
                other => other,
            })
            .collect()
    })
    .clone()
}

fn encode(record: &LeaseRecord) -> String {
    let state = if record.released { "released" } else { "active" };
    format!(
        "{state}|{}|{}|{}|{}\n",
        record.identity.host,
        record.identity.pid,
        record.identity.process_start,
        record.identity.nonce
    )
}

fn decode(contents: &str) -> Option<LeaseRecord> {
    let mut fields = contents.trim_end_matches(&['\r', '\n'][..]).split('|');
    let released = match fields.next()? {
        "active" => false,
        "released" => true,
        _ => return None,
    };
    let host = fields.next()?.to_owned();
    let pid = fields.next()?.parse().ok()?;
    let process_start = fields.next()?.parse().ok()?;
    let nonce = fields.next()?.to_owned();
    if fields.next().is_some() || nonce.is_empty() {
        return None;
    }
    Some(LeaseRecord {
        identity: LeaseIdentity {
            host,
            pid,
            process_start,
            nonce,
        },
        released,
    })
}

fn write_record(path: &Path, record: &LeaseRecord) -> io::Result<()> {
    fs::write(owner_file(path), encode(record))
}

fn read_record(path: &Path) -> Option<LeaseRecord> {
    fs::read_to_string(owner_file(path))
        .ok()
        .and_then(|contents| decode(&contents))
}

fn read_record_file(file: &mut File) -> io::Result<Option<LeaseRecord>> {
    file.seek(SeekFrom::Start(0))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(decode(&contents))
}

fn write_record_file(file: &mut File, record: &LeaseRecord) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(encode(record).as_bytes())?;
    file.sync_data()
}

fn open_owner(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(owner_file(path))
}

fn mark_released_if_owner(path: &Path, identity: &LeaseIdentity) -> io::Result<bool> {
    let mut file = match open_owner(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(record) = read_record_file(&mut file)? else {
        return Ok(false);
    };
    if record.released || record.identity != *identity {
        return Ok(false);
    }
    write_record_file(
        &mut file,
        &LeaseRecord {
            identity: identity.clone(),
            released: true,
        },
    )?;
    Ok(true)
}

fn refresh_owner(owner_path: &Path, identity: &LeaseIdentity) -> io::Result<bool> {
    let mut file = match OpenOptions::new().read(true).write(true).open(owner_path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(record) = read_record_file(&mut file)? else {
        return Ok(false);
    };
    if record.released || record.identity != *identity {
        return Ok(false);
    }
    // The handle remains bound to this lease generation even if the path is replaced after the
    // token check, so an old heartbeat cannot touch a successor's owner file.
    file.set_modified(SystemTime::now())?;
    Ok(true)
}

#[derive(Debug)]
pub(super) struct Heartbeat {
    shared: Arc<HeartbeatShared>,
    thread: Option<JoinHandle<()>>,
}

impl Heartbeat {
    pub(super) fn start(
        owner_path: PathBuf,
        identity: LeaseIdentity,
        interval: Duration,
    ) -> Self {
        let shared = Arc::new(HeartbeatShared {
            stop: Mutex::new(false),
            condvar: Condvar::new(),
            owner_path,
            identity,
            interval,
        });
        let worker = Arc::clone(&shared);
        let thread = thread::spawn(move || heartbeat_loop(&worker));
        Self {
            shared,
            thread: Some(thread),
        }
    }

    pub(super) fn stop(&mut self) {
        {
            let mut guard = poison_tolerant_lock(&self.shared.stop);
            *guard = true;
        }
        self.shared.condvar.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    #[cfg(test)]
    pub(super) fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .map_or(true, |thread| thread.is_finished())
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct HeartbeatShared {
    stop: Mutex<bool>,
    condvar: Condvar,
    owner_path: PathBuf,
    identity: LeaseIdentity,
    interval: Duration,
}

fn heartbeat_loop(shared: &HeartbeatShared) {
    loop {
        let stop = {
            let guard = poison_tolerant_lock(&shared.stop);
            if *guard {
                true
            } else {
                let (guard, _) = shared
                    .condvar
                    .wait_timeout(guard, shared.interval)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard
            }
        };
        if stop {
            return;
        }
        match refresh_owner(&shared.owner_path, &shared.identity) {
            Ok(true) => {}
            Ok(false) | Err(_) => return,
        }
    }
}

fn poison_tolerant_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn reclaim_if_stale(path: &Path, now: SystemTime) -> io::Result<bool> {
    let observed = observe(path)?;
    if !is_stale(observed.clone(), &LeaseIdentity::current(), now) {
        return Ok(false);
    }
    if observe(path)? != observed {
        return Ok(false);
    }
    let _ = fs::remove_file(owner_file(path));
    match fs::remove_dir(path) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn observe(path: &Path) -> io::Result<ObservedLock> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(ObservedLock {
                record: None,
                last_heartbeat: None,
            });
        }
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "invalid secure storage path",
        ));
    }
    let owner_path = owner_file(path);
    let last_heartbeat = fs::metadata(&owner_path)
        .or_else(|_| fs::metadata(path))
        .and_then(|metadata| metadata.modified())
        .ok();
    Ok(ObservedLock {
        record: read_record(path),
        last_heartbeat,
    })
}

pub(super) fn is_stale(
    observed: ObservedLock,
    current: &LeaseIdentity,
    now: SystemTime,
) -> bool {
    let Some(last_heartbeat) = observed.last_heartbeat else {
        return false;
    };
    if let Some(record) = observed.record {
        if record.released || record.identity.same_process(current) {
            return record.released;
        }
    }
    now.duration_since(last_heartbeat)
        .is_ok_and(|age| age >= STALE_LOCK_AGE)
}

fn owner_file(path: &Path) -> PathBuf {
    path.join(LOCK_OWNER_FILE)
}

#[cfg(test)]
pub(super) fn owner_file_for_test(path: &Path) -> PathBuf {
    owner_file(path)
}

#[cfg(test)]
pub(super) fn identity_for_test(
    host: &str,
    pid: u32,
    process_start: u128,
    nonce: &str,
) -> LeaseIdentity {
    LeaseIdentity {
        host: host.to_owned(),
        pid,
        process_start,
        nonce: nonce.to_owned(),
    }
}

#[cfg(test)]
pub(super) fn write_owner_for_test(path: &Path, identity: &LeaseIdentity, released: bool) {
    write_record(
        path,
        &LeaseRecord {
            identity: identity.clone(),
            released,
        },
    )
    .expect("owner record");
}

#[cfg(test)]
pub(super) fn observed_for_test(
    record: Option<(LeaseIdentity, bool)>,
    last_heartbeat: Option<SystemTime>,
) -> ObservedLock {
    ObservedLock {
        record: record.map(|(identity, released)| LeaseRecord { identity, released }),
        last_heartbeat,
    }
}

#[cfg(test)]
pub(super) fn stale_lock_age() -> Duration {
    STALE_LOCK_AGE
}
