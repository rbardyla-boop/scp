// scp-relay: dev-harness relay daemon with opaque token-keyed mailbox.
//
// NOT PRODUCTION. Mailbox token possession is the only access control.
// Relay restart clears ALL in-memory mailbox contents (documented limitation).
// Optional --store-dir enables bounded dev-harness mailbox persistence across
// relay restarts. Durable filenames are salted digests of mailbox tokens, but
// queue existence, sizes, and mtimes remain at-rest metadata surfaces. This is
// not a production storage/privacy design.
// Routes only by DevMailboxId; never receives, stores, or logs identity keys.
//
// Wire protocol (per RUNTIME_BOOTSTRAP_PLAN.md §3.2):
//   Store: [0x01][32 token][4 len LE][N payload bytes]  → [0x00 ack]
//   Poll:  [0x02][32 token]  → [4 count LE][for each: [4 len LE][N bytes]]
//
// Usage: scp-relay [--bind 127.0.0.1:PORT] [--store-dir PATH]
//        default bind: 127.0.0.1:7700

use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_BURST_BYTES: usize = 1_048_576; // 1 MiB per burst
const MAX_QUEUE_DEPTH: usize = 100; // oldest evicted on overflow
const STORE_MAGIC: &[u8; 8] = b"SCPRLY1\n";
const STORE_SALT_FILE: &str = "store.salt";
const MAILBOX_FILENAME_DOMAIN: &[u8] = b"scp-relay-durable-mailbox-path-v1";

type MailboxToken = [u8; 32];
type Burst = Vec<u8>;
type MailboxQueue = Vec<Burst>;
type Mailboxes = HashMap<MailboxToken, MailboxQueue>;

#[derive(Clone)]
struct MailboxStore {
    inner: Arc<Mutex<Mailboxes>>,
    durable: Option<Arc<DurableStore>>,
}

struct DurableStore {
    dir: PathBuf,
    salt: [u8; 32],
}

struct RelayConfig {
    addr: String,
    store_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let config = parse_args();
    run_relay(config).await;
}

async fn run_relay(config: RelayConfig) {
    let listener = match TcpListener::bind(&config.addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "{{\"event\":\"relay_bind_failed\",\"addr\":\"{}\",\"error\":\"{e}\"}}",
                config.addr
            );
            std::process::exit(1);
        }
    };

    let bound = listener.local_addr().unwrap();
    println!("{{\"event\":\"relay_listening\",\"addr\":\"{bound}\"}}");

    let store = match MailboxStore::new(config.store_dir) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("{{\"event\":\"relay_store_failed\",\"error\":\"{e}\"}}");
            std::process::exit(1);
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_connection(stream, store.clone()));
            }
            Err(e) => {
                eprintln!("{{\"event\":\"relay_accept_error\",\"error\":\"{e}\"}}");
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, store: MailboxStore) {
    let mut cmd = [0u8; 1];
    if stream.read_exact(&mut cmd).await.is_err() {
        return;
    }
    match cmd[0] {
        0x01 => handle_store(&mut stream, store).await,
        0x02 => handle_poll(&mut stream, store).await,
        _ => {} // unknown command: drop connection silently
    }
}

async fn handle_store(stream: &mut TcpStream, store: MailboxStore) {
    let mut token = [0u8; 32];
    let mut len_buf = [0u8; 4];

    if stream.read_exact(&mut token).await.is_err() {
        return;
    }
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }

    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len > MAX_BURST_BYTES {
        return;
    }

    let mut payload = vec![0u8; payload_len];
    if stream.read_exact(&mut payload).await.is_err() {
        return;
    }

    if let Err(e) = store.store(token, payload) {
        eprintln!(
            "{{\"event\":\"relay_store_error\",\"mailbox\":\"{}\",\"error\":\"{e}\"}}",
            hex(&token)
        );
        return;
    }

    println!(
        "{{\"event\":\"burst_stored\",\"mailbox\":\"{}\"}}",
        hex(&token)
    );
    let _ = stream.write_all(&[0x00]).await;
}

async fn handle_poll(stream: &mut TcpStream, store: MailboxStore) {
    let mut token = [0u8; 32];
    if stream.read_exact(&mut token).await.is_err() {
        return;
    }

    let bursts = match store.poll(token) {
        Ok(bursts) => bursts,
        Err(e) => {
            eprintln!(
                "{{\"event\":\"relay_poll_error\",\"mailbox\":\"{}\",\"error\":\"{e}\"}}",
                hex(&token)
            );
            return;
        }
    };

    if !bursts.is_empty() {
        println!(
            "{{\"event\":\"mailbox_drained\",\"mailbox\":\"{}\",\"count\":{}}}",
            hex(&token),
            bursts.len()
        );
    }

    let count = bursts.len() as u32;
    if stream.write_all(&count.to_le_bytes()).await.is_err() {
        return;
    }

    for burst in &bursts {
        let len = burst.len() as u32;
        if stream.write_all(&len.to_le_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(burst).await.is_err() {
            return;
        }
    }
}

impl MailboxStore {
    fn new(store_dir: Option<PathBuf>) -> io::Result<Self> {
        let durable = match store_dir {
            Some(dir) => Some(Arc::new(DurableStore::new(dir)?)),
            None => None,
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            durable,
        })
    }

    fn store(&self, token: [u8; 32], payload: Vec<u8>) -> io::Result<()> {
        let loaded = self.load_queue(&token)?;
        let mut mb = self.inner.lock().unwrap();
        let queue = mb.entry(token).or_insert(loaded);
        if queue.len() >= MAX_QUEUE_DEPTH {
            queue.remove(0); // evict oldest burst on overflow
        }
        queue.push(payload);
        self.persist_queue(&token, queue)
    }

    fn poll(&self, token: [u8; 32]) -> io::Result<Vec<Vec<u8>>> {
        let loaded = self.load_queue(&token)?;
        let mut mb = self.inner.lock().unwrap();
        let bursts = mb.remove(&token).unwrap_or(loaded);
        self.delete_queue(&token)?;
        Ok(bursts)
    }

    fn load_queue(&self, token: &[u8; 32]) -> io::Result<Vec<Vec<u8>>> {
        match &self.durable {
            Some(durable) => durable.load_queue(token),
            None => Ok(Vec::new()),
        }
    }

    fn persist_queue(&self, token: &[u8; 32], queue: &[Vec<u8>]) -> io::Result<()> {
        match &self.durable {
            Some(durable) => durable.persist_queue(token, queue),
            None => Ok(()),
        }
    }

    fn delete_queue(&self, token: &[u8; 32]) -> io::Result<()> {
        match &self.durable {
            Some(durable) => durable.delete_queue(token),
            None => Ok(()),
        }
    }
}

impl DurableStore {
    fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let salt = load_or_create_salt(&dir)?;
        Ok(Self { dir, salt })
    }

    fn mailbox_path(&self, token: &[u8; 32]) -> PathBuf {
        self.dir
            .join(format!("{}.mbox", self.mailbox_file_stem(token)))
    }

    fn legacy_mailbox_path(&self, token: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.mbox", hex(token)))
    }

    fn mailbox_file_stem(&self, token: &[u8; 32]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MAILBOX_FILENAME_DOMAIN);
        hasher.update(&self.salt);
        hasher.update(token);
        hasher.finalize().to_hex().to_string()
    }

    fn load_queue(&self, token: &[u8; 32]) -> io::Result<Vec<Vec<u8>>> {
        let path = match self.queue_path_for_load(token) {
            Some(path) => path,
            None => return Ok(Vec::new()),
        };

        let mut file = fs::File::open(path)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != STORE_MAGIC {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid durable mailbox magic",
            ));
        }

        let count = read_u32(&mut file)? as usize;
        if count > MAX_QUEUE_DEPTH {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "durable mailbox exceeds max queue depth",
            ));
        }

        let mut queue = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_u32(&mut file)? as usize;
            if len > MAX_BURST_BYTES {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "durable mailbox burst exceeds max size",
                ));
            }
            let mut payload = vec![0u8; len];
            file.read_exact(&mut payload)?;
            queue.push(payload);
        }

        Ok(queue)
    }

    fn persist_queue(&self, token: &[u8; 32], queue: &[Vec<u8>]) -> io::Result<()> {
        if queue.is_empty() {
            return self.delete_queue(token);
        }

        fs::create_dir_all(&self.dir)?;
        let path = self.mailbox_path(token);
        let tmp_path = tmp_path(&path);
        {
            let mut file = fs::File::create(&tmp_path)?;
            file.write_all(STORE_MAGIC)?;
            file.write_all(&(queue.len() as u32).to_le_bytes())?;
            for burst in queue {
                file.write_all(&(burst.len() as u32).to_le_bytes())?;
                file.write_all(burst)?;
            }
            file.sync_all()?;
        }
        fs::rename(tmp_path, path)?;
        remove_if_exists(self.legacy_mailbox_path(token))
    }

    fn delete_queue(&self, token: &[u8; 32]) -> io::Result<()> {
        remove_if_exists(self.mailbox_path(token))?;
        remove_if_exists(self.legacy_mailbox_path(token))
    }

    fn queue_path_for_load(&self, token: &[u8; 32]) -> Option<PathBuf> {
        let path = self.mailbox_path(token);
        if path.exists() {
            return Some(path);
        }
        let legacy_path = self.legacy_mailbox_path(token);
        legacy_path.exists().then_some(legacy_path)
    }
}

fn load_or_create_salt(dir: &Path) -> io::Result<[u8; 32]> {
    let path = dir.join(STORE_SALT_FILE);
    match read_salt(&path) {
        Ok(salt) => Ok(salt),
        Err(e) if e.kind() == ErrorKind::NotFound => create_salt(&path),
        Err(e) => Err(e),
    }
}

fn read_salt(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() != 32 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid durable store salt length",
        ));
    }

    let mut salt = [0u8; 32];
    file.read_exact(&mut salt)?;
    Ok(salt)
}

fn create_salt(path: &Path) -> io::Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut salt);

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(&salt)?;
            file.sync_all()?;
            Ok(salt)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_salt(path),
        Err(e) => Err(e),
    }
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    tmp
}

fn remove_if_exists(path: PathBuf) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn parse_args() -> RelayConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:7700".to_string();
    let mut store_dir = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--bind" && i + 1 < args.len() {
            addr = args[i + 1].clone();
            i += 2;
            continue;
        }
        if args[i] == "--store-dir" && i + 1 < args.len() {
            store_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        i += 1;
    }
    RelayConfig { addr, store_dir }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
