// scp-relay: dev-harness relay daemon with opaque token-keyed mailbox.
//
// NOT PRODUCTION. Mailbox token possession is the only access control.
// Relay restart clears ALL in-memory mailbox contents (documented limitation).
// Routes only by DevMailboxId; never receives, stores, or logs identity keys.
//
// Wire protocol (per RUNTIME_BOOTSTRAP_PLAN.md §3.2):
//   Store: [0x01][32 token][4 len LE][N payload bytes]  → [0x00 ack]
//   Poll:  [0x02][32 token]  → [4 count LE][for each: [4 len LE][N bytes]]
//
// Usage: scp-relay [--bind 127.0.0.1:PORT]   default: 127.0.0.1:7700

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type MailboxStore = Arc<Mutex<HashMap<[u8; 32], Vec<Vec<u8>>>>>;

const MAX_BURST_BYTES: usize = 1_048_576; // 1 MiB per burst
const MAX_QUEUE_DEPTH: usize = 100; // oldest evicted on overflow

#[tokio::main]
async fn main() {
    let addr = parse_bind_arg();
    run_relay(addr).await;
}

async fn run_relay(addr: String) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{{\"event\":\"relay_bind_failed\",\"addr\":\"{addr}\",\"error\":\"{e}\"}}");
            std::process::exit(1);
        }
    };

    let bound = listener.local_addr().unwrap();
    println!("{{\"event\":\"relay_listening\",\"addr\":\"{bound}\"}}");

    let store: MailboxStore = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let s = Arc::clone(&store);
                tokio::spawn(handle_connection(stream, s));
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

    {
        let mut mb = store.lock().unwrap();
        let queue = mb.entry(token).or_default();
        if queue.len() >= MAX_QUEUE_DEPTH {
            queue.remove(0); // evict oldest burst on overflow
        }
        queue.push(payload);
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

    let bursts: Vec<Vec<u8>> = {
        let mut mb = store.lock().unwrap();
        mb.remove(&token).unwrap_or_default()
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

fn parse_bind_arg() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--bind" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        i += 1;
    }
    "127.0.0.1:7700".to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
