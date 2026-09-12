//! A small WebSocket load client for benchmarking the relay without the
//! Python-signer bottleneck (a pure-python schnorr signer costs ~175 ms
//! per event; this client signs with the same secp256k1 crate the relay
//! itself uses, i.e. microseconds).
//!
//! Usage (release build!):
//!   cargo run --release --example bench -- ws://127.0.0.1:18999 ingest 2000
//!   cargo run --release --example bench -- ws://127.0.0.1:18999 fanout 60 200
//!   cargo run --release --example bench -- ws://127.0.0.1:18999 req 500
//!   cargo run --release --example bench -- ws://127.0.0.1:18999 search bench
//!
//! Notes: keep the subscriber count under the relay's default
//! `limits.max_connections_per_ip` (64) or the extra connections are
//! refused; a search term occurring in 4096+ stored events is treated as
//! a "common term" and returns nothing by design (use a rarer term).
//!
//! Scenarios:
//!   ingest <n>    publish n events in bursts, measure ev/s (all OKs)
//!   fanout <s> <p>  s subscribers, p publishes, measure deliveries
//!   req <n>       store n events, then measure a full REQ + EOSE latency
//!   search <term> measure a NIP-50 search REQ + EOSE latency
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

fn sign_event(
    secp: &Secp256k1<secp256k1::All>,
    keypair: &Keypair,
    kind: u64,
    content: &str,
    created_at: u64,
) -> String {
    // The event's pubkey must match the signing key (a mismatch would
    // make the relay reject every event as a signature failure).
    let pubkey = XOnlyPublicKey::from_keypair(keypair).0;
    let pubkey_hex = pubkey.to_string();
    let payload = json!([0, pubkey_hex, created_at, kind, [], content]);
    let serialized = serde_json::to_vec(&payload).expect("serialize");
    let id: [u8; 32] = Sha256::digest(&serialized).into();
    let sig = secp.sign_schnorr_no_aux_rand(&id, keypair);
    let event = json!({
        "id": hex::encode(id),
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": [],
        "content": content,
        "sig": sig.to_string(),
    });
    serde_json::to_string(&event).expect("serialize")
}

async fn connect(url: &str) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
    let (ws, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("connect");
    ws
}

fn frame(json: &str) -> WsMessage {
    WsMessage::Text(json.to_string().into())
}

async fn ingest(url: &str, n: usize) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ws = connect(url).await;
    let (mut sink, mut stream) = ws.split();
    let mut received = 0usize;
    let mut ok_true = 0usize;
    let mut first_reason = String::new();
    // Drain the OKs concurrently with the send loop.
    let drain = tokio::spawn(async move {
        while received < n {
            match stream.next().await {
                Some(Ok(msg)) if msg.is_text() => {
                    received += 1;
                    let t = msg.to_text().unwrap();
                    if t.starts_with("[\"AUTH\"") {
                        // The relay's auth challenge; not an OK.
                        received -= 1;
                        continue;
                    }
                    if t.contains(",true,") {
                        ok_true += 1;
                    } else if first_reason.is_empty() {
                        first_reason = t.to_string();
                    }
                }
                _ => break,
            }
        }
        (received, ok_true, first_reason)
    });
    let t0 = Instant::now();
    const BURST: usize = 200;
    let mut sent = 0;
    while sent < n {
        for _ in 0..BURST.min(n - sent) {
            // A unique content per event: identical contents and
            // timestamps would produce identical ids, and the relay would
            // deduplicate the whole burst into one stored event.
            // Spread created_at like real deployments (identical
            // timestamps force every index into the worst-case random
            // insert pattern and exaggerate the DB-size cost).
            let created = now - (sent % 1000) as u64;
            let ev = sign_event(&secp, &keypair, 1, &format!("bench {sent}"), created);
            sink.send(frame(&format!(r#"["EVENT",{ev}]"#)))
                .await
                .expect("send");
            sent += 1;
        }
        // Yield occasionally so the drain task (which reads the OKs that
        // unblock the relay's sends) gets scheduled between sends.
        tokio::task::yield_now().await;
    }
    let dt = t0.elapsed();
    let (got, ok_true, first_reason) = tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .expect("drain finished")
        .expect("drain ok");
    println!(
        "ingest: {} events in {:.2}s = {:.0} ev/s ({} ok, {} accepted)",
        sent,
        dt.as_secs_f64(),
        sent as f64 / dt.as_secs_f64(),
        got,
        ok_true
    );
    if !first_reason.is_empty() {
        println!("first rejection: {first_reason}");
    }
}

async fn fanout(url: &str, subscribers: usize, publishes: usize) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counters: Vec<Arc<std::sync::atomic::AtomicUsize>> = (0..subscribers)
        .map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
        .collect();
    for counter in &counters {
        let counter = Arc::clone(counter);
        let ws = connect(url).await;
        let (mut sink, mut stream) = ws.split();
        // A `since` slightly in the future keeps the initial query empty,
        // so only the live deliveries are counted (the offset must stay
        // under the relay's max_created_at_future_secs, or the published
        // events would be rejected as too far in the future).
        let live_offset = now + 60;
        let sub = format!(r#"["REQ","b",{{"kinds":[1],"since":{}}}]"#, live_offset);
        sink.send(frame(&sub)).await.unwrap();
        // Wait for the EOSE of the (empty) query, then count live events.
        tokio::spawn(async move {
            // The sink must stay alive for the connection to remain open.
            let _sink = sink;
            let mut started = false;
            while let Some(Ok(msg)) = stream.next().await {
                if msg.is_text() {
                    let t = msg.to_text().unwrap();
                    if t.contains("\"EOSE\"") {
                        started = true;
                        continue;
                    }
                    if started && t.contains("\"EVENT\"") {
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        });
    }
    let (mut pub_sink, mut pub_stream) = connect(url).await.split();
    // The relay sends an AUTH challenge first; confirm the connection is
    // alive before publishing.
    match tokio::time::timeout(Duration::from_secs(5), pub_stream.next()).await {
        Ok(Some(Ok(msg))) if msg.is_text() => {}
        other => {
            eprintln!("pub: unexpected handshake outcome {other:?}");
            std::process::exit(1);
        }
    }
    let pub_drain = tokio::spawn(async move {
        let mut ok = 0usize;
        while ok < publishes {
            match pub_stream.next().await {
                Some(Ok(_)) => ok += 1,
                _ => break,
            }
        }
    });
    // The published events must satisfy the subscribers' `since`, so
    // their created_at uses the same offset.
    let live_created = now + 60;
    let t0 = Instant::now();
    for i in 0..publishes {
        let ev = sign_event(&secp, &keypair, 1, &format!("fanout {i}"), live_created);
        pub_sink
            .send(frame(&format!(r#"["EVENT",{ev}]"#)))
            .await
            .unwrap_or_else(|e| {
                eprintln!("pub send {i} failed: {e}");
                std::process::exit(1);
            });
    }
    let _ = tokio::time::timeout(Duration::from_secs(60), pub_drain).await;
    let dt = t0.elapsed();
    // Wait for the last batch to reach every subscriber.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let delivered: usize = counters
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    println!(
        "fanout: {} subscribers, {} publishes in {:.2}s, deliveries {}/{}",
        subscribers,
        publishes,
        dt.as_secs_f64(),
        delivered,
        subscribers * publishes
    );
}

async fn req(url: &str, n: usize) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ws = connect(url).await;
    let (mut sink, mut stream) = ws.split();
    let mut ok = 0usize;
    let drain = tokio::spawn(async move {
        while ok < n {
            match stream.next().await {
                Some(Ok(_)) => ok += 1,
                _ => break,
            }
        }
    });
    for i in 0..n {
        let ev = sign_event(&secp, &keypair, 1, &format!("req {i}"), now - i as u64);
        sink.send(frame(&format!(r#"["EVENT",{ev}]"#)))
            .await
            .expect("send");
    }
    let _ = tokio::time::timeout(Duration::from_secs(60), drain).await;
    let ws2 = connect(url).await;
    let (mut sink2, mut stream2) = ws2.split();
    let t0 = Instant::now();
    sink2
        .send(frame(&format!(
            r#"["REQ","r",{{"kinds":[1],"limit":{n}}}]"#
        )))
        .await
        .unwrap();
    let mut events = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stream2.next()).await {
            Ok(Some(Ok(msg))) if msg.is_text() => {
                let t = msg.to_text().unwrap();
                if t.contains("\"EOSE\"") {
                    break;
                }
                if t.contains("\"EVENT\"") {
                    events += 1;
                }
            }
            _ => break,
        }
    }
    let dt = t0.elapsed();
    println!(
        "req: {events} events in {:.3}s (limit {n})",
        dt.as_secs_f64()
    );
}

async fn search(url: &str, term: &str) {
    let ws = connect(url).await;
    let (mut sink, mut stream) = ws.split();
    let t0 = Instant::now();
    sink.send(frame(&format!(
        r#"["REQ","s",{{"kinds":[1],"search":"{term}"}}]"#
    )))
    .await
    .unwrap();
    let mut events = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stream.next()).await {
            Ok(Some(Ok(msg))) if msg.is_text() => {
                let t = msg.to_text().unwrap();
                if t.contains("\"EOSE\"") {
                    break;
                }
                if t.contains("\"EVENT\"") {
                    events += 1;
                }
            }
            _ => break,
        }
    }
    let dt = t0.elapsed();
    println!("search: {events} events in {:.3}s", dt.as_secs_f64());
}

/// `parallel-ingest <conns> <n>`: `conns` concurrent connections each
/// publish `n` events (unique per connection), measuring the combined
/// throughput. Real deployments have many publishers, and the single
/// writer thread merges their batches, so the aggregate can exceed one
/// connection's ceiling.
async fn parallel_ingest(url: &str, conns: usize, n: usize) {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secp = Arc::new(secp);
    let mut handles = Vec::with_capacity(conns);
    for c in 0..conns {
        let url = url.to_string();
        let secp = Arc::clone(&secp);
        handles.push(tokio::spawn(async move {
            let ws = connect(&url).await;
            let (mut sink, mut stream) = ws.split();
            let drain = tokio::spawn(async move {
                let mut ok = 0usize;
                while ok < n {
                    match stream.next().await {
                        Some(Ok(msg)) if msg.is_text() => {
                            if !msg.to_text().unwrap().starts_with("[\"AUTH\"") {
                                ok += 1;
                            }
                        }
                        _ => break,
                    }
                }
            });
            const BURST: usize = 100;
            let mut sent = 0;
            while sent < n {
                for _ in 0..BURST.min(n - sent) {
                    let ev = sign_event(&secp, &keypair, 1, &format!("p{c} {sent}"), now);
                    sink.send(frame(&format!(r#"["EVENT",{ev}]"#)))
                        .await
                        .expect("send");
                    sent += 1;
                }
                tokio::task::yield_now().await;
            }
            let _ = tokio::time::timeout(Duration::from_secs(120), drain).await;
        }));
    }
    let t0 = Instant::now();
    for h in handles {
        h.await.unwrap();
    }
    let dt = t0.elapsed();
    println!(
        "parallel-ingest: {} conns x {} = {} events in {:.2}s = {:.0} ev/s",
        conns,
        n,
        conns * n,
        dt.as_secs_f64(),
        (conns * n) as f64 / dt.as_secs_f64()
    );
}

/// `parallel-req <conns> <term>`: issue the same search REQ from `conns`
/// concurrent connections and measure until every EOSE arrived. A single
/// heavy scan runs on one reader thread, so more reader threads
/// (database.reader_threads) shorten the tail latency.
async fn parallel_req(url: &str, conns: usize, term: &str) {
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(conns);
    for _ in 0..conns {
        let url = url.to_string();
        let term = term.to_string();
        handles.push(tokio::spawn(async move {
            let ws = connect(&url).await;
            let (mut sink, mut stream) = ws.split();
            sink.send(frame(&format!(
                r#"["REQ","p",{{"kinds":[1],"search":"{term}"}}]"#
            )))
            .await
            .unwrap();
            let started = Instant::now();
            loop {
                match tokio::time::timeout(Duration::from_secs(30), stream.next()).await {
                    Ok(Some(Ok(msg))) if msg.is_text() => {
                        if msg.to_text().unwrap().contains("\"EOSE\"") {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            started.elapsed()
        }));
    }
    let mut worst = Duration::ZERO;
    let mut total = Duration::ZERO;
    for h in handles {
        let dt = h.await.unwrap();
        total += dt;
        worst = worst.max(dt);
    }
    println!(
        "parallel-req: {conns} concurrent scans, worst {:.0}ms, avg {:.0}ms (total wall {:.0}ms)",
        worst.as_millis(),
        total.as_millis() / conns as u128,
        t0.elapsed().as_millis()
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: bench <ws://host:port> <ingest N | parallel-ingest C N | fanout S P | req N | search TERM | parallel-req C TERM>"
        );
        std::process::exit(1);
    }
    let url = &args[1];
    match args[2].as_str() {
        "ingest" => ingest(url, args[3].parse().expect("N")).await,
        "fanout" => {
            fanout(
                url,
                args[3].parse().expect("S"),
                args[4].parse().expect("P"),
            )
            .await
        }
        "req" => req(url, args[3].parse().expect("N")).await,
        "search" => search(url, &args[3]).await,
        "parallel-req" => parallel_req(url, args[3].parse().expect("C"), &args[4]).await,
        "parallel-ingest" => {
            parallel_ingest(
                url,
                args[3].parse().expect("C"),
                args[4].parse().expect("N"),
            )
            .await
        }
        other => {
            eprintln!("unknown scenario {other}");
            std::process::exit(1);
        }
    }
}
