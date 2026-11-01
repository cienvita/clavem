//! Write-behind for usage events.
//!
//! The request path hands events to a bounded channel and never waits on
//! Postgres. A single task drains it in batches. A failed batch is
//! retried with backoff and is idempotent (`request_id` is unique), so a
//! retry after a commit whose acknowledgement was lost does not double
//! count. While retrying, new events queue in the channel; once it is
//! full, new events are dropped and counted. Recording fails open, auth
//! fails closed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::db::{Db, UsageEvent};

const CHANNEL: usize = 10_000;
const BATCH: usize = 500;
const LINGER: Duration = Duration::from_millis(250);

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<UsageEvent>,
    stop: Arc<Notify>,
    pub dropped: Arc<AtomicU64>,
}

impl Writer {
    pub fn spawn(db: Db) -> (Writer, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(CHANNEL);
        let dropped = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(Notify::new());
        let handle = tokio::spawn(run(db, rx, stop.clone()));
        (Writer { tx, stop, dropped }, handle)
    }

    /// Asks the writer to flush what is queued and exit. Events sent
    /// after this are dropped.
    pub fn stop(&self) {
        self.stop.notify_one();
    }

    pub fn send(&self, e: UsageEvent) {
        if let Err(err) = self.tx.try_send(e) {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            let ev = match &err {
                mpsc::error::TrySendError::Full(e) | mpsc::error::TrySendError::Closed(e) => e,
            };
            error!(
                "usage writer: dropped event {} (tenant {}, model {}, ts {}); {n} dropped so far",
                ev.request_id, ev.tenant_id, ev.model, ev.ts
            );
        }
    }
}

async fn run(db: Db, mut rx: mpsc::Receiver<UsageEvent>, stop: Arc<Notify>) {
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        // Block for the first event, then linger briefly to fill a batch.
        tokio::select! {
            e = rx.recv() => match e {
                Some(e) => batch.push(e),
                None => break,
            },
            _ = stop.notified() => {
                rx.close();
                while let Some(e) = rx.recv().await {
                    batch.push(e);
                    if batch.len() >= BATCH {
                        flush(&db, &mut batch).await;
                    }
                }
                break;
            }
        }
        let deadline = tokio::time::Instant::now() + LINGER;
        while batch.len() < BATCH {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(e)) => batch.push(e),
                Ok(None) | Err(_) => break,
            }
        }
        flush(&db, &mut batch).await;
    }
    if !batch.is_empty() {
        flush(&db, &mut batch).await;
    }
    info!("usage writer: stopped");
}

/// Consecutive whole-batch failures before trying events one at a time.
const SPLIT_AFTER: u32 = 3;

async fn flush(db: &Db, batch: &mut Vec<UsageEvent>) {
    let mut delay = Duration::from_millis(200);
    let mut failures = 0;
    loop {
        match db.write_batch(batch).await {
            Ok(n) => {
                if n < batch.len() {
                    warn!("usage writer: {} duplicate events skipped", batch.len() - n);
                }
                batch.clear();
                return;
            }
            Err(e) => {
                failures += 1;
                error!(
                    "usage writer: writing {} events failed (attempt {failures}): {e:#}",
                    batch.len()
                );
            }
        }
        // A batch that keeps failing may hold one event Postgres will never
        // accept. Write singly: if some succeed the database is up, and the
        // ones that still fail are dropped rather than blocking every event
        // queued behind them. If none succeed but the database answers a
        // ping, every event is bad and all are dropped. Otherwise the
        // database is down and the batch is kept.
        if failures >= SPLIT_AFTER {
            let mut bad = Vec::new();
            let mut wrote = 0;
            for e in batch.iter() {
                match db.write_batch(std::slice::from_ref(e)).await {
                    Ok(_) => wrote += 1,
                    Err(err) => bad.push((e, err)),
                }
            }
            if wrote > 0 || db.ping().await.is_ok() {
                for (e, err) in &bad {
                    error!(
                        "usage writer: dropping event {} (tenant {}, model {}, ts {}): {err:#}",
                        e.request_id, e.tenant_id, e.model, e.ts
                    );
                }
                batch.clear();
                return;
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(10));
    }
}
