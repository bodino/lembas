//! Sessions: one two-party setup, many TLS connections, many requests.
//!
//! A session is one link between a borrower and a pool, kept for as long as
//! the borrower has requests to make. Inside it the borrower opens TLS
//! connections to the server on demand (one per request in flight, reused
//! with HTTP keep-alive), and every request is one spliced token record on
//! one of them. The zero-knowledge prover and verifier, with their OT setup,
//! are built once per session; a connection's key is just another witness.
//!
//! Frames carry a connection id. Everything the borrower sends goes on `up`,
//! everything the pool sends on `down`, the two-party computation on `mpc`.
//!
//! What the pool enforces per connection, so that the token record always
//! begins a fresh HTTP request:
//!
//! - before the first splice only handshake records pass (no application
//!   data, so the token record cannot continue something the borrower wrote);
//! - the token record is the whole request head, blank line included, so the
//!   borrower writes nothing the server could parse as framing; after a
//!   splice the borrower may send exactly `Content-Length` bytes of body,
//!   counted from the relayed records' plaintext lengths, and no application
//!   data outside that window: fewer bytes would make the next token record
//!   part of this body, more would make it the body of a pipelined request;
//! - a later splice must announce the sequence number the pool expects from
//!   the records it counted (the first one is 1: a TLS 1.2 client sends one
//!   encrypted record, `Finished`, before any application data), and no
//!   borrower record may reuse a token record's explicit nonce.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail, ensure};
use mpz_common::Context;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Mutex, Notify, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    Hello, MAX_BODY_LEN, PROTOCOL_VERSION, RequestHeader, SETUP_TIMEOUT, TOKEN_LEN,
    check_template, check_trailer, fill_template,
    record::{
        ALERT, APPLICATION_DATA, CHANGE_CIPHER_SPEC, CLOSE_NOTIFY, HANDSHAKE, LocalRecordLayer,
        LocalRecordReader, LocalRecordWriter, MAX_RECORD_PLAINTEXT,
    },
    splice::{Deframer, Proving, Verifying, extract_keys, span_blocks, tls_config},
    split_template,
};

/// Most handshake bytes the pool relays from the borrower on one connection
/// before its first splice.
pub const MAX_HANDSHAKE_BYTES: usize = 64 << 10;
/// Largest frame either side accepts.
pub const MAX_FRAME_BYTES: usize = 256 << 10;
/// Connections a session may have open at once.
pub const MAX_CONNECTIONS: usize = 16;
/// A session with no frame from the peer for this long is over.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
/// How long the borrower waits for a response to finish once it has begun
/// sending, from the last byte received (a model's thinking pause fits).
pub const RESPONSE_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the pool gives the lender lookup before it refuses the request:
/// shorter than the borrower's wait for `Accepted` (`SETUP_TIMEOUT`), so the
/// borrower is still there to hear the answer.
pub const LEASE_TIMEOUT: Duration = Duration::from_secs(45);
/// Frame size the borrower batches its records into.
const FRAME_TARGET: usize = 64 << 10;
/// Frames buffered per connection between tasks.
const CONN_QUEUE: usize = 64;
/// Requests after which the two-party setup is rebuilt. Measured, the VMs do
/// not grow with requests (resident memory plateaus after a dozen), so this
/// bounds the slow growth of the VMs' memory (about 80 KB of keys per
/// request): a renewal costs an OT setup (~0.9 MB) once in a while.
pub const RENEW_AFTER: usize = 256;

/// Everything the borrower sends.
#[derive(Serialize, Deserialize)]
pub enum Up {
    /// Open a connection to the server under this id.
    Open { conn: u32 },
    /// TLS bytes for the server.
    Bytes { conn: u32, bytes: Vec<u8> },
    /// Splice a token record: `header` is the whole request head, which the
    /// pool checks, fills and writes; the borrower follows with the body.
    Request {
        conn: u32,
        header: RequestHeader,
        seq: u64,
        nonce: [u8; 12],
    },
    /// The borrower's share of the pending token record's tag.
    TagShare { conn: u32, share: [u8; 16] },
    /// Done with this connection.
    Close { conn: u32 },
    /// The borrower starts a fresh two-party setup (both sides warm up again
    /// on `mpc` before the next request).
    Renew,
    /// Done with the session.
    Done,
}

/// Everything the pool sends, after its [`Hello`].
#[derive(Serialize, Deserialize)]
pub enum Down {
    Opened { conn: u32 },
    OpenFailed { conn: u32, reason: String },
    /// TLS bytes from the server.
    Bytes { conn: u32, bytes: Vec<u8> },
    /// A lender is found for the request; the proof starts now. `req`
    /// numbers the request within the session.
    Accepted { conn: u32, req: u64 },
    /// The token record is on its way to the server.
    Spliced { conn: u32, req: u64 },
    /// No token for this request (nobody lending right now, say). The
    /// connection stays usable.
    Refused { conn: u32, reason: String },
    /// The token record was not written (the connection went away first):
    /// nothing reached the server, so the request may move to another.
    Aborted { conn: u32 },
    /// The server closed this connection.
    ServerClosed { conn: u32 },
}

impl std::fmt::Display for Up {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Up::Open { conn } => write!(f, "Open({conn})"),
            Up::Bytes { conn, bytes } => write!(f, "Bytes({conn}, {})", bytes.len()),
            Up::Request { conn, seq, .. } => write!(f, "Request({conn}, seq {seq})"),
            Up::TagShare { conn, .. } => write!(f, "TagShare({conn})"),
            Up::Close { conn } => write!(f, "Close({conn})"),
            Up::Renew => f.write_str("Renew"),
            Up::Done => f.write_str("Done"),
        }
    }
}

impl std::fmt::Display for Down {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Down::Opened { conn } => write!(f, "Opened({conn})"),
            Down::OpenFailed { conn, reason } => write!(f, "OpenFailed({conn}, {reason})"),
            Down::Bytes { conn, bytes } => write!(f, "Bytes({conn}, {})", bytes.len()),
            Down::Accepted { conn, req } => write!(f, "Accepted({conn}, req {req})"),
            Down::Spliced { conn, req } => write!(f, "Spliced({conn}, req {req})"),
            Down::Refused { conn, reason } => write!(f, "Refused({conn}, {reason})"),
            Down::Aborted { conn } => write!(f, "Aborted({conn})"),
            Down::ServerClosed { conn } => write!(f, "ServerClosed({conn})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pool

/// A token for one request, and the number the pool gives that request.
pub struct Lease {
    pub token: String,
    pub req: u64,
}

/// Where the pool gets a token for each request: a fixed one, or a parent
/// process that picks a lender per request.
pub type TokenSource =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Option<Lease>>> + Send>> + Send + Sync>;

/// A token source lending the same credential to every request.
pub fn fixed_token(token: String) -> TokenSource {
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    Arc::new(move || {
        let token = token.clone();
        let req = counter.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move { Ok(Some(Lease { token, req })) })
    })
}

/// Opens a connection to the server.
pub type Connector<S> =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<S>> + Send>> + Send + Sync>;

/// Test hook: a misbehaving pool's change to a request's headers after the
/// token is in place.
pub type Tamper = Option<Arc<dyn Fn(&mut Vec<u8>) + Send + Sync>>;

/// Told to the parent after each splice (which request went on which lease).
pub type OnSpliced = Arc<dyn Fn(u64) + Send + Sync>;

/// What the pool counted.
#[derive(Debug, Default)]
pub struct PoolStats {
    pub connections: u64,
    pub requests: u64,
    pub refused: u64,
}

/// Where a pool-side connection is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Before the first splice: handshake records only.
    Handshake,
    /// Between requests: nothing but alerts may pass.
    Idle,
    /// A token record is being computed.
    Splicing,
    /// The borrower is sending the rest of a request.
    Sending,
}

/// The per-connection state the pool keeps, and the checks on it. Pure, so
/// it can be tested without a network.
struct Gate {
    phase: Phase,
    handshake_bytes: usize,
    spliced_once: bool,
    last_splice_seq: u64,
    records_since_splice: u64,
    /// Explicit nonces seen on this connection, token records' and the
    /// borrower's alike.
    nonces: HashSet<[u8; 8]>,
    /// Bytes of the current request the borrower has yet to send.
    remaining: usize,
}

impl Gate {
    fn new() -> Self {
        Self {
            phase: Phase::Handshake,
            handshake_bytes: 0,
            spliced_once: false,
            last_splice_seq: 0,
            records_since_splice: 0,
            nonces: HashSet::new(),
            remaining: 0,
        }
    }

    /// Admits one record from the borrower, or refuses it.
    fn accept_record(&mut self, record: &[u8]) -> Result<()> {
        let typ = record[0];
        let payload = &record[5..];
        match self.phase {
            Phase::Handshake => {
                self.handshake_bytes += record.len();
                ensure!(
                    self.handshake_bytes <= MAX_HANDSHAKE_BYTES,
                    "more than {MAX_HANDSHAKE_BYTES} bytes of handshake"
                );
                ensure!(
                    typ != APPLICATION_DATA,
                    "borrower sent application data before the token record"
                );
                Ok(())
            }
            Phase::Idle | Phase::Splicing => {
                ensure!(
                    typ == ALERT,
                    "borrower sent a record of type {typ} outside a request"
                );
                // An alert takes a sequence number like any encrypted record.
                self.records_since_splice += 1;
                Ok(())
            }
            Phase::Sending => match typ {
                APPLICATION_DATA => {
                    ensure!(payload.len() >= 24, "application-data record too short");
                    let nonce: [u8; 8] = payload[..8].try_into().unwrap();
                    // Every nonce on this connection, the pool's and the
                    // borrower's, is used once.
                    ensure!(
                        self.nonces.insert(nonce),
                        "borrower record reuses a nonce"
                    );
                    let plaintext = payload.len() - 24;
                    ensure!(
                        plaintext <= self.remaining,
                        "borrower sent {} bytes more than the request it announced",
                        plaintext - self.remaining
                    );
                    self.remaining -= plaintext;
                    self.records_since_splice += 1;
                    if self.remaining == 0 {
                        self.phase = Phase::Idle;
                    }
                    Ok(())
                }
                ALERT => {
                    self.records_since_splice += 1;
                    Ok(())
                }
                HANDSHAKE | CHANGE_CIPHER_SPEC => bail!("borrower sent a handshake record after the splice"),
                other => bail!("record of unknown type {other}"),
            },
        }
    }

    /// Admits a splice request, or refuses it.
    fn accept_splice(&mut self, seq: u64, nonce: &[u8; 12]) -> Result<()> {
        match self.phase {
            Phase::Handshake | Phase::Idle => {}
            Phase::Splicing => bail!("borrower asked for a token record while one is pending"),
            Phase::Sending => bail!(
                "borrower asked for a token record with {} bytes of the previous request unsent",
                self.remaining
            ),
        }
        let expected = if self.spliced_once {
            self.last_splice_seq + 1 + self.records_since_splice
        } else {
            // One encrypted record before application data: the client's
            // Finished.
            1
        };
        ensure!(
            seq == expected,
            "token record sequence number {seq} does not follow the {} records sent (expected {expected})",
            self.records_since_splice
        );
        let explicit: [u8; 8] = nonce[4..].try_into().unwrap();
        ensure!(!self.nonces.contains(&explicit), "token record nonce reused");
        self.phase = Phase::Splicing;
        Ok(())
    }

    /// The token record is written; the borrower may send `request_len` bytes.
    fn spliced(&mut self, seq: u64, nonce: &[u8; 12], request_len: usize) {
        self.spliced_once = true;
        self.last_splice_seq = seq;
        self.records_since_splice = 0;
        self.nonces.insert(nonce[4..].try_into().unwrap());
        self.remaining = request_len;
        self.phase = if request_len == 0 { Phase::Idle } else { Phase::Sending };
    }

    /// The token record could not be made; back to where we were.
    fn splice_failed(&mut self) {
        self.phase = if self.spliced_once { Phase::Idle } else { Phase::Handshake };
    }
}

struct PoolConn {
    gate: Gate,
    deframer: Deframer,
    to_server: mpsc::UnboundedSender<Vec<u8>>,
    /// Bytes queued for the server and not yet written.
    pending: Arc<std::sync::atomic::AtomicUsize>,
    reader: tokio::task::AbortHandle,
    pending_tag: Option<oneshot::Sender<[u8; 16]>>,
}

impl PoolConn {
    /// Queues bytes for the server without waiting on it; a server too far
    /// behind loses the connection rather than stalling the session.
    fn queue(&self, bytes: Vec<u8>) -> Result<()> {
        let pending = self.pending.fetch_add(bytes.len(), Ordering::Relaxed) + bytes.len();
        ensure!(
            pending <= crate::MAX_PENDING_BYTES,
            "server is {pending} bytes behind on this connection"
        );
        self.to_server
            .send(bytes)
            .map_err(|_| anyhow::anyhow!("server connection closed"))
    }
}

enum Event {
    Connected {
        conn: u32,
        to_server: mpsc::UnboundedSender<Vec<u8>>,
        pending: Arc<std::sync::atomic::AtomicUsize>,
        reader: tokio::task::AbortHandle,
    },
    /// No lender for this request; the connection stays.
    Refused {
        conn: u32,
        reason: String,
    },
    /// The token record could not be written for a reason on the wire (the
    /// server or the borrower closed the connection meanwhile); the
    /// connection goes, the session stays.
    SpliceAborted {
        conn: u32,
        err: anyhow::Error,
    },
    ConnectFailed {
        conn: u32,
        err: String,
    },
    Spliced {
        conn: u32,
        req: u64,
        seq: u64,
        nonce: [u8; 12],
        request_len: usize,
    },
    SpliceFailed {
        conn: u32,
        err: anyhow::Error,
    },
    ServerGone {
        conn: u32,
    },
    Fatal(anyhow::Error),
}

/// Work for the proof task.
enum Job {
    Splice {
        conn: u32,
        header: RequestHeader,
        seq: u64,
        nonce: [u8; 12],
        request_len: usize,
        /// The lender lookup, awaited here so that a slow one holds up the
        /// proofs, which are sequential anyway, and not the relay.
        lease: Pin<Box<dyn Future<Output = Result<Option<Lease>>> + Send>>,
        tag_rx: oneshot::Receiver<[u8; 16]>,
        conn_state: (mpsc::UnboundedSender<Vec<u8>>, Arc<std::sync::atomic::AtomicUsize>),
    },
    Renew,
}

/// Runs the pool's side of a session.
///
/// `connect` opens a connection to the API server for each `Open`;
/// `server_name` is the `Host` the borrower must use; `tokens` supplies a
/// token per request; `on_spliced` is told the request number of each record
/// written; `tamper` is a test hook for a misbehaving pool.
#[allow(clippy::too_many_arguments)]
pub async fn run_pool<S>(
    mpc: Context,
    mut up: Context,
    mut down: Context,
    connect: Connector<S>,
    server_name: &str,
    tokens: TokenSource,
    on_spliced: Option<OnSpliced>,
    tamper: Tamper,
) -> Result<PoolStats>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    down.io_mut()
        .send(Hello {
            version: PROTOCOL_VERSION,
            token_len: TOKEN_LEN,
            server_name: server_name.to_string(),
        })
        .await
        .context("prelude: greeting the borrower")?;

    // The OT setup, paid once per session.
    let t = Instant::now();
    let mut mpc = mpc;
    let mut verifying = Verifying::new();
    tokio::time::timeout(SETUP_TIMEOUT, verifying.warm_up(&mut mpc))
        .await
        .context("warm-up timed out")??;
    info!(took = ?t.elapsed(), "pool: session ready");

    // Everything the pool sends goes through one task.
    let (down_tx, mut down_rx) = mpsc::channel::<Down>(CONN_QUEUE);
    let mut tasks = JoinSet::new();
    let (events_tx, mut events) = mpsc::channel::<Event>(CONN_QUEUE);

    // The proofs run on one task, in the order the requests arrived: the
    // borrower proves in that same order, under one lock, so the two sides'
    // transcripts on `mpc` line up.
    let (jobs_tx, mut jobs) = mpsc::channel::<Job>(CONN_QUEUE);
    {
        let events_tx = events_tx.clone();
        let down_tx = down_tx.clone();
        let tamper = tamper.clone();
        tasks.spawn(async move {
            while let Some(job) = jobs.recv().await {
                match job {
                    Job::Renew => {
                        let t = Instant::now();
                        verifying = Verifying::new();
                        if let Err(e) = tokio::time::timeout(SETUP_TIMEOUT, verifying.warm_up(&mut mpc))
                            .await
                            .context("renewal timed out")
                            .and_then(|r| r)
                        {
                            let _ = events_tx.send(Event::Fatal(e)).await;
                            return Ok(());
                        }
                        info!(took = ?t.elapsed(), "pool: setup renewed");
                    }
                    Job::Splice { conn, header, seq, nonce, request_len, lease, tag_rx, conn_state } => {
                        // A lender, or not. Bounded: the borrower gives up
                        // waiting at SETUP_TIMEOUT, and an answer after that
                        // would start a proof nobody joins.
                        let lease = match tokio::time::timeout(LEASE_TIMEOUT, lease)
                            .await
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("no lender found in {} s", LEASE_TIMEOUT.as_secs())))
                        {
                            Ok(Some(lease)) if lease.token.len() == TOKEN_LEN
                                && !lease.token.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) =>
                            {
                                lease
                            }
                            Ok(Some(_)) => {
                                let _ = events_tx
                                    .send(Event::Refused { conn, reason: "the lent credential is not a token".into() })
                                    .await;
                                continue;
                            }
                            Ok(None) => {
                                let _ = events_tx.send(Event::Refused { conn, reason: "no token available".into() }).await;
                                continue;
                            }
                            Err(e) => {
                                let _ = events_tx.send(Event::Refused { conn, reason: format!("{e:#}") }).await;
                                continue;
                            }
                        };
                        let req = lease.req;
                        let mut headers = header.template.clone();
                        let span = &mut headers[header.token.clone()];
                        span.fill(b' ');
                        span[..lease.token.len()].copy_from_slice(lease.token.as_bytes());
                        drop(lease);
                        if let Some(tamper) = &tamper {
                            tamper(&mut headers);
                        }
                        let span_idx = span_blocks(&header);
                        // The borrower proves only once it knows there is a lender.
                        if down_tx.send(Down::Accepted { conn, req }).await.is_err() {
                            return Ok(());
                        }

                        // The proof: a failure here is the borrower cheating,
                        // and a borrower that stops proving (it gave up on the
                        // request) would leave this worker, and every request
                        // behind it, waiting forever. Bounded like the
                        // borrower's half; a session that times out here is
                        // better replaced than left limping.
                        let proven = tokio::time::timeout(
                            SETUP_TIMEOUT,
                            verifying.ciphertext_and_tag_share(&mut mpc, &headers, &span_idx, seq, &nonce),
                        )
                        .await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("the borrower did not finish its proof in time")));
                        let (ciphertext, mine) = match proven {
                            Ok(x) => x,
                            Err(err) => {
                                let _ = events_tx.send(Event::SpliceFailed { conn, err }).await;
                                return Ok(());
                            }
                        };
                        // The wire: a failure here is a connection gone.
                        let written = async {
                            let theirs = tokio::time::timeout(SETUP_TIMEOUT, tag_rx)
                                .await
                                .context("waiting for the borrower's tag share")?
                                .context("borrower never sent its tag share")?;
                            let record = Verifying::finish_record(&nonce, &ciphertext, mine, theirs);
                            let (to_server, pending) = &conn_state;
                            pending.fetch_add(record.len(), Ordering::Relaxed);
                            to_server
                                .send(record)
                                .map_err(|_| anyhow::anyhow!("server connection closed"))?;
                            Ok::<_, anyhow::Error>(())
                        }
                        .await;
                        let event = match written {
                            Ok(()) => Event::Spliced { conn, req, seq, nonce, request_len },
                            Err(err) => Event::SpliceAborted { conn, err },
                        };
                        if events_tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
            Ok(())
        });
    }
    tasks.spawn(async move {
        while let Some(frame) = down_rx.recv().await {
            if let Err(e) = down.io_mut().send(frame).await {
                debug!("pool: borrower left: {e}");
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    let mut conns: HashMap<u32, PoolConn> = HashMap::new();
    let mut connecting: HashSet<u32> = HashSet::new();
    let mut stats = PoolStats::default();
    let server_name = server_name.to_string();

    loop {
        tokio::select! {
            frame = tokio::time::timeout(SESSION_IDLE_TIMEOUT, up.io_mut().expect_next::<Up>()) => {
                let frame = match frame.context("no frame from the borrower for 2 h")? {
                    Ok(frame) => frame,
                    // The borrower closing its end is also how a session ends.
                    Err(e) => {
                        debug!("pool: borrower left: {e}");
                        break;
                    }
                };
                match frame {
                    Up::Open { conn } => {
                        ensure!(
                            !conns.contains_key(&conn) && connecting.insert(conn),
                            "connection {conn} already open"
                        );
                        ensure!(
                            conns.len() + connecting.len() <= MAX_CONNECTIONS,
                            "more than {MAX_CONNECTIONS} connections"
                        );
                        stats.connections += 1;
                        let connect = connect.clone();
                        let events_tx = events_tx.clone();
                        let down_tx = down_tx.clone();
                        tasks.spawn(async move {
                            match tokio::time::timeout(SETUP_TIMEOUT, connect()).await {
                                Ok(Ok(server)) => {
                                    let (rd, wr) = tokio::io::split(server);
                                    let (to_server, from_borrower) = mpsc::unbounded_channel::<Vec<u8>>();
                                    let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                                    let reader = tokio::spawn(read_server(conn, rd, down_tx, events_tx.clone()));
                                    tokio::spawn(write_server(conn, wr, from_borrower, pending.clone(), events_tx.clone()));
                                    let _ = events_tx
                                        .send(Event::Connected { conn, to_server, pending, reader: reader.abort_handle() })
                                        .await;
                                }
                                Ok(Err(e)) => {
                                    let _ = events_tx.send(Event::ConnectFailed { conn, err: format!("{e:#}") }).await;
                                }
                                Err(_) => {
                                    let _ = events_tx
                                        .send(Event::ConnectFailed { conn, err: "connect timed out".into() })
                                        .await;
                                }
                            }
                            Ok(())
                        });
                    }
                    Up::Bytes { conn, bytes } => {
                        ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                        let Some(c) = conns.get_mut(&conn) else {
                            ensure!(!connecting.contains(&conn), "bytes for a connection that is not open yet");
                            debug!("pool: bytes for closed connection {conn}, dropped");
                            continue;
                        };
                        c.deframer.push(&bytes);
                        let mut gone = None;
                        while let Some(record) = c.deframer.next_record()? {
                            c.gate.accept_record(&record)?;
                            if let Err(e) = c.queue(record) {
                                gone = Some(e);
                                break;
                            }
                        }
                        if let Some(e) = gone {
                            warn!("pool: dropping connection {conn}: {e:#}");
                            if let Some(c) = conns.remove(&conn) {
                                c.reader.abort();
                            }
                            let _ = down_tx.send(Down::ServerClosed { conn }).await;
                        }
                    }
                    Up::Request { conn, header, seq, nonce } => {
                        let Some(c) = conns.get_mut(&conn) else {
                            // The server closed it a moment ago; the borrower
                            // will hear so and try another connection.
                            debug!("pool: token record requested on closed connection {conn}");
                            let _ = down_tx.send(Down::ServerClosed { conn }).await;
                            continue;
                        };
                        ensure!(c.deframer.is_empty(), "partial record pending at the splice");
                        check_template(&header, TOKEN_LEN, &server_name).context("borrower's header rejected")?;
                        let body_len = check_trailer(&header, &[]).context("borrower's header rejected")?;
                        c.gate.accept_splice(seq, &nonce)?;
                        let (tag_tx, tag_rx) = oneshot::channel();
                        c.pending_tag = Some(tag_tx);
                        jobs_tx
                            .send(Job::Splice {
                                conn,
                                header,
                                seq,
                                nonce,
                                request_len: body_len,
                                lease: tokens(),
                                tag_rx,
                                conn_state: (c.to_server.clone(), c.pending.clone()),
                            })
                            .await
                            .map_err(|_| anyhow::anyhow!("proof worker is gone"))?;
                    }
                    Up::TagShare { conn, share } => {
                        // For a connection the server just closed there is
                        // nobody waiting; the job notices and aborts.
                        if let Some(c) = conns.get_mut(&conn) {
                            let tx = c.pending_tag.take().context("tag share without a pending token record")?;
                            let _ = tx.send(share);
                        }
                    }
                    Up::Close { conn } => {
                        if let Some(c) = conns.remove(&conn) {
                            c.reader.abort();
                            debug!("pool: connection {conn} closed by the borrower");
                        }
                    }
                    Up::Renew => {
                        jobs_tx
                            .send(Job::Renew)
                            .await
                            .map_err(|_| anyhow::anyhow!("proof worker is gone"))?;
                    }
                    Up::Done => break,
                }
            }
            Some(event) = events.recv() => match event {
                Event::Connected { conn, to_server, pending, reader } => {
                    connecting.remove(&conn);
                    conns.insert(conn, PoolConn {
                        gate: Gate::new(),
                        deframer: Deframer::default(),
                        to_server,
                        pending,
                        reader,
                        pending_tag: None,
                    });
                    let _ = down_tx.send(Down::Opened { conn }).await;
                }
                Event::Refused { conn, reason } => {
                    stats.refused += 1;
                    if let Some(c) = conns.get_mut(&conn) {
                        c.gate.splice_failed();
                        c.pending_tag = None;
                    }
                    let _ = down_tx.send(Down::Refused { conn, reason }).await;
                }
                Event::SpliceAborted { conn, err } => {
                    debug!("pool: token record for connection {conn} not written: {err:#}");
                    if let Some(c) = conns.remove(&conn) {
                        c.reader.abort();
                    }
                    let _ = down_tx.send(Down::Aborted { conn }).await;
                }
                Event::ConnectFailed { conn, err } => {
                    connecting.remove(&conn);
                    warn!("pool: connecting for {conn}: {err}");
                    let _ = down_tx.send(Down::OpenFailed { conn, reason: err }).await;
                }
                Event::Spliced { conn, req, seq, nonce, request_len } => {
                    if let Some(c) = conns.get_mut(&conn) {
                        c.gate.spliced(seq, &nonce, request_len);
                        stats.requests += 1;
                        if let Some(cb) = &on_spliced {
                            cb(req);
                        }
                        debug!(conn, req, seq, "pool: token record written");
                        let _ = down_tx.send(Down::Spliced { conn, req }).await;
                    }
                }
                Event::SpliceFailed { conn, err } => {
                    // A failed proof is the borrower cheating or a bug; either
                    // way this session is over.
                    return Err(err.context(format!("token record for connection {conn}")));
                }
                Event::Fatal(err) => return Err(err),
                Event::ServerGone { conn } => {
                    if let Some(c) = conns.remove(&conn) {
                        c.reader.abort();
                        let _ = down_tx.send(Down::ServerClosed { conn }).await;
                    }
                }
            },
        }
    }
    for (_, c) in conns.drain() {
        c.reader.abort();
    }
    tasks.abort_all();
    info!(?stats, "pool: session done");
    Ok(stats)
}

/// Forwards the server's bytes to the borrower until the server closes.
async fn read_server<R: AsyncRead + Unpin>(
    conn: u32,
    mut rd: R,
    down_tx: mpsc::Sender<Down>,
    events_tx: mpsc::Sender<Event>,
) {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if down_tx
                    .send(Down::Bytes {
                        conn,
                        bytes: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = events_tx.send(Event::ServerGone { conn }).await;
}

/// Writes the borrower's records to the server in order.
async fn write_server<W: AsyncWrite + Unpin>(
    conn: u32,
    mut wr: W,
    mut from_borrower: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: Arc<std::sync::atomic::AtomicUsize>,
    events_tx: mpsc::Sender<Event>,
) {
    while let Some(bytes) = from_borrower.recv().await {
        let n = bytes.len();
        let written = wr.write_all(&bytes).await;
        pending.fetch_sub(n, Ordering::Relaxed);
        if written.is_err() {
            let _ = events_tx.send(Event::ServerGone { conn }).await;
            return;
        }
    }
    let _ = wr.shutdown().await;
}

// ---------------------------------------------------------------------------
// Borrower

/// What one request came back with.
#[derive(Debug)]
pub struct Response {
    /// The pool's number for the request.
    pub req: u64,
    /// HTTP status, once the head arrived.
    pub status: Option<u16>,
    /// Response bytes, head included.
    pub bytes: usize,
    /// Time from sending the body to the first response byte.
    pub first_byte: Duration,
    /// Whether the connection was reused from an earlier request.
    pub reused: bool,
}

/// The pool declined to lend for this request; the connection is still fine.
#[derive(Debug, thiserror::Error)]
#[error("pool refused: {0}")]
pub struct Refused(pub String);

/// A reused connection turned out to be closed before the request went out;
/// nothing was sent, so another connection can take the request.
#[derive(Debug, thiserror::Error)]
#[error("connection was closed by the server while idle")]
struct Stale;

/// A borrower's session with a pool.
pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    up: mpsc::Sender<Up>,
    mpc: Mutex<(Proving, Context)>,
    routes: std::sync::Mutex<HashMap<u32, mpsc::Sender<Down>>>,
    idle: std::sync::Mutex<Vec<Conn>>,
    idle_notify: Notify,
    slots: Arc<Semaphore>,
    next_conn: AtomicU32,
    config: Arc<rustls::ClientConfig>,
    server_name: String,
    token_len: usize,
}

/// One TLS connection to the server, as the borrower holds it.
struct Conn {
    id: u32,
    rx: mpsc::Receiver<Down>,
    writer: LocalRecordWriter,
    reader: LocalRecordReader,
    key: [u8; 16],
    iv: [u8; 4],
    deframer: Deframer,
    _slot: tokio::sync::OwnedSemaphorePermit,
}

impl Session {
    /// Opens a session: reads the pool's `Hello`, pays the OT setup. The
    /// `down` reader and `up` writer run as tasks until the session is
    /// dropped.
    pub async fn start(
        mpc: Context,
        mut up: Context,
        mut down: Context,
        roots: &rustls::RootCertStore,
        server_name: &str,
        token_len: usize,
    ) -> Result<Self> {
        let hello: Hello = tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next())
            .await
            .context("waiting for the pool's hello")??;
        info!(?hello, "borrower: pool says hello");
        ensure!(
            hello.version == PROTOCOL_VERSION,
            "pool speaks protocol version {}, this borrower {PROTOCOL_VERSION}",
            hello.version
        );
        ensure!(
            hello.token_len == token_len,
            "pool announced a {}-byte token, expected {token_len}",
            hello.token_len
        );
        ensure!(
            hello.server_name == server_name,
            "pool lends for {}, this borrower wants {server_name}",
            hello.server_name
        );

        let t = Instant::now();
        let mut mpc = mpc;
        let mut proving = Proving::new();
        tokio::time::timeout(SETUP_TIMEOUT, proving.warm_up(&mut mpc))
            .await
            .context("warm-up timed out")??;
        info!(took = ?t.elapsed(), "borrower: session ready");

        let (up_tx, mut up_rx) = mpsc::channel::<Up>(CONN_QUEUE);
        tokio::spawn(async move {
            while let Some(frame) = up_rx.recv().await {
                if let Err(e) = up.io_mut().send(frame).await {
                    debug!("borrower: pool left: {e}");
                    break;
                }
            }
        });

        let inner = Arc::new(Inner {
            up: up_tx,
            mpc: Mutex::new((proving, mpc)),
            routes: std::sync::Mutex::new(HashMap::new()),
            idle: std::sync::Mutex::new(Vec::new()),
            idle_notify: Notify::new(),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            next_conn: AtomicU32::new(1),
            config: tls_config(roots)?,
            server_name: server_name.to_string(),
            token_len,
        });

        let routes = Arc::clone(&inner);
        tokio::spawn(async move {
            loop {
                let frame = match down.io_mut().expect_next::<Down>().await {
                    Ok(frame) => frame,
                    Err(e) => {
                        debug!("borrower: pool left: {e}");
                        routes.routes.lock().unwrap().clear();
                        break;
                    }
                };
                let conn = match &frame {
                    Down::Opened { conn }
                    | Down::OpenFailed { conn, .. }
                    | Down::Bytes { conn, .. }
                    | Down::Accepted { conn, .. }
                    | Down::Spliced { conn, .. }
                    | Down::Refused { conn, .. }
                    | Down::Aborted { conn }
                    | Down::ServerClosed { conn } => *conn,
                };
                let route = routes.routes.lock().unwrap().get(&conn).cloned();
                match route {
                    Some(tx) => {
                        if tx.send(frame).await.is_err() {
                            routes.routes.lock().unwrap().remove(&conn);
                        }
                    }
                    None => debug!("borrower: frame for unknown connection {conn}"),
                }
            }
        });

        Ok(Self { inner })
    }

    /// Ends the session. Connections still open are closed by the pool when
    /// the link goes.
    pub async fn close(&self) {
        let _ = self.inner.up.send(Up::Done).await;
    }

    /// Makes one request. `template` is the full header with
    /// [`TOKEN_MARKER`](crate::TOKEN_MARKER) and [`BODY_LEN_MARKER`](crate::BODY_LEN_MARKER)
    /// and a blank line at the end. The response is copied to `out` as it
    /// arrives; `on_req` is told the pool's request number before the first
    /// response byte.
    pub async fn request<W: AsyncWrite + Unpin + Send>(
        &self,
        template: &str,
        body: Vec<u8>,
        out: &mut W,
        on_req: impl FnOnce(u64) + Send + 'static,
    ) -> Result<Response> {
        let on_req: Box<dyn FnOnce(u64) + Send> = Box::new(on_req);
        let inner = &self.inner;
        let template = template.replace(crate::HOST_MARKER, &inner.server_name);
        let (head, trailer) = split_template(&template)?;
        debug_assert!(trailer.is_empty());
        let header = fill_template(&head, inner.token_len, body.len())?;
        ensure!(body.len() <= MAX_BODY_LEN, "body of {} bytes is over the limit", body.len());
        check_template(&header, inner.token_len, &inner.server_name)?;
        check_trailer(&header, &trailer)?;
        let span_idx = span_blocks(&header);

        let (mut conn, mut reused) = inner.take_connection().await?;
        let mut retried = false;
        let mut on_req = Some(on_req);
        let result = loop {
            let result = self
                .request_on(&mut conn, &header, &span_idx, &body, out, on_req.take().unwrap())
                .await;
            match result {
                // The connection went away before the token record was written
                // (an idle close, a server hiccup): nothing reached the server,
                // so once more on a fresh connection.
                Err(e) if !retried && e.downcast_ref::<Stale>().is_some() => {
                    debug!("borrower: connection {} closed before the request, retrying on a new one", conn.id);
                    inner.drop_connection(conn).await;
                    let (c, _) = inner.take_connection().await?;
                    conn = c;
                    reused = false;
                    retried = true;
                    on_req = Some(Box::new(|_| {}) as Box<dyn FnOnce(u64) + Send>);
                }
                other => break other,
            }
        };
        match result {
            Ok((response, keep)) => {
                if keep {
                    inner.idle.lock().unwrap().push(conn);
                    inner.idle_notify.notify_one();
                } else {
                    inner.drop_connection(conn).await;
                }
                Ok(Response { reused, ..response })
            }
            Err(e) => {
                // A refusal leaves the connection usable; anything else does not.
                if e.downcast_ref::<Refused>().is_some() {
                    inner.idle.lock().unwrap().push(conn);
                    inner.idle_notify.notify_one();
                } else {
                    inner.drop_connection(conn).await;
                }
                Err(e)
            }
        }
    }

    /// The request proper, on a connection that is past its handshake.
    /// Returns the response and whether the connection can serve again.
    #[allow(clippy::too_many_arguments)]
    async fn request_on<W: AsyncWrite + Unpin + Send>(
        &self,
        conn: &mut Conn,
        header: &RequestHeader,
        span_idx: &[usize],
        body: &[u8],
        out: &mut W,
        on_req: Box<dyn FnOnce(u64) + Send>,
    ) -> Result<(Response, bool)> {
        let inner = &self.inner;
        let seq = conn.writer.seq();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&conn.iv);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());

        // Request frame, proof and tag share go out under one lock, so the
        // pool sees proofs in the order of the requests they belong to.
        {
            let mut guard = inner.mpc.lock().await;
            let (proving, ctx) = &mut *guard;
            if proving.requests >= RENEW_AFTER {
                inner
                    .up
                    .send(Up::Renew)
                    .await
                    .map_err(|_| anyhow::anyhow!("session closed"))?;
                let t = Instant::now();
                *proving = Proving::new();
                tokio::time::timeout(SETUP_TIMEOUT, proving.warm_up(ctx))
                    .await
                    .context("renewal timed out")??;
                info!(took = ?t.elapsed(), "borrower: setup renewed");
            }
            inner
                .up
                .send(Up::Request {
                    conn: conn.id,
                    header: header.clone(),
                    seq,
                    nonce,
                })
                .await
                .map_err(|_| anyhow::anyhow!("session closed"))?;
            // Is there a lender? Only then is there a proof to make.
            loop {
                match tokio::time::timeout(SETUP_TIMEOUT, conn.rx.recv())
                    .await
                    .context("waiting for the pool to find a lender")?
                    .context("session closed")?
                {
                    Down::Accepted { .. } => break,
                    Down::Refused { reason, .. } => return Err(Refused(reason).into()),
                    // Nothing has been written yet either way.
                    Down::ServerClosed { .. } | Down::Aborted { .. } => return Err(Stale.into()),
                    Down::Bytes { bytes, .. } => {
                        conn.deframer.push(&bytes);
                        if let Some(record) = conn.deframer.next_record()? {
                            let (typ, plaintext) = conn.reader.decrypt(&record)?;
                            if typ == ALERT && plaintext == CLOSE_NOTIFY {
                                return Err(Stale.into());
                            }
                            bail!("server sent a record of type {typ} before the request: {plaintext:?}");
                        }
                    }
                    other => bail!("unexpected {other} while waiting for a lender"),
                }
            }
            let share = tokio::time::timeout(
                SETUP_TIMEOUT,
                proving.tag_share(ctx, &conn.key, &header.template, span_idx, seq, &nonce),
            )
            .await
            .context("keystream proof timed out")??;
            inner
                .up
                .send(Up::TagShare {
                    conn: conn.id,
                    share,
                })
                .await
                .map_err(|_| anyhow::anyhow!("session closed"))?;
        }

        // The pool's record goes first; ours follow at the next sequence number.
        let req = loop {
            match tokio::time::timeout(SETUP_TIMEOUT, conn.rx.recv())
                .await
                .context("waiting for the pool to write the token record")?
                .context("session closed")?
            {
                Down::Spliced { req, .. } => break req,
                Down::Refused { reason, .. } => return Err(Refused(reason).into()),
                // The record is the whole head, so the server may already be
                // answering it (a rejection, an early response): kept for the
                // response phase.
                Down::Bytes { bytes, .. } => {
                    ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                    conn.deframer.push(&bytes);
                }
                // The pool could not write the record, so nothing reached the
                // server and another connection can take the request.
                Down::Aborted { .. } => return Err(Stale.into()),
                // Here the record may have reached the server: no retry.
                Down::ServerClosed { .. } => bail!("server closed the connection on the request"),
                other => bail!("unexpected {other} while waiting for the token record"),
            }
        };
        on_req(req);
        conn.writer.set_seq(seq + 1);

        let mut frame = Vec::with_capacity(FRAME_TARGET + MAX_RECORD_PLAINTEXT + 64);
        for chunk in body.chunks(MAX_RECORD_PLAINTEXT) {
            frame.extend_from_slice(&conn.writer.encrypt(APPLICATION_DATA, chunk)?);
            if frame.len() >= FRAME_TARGET {
                inner
                    .up
                    .send(Up::Bytes {
                        conn: conn.id,
                        bytes: std::mem::take(&mut frame),
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("session closed"))?;
            }
        }
        if !frame.is_empty() {
            inner
                .up
                .send(Up::Bytes {
                    conn: conn.id,
                    bytes: frame,
                })
                .await
                .map_err(|_| anyhow::anyhow!("session closed"))?;
        }
        let sent_at = Instant::now();

        // The response, until its framing says it is complete. Records the
        // server sent while the token record was being written are in the
        // deframer already.
        let mut framer = crate::local::ResponseFramer::default();
        let mut first_byte = None;
        let mut total = 0usize;
        let mut server_closed = false;
        loop {
            while let Some(record) = conn.deframer.next_record()? {
                let (typ, plaintext) = conn.reader.decrypt(&record)?;
                match typ {
                    APPLICATION_DATA => {
                        first_byte.get_or_insert_with(|| sent_at.elapsed());
                        let used = framer.feed(&plaintext)?;
                        ensure!(
                            used == plaintext.len(),
                            "server sent {} bytes beyond the response",
                            plaintext.len() - used
                        );
                        total += plaintext.len();
                        out.write_all(&plaintext).await?;
                        out.flush().await?;
                    }
                    ALERT => {
                        ensure!(plaintext == CLOSE_NOTIFY, "unexpected alert from the server: {plaintext:?}");
                        debug!("borrower: server sent close_notify");
                        server_closed = true;
                    }
                    typ => bail!("unexpected record type {typ}"),
                }
            }
            if framer.complete() {
                break;
            }
            if server_closed {
                if framer.complete_at_close() {
                    break;
                }
                bail!("server closed the connection with the response incomplete");
            }
            let frame = tokio::time::timeout(RESPONSE_IDLE_TIMEOUT, conn.rx.recv())
                .await
                .context("no response bytes for 10 min")?
                .context("session closed")?;
            match frame {
                Down::Bytes { bytes, .. } => {
                    ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                    conn.deframer.push(&bytes);
                }
                Down::ServerClosed { .. } => server_closed = true,
                other => bail!("unexpected {other} during the response"),
            }
        }
        let keep = framer.keep_alive() && !server_closed;
        Ok((
            Response {
                req,
                status: framer.status(),
                bytes: total,
                first_byte: first_byte.unwrap_or_default(),
                reused: false,
            },
            keep,
        ))
    }
}

impl Inner {
    /// An idle connection, or a new one once a slot is free.
    async fn take_connection(self: &Arc<Self>) -> Result<(Conn, bool)> {
        loop {
            if let Some(conn) = self.idle.lock().unwrap().pop() {
                // It may have been closed by the server while idle.
                return Ok((conn, true));
            }
            match Arc::clone(&self.slots).try_acquire_owned() {
                Ok(slot) => return Ok((self.open_connection(slot).await?, false)),
                Err(_) => self.idle_notify.notified().await,
            }
        }
    }

    async fn drop_connection(&self, conn: Conn) {
        self.routes.lock().unwrap().remove(&conn.id);
        let _ = self.up.send(Up::Close { conn: conn.id }).await;
        // The slot frees when `conn` drops; wake a waiter.
        drop(conn);
        self.idle_notify.notify_one();
    }

    /// Opens a connection through the pool and runs the TLS handshake.
    async fn open_connection(&self, slot: tokio::sync::OwnedSemaphorePermit) -> Result<Conn> {
        let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<Down>(CONN_QUEUE);
        self.routes.lock().unwrap().insert(id, tx);
        let result = async {
            self.up
                .send(Up::Open { conn: id })
                .await
                .map_err(|_| anyhow::anyhow!("session closed"))?;
            match tokio::time::timeout(SETUP_TIMEOUT, rx.recv())
                .await
                .context("waiting for the pool to connect")?
                .context("session closed")?
            {
                Down::Opened { .. } => {}
                Down::OpenFailed { reason, .. } => bail!("pool could not connect: {reason}"),
                other => bail!("unexpected {other} while opening a connection"),
            }

            let name = rustls::pki_types::ServerName::try_from(self.server_name.clone())?;
            let mut tls = rustls::ClientConnection::new(self.config.clone(), name)?;
            let mut deframer = Deframer::default();
            loop {
                let mut bytes = Vec::new();
                while tls.wants_write() {
                    tls.write_tls(&mut bytes)?;
                }
                if !bytes.is_empty() {
                    self.up
                        .send(Up::Bytes { conn: id, bytes })
                        .await
                        .map_err(|_| anyhow::anyhow!("session closed"))?;
                }
                if !tls.is_handshaking() {
                    break;
                }
                match tokio::time::timeout(SETUP_TIMEOUT, rx.recv())
                    .await
                    .context("no bytes from the server")?
                    .context("session closed")?
                {
                    Down::Bytes { bytes, .. } => {
                        let mut rest = &bytes[..];
                        while !rest.is_empty() {
                            ensure!(tls.read_tls(&mut rest)? > 0, "TLS client refused the server's bytes");
                            tls.process_new_packets().context("TLS handshake with the server")?;
                        }
                    }
                    Down::ServerClosed { .. } => bail!("server closed the connection during the handshake"),
                    other => bail!("unexpected {other} during the handshake"),
                }
            }
            // rustls keeps nothing after the handshake in TLS 1.2, so nothing
            // is left in its buffer to carry over.
            let hs = extract_keys(tls)?;
            let key = hs.keys.client_write_key;
            let iv = hs.keys.client_write_iv;
            let (writer, reader) = LocalRecordLayer::new(&hs.keys, hs.write_seq, hs.read_seq).split();
            debug!(id, write_seq = hs.write_seq, read_seq = hs.read_seq, "borrower: connection ready");
            // Anything the server sent after its Finished belongs to the record layer.
            let _ = &mut deframer;
            Ok::<_, anyhow::Error>((writer, reader, key, iv))
        }
        .await;
        match result {
            Ok((writer, reader, key, iv)) => Ok(Conn {
                id,
                rx,
                writer,
                reader,
                key,
                iv,
                deframer: Deframer::default(),
                _slot: slot,
            }),
            Err(e) => {
                self.routes.lock().unwrap().remove(&id);
                let _ = self.up.send(Up::Close { conn: id }).await;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_record(nonce: u64, plaintext_len: usize) -> Vec<u8> {
        let len = 8 + plaintext_len + 16;
        let mut r = vec![APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        r.extend_from_slice(&nonce.to_be_bytes());
        r.extend(std::iter::repeat_n(0u8, plaintext_len + 16));
        r
    }

    fn nonce_for(seq: u64) -> [u8; 12] {
        let mut n = [9u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    #[test]
    fn gate_requires_a_fresh_request_per_splice() {
        let mut g = Gate::new();
        // Handshake: no application data.
        g.accept_record(&[HANDSHAKE, 3, 3, 0, 1, 0]).unwrap();
        assert!(g.accept_record(&app_record(1, 10)).is_err());
        // First splice at seq 1, a 100-byte request follows.
        g.accept_splice(1, &nonce_for(1)).unwrap();
        g.spliced(1, &nonce_for(1), 100);
        assert_eq!(g.phase, Phase::Sending);
        // Reusing the token record's nonce is refused.
        assert!(g.accept_record(&app_record(1, 40)).is_err());
        let mut g = Gate::new();
        g.accept_splice(1, &nonce_for(1)).unwrap();
        g.spliced(1, &nonce_for(1), 100);
        g.accept_record(&app_record(2, 40)).unwrap();
        // A splice mid-request is refused.
        assert!(g.accept_splice(4, &nonce_for(4)).is_err());
        assert_eq!(g.phase, Phase::Sending);
        g.accept_record(&app_record(3, 60)).unwrap();
        assert_eq!(g.phase, Phase::Idle);
        // One byte too many, or any application data while idle, is refused.
        assert!(g.accept_record(&app_record(4, 1)).is_err());
        // The next splice must take the next sequence number: 1 + 1 + 2 records.
        assert!(g.accept_splice(5, &nonce_for(5)).is_err());
        // The first splice is pinned to 1: the client's Finished was record 0.
        assert!(Gate::new().accept_splice(2, &nonce_for(2)).is_err());
        // A borrower record's nonce is remembered too: a later token record
        // may not reuse it.
        let mut g4 = Gate::new();
        g4.accept_splice(1, &nonce_for(1)).unwrap();
        g4.spliced(1, &nonce_for(1), 10);
        g4.accept_record(&app_record(7, 10)).unwrap();
        assert!(g4.accept_splice(3, &nonce_for(7)).is_err());
        g4.accept_splice(3, &nonce_for(3)).unwrap();
        // An alert while idle takes a sequence number too.
        let mut g3 = Gate::new();
        g3.accept_splice(1, &nonce_for(1)).unwrap();
        g3.spliced(1, &nonce_for(1), 0);
        g3.accept_record(&[ALERT, 3, 3, 0, 1, 0]).unwrap();
        assert!(g3.accept_splice(2, &nonce_for(2)).is_err());
        assert!(g3.accept_splice(3, &nonce_for(3)).is_ok());
        let mut g2 = Gate::new();
        g2.accept_splice(1, &nonce_for(1)).unwrap();
        g2.spliced(1, &nonce_for(1), 100);
        g2.accept_record(&app_record(2, 40)).unwrap();
        g2.accept_record(&app_record(3, 60)).unwrap();
        g2.accept_splice(4, &nonce_for(4)).unwrap();
        assert_eq!(g2.phase, Phase::Splicing);
        // While splicing, no application data; alerts pass and take a
        // sequence number.
        assert!(g2.accept_record(&app_record(5, 1)).is_err());
        g2.accept_record(&[ALERT, 3, 3, 0, 1, 0]).unwrap();
        // A refused lease returns to idle; the next splice follows the alert.
        g2.splice_failed();
        assert_eq!(g2.phase, Phase::Idle);
        assert!(g2.accept_splice(4, &nonce_for(4)).is_err());
        g2.accept_splice(5, &nonce_for(5)).unwrap();
    }
}
