//! In-process demo: pool, borrower and tlsn's echo server in one process,
//! many requests over one session, with checks that the token never reaches
//! the borrower.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Instant,
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Parser;
use lembas_mpc::{
    TOKEN_LEN, dechunk, fixture_roots, link,
    session::{Connector, Session, Tamper, fixed_token, run_pool},
};
use rand::RngExt;
use tls_server_fixture::SERVER_DOMAIN;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// The pool's secret. The borrower must never learn it.
const TOKEN: &str = "sk-ant-api03-THIS-IS-THE-POOLS-SECRET-TOKEN-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-A";

const TEMPLATE: &str = "POST /echo HTTP/1.1\r\nHost: {host}\r\n\
    Content-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\
    Content-Type: application/json\r\n\r\n";

/// The same, asking the server to close afterwards: forces a new connection
/// for the next request.
const TEMPLATE_CLOSE: &str = "POST /echo HTTP/1.1\r\nHost: {host}\r\n\
    Content-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\
    Content-Type: application/json\r\nConnection: close\r\n\r\n";

#[derive(Parser, Debug)]
struct Args {
    /// Requests to make over the one session.
    #[arg(long, default_value_t = 6)]
    requests: usize,
    /// How many at a time.
    #[arg(long, default_value_t = 3)]
    concurrency: usize,
    /// Size of each request body in bytes. The test server echoes it.
    #[arg(long, default_value_t = 32 * 1024)]
    body: usize,
    /// Refuse to lend for the first N requests (nobody has capacity), then
    /// lend; the borrower must report each refusal and the session go on.
    #[arg(long, default_value_t = 0)]
    refuse_first: usize,
    /// Misbehave as the pool: change a header byte outside the token span.
    /// The server must reject the record, since the tag binds the pool to
    /// the borrower's text.
    #[arg(long)]
    evil_rewrite: bool,
    /// Misbehave as the pool: connect the borrower to a server other than the
    /// one it expects. The borrower must refuse during the handshake.
    #[arg(long)]
    evil_server: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    // The pool↔borrower link, with byte counters on the pool's end.
    let (pool_sock, borrower_sock) = tokio::io::duplex(1 << 23);
    let counters = LinkCounters::default();
    let pool_sock = Counted::new(pool_sock, counters.clone());

    let pool_link = link(pool_sock.compat())?;
    let borrower_link = link(borrower_sock.compat())?;
    let pool_driver = tokio::spawn(pool_link.driver);
    let borrower_driver = tokio::spawn(borrower_link.driver);

    // Every `Open` gets its own echo server on an in-memory pipe.
    let connector: Connector<DuplexStream> = Arc::new(|| {
        Box::pin(async {
            let (client, server) = tokio::io::duplex(1 << 20);
            tokio::spawn(async move {
                if let Err(e) = tls_server_fixture::bind_test_server_hyper(server.compat()).await {
                    tracing::debug!("test server: {e}");
                }
            });
            Ok(client)
        })
    });

    let tamper: Tamper = args
        .evil_rewrite
        .then(|| Arc::new(|h: &mut Vec<u8>| h[0] = b'G') as Arc<dyn Fn(&mut Vec<u8>) + Send + Sync>);
    // The evil pool claims to lend for the name the borrower expects while
    // connecting it to the test server; only the certificate check can tell.
    let expected_server = if args.evil_server {
        "api.anthropic.com"
    } else {
        SERVER_DOMAIN
    };
    let announced_server = expected_server;

    let started = Instant::now();
    let pool = run_pool(
        pool_link.mpc,
        pool_link.up,
        pool_link.down,
        connector,
        announced_server,
        refusing_first(args.refuse_first, fixed_token(TOKEN.to_string())),
        None,
        tamper,
    );
    let borrower = async {
        let session = Arc::new(
            Session::start(
                borrower_link.mpc,
                borrower_link.up,
                borrower_link.down,
                &fixture_roots()?,
                expected_server,
                TOKEN_LEN,
            )
            .await?,
        );
        let ready = started.elapsed();

        let mut rng = rand::rng();
        let mut tasks = tokio::task::JoinSet::new();
        let mut outcomes = Vec::new();
        let per_request = Arc::new(std::sync::Mutex::new(Vec::new()));
        for i in 0..args.requests {
            // Keep `concurrency` in flight.
            while tasks.len() >= args.concurrency.max(1) {
                outcomes.push(tasks.join_next().await.unwrap()?);
            }
            let body: Vec<u8> = {
                let mut b = Vec::with_capacity(args.body);
                while b.len() < args.body {
                    b.extend_from_slice(format!("{{\"n\":{}}},", rng.random::<u32>()).as_bytes());
                }
                b.truncate(args.body);
                b
            };
            // Every third request asks the server to close: the next one
            // must open a new connection and re-handshake.
            let template = if i % 3 == 2 { TEMPLATE_CLOSE } else { TEMPLATE };
            let session = session.clone();
            let per_request = per_request.clone();
            tasks.spawn(async move {
                let t = Instant::now();
                let mut response = Vec::new();
                let r = match session.request(template, body.clone(), &mut response, |_| {}).await {
                    Ok(r) => r,
                    Err(e) if e.downcast_ref::<lembas_mpc::session::Refused>().is_some() => {
                        REFUSED.fetch_add(1, Ordering::Relaxed);
                        // Try again: the pool lends from the (N+1)th request on.
                        session.request(template, body.clone(), &mut response, |_| {}).await?
                    }
                    Err(e) => return Err(e),
                };
                per_request.lock().unwrap().push(t.elapsed());
                let text = String::from_utf8_lossy(&response);
                ensure!(
                    text.starts_with("HTTP/1.1 200 OK"),
                    "unexpected response: {}",
                    &text[..text.len().min(200)]
                );
                let body_pos = text.find("\r\n\r\n").context("no header terminator")? + 4;
                ensure!(dechunk(&response[body_pos..]) == body, "server did not echo the body");
                Ok::<_, anyhow::Error>(r)
            });
        }
        while let Some(outcome) = tasks.join_next().await {
            outcomes.push(outcome?);
        }
        session.close().await;
        let per_request = std::mem::take(&mut *per_request.lock().unwrap());
        let responses = outcomes.into_iter().collect::<Result<Vec<_>>>()?;
        Ok::<_, anyhow::Error>((responses, ready, per_request))
    };
    let outcome = tokio::try_join!(pool, borrower);
    let total = started.elapsed();

    if args.evil_rewrite || args.evil_server {
        let err = match outcome {
            Ok(_) => bail!("the borrower accepted a misbehaving pool"),
            Err(err) => err,
        };
        let expected = if args.evil_rewrite { "alert" } else { "certificate" };
        ensure!(
            format!("{err:#}").to_ascii_lowercase().contains(expected),
            "unexpected failure: {err:#}"
        );
        println!();
        println!("misbehaving pool rejected as expected: {err:#}");
        return Ok(());
    }
    let (stats, (responses, ready, per_request)) = outcome?;

    drop(pool_link.session);
    drop(borrower_link.session);
    let _ = pool_link.close.send(());
    let _ = borrower_link.close.send(());
    pool_driver.await??;
    borrower_driver.await??;

    ensure!(responses.len() == args.requests);
    ensure!(stats.requests as usize == args.requests, "pool counted {} requests", stats.requests);
    let reused = responses.iter().filter(|r| r.reused).count();
    let refused = REFUSED.load(Ordering::Relaxed);
    ensure!(refused == args.refuse_first, "{refused} refusals seen, expected {}", args.refuse_first);
    ensure!(stats.refused as usize == args.refuse_first, "pool counted {} refusals", stats.refused);

    // What went over the link to the borrower must not contain the token.
    let sent = SENT_TO_BORROWER.lock().unwrap();
    ensure!(
        !contains(&sent, TOKEN.as_bytes()),
        "the token went to the borrower in the clear"
    );
    drop(sent);

    let mut sorted = per_request.clone();
    sorted.sort();
    println!();
    println!("borrowed requests OK");
    println!("  protocol:              session of spliced records (zero-knowledge keystream)");
    println!(
        "  requests:              {} of {} bytes, {} at a time, all echoed back",
        args.requests, args.body, args.concurrency
    );
    println!(
        "  connections:           {} opened by the pool, {} requests reused one{}",
        stats.connections,
        reused,
        if refused > 0 { format!(", {refused} refusals handled") } else { String::new() }
    );
    println!("  server identity:       verified by the borrower");
    println!();
    println!("timing (both parties on this machine)");
    println!("  session ready (OT setup, once): {:>6.0?}", ready);
    println!(
        "  per request:           median {:>6.0?}, max {:>6.0?} (handshake included when a connection was opened)",
        sorted[sorted.len() / 2],
        sorted[sorted.len() - 1]
    );
    println!("  total:                 {:>8.0?}", total);
    println!();
    println!("pool↔borrower link");
    let up = counters.received.load(Ordering::Relaxed);
    let down = counters.sent.load(Ordering::Relaxed);
    println!("  borrower → pool:       {:>8} KB ({} KB of it request bodies)", up / 1024, args.requests * args.body / 1024);
    println!("  pool → borrower:       {:>8} KB (responses included)", down / 1024);

    Ok(())
}

#[derive(Default, Clone)]
struct LinkCounters {
    /// Bytes the pool sent to the borrower.
    sent: Arc<AtomicUsize>,
    /// Bytes the pool received from the borrower.
    received: Arc<AtomicUsize>,
}

/// Counts bytes and records everything the pool sends to the borrower, so the
/// program can check the token is not among it.
struct Counted {
    inner: DuplexStream,
    counters: LinkCounters,
}

impl Counted {
    fn new(inner: DuplexStream, counters: LinkCounters) -> Self {
        Self { inner, counters }
    }
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            self.counters.received.fetch_add(n, Ordering::Relaxed);
        }
        res
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            self.counters.sent.fetch_add(*n, Ordering::Relaxed);
            SENT_TO_BORROWER
                .lock()
                .unwrap()
                .extend_from_slice(&data[..*n]);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Everything the pool sent to the borrower, for the token check.
static SENT_TO_BORROWER: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
/// Refusals the borrower saw.
static REFUSED: AtomicUsize = AtomicUsize::new(0);

/// A token source that says no to the first `n` requests.
fn refusing_first(n: usize, inner: lembas_mpc::session::TokenSource) -> lembas_mpc::session::TokenSource {
    let count = Arc::new(AtomicUsize::new(0));
    Arc::new(move || {
        let inner = inner.clone();
        let count = count.clone();
        Box::pin(async move {
            if count.fetch_add(1, Ordering::Relaxed) < n {
                return Ok(None);
            }
            inner().await
        })
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
