//! In-process demo: pool, borrower and tlsn's echo server in one process,
//! with checks that the token never reaches the borrower.

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
    TOKEN_LEN, Tamper, dechunk, fixture_roots, link,
    record::{APPLICATION_DATA, LocalRecordLayer},
    splice::{run_borrower, run_pool},
};
use rand::RngExt;
use tls_server_fixture::SERVER_DOMAIN;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// The pool's secret. The borrower must never learn it.
const TOKEN: &str = "sk-ant-api03-THIS-IS-THE-POOLS-SECRET-TOKEN-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-A";

const TEMPLATE: &str = "POST /echo HTTP/1.1\r\nHost: test-server.io\r\n\
    Content-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\
    Connection: close\r\nContent-Type: application/json\r\n\r\n";

#[derive(Parser, Debug)]
struct Args {
    /// Size of the request body in bytes. The test server echoes it.
    #[arg(long, default_value_t = 32 * 1024)]
    body: usize,
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

    // The server.
    let (server_client_sock, server_sock) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(tls_server_fixture::bind_test_server_hyper(
        server_sock.compat(),
    ));

    // The pool↔borrower link, with byte counters on the pool's end.
    let (pool_sock, borrower_sock) = tokio::io::duplex(1 << 23);
    let counters = LinkCounters::default();
    let pool_sock = Counted::new(pool_sock, counters.clone());

    let pool_link = link(pool_sock.compat())?;
    let borrower_link = link(borrower_sock.compat())?;
    let pool_driver = tokio::spawn(pool_link.driver);
    let borrower_driver = tokio::spawn(borrower_link.driver);

    let body: Vec<u8> = {
        let mut rng = rand::rng();
        let mut b = Vec::with_capacity(args.body);
        while b.len() < args.body {
            b.extend_from_slice(format!("{{\"n\":{}}},", rng.random::<u32>()).as_bytes());
        }
        b.truncate(args.body);
        b
    };

    let token = TOKEN.to_string();
    let tamper: Tamper = args
        .evil_rewrite
        .then(|| Box::new(|h: &mut Vec<u8>| h[0] = b'G') as Box<dyn FnOnce(&mut Vec<u8>) + Send>);
    let expected_server = if args.evil_server {
        "api.anthropic.com"
    } else {
        SERVER_DOMAIN
    };

    let started = Instant::now();
    let outcome = tokio::try_join!(
        run_pool(
            pool_link.mpc,
            pool_link.up,
            pool_link.down,
            server_client_sock,
            SERVER_DOMAIN,
            &token,
            tamper,
        ),
        run_borrower(
            borrower_link.mpc,
            borrower_link.up,
            borrower_link.down,
            TEMPLATE,
            body.clone(),
            fixture_roots()?,
            expected_server,
            TOKEN_LEN,
            Box::new(tokio::io::sink()),
        ),
    );
    let total = started.elapsed();

    if args.evil_rewrite || args.evil_server {
        let err = match outcome {
            Ok(_) => bail!("the borrower accepted a misbehaving pool"),
            Err(err) => err,
        };
        let expected = if args.evil_rewrite {
            // The server fails the record's tag and sends a fatal alert.
            "alert"
        } else {
            "certificate"
        };
        ensure!(
            format!("{err:#}").to_ascii_lowercase().contains(expected),
            "unexpected failure: {err:#}"
        );
        println!();
        println!("misbehaving pool rejected as expected: {err:#}");
        return Ok(());
    }
    let (pool_report, borrower_report) = outcome?;

    drop(pool_link.session);
    drop(borrower_link.session);
    let _ = pool_link.close.send(());
    let _ = borrower_link.close.send(());
    pool_driver.await??;
    borrower_driver.await??;
    match server.await? {
        Ok(()) => {}
        Err(e) => println!("test server ended with an error: {e}"),
    }

    // Checks.
    let response = String::from_utf8_lossy(&borrower_report.response);
    ensure!(
        response.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {}",
        &response[..response.len().min(200)]
    );
    let body_pos = response
        .find("\r\n\r\n")
        .context("response has no header terminator")?
        + 4;
    let echoed = dechunk(&borrower_report.response[body_pos..]);
    ensure!(
        echoed == body,
        "server did not echo the body: got {} bytes, sent {} (response {} bytes)",
        echoed.len(),
        body.len(),
        borrower_report.response.len()
    );

    // What went over the link to the borrower must contain neither the token
    // nor the token record's ciphertext (mux framing could split a match, so
    // look for 16-byte windows of the record rather than the whole record).
    let sent = SENT_TO_BORROWER.lock().unwrap();
    ensure!(
        !contains(&sent, TOKEN.as_bytes()),
        "the token went to the borrower in the clear"
    );
    let record = &pool_report.record;
    ensure!(record.len() > 5 + 8 + 16, "token record too short");
    let ciphertext = &record[5 + 8..record.len() - 16];
    for window in ciphertext.chunks(16).filter(|w| w.len() == 16) {
        ensure!(
            !contains(&sent, window),
            "part of the token record's ciphertext went to the borrower"
        );
    }
    drop(sent);

    // Diagnostic only possible because both parties run in this process: the
    // token record the pool sent must be what the borrower's keys produce
    // from the borrower's template with the token in place.
    {
        let mut reference = LocalRecordLayer::new(&borrower_report.keys, borrower_report.splice_seq, 0);
        let mut expected_headers = borrower_report.header.template.clone();
        let span = &mut expected_headers[borrower_report.header.token.clone()];
        span.fill(b' ');
        span[..TOKEN.len()].copy_from_slice(TOKEN.as_bytes());
        ensure!(expected_headers == pool_report.headers);
        let expected = reference
            .encrypt(APPLICATION_DATA, &expected_headers)
            .context("reference encryption")?;
        ensure!(
            expected == pool_report.record,
            "the token record differs from what the traffic keys produce"
        );
    }

    println!();
    println!("borrowed request OK");
    println!("  protocol:              spliced record (borrower owns the session; zero-knowledge keystream)");
    println!("  body:                  {} bytes, echoed back", body.len());
    println!(
        "  token record:          {} bytes plaintext, seq {}; span hidden from the borrower, rest bound to its text",
        pool_report.headers.len(),
        borrower_report.splice_seq
    );
    println!("  server identity:       verified by the borrower");
    println!();
    println!("timing (both parties on this machine)");
    println!("  preprocessing:         {:>8.0?}  (overlapped with the handshake)", pool_report.preprocess);
    println!("  handshake:             {:>8.0?}", pool_report.handshake);
    println!("  token record:          {:>8.0?}", pool_report.splice);
    println!(
        "  body sent → first response byte: {:>5.0?}",
        borrower_report.first_byte
    );
    println!("  total:                 {:>8.0?}", total);
    println!();
    println!("pool↔borrower link");
    println!(
        "  pool → borrower:       {:>8} KB",
        counters.sent.load(Ordering::Relaxed) / 1024
    );
    println!(
        "  borrower → pool:       {:>8} KB",
        counters.received.load(Ordering::Relaxed) / 1024
    );

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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
