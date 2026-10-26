//! `lembas-mpc`: the pool and borrower helpers over TCP, or over stdin/stdout
//! for a parent process that bridges the link (the lembas pool and agent).
//!
//! ```text
//! lembas-mpc fixture  --listen 127.0.0.1:7443
//! lembas-mpc pool     --listen 127.0.0.1:7700 --server 127.0.0.1:7443 \
//!                     --server-name test-server.io --roots fixture --token-env LEMBAS_TOKEN
//! lembas-mpc borrower --pool 127.0.0.1:7700 --template req.http --body req.json
//! lembas-mpc pool     --stdio ...            # one borrower, link on stdin/stdout
//! lembas-mpc borrower --stdio --output resp.http --template ... --body ...
//! ```
//!
//! The borrower's template is the request header with `{token}` where the
//! pool's bearer token goes and `{body_len}` for the body length. The response
//! is written to stdout (or `--output`) as it arrives.
//!
//! The protocol is the spliced record (`lembas_mpc::splice`): the borrower
//! runs the TLS session itself and the pool inserts the one record that
//! carries the token.

use std::{
    io::Write as _,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Instant,
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use lembas_mpc::{
    TOKEN_LEN, dechunk, fixture_roots, link, mozilla_roots,
    splice::{BorrowerReport, run_borrower, run_pool},
};
use rustls::RootCertStore;
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info};

/// Request header for the Messages API with a subscription token, as the
/// lembas pool sends it.
const MESSAGES_TEMPLATE: &str = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
    Content-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\
    Connection: close\r\nContent-Type: application/json\r\nanthropic-version: 2023-06-01\r\n\
    anthropic-beta: claude-code-20250219,oauth-2025-04-20\r\n\
    user-agent: claude-cli/2.1.0 (external, cli)\r\naccept-encoding: identity\r\n\r\n";

/// How long to wait for the peer to acknowledge the end of the link.
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Subscription tokens are only accepted with a Claude Code system prompt.
const SYSTEM_PROMPT: &str = "You are Claude Code, Anthropic's official CLI for Claude.";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Roots {
    /// Mozilla's root certificates.
    Mozilla,
    /// tlsn's test server certificate.
    Fixture,
}

impl Roots {
    fn store(self) -> Result<RootCertStore> {
        match self {
            Roots::Mozilla => Ok(mozilla_roots()),
            Roots::Fixture => fixture_roots(),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the pool: accept borrowers and lend them the token.
    Pool {
        /// Address to accept borrowers on.
        #[arg(long, default_value = "127.0.0.1:7700")]
        listen: String,
        /// API server to connect to, host:port.
        #[arg(long, default_value = "api.anthropic.com:443")]
        server: String,
        /// The Host the borrower must use (its certificate check is its own).
        #[arg(long, default_value = "api.anthropic.com")]
        server_name: String,
        /// Accepted for compatibility with older callers; the borrower
        /// verifies the server's certificate, the pool has nothing to verify.
        #[arg(long, value_enum, default_value_t = Roots::Mozilla, hide = true)]
        roots: Roots,
        /// Environment variable holding the bearer token.
        #[arg(long, default_value = "LEMBAS_TOKEN")]
        token_env: String,
        /// Serve one borrower, then exit.
        #[arg(long)]
        once: bool,
        /// Serve one borrower whose link arrives on stdin/stdout (a parent
        /// process bridges it), then exit. Nothing else may use stdout.
        #[arg(long, conflicts_with = "listen")]
        stdio: bool,
    },
    /// Run the borrower: send one request through the pool.
    Borrower {
        /// The pool's address.
        #[arg(long, default_value = "127.0.0.1:7700")]
        pool: String,
        /// Request header template with `{token}` and `{body_len}`.
        #[arg(long)]
        template: PathBuf,
        /// Request body file.
        #[arg(long)]
        body: PathBuf,
        /// Name to verify the server's certificate for; defaults to the
        /// template's Host.
        #[arg(long)]
        server_name: Option<String>,
        #[arg(long, value_enum, default_value_t = Roots::Mozilla)]
        roots: Roots,
        /// Write the response here instead of stdout. Required with --stdio.
        #[arg(long, required_if_eq("stdio", "true"))]
        output: Option<PathBuf>,
        /// Length of the credential the pool lends.
        #[arg(long, default_value_t = TOKEN_LEN)]
        token_len: usize,
        /// The link to the pool arrives on stdin/stdout (a parent process
        /// bridges it); the response goes to --output.
        #[arg(long, conflicts_with = "pool")]
        stdio: bool,
    },
    /// Run tlsn's HTTPS echo server, for local tests.
    Fixture {
        #[arg(long, default_value = "127.0.0.1:7443")]
        listen: String,
    },
    /// Chat with the model; every turn is one borrowed request through the pool.
    Chat {
        /// The pool's address.
        #[arg(long, default_value = "127.0.0.1:7700")]
        pool: String,
        #[arg(long, default_value = "claude-sonnet-5-5")]
        model: String,
        #[arg(long, default_value_t = 1024)]
        max_tokens: u32,
        /// Length of the credential the pool lends.
        #[arg(long, default_value_t = TOKEN_LEN)]
        token_len: usize,
    },
}

#[tokio::main]
async fn main() {
    // Exit explicitly: with the link on stdin/stdout, tokio's blocking stdin
    // reader would otherwise keep the runtime alive until the peer closes its
    // end, and the peer is waiting for ours.
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("lembas-mpc: {e:#}");
            1
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lembas_mpc=info,lembas_mpc_bin=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Args::parse().cmd {
        Cmd::Fixture { listen } => {
            let listener = TcpListener::bind(&listen).await?;
            info!("fixture: listening on {listen}");
            loop {
                let (stream, peer) = listener.accept().await?;
                info!("fixture: connection from {peer}");
                tokio::spawn(async move {
                    if let Err(e) = tls_server_fixture::bind_test_server_hyper(stream.compat()).await {
                        error!("fixture: {e}");
                    }
                });
            }
        }
        Cmd::Pool {
            listen,
            server,
            server_name,
            roots: _,
            token_env,
            once,
            stdio,
        } => {
            let token = std::env::var(&token_env)
                .with_context(|| format!("set {token_env} to the bearer token"))?;
            if token.is_empty() || token.contains(['\r', '\n']) {
                bail!("{token_env} does not look like a token");
            }
            if stdio {
                let io = stdio_link();
                return lend(io.compat(), &server, &server_name, &token).await;
            }
            let listener = TcpListener::bind(&listen).await?;
            info!("pool: listening on {listen}, lending to {server} as {server_name}");
            loop {
                let (stream, peer) = listener.accept().await?;
                info!("pool: borrower connected from {peer}");
                stream.set_nodelay(true)?;
                let (server, server_name, token) =
                    (server.clone(), server_name.clone(), token.clone());
                let task = async move {
                    lend(stream.compat(), &server, &server_name, &token).await
                };
                if once {
                    task.await?;
                    return Ok(());
                }
                tokio::spawn(async move {
                    if let Err(e) = task.await {
                        let msg = format!("{e:#}");
                        if msg.starts_with("prelude") {
                            // Port scanners and liveness probes connect and leave.
                            tracing::debug!("pool: connection from {peer} ended early: {msg}");
                        } else {
                            error!("pool: borrower from {peer} failed: {msg}");
                        }
                    }
                });
            }
        }
        Cmd::Chat {
            pool,
            model,
            max_tokens,
            token_len,
        } => chat(&pool, &model, max_tokens, token_len).await,
        Cmd::Borrower {
            pool,
            template,
            body,
            server_name,
            roots,
            output,
            token_len,
            stdio,
        } => {
            let template = std::fs::read_to_string(&template)
                .with_context(|| format!("reading {}", template.display()))?;
            let body = std::fs::read(&body).with_context(|| format!("reading {}", body.display()))?;
            let server_name = match server_name {
                Some(name) => name,
                None => template
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_string())
                    })
                    .context("template has no Host header; pass --server-name")?,
            };
            let out: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match output {
                Some(path) => Box::new(tokio::fs::File::create(path).await?),
                None => Box::new(tokio::io::stdout()),
            };

            let started = Instant::now();
            let roots = roots.store()?;
            let report = if stdio {
                let io = stdio_link();
                borrow(io.compat(), &template, body, roots, &server_name, token_len, out).await?
            } else {
                let stream = TcpStream::connect(&pool)
                    .await
                    .with_context(|| format!("connecting to the pool at {pool}"))?;
                stream.set_nodelay(true)?;
                borrow(stream.compat(), &template, body, roots, &server_name, token_len, out).await?
            };
            info!(
                total = ?started.elapsed(),
                first_byte = ?report.first_byte,
                response_bytes = report.response.len(),
                "borrower: done"
            );
            Ok(())
        }
    }
}

/// stdin and stdout as one duplex stream, read and written as plain files.
/// tokio's `Stdout` goes through std's line-buffered handle, which holds back
/// a frame that happens to contain no newline until something flushes; the
/// mux's close frames are exactly that small, and the peer waits for them.
fn stdio_link() -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {
    use std::os::fd::FromRawFd as _;
    // SAFETY: fds 0 and 1 stay open for the life of the process, and once the
    // link is on them nothing else in this process uses them (logs go to
    // stderr, the response to --output).
    let stdin = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(0) });
    let stdout = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(1) });
    tokio::io::join(stdin, stdout)
}

/// Lends the token to the one borrower whose link is `io`.
async fn lend<Io>(io: Io, server: &str, server_name: &str, token: &str) -> Result<()>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let link = link(io)?;
    let driver = tokio::spawn(link.driver);

    let upstream = TcpStream::connect(server)
        .await
        .with_context(|| format!("connecting to {server}"))?;
    upstream.set_nodelay(true)?;

    let report = run_pool(
        link.mpc,
        link.up,
        link.down,
        upstream,
        server_name,
        token,
        None,
    )
    .await;

    info!("pool: closing the link");
    drop(link.session);
    let _ = link.close.send(());
    // The close handshake is a courtesy; a peer that is gone must not hold us.
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
    info!("pool: link closed");
    let report = report?;
    info!(
        total = ?started.elapsed(),
        preprocess = ?report.preprocess,
        handshake = ?report.handshake,
        splice = ?report.splice,
        "pool: borrowed request done"
    );
    Ok(())
}

/// Borrows once over the link `io`.
#[allow(clippy::too_many_arguments)]
async fn borrow<Io>(
    io: Io,
    template: &str,
    body: Vec<u8>,
    roots: RootCertStore,
    server_name: &str,
    token_len: usize,
    out: Box<dyn AsyncWrite + Unpin + Send>,
) -> Result<BorrowerReport>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let link = link(io)?;
    let driver = tokio::spawn(link.driver);
    let report = run_borrower(
        link.mpc,
        link.up,
        link.down,
        template,
        body,
        roots,
        server_name,
        token_len,
        out,
    )
    .await;
    info!("borrower: closing the link");
    drop(link.session);
    let _ = link.close.send(());
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
    info!("borrower: link closed");
    report
}

/// The interactive chat: reads a line, sends the whole conversation as one
/// borrowed request, streams the answer, repeats.
async fn chat(pool: &str, model: &str, max_tokens: u32, token_len: usize) -> Result<()> {
    let mut history: Vec<serde_json::Value> = Vec::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    eprintln!("Each message is one borrowed request through the pool at {pool}.");
    eprintln!("The pool lends the token but cannot read what you type or what comes back.");
    eprintln!("Empty line or Ctrl-D to quit.");
    eprintln!();

    loop {
        print!("you> ");
        std::io::stdout().flush()?;
        let Some(line) = lines.next_line().await? else {
            break;
        };
        let line = line.trim().to_string();
        if line.is_empty() || line == "exit" || line == "quit" {
            break;
        }

        history.push(serde_json::json!({"role": "user", "content": line}));
        let body = serde_json::json!({
            "model": model,
            "max_tokens": max_tokens,
            "stream": true,
            "system": SYSTEM_PROMPT,
            "messages": history,
        });

        print!("claude> ");
        std::io::stdout().flush()?;
        let sink = SseSink::new();
        let text = sink.text.clone();
        let started = Instant::now();

        let stream = TcpStream::connect(pool)
            .await
            .with_context(|| format!("connecting to the pool at {pool}"))?;
        stream.set_nodelay(true)?;
        let link = link(stream.compat())?;
        let driver = tokio::spawn(link.driver);
        let report = run_borrower(
            link.mpc,
            link.up,
            link.down,
            MESSAGES_TEMPLATE,
            serde_json::to_vec(&body)?,
            mozilla_roots(),
            "api.anthropic.com",
            token_len,
            Box::new(sink),
        )
        .await;
        drop(link.session);
        let _ = link.close.send(());
        let _ = driver.await;

        println!();
        match report {
            Ok(report) => {
                let status = report
                    .response
                    .split(|&b| b == b'\n')
                    .next()
                    .map(|l| String::from_utf8_lossy(l).trim().to_string())
                    .unwrap_or_default();
                if !status.contains(" 200 ") {
                    let body_pos = report
                        .response
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(report.response.len());
                    let body = dechunk(&report.response[body_pos..]);
                    eprintln!("{status}: {}", String::from_utf8_lossy(&body));
                    history.pop();
                } else {
                    let answer = std::mem::take(&mut *text.lock().unwrap());
                    history.push(serde_json::json!({"role": "assistant", "content": answer}));
                }
                eprintln!(
                    "[borrowed request: {:.1?} total, first byte after {:.1?}]",
                    started.elapsed(),
                    report.first_byte
                );
            }
            Err(e) => {
                eprintln!("request failed: {e:#}");
                history.pop();
            }
        }
        println!();
    }

    // Leave at once: tokio's stdin reader is a blocking thread that could
    // otherwise keep the runtime from shutting down.
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// Receives the raw HTTP response, decodes the chunked SSE body as it arrives,
/// prints text deltas and collects the answer.
struct SseSink {
    buf: Vec<u8>,
    headers_done: bool,
    /// Chunked transfer decoding: bytes left in the current chunk, if inside one.
    chunk_left: Option<usize>,
    body: Vec<u8>,
    line_start: usize,
    text: Arc<Mutex<String>>,
}

impl SseSink {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            headers_done: false,
            chunk_left: None,
            body: Vec::new(),
            line_start: 0,
            text: Arc::new(Mutex::new(String::new())),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        if !self.headers_done {
            let Some(p) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                return;
            };
            self.headers_done = true;
            self.buf.drain(..p + 4);
        }
        // Chunked body -> self.body.
        loop {
            match self.chunk_left {
                Some(0) => {
                    if self.buf.len() < 2 {
                        break;
                    }
                    self.buf.drain(..2);
                    self.chunk_left = None;
                }
                Some(n) => {
                    let take = n.min(self.buf.len());
                    if take == 0 {
                        break;
                    }
                    self.body.extend(self.buf.drain(..take));
                    self.chunk_left = Some(n - take);
                }
                None => {
                    let Some(eol) = self.buf.windows(2).position(|w| w == b"\r\n") else {
                        break;
                    };
                    let size = std::str::from_utf8(&self.buf[..eol])
                        .ok()
                        .and_then(|s| usize::from_str_radix(s.trim(), 16).ok());
                    self.buf.drain(..eol + 2);
                    match size {
                        Some(0) | None => {
                            self.chunk_left = Some(usize::MAX);
                            break;
                        }
                        Some(n) => self.chunk_left = Some(n),
                    }
                }
            }
        }
        // SSE lines.
        while let Some(eol) = self.body[self.line_start..].iter().position(|&b| b == b'\n') {
            let line = &self.body[self.line_start..self.line_start + eol];
            self.line_start += eol + 1;
            if let Some(json) = line.strip_prefix(b"data: ")
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(json)
            {
                if v["type"] == "content_block_delta" && v["delta"]["type"] == "text_delta"
                    && let Some(t) = v["delta"]["text"].as_str()
                {
                    print!("{t}");
                    let _ = std::io::stdout().flush();
                    self.text.lock().unwrap().push_str(t);
                } else if v["type"] == "error" {
                    eprintln!("\n{}", v["error"]);
                }
            }
        }
    }
}

impl AsyncWrite for SseSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.feed(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
