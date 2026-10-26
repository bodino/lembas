//! `lembas-mpc`: the pool and borrower helpers over TCP, or over stdin/stdout
//! for a parent process that bridges the link (the lembas pool and agent).
//!
//! ```text
//! lembas-mpc fixture  --listen 127.0.0.1:7443
//! lembas-mpc pool     --listen 127.0.0.1:7700 --server 127.0.0.1:7443 \
//!                     --server-name test-server.io --token-env LEMBAS_TOKEN
//! lembas-mpc borrower --pool 127.0.0.1:7700 --template req.http --body req.json
//! lembas-mpc pool     --stdio ...            # one session, link on stdin/stdout
//! lembas-mpc proxy    --stdio --listen 127.0.0.1:0 --port-file port
//! lembas-mpc chat     --pool 127.0.0.1:7700
//! ```
//!
//! A session (`session`) carries many requests over many connections with one
//! two-party setup. `proxy` is how the lembas agent uses it: the link to the
//! pool on stdin/stdout, and a local HTTP/1.1 port where every request the
//! agent sends becomes a borrowed request. The `pool --stdio` helper takes a
//! token per request from its parent over fd 3 (JSON lines) when that is
//! open, or lends the one from the environment.

use std::{
    collections::HashMap,
    io::Write as _,
    os::fd::{FromRawFd as _, OwnedFd},
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Instant,
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use lembas_mpc::{
    TOKEN_LEN, dechunk, fixture_roots, link,
    local::serve_local,
    mozilla_roots,
    session::{Connector, Lease, OnSpliced, Session, TokenSource, fixed_token, run_pool},
};
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info, warn};

// The proofs allocate and free tens of MB of temporaries per request; the system
// allocator keeps that as resident memory, mimalloc gives it back.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Request header for the Messages API with a subscription token, as the
/// lembas pool sends it.
const MESSAGES_TEMPLATE: &str = "POST /v1/messages HTTP/1.1\r\nHost: {host}\r\n\
    Content-Length: {body_len}\r\nContent-Type: application/json\r\n\
    anthropic-version: 2023-06-01\r\n\
    anthropic-beta: claude-code-20250219,oauth-2025-04-20\r\n\
    user-agent: claude-cli/2.1.0 (external, cli)\r\naccept-encoding: identity\r\n\
    Authorization: Bearer {token}\r\n\r\n";

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
        /// With --stdio: a descriptor the parent set up (JSON lines both
        /// ways) on which it lends a token per request; without it the token
        /// from the environment is lent to every request.
        #[arg(long, requires = "stdio")]
        control_fd: Option<i32>,
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
        /// Request header template with `{token}`, `{body_len}` and `{host}`.
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
    /// Run a session for a parent process: the link to the pool on
    /// stdin/stdout, a local HTTP/1.1 port where each request becomes a
    /// borrowed request.
    Proxy {
        /// Local TCP address to serve HTTP on; port 0 picks a free one. For tests:
        /// every process on the machine can reach a loopback port.
        #[arg(long, default_value = "127.0.0.1:0", conflicts_with = "socket")]
        listen: String,
        /// Where to write the port actually bound, for the parent.
        #[arg(long)]
        port_file: Option<PathBuf>,
        /// Serve on a Unix socket at this path instead (created 0600; put it in a
        /// directory only this user can enter).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Name to verify the server's certificate for.
        #[arg(long, default_value = "api.anthropic.com")]
        server_name: String,
        #[arg(long, value_enum, default_value_t = Roots::Mozilla)]
        roots: Roots,
        /// Length of the credential the pool lends.
        #[arg(long, default_value_t = TOKEN_LEN)]
        token_len: usize,
        /// The link arrives on stdin/stdout (the only mode).
        #[arg(long)]
        stdio: bool,
    },
    /// Run tlsn's HTTPS echo server, for local tests.
    Fixture {
        #[arg(long, default_value = "127.0.0.1:7443")]
        listen: String,
    },
    /// Chat with the model; the conversation is one session, every turn one
    /// borrowed request.
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
            control_fd,
            once,
            stdio,
        } => {
            let connector = tcp_connector(server.clone());
            if stdio {
                let (tokens, on_spliced) = match control_fd {
                    Some(fd) => {
                        let control = Control::open(fd)?;
                        (control.tokens(), Some(control.on_spliced()))
                    }
                    None => (env_token(&token_env)?, None),
                };
                let io = stdio_link();
                return lend(io.compat(), connector, &server_name, tokens, on_spliced).await;
            }
            let tokens = env_token(&token_env)?;
            let listener = TcpListener::bind(&listen).await?;
            info!("pool: listening on {listen}, lending to {server} as {server_name}");
            loop {
                let (stream, peer) = listener.accept().await?;
                info!("pool: borrower connected from {peer}");
                stream.set_nodelay(true)?;
                let (connector, server_name, tokens) = (connector.clone(), server_name.clone(), tokens.clone());
                let task = async move { lend(stream.compat(), connector, &server_name, tokens, None).await };
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
        Cmd::Proxy {
            listen,
            port_file,
            socket,
            server_name,
            roots,
            token_len,
            stdio: _,
        } => {
            let listener = match &socket {
                Some(path) => {
                    let _ = std::fs::remove_file(path);
                    let listener = tokio::net::UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
                    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
                    lembas_mpc::local::LocalListener::Unix(listener)
                }
                None => {
                    let listener = TcpListener::bind(&listen).await?;
                    if let Some(path) = &port_file {
                        let port = listener.local_addr()?.port();
                        std::fs::write(path, format!("{port}\n")).with_context(|| format!("writing {}", path.display()))?;
                    }
                    lembas_mpc::local::LocalListener::Tcp(listener)
                }
            };
            let where_ = listener.describe();
            let io = stdio_link();
            let link = link(io.compat())?;
            let driver = tokio::spawn(link.driver);
            let session = Arc::new(
                Session::start(link.mpc, link.up, link.down, &roots.store()?, &server_name, token_len).await?,
            );
            info!("proxy: session ready, serving on {where_}");
            tokio::select! {
                r = serve_local(session.clone(), listener) => r?,
                r = driver => {
                    // The parent closed the link: nothing more to do.
                    match r {
                        Ok(Ok(())) => info!("proxy: link closed"),
                        Ok(Err(e)) => warn!("proxy: link failed: {e:#}"),
                        Err(e) => warn!("proxy: link driver: {e}"),
                    }
                }
            }
            Ok(())
        }
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
                        let v = v.trim();
                        (k.trim().eq_ignore_ascii_case("host") && v != "{host}").then(|| v.to_string())
                    })
                    .context("template has no Host header; pass --server-name")?,
            };
            let out: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match output {
                Some(path) => Box::new(tokio::fs::File::create(path).await?),
                None => Box::new(tokio::io::stdout()),
            };

            let started = Instant::now();
            let roots = roots.store()?;
            let response = if stdio {
                let io = stdio_link();
                borrow_once(io.compat(), &template, body, &roots, &server_name, token_len, out).await?
            } else {
                let stream = TcpStream::connect(&pool)
                    .await
                    .with_context(|| format!("connecting to the pool at {pool}"))?;
                stream.set_nodelay(true)?;
                borrow_once(stream.compat(), &template, body, &roots, &server_name, token_len, out).await?
            };
            info!(
                total = ?started.elapsed(),
                first_byte = ?response.first_byte,
                status = ?response.status,
                response_bytes = response.bytes,
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
    // SAFETY: fds 0 and 1 stay open for the life of the process, and once the
    // link is on them nothing else in this process uses them (logs go to
    // stderr, the response to --output or the local port).
    let stdin = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(0) });
    let stdout = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(1) });
    tokio::io::join(stdin, stdout)
}

fn tcp_connector(server: String) -> Connector<TcpStream> {
    Arc::new(move || {
        let server = server.clone();
        Box::pin(async move {
            let stream = TcpStream::connect(&server)
                .await
                .with_context(|| format!("connecting to {server}"))?;
            stream.set_nodelay(true)?;
            Ok(stream)
        })
    })
}

fn env_token(token_env: &str) -> Result<TokenSource> {
    let token = std::env::var(token_env).with_context(|| format!("set {token_env} to the bearer token"))?;
    if token.is_empty() || token.contains(['\r', '\n']) {
        bail!("{token_env} does not look like a token");
    }
    Ok(fixed_token(token))
}

// ---------------------------------------------------------------------------
// Per-request tokens from the parent, over fd 3

/// What the parent answers to `{"type":"need_token","id":N}`.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlReply {
    Token { id: u64, token: String, req: u64 },
    Refuse { id: u64, reason: String },
}

/// JSON lines both ways on a descriptor the parent set up (a socketpair when
/// Node spawns the helper with a fourth `pipe`).
struct Control {
    writer: tokio::sync::Mutex<tokio::fs::File>,
    // A lease, or the parent's reason for refusing one (it reaches the borrower).
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Lease, String>>>>>,
    next: AtomicU64,
}

impl Control {
    fn open(fd: i32) -> Result<Arc<Self>> {
        // SAFETY: the parent named this descriptor for us and nothing else in
        // this process uses it. (Guessing a number instead would be unsafe:
        // without a parent, the runtime's own descriptors sit there.)
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let dup = fd.try_clone().context("the control descriptor is not open")?;
        let reader = tokio::fs::File::from_std(std::fs::File::from(fd));
        let writer = tokio::fs::File::from_std(std::fs::File::from(dup));
        let control = Arc::new(Self {
            writer: tokio::sync::Mutex::new(writer),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU64::new(1),
        });
        let pending = control.pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match serde_json::from_str::<ControlReply>(&line) {
                    Ok(ControlReply::Token { id, token, req }) => {
                        if let Some(tx) = pending.lock().unwrap().remove(&id) {
                            let _ = tx.send(Ok(Lease { token, req }));
                        }
                    }
                    Ok(ControlReply::Refuse { id, reason }) => {
                        warn!("pool: parent refused request {id}: {reason}");
                        if let Some(tx) = pending.lock().unwrap().remove(&id) {
                            let _ = tx.send(Err(reason));
                        }
                    }
                    Err(e) => warn!("pool: bad control line: {e}"),
                }
            }
            // The parent is gone; nobody waiting gets a token.
            pending.lock().unwrap().clear();
        });
        Ok(control)
    }

    fn tokens(self: &Arc<Self>) -> TokenSource {
        let control = self.clone();
        Arc::new(move || {
            let control = control.clone();
            Box::pin(async move {
                let id = control.next.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = oneshot::channel();
                control.pending.lock().unwrap().insert(id, tx);
                control
                    .send(&serde_json::json!({ "type": "need_token", "id": id }).to_string())
                    .await?;
                match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                    Ok(Ok(Ok(lease))) => Ok(Some(lease)),
                    Ok(Ok(Err(reason))) => bail!("{reason}"),
                    Ok(Err(_)) => bail!("parent went away"),
                    Err(_) => {
                        control.pending.lock().unwrap().remove(&id);
                        bail!("parent did not answer in 30 s")
                    }
                }
            })
        })
    }

    fn on_spliced(self: &Arc<Self>) -> OnSpliced {
        let control = self.clone();
        Arc::new(move |req| {
            let control = control.clone();
            tokio::spawn(async move {
                let _ = control
                    .send(&serde_json::json!({ "type": "spliced", "req": req }).to_string())
                    .await;
            });
        })
    }

    async fn send(&self, line: &str) -> Result<()> {
        let mut w = self.writer.lock().await;
        w.write_all(line.as_bytes()).await?;
        w.write_all(b"\n").await?;
        w.flush().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------

/// Lends to the one borrower whose link is `io`, for a whole session.
async fn lend<Io>(
    io: Io,
    connector: Connector<TcpStream>,
    server_name: &str,
    tokens: TokenSource,
    on_spliced: Option<OnSpliced>,
) -> Result<()>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let link = link(io)?;
    let driver = tokio::spawn(link.driver);
    let stats = run_pool(link.mpc, link.up, link.down, connector, server_name, tokens, on_spliced, None).await;
    info!("pool: closing the link");
    drop(link.session);
    let _ = link.close.send(());
    // The close handshake is a courtesy; a peer that is gone must not hold us.
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
    let stats = stats?;
    info!(total = ?started.elapsed(), ?stats, "pool: session done");
    Ok(())
}

/// One request over a session of its own.
#[allow(clippy::too_many_arguments)]
async fn borrow_once<Io>(
    io: Io,
    template: &str,
    body: Vec<u8>,
    roots: &RootCertStore,
    server_name: &str,
    token_len: usize,
    mut out: Box<dyn AsyncWrite + Unpin + Send>,
) -> Result<lembas_mpc::session::Response>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let link = link(io)?;
    let driver = tokio::spawn(link.driver);
    let session = Session::start(link.mpc, link.up, link.down, roots, server_name, token_len).await?;
    let response = session.request(template, body, &mut out, |_| {}).await;
    session.close().await;
    info!("borrower: closing the link");
    drop(link.session);
    let _ = link.close.send(());
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
    response
}

/// The interactive chat: one session; each line is one borrowed request with
/// the whole conversation, streamed back.
async fn chat(pool: &str, model: &str, max_tokens: u32, token_len: usize) -> Result<()> {
    let mut history: Vec<serde_json::Value> = Vec::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    let stream = TcpStream::connect(pool)
        .await
        .with_context(|| format!("connecting to the pool at {pool}"))?;
    stream.set_nodelay(true)?;
    let link = link(stream.compat())?;
    let driver = tokio::spawn(link.driver);
    let t = Instant::now();
    let session =
        Session::start(link.mpc, link.up, link.down, &mozilla_roots(), "api.anthropic.com", token_len).await?;

    eprintln!("One session with the pool at {pool} (ready in {:.0?}); each message is one borrowed request.", t.elapsed());
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
        let mut sink = SseSink::new();
        let text = sink.text.clone();
        let started = Instant::now();
        let result = session
            .request(MESSAGES_TEMPLATE, serde_json::to_vec(&body)?, &mut sink, |_| {})
            .await;
        println!();
        match result {
            Ok(response) => {
                if response.status != Some(200) {
                    let raw = sink.raw.lock().unwrap();
                    let body_pos = raw
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|p| p + 4)
                        .unwrap_or(raw.len());
                    eprintln!("{:?}: {}", response.status, String::from_utf8_lossy(&dechunk(&raw[body_pos..])));
                    history.pop();
                } else {
                    let answer = std::mem::take(&mut *text.lock().unwrap());
                    history.push(serde_json::json!({"role": "assistant", "content": answer}));
                }
                eprintln!(
                    "[borrowed request {}: {:.1?} total, first byte after {:.1?}, connection {}]",
                    response.req,
                    started.elapsed(),
                    response.first_byte,
                    if response.reused { "reused" } else { "new" }
                );
            }
            Err(e) => {
                eprintln!("request failed: {e:#}");
                history.pop();
            }
        }
        println!();
    }

    session.close().await;
    drop(link.session);
    let _ = link.close.send(());
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
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
    raw: Arc<Mutex<Vec<u8>>>,
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
            raw: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn feed(&mut self, data: &[u8]) {
        self.raw.lock().unwrap().extend_from_slice(data);
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
