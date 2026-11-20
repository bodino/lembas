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
//! lembas-mpc limit-verify --listen 127.0.0.1:7701        # a lender checks a limit proof
//! lembas-mpc limit-prove  --verifier 127.0.0.1:7701 --token-env LEMBAS_TOKEN
//! lembas-mpc peer --dir ~/.lembas/peer --name Alice --found --invite --control
//! lembas-mpc peer --dir ~/.lembas/peer --name Bob --join lembas://join/... --listen 127.0.0.1:8789
//! ```
//!
//! `peer` is the serverless mode: one process per Mac, lending and borrowing
//! with the other members of a circle directly over iroh (QUIC with hole
//! punching, a relay when that fails). With `--control` it takes JSON lines
//! on stdin (`{"cmd":"status"}`, `invite`, `join`, `lend`, `away`, `remove`,
//! `sync`, `report`, `spent`) and answers on stdout, one line each, plus a `status` event every
//! half minute; the local port or socket serves borrowed requests as `proxy`
//! does.
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
    TOKEN_LEN, dechunk, fixture_roots,
    limit::{self, USAGE_PATH},
    link,
    local::serve_local,
    peer::{ApiTarget, Peer, PeerConfig},
    mozilla_roots,
    session::{Connector, Lease, OnSpliced, Session, TokenSource, fixed_token, run_pool},
};
use rustls::RootCertStore;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
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
    /// Check one limit proof: accept a prover, relay its usage probe to the
    /// server, verify what it reveals, print the usage.
    LimitVerify {
        /// Address to accept the prover on.
        #[arg(long, default_value = "127.0.0.1:7701")]
        listen: String,
        /// API server to connect to, host:port.
        #[arg(long, default_value = "api.anthropic.com:443")]
        server: String,
        /// The Host the prover must use.
        #[arg(long, default_value = "api.anthropic.com")]
        server_name: String,
        /// The path the prover must request.
        #[arg(long, default_value = USAGE_PATH)]
        path: String,
    },
    /// Prove to a verifier what the usage endpoint says about the token in
    /// the environment, without showing it the token.
    LimitProve {
        /// The verifier's address.
        #[arg(long, default_value = "127.0.0.1:7701")]
        verifier: String,
        /// Environment variable holding the bearer token.
        #[arg(long, default_value = "LEMBAS_TOKEN")]
        token_env: String,
        #[arg(long, default_value = "api.anthropic.com")]
        server_name: String,
        /// The only path this prover reveals a response to.
        #[arg(long, default_value = USAGE_PATH)]
        path: String,
        #[arg(long, value_enum, default_value_t = Roots::Mozilla)]
        roots: Roots,
    },
    /// Run this Mac as a peer of a circle: lend to and borrow from the other
    /// members directly, no pool.
    Peer {
        /// Where the key, the circle and the settings are kept.
        #[arg(long)]
        dir: PathBuf,
        /// This Mac's name in the circle.
        #[arg(long)]
        name: String,
        /// Environment variable holding this Mac's own subscription token,
        /// for lending and for proving its limit. Without it the peer can do
        /// neither.
        #[arg(long, default_value = "LEMBAS_TOKEN")]
        token_env: String,
        /// Or a JSON file with `accessToken`, re-read at each use.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Found a circle, if this Mac is in none.
        #[arg(long)]
        found: bool,
        /// Join the circle this invite link points to, if in none.
        #[arg(long)]
        join: Option<String>,
        /// Print an invite link at start.
        #[arg(long)]
        invite: bool,
        /// Local TCP address for borrowed requests; port 0 picks a free one.
        #[arg(long, default_value = "127.0.0.1:0", conflicts_with = "socket")]
        listen: String,
        #[arg(long)]
        port_file: Option<PathBuf>,
        /// Serve borrowed requests on a Unix socket instead (created 0600).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Take commands as JSON lines on stdin, answer on stdout.
        #[arg(long)]
        control: bool,
        /// No relay or address lookup: direct addresses only (local tests).
        #[arg(long)]
        no_relay: bool,
        /// Bind the endpoint here (local tests).
        #[arg(long)]
        bind: Option<std::net::SocketAddr>,
        /// A borrower must prove a window at or past this percent.
        #[arg(long, default_value_t = 90.0)]
        borrow_at: f64,
        /// Lend while away until the five-hour window reaches this percent.
        #[arg(long, default_value_t = 70.0)]
        away5h: f64,
        /// Never lend past this percent of the week.
        #[arg(long, default_value_t = 60.0)]
        week: f64,
        /// API server to lend for and probe, host:port.
        #[arg(long, default_value = "api.anthropic.com:443")]
        api: String,
        #[arg(long, default_value = "api.anthropic.com")]
        api_name: String,
        #[arg(long, value_enum, default_value_t = Roots::Mozilla)]
        roots: Roots,
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
        Cmd::Peer {
            dir,
            name,
            token_env,
            token_file,
            found,
            join,
            invite,
            listen,
            port_file,
            socket,
            control,
            no_relay,
            bind,
            borrow_at,
            away5h,
            week,
            api,
            api_name,
            roots,
        } => {
            let token = std::env::var(&token_env).ok().filter(|t| !t.is_empty());
            if token.is_none() && token_file.is_none() {
                warn!("peer: no {token_env} and no --token-file: this Mac can neither lend nor prove its limit");
            }
            let fixture = matches!(roots, Roots::Fixture);
            let cfg = PeerConfig {
                dir,
                name,
                token,
                token_file,
                api: ApiTarget {
                    server: api,
                    server_name: api_name,
                    usage_path: if fixture { "/".into() } else { USAGE_PATH.into() },
                    roots: roots.store()?,
                    require_usage: !fixture,
                    // A test server has no model endpoint to keep to.
                    lendable: if fixture { None } else { Some(lembas_mpc::peer::model_request) },
                },
                relay: !no_relay,
                bind,
            };
            let peer = Peer::start(cfg).await?;
            {
                let mut st = peer.status();
                if found && st.circle.is_none() {
                    peer.found()?;
                    st = peer.status();
                }
                if let Some(link) = &join
                    && st.circle.is_none()
                {
                    peer.join(link).await?;
                }
            }
            if !control {
                peer.set_policy(lembas_mpc::peer::LendPolicy { away5h, week, borrow_at, away_after_minutes: 30 });
            }
            if invite {
                let link = peer.invite().await?;
                if control {
                    println!("{}", serde_json::json!({ "event": "invite", "link": link }));
                } else {
                    println!("{link}");
                }
            }
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
            info!("peer: {} ({}), borrowed requests on {}", peer.status().name, peer.id().fmt_short(), listener.describe());
            let proxy = tokio::spawn(peer.clone().serve_proxy(listener));
            if control {
                tokio::select! {
                    r = control_loop(peer.clone()) => r?,
                    r = proxy => r??,
                }
            } else {
                proxy.await??;
            }
            Ok(())
        }
        Cmd::LimitVerify {
            listen,
            server,
            server_name,
            path,
        } => {
            let listener = TcpListener::bind(&listen).await?;
            info!("verifier: listening on {listen}, probing {server} as {server_name}{path}");
            let (stream, peer) = listener.accept().await?;
            info!("verifier: prover connected from {peer}");
            stream.set_nodelay(true)?;
            let upstream = TcpStream::connect(&server)
                .await
                .with_context(|| format!("connecting to {server}"))?;
            upstream.set_nodelay(true)?;
            let counted = Counted::new(stream);
            let meter = counted.meter();
            let link = link(counted.compat())?;
            let driver = tokio::spawn(link.driver);
            let mut phases = Phases::new(meter);
            let verified = limit::verify(
                link.mpc,
                link.up,
                link.down,
                upstream,
                &server_name,
                &path,
                Some(&mut |p| phases.mark(p)),
            )
            .await;
            drop(link.session);
            let _ = link.close.send(());
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
            let verified = verified?;
            phases.print("verifier");
            println!("request:  {}", verified.request.trim_end().replace("\r\n", " | "));
            println!("response: {} ({} bytes of head, {} of body)", verified.status, verified.head.len(), verified.body.len());
            match verified.usage() {
                Ok(usage) => {
                    for (w, u) in &usage.windows {
                        println!("  {w}: {u:.1}%{}", usage.resets_at.get(w).map(|r| format!(", resets {r}")).unwrap_or_default());
                    }
                    println!("  locked: {}", usage.locked);
                }
                Err(e) => println!("  not a usage answer: {e:#}\n{}", String::from_utf8_lossy(&verified.body)),
            }
            Ok(())
        }
        Cmd::LimitProve {
            verifier,
            token_env,
            server_name,
            path,
            roots,
        } => {
            let token = std::env::var(&token_env).with_context(|| format!("set {token_env} to the bearer token"))?;
            let stream = TcpStream::connect(&verifier)
                .await
                .with_context(|| format!("connecting to the verifier at {verifier}"))?;
            stream.set_nodelay(true)?;
            let counted = Counted::new(stream);
            let meter = counted.meter();
            let link = link(counted.compat())?;
            let driver = tokio::spawn(link.driver);
            let mut phases = Phases::new(meter);
            let proven = limit::prove(
                link.mpc,
                link.up,
                link.down,
                &roots.store()?,
                &server_name,
                &path,
                &token,
                Some(&mut |p| phases.mark(p)),
            )
            .await;
            drop(link.session);
            let _ = link.close.send(());
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, driver).await;
            let proven = proven?;
            phases.print("prover");
            println!(
                "status {}, verifier {}: {}",
                proven.status,
                if proven.accepted { "accepted" } else { "refused" },
                proven.detail
            );
            Ok(())
        }
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
// The peer's control channel: JSON lines on stdin and stdout

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum PeerCmd {
    Status,
    Invite,
    Join { link: String },
    Lend {
        member: String,
        to: bool,
        #[serde(default)]
        while_working: bool,
    },
    Away { away: bool },
    Remove { member: String },
    Sync,
    Found,
    /// A borrowed request's cost, from the agent that metered it.
    Report {
        lender: String,
        usd: f64,
        #[serde(default)]
        model: String,
    },
    /// What a request on this Mac's own login cost, from its agent.
    Spent { usd: f64 },
    Policy {
        away5h: f64,
        week: f64,
        #[serde(default = "default_borrow_at")]
        borrow_at: f64,
        #[serde(default = "default_away_after")]
        away_after_minutes: u32,
    },
}

fn default_borrow_at() -> f64 {
    90.0
}

fn default_away_after() -> u32 {
    30
}

async fn control_loop(peer: Arc<Peer>) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    let say = |v: serde_json::Value| {
        println!("{v}");
        let _ = std::io::stdout().flush();
    };
    loop {
        tokio::select! {
            _ = tick.tick() => say(serde_json::json!({ "event": "status", "status": peer.status() })),
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                if line.trim().is_empty() {
                    continue;
                }
                let reply = match serde_json::from_str::<PeerCmd>(&line) {
                    Err(e) => Err(anyhow::anyhow!("bad command: {e}")),
                    Ok(cmd) => run_cmd(&peer, cmd).await,
                };
                match reply {
                    Ok(v) => say(serde_json::json!({ "ok": true, "result": v })),
                    Err(e) => say(serde_json::json!({ "ok": false, "error": format!("{e:#}") })),
                }
            }
        }
    }
}

async fn run_cmd(peer: &Arc<Peer>, cmd: PeerCmd) -> Result<serde_json::Value> {
    let member = |s: &str| -> Result<iroh::PublicKey> { s.parse().map_err(|e| anyhow::anyhow!("bad member id: {e}")) };
    Ok(match cmd {
        PeerCmd::Status => serde_json::to_value(peer.status())?,
        PeerCmd::Invite => serde_json::json!({ "link": peer.invite().await? }),
        PeerCmd::Join { link } => {
            peer.join(&link).await?;
            serde_json::to_value(peer.status())?
        }
        PeerCmd::Lend { member: m, to, while_working } => {
            peer.set_lend(member(&m)?, to, while_working);
            serde_json::Value::Null
        }
        PeerCmd::Away { away } => {
            peer.set_away(away);
            serde_json::Value::Null
        }
        PeerCmd::Remove { member: m } => {
            peer.remove(member(&m)?).await?;
            serde_json::Value::Null
        }
        PeerCmd::Sync => {
            peer.sync_all().await;
            serde_json::to_value(peer.status())?
        }
        PeerCmd::Found => {
            peer.found()?;
            serde_json::to_value(peer.status())?
        }
        PeerCmd::Report { lender, usd, model } => {
            peer.report(member(&lender)?, usd, model).await?;
            serde_json::Value::Null
        }
        PeerCmd::Spent { usd } => {
            peer.spent(usd)?;
            serde_json::Value::Null
        }
        PeerCmd::Policy { away5h, week, borrow_at, away_after_minutes } => {
            peer.set_policy(lembas_mpc::peer::LendPolicy { away5h, week, borrow_at, away_after_minutes });
            serde_json::Value::Null
        }
    })
}

// ---------------------------------------------------------------------------
// Measuring the link

#[derive(Default, Clone)]
struct Meter {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
}

/// A stream that counts what passes.
struct Counted<T> {
    inner: T,
    meter: Meter,
}

impl<T> Counted<T> {
    fn new(inner: T) -> Self {
        Self { inner, meter: Meter::default() }
    }

    fn meter(&self) -> Meter {
        self.meter.clone()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            self.meter.received.fetch_add(n as u64, Ordering::Relaxed);
        }
        res
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            self.meter.sent.fetch_add(*n as u64, Ordering::Relaxed);
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

/// Bytes and time per phase of a protocol run.
struct Phases {
    meter: Meter,
    started: Instant,
    last: (Instant, u64, u64),
    rows: Vec<(&'static str, std::time::Duration, u64, u64)>,
}

impl Phases {
    fn new(meter: Meter) -> Self {
        let now = Instant::now();
        Self { meter, started: now, last: (now, 0, 0), rows: Vec::new() }
    }

    fn mark(&mut self, phase: &'static str) {
        let now = Instant::now();
        let sent = self.meter.sent.load(Ordering::Relaxed);
        let received = self.meter.received.load(Ordering::Relaxed);
        let (t, s, r) = self.last;
        self.rows.push((phase, now - t, sent - s, received - r));
        self.last = (now, sent, received);
    }

    fn print(&self, who: &str) {
        println!("{who}: {:>8}  {:>10}  {:>10}  {:>10}", "phase", "time", "sent", "received");
        for (phase, took, sent, received) in &self.rows {
            println!("{who}: {phase:>8}  {:>10}  {:>10}  {:>10}", format!("{took:.1?}"), kb(*sent), kb(*received));
        }
        println!(
            "{who}: {:>8}  {:>10}  {:>10}  {:>10}",
            "total",
            format!("{:.1?}", self.started.elapsed()),
            kb(self.meter.sent.load(Ordering::Relaxed)),
            kb(self.meter.received.load(Ordering::Relaxed))
        );
    }
}

fn kb(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MB", n as f64 / (1u64 << 20) as f64)
    } else {
        format!("{:.1} KB", n as f64 / 1024.0)
    }
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
    let stats = run_pool(link.mpc, link.up, link.down, connector, server_name, tokens, None, on_spliced, None).await;
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
