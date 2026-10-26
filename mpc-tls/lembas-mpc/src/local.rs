//! The borrower's local face: HTTP/1.1 response framing, and a local proxy
//! that turns plain HTTP requests from a parent process (the lembas agent)
//! into borrowed requests on a session.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result, bail, ensure};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::{MAX_BODY_LEN, session::{Refused, Session}};

/// Largest request head the local proxy accepts.
const MAX_HEAD: usize = 64 << 10;

/// Headers the proxy never forwards into the template: the pool's record
/// supplies the first three, the rest are hop-by-hop or would change the
/// framing the pool counts on.
const DROPPED: &[&str] = &[
    "host",
    "content-length",
    "authorization",
    "x-api-key",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "expect",
    "keep-alive",
    "proxy-connection",
    "upgrade",
];

// ---------------------------------------------------------------------------
// Response framing

#[derive(Debug)]
enum Body {
    Length(usize),
    ChunkSize(Vec<u8>),
    ChunkData(usize),
    ChunkEnd(usize),
    Trailer(Vec<u8>),
    UntilClose,
    Done,
}

/// Follows an HTTP/1.1 response byte by byte to know where it ends, so a
/// connection can be reused.
#[derive(Debug, Default)]
pub struct ResponseFramer {
    head: Vec<u8>,
    status: Option<u16>,
    keep_alive: bool,
    body: Option<Body>,
}

impl ResponseFramer {
    /// Consumes bytes of the response; returns how many belonged to it.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<usize> {
        let total = bytes.len();
        while !bytes.is_empty() {
            let Some(body) = self.body.as_mut() else {
                // Still in the head.
                let take = bytes.len().min(MAX_HEAD - self.head.len());
                ensure!(take > 0, "response head longer than {MAX_HEAD} bytes");
                self.head.extend_from_slice(&bytes[..take]);
                if let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") {
                    let extra = self.head.len() - (end + 4);
                    self.head.truncate(end + 4);
                    self.parse_head()?;
                    // Replay what came after the head.
                    bytes = &bytes[take - extra..];
                } else {
                    bytes = &bytes[take..];
                }
                continue;
            };
            match body {
                Body::Done => break,
                Body::UntilClose => {
                    bytes = &[];
                }
                Body::Length(remaining) => {
                    let n = bytes.len().min(*remaining);
                    *remaining -= n;
                    bytes = &bytes[n..];
                    if *remaining == 0 {
                        self.body = Some(Body::Done);
                    }
                }
                Body::ChunkSize(line) => {
                    let (consumed, complete) = take_line(line, bytes);
                    bytes = &bytes[consumed..];
                    if complete {
                        let text = std::str::from_utf8(line).context("chunk size")?;
                        let size = text.split(';').next().unwrap_or("").trim();
                        if size.is_empty() {
                            // A stray CRLF between chunks; keep looking.
                            line.clear();
                            continue;
                        }
                        let size = usize::from_str_radix(size, 16).context("chunk size")?;
                        self.body = Some(if size == 0 {
                            Body::Trailer(Vec::new())
                        } else {
                            Body::ChunkData(size)
                        });
                    }
                }
                Body::ChunkData(remaining) => {
                    let n = bytes.len().min(*remaining);
                    *remaining -= n;
                    bytes = &bytes[n..];
                    if *remaining == 0 {
                        self.body = Some(Body::ChunkEnd(2));
                    }
                }
                Body::ChunkEnd(remaining) => {
                    let n = bytes.len().min(*remaining);
                    *remaining -= n;
                    bytes = &bytes[n..];
                    if *remaining == 0 {
                        self.body = Some(Body::ChunkSize(Vec::new()));
                    }
                }
                Body::Trailer(line) => {
                    let (consumed, complete) = take_line(line, bytes);
                    bytes = &bytes[consumed..];
                    if complete {
                        if line.is_empty() {
                            self.body = Some(Body::Done);
                        } else {
                            line.clear();
                        }
                    }
                }
            }
        }
        Ok(total - bytes.len())
    }

    fn parse_head(&mut self) -> Result<()> {
        let text = std::str::from_utf8(&self.head).context("response head is not UTF-8")?;
        let mut lines = text.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .context("malformed status line")?;
        self.status = Some(status);
        let mut length = None;
        let mut chunked = false;
        let mut close = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "content-length" => length = Some(value.parse::<usize>().context("Content-Length")?),
                "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                "connection" => close = value.to_ascii_lowercase().contains("close"),
                _ => {}
            }
        }
        self.keep_alive = !close;
        self.body = Some(if (100..200).contains(&status) || status == 204 || status == 304 {
            Body::Done
        } else if chunked {
            Body::ChunkSize(Vec::new())
        } else if let Some(n) = length {
            if n == 0 { Body::Done } else { Body::Length(n) }
        } else {
            self.keep_alive = false;
            Body::UntilClose
        });
        Ok(())
    }

    /// True once the whole response has been fed.
    pub fn complete(&self) -> bool {
        matches!(self.body, Some(Body::Done))
    }

    /// True if the server closing now ends the response properly.
    pub fn complete_at_close(&self) -> bool {
        matches!(self.body, Some(Body::Done) | Some(Body::UntilClose))
    }

    /// Whether the connection may carry another request afterwards.
    pub fn keep_alive(&self) -> bool {
        self.keep_alive && self.complete()
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }
}

/// Appends bytes to `line` up to and including a CRLF; returns how many were
/// consumed and whether the line is complete (`line` then holds it without
/// the CRLF).
fn take_line(line: &mut Vec<u8>, bytes: &[u8]) -> (usize, bool) {
    for (i, &b) in bytes.iter().enumerate() {
        line.push(b);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return (i + 1, true);
        }
        if line.len() > 1024 {
            // A chunk-size or trailer line this long is not HTTP; let the
            // caller's parse fail on it.
            return (i + 1, true);
        }
    }
    (bytes.len(), false)
}

// ---------------------------------------------------------------------------
// The local proxy

/// Serves plain HTTP/1.1 clients on `listener`, each request becoming one
/// borrowed request on `session`. One request per client connection: the
/// response is relayed as the server sent it, with one header added
/// (`x-lembas-request`, the pool's number for the request, so the client can
/// report its outcome to the pool), and the connection is closed after it, so
/// a client reading to the end of the stream needs no framing of its own.
pub async fn serve_local(session: Arc<Session>, listener: TcpListener) -> Result<()> {
    info!("proxy: listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_client(session, stream).await {
                debug!("proxy: client {peer}: {e:#}");
            }
        });
    }
}

async fn serve_client(session: Arc<Session>, stream: TcpStream) -> Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let result = async {
        // The head.
        let mut head = Vec::new();
        loop {
            let n = rd.read_until(b'\n', &mut head).await?;
            if n == 0 {
                return Ok(());
            }
            ensure!(head.len() <= MAX_HEAD, "request head longer than {MAX_HEAD} bytes");
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let (template, body_len) = match parse_request(&head) {
            Ok(x) => x,
            Err(e) => {
                respond_error(&mut wr, 400, "bad_request", &format!("{e:#}")).await?;
                return Ok(());
            }
        };
        let mut body = vec![0u8; body_len];
        rd.read_exact(&mut body).await.context("reading the request body")?;

        let req = Arc::new(AtomicU64::new(0));
        let mut out = HeaderInsert::new(&mut wr, req.clone());
        let on_req = {
            let req = req.clone();
            move |n: u64| req.store(n, Ordering::Relaxed)
        };
        match session.request(&template, body, &mut out, on_req).await {
            Ok(response) => {
                debug!(
                    req = response.req,
                    status = ?response.status,
                    bytes = response.bytes,
                    reused = response.reused,
                    "proxy: request done"
                );
            }
            Err(e) => {
                if out.started() {
                    // The client has part of a response; nothing to add.
                    warn!("proxy: request failed mid-response: {e:#}");
                    return Err(e);
                }
                let (status, kind) = match e.downcast_ref::<Refused>() {
                    Some(_) => (503, "refused"),
                    None => (502, "failed"),
                };
                warn!("proxy: request failed: {e:#}");
                respond_error(&mut wr, status, kind, &format!("{e:#}")).await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = wr.shutdown().await;
    result
}

/// Turns a request head into a template for the session: the pool's part
/// (request line, Host, Content-Length, Authorization) first, then the
/// client's other headers.
fn parse_request(head: &[u8]) -> Result<(String, usize)> {
    let text = std::str::from_utf8(head).context("request head is not UTF-8")?;
    let mut lines = text.trim_end_matches("\r\n").split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    ensure!(
        !method.is_empty()
            && method.bytes().all(|b| b.is_ascii_alphabetic())
            && path.starts_with('/')
            && version.starts_with("HTTP/1.")
            && parts.next().is_none(),
        "malformed request line"
    );
    let mut body_len = None;
    let mut rest = String::new();
    for line in lines {
        let (name, value) = line.split_once(':').context("malformed header line")?;
        let lname = name.trim().to_ascii_lowercase();
        let value = value.trim();
        ensure!(!value.contains(['\r', '\n']), "header value with a line break");
        if lname == "content-length" {
            body_len = Some(value.parse::<usize>().context("Content-Length")?);
        }
        if lname == "transfer-encoding" {
            bail!("chunked requests are not supported; send Content-Length");
        }
        if DROPPED.contains(&lname.as_str()) {
            continue;
        }
        rest.push_str(name.trim());
        rest.push_str(": ");
        rest.push_str(value);
        rest.push_str("\r\n");
    }
    let body_len = body_len.context("Content-Length required")?;
    ensure!(body_len <= MAX_BODY_LEN, "body of {body_len} bytes is over the limit");
    rest.push_str("accept-encoding: identity\r\n");
    let template = format!(
        "{method} {path} HTTP/1.1\r\nHost: {{host}}\r\nContent-Length: {{body_len}}\r\nAuthorization: Bearer {{token}}\r\n{rest}\r\n"
    );
    Ok((template, body_len))
}

async fn respond_error<W: AsyncWrite + Unpin>(wr: &mut W, status: u16, kind: &str, message: &str) -> Result<()> {
    let reason = match status {
        400 => "Bad Request",
        503 => "Service Unavailable",
        _ => "Bad Gateway",
    };
    let body = serde_json::json!({
        "type": "error",
        "error": { "type": format!("lembas_{kind}"), "message": message },
    })
    .to_string();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nx-lembas-error: {kind}\r\n\r\n",
        body.len()
    );
    wr.write_all(head.as_bytes()).await?;
    wr.write_all(body.as_bytes()).await?;
    wr.flush().await?;
    Ok(())
}

/// Passes a response through, adding `x-lembas-request` to its head.
struct HeaderInsert<'a, W> {
    inner: &'a mut W,
    req: Arc<AtomicU64>,
    head: Vec<u8>,
    in_head: bool,
    started: bool,
}

impl<'a, W: AsyncWrite + Unpin> HeaderInsert<'a, W> {
    fn new(inner: &'a mut W, req: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            req,
            head: Vec::new(),
            in_head: true,
            started: false,
        }
    }

    fn started(&self) -> bool {
        self.started
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HeaderInsert<'_, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.started = true;
        if self.in_head {
            self.head.extend_from_slice(data);
            if let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") {
                let line = format!("x-lembas-request: {}\r\n", self.req.load(Ordering::Relaxed));
                self.head.splice(end + 2..end + 2, line.into_bytes());
                self.in_head = false;
                // Hand the whole head (and whatever followed) to the inner
                // writer in one go.
                let pending = std::mem::take(&mut self.head);
                let this = &mut *self;
                let mut written = 0;
                while written < pending.len() {
                    match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &pending[written..]) {
                        std::task::Poll::Ready(Ok(n)) => written += n,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Pending => {
                            // Keep the rest for the next poll.
                            this.head = pending[written..].to_vec();
                            this.in_head = false;
                            return std::task::Poll::Ready(Ok(data.len()));
                        }
                    }
                }
            } else if self.head.len() > MAX_HEAD {
                return std::task::Poll::Ready(Err(std::io::Error::other("response head too long")));
            }
            return std::task::Poll::Ready(Ok(data.len()));
        }
        // Drain anything a Pending left behind, then the new data.
        if !self.head.is_empty() {
            let pending = std::mem::take(&mut self.head);
            let this = &mut *self;
            match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &pending) {
                std::task::Poll::Ready(Ok(n)) if n == pending.len() => {}
                std::task::Poll::Ready(Ok(n)) => {
                    this.head = pending[n..].to_vec();
                    this.head.extend_from_slice(data);
                    return std::task::Poll::Ready(Ok(data.len()));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    this.head = pending;
                    return std::task::Poll::Pending;
                }
            }
        }
        std::pin::Pin::new(&mut *self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.in_head && !self.head.is_empty() {
            let pending = std::mem::take(&mut self.head);
            let this = &mut *self;
            match std::pin::Pin::new(&mut *this.inner).poll_write(cx, &pending) {
                std::task::Poll::Ready(Ok(n)) if n == pending.len() => {}
                std::task::Poll::Ready(Ok(n)) => {
                    this.head = pending[n..].to_vec();
                    cx.waker().wake_by_ref();
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => {
                    this.head = pending;
                    return std::task::Poll::Pending;
                }
            }
        }
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framer_follows_content_length_and_chunks() {
        let mut f = ResponseFramer::default();
        let resp = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(f.feed(&resp[..10]).unwrap(), 10);
        assert!(!f.complete());
        assert_eq!(f.feed(&resp[10..]).unwrap(), resp.len() - 10 - 5);
        assert!(f.complete() && f.keep_alive());
        assert_eq!(f.status(), Some(200));

        let mut f = ResponseFramer::default();
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        for b in resp.iter() {
            assert_eq!(f.feed(std::slice::from_ref(b)).unwrap(), 1);
        }
        assert!(f.complete());
        assert!(!f.keep_alive());

        let mut f = ResponseFramer::default();
        f.feed(b"HTTP/1.1 200 OK\r\n\r\nstream").unwrap();
        assert!(!f.complete() && f.complete_at_close() && !f.keep_alive());

        let mut f = ResponseFramer::default();
        f.feed(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert!(f.complete() && f.keep_alive());
    }

    #[test]
    fn request_head_becomes_a_template() {
        let head = b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\nAuthorization: Bearer nope\r\nanthropic-version: 2023-06-01\r\nConnection: keep-alive\r\n\r\n";
        let (template, len) = parse_request(head).unwrap();
        assert_eq!(len, 12);
        assert_eq!(
            template,
            "POST /v1/messages HTTP/1.1\r\nHost: {host}\r\nContent-Length: {body_len}\r\nAuthorization: Bearer {token}\r\nanthropic-version: 2023-06-01\r\naccept-encoding: identity\r\n\r\n"
        );
        assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
    }
}
