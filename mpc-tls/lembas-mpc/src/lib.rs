//! Borrowed requests with a spliced token record.
//!
//! The **borrower** runs an ordinary TLS session to the API server through a
//! relay operated by the **pool**, which holds the token. The pool writes
//! exactly one record into that session, the one carrying the token, and can
//! read or forge nothing else; the borrower never learns the token. The
//! protocol is in [`splice`]; this module holds what both sides share: the
//! template policy, the wire prelude, the link plumbing.
//!
//! The link between pool and borrower must itself be authenticated (in
//! lembas, the existing pool WebSocket over TLS). A man in the middle on it
//! can only cause failures, never read or forge, but the pool must know it is
//! lending to a member.
//!
//! The pool and the borrower talk over one byte stream multiplexed by
//! tlsn-mux. Each side opens three channels in the same order: `mpc` for the
//! two-party computation, `up` for everything the borrower sends, `down` for
//! everything the pool sends.

use std::{future::Future, ops::Range, pin::Pin, time::Duration};

use anyhow::{Context as _, Result, bail, ensure};
use mpz_common::{Context, Session, ThreadPool, ThreadPoolBuildError, mux::Mux};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use webpki::anchor_from_trusted_cert;

pub mod local;
pub mod record;
pub mod session;
pub mod splice;

/// Largest token record the pool may send: the whole request head, request
/// line through the blank line, with the Authorization line last. Each 16-byte
/// block is one AES block proven in zero knowledge, so callers keep the head
/// lean (Claude Code's essential headers come to about 450 bytes).
///
/// The whole head is the pool's so that nothing the server can parse as
/// framing is written by the borrower: after the token record the borrower
/// sends exactly `Content-Length` bytes of body, which the pool counts, and a
/// body cannot smuggle a `Transfer-Encoding` or a second request in front of
/// the next token record.
pub const MAX_HEADER_LEN: usize = 1024;

/// Marker in a borrower's template that becomes the token span.
pub const TOKEN_MARKER: &str = "{token}";
/// Marker in a borrower's template that becomes the server name.
pub const HOST_MARKER: &str = "{host}";
/// Marker in a borrower's template that becomes the body length.
pub const BODY_LEN_MARKER: &str = "{body_len}";

/// How long the prelude, preprocessing, handshake and splice may take.
/// The relay itself is bounded separately: a model may stream for minutes.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(90);
/// How long the relay waits for the next frame from either side before it
/// gives up. Long enough for a model's thinking pause (the lembas agent's own
/// request timeout is the same 10 minutes), short enough that a vanished peer
/// does not hold the pool's helper forever.
pub const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// The most a single borrow may last, idle or not.
pub const RELAY_MAX_DURATION: Duration = Duration::from_secs(3600);
/// Largest body a template may announce in `Content-Length`. The pool cannot
/// read the body, so the announced length and the bytes actually relayed are
/// its only levers against a borrower spending a lender's quota on huge
/// requests.
pub const MAX_BODY_LEN: usize = 64 << 20;
/// Most bytes the pool relays from the borrower to the server in one borrow:
/// the announced body plus record framing, with room to spare.
pub const MAX_SENT_BYTES: usize = MAX_BODY_LEN + (4 << 20);
/// Bytes from the borrower waiting to be written to a slow server; beyond
/// this the pool stops reading until the server catches up.
pub const MAX_PENDING_BYTES: usize = 4 << 20;
/// Changes whenever `Hello` or what follows it changes; the wire codec is not
/// self-describing, so this is what turns an old peer into a clean error.
pub const PROTOCOL_VERSION: u32 = 6;
/// Threads for the two-party computation (`LEMBAS_MPC_THREADS` overrides).
pub const MPC_THREADS: usize = 4;

/// The pool's opening message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// [`PROTOCOL_VERSION`]; the borrower refuses any other.
    pub version: u32,
    /// Length of the token the pool will put in the span.
    pub token_len: usize,
    /// Server the pool connects to; the borrower's `Host` must match.
    pub server_name: String,
}

/// The borrower's request head: the pool's record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHeader {
    /// The whole head, request line through the blank line, with the
    /// Authorization line last and any bytes in `token`.
    pub template: Vec<u8>,
    /// Span the pool fills with the token.
    pub token: Range<usize>,
}

/// Length of a subscription token (`sk-ant-oat01-…`) or API key
/// (`sk-ant-api03-…`); both are 108 bytes.
///
/// This is a security invariant, not a convenience: the token span is
/// `TOKEN_LEN` rounded up to 16-byte blocks, and the slack a pool has for
/// smuggling bytes into the span is `span - token`. With a 108-byte token
/// that is 4 bytes, too few for a header. A shorter credential in the same
/// span would leave room: 112 - 97 = 15 bytes fit `\r\nX: value`. So the
/// pool refuses to lend any credential of another length, and the borrower
/// refuses a pool announcing another length.
pub const TOKEN_LEN: usize = 108;

/// Rounds a span length up to whole 16-byte blocks.
fn span_len_for(token_len: usize) -> usize {
    token_len.div_ceil(16) * 16
}

/// Checks a borrower's head on the pool's side.
///
/// The span must be exactly the value of an `Authorization: Bearer` header,
/// the last header before the blank line, so the token can only ever land
/// where a bearer token belongs, never in a path or a header the server might
/// echo. It must be block aligned and no more than 15 bytes longer than the
/// token, which with a working token leaves the pool no room for anything
/// else (see `fill_template`). `Host` must name the server the pool connects
/// to; `Content-Length` is digits only and the only framing header.
pub fn check_template(header: &RequestHeader, token_len: usize, server_name: &str) -> Result<()> {
    ensure!(
        token_len == TOKEN_LEN,
        "only {TOKEN_LEN}-byte credentials can be lent, see TOKEN_LEN"
    );
    let text = &header.template;
    ensure!(
        text.len() <= MAX_HEADER_LEN,
        "header is {} bytes; at most {MAX_HEADER_LEN} can be sent",
        text.len()
    );
    ensure!(
        text.ends_with(b"\r\n\r\n"),
        "the token record must end with the blank line"
    );
    let span = header.token.clone();
    ensure!(
        span.start < span.end && span.end <= text.len(),
        "token span must be inside the header"
    );
    ensure!(
        span.len() == span_len_for(token_len) && span.start.is_multiple_of(16),
        "token span must be the token length rounded up to 16-byte blocks, block aligned"
    );
    ensure!(
        span.end + 4 == text.len(),
        "the Authorization line must be the last header line"
    );
    let head = std::str::from_utf8(&text[..text.len() - 4]).context("header is not UTF-8")?;
    ensure!(!head.contains("\r\n\r\n"), "header contains a blank line");

    let mut pos = 0;
    let mut saw_auth = false;
    let mut saw_host = false;
    let mut saw_length = false;
    let mut names = std::collections::HashSet::new();
    for (i, line) in head.split("\r\n").enumerate() {
        let line_range = pos..pos + line.len();
        pos += line.len() + 2;
        ensure!(!line.contains(['\r', '\n']), "header line with a stray CR or LF");
        if i == 0 {
            ensure!(line.ends_with(" HTTP/1.1"), "first line must be an HTTP/1.1 request line");
            ensure!(line.matches(' ').count() == 2, "malformed request line");
            ensure!(
                line.bytes().all(|b| (0x21..=0x7e).contains(&b) || b == b' '),
                "request line with a control or non-ASCII byte"
            );
            continue;
        }
        ensure!(!line.starts_with([' ', '\t']), "header line starts with whitespace");
        let (name, value) = line.split_once(':').context("malformed header line")?;
        ensure!(is_header_name(name), "malformed header name");
        let name = name.to_ascii_lowercase();
        ensure!(names.insert(name.clone()), "header {name} appears twice");
        let value = value.trim_start();
        let value_start = line_range.start + (line.len() - value.len());
        if name == "authorization" {
            ensure!(!saw_auth, "more than one Authorization header");
            saw_auth = true;
            let rest = value
                .strip_prefix("Bearer")
                .context("Authorization must be a bearer token")?;
            let spaces = rest.len() - rest.trim_start_matches(' ').len();
            ensure!(spaces >= 1, "Authorization must be a bearer token");
            let expected = value_start + "Bearer".len() + spaces..line_range.end;
            ensure!(
                span == expected,
                "token span must be exactly the bearer token value"
            );
        } else {
            ensure!(
                span.start >= line_range.end || span.end <= line_range.start,
                "token span overlaps a header other than Authorization"
            );
            if name == "host" {
                ensure!(!saw_host, "more than one Host header");
                ensure!(value.trim_end() == server_name, "Host must be {server_name}");
                saw_host = true;
            }
            if name == "content-length" {
                let len = parse_length(value.trim_end())?;
                ensure!(len <= MAX_BODY_LEN, "Content-Length {len} is over the {MAX_BODY_LEN}-byte limit");
                saw_length = true;
            }
            ensure!(
                name != "transfer-encoding",
                "Transfer-Encoding is not allowed: Content-Length frames the request"
            );
        }
    }
    ensure!(saw_auth, "no Authorization header");
    ensure!(saw_host, "no Host header");
    ensure!(saw_length, "no Content-Length header");
    Ok(())
}

/// A `Content-Length` value: decimal digits and nothing else. Rust's integer
/// parser would also take a leading `+`, which is the kind of thing two HTTP
/// parsers disagree on.
/// An HTTP header field name as RFC 9110 defines it: a non-empty token, no
/// whitespace anywhere, so nothing can be read as two names or hide a colon.
pub fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

pub fn parse_length(value: &str) -> Result<usize> {
    ensure!(
        !value.is_empty() && value.len() <= 18 && value.bytes().all(|b| b.is_ascii_digit()),
        "Content-Length must be a decimal number"
    );
    value.parse::<usize>().context("Content-Length")
}

/// The body length the pool's record announces: the request length the pool
/// lets through before the next token record. `trailer` is what the borrower
/// would send between the record and the body, and must be empty: the head is
/// the pool's, blank line included.
pub fn check_trailer(header: &RequestHeader, trailer: &[u8]) -> Result<usize> {
    ensure!(
        trailer.is_empty(),
        "the borrower sends nothing between the token record and the body"
    );
    let head = std::str::from_utf8(&header.template).context("header is not UTF-8")?;
    let mut body_len = None;
    for line in head.split("\r\n").skip(1) {
        if let Some((n, v)) = line.split_once(':')
            && n.trim().eq_ignore_ascii_case("content-length")
        {
            body_len = Some(parse_length(v.trim())?);
        }
    }
    body_len.context("header has no Content-Length")
}

/// Checks a full header template (ending in a blank line, the token line
/// last) and returns it as the pool's record plus what the borrower sends
/// between the record and the body: nothing. Kept as a pair for the callers
/// that frame the request.
pub fn split_template(template: &str) -> Result<(String, Vec<u8>)> {
    ensure!(
        template.ends_with("\r\n\r\n"),
        "template must end with a blank line"
    );
    let marker = template
        .find(TOKEN_MARKER)
        .context("template has no {token}")?;
    let line_end = template[marker..]
        .find("\r\n")
        .map(|i| marker + i + 2)
        .unwrap();
    ensure!(
        &template[line_end..] == "\r\n",
        "the Authorization line must be the last header: the pool's record is the whole head"
    );
    Ok((template.to_string(), Vec::new()))
}

/// Builds the borrower's header from a template with markers.
///
/// The token span is pinned to `token_len` rounded up to whole 16-byte blocks
/// and aligned to a block boundary by padding the end of the preceding header
/// line with spaces (optional whitespace, which servers strip). The pool fills
/// the span with its token followed by spaces. A pool that put anything but a
/// token in the span would break its own credential, and the alignment leaves
/// it no byte outside the span, so it cannot smuggle in a header.
pub fn fill_template(template: &str, token_len: usize, body_len: usize) -> Result<RequestHeader> {
    ensure!(
        template.matches(TOKEN_MARKER).count() == 1,
        "template must contain {TOKEN_MARKER} exactly once"
    );
    let span_len = span_len_for(token_len);
    let mut text = template.replace(BODY_LEN_MARKER, &body_len.to_string());
    let marker = text.find(TOKEN_MARKER).unwrap();
    let line_start = text[..marker]
        .rfind("\r\n")
        .context("the Authorization header must not be the first line")?;
    ensure!(
        text[..line_start].contains("\r\n"),
        "put at least one header before Authorization: the line before it is padded for alignment"
    );
    let pad = (16 - marker % 16) % 16;
    text.insert_str(line_start, &" ".repeat(pad));
    let start = marker + pad;
    text.replace_range(start..start + TOKEN_MARKER.len(), &"x".repeat(span_len));
    // The pool's record is the whole head: the Authorization line, then the
    // blank line.
    let template = text.into_bytes();
    ensure!(
        template.ends_with(b"\r\n\r\n"),
        "the head must end with the blank line"
    );
    Ok(RequestHeader {
        template,
        token: start..start + span_len,
    })
}

/// Roots trusting tlsn's test server.
pub fn fixture_roots() -> Result<rustls::RootCertStore> {
    let der = CertificateDer::from_slice(tls_server_fixture::CA_CERT_DER);
    let anchor = anchor_from_trusted_cert(&der)?.to_owned();
    Ok(rustls::RootCertStore {
        roots: vec![anchor],
    })
}

/// Mozilla's roots, for real servers.
pub fn mozilla_roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Multiplexed session over one byte stream, as tlsn does it. The returned
/// sender closes the session; the driver then runs until the peer agrees.
#[allow(clippy::type_complexity)]
pub fn session<Io>(
    io: Io,
) -> Result<(
    Session,
    Pin<Box<dyn Future<Output = Result<()>> + Send>>,
    tokio::sync::oneshot::Sender<()>,
)>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    struct MuxHandle(tlsn_mux::Handle);

    impl std::fmt::Debug for MuxHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("MuxHandle")
        }
    }

    impl Mux for MuxHandle {
        fn open(&self, id: &[u8]) -> Result<mpz_common::io::Io, std::io::Error> {
            let stream = self.0.new_stream(id).map_err(std::io::Error::other)?;
            Ok(mpz_common::io::Io::from_io(stream))
        }
    }

    let config = tlsn_mux::Config::builder()
        .keep_alive(true)
        .close_sync(true)
        .build()?;
    let mut conn = tlsn_mux::Connection::new(io, config);
    let handle = conn.handle()?;

    // Threads for the two-party computation. Each keeps an allocator cache of
    // its own, so more threads mean more resident memory for the same work;
    // the proofs are short and mostly sequential, so a few are plenty.
    let threads = std::env::var("LEMBAS_MPC_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(MPC_THREADS);
    match ThreadPool::builder().num_threads(threads).build_global() {
        Ok(()) | Err(ThreadPoolBuildError::AlreadyInitialized) => {}
        Err(e) => bail!("thread pool: {e}"),
    }

    let session = Session::builder()
        .pool(ThreadPool::global())
        .build(MuxHandle(handle))?;

    // Drive the mux; close it when asked, then run until the peer agrees.
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();
    let driver = Box::pin(async move {
        let mut closing = false;
        futures::future::poll_fn(|cx| {
            if !closing && Pin::new(&mut close_rx).poll(cx).is_ready() {
                closing = true;
                conn.close();
            }
            conn.poll(cx)
        })
        .await?;
        Ok(())
    });

    Ok((session, driver, close_tx))
}

/// A connection with three channels opened in the order both sides agree on.
pub struct Link {
    pub session: Session,
    pub driver: Pin<Box<dyn Future<Output = Result<()>> + Send>>,
    pub close: tokio::sync::oneshot::Sender<()>,
    /// The two-party computation.
    pub mpc: Context,
    /// Everything the borrower sends.
    pub up: Context,
    /// Everything the pool sends.
    pub down: Context,
}

/// Opens a link over `io`.
pub fn link<Io>(io: Io) -> Result<Link>
where
    Io: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
{
    let (session, driver, close) = session(io)?;
    let mpc = session.new_context()?;
    let up = session.new_context()?;
    let down = session.new_context()?;
    Ok(Link {
        session,
        driver,
        close,
        mpc,
        up,
        down,
    })
}

/// Decodes an HTTP/1.1 chunked body; returns the input unchanged if it is not
/// chunked.
pub fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
            return body.to_vec();
        };
        let Ok(size) = usize::from_str_radix(std::str::from_utf8(&rest[..eol]).unwrap_or("x"), 16)
        else {
            return body.to_vec();
        };
        rest = &rest[eol + 2..];
        if size == 0 {
            return out;
        }
        // A hostile size would overflow `size + 2`; check before adding.
        if size > rest.len() || rest.len() < size + 2 {
            return body.to_vec();
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(text: &str) -> RequestHeader {
        fill_template(&split_template(text).unwrap().0, 8, 5).unwrap()
    }

    #[test]
    fn template_is_pinned_and_aligned() {
        let ok = header(
            "POST /v1/messages HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\r\n",
        );
        assert_eq!(ok.token.start % 16, 0);
        assert_eq!(ok.token.len(), 16);
        assert_eq!(ok.template.len(), ok.token.end + 4);
        let text = String::from_utf8(ok.template.clone()).unwrap();
        assert!(text.ends_with("Bearer xxxxxxxxxxxxxxxx\r\n\r\n"));
        // Only the real credential length is lent (see TOKEN_LEN).
        assert!(check_template(&ok, 8, "api.example").is_err());
        // The whole head is the pool's: other headers go before Authorization,
        // and the borrower sends nothing between the record and the body.
        let full = "POST /v1/messages HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nX-Later: 1\r\nAuthorization: Bearer {token}\r\n\r\n";
        let (hidden, trailer) = split_template(full).unwrap();
        assert!(trailer.is_empty());
        let real = fill_template(&hidden, TOKEN_LEN, 5).unwrap();
        assert_eq!(real.token.len(), 112);
        check_template(&real, TOKEN_LEN, "api.example").unwrap();
        assert_eq!(check_trailer(&real, b"").unwrap(), 5);
        assert!(check_trailer(&real, b"\r\n").is_err());
        // A header after Authorization is refused.
        assert!(split_template("POST / HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nAuthorization: Bearer {token}\r\nX-Later: 1\r\n\r\n").is_err());
        // So are chunked framing and a Content-Length that is not plain digits.
        let made = |t: &str| fill_template(&split_template(t).unwrap().0, TOKEN_LEN, 5).unwrap();
        assert!(check_template(&made("POST / HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer {token}\r\n\r\n"), TOKEN_LEN, "api.example").is_err());
        assert!(check_template(&made("POST / HTTP/1.1\r\nHost: api.example\r\nContent-Length: +5\r\nAuthorization: Bearer {token}\r\n\r\n"), TOKEN_LEN, "api.example").is_err());
        assert!(parse_length("+5").is_err() && parse_length("5").unwrap() == 5 && parse_length("").is_err());
        assert!(check_template(&real, TOKEN_LEN, "other.example").is_err());
        // A shorter credential in the same span would leave room to smuggle a
        // header, which is why it is refused.
        let smuggled = b"\r\nX: value";
        assert!(112 - 97 >= smuggled.len());
        assert!(check_template(&real, 97, "api.example").is_err());

        // The token must be the whole bearer value.
        let bad = header(
            "POST / HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer {token}extra\r\n\r\n",
        );
        assert!(check_template(&bad, 8, "api.example").is_err());
        // Not in another header.
        let bad = header("POST / HTTP/1.1\r\nHost: api.example\r\nX-Key: {token}\r\n\r\n");
        assert!(check_template(&bad, 8, "api.example").is_err());
        // Not on the request line, and not right after it either (the line
        // before Authorization is padded).
        assert!(fill_template("POST /{token} HTTP/1.1\r\nHost: a\r\n\r\n", 8, 0).is_err());
        assert!(fill_template("POST / HTTP/1.1\r\nAuthorization: Bearer {token}\r\nHost: a\r\n\r\n", 8, 0).is_err());
        // Duplicate Host is refused.
        let dup = header("POST / HTTP/1.1\r\nHost: a\r\nHost: api.example\r\nAuthorization: Bearer {token}\r\n\r\n");
        assert!(check_template(&dup, 8, "api.example").is_err());
    }

    // The pool cannot read the body, so the template must say how long it is,
    // within the limit, and may not repeat a header.
    #[test]
    fn template_policy_bounds_the_request() {
        let real = |t: &str, body: usize| fill_template(&split_template(t).unwrap().0, TOKEN_LEN, body).unwrap();
        let base = "POST / HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n\r\n";
        check_template(&real(base, MAX_BODY_LEN), TOKEN_LEN, "api.example").unwrap();
        assert!(check_template(&real(base, MAX_BODY_LEN + 1), TOKEN_LEN, "api.example").is_err());
        let no_length = real("POST / HTTP/1.1\r\nHost: api.example\r\nX: y\r\nAuthorization: Bearer {token}\r\n\r\n", 0);
        assert!(check_template(&no_length, TOKEN_LEN, "api.example").is_err());
        let twice = real(
            "POST / HTTP/1.1\r\nHost: api.example\r\nContent-Length: {body_len}\r\nX-A: 1\r\nx-a: 2\r\nAuthorization: Bearer {token}\r\n\r\n",
            0,
        );
        // (X-A before Authorization is the shape now; the duplicate is the error.)
        assert!(check_template(&twice, TOKEN_LEN, "api.example").is_err());
    }

    #[test]
    fn dechunk_survives_hostile_sizes() {
        assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n\r\n"), b"abc");
        // A size that would overflow `size + 2` is returned as-is, not panicked on.
        let hostile = b"ffffffffffffffff\r\nabc\r\n";
        assert_eq!(dechunk(hostile), hostile.to_vec());
        let short = b"10\r\nabc\r\n";
        assert_eq!(dechunk(short), short.to_vec());
    }
}
