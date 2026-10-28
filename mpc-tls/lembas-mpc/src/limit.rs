//! The limit proof: a member shows a lender what Anthropic says about the
//! member's own usage, without the lender holding the member's login.
//!
//! The **prover** (the member that wants to borrow) runs an ordinary TLS
//! session to the API server through a relay operated by the **verifier**
//! (the lender), exactly as a borrowed request does, and sends one request of
//! its own: `GET /api/oauth/usage` with its own bearer token. The verifier
//! relays bytes it cannot read, and keeps every record of the connection: the
//! prover's request record and the server's response records, as they came
//! off the verifier's own TCP connection to the server.
//!
//! Then the prover opens a prefix of each side, under the key that wrote it:
//!
//! - It commits to the key in the zero-knowledge VM and proves `AES_K` on
//!   public blocks: the zero block (`H`), the record's `J0`, and the counter
//!   blocks of the bytes to reveal. The same key, committed once, feeds all
//!   three (one key schedule in the circuit).
//! - The verifier checks the record's GCM tag with the proven `H` and
//!   `E_K(J0)`, against the ciphertext it took off the wire. The tag holds
//!   only under the key the server used (another key making a valid tag on a
//!   ciphertext the prover did not choose is a 2^128 search), so the key the
//!   prover committed to is the real one, and the keystream blocks XOR the
//!   wire ciphertext to the real plaintext.
//!
//! What the verifier sees: the request line and `Host` (so it knows which
//! endpoint answered: the prover's `Authorization` line stays hidden) and the
//! response from its first byte through the end of its body, so no part of it
//! can be pointed at out of context. What it does not see: the token, the
//! other request headers, anything in other TLS sessions.
//!
//! The verifier's own TCP path to the server is trusted, as it is for a
//! borrowed request: the prover cannot swap the server's bytes, since they
//! never pass through it on their way to the verifier.

use std::{collections::BTreeMap, time::Instant};

use anyhow::{Context as _, Result, bail, ensure};
use mpz_common::Context;
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

use crate::{
    SETUP_TIMEOUT, dechunk,
    local::ResponseFramer,
    record::{ALERT, APPLICATION_DATA, CHANGE_CIPHER_SPEC, CLOSE_NOTIFY, HANDSHAKE, LocalRecordLayer, tls12_aad},
    session::MAX_FRAME_BYTES,
    splice::{Deframer, Proving, Verifying, counter_block, extract_keys, gf, ghash_blocks, h_powers, tls_config},
};

/// Changes whenever the messages below change.
pub const LIMIT_PROTOCOL_VERSION: u32 = 1;
/// The endpoint a member's usage is read from, with its own token.
pub const USAGE_PATH: &str = "/api/oauth/usage";
/// Most bytes of handshake either side may send.
pub const MAX_HANDSHAKE_BYTES: usize = 64 << 10;
/// Most response bytes the verifier keeps.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Most plaintext bytes a prover may reveal: each 16 bytes is one AES block
/// proven in zero knowledge, so this bounds the proof's cost.
pub const MAX_REVEAL: usize = 32 << 10;

/// The verifier's opening message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitHello {
    pub version: u32,
    /// The server the verifier connected to; the prover's `Host`.
    pub server_name: String,
    /// The path the prover must request.
    pub path: String,
}

/// What the prover opens, once the response is in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    /// Implicit nonce parts of the two directions. Not secret: the keys are.
    pub client_iv: [u8; 4],
    pub server_iv: [u8; 4],
    /// Bytes of the request record's plaintext to reveal, from the start.
    pub request_len: usize,
    /// Bytes of the response plaintext to reveal, from its first byte,
    /// across as many records as it takes.
    pub response_len: usize,
}

/// Everything the prover sends.
#[derive(Serialize, Deserialize)]
pub enum ProverMsg {
    /// TLS bytes for the server.
    Bytes(Vec<u8>),
    /// The response is in; the proof starts.
    Reveal(Reveal),
    Done,
}

/// Everything the verifier sends, after its [`LimitHello`].
#[derive(Serialize, Deserialize)]
pub enum VerifierMsg {
    /// TLS bytes from the server.
    Bytes(Vec<u8>),
    ServerClosed,
    /// What the verifier made of the proof.
    Verdict { ok: bool, detail: String },
}

// ---------------------------------------------------------------------------
// The request

/// The request as both sides know it: what the prover reveals (the request
/// line and `Host`), then one fixed line so that a reveal rounded to a block
/// cannot run into a private header.
pub fn fixed_head(path: &str, host: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\naccept-encoding: identity\r\n")
}

/// How many bytes of the request the prover reveals: the first two lines.
pub fn revealed_head_len(path: &str, host: &str) -> usize {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n").len()
}

/// The whole request, as the prover sends it. The `user-agent` shape is
/// required by the usage endpoint.
pub fn request_text(path: &str, host: &str, token: &str) -> String {
    format!(
        "{}user-agent: claude-code/2.1.0\r\nanthropic-beta: oauth-2025-04-20\r\n\
         content-type: application/json\r\nAuthorization: Bearer {token}\r\n\r\n",
        fixed_head(path, host)
    )
}

// ---------------------------------------------------------------------------
// The transcript the verifier keeps

/// A TLS 1.2 AES-GCM record taken apart.
#[derive(Debug, Clone)]
pub struct EncryptedRecord {
    pub seq: u64,
    pub explicit_nonce: [u8; 8],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

impl EncryptedRecord {
    fn parse(seq: u64, record: &[u8]) -> Result<Self> {
        let payload = &record[5..];
        ensure!(payload.len() >= 24, "encrypted record too short");
        let (explicit, rest) = payload.split_at(8);
        let (ct, tag) = rest.split_at(rest.len() - 16);
        Ok(Self {
            seq,
            explicit_nonce: explicit.try_into().unwrap(),
            ciphertext: ct.to_vec(),
            tag: tag.try_into().unwrap(),
        })
    }
}

/// One side of the connection as the verifier counts it: handshake in the
/// clear, then encrypted records from the change of cipher spec on, the first
/// of them `Finished` at sequence number 0.
#[derive(Debug, Default)]
struct Side {
    bytes: usize,
    ccs: bool,
    encrypted: u64,
}

impl Side {
    /// Admits a record; returns its sequence number if it is encrypted.
    fn record(&mut self, record: &[u8]) -> Result<Option<u64>> {
        let typ = record[0];
        if !self.ccs {
            self.bytes += record.len();
            ensure!(
                self.bytes <= MAX_HANDSHAKE_BYTES,
                "more than {MAX_HANDSHAKE_BYTES} bytes of handshake"
            );
            match typ {
                CHANGE_CIPHER_SPEC => self.ccs = true,
                HANDSHAKE | ALERT => {}
                APPLICATION_DATA => bail!("application data before the change of cipher spec"),
                other => bail!("record of unknown type {other}"),
            }
            return Ok(None);
        }
        let seq = self.encrypted;
        self.encrypted += 1;
        if seq == 0 {
            ensure!(typ == HANDSHAKE, "the first encrypted record is not Finished");
        }
        Ok(Some(seq))
    }
}

/// The records the proof is about, as the verifier took them off the wire.
#[derive(Debug, Default)]
pub struct Transcript {
    client: Side,
    server: Side,
    /// The prover's one request record, at sequence number 1.
    pub request: Option<EncryptedRecord>,
    /// The server's application-data records, in order.
    pub responses: Vec<EncryptedRecord>,
    response_bytes: usize,
}

impl Transcript {
    /// A record from the prover: handshake, `Finished`, then exactly one
    /// application-data record, then alerts only.
    pub fn client_record(&mut self, record: &[u8]) -> Result<()> {
        let typ = record[0];
        let Some(seq) = self.client.record(record)? else {
            return Ok(());
        };
        match (seq, typ) {
            (0, _) => Ok(()),
            (1, APPLICATION_DATA) => {
                self.request = Some(EncryptedRecord::parse(seq, record)?);
                Ok(())
            }
            (_, ALERT) => Ok(()),
            (_, APPLICATION_DATA) => bail!("prover sent a second application-data record"),
            (_, other) => bail!("prover sent a record of type {other} after the request"),
        }
    }

    /// A record from the server: handshake, `Finished`, then the response.
    pub fn server_record(&mut self, record: &[u8]) -> Result<()> {
        let typ = record[0];
        let Some(seq) = self.server.record(record)? else {
            return Ok(());
        };
        if seq > 0 && typ == APPLICATION_DATA {
            self.response_bytes += record.len();
            ensure!(
                self.response_bytes <= MAX_RESPONSE_BYTES,
                "more than {MAX_RESPONSE_BYTES} bytes of response"
            );
            self.responses.push(EncryptedRecord::parse(seq, record)?);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The proof

/// One record to open: what the AES inputs and the tag check need.
#[derive(Debug, Clone)]
struct Opening {
    nonce: [u8; 12],
    seq: u64,
    ciphertext: Vec<u8>,
    tag: [u8; 16],
    /// Bytes of plaintext to reveal, from the start.
    reveal: usize,
}

impl Opening {
    fn new(iv: &[u8; 4], record: &EncryptedRecord, reveal: usize) -> Self {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(iv);
        nonce[4..].copy_from_slice(&record.explicit_nonce);
        Self {
            nonce,
            seq: record.seq,
            ciphertext: record.ciphertext.clone(),
            tag: record.tag,
            reveal,
        }
    }

    fn blocks(&self) -> usize {
        self.reveal.div_ceil(16)
    }

    /// `J0`, then the counter blocks of the revealed bytes.
    fn inputs(&self) -> Vec<[u8; 16]> {
        let mut v = vec![counter_block(&self.nonce, 1)];
        v.extend((0..self.blocks()).map(|i| counter_block(&self.nonce, i as u32 + 2)));
        v
    }

    /// Checks the tag under `h` and `e_j0`, then opens the plaintext.
    fn open(&self, h: [u8; 16], e_j0: [u8; 16], keystream: &[[u8; 16]]) -> Result<Vec<u8>> {
        let aad = tls12_aad(self.seq, APPLICATION_DATA, self.ciphertext.len());
        let blocks = ghash_blocks(&aad, &self.ciphertext);
        let powers = h_powers(gf(h), blocks.len());
        let tag = blocks
            .iter()
            .zip(&powers)
            .fold(gf(e_j0), |acc, (b, p)| acc + gf(*b) * *p);
        ensure!(
            tag == gf(self.tag),
            "record {} does not authenticate under the key the prover committed to",
            self.seq
        );
        ensure!(keystream.len() == self.blocks(), "keystream block count");
        Ok(self.ciphertext[..self.reveal]
            .iter()
            .enumerate()
            .map(|(i, c)| c ^ keystream[i / 16][i % 16])
            .collect())
    }
}

/// The openings under one key: the AES inputs are the zero block (`H`), then
/// each record's.
#[derive(Debug, Clone)]
struct KeyPlan {
    openings: Vec<Opening>,
}

impl KeyPlan {
    fn inputs(&self) -> Vec<[u8; 16]> {
        let mut v = vec![[0u8; 16]];
        for o in &self.openings {
            v.extend(o.inputs());
        }
        v
    }

    /// Checks every record's tag and returns the revealed plaintexts.
    fn open(&self, outputs: &[[u8; 16]]) -> Result<Vec<Vec<u8>>> {
        ensure!(outputs.len() == self.inputs().len(), "AES output count");
        let h = outputs[0];
        let mut at = 1;
        let mut out = Vec::new();
        for o in &self.openings {
            let e_j0 = outputs[at];
            let ks = &outputs[at + 1..at + 1 + o.blocks()];
            at += 1 + o.blocks();
            out.push(o.open(h, e_j0, ks)?);
        }
        Ok(out)
    }
}

/// What both sides agree to prove, from the transcript and the reveal.
struct Plan {
    request: KeyPlan,
    response: KeyPlan,
}

impl Plan {
    fn new(transcript: &Transcript, reveal: &Reveal, min_request: usize) -> Result<Self> {
        let request = transcript.request.as_ref().context("no request record")?;
        ensure!(
            reveal.request_len >= min_request && reveal.request_len <= request.ciphertext.len(),
            "request reveal of {} bytes (need {min_request}, have {})",
            reveal.request_len,
            request.ciphertext.len()
        );
        ensure!(
            reveal.response_len > 0 && reveal.response_len <= MAX_REVEAL,
            "response reveal of {} bytes (at most {MAX_REVEAL})",
            reveal.response_len
        );
        let mut openings = Vec::new();
        let mut remaining = reveal.response_len;
        for record in &transcript.responses {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(record.ciphertext.len());
            openings.push(Opening::new(&reveal.server_iv, record, take));
            remaining -= take;
        }
        ensure!(remaining == 0, "response reveal runs past the response records");
        Ok(Self {
            request: KeyPlan {
                openings: vec![Opening::new(&reveal.client_iv, request, reveal.request_len)],
            },
            response: KeyPlan { openings },
        })
    }
}

// ---------------------------------------------------------------------------
// What the verifier learns

/// Anthropic's answer to the usage probe, as the verifier read it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Utilization per window, 0 to 100 (`five_hour`, `seven_day`, model
    /// windows).
    pub windows: BTreeMap<String, f64>,
    /// When each window resets, as the server wrote it.
    pub resets_at: BTreeMap<String, String>,
    /// Anthropic locked a window.
    pub locked: bool,
}

impl Usage {
    /// Reads the usage endpoint's body, as the lembas pool does.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(body).context("usage body is not JSON")?;
        let obj = v.as_object().context("usage body is not an object")?;
        let mut windows = BTreeMap::new();
        let mut resets_at = BTreeMap::new();
        let mut locked = false;
        for (key, value) in obj {
            if key == "extra_usage" {
                continue;
            }
            let Some(value) = value.as_object() else { continue };
            if let Some(u) = value.get("utilization").and_then(|u| u.as_f64())
                && u.is_finite()
            {
                windows.insert(key.clone(), u.clamp(0.0, 100.0));
            }
            if let Some(r) = value.get("resets_at").and_then(|r| r.as_str()) {
                resets_at.insert(key.clone(), r.to_string());
            }
            if value.get("locked_reason").is_some_and(|l| !l.is_null()) {
                locked = true;
            }
        }
        ensure!(
            windows.contains_key("five_hour") && windows.contains_key("seven_day"),
            "usage body has no five_hour and seven_day windows"
        );
        Ok(Self {
            windows,
            resets_at,
            locked,
        })
    }

    /// True when any window is at `percent` or Anthropic locked one.
    pub fn at_limit(&self, percent: f64) -> bool {
        self.locked || self.windows.values().any(|&u| u >= percent)
    }
}

/// What the verifier got out of a proof.
#[derive(Debug)]
pub struct Verified {
    /// The revealed request prefix: the request line and `Host`.
    pub request: String,
    /// The response head, status line through the blank line.
    pub head: String,
    pub status: u16,
    /// The response body, chunking removed.
    pub body: Vec<u8>,
}

impl Verified {
    pub fn usage(&self) -> Result<Usage> {
        ensure!(self.status == 200, "usage endpoint answered {}", self.status);
        Usage::parse(&self.body)
    }
}

/// Reads the revealed response: it must be one whole HTTP/1.1 response and
/// nothing else.
fn parse_response(plaintext: &[u8]) -> Result<(String, u16, Vec<u8>)> {
    let mut framer = ResponseFramer::default();
    let used = framer.feed(plaintext)?;
    ensure!(used == plaintext.len(), "revealed bytes run past the response");
    ensure!(framer.complete(), "the revealed response is incomplete");
    let status = framer.status().context("no status")?;
    let end = plaintext
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("no head")?;
    let head = String::from_utf8(plaintext[..end + 4].to_vec()).context("head is not UTF-8")?;
    let body = dechunk(&plaintext[end + 4..]);
    Ok((head, status, body))
}

/// Phases, for whoever measures them.
pub type OnPhase<'a> = &'a mut (dyn FnMut(&'static str) + Send);

fn no_phase(_: &'static str) {}

// ---------------------------------------------------------------------------
// Verifier

/// Runs the verifier's side over an open connection to the server. The link
/// to the prover is `mpc`, `up` (the prover's frames) and `down` (ours).
pub async fn verify<S>(
    mut mpc: Context,
    mut up: Context,
    mut down: Context,
    server: S,
    server_name: &str,
    path: &str,
    on_phase: Option<OnPhase<'_>>,
) -> Result<Verified>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut phase_fn = no_phase;
    let on_phase: OnPhase<'_> = match on_phase {
        Some(f) => f,
        None => &mut phase_fn,
    };
    down.io_mut()
        .send(LimitHello {
            version: LIMIT_PROTOCOL_VERSION,
            server_name: server_name.to_string(),
            path: path.to_string(),
        })
        .await
        .context("prelude: greeting the prover")?;

    let t = Instant::now();
    let mut verifying = Verifying::new();
    tokio::time::timeout(SETUP_TIMEOUT, verifying.warm_up(&mut mpc))
        .await
        .context("warm-up timed out")??;
    info!(took = ?t.elapsed(), "verifier: ready");
    on_phase("setup");

    // The relay, with the transcript.
    let (mut rd, mut wr) = tokio::io::split(server);
    let mut transcript = Transcript::default();
    let mut from_prover = Deframer::default();
    let mut from_server = Deframer::default();
    let mut buf = vec![0u8; 64 << 10];
    let mut server_open = true;
    let deadline = tokio::time::sleep(SETUP_TIMEOUT);
    tokio::pin!(deadline);
    let reveal = loop {
        tokio::select! {
            _ = &mut deadline => bail!("the prover did not finish its probe in time"),
            frame = up.io_mut().expect_next::<ProverMsg>() => match frame.context("prover left")? {
                ProverMsg::Bytes(bytes) => {
                    ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                    from_prover.push(&bytes);
                    while let Some(record) = from_prover.next_record()? {
                        transcript.client_record(&record)?;
                        if server_open {
                            wr.write_all(&record).await.context("writing to the server")?;
                        }
                    }
                }
                ProverMsg::Reveal(reveal) => break reveal,
                ProverMsg::Done => bail!("prover gave up before revealing"),
            },
            read = rd.read(&mut buf), if server_open => match read {
                Ok(0) | Err(_) => {
                    server_open = false;
                    let _ = down.io_mut().send(VerifierMsg::ServerClosed).await;
                }
                Ok(n) => {
                    from_server.push(&buf[..n]);
                    while let Some(record) = from_server.next_record()? {
                        transcript.server_record(&record)?;
                    }
                    down.io_mut().send(VerifierMsg::Bytes(buf[..n].to_vec())).await.context("prover left")?;
                }
            },
        }
    };
    on_phase("probe");
    debug!(?reveal, responses = transcript.responses.len(), "verifier: reveal");

    let result = async {
        let plan = Plan::new(&transcript, &reveal, revealed_head_len(path, server_name))?;
        let t = Instant::now();
        let request_out = verifying.aes_blocks(&mut mpc, None, &plan.request.inputs()).await?;
        let response_out = verifying.aes_blocks(&mut mpc, None, &plan.response.inputs()).await?;
        info!(took = ?t.elapsed(), blocks = request_out.len() + response_out.len(), "verifier: proof checked");
        let request = plan.request.open(&request_out)?.remove(0);
        let expected = fixed_head(path, server_name);
        ensure!(
            expected.as_bytes().starts_with(&request),
            "the request is not {:?}",
            String::from_utf8_lossy(&request)
        );
        let response: Vec<u8> = plan.response.open(&response_out)?.concat();
        let (head, status, body) = parse_response(&response)?;
        Ok::<_, anyhow::Error>(Verified {
            request: String::from_utf8(request).unwrap(),
            head,
            status,
            body,
        })
    };
    let result = tokio::time::timeout(SETUP_TIMEOUT, result)
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("the prover did not finish its proof in time")));
    on_phase("proof");
    let verdict = match &result {
        Ok(v) => VerifierMsg::Verdict {
            ok: true,
            detail: format!("{} {}, {} bytes of body", v.request.trim_end(), v.status, v.body.len()),
        },
        Err(e) => VerifierMsg::Verdict {
            ok: false,
            detail: format!("{e:#}"),
        },
    };
    let _ = down.io_mut().send(verdict).await;
    let _ = tokio::time::timeout(SETUP_TIMEOUT, up.io_mut().expect_next::<ProverMsg>()).await;
    let _ = wr.shutdown().await;
    result
}

// ---------------------------------------------------------------------------
// Prover

/// What the prover got back.
#[derive(Debug)]
pub struct Proven {
    pub status: u16,
    /// The verifier's verdict.
    pub accepted: bool,
    pub detail: String,
}

/// Test hook: a prover that lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cheat {
    /// Proves the response under a key of its own, so the plaintext is one it
    /// chose. The tag check must catch it.
    WrongServerKey,
    /// Claims another implicit nonce for the server's records.
    WrongServerIv,
    /// Reveals less than the whole response.
    ShortResponse,
}

/// Runs the prover's side: the probe with `token`, then the proof. The
/// verifier must name `expected_path` (the prover reveals a response to that
/// path and no other).
#[allow(clippy::too_many_arguments)]
pub async fn prove(
    mpc: Context,
    up: Context,
    down: Context,
    roots: &rustls::RootCertStore,
    server_name: &str,
    expected_path: &str,
    token: &str,
    on_phase: Option<OnPhase<'_>>,
) -> Result<Proven> {
    prove_with(mpc, up, down, roots, server_name, expected_path, token, on_phase, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn prove_with(
    mut mpc: Context,
    mut up: Context,
    mut down: Context,
    roots: &rustls::RootCertStore,
    server_name: &str,
    expected_path: &str,
    token: &str,
    on_phase: Option<OnPhase<'_>>,
    cheat: Option<Cheat>,
) -> Result<Proven> {
    let mut phase_fn = no_phase;
    let on_phase: OnPhase<'_> = match on_phase {
        Some(f) => f,
        None => &mut phase_fn,
    };
    ensure!(
        !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic()),
        "the token does not look like one"
    );
    let hello: LimitHello = tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next())
        .await
        .context("waiting for the verifier's hello")??;
    ensure!(
        hello.version == LIMIT_PROTOCOL_VERSION,
        "verifier speaks limit protocol {}, this prover {LIMIT_PROTOCOL_VERSION}",
        hello.version
    );
    ensure!(
        hello.server_name == server_name,
        "verifier connected to {}, this prover wants {server_name}",
        hello.server_name
    );
    ensure!(
        hello.path == expected_path,
        "verifier asks for {}, this prover only reveals {expected_path}",
        hello.path
    );

    let t = Instant::now();
    let mut proving = Proving::new();
    tokio::time::timeout(SETUP_TIMEOUT, proving.warm_up(&mut mpc))
        .await
        .context("warm-up timed out")??;
    info!(took = ?t.elapsed(), "prover: ready");
    on_phase("setup");

    // The TLS session through the verifier.
    let t = Instant::now();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let mut tls = rustls::ClientConnection::new(tls_config(roots)?, name)?;
    let mut deframer = Deframer::default();
    let mut transcript = Transcript::default();
    loop {
        let mut bytes = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut bytes)?;
        }
        if !bytes.is_empty() {
            let mut d = Deframer::default();
            d.push(&bytes);
            while let Some(record) = d.next_record()? {
                transcript.client_record(&record)?;
            }
            up.io_mut().send(ProverMsg::Bytes(bytes)).await.context("verifier left")?;
        }
        if !tls.is_handshaking() {
            break;
        }
        match tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next::<VerifierMsg>())
            .await
            .context("no bytes from the server")??
        {
            VerifierMsg::Bytes(bytes) => {
                let mut rest = &bytes[..];
                while !rest.is_empty() {
                    ensure!(tls.read_tls(&mut rest)? > 0, "TLS client refused the server's bytes");
                    tls.process_new_packets().context("TLS handshake with the server")?;
                }
                deframer.push(&bytes);
                while let Some(record) = deframer.next_record()? {
                    transcript.server_record(&record)?;
                }
            }
            VerifierMsg::ServerClosed => bail!("server closed the connection during the handshake"),
            VerifierMsg::Verdict { detail, .. } => bail!("verifier gave up: {detail}"),
        }
    }
    let hs = extract_keys(tls)?;
    ensure!(hs.write_seq == 1 && hs.read_seq == 1, "unexpected sequence numbers after the handshake");
    let mut keys = hs.keys.clone();
    let mut layer = LocalRecordLayer::new(&hs.keys, hs.write_seq, hs.read_seq);

    // The request: one record, no body.
    let text = request_text(&hello.path, server_name, token);
    let record = layer.encrypt(APPLICATION_DATA, text.as_bytes())?;
    transcript.client_record(&record)?;
    up.io_mut().send(ProverMsg::Bytes(record)).await.context("verifier left")?;

    // The response, until its framing says it is complete.
    let mut framer = ResponseFramer::default();
    let mut response_len = 0usize;
    let mut server_closed = false;
    loop {
        while let Some(record) = deframer.next_record()? {
            transcript.server_record(&record)?;
            let (typ, plaintext) = layer.decrypt(&record)?;
            match typ {
                APPLICATION_DATA => {
                    let used = framer.feed(&plaintext)?;
                    ensure!(used == plaintext.len(), "server sent bytes beyond the response");
                    response_len += plaintext.len();
                }
                ALERT => {
                    ensure!(plaintext == CLOSE_NOTIFY, "unexpected alert from the server: {plaintext:?}");
                    server_closed = true;
                }
                typ => bail!("unexpected record type {typ}"),
            }
        }
        if framer.complete() {
            break;
        }
        if server_closed {
            bail!("server closed the connection with the response incomplete");
        }
        match tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next::<VerifierMsg>())
            .await
            .context("no response from the server")??
        {
            VerifierMsg::Bytes(bytes) => deframer.push(&bytes),
            VerifierMsg::ServerClosed => server_closed = true,
            VerifierMsg::Verdict { detail, .. } => bail!("verifier gave up: {detail}"),
        }
    }
    let status = framer.status().context("no status")?;
    info!(took = ?t.elapsed(), status, response_len, "prover: response in");
    on_phase("probe");

    // The reveal and the proof.
    let mut reveal = Reveal {
        client_iv: keys.client_write_iv,
        server_iv: keys.server_write_iv,
        request_len: revealed_head_len(&hello.path, server_name),
        response_len,
    };
    match cheat {
        Some(Cheat::WrongServerKey) => keys.server_write_key[0] ^= 1,
        Some(Cheat::WrongServerIv) => reveal.server_iv[0] ^= 1,
        Some(Cheat::ShortResponse) => reveal.response_len = response_len.saturating_sub(16).max(1),
        None => {}
    }
    let plan = Plan::new(&transcript, &reveal, reveal.request_len)?;
    up.io_mut().send(ProverMsg::Reveal(reveal)).await.context("verifier left")?;
    let t = Instant::now();
    let request_out = tokio::time::timeout(
        SETUP_TIMEOUT,
        proving.aes_blocks(&mut mpc, Some(keys.client_write_key), &plan.request.inputs()),
    )
    .await
    .context("request proof timed out")??;
    let response_out = tokio::time::timeout(
        SETUP_TIMEOUT,
        proving.aes_blocks(&mut mpc, Some(keys.server_write_key), &plan.response.inputs()),
    )
    .await
    .context("response proof timed out")??;
    info!(took = ?t.elapsed(), blocks = request_out.len() + response_out.len(), "prover: proof done");
    on_phase("proof");
    if cheat.is_none() {
        // Our own check of what the verifier will see.
        plan.request.open(&request_out).context("own check of the request")?;
        plan.response.open(&response_out).context("own check of the response")?;
    }

    let (accepted, detail) = match tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next::<VerifierMsg>())
        .await
        .context("waiting for the verdict")??
    {
        VerifierMsg::Verdict { ok, detail } => (ok, detail),
        VerifierMsg::Bytes(_) | VerifierMsg::ServerClosed => (false, "no verdict".into()),
    };
    let _ = up.io_mut().send(ProverMsg::Done).await;
    Ok(Proven {
        status,
        accepted,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use aes_gcm::{Aes128Gcm, NewAead, aead::AeadInPlace};
    use rand::RngExt;
    use tls_server_fixture::SERVER_DOMAIN;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;
    use crate::{fixture_roots, link, splice::aes_block as aes};

    /// The tag check and the opening agree with AES-GCM.
    #[test]
    fn opening_matches_aes_gcm() {
        let mut rng = rand::rng();
        let key: [u8; 16] = rng.random();
        let iv: [u8; 4] = rng.random();
        let seq = 3u64;
        let plaintext: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let cipher = Aes128Gcm::new(aes_gcm::aead::generic_array::GenericArray::from_slice(&key));
        let mut ct = plaintext.clone();
        let aad = tls12_aad(seq, APPLICATION_DATA, plaintext.len());
        let tag = cipher
            .encrypt_in_place_detached(aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce), &aad, &mut ct)
            .unwrap();
        let record = EncryptedRecord {
            seq,
            explicit_nonce: seq.to_be_bytes(),
            ciphertext: ct,
            tag: tag.into(),
        };
        let plan = KeyPlan {
            openings: vec![Opening::new(&iv, &record, 100)],
        };
        let outputs: Vec<[u8; 16]> = plan.inputs().iter().map(|b| aes(&key, *b)).collect();
        let opened = plan.open(&outputs).unwrap();
        assert_eq!(opened[0], plaintext[..100]);
        // Another key: the tag fails before anything is opened.
        let mut other = key;
        other[3] ^= 1;
        let outputs: Vec<[u8; 16]> = plan.inputs().iter().map(|b| aes(&other, *b)).collect();
        assert!(plan.open(&outputs).is_err());
    }

    #[test]
    fn usage_is_read_like_the_pool_reads_it() {
        let body = br#"{"five_hour":{"utilization":87.5,"resets_at":"2026-10-28T17:00:00Z"},
            "seven_day":{"utilization":12,"resets_at":null},"seven_day_opus":{"utilization":0},
            "extra_usage":{"utilization":500},"other":null}"#;
        let u = Usage::parse(body).unwrap();
        assert_eq!(u.windows["five_hour"], 87.5);
        assert_eq!(u.windows["seven_day"], 12.0);
        assert!(!u.windows.contains_key("extra_usage"));
        assert!(!u.locked);
        assert!(u.at_limit(80.0));
        assert!(!u.at_limit(90.0));
        let locked = br#"{"five_hour":{"utilization":1,"locked_reason":"x"},"seven_day":{"utilization":1}}"#;
        assert!(Usage::parse(locked).unwrap().at_limit(100.0));
        assert!(Usage::parse(br#"{"five_hour":{"utilization":1}}"#).is_err());
    }

    async fn run(cheat: Option<Cheat>) -> (Result<Verified>, Result<Proven>) {
        let (verifier_io, prover_io) = tokio::io::duplex(1 << 20);
        let (server_io, fixture_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let _ = tls_server_fixture::bind_test_server_hyper(fixture_io.compat()).await;
        });
        let v = link(verifier_io.compat()).unwrap();
        let p = link(prover_io.compat()).unwrap();
        let vd = tokio::spawn(v.driver);
        let pd = tokio::spawn(p.driver);
        let roots = fixture_roots().unwrap();
        let verifier = tokio::spawn(async move {
            verify(v.mpc, v.up, v.down, server_io, SERVER_DOMAIN, "/", None).await
        });
        let proven = prove_with(p.mpc, p.up, p.down, &roots, SERVER_DOMAIN, "/", "sk-test-token", None, cheat).await;
        let verified = verifier.await.unwrap();
        drop(p.session);
        drop(v.session);
        let _ = p.close.send(());
        let _ = v.close.send(());
        let _ = pd.await;
        let _ = vd.await;
        (verified, proven)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn honest_prover_is_accepted() {
        let (verified, proven) = run(None).await;
        let verified = verified.unwrap();
        let proven = proven.unwrap();
        assert!(proven.accepted, "{}", proven.detail);
        assert_eq!(verified.status, 200);
        assert_eq!(verified.request, format!("GET / HTTP/1.1\r\nHost: {SERVER_DOMAIN}\r\n"));
        assert!(!verified.body.is_empty());
        assert!(verified.head.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cheating_provers_are_refused() {
        for cheat in [Cheat::WrongServerKey, Cheat::WrongServerIv, Cheat::ShortResponse] {
            let (verified, proven) = run(Some(cheat)).await;
            let err = verified.expect_err(&format!("{cheat:?} should be refused"));
            let text = format!("{err:#}");
            match cheat {
                Cheat::WrongServerKey | Cheat::WrongServerIv => assert!(text.contains("authenticate"), "{text}"),
                Cheat::ShortResponse => assert!(text.contains("incomplete") || text.contains("runs past"), "{text}"),
            }
            if let Ok(p) = proven {
                assert!(!p.accepted);
            }
        }
    }
}
