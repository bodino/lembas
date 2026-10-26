//! The spliced token record: the borrower owns the TLS session, the pool
//! inserts one record.
//!
//! The borrower runs an ordinary TLS 1.2 client (rustls) over a byte relay
//! through the pool, verifies the server's certificate itself and holds the
//! traffic keys alone from the start. The pool opens the TCP connection, so it
//! decides which server the token goes to, and it writes exactly one record:
//! the request line, `Host`, `Content-Length` and the `Authorization` line.
//! For that record it needs keystream and a tag.
//!
//! - Keystream: AES on the borrower's client key, proven in zero knowledge
//!   (mpz's QuickSilver VM). The borrower is the prover, so its key stays
//!   private against a malicious pool; the pool is the verifier and receives
//!   the keystream with a soundness guarantee against a borrower that would
//!   try to pass off a keystream of its choosing (say zeros, which would put
//!   the token on the pool's uplink in the clear). Nothing is garbled: the
//!   pool has no private input, so a proof is all it needs.
//! - Tag: the borrower knows `H` and `E_K(J0)` and computes the GHASH terms
//!   for every block it knows; the token span's blocks go through one
//!   multiplicative-to-additive conversion each, with the pool's ciphertext
//!   block as its input. The pool learns only the finished tag.
//!
//! The pool refuses to splice unless the first application-data record on the
//! connection is its own, so the token cannot become the body or a header
//! continuation of a request the borrower wrote. Then the borrower continues
//! with its own records, sequence number +1, and the pool relays bytes it can
//! neither read nor forge.
//!
//! The link carries three channels, opened in the same order by both sides:
//! `mpc` for the two-party computation, `up` for everything the borrower
//! sends (its header, then [`Frame`]s), `down` for everything the pool sends
//! (its [`Hello`], then [`Frame`]s).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Context as _, Result, bail, ensure};
use mpz_circuits::{AES128_KS, AES128_POST_KS};
use mpz_common::{Context, Flush, future::Output as _};
use mpz_core::{Block, bitvec::BitVec};
use mpz_fields::{Field, gf2_128::Gf2_128};
use mpz_garble_core::Delta;
use mpz_memory_core::DecodeFutureTyped;
use mpz_ole::{Receiver as OleReceiver, Sender as OleSender};
use mpz_ot::{
    chou_orlandi as co, ferret, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{
    MultiplicativeToAdditive, ShareConversionReceiver, ShareConversionSender,
};
use mpz_vm_core::{
    Call, Execute, Vm,
    memory::{Array, binary::U8},
    prelude::*,
};
use mpz_zk::{Prover, Verifier};
use rustls::crypto::{CryptoProvider, ring};
use serde::{Deserialize, Serialize};
use serio::{SinkExt, stream::IoStreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

use crate::{
    Hello, MAX_PENDING_BYTES, MAX_SENT_BYTES, PROTOCOL_VERSION, RELAY_IDLE_TIMEOUT,
    RELAY_MAX_DURATION, RequestHeader, SETUP_TIMEOUT, TOKEN_LEN, Tamper, check_template,
    fill_template,
    record::{ALERT, APPLICATION_DATA, CLOSE_NOTIFY, LocalRecordLayer, MAX_RECORD_PLAINTEXT, TrafficKeys, tls12_aad},
    split_template,
};

/// Most handshake bytes the pool relays from the borrower before the splice.
pub const MAX_HANDSHAKE_BYTES: usize = 64 << 10;
/// Largest frame either side accepts on the relay channels.
pub const MAX_FRAME_BYTES: usize = 256 << 10;
/// Frame size the borrower batches its records into.
const FRAME_TARGET: usize = 64 << 10;
/// Largest TLS record payload on the wire (plaintext plus AEAD expansion).
const MAX_RECORD_WIRE: usize = (1 << 14) + 2048;

/// Everything that crosses the relay channels after the opening messages.
#[derive(Debug, Serialize, Deserialize)]
pub enum Frame {
    /// TLS bytes to relay: borrower → server on `up`, server → borrower on
    /// `down`.
    Bytes(Vec<u8>),
    /// The borrower's handshake is done; the pool's record takes this
    /// sequence number and nonce.
    Splice { seq: u64, nonce: [u8; 12] },
    /// The borrower's share of the token record's tag.
    TagShare([u8; 16]),
    /// The pool wrote the token record; the borrower may continue.
    Spliced,
    /// The server closed its side.
    ServerClosed,
    /// The borrower is finished with the connection.
    Done,
}

impl std::fmt::Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Frame::Bytes(b) => write!(f, "Bytes({})", b.len()),
            Frame::Splice { seq, .. } => write!(f, "Splice(seq {seq})"),
            Frame::TagShare(_) => f.write_str("TagShare"),
            Frame::Spliced => f.write_str("Spliced"),
            Frame::ServerClosed => f.write_str("ServerClosed"),
            Frame::Done => f.write_str("Done"),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS record framing

/// Cuts a byte stream into whole TLS records (5-byte header included).
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete record, if the buffer holds one.
    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        ensure!(
            (20..=23).contains(&self.buf[0]) && self.buf[1] == 3,
            "not a TLS record (type {}, version {}.{})",
            self.buf[0],
            self.buf[1],
            self.buf[2]
        );
        let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        ensure!(len <= MAX_RECORD_WIRE, "TLS record of {len} bytes is too long");
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let record = self.buf.drain(..5 + len).collect();
        Ok(Some(record))
    }

    /// True when no partial record is pending.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Encodes a TLS 1.2 AES-GCM record from its parts.
fn encode_record(nonce: &[u8; 12], ciphertext: &[u8], tag: [u8; 16]) -> Vec<u8> {
    let len = 8 + ciphertext.len() + 16;
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&[0x17, 0x03, 0x03]);
    record.extend_from_slice(&(len as u16).to_be_bytes());
    record.extend_from_slice(&nonce[4..]);
    record.extend_from_slice(ciphertext);
    record.extend_from_slice(&tag);
    record
}

// ---------------------------------------------------------------------------
// GHASH helpers, with tlsn's bit conventions.

fn gf(block: [u8; 16]) -> Gf2_128 {
    Gf2_128::from(Block::from(block).reverse_bits())
}

fn un_gf(x: Gf2_128) -> [u8; 16] {
    Block::from(x).reverse_bits().to_bytes()
}

/// The blocks GHASH runs over: AAD (padded), ciphertext (padded), lengths.
fn ghash_blocks(aad: &[u8], ciphertext: &[u8]) -> Vec<[u8; 16]> {
    let mut data = aad.to_vec();
    data.resize(aad.len().div_ceil(16) * 16, 0);
    let ct_start = data.len();
    data.extend_from_slice(ciphertext);
    data.resize(ct_start + ciphertext.len().div_ceil(16) * 16, 0);
    let len_block =
        (((aad.len() as u64) * 8) as u128) << 64 | ((ciphertext.len() as u64) * 8) as u128;
    data.extend_from_slice(&len_block.to_be_bytes());
    data.chunks_exact(16)
        .map(|c| {
            let mut b = [0u8; 16];
            b.copy_from_slice(c);
            b
        })
        .collect()
}

/// Powers of H for each GHASH block: block `j` of `m` is multiplied by H^(m-j).
fn h_powers(h: Gf2_128, m: usize) -> Vec<Gf2_128> {
    let mut powers = vec![Gf2_128::zero(); m];
    let mut acc = Gf2_128::one();
    for j in (0..m).rev() {
        acc = acc * h;
        powers[j] = acc;
    }
    powers
}

fn counter_block(nonce: &[u8; 12], ctr: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[12..].copy_from_slice(&ctr.to_be_bytes());
    b
}

/// Which GHASH block indices hold the token span. Ciphertext block `k` is
/// data block `1 + k`, after the single AAD block; the span is block aligned
/// (`check_template`), so these blocks hold nothing but the span.
fn span_blocks(header: &RequestHeader) -> Vec<usize> {
    (header.token.start / 16..header.token.end.div_ceil(16))
        .map(|k| 1 + k)
        .collect()
}

fn aes_block(key: &[u8; 16], block: [u8; 16]) -> [u8; 16] {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut b = GenericArray::from(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn xor_keystream(plaintext: &[u8], keystream: &[[u8; 16]]) -> Vec<u8> {
    plaintext
        .iter()
        .enumerate()
        .map(|(i, p)| p ^ keystream[i / 16][i % 16])
        .collect()
}

// ---------------------------------------------------------------------------
// MPC plumbing

/// KOS correlated OT, for the share conversion.
type CotSender = SharedRCOTSender<kos::Sender<co::Receiver>, Block>;
type CotReceiver = SharedRCOTReceiver<kos::Receiver<co::Sender>, bool, Block>;

/// Correlated OT for the proof: ferret (LPN-based extension) over KOS, as
/// tlsn does it. KOS alone costs the receiver, here the borrower, 16 bytes per
/// correlation; ferret amortizes that to a fraction of a bit.
type ProofCotSender = SharedRCOTSender<ferret::Sender<kos::Sender<co::Receiver>>, Block>;
type ProofCotReceiver =
    SharedRCOTReceiver<ferret::Receiver<kos::Receiver<co::Sender>>, bool, Block>;
/// The pool verifies the keystream proof; its correlated-OT sender carries
/// the VOLE correlations the proof runs on.
type PoolVm = Verifier<ProofCotSender>;
/// The borrower proves the keystream.
type BorrowerVm = Prover<ProofCotReceiver>;

fn ferret_config() -> ferret::FerretConfig {
    ferret::FerretConfig::builder()
        .lpn_type(ferret::LpnType::Regular)
        .build()
        .expect("ferret config is valid")
}

/// The pool's share converter: OLE sender on its correlated-OT sender.
type PoolConverter =
    ShareConversionSender<OleSender<AnySender<RandomizeRCOTSender<CotSender>>, Gf2_128>, Gf2_128>;
/// The borrower's share converter: OLE receiver on its correlated-OT receiver.
type BorrowerConverter = ShareConversionReceiver<
    OleReceiver<AnyReceiver<RandomizeRCOTReceiver<CotReceiver>>, Gf2_128>,
    Gf2_128,
>;

/// One KOS sender (with its delta) and one KOS receiver for a party.
fn cot_pair() -> (Delta, CotSender, CotReceiver) {
    let mut rng = rand::rng();
    let delta = Delta::random(&mut rng);
    let cot_send = SharedRCOTSender::new(kos::Sender::new(
        kos::SenderConfig::default(),
        delta.into_inner(),
        co::Receiver::default(),
    ));
    let cot_recv = SharedRCOTReceiver::new(kos::Receiver::new(
        kos::ReceiverConfig::default(),
        co::Sender::default(),
    ));
    (delta, cot_send, cot_recv)
}

/// The pool's VM: the zero-knowledge verifier. It has no private input and
/// learns the keystream, which the borrower knows anyway.
///
/// The share converter gets a correlated-OT instance of its own rather than a
/// clone of the VM's: a shared instance's `flush` is a barrier across every
/// handle with allocations, and the two are flushed at different times. The
/// extra base OT costs about a millisecond.
fn pool_vm() -> (PoolVm, PoolConverter) {
    let mut rng = rand::rng();
    let delta = Delta::random(&mut rng);
    let kos = kos::Sender::new(
        kos::SenderConfig::default(),
        delta.into_inner(),
        co::Receiver::default(),
    );
    let cot_send = SharedRCOTSender::new(ferret::Sender::new(
        ferret_config(),
        Block::random(&mut rng),
        kos,
    ));
    let vm = Verifier::new(Default::default(), delta, cot_send);
    let (_, ole_cot, _) = cot_pair();
    let converter = ShareConversionSender::new(OleSender::new(
        Block::random(&mut rand::rng()),
        AnySender::new(RandomizeRCOTSender::new(ole_cot)),
    ));
    (vm, converter)
}

/// The borrower's VM: the zero-knowledge prover. Its key is a witness,
/// private against a malicious pool. The roles are fixed in code: the key
/// holder proves, and no message from the peer can change that.
fn borrower_vm() -> (BorrowerVm, BorrowerConverter) {
    let mut rng = rand::rng();
    let kos = kos::Receiver::new(kos::ReceiverConfig::default(), co::Sender::default());
    let cot_recv = SharedRCOTReceiver::new(ferret::Receiver::new(
        ferret_config(),
        Block::random(&mut rng),
        kos,
    ));
    let vm = Prover::new(Default::default(), cot_recv);
    let (_, _, ole_cot) = cot_pair();
    let converter = ShareConversionReceiver::new(OleReceiver::new(AnyReceiver::new(
        RandomizeRCOTReceiver::new(ole_cot),
    )));
    (vm, converter)
}

/// The keystream circuit: one key schedule, then one AES block per counter.
struct Keystream {
    key: Array<U8, 16>,
    counters: Vec<Array<U8, 16>>,
    outputs: Vec<DecodeFutureTyped<BitVec, [u8; 16]>>,
}

/// Declares the circuit so it can be preprocessed before the handshake.
fn alloc_keystream<V: Vm<mpz_vm_core::memory::binary::Binary>>(
    vm: &mut V,
    blocks: usize,
    holds_key: bool,
) -> Result<Keystream> {
    let key: Array<U8, 16> = vm.alloc()?;
    if holds_key {
        vm.mark_private(key)?;
    } else {
        vm.mark_blind(key)?;
    }
    let schedule: Array<U8, 176> =
        vm.call(Call::builder(AES128_KS.clone()).arg(key).build()?)?;
    let mut counters = Vec::with_capacity(blocks);
    let mut outputs = Vec::with_capacity(blocks);
    for _ in 0..blocks {
        let ctr: Array<U8, 16> = vm.alloc()?;
        vm.mark_public(ctr)?;
        let out: Array<U8, 16> = vm.call(
            Call::builder(AES128_POST_KS.clone())
                .arg(schedule)
                .arg(ctr)
                .build()?,
        )?;
        outputs.push(vm.decode(out)?);
        counters.push(ctr);
    }
    Ok(Keystream {
        key,
        counters,
        outputs,
    })
}

/// Runs the keystream circuit and returns the keystream. `key` is `Some` on
/// the borrower only. On the pool the outputs come out of the verifier, so
/// they are correct for whatever key the borrower committed to, or the proof
/// fails and this errors.
async fn compute_keystream<V: Vm<mpz_vm_core::memory::binary::Binary>>(
    vm: &mut V,
    ctx: &mut Context,
    ks: Keystream,
    key: Option<[u8; 16]>,
    nonce: &[u8; 12],
) -> Result<Vec<[u8; 16]>> {
    if let Some(key) = key {
        vm.assign(ks.key, key)?;
    }
    vm.commit(ks.key)?;
    for (i, ctr) in ks.counters.iter().enumerate() {
        // J0 is counter 1; the keystream starts at counter 2.
        vm.assign(*ctr, counter_block(nonce, i as u32 + 2))?;
        vm.commit(*ctr)?;
    }
    vm.flush(ctx).await?;
    vm.execute(ctx).await?;
    // The verifier's check of the proof happens in this flush; a prover that
    // cheated is caught before the keystream is used.
    vm.flush(ctx).await.context("keystream proof")?;
    ks.outputs
        .into_iter()
        .map(|mut out| {
            out.try_recv()?
                .context("keystream block was not decoded")
        })
        .collect()
}

/// Additive shares of `my_input * their_input`, one per element.
async fn to_additive<C>(
    converter: &mut C,
    ctx: &mut Context,
    inputs: &[Gf2_128],
) -> Result<Vec<Gf2_128>>
where
    C: MultiplicativeToAdditive<Gf2_128> + Flush,
    <C as MultiplicativeToAdditive<Gf2_128>>::Error: std::fmt::Display,
    <C as Flush>::Error: std::fmt::Display,
{
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = converter
        .queue_to_additive(inputs)
        .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?;
    converter
        .flush(ctx)
        .await
        .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?;
    Ok(out
        .try_recv()
        .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?
        .context("shares were not computed")?
        .shares)
}

// ---------------------------------------------------------------------------
// Pool

/// What the pool measured.
pub struct PoolReport {
    /// Circuit and OT preprocessing, overlapped with the handshake.
    pub preprocess: Duration,
    /// From the borrower's header to its `Splice` request.
    pub handshake: Duration,
    /// Keystream, tag and writing the record.
    pub splice: Duration,
    /// The token record as sent to the server.
    pub record: Vec<u8>,
    /// Its plaintext, with the token in place. Never log it.
    pub headers: Vec<u8>,
}

// The report holds the token; a `?report` in a log line must not print it.
impl std::fmt::Debug for PoolReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolReport")
            .field("preprocess", &self.preprocess)
            .field("handshake", &self.handshake)
            .field("splice", &self.splice)
            .field("record_len", &self.record.len())
            .finish()
    }
}

/// Runs the pool's side of one borrowed request.
///
/// `mpc`, `up`, `down` are the three channels, in order. `server` is the
/// connection to the API server; the pool does not verify it (the borrower
/// does, and the token record is only written after the borrower's handshake
/// has completed). `token` goes into the borrower's `Authorization` header.
/// `tamper` is a test hook for a misbehaving pool.
pub async fn run_pool<S>(
    mpc: Context,
    mut up: Context,
    mut down: Context,
    server: S,
    server_name: &str,
    token: &str,
    tamper: Tamper,
) -> Result<PoolReport>
where
    S: AsyncRead + AsyncWrite,
{
    ensure!(
        token.len() == TOKEN_LEN,
        "refusing to lend a {}-byte credential: only {TOKEN_LEN}-byte ones keep the span tight",
        token.len()
    );
    ensure!(
        !token.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
        "credential contains whitespace or control characters"
    );

    let started = Instant::now();
    let prelude = async {
        down.io_mut()
            .send(Hello {
                version: PROTOCOL_VERSION,
                token_len: token.len(),
                server_name: server_name.to_string(),
            })
            .await
            .context("prelude: greeting the borrower")?;
        let request: RequestHeader = up
            .io_mut()
            .expect_next()
            .await
            .context("prelude: waiting for the borrower's header")?;
        check_template(&request, token.len(), server_name).context("borrower's header rejected")?;
        Ok::<_, anyhow::Error>(request)
    };
    let request = tokio::time::timeout(SETUP_TIMEOUT, prelude)
        .await
        .context("prelude timed out")??;

    let mut headers = request.template.clone();
    let span = &mut headers[request.token.clone()];
    span.fill(b' ');
    span[..token.len()].copy_from_slice(token.as_bytes());
    if let Some(tamper) = tamper {
        tamper(&mut headers);
    }
    let blocks = headers.len().div_ceil(16);
    let span_idx = span_blocks(&request);

    // Preprocess while the borrower's handshake is relayed.
    let (mut vm, mut converter) = pool_vm();
    let mut ks = Some(alloc_keystream(&mut vm, blocks, false)?);
    MultiplicativeToAdditive::<Gf2_128>::alloc(&mut converter, span_idx.len())
        .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?;
    let pre = async move {
        let mut mpc = mpc;
        let t = Instant::now();
        vm.preprocess(&mut mpc).await.context("preprocessing the circuit")?;
        vm.flush(&mut mpc).await.context("preparing the keystream proof")?;
        debug!("pool: circuit preprocessed");
        converter
            .flush(&mut mpc)
            .await
            .map_err(|e| anyhow::anyhow!("preprocessing the share conversion: {e}"))?;
        Ok::<_, anyhow::Error>((vm, converter, mpc, t.elapsed()))
    };
    tokio::pin!(pre);
    let mut pre_done = false;
    let mut parts = None;
    let mut preprocess = Duration::ZERO;

    // Relay. Reads and writes on the server socket must not block each other,
    // or the pool stalls writing a large body while the server stalls writing
    // the response; writes are queued and drained by their own select arm.
    let (mut rd, mut wr) = tokio::io::split(server);
    let mut buf = vec![0u8; 64 << 10];
    let mut out: Vec<u8> = Vec::new();
    let mut written = 0;
    let mut server_open = true;
    let mut spliced = false;
    let mut handshake_bytes = 0usize;
    let mut sent = 0usize;
    let mut deframer = Deframer::default();
    let mut handshake = Duration::ZERO;
    let mut splice = Duration::ZERO;
    let mut record = Vec::new();
    let setup_deadline = tokio::time::sleep(SETUP_TIMEOUT);
    tokio::pin!(setup_deadline);
    let deadline = tokio::time::sleep(RELAY_MAX_DURATION);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            res = &mut pre, if !pre_done => {
                pre_done = true;
                let (vm, converter, mpc, took) = res?;
                parts = Some((vm, converter, mpc));
                preprocess = took;
                info!(?preprocess, "pool: preprocessed");
            }
            // Stop taking frames while the server is behind on the bytes queued.
            frame = tokio::time::timeout(RELAY_IDLE_TIMEOUT, up.io_mut().expect_next::<Frame>()),
                if out.len() - written < MAX_PENDING_BYTES =>
            {
                let frame = match frame.context("no frame from the borrower for 10 min")? {
                    Ok(frame) => frame,
                    // The borrower closing its end is also how a borrow ends.
                    Err(e) => {
                        debug!("pool: borrower left: {e}");
                        break;
                    }
                };
                match frame {
                    Frame::Bytes(bytes) => {
                        ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                        if spliced {
                            sent += bytes.len();
                            ensure!(sent <= MAX_SENT_BYTES, "borrower sent more than {MAX_SENT_BYTES} bytes");
                            if server_open {
                                out.extend_from_slice(&bytes);
                            }
                        } else {
                            handshake_bytes += bytes.len();
                            ensure!(
                                handshake_bytes <= MAX_HANDSHAKE_BYTES,
                                "more than {MAX_HANDSHAKE_BYTES} bytes of handshake"
                            );
                            deframer.push(&bytes);
                            while let Some(rec) = deframer.next_record()? {
                                // The token record must be the first
                                // application data on this connection.
                                ensure!(
                                    rec[0] != 0x17,
                                    "borrower sent application data before the token record"
                                );
                                out.extend_from_slice(&rec);
                            }
                        }
                    }
                    Frame::Splice { seq, nonce } => {
                        ensure!(!spliced, "borrower asked for a second token record");
                        ensure!(deframer.is_empty(), "partial record pending at the splice");
                        ensure!(server_open, "server closed before the token record");
                        handshake = started.elapsed();
                        if !pre_done {
                            let (vm, converter, mpc, took) = (&mut pre).await?;
                            pre_done = true;
                            parts = Some((vm, converter, mpc));
                            preprocess = took;
                        }
                        let (vm, converter, mpc) = parts.as_mut().expect("preprocessed");
                        let t = Instant::now();
                        record = splice_record(
                            vm,
                            converter,
                            mpc,
                            &mut up,
                            ks.take().expect("one splice"),
                            &headers,
                            &span_idx,
                            seq,
                            &nonce,
                        )
                        .await?;
                        out.extend_from_slice(&record);
                        down.io_mut()
                            .send(Frame::Spliced)
                            .await
                            .context("telling the borrower the record is written")?;
                        spliced = true;
                        splice = t.elapsed();
                        info!(?handshake, ?splice, "pool: token record written");
                    }
                    Frame::Done => break,
                    other => bail!("unexpected {other} from the borrower"),
                }
            }
            _ = &mut setup_deadline, if !spliced => {
                bail!("setup timed out");
            }
            _ = &mut deadline => {
                bail!("borrow ran for more than {} s", RELAY_MAX_DURATION.as_secs());
            }
            n = wr.write(&out[written..]), if written < out.len() => {
                written += n.context("writing to the server")?;
                if written == out.len() {
                    out.clear();
                    written = 0;
                }
            }
            n = rd.read(&mut buf), if server_open => {
                let n = n.context("reading from the server")?;
                if n == 0 {
                    server_open = false;
                    // The borrower may already have left after the server's
                    // close_notify; then there is nobody to tell.
                    if down.io_mut().send(Frame::ServerClosed).await.is_err() {
                        debug!("pool: borrower gone before the server closed");
                        break;
                    }
                } else if let Err(e) = down.io_mut().send(Frame::Bytes(buf[..n].to_vec())).await {
                    if spliced {
                        debug!("pool: borrower left: {e}");
                        break;
                    }
                    return Err(anyhow::Error::from(e).context("forwarding the server's bytes"));
                }
            }
        }
    }
    if server_open && written < out.len() {
        wr.write_all(&out[written..]).await.context("writing the rest to the server")?;
    }
    let _ = wr.shutdown().await;
    ensure!(spliced, "the borrower left before the token record was written");
    info!("pool: done");

    Ok(PoolReport {
        preprocess,
        handshake,
        splice,
        record,
        headers,
    })
}

/// Computes and encodes the token record on the pool's side.
#[allow(clippy::too_many_arguments)]
async fn splice_record(
    vm: &mut PoolVm,
    converter: &mut PoolConverter,
    ctx: &mut Context,
    up: &mut Context,
    ks: Keystream,
    headers: &[u8],
    span_idx: &[usize],
    seq: u64,
    nonce: &[u8; 12],
) -> Result<Vec<u8>> {
    let keystream = compute_keystream(vm, ctx, ks, None, nonce).await?;
    let ciphertext = xor_keystream(headers, &keystream);

    // The tag: the borrower covers every block it knows; for the span's blocks
    // this side inputs its ciphertext block, the borrower the matching power
    // of H, and each gets an additive share of the product.
    let blocks = ghash_blocks(&tls12_aad(seq, APPLICATION_DATA, headers.len()), &ciphertext);
    let inputs: Vec<Gf2_128> = span_idx.iter().map(|&j| gf(blocks[j])).collect();
    let shares = to_additive(converter, ctx, &inputs).await?;
    let mine = shares.into_iter().fold(Gf2_128::zero(), |acc, s| acc + s);

    let share = match up.io_mut().expect_next::<Frame>().await? {
        Frame::TagShare(share) => share,
        other => bail!("expected the borrower's tag share, got {other}"),
    };
    let tag = un_gf(gf(share) + mine);
    Ok(encode_record(nonce, &ciphertext, tag))
}

// ---------------------------------------------------------------------------
// Borrower

/// What the borrower got.
#[derive(Debug)]
pub struct BorrowerReport {
    /// The whole response, headers included.
    pub response: Vec<u8>,
    /// Time from sending the body to the first response byte.
    pub first_byte: Duration,
    /// The traffic keys, for diagnostics in tests.
    pub keys: TrafficKeys,
    /// Sequence number of the token record.
    pub splice_seq: u64,
    /// The header as the borrower asked for it (token span filled with x).
    pub header: RequestHeader,
}

/// The borrower's TLS client configuration: TLS 1.2 with AES-128-GCM only,
/// since that is the record format the pool's spliced record uses.
fn tls_config(roots: &rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>> {
    let provider = CryptoProvider {
        cipher_suites: vec![
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        ..ring::default_provider()
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.enable_secret_extraction = true;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// The session as rustls leaves it after the handshake.
struct Session {
    keys: TrafficKeys,
    /// Next client sequence number: the token record's.
    write_seq: u64,
    /// Next server sequence number.
    read_seq: u64,
}

/// Runs the TLS handshake over the relay and takes the keys out.
async fn handshake(
    up: &mut Context,
    down: &mut Context,
    config: Arc<rustls::ClientConfig>,
    server_name: &str,
) -> Result<Session> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())?;
    let mut conn = rustls::ClientConnection::new(config, name)?;
    loop {
        let mut bytes = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut bytes)?;
        }
        if !bytes.is_empty() {
            up.io_mut().send(Frame::Bytes(bytes)).await?;
        }
        if !conn.is_handshaking() {
            break;
        }
        match tokio::time::timeout(SETUP_TIMEOUT, down.io_mut().expect_next::<Frame>())
            .await
            .context("no bytes from the server")??
        {
            Frame::Bytes(bytes) => {
                let mut rest = &bytes[..];
                while !rest.is_empty() {
                    ensure!(conn.read_tls(&mut rest)? > 0, "TLS client refused the server's bytes");
                    conn.process_new_packets()
                        .context("TLS handshake with the server")?;
                }
            }
            Frame::ServerClosed => bail!("server closed the connection during the handshake"),
            other => bail!("unexpected {other} during the handshake"),
        }
    }
    let secrets = conn
        .dangerous_extract_secrets()
        .context("taking the traffic keys out of the TLS client")?;
    let (write_seq, tx) = secrets.tx;
    let (read_seq, rx) = secrets.rx;
    let (client_write_key, client_write_iv) = gcm_parts(tx)?;
    let (server_write_key, server_write_iv) = gcm_parts(rx)?;
    Ok(Session {
        keys: TrafficKeys {
            client_write_key,
            client_write_iv,
            server_write_key,
            server_write_iv,
        },
        write_seq,
        read_seq,
    })
}

/// Key and implicit nonce of an AES-128-GCM direction.
fn gcm_parts(secrets: rustls::ConnectionTrafficSecrets) -> Result<([u8; 16], [u8; 4])> {
    match secrets {
        rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } => Ok((
            key.as_ref().try_into().context("key length")?,
            iv.as_ref()[..4].try_into().context("iv length")?,
        )),
        _ => bail!("the negotiated cipher is not AES-128-GCM"),
    }
}

/// Runs the borrower's side of one borrowed request.
///
/// `template` is the header text with [`TOKEN_MARKER`](crate::TOKEN_MARKER)
/// and optionally [`BODY_LEN_MARKER`](crate::BODY_LEN_MARKER).
/// `expected_server` is the name the borrower verifies the server's
/// certificate for. `token_len` is the length of the credential the borrower
/// expects; a pool announcing another length is refused. The response is
/// copied to `out` as it arrives.
#[allow(clippy::too_many_arguments)]
pub async fn run_borrower(
    mpc: Context,
    mut up: Context,
    mut down: Context,
    template: &str,
    body: Vec<u8>,
    roots: rustls::RootCertStore,
    expected_server: &str,
    token_len: usize,
    mut out: Box<dyn AsyncWrite + Unpin + Send>,
) -> Result<BorrowerReport> {
    let config = tls_config(&roots)?;

    let setup = async {
        let hello: Hello = down.io_mut().expect_next().await?;
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

        // Only the part through the Authorization line is the pool's record;
        // the remaining headers go in the borrower's own first record.
        let (hidden, trailer) = split_template(template)?;
        let header = fill_template(&hidden, token_len, body.len())?;
        up.io_mut().send(header.clone()).await?;
        let blocks = header.template.len().div_ceil(16);
        let span_idx = span_blocks(&header);

        let (mut vm, mut converter) = borrower_vm();
        let ks = alloc_keystream(&mut vm, blocks, true)?;
        MultiplicativeToAdditive::<Gf2_128>::alloc(&mut converter, span_idx.len())
            .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?;

        // Preprocess and shake hands at the same time.
        let mut mpc = mpc;
        let pre = async {
            let t = Instant::now();
            vm.preprocess(&mut mpc).await.context("preprocessing the circuit")?;
            vm.flush(&mut mpc).await.context("preparing the keystream proof")?;
            debug!("borrower: circuit preprocessed");
            converter
                .flush(&mut mpc)
                .await
                .map_err(|e| anyhow::anyhow!("preprocessing the share conversion: {e}"))?;
            info!(took = ?t.elapsed(), "borrower: preprocessed");
            Ok::<_, anyhow::Error>(())
        };
        let hs = handshake(&mut up, &mut down, config, expected_server);
        let ((), session) = tokio::try_join!(pre, hs)?;
        info!(
            write_seq = session.write_seq,
            read_seq = session.read_seq,
            "borrower: handshake done, holds the traffic keys"
        );

        // The token record takes the next client sequence number.
        let seq = session.write_seq;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&session.keys.client_write_iv);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        up.io_mut().send(Frame::Splice { seq, nonce }).await?;

        let key = session.keys.client_write_key;
        let keystream = compute_keystream(&mut vm, &mut mpc, ks, Some(key), &nonce).await?;

        // Tag share: every block this side knows, locally; the span's blocks
        // through the share conversion with the pool's ciphertext.
        let h = gf(aes_block(&key, [0u8; 16]));
        let e_j0 = gf(aes_block(&key, counter_block(&nonce, 1)));
        let ciphertext = xor_keystream(&header.template, &keystream);
        let blocks = ghash_blocks(&tls12_aad(seq, APPLICATION_DATA, header.template.len()), &ciphertext);
        let powers = h_powers(h, blocks.len());
        let local = blocks
            .iter()
            .zip(&powers)
            .enumerate()
            .filter(|(j, _)| !span_idx.contains(j))
            .fold(Gf2_128::zero(), |acc, (_, (block, power))| acc + gf(*block) * *power);
        let inputs: Vec<Gf2_128> = span_idx.iter().map(|&j| powers[j]).collect();
        let shares = to_additive(&mut converter, &mut mpc, &inputs).await?;
        let joint = shares.into_iter().fold(Gf2_128::zero(), |acc, s| acc + s);
        up.io_mut()
            .send(Frame::TagShare(un_gf(e_j0 + local + joint)))
            .await?;

        Ok::<_, anyhow::Error>((header, trailer, session))
    };
    let (header, trailer, session) = tokio::time::timeout(SETUP_TIMEOUT, setup)
        .await
        .context("setup timed out")??;
    let keys = session.keys.clone();
    let splice_seq = session.write_seq;
    let (mut writer, mut reader) =
        LocalRecordLayer::new(&keys, splice_seq + 1, session.read_seq).split();

    // Read the response while the body is still being sent. The pool's
    // `Spliced` arrives on the same channel, so the reader relays it.
    let (spliced_tx, spliced_rx) = tokio::sync::oneshot::channel();
    let t = Instant::now();
    let reading = tokio::spawn(async move {
        let mut spliced_tx = Some(spliced_tx);
        let mut deframer = Deframer::default();
        let mut response = Vec::new();
        let mut first_byte = None;
        loop {
            match tokio::time::timeout(RELAY_IDLE_TIMEOUT, down.io_mut().expect_next::<Frame>())
                .await
                .context("no frame from the pool for 10 min")??
            {
                Frame::Spliced => {
                    if let Some(tx) = spliced_tx.take() {
                        let _ = tx.send(());
                    }
                }
                Frame::Bytes(bytes) => {
                    ensure!(bytes.len() <= MAX_FRAME_BYTES, "frame of {} bytes", bytes.len());
                    deframer.push(&bytes);
                    while let Some(record) = deframer.next_record()? {
                        let (typ, plaintext) = reader.decrypt(&record)?;
                        match typ {
                            APPLICATION_DATA => {
                                first_byte.get_or_insert_with(|| t.elapsed());
                                out.write_all(&plaintext).await?;
                                out.flush().await?;
                                response.extend_from_slice(&plaintext);
                            }
                            ALERT => {
                                ensure!(
                                    plaintext == CLOSE_NOTIFY,
                                    "unexpected alert from the server: {plaintext:?}"
                                );
                                debug!("borrower: server sent close_notify");
                                return Ok((response, first_byte.unwrap_or_default()));
                            }
                            typ => bail!("unexpected record type {typ}"),
                        }
                    }
                }
                Frame::ServerClosed => {
                    debug!("borrower: server closed the connection");
                    return Ok((response, first_byte.unwrap_or_default()));
                }
                other => bail!("unexpected {other} from the pool"),
            }
        }
    });

    // The body waits for the token record to be on the wire.
    if spliced_rx.await.is_err() {
        // The reader ended first: a server alert, most likely.
        let err = match reading.await? {
            Ok(_) => anyhow::anyhow!("server closed before the token record was written"),
            Err(e) => e,
        };
        return Err(err);
    }
    let payload = [trailer, body].concat();
    let mut frame = Vec::with_capacity(FRAME_TARGET + MAX_RECORD_PLAINTEXT + 64);
    for chunk in payload.chunks(MAX_RECORD_PLAINTEXT) {
        frame.extend_from_slice(&writer.encrypt(APPLICATION_DATA, chunk)?);
        if frame.len() >= FRAME_TARGET {
            up.io_mut().send(Frame::Bytes(std::mem::take(&mut frame))).await?;
        }
    }
    if !frame.is_empty() {
        up.io_mut().send(Frame::Bytes(frame)).await?;
    }
    debug!(bytes = payload.len(), "borrower: request sent");

    let (response, first_byte) = tokio::time::timeout(RELAY_MAX_DURATION, reading)
        .await
        .context("borrow ran too long")???;

    let close_notify = writer.encrypt(ALERT, &CLOSE_NOTIFY)?;
    let _ = up.io_mut().send(Frame::Bytes(close_notify)).await;
    let _ = up.io_mut().send(Frame::Done).await;
    info!("borrower: done");

    Ok(BorrowerReport {
        response,
        first_byte,
        keys,
        splice_seq,
        header,
    })
}

#[cfg(test)]
mod tests {
    use aes_gcm::{Aes128Gcm, NewAead, aead::AeadInPlace};
    use rand::RngExt;

    use super::*;

    /// The tag assembled from the borrower's local terms and simulated
    /// additive shares for the span must be AES-GCM's tag.
    #[test]
    fn split_tag_matches_aes_gcm() {
        let mut rng = rand::rng();
        let key: [u8; 16] = rng.random();
        let nonce: [u8; 12] = rng.random();
        let seq = 1u64;
        // 226-byte header with a 112-byte span at offset 112 (seven blocks).
        let mut plaintext: Vec<u8> = (0..226u32).map(|i| (i % 251) as u8).collect();
        let span = 112..224;
        for b in &mut plaintext[span.clone()] {
            *b = rng.random();
        }
        let header = RequestHeader {
            template: plaintext.clone(),
            token: span.clone(),
        };
        let span_idx = span_blocks(&header);
        assert_eq!(span_idx, vec![8, 9, 10, 11, 12, 13, 14]);

        // Pool: keystream, ciphertext.
        let keystream: Vec<[u8; 16]> = (0..plaintext.len().div_ceil(16))
            .map(|i| aes_block(&key, counter_block(&nonce, i as u32 + 2)))
            .collect();
        let ciphertext = xor_keystream(&plaintext, &keystream);
        let aad = tls12_aad(seq, APPLICATION_DATA, plaintext.len());
        let blocks = ghash_blocks(&aad, &ciphertext);

        // Borrower: everything but the span.
        let h = gf(aes_block(&key, [0u8; 16]));
        let e_j0 = gf(aes_block(&key, counter_block(&nonce, 1)));
        let powers = h_powers(h, blocks.len());
        let local = blocks
            .iter()
            .zip(&powers)
            .enumerate()
            .filter(|(j, _)| !span_idx.contains(j))
            .fold(Gf2_128::zero(), |acc, (_, (b, p))| acc + gf(*b) * *p);

        // Simulated conversion: random additive shares of block * power.
        let mut borrower_joint = Gf2_128::zero();
        let mut pool_joint = Gf2_128::zero();
        for &j in &span_idx {
            let product = gf(blocks[j]) * powers[j];
            let a: Gf2_128 = gf(rng.random());
            borrower_joint = borrower_joint + a;
            pool_joint = pool_joint + (product + a);
        }
        let share = un_gf(e_j0 + local + borrower_joint);
        let tag = un_gf(gf(share) + pool_joint);

        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
        let mut reference = plaintext.clone();
        let expected = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut reference)
            .unwrap();
        assert_eq!(reference, ciphertext);
        assert_eq!(tag[..], expected[..]);
        assert_eq!(encode_record(&nonce, &ciphertext, tag).len(), 5 + 8 + 226 + 16);
    }

    #[test]
    fn deframer_cuts_records() {
        let mut d = Deframer::default();
        let rec1 = [0x16, 3, 3, 0, 2, 0xaa, 0xbb];
        let rec2 = [0x17, 3, 3, 0, 1, 0xcc];
        d.push(&rec1[..4]);
        assert!(d.next_record().unwrap().is_none());
        assert!(!d.is_empty());
        d.push(&rec1[4..]);
        d.push(&rec2);
        assert_eq!(d.next_record().unwrap().unwrap(), rec1);
        assert_eq!(d.next_record().unwrap().unwrap(), rec2);
        assert!(d.next_record().unwrap().is_none());
        assert!(d.is_empty());
        d.push(&[0x50, 3, 3, 0, 0]);
        assert!(d.next_record().is_err());
    }
}
