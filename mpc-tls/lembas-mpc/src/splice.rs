//! The spliced token record: the primitives.
//!
//! The borrower owns the TLS session (an ordinary rustls client whose keys it
//! takes out after the handshake); the pool inserts one record per request,
//! the one carrying the token. For that record it needs:
//!
//! - **Keystream**: AES on the borrower's client key, proven in zero knowledge
//!   (mpz's QuickSilver VM over ferret correlated OT). The borrower is the
//!   prover, so its key stays private against a malicious pool; the pool is the
//!   verifier and receives the keystream with a soundness guarantee against a
//!   borrower that would pass off a keystream of its choosing (say zeros, which
//!   would put the token on the pool's uplink in the clear). Nothing is
//!   garbled: the pool has no private input, so a proof is all it needs.
//! - **The tag**: the borrower knows `H` and `E_K(J0)` and computes the GHASH
//!   terms for every block it knows; the token span's blocks go through one
//!   multiplicative-to-additive share conversion each, with the pool's
//!   ciphertext block as its input. The pool learns only the finished tag.
//!
//! The protocol that uses these, with many connections and many requests per
//! session, is in [`crate::session`].

use std::sync::Arc;

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
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{
    MultiplicativeToAdditive, ShareConversionReceiver, ShareConversionSender,
};
use mpz_vm_core::{
    Call, Vm,
    memory::{Array, binary::U8},
    prelude::*,
};
use mpz_zk::{Prover, Verifier};
use rustls::crypto::{CryptoProvider, ring};
use tracing::debug;

use crate::{
    RequestHeader,
    record::{APPLICATION_DATA, TrafficKeys, tls12_aad},
};

/// Largest TLS record payload on the wire (plaintext plus AEAD expansion).
const MAX_RECORD_WIRE: usize = (1 << 14) + 2048;

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

/// Encodes a TLS 1.2 AES-GCM application-data record from its parts.
pub(crate) fn encode_record(nonce: &[u8; 12], ciphertext: &[u8], tag: [u8; 16]) -> Vec<u8> {
    let len = 8 + ciphertext.len() + 16;
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&[APPLICATION_DATA, 0x03, 0x03]);
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
pub fn span_blocks(header: &RequestHeader) -> Vec<usize> {
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

/// Correlated OT: ferret (LPN-based extension) over KOS, as tlsn does it.
/// KOS alone costs the receiver, here the borrower, 16 bytes per correlation
/// and can only extend once; ferret amortizes to a fraction of a bit and
/// extends as often as a session needs.
type CotSender = ferret::Sender<kos::Sender<co::Receiver>>;
type CotReceiver = ferret::Receiver<kos::Receiver<co::Sender>>;
/// The pool verifies the keystream proof; its correlated-OT sender carries
/// the VOLE correlations the proof runs on.
type PoolVm = Verifier<CotSender>;
/// The borrower proves the keystream.
type BorrowerVm = Prover<CotReceiver>;
/// The pool's share converter: OLE sender on a correlated-OT sender of its own.
type PoolConverter =
    ShareConversionSender<OleSender<AnySender<RandomizeRCOTSender<CotSender>>, Gf2_128>, Gf2_128>;
/// The borrower's share converter: OLE receiver on a correlated-OT receiver
/// of its own.
type BorrowerConverter = ShareConversionReceiver<
    OleReceiver<AnyReceiver<RandomizeRCOTReceiver<CotReceiver>>, Gf2_128>,
    Gf2_128,
>;

/// The pool's side of the two-party computation, for a whole session.
pub type Verifying = Party<PoolVm, PoolConverter>;
/// The borrower's side of the two-party computation, for a whole session.
pub type Proving = Party<BorrowerVm, BorrowerConverter>;

/// Which ferret parameters an instance extends with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Batch {
    /// mpz's default choice: the smallest set that covers the request,
    /// 256k correlations per extension. Right for the share conversion,
    /// which needs under a thousand per request.
    Small,
    /// Half a million per extension: measured the best trade for the proof,
    /// about 95 MB of resident memory a side and 80 KB of download per
    /// request, against 80 MB and 160 KB for the small batch and 140 MB and
    /// 90 KB for the large one. (One request's proof needs about 75k
    /// correlations; the bootstrap costs k base correlations once.)
    #[default]
    Medium,
    /// A million per extension.
    Proof,
}

fn ferret_config(batch: Batch) -> ferret::FerretConfig {
    let mut builder = ferret::FerretConfig::builder();
    builder.lpn_type(ferret::LpnType::Regular);
    let (n, k) = match batch {
        Batch::Small => return builder.build().expect("ferret config is valid"),
        Batch::Medium => (512_000, 22_653),
        Batch::Proof => (1_024_000, 38_737),
    };
    // The first extension runs on the bootstrap correlations, which only
    // cover the smallest parameters; from then on, the chosen batch.
    builder.param_selector(move |_, available, _| {
        if available < 80_000 {
            // mpz's smallest regular parameters.
            mpz_core::lpn::LpnParameters {
                n: 256_000,
                k: 13_249,
                t: 2_000,
            }
        } else {
            mpz_core::lpn::LpnParameters { n, k, t: 2_000 }
        }
    });
    builder.build().expect("ferret config is valid")
}

fn cot_sender(rng: &mut rand::rngs::ThreadRng, batch: Batch) -> (Delta, CotSender) {
    let delta = Delta::random(rng);
    let kos = kos::Sender::new(
        kos::SenderConfig::default(),
        delta.into_inner(),
        co::Receiver::default(),
    );
    (delta, ferret::Sender::new(ferret_config(batch), Block::random(rng), kos))
}

fn cot_receiver(rng: &mut rand::rngs::ThreadRng, batch: Batch) -> CotReceiver {
    let kos = kos::Receiver::new(kos::ReceiverConfig::default(), co::Sender::default());
    ferret::Receiver::new(ferret_config(batch), Block::random(rng), kos)
}

/// One party's zero-knowledge VM and share converter.
///
/// Each has a correlated-OT instance of its own. mpz's shared instance would
/// let them draw on one, but its `flush` is a barrier that every live handle
/// must reach, and the converter only flushes its handle when it has
/// conversions queued, so a VM flush with an idle converter would wait
/// forever. Two ferret setups per session cost less than untangling that.
pub struct Party<V, C> {
    vm: V,
    converter: C,
    /// Requests proven or verified since this setup.
    pub requests: usize,
}

impl Verifying {
    pub fn new() -> Self {
        Self::with_batch(Batch::default())
    }

    /// With a given ferret batch for the proof's correlations.
    pub fn with_batch(batch: Batch) -> Self {
        let mut rng = rand::rng();
        let (delta, cot) = cot_sender(&mut rng, batch);
        let vm = Verifier::new(Default::default(), delta, cot);
        let (_, cot) = cot_sender(&mut rng, Batch::Small);
        let converter = ShareConversionSender::new(OleSender::new(
            Block::random(&mut rng),
            AnySender::new(RandomizeRCOTSender::new(cot)),
        ));
        Self {
            vm,
            converter,
            requests: 0,
        }
    }

    /// Pays the OT setup now rather than at the first request: one throwaway
    /// block proven and checked, one share conversion.
    pub async fn warm_up(&mut self, ctx: &mut Context) -> Result<()> {
        self.keystream(ctx, 1, None, &[0u8; 12]).await?;
        self.convert_to_additive(ctx, &[Gf2_128::one()]).await?;
        debug!("verifier warmed up");
        Ok(())
    }

    /// Computes the token record's ciphertext and this side's share of the
    /// tag. `headers` is the record's plaintext with the token in place.
    pub async fn ciphertext_and_tag_share(
        &mut self,
        ctx: &mut Context,
        headers: &[u8],
        span_idx: &[usize],
        seq: u64,
        nonce: &[u8; 12],
    ) -> Result<(Vec<u8>, Gf2_128)> {
        self.requests += 1;
        let keystream = self.keystream(ctx, headers.len().div_ceil(16), None, nonce).await?;
        let ciphertext = xor_keystream(headers, &keystream);
        let blocks = ghash_blocks(&tls12_aad(seq, APPLICATION_DATA, headers.len()), &ciphertext);
        let inputs: Vec<Gf2_128> = span_idx.iter().map(|&j| gf(blocks[j])).collect();
        let shares = self.convert_to_additive(ctx, &inputs).await?;
        let mine = shares.into_iter().fold(Gf2_128::zero(), |acc, s| acc + s);
        Ok((ciphertext, mine))
    }

    /// The finished record, once the borrower's tag share has arrived.
    pub fn finish_record(
        nonce: &[u8; 12],
        ciphertext: &[u8],
        mine: Gf2_128,
        theirs: [u8; 16],
    ) -> Vec<u8> {
        encode_record(nonce, ciphertext, un_gf(gf(theirs) + mine))
    }
}

impl Default for Verifying {
    fn default() -> Self {
        Self::new()
    }
}

impl Proving {
    pub fn new() -> Self {
        Self::with_batch(Batch::default())
    }

    /// With a given ferret batch for the proof's correlations.
    pub fn with_batch(batch: Batch) -> Self {
        let mut rng = rand::rng();
        let vm = Prover::new(Default::default(), cot_receiver(&mut rng, batch));
        let converter = ShareConversionReceiver::new(OleReceiver::new(AnyReceiver::new(
            RandomizeRCOTReceiver::new(cot_receiver(&mut rng, Batch::Small)),
        )));
        Self {
            vm,
            converter,
            requests: 0,
        }
    }

    /// Mirrors [`Verifying::warm_up`].
    pub async fn warm_up(&mut self, ctx: &mut Context) -> Result<()> {
        self.keystream(ctx, 1, Some([0u8; 16]), &[0u8; 12]).await?;
        self.convert_to_additive(ctx, &[Gf2_128::one()]).await?;
        debug!("prover warmed up");
        Ok(())
    }

    /// Proves the keystream for the record and returns this side's tag share.
    /// `template` is the record's plaintext with the span filled with
    /// placeholders; only the blocks outside the span count.
    pub async fn tag_share(
        &mut self,
        ctx: &mut Context,
        key: &[u8; 16],
        template: &[u8],
        span_idx: &[usize],
        seq: u64,
        nonce: &[u8; 12],
    ) -> Result<[u8; 16]> {
        self.requests += 1;
        let keystream = self.keystream(ctx, template.len().div_ceil(16), Some(*key), nonce).await?;

        let h = gf(aes_block(key, [0u8; 16]));
        let e_j0 = gf(aes_block(key, counter_block(nonce, 1)));
        let ciphertext = xor_keystream(template, &keystream);
        let blocks = ghash_blocks(&tls12_aad(seq, APPLICATION_DATA, template.len()), &ciphertext);
        let powers = h_powers(h, blocks.len());
        let local = blocks
            .iter()
            .zip(&powers)
            .enumerate()
            .filter(|(j, _)| !span_idx.contains(j))
            .fold(Gf2_128::zero(), |acc, (_, (block, power))| acc + gf(*block) * *power);
        let inputs: Vec<Gf2_128> = span_idx.iter().map(|&j| powers[j]).collect();
        let shares = self.convert_to_additive(ctx, &inputs).await?;
        let joint = shares.into_iter().fold(Gf2_128::zero(), |acc, s| acc + s);
        Ok(un_gf(e_j0 + local + joint))
    }
}

impl Default for Proving {
    fn default() -> Self {
        Self::new()
    }
}

impl<V, C> Party<V, C>
where
    V: Vm<mpz_vm_core::memory::binary::Binary>,
    C: MultiplicativeToAdditive<Gf2_128> + Flush,
    <C as MultiplicativeToAdditive<Gf2_128>>::Error: std::fmt::Display,
    <C as Flush>::Error: std::fmt::Display,
{
    /// Runs the keystream circuit for `blocks` counter blocks and returns the
    /// keystream. `key` is `Some` on the prover only. On the verifier the
    /// outputs are correct for whatever key the prover committed to, or the
    /// proof fails and this errors.
    async fn keystream(
        &mut self,
        ctx: &mut Context,
        blocks: usize,
        key: Option<[u8; 16]>,
        nonce: &[u8; 12],
    ) -> Result<Vec<[u8; 16]>> {
        let vm = &mut self.vm;
        let ks = alloc_keystream(vm, blocks, key.is_some())?;
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
        // The verifier's check of the proof happens in this flush; a prover
        // that cheated is caught before the keystream is used.
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
    async fn convert_to_additive(&mut self, ctx: &mut Context, inputs: &[Gf2_128]) -> Result<Vec<Gf2_128>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let converter = &mut self.converter;
        MultiplicativeToAdditive::<Gf2_128>::alloc(converter, inputs.len())
            .map_err(|e| anyhow::anyhow!("share conversion: {e}"))?;
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
}

/// The keystream circuit: one key schedule, then one AES block per counter.
struct Keystream {
    key: Array<U8, 16>,
    counters: Vec<Array<U8, 16>>,
    outputs: Vec<DecodeFutureTyped<BitVec, [u8; 16]>>,
}

/// Declares the circuit.
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

// ---------------------------------------------------------------------------
// The borrower's TLS client

/// The borrower's TLS client configuration: TLS 1.2 with AES-128-GCM only,
/// since that is the record format the pool's spliced record uses.
pub fn tls_config(roots: &rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>> {
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
pub struct Handshaken {
    pub keys: TrafficKeys,
    /// Next client sequence number: the first token record's.
    pub write_seq: u64,
    /// Next server sequence number.
    pub read_seq: u64,
}

/// Takes the keys out of a finished rustls connection.
pub fn extract_keys(conn: rustls::ClientConnection) -> Result<Handshaken> {
    let secrets = conn
        .dangerous_extract_secrets()
        .context("taking the traffic keys out of the TLS client")?;
    let (write_seq, tx) = secrets.tx;
    let (read_seq, rx) = secrets.rx;
    let (client_write_key, client_write_iv) = gcm_parts(tx)?;
    let (server_write_key, server_write_iv) = gcm_parts(rx)?;
    Ok(Handshaken {
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
        let record = Verifying::finish_record(&nonce, &ciphertext, pool_joint, share);

        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
        let mut reference = plaintext.clone();
        let expected = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut reference)
            .unwrap();
        assert_eq!(reference, ciphertext);
        assert_eq!(record.len(), 5 + 8 + 226 + 16);
        assert_eq!(record[record.len() - 16..], expected[..]);
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
