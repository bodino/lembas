# Borrowed requests the pool can't read or tamper with: the spliced token record (research branch)

## Threat model

The pool stores members' subscription tokens, as it does today, so the operator can use
them; that trust is accepted. What this branch adds: when a friend (the **borrower**)
sends a request on someone else's subscription, **the pool can neither read nor alter
the request body or Anthropic's response, nor change the request headers.** In
particular it can't inject tool calls into a response to run code on the borrower's
Mac. The pool does see the request **line and the headers up to the token** (path,
`Host`, `Content-Length`) and the sizes and timing of everything else; it must, to put
the token in. In return, the borrower never learns the token. The lender takes no
part: their Mac can be asleep.

The link between pool and borrower must itself be authenticated (in lembas, the
existing pool WebSocket over TLS): a man in the middle on it can only cause failures,
never read or forge, but the pool needs to know it is lending to a member.

## Protocol

The borrower owns the TLS session; the pool is a relay that inserts exactly one record.

| | Who | Holds |
|---|---|---|
| TLS client | borrower | the whole session: it verifies the certificate and holds both traffic keys from the start |
| Relay and splicer | pool | the TCP connection to `api.anthropic.com`, the token |

1. **Handshake.** The borrower runs an ordinary TLS 1.2 client (rustls, AES-128-GCM
   with ECDHE only) over a byte relay through the pool. It verifies the certificate
   chain for the name it expects and holds the keys alone; the pool sees the handshake
   in the clear, as any network hop does, and learns nothing from it. When the
   handshake is done the borrower takes the traffic keys and both sequence numbers out
   of rustls (`dangerous_extract_secrets`) and runs the record layer itself from then
   on.
2. **The pool's record.** The borrower sends the pool a template: the request line,
   `Host`, `Content-Length` and an `Authorization: Bearer` line whose value is a
   placeholder span. The pool checks the template (see "Policy" below) and asks for the
   one record that carries the token. It needs two things it cannot compute alone:
   - **Keystream** for the record's blocks: AES under the borrower's client key. The
     borrower **proves it in zero knowledge** (mpz's QuickSilver VM over ferret
     correlated OT): one key-schedule circuit and one AES block per 16 bytes of the
     record, with the key as the witness and the counter blocks public. The pool, as
     verifier, receives the outputs and knows they are the AES of *some* key the
     borrower committed to; the borrower knows them anyway since it holds the key.
     Nothing is garbled: the pool has no private input, so a proof is all it needs.
   - **The tag.** The borrower knows `H = AES_K(0)` and `E_K(J0)` and computes the GHASH
     terms for every block it knows: the AAD, the request line, `Host`,
     `Content-Length`, the length block. The token span's blocks (seven of them) go
     through one multiplicative-to-additive share conversion each: the pool inputs its
     ciphertext block, the borrower the matching power of `H`, and each gets an
     additive share of the product. The borrower sends its share of the tag; the pool
     adds its own and has the tag. The borrower sees neither the span's ciphertext nor
     the tag.
   The pool XORs the token into the keystream locally, assembles the record and writes
   it to the server itself. Nothing of it goes back to the borrower.
3. **Everything else.** The borrower continues with its own records (sequence number
   +1): the remaining headers, the blank line, the body. The pool relays bytes it
   cannot read or forge.
4. **Response, streamed.** The pool forwards the server's bytes as they arrive and the
   borrower decrypts record by record. The pool can't inject, change, drop or reorder
   records (the AES-GCM tag needs the server key, and the sequence number is
   authenticated). It can cut the stream short, but `close_notify` and the
   `message_stop` event make that visible. It can also delay or refuse service.

### Policy: what the pool enforces

- **The token record is the first application data on the connection.** Before the
  splice the pool deframes every record from the borrower and refuses any of type
  application data. Otherwise a borrower could send `POST /x … Transfer-Encoding:
  chunked\r\n\r\n` first and make the token record the *body* of its own request, to a
  path that echoes it. Handshake records are in the clear in TLS 1.2, so this check
  costs nothing. (It also means a TLS 1.3 borrower cannot use the splice: its
  `Finished` already looks like application data. The record format of the spliced
  record is TLS 1.2's anyway.)
- **The template** (`check_template`): the span is exactly the value of an
  `Authorization: Bearer` header, which is the last line of the pool's record; `Host`
  is the server the pool connects to; exactly one `Content-Length`, at most 64 MB; no
  header twice; the span is block aligned and its length is the token length rounded up
  to 16 bytes. With the **108-byte credential invariant** (`TOKEN_LEN`: subscription
  tokens and API keys are both 108 bytes) the pool has 4 bytes of slack inside the span,
  too few to smuggle a header; a pool with a credential of any other length refuses to
  lend, and a borrower refuses a pool that announces any other length.
- **Header integrity for the borrower.** The tag covers every block outside the span
  with the borrower's own text, so a pool that changes a byte there produces a record
  the server rejects (`bad_record_mac`); it can't rewrite the path or add a header.
- **Server identity.** The borrower verifies the certificate; the pool chooses the TCP
  destination. The pool verifies nothing itself, and nothing would be gained if it did:
  against an honest borrower, the borrower's check already stops a wrong server; a
  malicious borrower colluding with someone on the pool's uplink can hand over the
  session key in any design where the borrower holds it.

### Why the keystream must be proven

If the borrower simply told the pool the keystream, it could say zeros, and the pool
would XOR the token into it and put the token on its own uplink in the clear, inside a
record the server rejects. The borrower still wouldn't see it; whoever taps the pool's
network would. The proof closes this: the pool only uses a keystream the verifier
accepted. The first version of this protocol used a garbled AES circuit inside DEAP
(tlsn's dual execution) for the same purpose; the garbled circuit turned out to be
redundant, since DEAP exists to protect the follower's private inputs and the pool has
none. Dropping it cut the traffic from 3.6 MB to about 1.2 MB, and ferret on top of KOS
for the proof's correlated OTs cut it again to about 0.5 MB each way.

One connection per borrowed request today. Nothing in the design prevents a second
splice on a kept-alive connection; see "Open".

## What each side can do

| | Can | Can't |
|---|---|---|
| Pool / operator | use stored tokens; refuse or delay service; cut a stream short | read or alter borrowed requests or responses |
| Borrower | use the lender's account for the request being made | learn the token |
| Lender | nothing to do; the Mac can be asleep | |

## What's been built (2026-10-25/26)

The crate `lembas-mpc` (`mpc-tls/lembas-mpc/`): `splice.rs` is the protocol, `record.rs`
the local TLS 1.2 AES-GCM record layer the borrower runs after the handshake (about 150
lines over `aes-gcm`), `lib.rs` the template policy and the link plumbing. The TLS
client is rustls 0.23 restricted to TLS 1.2 and the two ECDHE AES-128-GCM suites, with
secret extraction on and resumption off. From tlsn the crate uses only `tlsn-mux` (the
multiplexed link) and the test server fixture; from mpz, the QuickSilver prover and
verifier, KOS and ferret correlated OT, OLE and share conversion, and the AES circuits.

**The tlsn fork is gone.** The patch (`mpc-tls/tlsn-eb19c82-lembas-splice.patch`) now
only adds the crate to tlsn's workspace, with the `Cargo.lock` entries that follow; the
earlier patch with the `mpc-tls` changes (hidden header record, server verification by
the follower, key hand-off, relay) is kept as `mpc-tls/legacy/` for the record, with its
measurements below. The crate could become a standalone one depending on tlsn's
published components.

The link carries three mux channels, opened in the same order on both sides: `mpc` for
the two-party computation, `up` for everything the borrower sends (its header, then
frames), `down` for everything the pool sends (its `Hello`, then frames). Frames are
`Bytes` (TLS bytes either way), `Splice { seq, nonce }`, `TagShare`, `Spliced`,
`ServerClosed`, `Done`. `Hello` starts with `PROTOCOL_VERSION`, now 4; an old peer gets
a clean refusal.

The demo (`demo`) runs the pool, the borrower and tlsn's hyper echo server in one
process over in-memory pipes and checks: the body is echoed; the token never appears on
the pool↔borrower link, nor does any 16-byte window of the token record's ciphertext;
and the token record is byte-for-byte what the borrower's keys produce from its
template with the token in place, at the sequence number the borrower announced.
`--evil-rewrite` (the pool changes a header byte outside the span) ends with the
server's `bad_record_mac` alert reaching the borrower; `--evil-server` (the borrower
expects `api.anthropic.com`, the pool connects it to the test server) fails in the
borrower's certificate check.

**Measured** on one Mac, both parties local, 32 KB body, 210-byte token record:

| | spliced record, ZK + ferret (now) | spliced record, DEAP (first version) | legacy, default PRF | legacy, low-bandwidth PRF |
|---|---|---|---|---|
| preprocessing (overlapped with the handshake) | 68 ms | 24 ms | 78 ms | — |
| handshake | 71 ms | 30 ms | 57 ms | — |
| token record (+ hand-off for legacy) | 18 ms | 53 ms | 6 ms | — |
| total | **89 ms** | 84 ms | 142 ms | 66 ms |
| bytes borrower → pool | **504 KB** (32 KB of it body) | 3.6 MB | 33.8 MB | 19.6 MB |
| bytes pool → borrower | **525 KB** | 56 KB | 303 KB | 302 KB |

Ferret trades a fixed setup (the ~0.5 MB each way, mostly its base correlations and
LPN expansion) for a per-gate cost near zero, which is why the pool's side went up and
the borrower's came down; with plain KOS the borrower pays 16 bytes per AND gate (the
1.2 MB figure). A 16 MB body adds its own size and about 0.1 s (226 ms in total).
Against `api.anthropic.com` with the user's subscription token, in two processes over
TCP: a non-streaming `POST /v1/messages` with the headers lembas uses returned 200 and
the model's answer in 1.3 s, a streaming one in 1.4 s, of which about 65 ms handshake
(preprocessing hidden behind it) and 20 ms for the token record; the rest is the
model.

## In lembas (2026-10-25)

Wired in behind a **Private Borrowing** switch in the app's ⚙ menu, stored as
`privateBorrowing` in `~/.config/lembas.json` and re-read by the agent per request.
The helper's command line and the bridge did not change with the new protocol; the
pool no longer passes `--low-bandwidth`, and `--roots` on the pool side is accepted
but has nothing to verify.

- **Transport.** The agent opens a WebSocket to the pool's `GET /pool/borrow` with its
  pool token (the same HTTPS address as everything else, so Tailscale Funnel carries
  it). Text frames are control: the pool's first frame names the donor (or an error:
  `unsupported`, `no_capacity`, `helper`), the agent's last frame reports the outcome.
  Binary frames are the tlsn-mux byte stream. `src/ws.ts` is a hand-written RFC 6455
  server, since the pool has no npm dependencies and Node ships only the client.
- **Helpers.** One `lembas-mpc` process per borrowed request on each side, both in
  `--stdio` mode: the pool spawns `pool --stdio` with the donor's freshly refreshed
  token in its environment and pipes the socket to its stdin/stdout; the agent spawns
  `borrower --stdio` with the template and body as files in a 0700 temp folder and the
  response coming back through a FIFO, parsed and streamed to Claude Code (chunked
  transfer decoded, usage metered locally).
- **Template.** The agent builds it from Claude Code's request with the relay's header
  policy (hop headers dropped, the two beta flags merged in, a Claude Code user agent,
  `accept-encoding: identity`), `Content-Length: {body_len}` before `Authorization:
  Bearer {token}`. Only the part through the Authorization line is the pool's record
  (`MAX_HEADER_LEN` 320 bytes, about 210 in practice); the other headers follow in the
  borrower's own first record and cost nothing.
- **Metering and limits move to the borrower.** The pool can't see the response, so
  the agent reports `{type: result, status, model, usd}` (metered with the same table
  the agent uses for direct requests), `{type: limit, forMs}` on a usage-limit 429
  (the pool parks the donor and the agent retries the next donor, up to three, naming
  the ones to skip in the `exclude` query), `{type: dead}` on a 401, or
  `{type: failed}`. The pool trusts these; a dishonest borrower could under-report or
  park a friend's token. Among friends this is accepted and stated in the README.
- **Strict.** With the switch on the agent never falls back to the readable relay. If
  the pool has no helper (`privateBorrowing: false` in `GET /pool`) or a private borrow
  fails, Claude Code gets Anthropic's own limit error and the app says borrowing is
  paused.
- **Lifetimes.** Setup 90 s, relay idle 10 min (`RELAY_IDLE_TIMEOUT`, matching the
  agent's request timeout), mux close handshake 5 s (`CLOSE_TIMEOUT`); the pool ends
  the helper's stdin when the socket closes and kills it after 5 s, SIGKILL after 10.
- **Build.** `./build.sh` clones tlsn at eb19c82 into `build/tlsn`, applies the patch,
  copies in `mpc-tls/lembas-mpc`, builds for arm64 and x86_64 and puts the universal
  helper in the app bundle and in `build/lembas-mpc` for the pool. The release
  workflow caches the Rust build.
- **Verified end to end** (2026-10-26) with the zero-knowledge helper: a scratch pool
  on 8790 (copy of the live config and state, never the live pool) and the freshly
  built agent on 8791 with `LEMBAS_AGENT_FORCE_POOL=1`; a Claude Code-style
  `POST /v1/messages` as katya came back 200 through alessandro's token, plain and
  streaming, in 1.1–1.3 s, metered by the pool as "privately". Two earlier attempts
  were refused with `no_capacity` because the pool's usage fetch for the donor had
  failed transiently and the null is cached for 60 s; that is the existing lending
  policy ("if it can't be read, nobody borrows"), not the private path.

## Security, as it stands

- **The key never leaves the borrower.** It is the witness of a zero-knowledge proof,
  private against a malicious verifier. The roles are fixed in code, borrower =
  prover; no message from the peer assigns a role (the rule from finding 12).
- **The token** reaches the borrower only through the span's ciphertext or the tag,
  and it sees neither. The span's ciphertext enters only the share conversion, as the
  pool's (OLE sender's) input, which stays private against a malicious receiver. The
  tag is masked by `E_K(J0)` and never sent to the borrower.
- **The keystream is honest** or the pool aborts before using it (the proof's
  soundness). A borrower that cheats learns nothing it did not already know.
- **Header integrity** outside the span rests on the tag, as before: the server, not
  the borrower, rejects a tampered record, and a pool that tries it produces
  `bad_record_mac` failures on the lender's account, visible to the lender.
- **The nonce** the borrower announces for the token record (client write IV and
  sequence number) reveals the 4-byte GCM salt to the pool. GCM does not rely on nonce
  secrecy; it is harmless, and could be made a private circuit input if wanted.
- **What is still only semi-honest:** mpz's share conversion (OLE from KOS), used for
  the seven span blocks of the tag. Its correctness against a cheating party is "wrong
  tag, so abort". Its privacy is what a review should examine, along one path: a
  borrower mauling the conversion to learn the pool's ciphertext blocks, which,
  holding the key, it could then decrypt. The handshake is not in MPC and there is no
  garbled circuit, so the earlier concerns about key-exchange conversions and
  garbling orientation are gone.
- **Bounds.** Setup (prelude, preprocessing, handshake, splice) has a 90 s deadline on
  both sides; at most 64 KB of handshake from the borrower before the splice; frames
  of at most 256 KB; the relay gives up after 10 minutes without a frame from either
  side and after an hour in total; the pool holds at most 4 MB of the borrower's bytes
  for a slow server and relays at most 68 MB per borrow; `Content-Length` at most 64 MB.

## Findings

Findings 1 to 15 are from the earlier design and explain why it looked the way it did;
they are kept because several of them still apply (8, 9, 12, 13, 14, 15).

1. **The follower sees every ciphertext in tlsn's record layer.** Encryption in MPC
   decodes the ciphertext to both parties, because both compute their GHASH share
   from it. Once the borrower holds the client key it could decrypt the header record
   and read the token. Hence the hidden record, and now the pool writing its record
   itself.
2. **Why a cheap fix fails.** Giving the follower a masked ciphertext and correcting the
   tag by `sum M_i * H^k` hands the leader a polynomial in H of small degree, from
   which H can be found by root-finding. Knowing H lets the pool forge tags on
   modified body ciphertexts. The share conversion avoids this: the pool learns only
   the tag, masked by `E_K(J0)`.
3. **DEAP doesn't fit the old design** because its finalization reveals the
   follower's private inputs, which were the borrower's key pads. In the new design it
   fit but was redundant (finding 21).
4. **Who garbles matters.** The garbler's inputs are private even against a malicious
   evaluator; the evaluator's only against a semi-honest garbler. The key holder must
   garble. Moot now that nothing is garbled; the analogue is that the key holder must
   be the prover.
5. **Late private inputs stall mpz.** Allocate and mark everything before
   preprocessing, assign later. Still the pattern.
6. **A single-channel context can't run concurrent protocol branches.** Use the mux
   with multi-threaded sessions and one channel per direction.
7. The fork kept tlsn's `run()` and transcript path working while it existed.
8. **The token must only ever be a bearer value.** Still enforced by `check_template`.
9. **The credential length is a security parameter.** Still enforced.
10. **A circuit that handles the token is a liability.** The token is still outside
   every circuit: keystream in, token XORed in locally.
11. **The circuit builder can't output constants.** No longer relevant.
12. **No adversary-controlled message assigns a security role.** The prover role is
   hard-coded.
13. **A link on stdin/stdout needs raw descriptors.** Still how the helpers run.
14. **The bridge must survive the other side leaving first.** Still how the agent runs.
15. **The edges:** resource limits and template policy. Carried over, plus the
   handshake and frame bounds above.
16. **A shared correlated-OT handle's `flush` is a barrier.** mpz's `SharedRCOTSender`
   and `Receiver` let several consumers draw on one KOS instance, but `flush` waits
   for every handle that has allocations to flush too. The share conversion allocated
   its OLEs on a handle shared with the proof's VM, whose handle flushes at another
   time, so the conversion's preprocessing flush waited forever (the first run of the
   new protocol stalled exactly there, after the TLS handshake had completed). The
   conversion now has a KOS instance of its own; one more base OT, about a
   millisecond.
17. **rustls gives away exactly what the splice needs.** `dangerous_extract_secrets`
   returns the two AES-GCM keys with their IVs and the next sequence number in each
   direction (1 and 1 after a TLS 1.2 handshake: one `Finished` each way). The token
   record takes client sequence number 1 and the borrower continues at 2; the server
   accepted this on the first try, and the demo's reference encryption agrees.
18. **The first application-data record must be the pool's.** Without the check, the
   token record could become the body of a borrower-written request to an echoing
   path. The pool reads TLS record headers in the clear before the splice, which is
   enough. A side effect: TLS 1.3 is excluded, which is fine since the spliced record
   is a TLS 1.2 record anyway.
19. **The pool has nothing to verify about the server**, and that is not a loss: see
   "Server identity" under Policy.
20. **The handshake relay and the preprocessing overlap** on the pool with a `select!`
   over a pinned preprocessing future and the relay arms, so the ClientHello is not
   held back by the proof's setup; the borrower uses `try_join!`. If `Splice` arrives
   first, the pool finishes preprocessing before answering.
21. **The garbled circuit was redundant.** The pool needs an authentic keystream, not
   a joint computation: a zero-knowledge proof of `y = AES_K(ctr)` gives the verifier
   `y` with soundness and keeps `K` private, which is the whole requirement. DEAP's
   garbled half protected follower inputs that do not exist here. Removing it also
   removed the "malicious garbler" analysis and 2.4 MB per request.
22. **The OT direction decides who uploads.** In KOS the receiver sends 16 bytes per
   correlation, and the prover is the receiver, so with KOS alone the borrower uploaded
   1.2 MB. ferret (LPN-based extension, which tlsn also uses for its proofs) makes the
   per-correlation cost negligible at the price of a fixed setup, ~0.5 MB each way.
   For lembas, where the borrower is on a home uplink and the pool on a better one,
   this is the right trade; for very small circuits plain KOS would be cheaper.

## Open

- **Keep-alive: one connection per Claude Code session.** Once the borrower holds the
  key and the token record is spliced, a second request on the same connection needs
  only another splice: no handshake. The pool would need to know where the previous
  request ended before allowing the next splice; it knows `Content-Length` (it wrote
  it) and can count the borrower's plaintext bytes from the relayed record lengths.
  Most of the 0.5 MB is ferret's setup, which a kept-alive helper would pay once per
  session rather than per request.
- **Standalone crate.** Nothing in `lembas-mpc` depends on the tlsn workspace except
  `tlsn-mux` and the test fixture; with those as git dependencies the patch goes away
  entirely and `build.sh` no longer needs a tlsn checkout.
- **Cheaper circuit.** Fewer blocks (drop `Content-Length` from the pool's record if the
  byte-count policy moves to counting relayed bytes), or the 4-byte salt as a private
  input (cosmetic).
- **Try it with a real friend over Tailscale Funnel.** Half a megabyte each way is a
  fraction of a second on any home connection, overlapped with the handshake.
- The direct-first flow tries the private path, falls through to a direct request
  that fails again, and tries the private path once more before giving up; the agent
  should remember a failed private borrow for a minute.
- **Cryptographer review**, now of a small surface: QuickSilver as used here (one
  prover input, public counters, outputs revealed to the verifier) and the share
  conversion's privacy against a malicious receiver.

## Earlier checks

- `api.anthropic.com` accepts TLS 1.2 with `ECDHE-ECDSA-AES128-GCM-SHA256` and
  `ECDHE-RSA-AES128-GCM-SHA256` over P-256, which is what the splice needs. It also
  accepts TLS 1.3 KeyUpdate, which this design doesn't need.
- `tlsn` at commit eb19c82 (2026-10-21) needs Rust 1.95 (pinned in its own
  `rust-toolchain.toml`).
- Its `basic` example runs in 0.94 s with both parties on one Mac, using about
  700 MB of memory.
