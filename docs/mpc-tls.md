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
2. **The pool's record.** The borrower sends the pool the whole request head as a
   template: the request line, `Host`, `Content-Length`, its other headers, and last
   an `Authorization: Bearer` line whose value is a placeholder span, then the blank
   line. The pool checks the template (see "Policy" below) and asks for the one record
   that carries the token. It needs two things it cannot compute alone:
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
3. **The body.** The borrower continues with its own records (sequence number +1):
   exactly `Content-Length` bytes of body, nothing else. The pool relays bytes it
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
- **The whole head is the pool's.** Everything the server can parse as framing is
  written by the pool and checked: the record runs through the blank line, and after it
  the borrower sends exactly `Content-Length` bytes of body. A body cannot carry a
  `Transfer-Encoding` or a second request in front of the next token record, whatever
  the server's parser prefers. (An earlier version let the borrower send its own
  headers after the pool's record and only counted their declared length; a borrower
  could have transmitted different ones, see finding 31.)
- **The template** (`check_template`): the span is exactly the value of an
  `Authorization: Bearer` header, the last header line; `Host` is the server the pool
  connects to; exactly one `Content-Length`, decimal digits only, at most 64 MB; no
  `Transfer-Encoding`; no header twice; the head at most 1 KB (`MAX_HEADER_LEN`; the
  proxy drops Claude Code's telemetry headers to keep it around 450 bytes); the span is
  block aligned and its length is the token length rounded up to 16 bytes. With the **108-byte credential invariant** (`TOKEN_LEN`: subscription
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

### Sessions: many requests, many connections, one setup

A borrower keeps one **session** with the pool for as long as it has requests (in
lembas, for the life of the agent): one link, one prover and verifier with their OT
setup, many TLS connections to Anthropic opened on demand and reused with HTTP
keep-alive, and one spliced token record per request. Five Claude Code sessions on one
Mac share the one helper; it opens a connection per request in flight (at most 16) and
proves the records one at a time. Frames carry a connection id; the pool keeps per
connection the state it needs to enforce, before every token record, that the record
begins a fresh HTTP request:

- before the first splice on a connection only handshake records pass, and the first
  splice takes sequence number 1 (a TLS 1.2 client sends one encrypted record, its
  `Finished`, before application data);
- after a splice the borrower may send exactly `Content-Length` bytes of body, measured
  from the relayed records' plaintext lengths: fewer would make the next token record
  part of this body, more would make it the body of a pipelined request;
- the next splice must announce the sequence number the pool expects from the records
  it counted (alerts included: they take sequence numbers too), and no borrower record
  may reuse a token record's explicit nonce.

A request's frame, proof and tag share go out under one lock on the borrower, and the
pool runs its proofs on one task in arrival order, so the two transcripts on the `mpc`
channel line up whatever the concurrency. The lender lookup rides inside that queued
job, so a slow one delays proofs, which are sequential anyway, and not the relay. The
pool answers each request with `Accepted` (a lender was found; the proof starts) or
`Refused` (nobody lends right now; the connection stays usable), and with `Aborted` if
the connection went away before the record could be written, in which case nothing
reached the server and the borrower moves the request to a fresh connection. A proof
that fails to verify ends the session; a socket that fails ends only that connection.
Since the record is the whole head, the server may start answering before the body
(a rejection, an early response); those bytes are kept for the response phase. Writes
to each server connection are queued per connection with a byte cap, so one slow
server cannot stall the others. Every 256 requests the borrower renews the setup, a
safety net for the slow growth of the VMs' memory.

The pool side takes a token per request from its parent over a control descriptor
(`--control-fd 3`, JSON lines), so lenders are chosen per request and can change
within a session; the pool allows a member two sessions at once. The borrower side is
a local HTTP/1.1 proxy (`lembas-mpc proxy`): the agent sends each request as plain
HTTP to a local port and reads the response as the server sent it, one connection per
request, plus one header, `x-lembas-request`, the pool's number for the request, which
the agent quotes when it reports the outcome.

## What each side can do

| | Can | Can't |
|---|---|---|
| Pool / operator | use stored tokens; refuse or delay service; cut a stream short | read or alter borrowed requests or responses |
| Borrower | use the lender's account for the request being made | learn the token |
| Lender | nothing to do; the Mac can be asleep | |

## What's been built (2026-10-25/26)

The crate `lembas-mpc` (`mpc-tls/lembas-mpc/`): `splice.rs` has the primitives
(keystream proof, tag, TLS client), `session.rs` the protocol (frames, the pool's
per-connection gate, the borrower's connection pool), `local.rs` the borrower's local
HTTP proxy and response framing, `record.rs` the local TLS 1.2 AES-GCM record layer the
borrower runs after the handshake, `lib.rs` the template policy and the link plumbing. The TLS
client is rustls 0.23 restricted to TLS 1.2 and the two ECDHE AES-128-GCM suites, with
secret extraction on and resumption off. From tlsn the crate uses only `tlsn-mux` (the
multiplexed link) and the test server fixture; from mpz, the QuickSilver prover and
verifier, KOS and ferret correlated OT, OLE and share conversion, and the AES circuits.

**The tlsn fork is gone, and so is the patch.** The crate is a standalone Cargo project
(`mpc-tls/lembas-mpc`, with its own `Cargo.lock` and `rust-toolchain.toml`) on pinned
git dependencies: TLSNotary's multiplexer and test server, mpz. `build.sh` builds it
directly for both architectures. The earlier patches (the fork's `mpc-tls` changes for
the hidden-record protocol, then the workspace-only patch) are in this repository's
history under `mpc-tls/`, with their measurements below.

The link carries three mux channels, opened in the same order on both sides: `mpc` for
the two-party computation, `up` for everything the borrower sends, `down` for
everything the pool sends (its `Hello` first). Up: `Open`, `Bytes`, `Request { header,
seq, nonce }`, `TagShare`, `Close`, `Renew`, `Done`; down: `Opened`, `OpenFailed`,
`Bytes`, `Accepted { req }`, `Spliced { req }`, `Refused`, `Aborted`, `ServerClosed`;
all but `Renew`/`Done` carry a connection id. `Hello` starts with `PROTOCOL_VERSION`,
now 6; an old peer gets a clean refusal.

The demo (`demo`) runs the pool, the borrower and tlsn's echo server in one process
over in-memory pipes: one session, `--requests` requests `--concurrency` at a time
(every third asks the server to close, so the next must open a new connection), each
body echoed back; `--refuse-first N` makes the pool refuse the first N requests and
checks the session goes on; the token never appears on the pool↔borrower link.
`--evil-rewrite` (the pool changes a header byte outside the span) ends with the
server's `bad_record_mac` alert reaching the borrower; `--evil-server` (the pool
announces the name the borrower expects but connects it to the test server) fails in
the borrower's certificate check. The pool's per-connection gate has a unit test of
its own (`session::tests`).

**Measured** on one Mac, both parties local, 32 KB body, 210-byte token record:

| | spliced record, ZK + ferret (now) | spliced record, DEAP (first version) | legacy, default PRF | legacy, low-bandwidth PRF |
|---|---|---|---|---|
| preprocessing (overlapped with the handshake) | 68 ms | 24 ms | 78 ms | — |
| handshake | 71 ms | 30 ms | 57 ms | — |
| token record (+ hand-off for legacy) | 18 ms | 53 ms | 6 ms | — |
| total | **89 ms** | 84 ms | 142 ms | 66 ms |
| bytes borrower → pool | **504 KB** (32 KB of it body) | 3.6 MB | 33.8 MB | 19.6 MB |
| bytes pool → borrower | **525 KB** | 56 KB | 303 KB | 302 KB |

Ferret trades a fixed setup for a per-gate cost near zero; with plain KOS the borrower
pays 16 bytes per AND gate (the 1.2 MB figure). The table is for one request per
session, the shape before sessions.

**Sessions, measured** (demo, 1 KB bodies, 4 at a time):

| | per session | per request |
|---|---|---|
| setup (two ferret instances: proof and share conversion) | ~0.9 MB each way, 105 ms | — |
| proof and tag | — | 20 ms of proving, serialized; ~13 KB borrower → pool |
| ferret extension for the proof (one per ~13 requests) | — | ~80–120 KB pool → borrower, amortized |
| setup renewal every 32 requests | — | ~30 KB each way, amortized |
| new TLS connection (when none is idle) | — | 2 round trips, no MPC |

Sixty requests in 2 s locally, 22 connections opened and 38 reused. Through lembas's
pool and agent against `api.anthropic.com`: eight requests over one session, four of
them at once and two streaming, all 200, each metered to the lender, later ones on
reused connections.

**Memory**, measured with the demo's `--bench` (only the two-party part, both sides in
one process) and then on the two helpers as separate processes over 100 requests:

| ferret batch for the proof | resident, both sides, plateau | download per request |
|---|---|---|
| small (mpz default, 256k) | 160 MB | ~160 KB |
| medium (512k, the default now) | 180–195 MB | ~80 KB |
| large (1M) | 280 MB | ~90 KB |

Those are with mimalloc as the allocator; with the system allocator the large batch sat
at 405 MB. Memory does not grow with requests beyond the plateau, reached after a dozen
or so: each proof allocates and frees tens of MB of temporaries (the ZK gate vectors,
ferret's expansions) and the plateau is the allocator's high-water mark. The VMs' own
memory grows only by the keys of the values allocated per request (about 80 KB), which
the setup renewal every 256 requests bounds. As separate processes the two helpers sit
at about 165 MB each after 100 requests. The share conversion keeps mpz's small
parameters; it needs under a thousand correlations per request.

## In lembas (2026-10-25)

**The only way to borrow** since 1.3.4. The readable relay (the pool making the
request itself with a lender's token) is gone from both ends: the agent has no code
path for it and the pool answers model calls with 410. A pool without the helper can't
lend; any failure of the private path pauses borrowing, and Claude Code gets
Anthropic's own limit error. There is no switch and no escape hatch.
Since sessions, the agent keeps one helper and one WebSocket per pool for as long as it
runs (started on the first borrowed request, replaced if it dies), and the pool keeps
one helper per borrowing member.

- **Transport.** The agent opens a WebSocket to the pool's `GET /pool/borrow` with its
  pool token (the same HTTPS address as everything else, so Tailscale Funnel carries
  it). Text frames are control: the pool's first frame names the donor (or an error:
  `unsupported`, `no_capacity`, `helper`), the agent's last frame reports the outcome.
  Binary frames are the tlsn-mux byte stream. `src/ws.ts` is a hand-written RFC 6455
  server, since the pool has no npm dependencies and Node ships only the client.
- **Helpers.** The pool spawns `pool --stdio --control-fd 3` per member session,
  pipes the WebSocket to its stdin/stdout, and answers its `need_token` lines on fd 3
  with a lender's freshly refreshed token and a request number (or `refuse`). The agent
  spawns `proxy --stdio --socket <dir>/sock` once (a Unix socket in a 0700 directory:
  a loopback port would be open to every process of every user on the Mac, and the
  session spends a lender's quota), bridges its stdin/stdout to the WebSocket, and
  sends each Claude Code request to the socket as plain HTTP (Claude Code's headers minus the per-hop ones, the two beta flags, a
  Claude Code user agent); the helper puts the request line, `Host`, `Content-Length`
  and the Authorization line in the pool's record and sends the rest itself. The
  response comes back as the server sent it, one connection per request, and the agent
  streams it to Claude Code (chunked transfer decoded, usage metered locally).
- **Metering and limits move to the borrower.** The pool can't see the response, so
  the agent reports per request, with the request number from `x-lembas-request`:
  `{type: result, req, status, model, usd}` (metered with the same table the agent uses
  for direct requests), `{type: limit, req, forMs}` on a usage-limit 429 (the pool
  parks that lender; the agent retries, and the pool picks another), `{type: dead,
  req}` on a 401. Usage is taken as reported (bounded to $10 a request), so a
  dishonest borrower could under-report cost; among friends this is accepted and
  stated in the README. Limits and deaths are not taken on trust: the pool holds the
  lender's login, so it reads the lender's usage from Anthropic (at most 15 s old) and
  parks them only if a window is within 5 points of the threshold or locked, or the
  usage endpoint answers 401. An unconfirmed report only makes this session skip that
  lender for 3 minutes.
- **Who may borrow.** Before any lender is picked, the pool reads the borrower's own
  usage with the borrower's login: they borrow only if a window (5-hour, 7-day, or a
  model-specific one) is at `borrowAtPercent` (default 90) or locked. A member who has
  not connected a subscription, or whose usage can't be read, is refused
  (`unconnected`, `usage_unknown`, `not_at_limit` reach the agent as the helper's
  503). So nobody can borrow without having a subscription to lend in return, and
  nobody can borrow before they are actually out. Lending stays as it was: the lender's
  own live utilization against their policy.
- **Membership is live.** Every lease re-checks that the caller is still a member with
  the same pool token; removal closes their open sessions at once; a session is closed
  after 24 h regardless (the agent opens a new one on the next request).
- **Lifetimes.** Setup, connect and splice steps 90 s each; a response may pause for
  10 min between bytes (`RESPONSE_IDLE_TIMEOUT`, matching the agent's request
  timeout); a session with no frame for 2 h ends; mux close handshake 5 s. The pool
  ends the helper's stdin when the socket closes and kills it after 5 s, SIGKILL after
  10.
- **Build.** `./build.sh` clones tlsn at eb19c82 into `build/tlsn`, applies the patch,
  copies in `mpc-tls/lembas-mpc`, builds for arm64 and x86_64 and puts the universal
  helper in the app bundle and in `build/lembas-mpc` for the pool. The release
  workflow caches the Rust build.
- **Verified end to end** (2026-10-26, sessions) with a scratch pool on 8790 (copy of
  the live config and state, never the live pool) and the freshly built agent on 8791
  with `LEMBAS_AGENT_FORCE_POOL=1`: eight Claude Code-style requests as katya over one
  session, four at once, two streaming, all 200 through alessandro's token, each
  metered by the pool as "privately" with its request number. Refusals (`no_capacity`,
  which also happens when the pool's usage fetch for a lender fails transiently and
  the null is cached for 60 s) come back to Claude Code as the agent's usual error, and
  the session goes on.

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
- **Bounds.** Each setup, connect and splice step has a 90 s deadline; at most 64 KB of
  handshake per connection before its first splice; frames of at most 256 KB; at most
  16 connections per session; a request's bytes are exactly its announced length
  (trailer at most 8 KB, `Content-Length` at most 64 MB); a session ends after 2 h
  without a frame; per-connection queues give backpressure to a slow server.

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
23. **mpz's KOS extends once; ferret extends forever.** A session needs correlations
   per request, so the share conversion could not stay on KOS; it has a ferret
   instance of its own. Sharing the proof's instance was tried and deadlocks: a
   shared handle's `flush` is a barrier every live handle must reach, and the converter
   skips its flush when nothing is queued. Two setups per session cost less than
   untangling that.
24. **Ferret's batch size is the per-request cost.** With mpz's default parameters
   (256k correlations per extension) every third request paid a ~200 KB extension;
   choosing a million per extension (16 MB of memory a side) makes it one per dozen.
   The first extension must use the small parameters, since it runs on the bootstrap
   correlations; a selector that ignores that panics inside ferret.
25. **Proofs must be ordered like requests.** With concurrent requests, the borrower's
   proof order and the pool's splice order can differ unless the request frame, the
   proof and the tag share go out under one lock on the borrower and the pool proves
   on one task in arrival order. The first version raced; a renewal landing between a
   request and its proof made it visible.
26. **Say yes before proving.** The borrower must not start its proof until the pool
   has a lender: a refusal left the borrower proving alone for 90 s. Hence `Accepted`.
27. **One request per local connection.** The agent reads a response to the end of the
   stream; a keep-alive proxy left it waiting forever and leaked a reader thread per
   request. The proxy now closes after each response.
28. **Never guess a descriptor.** Detecting the control channel by trying fd 3 worked
   under Node (which opens it before exec) and closed tokio's own kqueue under
   anything else. The parent names it (`--control-fd`).
29. **The memory is the allocator's high-water mark, not a leak.** Resident memory
   grows for a dozen proofs and then plateaus, the same with one worker thread or
   twelve, and the renewal that was meant to bound it only re-allocated the ferret
   state. mimalloc as the global allocator took a third off; the ferret batch size moves
   the plateau and the per-request download in opposite directions, and 512k is the
   best of both.
30. **A standalone crate was one manifest away.** Everything the helper needs from
   TLSNotary is published in its git repositories (the multiplexer in `tlsn-utils`, the
   test server in `tlsn`), and cargo resolves a workspace member from a git dependency
   by name. No fork, no patch, a 45 s incremental build.
31. **A declared trailer is not a transmitted one.** (From the second external review
   of the sessions.) The first session design let the borrower send its remaining
   headers itself and had the pool check a *declared* copy and count bytes. The pool
   cannot read what is actually sent, so a borrower could transmit `Transfer-Encoding:
   chunked` and a pipelined request head inside the byte budget and make the next token
   record the body of its own request, if the server framed by the chunking. The gate's
   guarantee held only for honest borrowers. Now the record is the whole head and the
   borrower sends only body bytes; the guarantee no longer depends on the server's
   parser. Cost: about twice the proof with Claude Code's essential headers (the proxy
   drops its telemetry ones).
32. **`parse::<usize>()` accepts `+5`.** Two HTTP parsers disagreeing on a length is
   how smuggling starts; `Content-Length` is digits only, everywhere it is read.
33. **A socket failure is not cheating.** The first version ended the session on any
   error in the splice job, including the server or the borrower closing the connection
   mid-splice. Only a proof that fails to verify is fatal now; the rest ends one
   connection, and `Aborted` tells the borrower the record was never written, which is
   what makes its retry safe.
34. **Nothing waits in the frame loop.** The lender lookup (a round trip to the parent,
   possibly with a live usage fetch) and a full write queue to one slow server both
   used to stall every connection's bytes. The lookup moved into the proof job; writes
   are queued per connection with a cap.
35. **The server may answer the head.** With the blank line in the pool's record, a
   server can respond (a 4xx, or an echo server's status line) before the body is sent.
   The borrower keeps such records for the response phase instead of treating them as
   an error, which the first whole-head build did.
36. **The proof worker must not wait forever.** (Third review of the sessions.) The pool
   proves on one task in request order; if the borrower gave up a request (its 90 s
   wait for `Accepted` ran out) the pool's half of the proof had nobody to talk to and
   every later request queued behind it, while the session never errored. The lender
   lookup is bounded at 45 s (under the borrower's wait) and refuses; the proof is
   bounded at 90 s and ends the session, which the agent replaces. The control channel
   already gave up after 30 s, so the lease could not wedge in lembas, only the proof.

37. **A task group is not a deadline.** (Third external review of lembas.) The agent's
   `withTimeout` raced the operation against a sleep in a task group, and a group
   returns only when every child has: the sleep could throw, but the caller still
   waited for the operation to notice its cancellation. `URLSessionWebSocketTask.receive`
   never does, so a pool that accepted the session and said nothing held the agent (and
   the one session every borrow waits on) forever. The helper is now a plain race, two
   tasks and a continuation, resolved at the deadline whatever the operation is doing,
   with an `onTimeout` that closes the socket or cancels the WebSocket so the orphan
   ends too. The response-head path was in fact fine (the stream reader honours
   cancellation), but it gets the same treatment: the socket is shut at the deadline.

38. **The build job had credentials.** The job that runs the tag's `build.sh` held an
   OIDC token and `attestations: write`, and the checkout left the job token on disk,
   so a malicious tag could attest an arbitrary artifact as this workflow's. The key was
   never at risk (it lives in the approved job), but provenance was only as good as the
   tag. The build job now runs with `persist-credentials: false` and nothing but
   `contents: read`; the approved job attests what it downloaded, then signs.

39. **Status fanned out to Anthropic.** Every `GET /pool` probed every member's usage
   with no coalescing, so a burst of reads missed the cache together and became a
   burst at an endpoint that rate-limits hard; one 429 cached as "unknown" for a minute
   and nobody borrowed. Probes are single-flight per member, a probe whose login
   changed meanwhile is discarded rather than cached against the new one, and reads
   are limited per member (the app reads every 30 s). Verified with a counting fake
   upstream: 25 concurrent reads, 2 probes.

40. **A limiter that remembers the flood is part of it.** The write limiter appended
   every attempt, denied ones included, and filtered the array each time; and the body
   was read before the check. Fixed one-minute windows, one small record per key,
   checked before the body; the same for the public pages per visitor (cached in
   memory) and 1000 requests per kept-alive socket.

41. **Small residues.** A fresh login is unparked; the token fallback re-reads the
   current login instead of the one captured before the refresh; a dead session is
   shut down before it is replaced; presence comes from a kept mark, not a log scan,
   and the logs are capped per owner so one member's flood evicts only their own
   history; the request line is checked for control bytes on both sides of the helper
   and before it enters the pool's record.

42. **A full pass over lembas itself** (2026-10-26, every file). The agent's HTTP
   parser took a chunk size through `Int(_, radix:)`, which also reads a sign, so a
   local client sending `-5` as a chunk size crashed the agent on a negative range
   (reproduced on 1.3.6; the response decoder for borrowed answers had the same hole).
   A request with no token at all counted as a failed guess, so a browser on the invite
   page, asking for `/favicon.ico` each time, locked its own guest out after ten loads;
   only a wrong token counts now. The app's updater deleted the old bundle before moving
   the new one in, so a failed move left no lembas; it moves the old one aside and puts
   it back on failure. The pool flushes the ledger on SIGTERM (a `kickstart -k` inside
   the save debounce lost the last writes), prunes months of totals, forgets a removed
   member's last-use mark, resolves the helper's path through `fileURLToPath`, and gives
   every socket it takes over on an upgrade an error listener before writing to it. The
   agent refuses a path a URL can't carry instead of force-unwrapping it. The two
   terminal scripts that edit `config.json` restart the pool, which otherwise wrote its
   in-memory copy back over the edit.

43. **A FIN is not a close frame.** (Fourth external review.) Node's HTTP server keeps
   sockets half-open, so a borrower that sent a TCP FIN without a WebSocket close frame
   produced only `end`, and the pool cleaned up on `close`: the session stayed counted
   and its helper (165 MB once set up) ran on until its two-hour idle timer, two slots
   per member. Reproduced on a scratch pool; `end` now ends the connection like `close`.
   Also from that review: a lender's parking time came from the borrower's report (up to
   six hours) and now comes from Anthropic's own reset time for the window at the limit,
   with the 20-minute default when there is none; a refused upgrade and a 401, 413 or 429
   answer close the socket instead of leaving it kept alive; and the last-own-use marks
   are rebuilt from the log only for a state file that predates them, so a mark deleted
   with a removed member doesn't come back for a newcomer of that name. What stays: one
   address behind Funnel can still fill the connection budget, since every Funnel
   connection arrives from loopback and the pool can't tell them apart before the
   headers; Claude Code keeps working through that, only borrowing pauses.

## Open

- **Memory.** About 165 MB per helper at steady state, mostly allocator high-water
  mark from each proof's temporaries. Reusing those buffers across proofs inside mpz
  (or a smaller ferret batch, at twice the download per request) would cut it.
- **Cheaper circuit.** The head is the proof's size; trimming more headers, or the
  4-byte salt as a private input (cosmetic).
- **Try it with a real friend over Tailscale Funnel.** The transport is verified: a
  session from this Mac to the live pool through its public Funnel address came up in
  0.3 s (the refusal that followed was the lending policy, nobody had capacity). What
  remains is a friend on 1.3.4 at their limit and a lender with headroom.
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
