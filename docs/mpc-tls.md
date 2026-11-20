# The cryptography: the spliced token record and the limit proof

Two protocols carry everything private in lembas, and both run between two friends'
Macs with nobody else involved:

- **The spliced token record** lets a friend (the **borrower**) send a request on your
  subscription through your Mac (the **lender**) so that your Mac can neither read nor
  alter the request or Anthropic's answer, and the borrower never learns your token.
- **The limit proof** lets the borrower show the lender what Anthropic says about the
  borrower's own usage, without the lender holding the borrower's login.

How the Macs find each other, who may ask whom, and how the app drives all this is in
[p2p.md](p2p.md). The code is the Rust crate `mpc-tls/lembas-mpc`. In it the lender's
side of a borrow is still called `pool` (`run_pool`, the `pool` test command): the name
is from an earlier design and means *the side that holds the token*.

## Threat model

Each Mac holds its own subscription token and nobody else's. When a borrower sends a
request on a lender's subscription:

- **The lender can neither read nor alter the request body or Anthropic's response, nor
  change the request headers.** In particular it can't inject tool calls into a response
  to run code on the borrower's Mac. It does see the request **line and the headers up
  to the token** (path, `Host`, `Content-Length`) and the sizes and timing of everything
  else; it must, to put the token in, and it uses the request line to decide what it
  lends its login to.
- **The borrower never learns the token.**
- **The link between the two is authenticated.** It is an [iroh](https://iroh.computer)
  QUIC stream between two Ed25519 keys that are also the circle's member ids, so the
  lender knows which member it is lending to. A relay, when one is used, carries
  encrypted QUIC; a man in the middle on the link can only cause failures.

## The spliced token record

The borrower owns the TLS session; the lender is a relay that inserts exactly one
record per request.

| | Who | Holds |
|---|---|---|
| TLS client | borrower | the whole session: it verifies the certificate and holds both traffic keys from the start |
| Relay and splicer | lender | the TCP connection to `api.anthropic.com`, the token |

1. **Handshake.** The borrower runs an ordinary TLS 1.2 client (rustls, AES-128-GCM
   with ECDHE only) over a byte relay through the lender. It verifies the certificate
   chain for the name it expects and holds the keys alone; the lender sees the handshake
   in the clear, as any network hop does, and learns nothing from it. When the
   handshake is done the borrower takes the traffic keys and both sequence numbers out
   of rustls (`dangerous_extract_secrets`) and runs the record layer itself from then
   on (`record.rs`).
2. **The lender's record.** The borrower sends the lender the whole request head as a
   template: the request line, `Host`, `Content-Length`, its other headers, and last
   an `Authorization: Bearer` line whose value is a placeholder span, then the blank
   line. The lender checks the template (see "Policy" below) and asks for the one record
   that carries the token. It needs two things it cannot compute alone:
   - **Keystream** for the record's blocks: AES under the borrower's client key. The
     borrower **proves it in zero knowledge** (mpz's QuickSilver VM over ferret
     correlated OT): one key-schedule circuit and one AES block per 16 bytes of the
     record, with the key as the witness and the counter blocks public. The lender, as
     verifier, receives the outputs and knows they are the AES of *some* key the
     borrower committed to; the borrower knows them anyway since it holds the key.
     Nothing is garbled: the lender has no private input to the keystream, so a proof
     is all it needs.
   - **The tag.** The borrower knows `H = AES_K(0)` and `E_K(J0)` and computes the GHASH
     terms for every block it knows: the AAD, the request line, `Host`,
     `Content-Length`, the length block. The token span's blocks (seven of them) go
     through one multiplicative-to-additive share conversion each: the lender inputs its
     ciphertext block, the borrower the matching power of `H`, and each gets an
     additive share of the product. The borrower sends its share of the tag; the lender
     adds its own and has the tag. The borrower sees neither the span's ciphertext nor
     the tag.

   The lender XORs the token into the keystream locally, assembles the record and writes
   it to the server itself. Nothing of it goes back to the borrower. The token is never
   inside a circuit.
3. **The body.** The borrower continues with its own records (sequence number +1):
   exactly `Content-Length` bytes of body, nothing else. The lender relays bytes it
   cannot read or forge.
4. **Response, streamed.** The lender forwards the server's bytes as they arrive and the
   borrower decrypts record by record. The lender can't inject, change, drop or reorder
   records (the AES-GCM tag needs the server key, and the sequence number is
   authenticated). It can cut the stream short, but `close_notify` and the
   `message_stop` event make that visible. It can also delay or refuse service.

### Why the keystream must be proven

If the borrower simply told the lender the keystream, it could say zeros, and the
lender would XOR the token into it and put the token on its own uplink in the clear,
inside a record the server rejects. The borrower still wouldn't see it; whoever taps
the lender's network would. The proof closes this: the lender only uses a keystream the
verifier accepted. A zero-knowledge proof of `y = AES_K(ctr)` gives the verifier `y`
with soundness and keeps `K` private, which is the whole requirement.

### Why the tag needs a share conversion

Giving the borrower a masked ciphertext and correcting the tag by `sum M_i * H^k` would
hand the lender a polynomial in `H` of small degree, from which `H` can be found by
root-finding; knowing `H` lets the lender forge tags on modified body ciphertexts. With
the share conversion the lender learns only the finished tag, masked by `E_K(J0)`.

### Policy: what the lender enforces

- **What the login is lent to.** The lender reads the request line, which the borrower
  wrote, and lends only to `POST /v1/messages` and `POST /v1/messages/count_tokens` (any
  query). Everything else the token opens, the owner's profile and usage among them, is
  refused (`model_request` in `peer.rs`).
- **The token record is the first application data on the connection.** Before the
  splice the lender deframes every record from the borrower and refuses any of type
  application data. Otherwise a borrower could send `POST /x … Transfer-Encoding:
  chunked\r\n\r\n` first and make the token record the *body* of its own request, to a
  path that echoes it. Handshake records are in the clear in TLS 1.2, so this check
  costs nothing. (It also means a TLS 1.3 borrower cannot use the splice: its
  `Finished` already looks like application data. The spliced record is a TLS 1.2
  record anyway.)
- **The whole head is the lender's.** Everything the server can parse as framing is
  written by the lender and checked: the record runs through the blank line, and after
  it the borrower sends exactly `Content-Length` bytes of body. A body cannot carry a
  `Transfer-Encoding` or a second request in front of the next token record, whatever
  the server's parser prefers. The lender cannot read what the borrower transmits, so
  it never relies on a declared copy of anything: it writes the head itself and counts
  bytes.
- **The template** (`check_template`): the span is exactly the value of an
  `Authorization: Bearer` header, the last header line; `Host` is the server the lender
  connects to; exactly one `Content-Length`, decimal digits only (a parser that accepts
  `+5` is how smuggling starts), at most 64 MB; no `Transfer-Encoding`; no header
  twice; the head at most 1 KB (`MAX_HEADER_LEN`; the proxy drops Claude Code's
  telemetry headers to keep it around 450 bytes); the span is block aligned and its
  length is the token length rounded up to 16 bytes. With the **108-byte credential
  invariant** (`TOKEN_LEN`: subscription tokens and API keys are both 108 bytes) the
  lender has 4 bytes of slack inside the span, too few to smuggle a header; a lender
  with a credential of any other length refuses to lend, and a borrower refuses a lender
  that announces any other length.
- **Header integrity for the borrower.** The tag covers every block outside the span
  with the borrower's own text, so a lender that changes a byte there produces a record
  the server rejects (`bad_record_mac`); it can't rewrite the path or add a header.
- **Server identity.** The borrower verifies the certificate; the lender chooses the TCP
  destination. The lender verifies nothing itself, and nothing would be gained if it
  did: against an honest borrower, the borrower's check already stops a wrong server; a
  malicious borrower colluding with someone on the lender's uplink can hand over the
  session key in any design where the borrower holds it.

### Sessions: many requests, many connections, one setup

A borrower keeps one **session** with a lender for as long as it has requests: one
link, one prover and verifier with their OT setup, many TLS connections to Anthropic
opened on demand and reused with HTTP keep-alive, and one spliced token record per
request. Five Claude Code sessions on one Mac share the one peer; it opens a connection
per request in flight (at most 16) and proves the records one at a time. Frames carry a
connection id; the lender keeps per connection the state it needs to enforce, before
every token record, that the record begins a fresh HTTP request:

- before the first splice on a connection only handshake records pass, and the first
  splice takes sequence number 1 (a TLS 1.2 client sends one encrypted record, its
  `Finished`, before application data);
- after a splice the borrower may send exactly `Content-Length` bytes of body, measured
  from the relayed records' plaintext lengths: fewer would make the next token record
  part of this body, more would make it the body of a pipelined request;
- the next splice must announce the sequence number the lender expects from the records
  it counted (alerts included: they take sequence numbers too), and no borrower record
  may reuse a token record's explicit nonce.

The link carries three mux channels (`tlsn-mux`), opened in the same order on both
sides: `mpc` for the two-party computation, `up` for everything the borrower sends,
`down` for everything the lender sends (its `Hello` first). Up: `Open`, `Bytes`,
`Request { header, seq, nonce }`, `TagShare`, `Close`, `Renew`, `Done`; down: `Opened`,
`OpenFailed`, `Bytes`, `Accepted { req }`, `Spliced { req }`, `Refused`, `Aborted`,
`ServerClosed`; all but `Renew`/`Done` carry a connection id. `Hello` starts with
`PROTOCOL_VERSION`, now 6; a peer on another version gets a clean refusal.

How a request moves through a session:

- **Proofs are ordered like requests.** A request's frame, proof and tag share go out
  under one lock on the borrower, and the lender runs its proofs on one task in arrival
  order, so the two transcripts on the `mpc` channel line up whatever the concurrency.
- **The lender says yes before anyone proves.** Each request passes the lender's
  lending gate (see [p2p.md](p2p.md)) and is answered `Accepted` (the proof starts) or
  `Refused` (not now; the connection and the session stay usable). The borrower does
  not start a proof the lender would not finish.
- **A socket failure is not cheating.** `Aborted` means the connection went away before
  the record could be written: nothing reached the server, and the borrower moves the
  request to a fresh connection. A proof that fails to verify ends the session; a
  socket that fails ends only that connection.
- **The server may answer the head.** Since the record is the whole head, the server
  can respond before the body is sent (a rejection, an early response); those bytes are
  kept for the response phase.
- **Nothing waits forever.** The gate is bounded at 45 s and refuses; a proof is bounded
  at 90 s and ends the session, which the borrower replaces. Writes to each server
  connection are queued per connection with a byte cap, so one slow server cannot stall
  the others.
- **The setup is renewed** every 256 requests, a safety net for the slow growth of the
  VMs' memory.

The borrower's side is a local HTTP/1.1 proxy on a Unix socket (`local.rs`): the agent
sends each request as plain HTTP and reads the response as the server sent it, one
connection per request, plus two headers of the peer's own, `x-lembas-request` and
`x-lembas-lender`, which the agent uses for metering and strips.

### What each side can do

| | Can | Can't |
|---|---|---|
| Lender | use its own token; refuse or delay service; cut a stream short; see the request line, `Host`, `Content-Length`, sizes and timing | read or alter borrowed requests or responses |
| Borrower | use the lender's account for the model request being made | learn the token; make any other request with it |

## The limit proof

A lender's Mac has no way to look up a borrower's usage: it does not hold the
borrower's login. So the borrower proves what Anthropic says, using the same machinery
as a borrowed request with the roles of the keys reversed.

1. The **prover** (would-be borrower) runs a TLS 1.2 session to `api.anthropic.com`
   through the **verifier**'s (lender's) relay, exactly as a borrow does, and sends one
   request of its own: `GET /api/oauth/usage` with its own bearer token. The verifier
   relays bytes it cannot read, and keeps every TLS record of the connection: the
   prover's request record and the server's response records, as they came off the
   verifier's own TCP connection.
2. Once the response is in, the prover **opens a prefix of each side** under the key
   that wrote it. In the zero-knowledge VM it commits to the key and proves `AES_K` on
   public blocks: the zero block (`H`), the record's `J0`, and the counter blocks of
   the bytes to reveal, all under the one committed key (one key schedule). The
   verifier checks the record's GCM tag with the proven `H` and `E_K(J0)` against the
   ciphertext it took off the wire. Only the key the server actually used makes that
   tag hold (another one would be a 2^128 search, since the prover did not choose the
   ciphertext), so the proven keystream XOR the wire ciphertext is the real plaintext.
3. What the verifier sees: the request line and `Host` (so it knows which endpoint
   answered; the `Authorization` line stays hidden), and the response from its first
   byte through the end of its body (so no part of it can be pointed at out of
   context: the head is parsed, the body de-chunked, the JSON read). It accepts a `200`
   whose windows put the borrower at or past `borrow_at` (90% by default) or locked,
   and keeps the proof until the earliest reset of a window at the limit: at most six
   hours, and one hour when Anthropic gives no reset time.

What the prover cannot do: swap the server's bytes (they never pass through it on the
way to the verifier), open them under another key (the tag check), reveal a window out
of context (the reveal is a prefix), or claim a response to another path (the request
line is opened too and must be the usage endpoint). What it can do: prove with a
different, exhausted account. Binding the proof to an account is listed under open
work; the lender's own limits still cap the damage.

Trust the proof shares with the splice: the verifier's own network path to Anthropic.
The verifier does not check the certificate the prover's TLS client saw (the handshake
is in the clear and it could); as for a borrow, a man in the middle on the lender's
side can only cause failures.

Code: `limit.rs` (`verify`, `prove`, `Transcript`, the `Opening`/`KeyPlan` AES input
layout, `Usage`; `LIMIT_PROTOCOL_VERSION` 1), with `splice::aes_blocks` proving AES on
any public blocks under a committed key. The proof runs on a stream of its own, with
its own setup.

## What's been built

The crate `lembas-mpc` (`mpc-tls/lembas-mpc/`), a standalone Cargo project on pinned
git dependencies:

| File | What |
|---|---|
| `splice.rs` | the primitives: keystream proof, tag, TLS client |
| `session.rs` | the borrowing protocol: frames, the lender's per-connection gate, the borrower's connection pool |
| `limit.rs` | the limit proof |
| `record.rs` | the TLS 1.2 AES-GCM record layer the borrower runs after the handshake |
| `local.rs` | the borrower's local HTTP proxy and response framing |
| `lib.rs` | the template policy and the link plumbing |
| `circle.rs`, `peer.rs` | the circle and the peer ([p2p.md](p2p.md)) |

The TLS client is rustls 0.23 restricted to TLS 1.2 and the two ECDHE AES-128-GCM
suites, with secret extraction on and resumption off. From TLSNotary the crate uses
only `tlsn-mux` (the multiplexed link) and the test server fixture; from mpz, the
QuickSilver prover and verifier, KOS and ferret correlated OT, OLE and share
conversion, and the AES circuits. `api.anthropic.com` accepts TLS 1.2 with
`ECDHE-ECDSA-AES128-GCM-SHA256` and `ECDHE-RSA-AES128-GCM-SHA256` over P-256, which is
what the splice needs.

Tests (`cargo test --release`): the template policy; the lender's per-connection gate;
the limit proof against tlsn's test server, with an honest prover accepted and three
cheats (another server key, another server IV, a truncated response) refused for the
expected reason; and `peer::two_peers_lend_and_borrow`, where a borrow is refused for
lack of a proof, accepted after proving, and refused again on the same session once the
lender stops lending, with the token never appearing in what the borrower receives. The
`demo` binary runs both sides and an echo server in one process: `--evil-rewrite` (the
lender changes a header byte outside the span) ends with the server's `bad_record_mac`
reaching the borrower, and `--evil-server` (the lender connects the borrower to the
wrong server) fails in the borrower's certificate check.

## Measured

On one Mac (M-series), both parties local.

**A session** (demo, 1 KB bodies, 4 at a time):

| | per session | per request |
|---|---|---|
| setup (two ferret instances: proof and share conversion) | ~0.9 MB each way, 105 ms | |
| proof and tag | | 20 ms of proving, serialized; ~13 KB borrower → lender |
| ferret extension for the proof (one per ~13 requests) | | ~80–120 KB lender → borrower, amortized |
| new TLS connection (when none is idle) | | 2 round trips, no two-party computation |

Sixty requests in 2 s locally, 22 connections opened and 38 reused.

**A limit proof** (`limit-verify` and `limit-prove` on loopback, a real Claude Code
login, live `api.anthropic.com`):

| Phase | Time | Prover sends | Prover receives | What |
|---|---|---|---|---|
| setup | 0.13 s | 879 KB | 949 KB | the OT setup, same as a borrowing session |
| probe | 0.29 s | 0.7 KB | 6.2 KB | TLS handshake and the usage request through the relay |
| proof | 0.42 s | 170 KB | 1.56 MB | 222 AES blocks (4 of request, 218 of a 3351-byte response) |

The 1.56 MB is the ferret correlated-OT extension that the first real proof of a setup
pays. About fifteen times one borrowed request, once per limit hit, good until the
window resets.

**Two peers over iroh** (two processes on one Mac, n0's relays and address lookup on,
the real API): on the first borrowed request the limit proof takes 0.43 s and opening
the borrowing session 0.15 s; Anthropic's `200` arrives about 1.1 s after the request
started. Through two agents and their peers, a Claude Code-shaped request took about
2.5 s on first use (proof and session) and 1.4 s after.

**Memory** of the two-party part, by ferret batch size for the proof:

| ferret batch | resident, both sides, plateau | download per request |
|---|---|---|
| small (mpz default, 256k) | 160 MB | ~160 KB |
| medium (512k, the default) | 180–195 MB | ~80 KB |
| large (1M) | 280 MB | ~90 KB |

Those are with mimalloc as the allocator. Memory does not grow with requests beyond the
plateau, reached after a dozen or so: each proof allocates and frees tens of MB of
temporaries (the ZK gate vectors, ferret's expansions) and the plateau is the
allocator's high-water mark, not a leak. As separate processes each side sits at about
165 MB after 100 requests. The share conversion keeps mpz's small parameters; it needs
under a thousand correlations per request.

## Security, as it stands

- **The key never leaves the borrower.** It is the witness of a zero-knowledge proof,
  private against a malicious verifier. The roles are fixed in code, borrower = prover;
  no message from the other side assigns a role.
- **The token** could reach the borrower only through the span's ciphertext or the tag,
  and it sees neither. The span's ciphertext enters only the share conversion, as the
  lender's (OLE sender's) input, which stays private against a malicious receiver. The
  tag is masked by `E_K(J0)` and never sent to the borrower.
- **The token is only ever a bearer value of a fixed length**, XORed into a proven
  keystream outside every circuit (`check_template`, `TOKEN_LEN`).
- **The keystream is honest** or the lender aborts before using it (the proof's
  soundness). A borrower that cheats learns nothing it did not already know.
- **Header integrity** outside the span rests on the tag: the server, not the borrower,
  rejects a tampered record, and a lender that tries it produces `bad_record_mac`
  failures on its own account.
- **The nonce** the borrower announces for the token record (client write IV and
  sequence number) reveals the 4-byte GCM salt to the lender. GCM does not rely on
  nonce secrecy; it is harmless.
- **What is still only semi-honest:** mpz's share conversion (OLE from correlated OT),
  used for the seven span blocks of the tag. Its correctness against a cheating party
  is "wrong tag, so abort". Its privacy is what a review should examine, along one
  path: a borrower mauling the conversion to learn the lender's ciphertext blocks,
  which, holding the key, it could then decrypt. The handshake is not in a two-party
  computation and nothing is garbled, so there is no key-exchange conversion or
  garbling orientation to analyse.
- **The limit proof** is the same QuickSilver statement as the splice, now with `H` and
  `E_K(J0)` among the outputs, and the GCM tag used as the key-binding check.
- **Bounds.** Each setup, connect and splice step has a 90 s deadline; at most 64 KB of
  handshake per connection before its first splice; frames of at most 256 KB; at most
  16 connections per session; a request's bytes are exactly its announced length
  (`Content-Length` at most 64 MB); a response may pause for 10 min between bytes; a
  session ends after 2 h without a frame; per-connection queues give backpressure to a
  slow server.

## Why it is built this way

Notes on choices that are not obvious from the protocol itself.

- **Two ferret instances per session.** mpz's KOS extends once and ferret extends
  forever; a session needs correlations per request, so both the proof and the share
  conversion run on ferret. They cannot share one instance: a shared correlated-OT
  handle's `flush` is a barrier every live handle must reach, and the converter skips
  its flush when nothing is queued, which deadlocks. Two setups per session cost less
  than untangling that.
- **The OT direction decides who uploads.** In KOS the receiver sends 16 bytes per
  correlation, and the prover is the receiver, so with KOS alone the borrower would
  upload over a megabyte per request. ferret makes the per-correlation cost negligible
  at the price of a fixed setup, about 0.5 MB each way per instance.
- **Ferret's batch size is the per-request cost.** With mpz's default parameters every
  third request paid a ~200 KB extension; a larger batch makes it one per dozen at the
  cost of memory. 512k is the best of both. The first extension must use the small
  parameters, since it runs on the bootstrap correlations.
- **Allocate before preprocessing.** Late private inputs stall mpz: everything is
  allocated and marked before preprocessing and assigned later.
- **rustls gives away exactly what the splice needs.** `dangerous_extract_secrets`
  returns the two AES-GCM keys with their IVs and the next sequence number in each
  direction (1 and 1 after a TLS 1.2 handshake: one `Finished` each way). The token
  record takes client sequence number 1 and the borrower continues at 2.
- **One request per local connection.** The agent reads a response to the end of the
  stream, so the local proxy closes after each response.

## Open

- **The proof inside the borrowing session**, as one more `Up`/`Down` message pair, so
  it shares the OT setup: saves the 1.8 MB of setup and extension per proof and one
  stream.
- **Account binding.** Reveal an account identifier with the limit proof and compare it
  with one seen at join time, so a second, exhausted account proves nothing.
- **The verifier checking the handshake**: parsing the clear handshake to check the
  certificate chain and the cipher suite on the lender's side too.
- **Memory.** About 165 MB per side at steady state, mostly allocator high-water mark
  from each proof's temporaries. Reusing those buffers across proofs inside mpz (or a
  smaller ferret batch, at twice the download per request) would cut it.
- **Cheaper circuit.** The head is the proof's size; trimming more headers would shrink
  it.
- **Cryptographer review**, of a small surface: QuickSilver as used here (one prover
  input, public blocks, outputs revealed to the verifier), the GCM tag as the
  key-binding check in the limit proof, and the share conversion's privacy against a
  malicious receiver.
