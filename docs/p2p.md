# lembas without a pool: circles, peers and the limit proof (p2p branch)

Branch `p2p`, 2026-10-28. What this adds to [the spliced token record](mpc-tls.md):
a way for members to lend to each other **directly**, Mac to Mac, with no pool holding
anyone's login, and a **limit proof** that replaces the one thing the pool did with a
borrower's login: checking with Anthropic that the borrower really is at its usage
limit.

Everything below is built and runs: the Rust side (`mpc-tls/lembas-mpc`) has the proof,
the circle and the peer daemon, with in-process tests and a two-process demo on one Mac
over real iroh relays against the real API. What is not done is the app: lembas.app and
the agent still talk to a pool. The last section says what that takes.

## Decisions

- **No leaders, no admins.** A pool needed governing because it held everyone's login.
  Once each login stays on its owner's Mac, the only real decision is bilateral: *do I
  lend to Maya?* A circle is just the list of people who may ask. Anyone in it can
  invite; lending stays each lender's own choice, per person; removal is a signed note
  that every Mac honours when it sees it (and anyone can be invited back).
- **Identity is the Mac's key.** Each peer has an Ed25519 key, generated on first run
  and kept at `<dir>/peer.key` (0600). Its public half is both who you are and, as the
  iroh endpoint id, how you are reached. One person with two Macs is two members for
  now.
- **iroh for the network.** QUIC between peers, NAT hole punching, a relay from n0
  when that fails (the relay carries encrypted QUIC and holds no login; it is a server
  in the path, so the headline becomes *no server ever holds a login or sees your
  traffic*, not *nothing in between*). Peers authenticate each other by key; iroh's TLS
  is the link encryption the pool's WebSocket used to provide.
- **The token splice is unchanged.** A borrow is the same session protocol
  (`session.rs`, protocol 6) over an iroh stream instead of a WebSocket, the lender's
  Mac being the pool's side with its own token. Nothing in the proof or the policy
  changed.
- **Lenders must be awake.** The pool lent a friend's login while their laptop slept;
  a peer lends only while its Mac is up. Expect less overnight capacity. A power
  assertion while lending on mains, and a Mac mini as a good lender, soften this.
- **The borrower proves its limit instead of being checked.** See the next section.

## The limit proof

The pool read a borrower's usage with the borrower's own login. A lender's Mac has no
such login, so the borrower proves what Anthropic says, using the same machinery as a
borrowed request, with the roles of the keys reversed.

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
   context: the head is parsed, the body de-chunked, the JSON read as the pool read
   it). It accepts a `200` whose windows put the borrower at or past `borrow_at`
   (90 % by default), and keeps the proof until the earliest reset of a window at the
   limit (at most six hours).

What the prover cannot do: swap the server's bytes (they never pass through it on the
way to the verifier), open them under another key (the tag check), reveal a window out
of context (the reveal is a prefix), or claim a response to another path (the request
line is opened too and must be the usage endpoint). What it can do: prove with a
different, exhausted account. Binding the proof to the account seen at join time is
listed under open work; the lender's own limits still cap the damage.

Trust the proof shares with the splice: the verifier's own network path to Anthropic.
The verifier does not check the certificate the prover's TLS client saw (the handshake
is in the clear and it could); as for a borrow, a man in the middle on the lender's
side can only cause failures.

Code: `limit.rs` (`verify`, `prove`, `Transcript`, the `Opening`/`KeyPlan` AES input
layout, `Usage`), with `splice::aes_blocks` generalised from the keystream to any
public blocks under a committed key. Tests: the opening agrees with AES-GCM; the usage
body is read as the pool reads it; an honest prover against tlsn's test server is
accepted, and three cheats (another server key, another server IV, a truncated
response) are refused with the expected reason.

### Measured

`lembas-mpc limit-verify` and `limit-prove`, one Mac (M-series), both helpers on
loopback, this Mac's own Claude Code login (`sk-ant-oat01`, from the Keychain, never
printed), live `api.anthropic.com`:

| Phase | Time | Prover sends | Prover receives | What |
|---|---|---|---|---|
| setup | 0.13 s | 879 KB | 949 KB | the usual OT setup (warm-up), same as a borrowing session |
| probe | 0.29 s | 0.7 KB | 6.2 KB | TLS handshake and the usage request through the relay |
| proof | 0.42 s | 170 KB | 1.56 MB | 222 AES blocks (4 of request, 218 of a 3351-byte response) |

The 1.56 MB is the ferret correlated-OT extension that the first real proof of a
session pays (the warm-up's single block fits in the bootstrap); a borrowing session
pays it on its first request anyway, so inside a shared session the proof's own cost is
the 170 KB and 0.4 s. Against the local test server the same proof is 18 blocks, 14 KB
and 14 ms. The earlier estimate of 20 to 35 MB assumed full MPC-TLS with split keys; it
is not needed, because the lender holds the connection and the wire ciphertext.

Compared with a borrowed request (13 KB up, 80 KB down, 20 ms): about fifteen times
one request, once per limit hit, good until the window resets.

## The peer

`lembas-mpc peer` is one process per Mac (`peer.rs`, with the circle in `circle.rs`).
It listens on an iroh endpoint with ALPN `lembas/p2p/1` and speaks to members over
bidirectional streams; the first byte says what the stream is for.

| Stream | Who opens it | What happens |
|---|---|---|
| join | a newcomer with an invite link | shows the one-time secret from the link; the inviter signs its membership, replies with the circle, lends to it by default |
| sync | any member, every 30 s and after a change | each side sends the circle (signed memberships and removals, merged on arrival), its presence and its iroh address |
| limit | a would-be borrower | the limit proof above; the lender keeps the proof until the reset |
| borrow | a borrower | the lender runs the pool's side of a session with its own token; each request's lease goes through the gate |

**The circle** (`circle.rs`) is a set of memberships, each signed by the inviter over
`(circle, member, name, invited_by, at)`; the founder's by itself. Merging accepts a
membership when its signature checks and its inviter was a member then, in rounds
until nothing is new, so order does not matter. A removal is signed by any member;
a later membership reinstates; nobody removes the founder. Tests: a chain of invites
from the founder, a stranger's invite refused, a forged name refused, another Mac
rebuilding the circle from the state, removal and reinstatement, merges converging.

**Invite links** are `lembas://join/<base64url JSON>`: circle id, the inviter's key,
its relay URL and direct addresses, a one-time 16-byte secret, an expiry (7 days).

**The lending gate**, per request: the borrower is a member; the owner set *lend to
them*; a limit proof of theirs is current; the owner's own usage (read every minute
with its own token) is under its limits (`week`, `away5h`; while working, only members
with *even while I'm working*); then the lease is the owner's token. Anything else is a
`Refused` the borrower's proxy turns into an HTTP error, and the session stays up.

**Presence**: name, away or working, lending on, five-hour and week utilization, and
*room* (whether the owner's own limits would allow a lend right now). A borrower picks
the lender with the most of its five-hour window left among those with room heard from
in the last 2.5 minutes.

**Borrowing** is the local proxy from `local.rs` (`serve_client`, a Unix socket or
loopback port, same interface the agent uses today): for each request it picks a
lender, proves its limit to it if that lender has no current proof, opens or reuses a
borrowing session, and relays. Settings (`settings.json`) and the circle
(`circle.json`) persist in `--dir`.

**Control**: with `--control` the peer takes JSON lines on stdin and answers one line
each on stdout, plus a `status` event every 30 s. Commands: `status`, `invite`
(returns a link), `join {link}`, `lend {member, to, while_working}`, `away {away}`,
`remove {member}`, `sync`. This is the interface the app will drive.

### Tests and the demo

`cargo test --release` in `mpc-tls/lembas-mpc`: 17 tests, among them
`peer::two_peers_lend_and_borrow`: two peers in one process on loopback with relays
off, tlsn's test server for the API; Alice founds and invites, Bob joins; Bob's borrow
is refused for lack of a proof, accepted after proving, and refused again on the same
session once Alice stops lending to him; the token never appears in what Bob receives.

The two-process demo (scratchpad `p2p/demo.sh`) runs two peers on this Mac with n0's
relays and address lookup on, this Mac's login as both members' token, and the real
API:

```
lembas-mpc peer --dir a --name Alice --found --invite --control --borrow-at 20 --week 100 --away5h 100
lembas-mpc peer --dir b --name Bob --join lembas://join/… --control --listen 127.0.0.1:8789
echo '{"cmd":"away","away":true}' > a.in; echo '{"cmd":"sync"}' > b.in
curl http://127.0.0.1:8789/v1/messages …
```

The thresholds are lowered because this account is at 31 % of its five-hour window and
63 % of its week: with the defaults Alice's Mac refused on its own week limit (correct),
and Bob's account would not have passed as at its limit. With them lowered: join and
sync, then on the first proxy request the limit proof over iroh (0.43 s; Alice's log:
`limit proof accepted member="Bob" until=…`), the borrowing session (0.15 s), and
Anthropic's `200` with the one-word answer, spliced with Alice's token, about 1.1 s
after `curl` started.

## What's left

The order I would do it in:

1. **The app.** The agent spawns `lembas-mpc peer --control --socket …` instead of
   opening the pool WebSocket and `proxy`; `PrivateBorrow.swift` already talks to a
   local socket and reads `x-lembas-request`. lembas.app drives the control channel:
   found or join (the invite link replaces the pool's join page), the member list with
   a *Lend to Sam?* prompt for members one did not invite, the away switch (the app's
   auto-away stays), the limits. The pool's lending ledger (who used how much of whose)
   becomes each Mac's own log.
2. **Migration.** The pool could introduce existing members once (hand out an invite
   and member list) and then drop out; or members simply re-invite each other. After
   that the pool deletes the logins it holds.
3. **The proof inside the borrowing session**, as one more `Up`/`Down` message pair,
   so it shares the OT setup: saves the 1.8 MB of setup and extension per proof and
   one stream. The verifier side needs the session's gate to keep a transcript for a
   *limit* connection; the proving code is already written for any `Party`.
4. **Account binding.** Reveal an account identifier with the proof (if the usage body
   or a profile endpoint carries one) and compare it with the one seen at join time, so
   a second, exhausted account proves nothing.
5. **Presence privacy.** Members now see each other's utilization numbers (the pool saw
   them before; the members did not). Sending only *room* and *away* is enough for
   picking a lender.
6. **Hardening**: the verifier parsing the clear handshake to check the certificate
   chain and the cipher suite; rate limits on streams per peer; power assertion while
   lending; the `lender must be awake` caveat in the README; a lembas relay if n0's
   public ones rate-limit; cryptographer review of the proof as used (the same
   QuickSilver statement as the splice, now with `H` and `E_K(J0)` among the outputs,
   and the GCM tag used as the key-binding check).
