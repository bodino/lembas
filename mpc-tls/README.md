# lembas-mpc: the peer and its cryptography

The Rust half of lembas: one binary, `lembas-mpc`, that each Mac's agent runs as its
**peer**. The design is in [`../docs/mpc-tls.md`](../docs/mpc-tls.md) (the spliced token
record and the limit proof) and [`../docs/p2p.md`](../docs/p2p.md) (circles and peers).

## What is here

`lembas-mpc/` is a standalone Cargo project on pinned git dependencies: TLSNotary's
multiplexer and test server, mpz for the zero-knowledge VM and oblivious transfer, iroh
for the network.

| File | What |
|---|---|
| `src/peer.rs` | the peer: iroh endpoint, join / sync / limit / borrow streams, the lending gate, presence, the week's ledger |
| `src/circle.rs` | the circle: signed memberships and removals, invite links |
| `src/splice.rs` | the splice's primitives: the keystream proven in zero knowledge, the tag by share conversion, the TLS client |
| `src/session.rs` | the borrowing protocol: one session, many connections, many requests, one setup |
| `src/limit.rs` | the limit proof |
| `src/record.rs` | the TLS 1.2 AES-GCM record layer the borrower runs after the handshake |
| `src/local.rs` | the borrower's local HTTP proxy |
| `src/lib.rs` | the template policy and the link plumbing |
| `src/bin/lembas-mpc.rs` | the `lembas-mpc` binary |
| `src/main.rs` | the `demo` binary: both sides and an echo server in one process, with checks |

In the code the lender's side of a borrow is called `pool` (`run_pool`, the `pool`
command below): the side that holds the token.

`requests/` has request templates for the test commands: `echo.*` for tlsn's test
server, `messages.*` and `stream.json` for `api.anthropic.com`. A template is the whole
request head with the Authorization line last; `{token}` is where the lender's bearer
token goes, `{body_len}` the body length, `{host}` the server.

## Build

Needs Rust 1.95 (`rust-toolchain.toml` pins it; rustup installs it). Dependencies are
fetched from git at pinned revisions and locked in `Cargo.lock`.

```sh
cd mpc-tls/lembas-mpc
cargo build --release
cargo test --release
```

`./build.sh` at the repo root builds this for both architectures and puts it in the app
bundle; nothing here needs to be run by hand to use lembas.

## Inside lembas

The agent runs one peer per Mac and drives it over JSON lines:

```sh
lembas-mpc peer --dir <Application Support/lembas/…/peer> --name <you> \
  --token-file ~/.config/lembas-login.json --control --socket <dir>/sock
```

`--control` takes commands on stdin (`status`, `found`, `invite`, `join`, `lend`,
`policy`, `away`, `remove`, `sync`, `report`, `spent`) and answers on stdout, with a
`status` event every half minute. The socket serves borrowed requests: the agent sends
each one as plain HTTP and reads the response as Anthropic sent it.

## Two peers by hand

On one Mac, each with a subscription token in `LEMBAS_TOKEN`:

```sh
./target/release/lembas-mpc peer --dir a --name Alice --found --invite --control
./target/release/lembas-mpc peer --dir b --name Bob --join lembas://join/… --control --listen 127.0.0.1:8789
curl http://127.0.0.1:8789/v1/messages …
```

Alice lends only while away and only to a borrower that proved its limit, so for a
test on accounts that are not exhausted: send `{"cmd":"away","away":true}` to Alice and
lower the thresholds with `--borrow-at`, `--away5h` and `--week`. `--no-relay` keeps
everything on direct addresses.

## The limit proof alone

```sh
./target/release/lembas-mpc limit-verify                    # the lender's side, on 127.0.0.1:7701
LEMBAS_TOKEN=… ./target/release/lembas-mpc limit-prove      # the borrower's side
```

The verifier prints the usage it was shown and the bytes and time per phase.

## The splice alone

`demo` runs a lender, a borrower and tlsn's echo server in one process:

```sh
./target/release/demo                                  # one session, 6 requests, 3 at a time
./target/release/demo --requests 60 --concurrency 4 --body 1024
./target/release/demo --refuse-first 2 --requests 6    # the lender refuses the first two
./target/release/demo --evil-rewrite       # lender edits a header byte: the server rejects the record
./target/release/demo --evil-server        # lender connects to the wrong server: the borrower refuses
./target/release/demo --bench 64 --bench-batch medium   # only the proofs: memory and bytes per request
```

Requests run in parallel over connections that are reused (every third request asks
the server to close, so the next opens a new one), each body is echoed back, and the
token never appears on the link. Typical numbers on one Mac: about 100 ms and 0.9 MB
each way to set a session up, then 20 ms of proving and a few tens of KB per request.

As two processes over TCP (for local testing only: the link has no authentication
here, where a peer's has iroh's), against the echo server:

```sh
./target/release/lembas-mpc fixture --listen 127.0.0.1:7443
LEMBAS_TOKEN=$(python3 -c "print('x'*108)") ./target/release/lembas-mpc pool \
  --listen 127.0.0.1:7700 --server 127.0.0.1:7443 --server-name test-server.io
./target/release/lembas-mpc borrower --pool 127.0.0.1:7700 \
  --template requests/echo.http --body requests/echo.json --roots fixture
```

or against `api.anthropic.com` with a subscription token:

```sh
LEMBAS_TOKEN=… ./target/release/lembas-mpc pool          # defaults: api.anthropic.com
./target/release/lembas-mpc borrower --template requests/messages.http --body requests/messages.json
./target/release/lembas-mpc chat                         # a conversation, one borrowed request per message
```

The borrower prints the raw HTTP response as it arrives and verifies the server's
certificate itself (`--roots`, Mozilla's by default). The lender's side checks the
template and refuses a credential of any length but 108 bytes; see `check_template` and
`TOKEN_LEN` in `lib.rs`, and "Policy" in the design document.
