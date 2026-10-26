# The spliced token record: helper for borrowed requests

See `../docs/mpc-tls.md` for the design and findings.

## What is here

- `lembas-mpc/` — a standalone Cargo project on pinned git dependencies (TLSNotary's
  multiplexer and test server, mpz for the zero-knowledge VM and oblivious transfer;
  no fork, no patch). `src/splice.rs` has the primitives (the borrower is an
  ordinary TLS 1.2 client over a relay through the pool; the pool inserts one record
  per request, the one carrying the token, with its keystream proven in zero knowledge
  by the borrower and its tag from the borrower's GHASH terms plus one share conversion
  per token block), `src/session.rs` the protocol (one session, many connections, many
  requests, one setup), `src/local.rs` the borrower's local HTTP proxy, `src/record.rs`
  the local TLS 1.2 AES-GCM record layer, `src/lib.rs` the template policy and the link
  plumbing, `src/main.rs` the `demo` binary (everything in one process, with checks),
  `src/bin/lembas-mpc.rs` the `lembas-mpc` binary (pool, borrower, proxy, chat).
- `requests/` — the request templates used so far: `echo.*` for tlsn's test server,
  `messages.*` and `stream.json` for `api.anthropic.com` with a subscription token.
  A template is the whole request head with the Authorization line last; `{token}` is
  where the pool's bearer token goes, `{body_len}` the body length, `{host}` the
  server.

## Build

Needs Rust 1.95 (`rust-toolchain.toml` pins it; rustup installs it). Dependencies are
fetched from git at pinned revisions and locked in `Cargo.lock`.

```sh
cd mpc-tls/lembas-mpc
cargo build --release
cargo test --release
```

(The earlier versions were a patch on a TLSNotary checkout; `git log -- mpc-tls` has
them.)

## In-process demo

```sh
./target/release/demo                                  # one session, 6 requests, 3 at a time
./target/release/demo --requests 60 --concurrency 4 --body 1024
./target/release/demo --refuse-first 2 --requests 6    # the pool has no lender for the first two
./target/release/demo --evil-rewrite       # pool edits a header byte: the server rejects the record
./target/release/demo --evil-server        # pool connects to the wrong server: the borrower refuses
./target/release/demo --bench 64 --bench-batch medium   # only the proofs: memory and bytes per request
```

The demo runs the pool, the borrower and tlsn's echo server in one process: one
session, requests in parallel over connections that are reused (every third request
asks the server to close, so the next opens a new one), each body echoed back, the
token never on the pool↔borrower link.

Typical numbers on one Mac: about 100 ms and 0.9 MB each way to set a session up, then
20 ms of proving and a few tens of KB per request.

## Chat

```sh
mpc-tls/chat.sh            # starts a pool with your token from state.json, opens the chat
```

The conversation is one session; every message you type is one borrowed request on
it, with the connection reused when the server allows. `lembas-mpc chat --pool
host:port` talks to a pool you started yourself.

## Inside lembas

`./build.sh` at the repo root builds this helper (both architectures) into the app and
into `build/lembas-mpc` for the pool; nothing here needs to be run by hand. The pool
spawns `pool --stdio --control-fd 3` per member session and lends a token per request
over fd 3; the agent spawns `proxy --stdio --listen 127.0.0.1:0 --port-file …` once and
sends each request to the local port as plain HTTP. See "In lembas" in
`../docs/mpc-tls.md`.

## Two processes

Against tlsn's echo server, three terminals:

```sh
./target/release/lembas-mpc fixture --listen 127.0.0.1:7443
LEMBAS_TOKEN=$(python3 -c "print('x'*108)") ./target/release/lembas-mpc pool \
  --listen 127.0.0.1:7700 --server 127.0.0.1:7443 --server-name test-server.io
./target/release/lembas-mpc borrower --pool 127.0.0.1:7700 \
  --template requests/echo.http --body requests/echo.json --roots fixture
```

Against `api.anthropic.com` with a subscription token (`sk-ant-oat01-…`, as stored
in the pool's ledger):

```sh
LEMBAS_TOKEN=… ./target/release/lembas-mpc pool          # defaults: api.anthropic.com
./target/release/lembas-mpc borrower --template requests/messages.http --body requests/messages.json
./target/release/lembas-mpc borrower --template requests/messages.http --body requests/stream.json
```

The borrower prints the raw HTTP response as it arrives and verifies the server's
certificate itself (`--roots`, Mozilla's by default). The pool checks the borrower's
template: the token span must be exactly the value of an `Authorization: Bearer`
header, the last header line of the whole head, block aligned and sized for the token
(108 bytes rounded up to 112), `Host` must be the server the pool connects to,
`Content-Length` is the only framing header; and on each connection a token record
must begin a fresh request (the first application data, then exactly the body's
length between records). The pool refuses to lend a credential of any length but 108 bytes, and the
borrower refuses a pool that announces any other length; see `TOKEN_LEN` in `lib.rs`
for why. The pool↔borrower stream must run over an authenticated channel in
production; the TCP port here is for local testing.
