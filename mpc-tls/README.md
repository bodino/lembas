# The spliced token record: helper for borrowed requests

Research branch. See `../docs/mpc-tls.md` for the design and findings.

## What is here

- `lembas-mpc/` — the crate: `src/splice.rs` is the protocol (the borrower is an
  ordinary TLS 1.2 client over a relay through the pool; the pool inserts the one
  record that carries the token, with its keystream proven in zero knowledge by the
  borrower and its tag from the borrower's GHASH terms plus one share conversion per
  token block), `src/record.rs` the local TLS 1.2 AES-GCM record layer the borrower
  runs after the handshake, `src/lib.rs` the template policy and the link plumbing,
  `src/main.rs` the `demo` binary (everything in one process, with leak checks),
  `src/bin/lembas-mpc.rs` the `lembas-mpc` binary (pool and borrower over TCP or
  stdin/stdout, a chat).
- `tlsn-eb19c82-lembas-splice.patch` — adds the crate to TLSNotary's workspace at commit
  `eb19c82` (2026-10-21), with the `Cargo.lock` entries that follow. The crate uses
  tlsn only for its mux and its test server; everything else comes from mpz and rustls.
- `legacy/` — the earlier patch, which changed tlsn's `mpc-tls` crate for a protocol
  with a joint MPC handshake and a key hand-off. Superseded; kept for the measurements
  in the design doc.
- `requests/` — the request templates used so far: `echo.*` for tlsn's test server,
  `messages.*` and `stream.json` for `api.anthropic.com` with a subscription token.
  In a template, `{token}` is where the pool's bearer token goes and `{body_len}`
  is the body length.

## Build

Needs Rust 1.95 (tlsn pins it in `rust-toolchain.toml`; rustup installs it).

```sh
git clone https://github.com/tlsnotary/tlsn
cd tlsn && git checkout eb19c82
git apply /path/to/claudus/mpc-tls/tlsn-eb19c82-lembas-splice.patch
cargo build --release -p lembas-mpc
cargo test -p lembas-mpc --release
```

## In-process demo

```sh
./target/release/demo                      # 32 KB body
./target/release/demo --body 16777216      # 16 MB body
./target/release/demo --evil-rewrite       # pool edits a header byte: the server rejects the record
./target/release/demo --evil-server        # pool connects to the wrong server: the borrower refuses
```

The demo runs the pool, the borrower and tlsn's hyper echo server in one process
and checks that the body was echoed, that neither the token nor the token record's
ciphertext crossed the pool↔borrower link, and that the token record is exactly what
the borrower's keys produce from its template with the token in place.

Typical numbers on one Mac: about 90 ms in total and half a megabyte each way on the
link, most of it the proof system's setup, overlapped with the TLS handshake.

## Chat

```sh
mpc-tls/chat.sh            # starts a pool with your token from state.json, opens the chat
```

Every message you type is one borrowed request: a fresh TLS handshake relayed through
the pool, the spliced token record, then the streamed answer. Expect about 0.1 s of
overhead per turn on top of the model's time. `lembas-mpc chat --pool host:port`
talks to a pool you started yourself.

## Inside lembas

`./build.sh` at the repo root builds this helper (both architectures) into the app and
into `build/lembas-mpc` for the pool; nothing here needs to be run by hand. The pool and
the agent each spawn one helper per borrowed request in `--stdio` mode, with the link on
stdin/stdout and the response (borrower side) written to a `--output` FIFO. See "In
lembas" in `../docs/mpc-tls.md`.

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
header, the last line of the pool's record, block aligned and sized for the token
(108 bytes rounded up to 112), and `Host` must be the server the pool connects to; and
it refuses to write the token record unless it is the first application data on the
connection. The pool refuses to lend a credential of any length but 108 bytes, and the
borrower refuses a pool that announces any other length; see `TOKEN_LEN` in `lib.rs`
for why. The pool↔borrower stream must run over an authenticated channel in
production; the TCP port here is for local testing.
