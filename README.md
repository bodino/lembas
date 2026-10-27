# lembas

Friends back up each other's Claude subscriptions. When you hit your Claude Code
usage limit, lembas retries on a friend's spare capacity — and when you log off for the
day, your unused capacity can help them.

> ⚠️ **Read this first.** lembas works by letting several people send requests on one
> Claude account. That is credential sharing and is **not permitted by Anthropic's
> terms of service** — accounts doing it can be rate-limited or banned. The pool
> stores every member's subscription access, so treat it (and its `config.json` /
> `state.json`) as highly sensitive. Use it at your own risk.

## How it works

- **Direct first, always.** Every normal Claude Code request goes straight from your
  Mac to Anthropic on your own claude.ai login. Only an actual usage-limit error is
  retried through the pool, on a friend's subscription.
- **Lending follows your day.** You're *working* while you use Claude Code and *away*
  after a stretch without it (or as soon as you flip the **Away** switch). While you're
  away, the friends you picked can borrow; while you work, only those you allow "even
  while I'm working" can, up to a level you set.
- **On by default, with safe limits.** Everyone in a pool can borrow from everyone
  while they're away — until your 5-hour window reaches 70%, and never past 60% of your
  week. Limits are checked against Anthropic's own live usage numbers; if they can't be
  read, nobody borrows. Turn people off or adjust the limits in the app.
- **Prompts stay home.** In the normal path only `{model, estimated USD}` leaves your
  Mac. Only borrowed requests pass through the pool.
- **Borrowing is private.** A borrowed request goes through a
  [spliced token record](docs/mpc-tls.md): your Mac runs the TLS session to Anthropic
  and holds its keys alone, and the pool inserts the one record that carries the
  lender's token, computed between the two so that the pool never sees the keys and
  your Mac never sees the token. The pool can't read or change the request or the
  answer. There is no other way to borrow: if the private path fails, borrowing pauses,
  and a pool built without the helper can't lend at all (the menu says so). Before
  lending, the pool checks with Anthropic, using your own login, that you really are at
  a usage limit; a lender's limit reported by a borrower is checked the same way before
  the lender is skipped for everyone. What the pool has to take your agent's word for is
  the metered cost of each request, since it can't see Anthropic's answer. About a
  megabyte each way to set up when the agent starts borrowing, then a few tens of KB and
  some 20 ms per request, with the connections to Anthropic kept open and reused.

The pieces:

| Piece | Runs on | What it does |
|---|---|---|
| **lembas.app** | every member's Mac | Menu bar app: join with an invite code, connect your subscription, set who you lend to. |
| **lembas-agent** | every member's Mac (a launchd job, run from `~/Library/Application Support/lembas`) | Local proxy on `127.0.0.1:8788` that Claude Code talks to: direct to Anthropic, pool only on usage limits. |
| **pool** (`src/server.ts`) | one Mac in the group | Holds members' subscription access, decides who can lend right now, carries borrowed requests' encrypted bytes and splices the lender's token in. |
| **lembas-mpc** | inside lembas.app, and in `build/` next to the pool | The helper for private borrowing: one process per session on each side (`mpc-tls/`). |

## Joining a pool

You need macOS 26 or later. Open the invite link a friend sent you — it's a page on
their pool with two buttons:

1. **Download** lembas, unzip it, and open it. The app isn't notarized by Apple, so the
   first time macOS blocks it: open **System Settings › Privacy & Security** and click
   **Open Anyway**. If you opened it from Downloads, lembas offers to move itself to
   Applications first — it needs a permanent home to update itself.
2. **Join** opens lembas with the invite filled in (or paste the link into lembas).
   Then finish the short setup checklist: connect your subscription (approve the
   claude.ai login in your browser; **Retry** if you closed the tab) and choose whether
   lembas opens at login. Wrong invite? **Use a different invite** goes back, and the
   invite stays valid until you've connected.

You can also download lembas from the [latest release](../../releases/latest). That first
download is the one step the app can't check for you: it trusts GitHub's latest release
(built by this repository's workflow; `gh attestation verify lembas.zip --repo
bodino/lembas` confirms that). Every update after it is checked against the release key.

That's it — no Terminal, no Tailscale, no Node. lembas installs its agent (a launchd
job, `com.lembas.agent`) and sets only `ANTHROPIC_BASE_URL=http://127.0.0.1:8788` in
Claude Code's settings, so Claude Code keeps its own login, connectors and `/usage`.
The **fallback** switch in the app header turns this off (direct only, no borrowing).

**Claude Code always keeps working:**

- With the app closed — the agent runs on its own.
- When the pool is unreachable (its Mac asleep, or its owner on another VPN) — requests
  go straight to Anthropic; only borrowing pauses.
- After **Leave Pool** (⚙ menu), after being removed by an admin, or after deleting
  lembas.app — the agent stops using the pool, takes itself out of Claude Code's
  settings so new sessions talk to Anthropic directly, keeps serving sessions that were
  already open, and removes itself once they're gone.

**Updates** come only from this repository's GitHub releases, built by GitHub Actions
from the public source, never from a pool, so whoever runs your pool can't ship code to
your Mac. The app installs a release only if its `version.json` is signed by the lembas
release key (Ed25519; the public half is pinned in the app, the private half lives in
the workflow's `release` environment, which signs only after a reviewer approves and
runs nothing from the tag's checkout, while the build job that does has no credentials
at all), so neither can anyone who merely gets to publish a release or push a tag. When a new release is out, lembas shows **Install latest build…** at the
bottom; one click updates and relaunches. Check where a download came from with
`gh attestation verify lembas.zip --repo bodino/lembas`.

## Running a pool

One person runs the pool on a Mac that's usually awake. Requirements: Node ≥ 22.18
(the server has no npm dependencies), Tailscale, Xcode with the macOS 26 SDK or newer
to build the app, and Rust via [rustup](https://rustup.rs) for the private-borrowing
helper (`LEMBAS_SKIP_MPC=1 ./build.sh` builds without it, for quick work on the app;
such a pool can't lend at all, and its members' menu says so).

1. Clone this repo and build the app (the pool serves it to joiners and offers each new
   build to members as an update):
   ```sh
   ./build.sh
   ```
2. Create your config — you're the first member and the admin:
   ```sh
   cp config.example.json config.json
   openssl rand -hex 24   # paste as your token, prefixed with "pool-"
   ```
   Set `host` to your Tailscale IP (`tailscale ip -4`) and rename `alice` to you.
3. Start the pool at login: copy `deploy/com.lembas.pool.plist.example` to
   `~/Library/LaunchAgents/com.lembas.pool.plist`, fix the paths, then
   `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.lembas.pool.plist`
   (logs go to `pool.log`).
4. Make it reachable for friends with **Tailscale Funnel** (from your own Terminal):
   `tailscale funnel --bg 8787`. If Funnel isn't allowed yet it prints a link to
   approve it. Put the printed `https://….ts.net` address in `config.json` as
   `publicUrl` and restart the pool:
   `launchctl kickstart -k gui/$(id -u)/com.lembas.pool`.
5. Join your own pool: download lembas from the [latest release](../../releases/latest)
   like everyone else, write its config with your address and token —
   ```sh
   mkdir -p ~/.config && printf '{"url":"%s","token":"%s"}\n' https://your-mac.your-tailnet.ts.net pool-… > ~/.config/lembas.json && chmod 600 ~/.config/lembas.json
   ```
   — open the app, then choose **Connect Subscription…**. (The pool never serves a
   script to run: whoever runs a pool must not get to run code on a member's Mac, and
   that includes the pool's own operator joining.)
6. Invite friends: **Invite to Pool…** in the app copies a one-time link (valid 7 days)
   that opens the invite page described above. Nobody is added until it's used. Admins
   can also **Remove from Pool** on a person's page, which revokes their access at once.
7. Updates are released from this repository: bump `CFBundleShortVersionString` in
   `resources/Info.plist`, push, then push a matching tag (`git tag v1.2.0 && git push
   origin v1.2.0`). The release workflow builds and publishes it; members get it within
   a minute. A pool's own `./build.sh` output is only offered to apps older than 1.2.

### What protects a public pool

- Every route except the invite page, `/pool/redeem` and `/logo.png` needs a pool
  token (192 random bits); nothing the pool serves is a program. Invite codes
  are 16 characters (~79 bits) and single-use; the invite page only displays, it never
  joins anyone.
- 10 failed tokens or codes from one client block it for 10 minutes. Valid tokens are
  never blocked. Unauthenticated bodies are capped, the public pages are rate-limited
  per visitor, and members' own reads and writes per member, so one client can't keep
  the pool (or Anthropic's usage endpoint, which the pool asks once per member at a
  time) busy.
- The pool listens only on your Tailscale IP and, for Funnel, on `127.0.0.1`.
- Keep 2FA on your Tailscale account: it controls the Funnel.

## Lending, in detail

- **Away** turns on after `awayAfterMinutes` (default 30) without your own Claude Code
  use, or when you flip the switch; your next own request turns it off. The pool sees
  your activity through the usage your agent reports, so this works with the laptop
  closed.
- **Per person** (their page in the app): *When I'm away* (on by default) and *While
  I'm working* (until your 5-hour window reaches the level you set).
- **Your limits** (*Lending limits*): while away, friends borrow until your 5-hour
  window reaches `away5h` (default 70%). Nobody borrows past `week` (default 60%) of
  your 7-day window. Unused 5-hour capacity is lost at reset anyway; the week limit is
  the real protection.
- **Pick order:** the lender with the most 5-hour room goes first. The week is a gate:
  once someone's week reaches their limit they can't lend, whatever their 5-hour room.
  The app shows each lender's 5-hour room ("41% left"); a percent of a week and a percent
  of a 5-hour window aren't comparable, so they're never mixed.
- Usage is read at most once a minute (Anthropic rate-limits that endpoint), so a
  borrower can overshoot a limit by what they use within that minute.
- Dollar amounts in the app are API-price estimates, a fairness indicator only.

### API

`GET /pool` returns your `policy`, `presence`, `lending` map and `borrowingFrom`
(whether you can borrow from each member right now, and why: `away`, `working`, `off`,
`full`, `parked`, `unconnected`, `unknown`). Settings:

```http
PUT /pool/share     {"policy":{"away5h":90,"week":60,"awayAfterMinutes":30},
                     "lendTo":{"bob":{"away":true,"working5h":40}}}
PUT /pool/presence  {"away":true}
```

Either part of `/pool/share` may be sent alone. `lendTo` replaces the whole map; anyone
omitted gets the default (may borrow while you're away), so send `{"away": false}` to
turn someone off.

## Building from source

`./build.sh` compiles the app and agent (universal arm64 + x86_64, macOS 26+) with the
first toolchain that has a macOS 26+ SDK (the active one, else `/Applications/Xcode.app`),
draws the app icon, signs ad hoc, and writes `installer/lembas.zip` plus
`installer/version.json` (the update members are offered). Sources:

- `src/PoolBar.swift` — the menu bar app
- `src/Agent.swift` — the local agent
- `src/Login.swift` — connecting a claude.ai subscription (OAuth with PKCE)
- `src/Logo.swift` — the logo, drawn in code (app icon, badge, menu bar icon)
- `src/HTTPServer.swift` — small HTTP server shared by the agent and login
- `src/server.ts`, `src/ledger.ts` — the pool

Terminal-only alternative for pool admins: `./set-token.sh <name>` stores a `claude
setup-token` token for a member who can't use the app's login (that path can't read
usage windows, so such members never lend). Members are added with invites from the app.

## Notes

- `LEMBAS_PROFILE=<name>` runs a second member side by side on one Mac (own config,
  agent on port 8789, Claude Code settings in `~/.claude-<name>`) — handy for testing
  invites. `LEMBAS_APPEARANCE=light|dark` forces an appearance.
- The pool never rewrites request bodies; it swaps the auth header and adds the OAuth
  beta flags Anthropic requires. Requests must look like Claude Code's, so other
  clients pointed at the pool may be rejected.
- Not every 429 is a usage limit. Transient `rate_limit_error`s are passed back so
  Claude Code retries; only real usage-limit responses move a request to the pool.
- Borrowed responses carry an `x-pool-key-owner` header naming whose subscription
  served them.

## License

[MIT](LICENSE)
