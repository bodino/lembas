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
- **Your limits are exact.** Friends borrow until your 5-hour window reaches 90% and
  never past 60% of your week (both adjustable), checked against Anthropic's own live
  usage numbers. If they can't be read, nobody borrows.
- **Prompts stay home.** In the normal path only `{model, estimated USD}` leaves your
  Mac. Only borrowed requests pass through the pool.

The pieces:

| Piece | Runs on | What it does |
|---|---|---|
| **lembas.app** | every member's Mac | Menu bar app: join with an invite code, connect your subscription, set who you lend to. |
| **lembas-agent** | every member's Mac (inside the app, run by launchd) | Local proxy on `127.0.0.1:8788` that Claude Code talks to: direct to Anthropic, pool only on usage limits. |
| **pool** (`src/server.ts`) | one Mac in the group | Holds members' subscription access, decides who can lend right now, relays borrowed requests. |

## Joining a pool

1. Download **lembas.zip** from the [latest release](../../releases/latest), unzip it,
   and move **lembas.app** to Applications.
2. Open it. The app isn't notarized by Apple, so the first time macOS blocks it: open
   **System Settings › Privacy & Security** and click **Open Anyway**.
3. Click the parcel in the menu bar, paste the invite code a friend sent you, and click
   **Join**. Then approve the claude.ai login that opens in your browser.

That's it — no Terminal, no Tailscale, no Node. lembas installs its agent (a launchd
job, `com.lembas.agent`) and sets only `ANTHROPIC_BASE_URL=http://127.0.0.1:8788` in
Claude Code's settings, so Claude Code keeps its own login, connectors and `/usage`.
The **fallback** switch in the app header turns this off (direct only, no borrowing).

## Running a pool

One person runs the pool on a Mac that's usually awake. Requirements: Node ≥ 22.18
(the server has no npm dependencies) and Tailscale.

1. Clone this repo and build the app (the pool serves it to joiners):
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
5. Join your own pool: install the app on this Mac with your token —
   ```sh
   curl -fsSL http://127.0.0.1:8787/join.sh | sh -s -- https://your-mac.your-tailnet.ts.net pool-…
   ```
   — then choose **Connect Subscription…** in the app.
6. Invite friends: **Invite to Pool…** in the app gives a one-time code (valid 7 days)
   with a ready-to-send message. Nobody is added until the code is used. Admins can
   also **Remove from Pool** on a person's page, which revokes their access at once.

### What protects a public pool

- Every route except `/pool/redeem`, `/join.sh` and `/lembas.zip` needs a pool token
  (192 random bits). Invite codes are 16 characters (~79 bits) and single-use.
- 10 failed tokens or codes from one client block it for 10 minutes; 30 failed codes
  across everyone pause redemption for 10 minutes. Unauthenticated bodies are capped.
- The pool listens only on your Tailscale IP and, for Funnel, on `127.0.0.1`.
- Keep 2FA on your Tailscale account: it controls the Funnel.

## Lending, in detail

- **Away** turns on after `awayAfterMinutes` (default 30) without your own Claude Code
  use, or when you flip the switch; your next own request turns it off. The pool sees
  your activity through the usage your agent reports, so this works with the laptop
  closed.
- **Per person** (their page in the app): *When I'm away* and *While I'm working*
  (until your 5-hour window reaches the level you set).
- **Your limits** (*Lending limits*): while away, friends borrow until your 5-hour
  window reaches `away5h` (default 90%). Nobody borrows past `week` (default 60%) of
  your 7-day window. Unused 5-hour capacity is lost at reset anyway; the week limit is
  the real protection.
- **Pick order:** the lender with the most room under their limits goes first.
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

Either part of `/pool/share` may be sent alone; `lendTo` replaces the whole map.

## Building from source

`./build.sh` compiles the app and agent (universal arm64 + x86_64, macOS 13+), draws
the app icon, signs ad hoc, and writes `installer/lembas.zip`. Sources:

- `src/PoolBar.swift` — the menu bar app
- `src/Agent.swift` — the local agent
- `src/Login.swift` — connecting a claude.ai subscription (OAuth with PKCE)
- `src/Logo.swift` — the logo, drawn in code (app icon, badge, menu bar icon)
- `src/HTTPServer.swift` — small HTTP server shared by the agent and login
- `src/server.ts`, `src/ledger.ts` — the pool

Terminal-only alternatives for pool admins: `./add-user.sh <name>` adds a member and
prints a `join.sh` one-liner; `./set-token.sh <name>` stores a `claude setup-token`
token for members who can't use the app's login (that path can't read usage windows,
so such members never lend).

## Notes

- The pool never rewrites request bodies; it swaps the auth header and adds the OAuth
  beta flags Anthropic requires. Requests must look like Claude Code's, so other
  clients pointed at the pool may be rejected.
- Not every 429 is a usage limit. Transient `rate_limit_error`s are passed back so
  Claude Code retries; only real usage-limit responses move a request to the pool.
- Borrowed responses carry an `x-pool-key-owner` header naming whose subscription
  served them.

## License

[MIT](LICENSE)
