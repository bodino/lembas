# lembas

Friends back up each other's Claude subscriptions. When you hit your Claude Code
usage limit, lembas retries on a friend's spare capacity, and when you log off for the
day, your unused capacity can help them.

> ⚠️ **Read this first.** lembas works by letting a friend's request run on your
> Claude account, and yours on theirs. That is account sharing and is **not permitted
> by Anthropic's terms of service**: accounts doing it can be rate-limited or banned.
> Use it at your own risk.

There is no server. Each person's Mac lends to the others directly, in a **circle**:
your login never leaves your Mac, a friend's request reaches Anthropic through your Mac
without your Mac being able to read it, and your friend never sees your login.

## How it works

- **Direct first, always.** Every normal Claude Code request goes straight from your
  Mac to Anthropic on your own claude.ai login. Only an actual usage-limit error is
  retried on a friend's subscription.
- **Mac to Mac.** Circle members reach each other over [iroh](https://iroh.computer):
  QUIC between the Macs, hole punching through home routers, and a public relay that
  carries the encrypted bytes when hole punching fails. Each Mac has a key; it is both
  who you are in the circle and how you are reached.
- **Your login stays home.** It lives in a file only your user can read, and your own
  Mac is the only one that ever uses it. A lender must therefore be **awake**: a
  sleeping Mac lends nothing.
- **Borrowing is private, both ways.** A borrowed request goes through a
  [spliced token record](docs/mpc-tls.md): your Mac runs the TLS session to Anthropic
  and holds its keys alone, and your friend's Mac inserts the one record that carries
  their token, computed between the two so that their Mac never sees your keys and
  yours never sees their token. Their Mac can't read or change your prompt or the
  answer. There is no other way to borrow: if the private path fails, borrowing pauses.
- **You prove you're out before you borrow.** A lender has no way to look up your
  usage, so your Mac proves it in zero knowledge: it shows the lender Anthropic's own
  answer about your usage windows without showing your login
  ([the limit proof](docs/mpc-tls.md#the-limit-proof)). You can borrow once a window is
  at 90% or locked.
- **Lending follows your day.** You're *working* while you use Claude Code and *away*
  after a stretch without it (or when you flip the **Away** switch). While you're away,
  the friends you lend to can borrow; while you work, only those you allow *While I'm
  working* can.
- **Safe limits.** Friends borrow until your 5-hour window reaches 70%, and never past
  60% of your week. Your Mac checks this against Anthropic's own live numbers; if it
  can't read them, nobody borrows.

The pieces, all on your Mac:

| Piece | What it does |
|---|---|
| **lembas.app** | Menu bar app: start or join a circle, connect your subscription, choose who you lend to. |
| **lembas-agent** | A launchd job (`com.lembas.agent`, run from `~/Library/Application Support/lembas`). Local proxy on `127.0.0.1:8788` that Claude Code talks to: direct to Anthropic, a friend only on usage limits. Keeps your login fresh and runs the peer. |
| **lembas-mpc** | The peer (`lembas-mpc peer`, a child of the agent): the circle, the connections to friends' Macs, and the cryptography for lending and borrowing. Source in `mpc-tls/`. |

## Getting started

You need macOS 26 or later.

**Joining a friend.** Open the invite link they sent you. It is a page with two
buttons:

1. **Download** lembas, unzip it, and open it. The app isn't notarized by Apple, so the
   first time macOS blocks it: open **System Settings › Privacy & Security** and click
   **Open Anyway**. If you opened it from Downloads, lembas offers to move itself to
   Applications first, since it needs a permanent home to update itself.
2. **Join** opens lembas with the invite filled in (or paste the link into lembas).
   Type your name, press **Join**, then finish the short checklist: connect your
   subscription (approve the claude.ai login in your browser; **Retry** if you closed
   the tab) and choose whether lembas opens at login.

**Starting a circle.** Download lembas from the
[latest release](../../releases/latest), open it, type your name and press **Start a
Circle**. Then **Invite a friend…** makes a link that works once and expires in seven
days. Anyone in a circle can invite.

That's it: no Terminal, no account, no server to run. lembas installs its agent and
sets only `ANTHROPIC_BASE_URL=http://127.0.0.1:8788` in Claude Code's settings, so
Claude Code keeps its own login, connectors and `/usage`. The **Borrowing** switch in
the app header turns that off (direct only).

The first download is the one step the app can't check for you: it trusts GitHub's
latest release, built by this repository's workflow (`gh attestation verify lembas.zip
--repo bodino/lembas` confirms that). Every update after it is checked against the
release key.

**Claude Code always keeps working:**

- With the app closed: the agent runs on its own.
- When no friend's Mac can be reached or nobody has room: requests go straight to
  Anthropic, and you get Anthropic's own limit message as you would without lembas.
- After **Leave Circle…** (⚙ menu) or after deleting lembas.app: the agent takes itself
  out of Claude Code's settings so new sessions talk to Anthropic directly, keeps
  serving sessions that were already open, and removes itself once they're gone.

**Updates** come only from this repository's GitHub releases, built by GitHub Actions
from the public source. The app installs a release only if its `version.json` is signed
by the lembas release key (Ed25519; the public half is pinned in the app, the private
half lives in the workflow's `release` environment, which signs only after a reviewer
approves and runs nothing from the tag's checkout, while the build job that does has no
credentials at all). When a new release is out, lembas shows **Install latest build…**
at the bottom; one click updates and relaunches.

## Circles and people

- **A circle is a list of people, with no leader.** Each membership is signed by
  whoever invited that person, so every Mac can check the whole list for itself.
- **Lending is your own choice, per person.** You and the person who invited you lend
  to each other from the start. Everyone else in the circle shows up under **People**
  with lending off until you turn it on.
- **More than one circle.** **Accept an invite…** joins a friend's circle while keeping
  the people you have; the app shows everyone as one list. Your own invites stay to
  your first circle.
- **Remove from Circle** (on a person's page) stops your Mac lending to them at once and
  tells the others. **Leave Circle…** stops lending and borrowing and deletes this Mac's
  key, its copy of the circle and the stored login.

## Lending, in detail

- **Away** turns on after 30 minutes (15 to 120, under *Lending limits*) without your
  own Claude Code use, or when you flip the switch; your next own request turns it off.
- **Per person** (their page in the app): *When I'm away* and *While I'm working*.
- **Your limits** (*Lending limits*): friends borrow until your 5-hour window reaches
  70%, and nobody borrows past 60% of your 7-day window. Unused 5-hour capacity is lost
  at reset anyway; the week limit is the real protection.
- **What a friend can use your login for:** model requests (`POST /v1/messages` and its
  token count) and nothing else. Your profile and usage stay yours.
- **Pick order:** a borrower takes the lender with the most 5-hour room among those it
  has heard from in the last two and a half minutes.
- Your Mac reads its own usage once a minute, so a borrower can overshoot a limit by
  what they use within that minute.
- **This week** in the app shows dollars lent and borrowed. These are API-price
  estimates, a fairness indicator only: the borrower's Mac meters each borrowed request
  and tells the lender's, which takes its word (it cannot see the answer). The
  *Friends* line under your usage bars estimates how much of each window went to them.

## What a friend's Mac sees

| | Sees | Never sees |
|---|---|---|
| The lender's Mac, of a borrowed request | the request line, `Host` and `Content-Length`; sizes and timing | your prompt, the answer, your other headers |
| The borrower's Mac | the answer to its own request | the lender's login |
| Everyone in a circle | names, away or working, each other's usage percentages | logins, prompts |
| The relay, when one is used | encrypted QUIC packets | everything else |

The details, and what each side could still do, are in
[docs/mpc-tls.md](docs/mpc-tls.md) (the cryptography) and [docs/p2p.md](docs/p2p.md)
(circles, peers and the app).

## Building from source

`./build.sh` needs Xcode with the macOS 26 SDK or newer and Rust via
[rustup](https://rustup.rs). It builds the peer (`mpc-tls/lembas-mpc`, both
architectures), compiles the app and agent (universal arm64 + x86_64), draws the app
icon, signs ad hoc, and writes `build/lembas.app`, `installer/lembas.zip` and
`installer/version.json`. `LEMBAS_SKIP_MPC=1 ./build.sh` skips the Rust build for quick
work on the app; such a build has no peer, so it can neither lend nor borrow.

- `src/PoolBar.swift`: the menu bar app
- `src/Agent.swift`: the local agent
- `src/Peer.swift`: the agent's side of the peer (its child process and control channel)
- `src/PrivateBorrow.swift`: sending a borrowed request through the peer
- `src/Login.swift`: connecting a claude.ai subscription (OAuth with PKCE)
- `src/HTTPServer.swift`: small HTTP server shared by the agent and login
- `src/Logo.swift`: the logo, drawn in code (app icon, badge, menu bar icon)
- `mpc-tls/lembas-mpc/`: the peer and its cryptography, in Rust ([its README](mpc-tls/README.md))
- `site/`: the landing page and the invite page, published to GitHub Pages

**Releasing:** bump `CFBundleShortVersionString` in `resources/Info.plist`, push, then
push a matching tag (`git tag v1.4.2 && git push origin v1.4.2`). The release workflow
builds, waits for approval, signs and publishes; apps pick it up within a minute.

## Where things live

| Path | What |
|---|---|
| `~/.config/lembas.json` | your name and the secret the app uses to talk to the agent (0600) |
| `~/.config/lembas-login.json` | your claude.ai login, kept fresh by the agent (0600) |
| `~/Library/Application Support/lembas/` | the agent's own copy of itself and the peer |
| `…/lembas/peer/` | the Mac's key (`peer.key`), the circles, your lending settings, the week's ledger |
| `~/Library/Logs/lembas-agent.log` | the agent's log (never prompt content) |

## Notes

- `LEMBAS_PROFILE=<name>` runs a second person side by side on one Mac (own config,
  agent on port 8789 or `LEMBAS_AGENT_PORT`, Claude Code settings in
  `~/.claude-<name>`), handy for testing invites. Setting `"pretendLimited": true` in a
  profile's config makes every model request borrow. `LEMBAS_APPEARANCE=light|dark`
  forces an appearance.
- Not every 429 is a usage limit. Transient `rate_limit_error`s are passed back so
  Claude Code retries; only real usage-limit responses move a request to a friend.
- The agent serves only Claude Code on this Mac, and only model requests are ever
  borrowed: Claude Code's account and usage screens always show your own login.

## License

[MIT](LICENSE)
