# Circles and peers: lembas with no server

How friends' Macs lend to each other directly. Nobody holds anyone else's login, and
there is no server to run: each Mac runs a **peer**, the peers of a **circle** find each
other over [iroh](https://iroh.computer), and a borrowed request goes Mac to Mac through
the cryptography in [mpc-tls.md](mpc-tls.md) (the spliced token record and the limit
proof).

## Decisions

- **No leaders, no admins.** Each login stays on its owner's Mac, so the only real
  decision is bilateral: *do I lend to Maya?* A circle is just the list of people who
  may ask. Anyone in it can invite; lending stays each lender's own choice, per person;
  removal is a signed note that every Mac honours when it sees it (and anyone can be
  invited back).
- **Identity is the Mac's key.** Each peer has an Ed25519 key, generated on first run
  and kept at `<dir>/peer.key` (0600). Its public half is both who you are and, as the
  iroh endpoint id, how you are reached. One person with two Macs is two members.
- **iroh for the network.** QUIC between peers, NAT hole punching, a relay from n0
  when that fails. The relay carries encrypted QUIC and holds no login; it is a server
  in the path, so the promise is *no server ever holds a login or sees your traffic*,
  not *nothing in between*. Peers authenticate each other by key, and iroh's TLS is the
  link encryption.
- **Lenders must be awake.** A peer lends only while its Mac is up. A Mac that stays on
  makes a good lender.
- **The borrower proves its limit.** No Mac can look up another's usage, so a borrower
  proves to each lender, in zero knowledge, what Anthropic says about its own usage
  ([the limit proof](mpc-tls.md#the-limit-proof)).

## The circle

A circle (`circle.rs`) is a set of **memberships**, each signed by the inviter over
`(circle, member, name, invited_by, at)`; the founder's by itself. Merging accepts a
membership when its signature checks and its inviter was a member then, in rounds until
nothing is new, so order does not matter and no Mac is an authority. A **removal** is
signed by any member; a later membership reinstates; nobody removes the founder.

**Invite links** are `lembas://join/<base64url JSON>`: circle id, the inviter's key,
its relay URL and direct addresses, a one-time 16-byte secret, an expiry (7 days). The
newcomer shows the secret to the inviter's Mac, which signs its membership and replies
with the circle. The two lend to each other from then on; everyone else in the circle
starts with lending to the newcomer off.

The app sends an invite as its **invite page**,
`https://bodino.github.io/lembas/join#invite=<the same payload>&from=<inviter's name>`
(`site/join.html`, published by `.github/workflows/pages.yml`): download the app, then
a *Join* button that opens the `lembas://` link. The payload is in the fragment, which
a browser never sends, so the host of the page sees no invites; the page loads no
scripts but its own and is never fetched by the app, which reads the payload out of a
pasted page link itself. The name is only the page's greeting.

**More than one circle.** Someone who already has the app is already in a circle, their
own or the one they joined first, so an invite from a friend in another has to be
something they can take. Joining adds the friend's circle and keeps the first: the Mac
holds a list of circles (`circle.json` the first, `joined.json` the others), the app
shows the people of all of them as one list, and lending, borrowing and presence go by
*is in a circle with me*. The Mac's own invites stay to its first circle, so taking
Maya's invite does not show Maya's friends to the people one invites afterwards. A
sync carries one circle, so two Macs that share two sync twice. Removing someone signs
a removal in each circle shared with them; where they are the founder, whom nobody
removes, the Mac signs its own removal from that circle instead, tells the others and
forgets it. That reaches only the Macs that are up at the time: the rest keep listing
the one who left until one of them removes it.

## The peer

`lembas-mpc peer` is one process per Mac (`peer.rs`). It listens on an iroh endpoint
with ALPN `lembas/p2p/1` and speaks to members over bidirectional streams; the first
byte says what the stream is for. Everything but a join is refused from a non-member.

| Stream | Who opens it | What happens |
|---|---|---|
| join | a newcomer with an invite link | shows the one-time secret from the link; the inviter signs its membership, replies with the circle, lends to it by default |
| sync | any member, every 30 s and after a change | each side sends the circle (signed memberships and removals, merged on arrival), its presence, its iroh address, and what it borrowed from the other lately |
| limit | a would-be borrower | the limit proof; the lender keeps the proof until the window resets |
| borrow | a borrower | the lender runs its side of a borrowing session with its own token; each request goes through the gate |

**The lending gate**, per request: the request line is a model request (`POST
/v1/messages` or `POST /v1/messages/count_tokens`; the owner's profile and usage are
never lent); the borrower is in a circle with this Mac; the owner set *lend to them*; a
limit proof of theirs is current; the owner's own usage (read every minute with its own
token, and no older than three minutes) is under its limits (`week`, 60%; `away5h`,
70%); and while the owner is working, the borrower is one allowed *while I'm working*.
Then the lease is the owner's token. Anything else is a `Refused` the borrower's proxy
turns into an HTTP error, and the session stays up.

**Presence**: name, away or working, lending on, five-hour and week utilization, and
*room* (whether the owner's own limits would allow a lend right now). A borrower picks
the lender with the most of its five-hour window left among those with room heard from
in the last 2.5 minutes.

**Borrowing** is a local proxy on a Unix socket (`local.rs`): for each request it picks
a lender, proves its limit to it if that lender has no current proof, opens or reuses a
borrowing session, and relays. If nobody can lend the request fails with a `503` and
the agent hands Claude Code Anthropic's own limit error.

**The week's ledger.** A lender cannot see what a borrowed request cost, so the
borrower's agent meters it (tokens out of the response, at API prices) and tells its
peer, which writes it into its own book and tells the lender's peer on the next sync.
The lender takes the borrower's word, bounded at $10 a request. Both keep entries for
eight days; the app's *This week* tiles and each person's totals come from this book.
The agent also reports what the Mac's own requests cost, which never leaves the Mac: it
is the other half of the *Friends* estimate under the usage bars (each window's
utilization split by dollars, friends' against one's own).

**Control**: with `--control` the peer takes JSON lines on stdin and answers one line
each on stdout, plus a `status` event every 30 s. Commands: `status`, `found`, `invite`
(returns a link), `join {link}`, `lend {member, to, while_working}`, `policy {away5h,
week, borrow_at, away_after_minutes}`, `away {away}`, `remove {member}`, `sync`,
`report {lender, usd, model}`, `spent {usd}`.

**On disk**, in `--dir`: `peer.key`, `circle.json` and `joined.json`, `settings.json`
(limits and who is lent to), `ledger.json`, `own.json`.

## In the app

- **The agent** (`Agent.swift`, `Peer.swift`, `PrivateBorrow.swift`) runs
  `lembas-mpc peer --dir <Application Support/lembas/…/peer> --name … --token-file …
  --control --socket …` as a child, restarts it if it dies, and speaks its control
  channel. Borrowed requests go to the peer's socket. The agent's config
  (`~/.config/lembas.json`, 0600) is `{"name", "secret"}`; the app shows the secret to
  the agent's endpoints: `GET /lembas/status`, `POST /lembas/cmd` (forwarded to the
  peer), `POST /lembas/leave`. The agent flips the peer to away after the owner's idle
  time and back on the next request, unless the owner flipped the switch.
- **The login** stays on the Mac: `Login.swift` writes Claude Code's OAuth tokens to
  `~/.config/lembas-login.json` (0600); the agent refreshes the access token when it is
  about to expire; the peer re-reads the file at each use. Nobody else ever holds it.
- **The app** (`PoolBar.swift`): the first screen asks for a name and either an invite
  link (the invite page's, or `lembas://join/…`, also as a clickable link) or *Start a
  Circle*; the checklist then connects the subscription. The main screen shows your
  usage with the friends' share, *This week* (lent and borrowed), and *People*. Each
  person's page has the two lending switches (*When I'm away*, *While I'm working*),
  what they lend you, and *Remove from Circle*. *Invite a friend…* makes a one-time
  link; *Accept an invite…* joins another circle; the gear menu has *Leave Circle…*,
  which stops the peer and deletes its key, the circles and the login on this Mac.

## Tests and trying it

`cargo test --release` in `mpc-tls/lembas-mpc` covers the circle (a chain of invites
from the founder, a stranger's invite refused, a forged name refused, another Mac
rebuilding the circle from the state, removal and reinstatement, merges converging) and
the peer: `two_peers_lend_and_borrow` (two peers in one process on loopback with relays
off, tlsn's test server for the API; a borrow refused for lack of a proof, accepted
after proving, refused again once the lender stops lending), `a_mac_in_two_circles`,
`only_model_requests_are_lendable` and `friends_share_of_a_window`.

Two peers by hand on one Mac, each with a token in `LEMBAS_TOKEN`:

```
lembas-mpc peer --dir a --name Alice --found --invite --control
lembas-mpc peer --dir b --name Bob --join lembas://join/… --control --listen 127.0.0.1:8789
curl http://127.0.0.1:8789/v1/messages …
```

`--borrow-at`, `--away5h` and `--week` lower the thresholds when the accounts at hand
are not at their limits. In the app, a second profile does the same job: see
`LEMBAS_PROFILE` and `pretendLimited` in the README.

## What's left

1. **Presence privacy.** Members see each other's utilization numbers. Sending only
   *room* and *away* is enough for picking a lender.
2. **A *Lend to Sam?* prompt** when someone you did not invite joins. Today it is the
   switch on their page, off until you turn it on.
3. **Hardening**: rate limits on streams per peer; a power assertion while lending on
   mains; a lembas relay if n0's public ones rate-limit.
4. The open items of the cryptography are in [mpc-tls.md](mpc-tls.md#open): the proof
   inside the borrowing session, account binding, a cryptographer's review.
