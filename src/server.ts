import http from "node:http";
import { spawn } from "node:child_process";
import { accessSync, chmodSync, constants as fsConstants, fchmodSync, fstatSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Ledger, type LendPolicy, type LendRule } from "./ledger.ts";
import { WebSocketConnection } from "./ws.ts";

type User = {
  token: string; // what this person puts in Claude Code to talk to the pool
  // Legacy: an sk-ant-oat01-... from `claude setup-token`, from before the login flow.
  // Dropped the moment the member connects their subscription (OAuth in the ledger).
  claudeToken?: string;
  // The invite they joined with, kept until they connect a subscription: leaving before
  // that (going back during setup) makes the code valid again.
  invite?: { code: string; by?: string; expiresAt: number };
};

type Config = {
  port?: number;
  host?: string;
  upstream?: string;
  statePath?: string;
  // How long a token is skipped after a usage-limit 429 when Anthropic gives no retry-after.
  limitCooldownMinutes?: number;
  // How long to trust Anthropic's usage numbers; the endpoint is aggressively rate-limited.
  usageCacheSeconds?: number;
  // A member may borrow only while one of their own usage windows is at least this full
  // (percent), as read from Anthropic with their token. Default 90. Lower it for tests.
  borrowAtPercent?: number;
  // Members allowed to invite and remove people from the menu bar app.
  admins?: string[];
  // Public HTTPS address from Tailscale Funnel, e.g. "https://mac.tail1234.ts.net".
  // When set, invite codes use it and the pool also listens on 127.0.0.1 for Funnel.
  publicUrl?: string;
  // One-time invite codes, redeemed by the menu bar app for that member's pool token.
  invites?: Record<string, { name: string; by?: string; expiresAt: number }>;
  // Private borrowing (see docs/mpc-tls.md): where the helper built by ./build.sh
  // lives. `roots` and `serverName` exist for tests against tlsn's fixture server.
  mpc?: { helper?: string; roots?: "mozilla" | "fixture"; serverName?: string };
  users: Record<string, User>;
};

const CONFIG_PATH = process.env.POOL_CONFIG ?? "config.json";
const config: Config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
const users = config.users;
const UPSTREAM = (config.upstream ?? "https://api.anthropic.com").replace(/\/$/, "");
const LIMIT_COOLDOWN_MS = (config.limitCooldownMinutes ?? 20) * 60_000;
// Lending checks against this, so keep it fresh; borrowed calls no longer bust it,
// because Anthropic rate-limits the usage endpoint hard.
const USAGE_CACHE_MS = (config.usageCacheSeconds ?? 60) * 1000;
const BORROW_AT_PERCENT = config.borrowAtPercent ?? 90;
// One usage fetch; lenders are probed in parallel, and the helper waits 30 s in all.
const USAGE_TIMEOUT_MS = 6_000;
// Members' requests to the pool carry JSON settings and reports, never model calls.
const MAX_BODY = 64 * 1024;
// A private session is closed after this long; the agent opens a fresh one, so the
// pool re-checks membership and the lending policy from scratch at least daily.
const SESSION_MAX_MS = 24 * 3_600_000;
const ledger = new Ledger(config.statePath ?? "state.json");

// Borrowing is private, and only private: it needs the MPC helper. Without it this
// pool cannot lend at all; the route says so and members' agents pause borrowing.
const MPC_HELPER = config.mpc?.helper ?? fileURLToPath(new URL("../build/lembas-mpc", import.meta.url));
// A borrower's share of the handshake plus a body up to the helper's 64 MB limit.
// Over a whole session; the helper bounds each request on its own.
const MPC_MAX_FROM_BORROWER = 8 * 1024 * 1024 * 1024;
const UPSTREAM_URL = new URL(UPSTREAM);
function mpcAvailable(): boolean {
  try {
    accessSync(MPC_HELPER, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

// Claude Code's OAuth client. The login flow runs on each member's machine; the pool
// only ever talks to the token endpoint to refresh what they deposited.
const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token";

// ---------- which credential does this member use upstream? ----------

const refreshInFlight = new Map<string, Promise<string | null>>();

// Which login a member's name currently stands for. Bumped when they deposit a new
// login and when they are removed, so a refresh that started under the old one can't
// write its result over the new one (or resurrect a removed member's tokens for a
// newcomer with the same name).
const oauthGeneration = new Map<string, number>();
const generationOf = (name: string) => oauthGeneration.get(name) ?? 0;
const newGeneration = (name: string) => oauthGeneration.set(name, generationOf(name) + 1);

// Refresh a member's stored OAuth token (rotation: store the new refresh token).
async function refreshOAuth(name: string): Promise<string | null> {
  const generation = generationOf(name);
  const key = `${name}#${generation}`;
  const existing = refreshInFlight.get(key);
  if (existing) return existing;
  const task = (async () => {
    const tokens = ledger.oauth(name);
    if (!tokens) return null;
    // Still the same member and the same login once the network answers?
    const unchanged = () => generationOf(name) === generation && Object.hasOwn(users, name)
      && ledger.oauth(name)?.refreshToken === tokens.refreshToken;
    try {
      const res = await fetch(OAUTH_TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "claude-cli/2.1.310" },
        body: JSON.stringify({
          grant_type: "refresh_token",
          refresh_token: tokens.refreshToken,
          client_id: OAUTH_CLIENT_ID,
          scope: "user:inference user:profile",
        }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!unchanged()) return null; // someone else's result now; theirs is the one that counts
      if (res.status === 400 || res.status === 401) {
        // The refresh token itself was rejected (revoked, rotated elsewhere): this
        // login is gone and the member has to connect again.
        console.log(`[pool] ${name}'s login was rejected by Anthropic (HTTP ${res.status}); their subscription is disconnected`);
        ledger.clearOAuth(name);
        return null;
      }
      if (!res.ok) throw new Error(`refresh failed: HTTP ${res.status}`);
      const body = (await res.json()) as { access_token?: string; refresh_token?: string; expires_at?: number; expires_in?: number };
      if (!body.access_token || !body.refresh_token) throw new Error("refresh response missing tokens");
      let expiresAt = body.expires_at ?? Date.now() + (body.expires_in ?? 3600) * 1000;
      if (expiresAt < 1e12) expiresAt *= 1000; // seconds -> ms
      if (!unchanged()) return null;
      ledger.setOAuth(name, { accessToken: body.access_token, refreshToken: body.refresh_token, expiresAt });
      return body.access_token;
    } catch (err) {
      // Network trouble or an odd answer: keep the login and try again next time.
      console.log(`[pool] ${name}'s OAuth refresh failed (${(err as Error).message}); keeping their login for now`);
      return null;
    } finally {
      refreshInFlight.delete(key);
    }
  })();
  refreshInFlight.set(key, task);
  return task;
}

// The bearer token to use for `name` upstream: their OAuth token (refreshed when within
// 2 minutes of expiry), or a legacy setup token. Throws when there is none that works,
// so a lease is refused rather than made with a credential known to be bad.
async function anthropicToken(name: string): Promise<string> {
  const tokens = ledger.oauth(name);
  if (tokens) {
    if (tokens.expiresAt - 120_000 > Date.now()) return tokens.accessToken;
    const refreshed = await refreshOAuth(name);
    if (refreshed) return refreshed;
    // Whatever is stored now is what counts: the refresh steps aside when a new login
    // was deposited meanwhile, and the token read above belongs to the old one.
    const current = Object.hasOwn(users, name) ? ledger.oauth(name) : undefined;
    if (!current) throw new Error(`${name} has not connected a subscription`);
    if (current.expiresAt > Date.now()) return current.accessToken; // the new login, or a refresh hiccup with the old one still valid
    throw new Error(`${name}'s login could not be refreshed`);
  }
  const legacy = users[name]?.claudeToken;
  if (legacy && legacy.startsWith("sk-ant-")) return legacy;
  throw new Error(`${name} has not connected a subscription`);
}

// ---------- how much of each subscription is left ----------

type Utilization = {
  fiveHour: number;
  sevenDay: number;
  resetsAt: number | null;
  sevenDayResetsAt: number | null;
  // Every window Anthropic reports for this account (the two above plus any
  // model-specific ones, e.g. a weekly Opus window), by its name, in percent.
  windows: Record<string, number>;
  // Anthropic has locked the account out of some window regardless of the percentage.
  locked: boolean;
};
type UsageProbe = { usage: Utilization | null; status: number | null };
const usageCache = new Map<string, { at: number } & UsageProbe>();

// Asks Anthropic the same thing Claude Code's /usage command asks: how full are this
// person's usage windows, as a percentage. Cached because Anthropic rate limits this
// endpoint hard. `status` is the HTTP status of the last real answer (401 means the
// login is dead), null when nothing came back.
const probing = new Map<string, Promise<UsageProbe>>();
async function probeUsage(name: string, maxAgeMs = USAGE_CACHE_MS): Promise<UsageProbe> {
  const cached = usageCache.get(name);
  if (cached && Date.now() - cached.at < maxAgeMs) return cached;
  // One question upstream per member at a time, whoever asks: a burst of status reads,
  // or a lease probing every lender, must not fan out into a burst at Anthropic, where
  // this endpoint rate-limits hard and one 429 would leave everyone "unknown".
  let inFlight = probing.get(name);
  if (!inFlight) {
    inFlight = fetchUsage(name).finally(() => probing.delete(name));
    probing.set(name, inFlight);
  }
  return inFlight;
}

async function fetchUsage(name: string): Promise<UsageProbe> {
  const generation = generationOf(name);
  let usage: Utilization | null = null;
  let status: number | null = null;
  try {
    const token = await anthropicToken(name);
    const res = await fetch(UPSTREAM + "/api/oauth/usage", {
      headers: {
        authorization: `Bearer ${token}`,
        // The User-Agent shape is mandatory: without "claude-code/<version>" this endpoint 429s persistently.
        "user-agent": "claude-code/2.1.0",
        "anthropic-beta": "oauth-2025-04-20",
        "content-type": "application/json",
      },
      signal: AbortSignal.timeout(USAGE_TIMEOUT_MS),
    });
    status = res.status;
    if (res.ok) {
      const body = (await res.json()) as Record<string, { utilization?: unknown; resets_at?: unknown; locked_reason?: unknown } | null>;
      const windows: Record<string, number> = {};
      let locked = false;
      for (const [key, value] of Object.entries(body)) {
        if (key === "extra_usage" || typeof value !== "object" || value === null) continue;
        if (typeof value.utilization === "number" && Number.isFinite(value.utilization)) {
          windows[key] = Math.min(100, Math.max(0, value.utilization));
        }
        if (value.locked_reason) locked = true;
      }
      const when = (v: unknown) => {
        const t = typeof v === "string" ? Date.parse(v) : NaN;
        return Number.isFinite(t) ? t : null;
      };
      // The two windows lending is measured against must be there as numbers; an
      // answer of another shape (a changed API, a proxy page) is "unknown", not
      // "idle", so nobody lends on it.
      if ("five_hour" in windows && "seven_day" in windows) {
        usage = {
          fiveHour: windows.five_hour,
          sevenDay: windows.seven_day,
          resetsAt: when(body.five_hour?.resets_at),
          sevenDayResetsAt: when(body.seven_day?.resets_at),
          windows,
          locked,
        };
      }
    }
  } catch {
    // Network or parse failure, or no credential; fall through with null.
  }
  // A new login (or a removal) landed while Anthropic answered: this is the old
  // account's usage and says nothing about the new one.
  if (generationOf(name) !== generation || !Object.hasOwn(users, name)) return { usage: null, status: null };
  const probe = { at: Date.now(), usage, status };
  usageCache.set(name, probe);
  return probe;
}

async function fetchUtilization(name: string): Promise<Utilization | null> {
  return (await probeUsage(name)).usage;
}

// Has this member really run out? True when any of their windows is at the threshold
// or Anthropic has locked one. Read with their own token, so a borrower can't claim a
// limit they don't have; a model-specific window counts, since the pool can't see
// which model a private request is for.
function atLimit(usage: Utilization): boolean {
  return usage.locked || Object.values(usage.windows).some((pct) => pct >= BORROW_AT_PERCENT);
}

// Whether `caller` may borrow at all right now, before any lender is considered.
type BorrowGate = { ok: true } | { ok: false; reason: "unconnected" | "usage_unknown" | "not_at_limit" };
async function borrowGate(caller: string): Promise<BorrowGate> {
  if (!ledger.oauth(caller)) return { ok: false, reason: "unconnected" };
  const usage = await fetchUtilization(caller);
  if (!usage) return { ok: false, reason: "usage_unknown" };
  return atLimit(usage) ? { ok: true } : { ok: false, reason: "not_at_limit" };
}

// ---------- who may borrow from whom, right now ----------
//
// Lending follows the owner's day. While they're away (no own Claude Code use for a
// while, or "I'm done for today") the people they picked may borrow until the 5-hour
// window reaches the away limit. People with a "while working" allowance may also
// borrow while the owner works, up to that 5-hour level. The week limit always
// applies. All limits are compared with Anthropic's own live utilization, so nothing
// is estimated or attributed — and if it can't be read, nobody borrows.

const FIVE_HOURS_MS = 5 * 3_600_000;

// The part of an owner's window utilization that friends used: utilization split by
// estimated dollars spent in the window (own direct use is reported by the agent,
// borrowed use is metered here). Use outside lembas (claude.ai web, desktop) isn't seen,
// so heavy off-lembas use makes this read high rather than low.
function lentShare(owner: string, utilization: number, resetsAt: number | null, spanMs: number): number {
  const since = resetsAt !== null ? resetsAt - spanMs : Date.now() - spanMs;
  const { total, borrowed } = ledger.spendSince(owner, since);
  return total > 0 ? utilization * (borrowed / total) : 0;
}

type Availability = {
  headroom: number; // percentage points left in the 5-hour window (> 0 only if the week has room too)
  // Points left in each window, each in its own unit: a percent of a week is worth many
  // percents of a 5-hour window, by a ratio Anthropic doesn't publish, so the two are
  // never compared — borrowing just needs room in both.
  left5h?: number;
  leftWeek?: number;
  reason: "away" | "working" | "off" | "unconnected" | "parked" | "unknown" | "full" | "weekFull";
};

async function availability(owner: string, consumer: string): Promise<Availability> {
  if (!ledger.oauth(owner)) return { headroom: 0, reason: "unconnected" };
  if (ledger.isParked(owner)) return { headroom: 0, reason: "parked" };
  const rule = ledger.lendRule(owner, consumer);
  const away = ledger.presence(owner).away;
  const policy = ledger.policy(owner);
  const ceiling5h = Math.max(rule.away && away ? policy.away5h : 0, rule.working5h);
  if (ceiling5h <= 0) return { headroom: 0, reason: "off" };
  const usage = await fetchUtilization(owner);
  if (!usage) return { headroom: 0, reason: "unknown" };
  if (usage.locked) return { headroom: 0, reason: "full" }; // Anthropic says no, whatever the numbers
  // What they allow minus what's used, per window. Room in both is required.
  const left5h = ceiling5h - usage.fiveHour;
  const leftWeek = policy.week - usage.sevenDay;
  // The week is a gate: once it's used up they can't lend, whatever the 5-hour room.
  if (leftWeek <= 0) return { headroom: 0, reason: "weekFull" };
  if (left5h <= 0) return { headroom: 0, reason: "full" };
  return { headroom: left5h, left5h, leftWeek, reason: away ? "away" : "working" };
}

// Whoever is lending to `caller` right now, most headroom first.
async function lenderOrder(caller: string): Promise<string[]> {
  const others = Object.keys(users).filter((name) => name !== caller);
  const probed = await Promise.all(others.map(async (name): Promise<[string, number]> => [name, (await availability(name, caller)).headroom]));
  return probed.filter(([, headroom]) => headroom > 0).sort((a, b) => b[1] - a[1]).map(([name]) => name);
}

// ---------- HTTP plumbing ----------

function authenticate(req: http.IncomingMessage): string | undefined {
  const presented = presentedToken(req);
  if (!presented) return undefined;
  return Object.keys(users).find((name) => safeEqual(presented, users[name].token));
}

function presentedToken(req: http.IncomingMessage): string | undefined {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  return (req.headers["x-api-key"] as string | undefined) ?? bearer;
}

// A request with no token at all is not a guess: a browser on the invite page asks
// for /favicon.ico, and a probe asks for /. Only a wrong token counts toward the
// lockout, or a few page loads would lock a guest out of their own invite.
function recordUnauthenticated(req: http.IncomingMessage): void {
  if (presentedToken(req)) recordFailure(clientId(req));
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

// Same shape as Anthropic's own errors, so Claude Code displays them properly.
function sendError(res: http.ServerResponse, status: number, type: string, message: string): void {
  sendJson(res, status, { type: "error", error: { type, message } });
}

// ---------- routes ----------

async function status(caller: string): Promise<unknown> {
  // `privateBorrowing`: whether this pool can lend at all (it has the helper); the
  // name is from when the readable relay still existed, and older apps read it.
  const out: Record<string, unknown> = { you: caller, canInvite: isAdmin(caller), privateBorrowing: mpcAvailable() };
  const borrowingFrom: Record<string, unknown> = {};
  for (const name of Object.keys(users)) {
    if (name === caller) {
      const usage = await fetchUtilization(name);
      const weekBy = ledger.borrowedThisWeekBy(name);
      const lending: Record<string, unknown> = {};
      for (const consumer of Object.keys(users)) {
        if (consumer === name) continue;
        const rule = ledger.lendRule(name, consumer);
        lending[consumer] = {
          away: rule.away,
          working5h: rule.working5h,
          borrowedThisWeekUsd: round(weekBy[consumer] ?? 0),
        };
      }
      const borrowedBy = ledger.borrowedByFrom(name);
      out[name] = {
        subscriptionConnected: Boolean(ledger.oauth(name)),
        // Joined with an invite and not set up yet: going back is safe and gives it back.
        inviteReturnable: Boolean(users[name].invite),
        utilization: usage ? {
          fiveHour: usage.fiveHour,
          sevenDay: usage.sevenDay,
          fiveHourResetsAt: usage.resetsAt,
          // How much of each window friends used (estimate, see lentShare).
          lentFiveHour: round1(lentShare(name, usage.fiveHour, usage.resetsAt, FIVE_HOURS_MS)),
          lentSevenDay: round1(lentShare(name, usage.sevenDay, usage.sevenDayResetsAt, 7 * 86_400_000)),
        } : null,
        policy: ledger.policy(name),
        presence: ledger.presence(name),
        lending,
        borrowedFromMeThisWeekUsd: {
          total: round(ledger.borrowedThisWeekOn(name)),
          byCaller: Object.fromEntries(Object.entries(weekBy).map(([who, usd]) => [who, round(usd)])),
        },
        borrowedFromMeLast5hUsd: round(ledger.borrowedInLastOn(name, FIVE_HOURS_MS)),
        borrowedByMeThisWeekUsd: {
          total: round(Object.values(borrowedBy).reduce((a, b) => a + b, 0)),
          byOwner: Object.fromEntries(Object.entries(borrowedBy).map(([who, usd]) => [who, round(usd)])),
        },
        borrowedByMeLast5hUsd: round(Object.values(ledger.borrowedByFrom(name, FIVE_HOURS_MS)).reduce((a, b) => a + b, 0)),
      };
    } else {
      // The caller's view of each other member: can I borrow from them right now, and
      // why (not). Their own per-person choices for others are not exposed.
      const { headroom, reason, left5h, leftWeek } = await availability(name, caller);
      borrowingFrom[name] = {
        reason,
        availablePoints: round1(headroom),
        left5h: left5h === undefined ? null : round1(Math.max(0, left5h)),
        leftWeek: leftWeek === undefined ? null : round1(Math.max(0, leftWeek)),
        away: ledger.presence(name).away,
        subscriptionConnected: Boolean(ledger.oauth(name)),
      };
    }
  }
  const me = out[caller] as Record<string, unknown> | undefined;
  if (me) me.borrowingFrom = borrowingFrom;
  return out;
}

// ---------- borrowing: a session of spliced token records, over a WebSocket ----------
//
// The agent connects here when its member's own login is at a usage limit and keeps
// the connection for as long as it has requests: one session, many TLS connections to
// Anthropic, one spliced token record per request. The pool bridges binary frames to
// `lembas-mpc pool --stdio`, which relays the agent's TLS bytes and writes the token
// records, and can read nothing else (docs/mpc-tls.md). The helper asks for a token
// per request over fd 3, and a lender is picked here each time, after checking with
// Anthropic that the borrower really is out: the pool holds every member's login, so
// it reads the borrower's own usage rather than take their word. Because the pool
// cannot see Anthropic's answers, the agent reports each request's outcome in a text
// frame, naming the request number the helper gave it: usage to meter, or a usage
// limit on the lender's side. Those reports are checked against Anthropic too before
// a lender is parked for everyone; an unconfirmed one only steers this session away
// from that lender for a few minutes.

let nextLease = 1;
// Each session is a helper process of some 150 MB; a member gets a couple (the agent
// keeps one, and a restart may overlap the old one briefly), not a fleet.
const MAX_SESSIONS_PER_MEMBER = 2;
const AVOID_MS = 3 * 60_000;
const MAX_REPORT = 4096;
const MAX_REPORTS_PER_MINUTE = 300; // five Claude Code windows with background calls stay well under

// For the log: a member-supplied string with nothing that could pass for another line.
function safe(value: unknown, max = 200): string {
  return String(value ?? "").replace(/[^\x20-\x7e]/g, "?").slice(0, max);
}
type PrivateSession = {
  caller: string;
  leases: Map<number, { owner: string; at: number }>;
  avoid: Map<string, number>; // lender -> until when this session skips them
  ws: WebSocketConnection;
};
const privateSessions = new Map<string, Set<PrivateSession>>();

// Every live session of a member ends: on removal, their open socket must not keep
// drawing leases.
function closeSessions(name: string, reason: string): void {
  for (const session of privateSessions.get(name) ?? []) {
    if (!session.ws.closed) {
      session.ws.send(JSON.stringify({ type: "error", code: "closed", message: reason }));
      session.ws.terminate(); // now, not after a close handshake an in-flight request could ride out
    }
  }
}

async function borrowPrivately(ws: WebSocketConnection, caller: string, _url: URL): Promise<void> {
  const fail = (code: string, message: string) => {
    ws.send(JSON.stringify({ type: "error", code, message }));
    ws.close(1000);
  };
  if (!mpcAvailable()) return fail("unsupported", "This pool has no MPC helper, so it can't lend.");
  const mine = privateSessions.get(caller) ?? new Set<PrivateSession>();
  if (mine.size >= MAX_SESSIONS_PER_MEMBER) return fail("busy", `You already have ${mine.size} sessions open with this pool.`);
  const session: PrivateSession = { caller, leases: new Map(), avoid: new Map(), ws };
  mine.add(session);
  privateSessions.set(caller, mine);
  const poolToken = users[caller].token; // a rotated token means a different member

  const child = spawn(
    MPC_HELPER,
    [
      "pool", "--stdio",
      "--server", `${UPSTREAM_URL.hostname}:${UPSTREAM_URL.port || 443}`,
      "--server-name", config.mpc?.serverName ?? UPSTREAM_URL.hostname,
      "--roots", config.mpc?.roots ?? "mozilla",
      "--control-fd", "3",
    ],
    // Tokens reach the helper over fd 3, one per request, and nowhere else.
    { env: { RUST_LOG: process.env.RUST_LOG ?? "warn" }, stdio: ["pipe", "pipe", "pipe", "pipe"] },
  );
  const control = child.stdio[3] as import("node:stream").Duplex;
  const started = Date.now();
  let fromBorrower = 0;
  let requests = 0;
  const finish = () => {
    if (!ws.closed) ws.close(1000);
  };
  const controlSend = (message: object) => {
    if (control.writable) control.write(JSON.stringify(message) + "\n");
  };
  child.on("error", (err) => fail("helper", `The pool's MPC helper could not start: ${err.message}`));
  child.stdin.on("error", () => {}); // EPIPE once the helper has exited
  control.on("error", () => {});
  child.stderr.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString().split("\n")) if (line.trim()) console.log(`[mpc ${caller}] ${line.trim()}`);
  });
  const lifetime = setTimeout(() => {
    console.log(`[pool] ${caller}'s session reached its maximum age; closing it`);
    fail("closed", "This session reached its maximum age; open a new one.");
  }, SESSION_MAX_MS);

  // A lender for each request, as the helper asks.
  const leaseToken = async (id: number) => {
    try {
      if (!Object.hasOwn(users, caller) || users[caller].token !== poolToken) {
        controlSend({ type: "refuse", id, reason: "not_a_member" });
        return fail("closed", "You are no longer a member of this pool.");
      }
      const gate = await borrowGate(caller);
      if (!gate.ok) {
        console.log(`[pool] ${caller} asked to borrow but ${describeGate(gate.reason)}`);
        return controlSend({ type: "refuse", id, reason: gate.reason });
      }
      const now = Date.now();
      const order = (await lenderOrder(caller)).filter((name) => (session.avoid.get(name) ?? 0) < now);
      if (order.length === 0) return controlSend({ type: "refuse", id, reason: "no_capacity" });
      for (const owner of order) {
        let token: string;
        try {
          token = await anthropicToken(owner);
        } catch (err) {
          console.log(`[pool] ${owner} can't lend right now (${(err as Error).message}); trying the next lender`);
          continue;
        }
        // The awaits above may have outlived the membership.
        if (!Object.hasOwn(users, caller) || users[caller].token !== poolToken) {
          controlSend({ type: "refuse", id, reason: "not_a_member" });
          return fail("closed", "You are no longer a member of this pool.");
        }
        const req = nextLease++;
        session.leases.set(req, { owner, at: now });
        requests++;
        return controlSend({ type: "token", id, token, req });
      }
      controlSend({ type: "refuse", id, reason: "no_capacity" });
    } catch (err) {
      controlSend({ type: "refuse", id, reason: `lender lookup failed: ${(err as Error).message}` });
    }
  };
  let controlBuffer = "";
  control.on("data", (chunk: Buffer) => {
    controlBuffer += chunk.toString();
    let nl: number;
    while ((nl = controlBuffer.indexOf("\n")) >= 0) {
      const line = controlBuffer.slice(0, nl).trim();
      controlBuffer = controlBuffer.slice(nl + 1);
      if (!line) continue;
      let message: { type?: unknown; id?: unknown; req?: unknown };
      try {
        message = JSON.parse(line);
      } catch {
        console.log(`[pool] ${caller}'s helper sent a malformed control line`);
        continue;
      }
      if (message.type === "need_token" && typeof message.id === "number") void leaseToken(message.id);
      else if (message.type === "spliced" && typeof message.req === "number") {
        const lease = session.leases.get(message.req);
        if (lease) console.log(`[pool] ${caller} borrows ${lease.owner}'s token privately (request ${message.req})`);
      }
    }
  });

  // The bridge, with backpressure both ways.
  child.stdout.on("data", (chunk: Buffer) => {
    if (!ws.send(chunk)) child.stdout.pause();
  });
  ws.on("drain", () => child.stdout.resume());
  child.stdin.on("drain", () => ws.resume());
  let reportsThisMinute = 0;
  let reportMinute = 0;
  ws.on("message", (data: Buffer, isText: boolean) => {
    if (isText) {
      // A report is a line of JSON; anything bigger, or a flood of them, is not the agent.
      if (data.length > MAX_REPORT) return ws.close(1009, "report too large");
      const minute = Math.floor(Date.now() / 60_000);
      if (minute !== reportMinute) {
        reportMinute = minute;
        reportsThisMinute = 0;
      }
      if (++reportsThisMinute > MAX_REPORTS_PER_MINUTE) return ws.close(1008, "too many reports");
      void recordPrivateResult(session, data.toString());
      return;
    }
    {
      // The helper bounds each request; this only keeps Node's buffer honest over a
      // long session.
      fromBorrower += data.length;
      if (fromBorrower > MPC_MAX_FROM_BORROWER) return ws.close(1009, "too much data");
      if (!child.stdin.destroyed && child.stdin.writable && !child.stdin.write(data)) ws.pause();
    }
  });
  ws.on("close", () => {
    clearTimeout(lifetime);
    mine.delete(session);
    if (mine.size === 0) privateSessions.delete(caller);
    child.stdin.end();
    control.end();
    // The helper leaves on its own once its stdin ends; make sure of it.
    setTimeout(() => {
      if (child.exitCode === null) child.kill();
    }, 5000).unref();
    setTimeout(() => {
      if (child.exitCode === null) {
        console.log(`[pool] the MPC helper for ${caller} had to be killed`);
        child.kill("SIGKILL");
      }
    }, 10_000).unref();
    console.log(`[pool] ${caller}'s session ended after ${requests} requests (${Math.round((Date.now() - started) / 1000)} s)`);
  });
  child.on("exit", (code) => {
    child.stdout.resume();
    if (code !== 0 && !ws.closed) ws.send(JSON.stringify({ type: "error", code: "helper", message: `The pool's MPC helper failed (exit ${code}).` }));
    finish();
  });
  ws.send(JSON.stringify({ type: "session" }));
}

function describeGate(reason: "unconnected" | "usage_unknown" | "not_at_limit"): string {
  switch (reason) {
    case "unconnected": return "they have not connected a subscription";
    case "usage_unknown": return "their usage can't be read right now";
    case "not_at_limit": return `their own login is not at a usage limit (under ${BORROW_AT_PERCENT}%)`;
  }
}

// What the borrower says Anthropic answered to one request. Usage is taken as
// reported (bounded); a lender's limit or death is confirmed with Anthropic first.
async function recordPrivateResult(session: PrivateSession, text: string): Promise<void> {
  const { caller, leases } = session;
  let report: { type?: unknown; req?: unknown; status?: unknown; model?: unknown; usd?: unknown; forMs?: unknown; message?: unknown };
  try {
    report = JSON.parse(text);
  } catch {
    return console.log(`[pool] ${caller} sent a malformed report`);
  }
  const lease = typeof report.req === "number" ? leases.get(report.req) : undefined;
  if (!lease) return console.log(`[pool] ${caller} reported on an unknown request`);
  leases.delete(report.req as number);
  const owner = lease.owner;
  const elapsedMs = Date.now() - lease.at;
  const model = typeof report.model === "string" ? safe(report.model, 64) : undefined;
  switch (report.type) {
    case "result": {
      const usd = typeof report.usd === "number" && Number.isFinite(report.usd) && report.usd >= 0 && report.usd <= 10 ? report.usd : 0;
      if (usd > 0) ledger.record(owner, caller, usd);
      console.log(`[pool] ${caller} ${model ?? "request"} ~$${usd.toFixed(4)} via ${owner}'s token, privately (${(elapsedMs / 1000).toFixed(1)} s)`);
      return;
    }
    case "limit": {
      // Anthropic's numbers, at most 15 s old, decide; the usage endpoint lags a little
      // behind a fresh 429, so a window within a few points of the threshold counts.
      const probe = await probeUsage(owner, 15_000);
      if (probe.usage && (probe.usage.locked || Object.values(probe.usage.windows).some((pct) => pct >= BORROW_AT_PERCENT - 5))) {
        const forMs = typeof report.forMs === "number" && Number.isFinite(report.forMs) && report.forMs > 0
          ? Math.min(report.forMs, 6 * 60 * 60_000)
          : LIMIT_COOLDOWN_MS;
        ledger.park(owner, forMs);
        console.log(`[pool] ${owner}'s token is at its usage limit (${caller} reports, confirmed); parked for ${Math.round(forMs / 60_000)} min`);
      } else {
        session.avoid.set(owner, Date.now() + AVOID_MS);
        console.log(`[pool] ${caller} reports a usage limit on ${owner}'s token that Anthropic doesn't show; skipping that lender for this session for ${AVOID_MS / 60_000} min`);
      }
      return;
    }
    case "dead": {
      const probe = await probeUsage(owner, 15_000);
      if (probe.status === 401) {
        ledger.park(owner, 24 * 60 * 60_000);
        console.log(`[pool] ${owner}'s token is dead (${caller} got a 401, confirmed); parked for 24 h`);
      } else {
        session.avoid.set(owner, Date.now() + AVOID_MS);
        console.log(`[pool] ${caller} reports ${owner}'s token dead but it answers Anthropic; skipping that lender for this session for ${AVOID_MS / 60_000} min`);
      }
      return;
    }
    case "failed":
      console.log(`[pool] ${caller}'s private request on ${owner}'s token failed: ${safe(report.message)}`);
      return;
    default:
      console.log(`[pool] ${caller} sent an unknown report type for ${owner}'s token`);
  }
}

function round(usd: number): number {
  return Math.round(usd * 100) / 100;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

const isPercent = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;

// PUT /pool/share {"policy": {"away5h": 90, "week": 60, "awayAfterMinutes": 30},
//                  "lendTo": {"max": {"away": true, "working5h": 40}}}
// Either part may be sent alone. lendTo is merged into the stored rules: members named
// are set, members omitted keep their rule, so a partial update can't switch anyone on.
// Send {"away": false, "working5h": 0} to turn someone off.
async function setShare(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { policy?: unknown; lendTo?: unknown };
  try {
    body = JSON.parse(raw.toString());
} catch (err) {
    return sendError(res, 400, "invalid_request_error", 'Send JSON like {"lendTo":{"max":{"away":true,"working5h":0}}}.');
  }
  const { policy, lendTo } = body;
  if (policy === undefined && lendTo === undefined) {
    return sendError(res, 400, "invalid_request_error", "Send policy, lendTo, or both.");
  }

  let newPolicy: LendPolicy | undefined;
  if (policy !== undefined) {
    const p = policy as Partial<Record<keyof LendPolicy, unknown>>;
    if (typeof policy !== "object" || policy === null || !isPercent(p.away5h) || !isPercent(p.week) ||
        typeof p.awayAfterMinutes !== "number" || p.awayAfterMinutes < 5 || p.awayAfterMinutes > 24 * 60) {
      return sendError(res, 400, "invalid_request_error", "policy needs away5h and week (0–100) and awayAfterMinutes (5–1440).");
    }
    newPolicy = { away5h: p.away5h, week: p.week, awayAfterMinutes: p.awayAfterMinutes };
  }

  let rules: Record<string, LendRule> | undefined;
  if (lendTo !== undefined) {
    if (typeof lendTo !== "object" || lendTo === null || Array.isArray(lendTo)) {
      return sendError(res, 400, "invalid_request_error", "lendTo must be an object keyed by pool member.");
    }
    rules = {};
    for (const [consumer, raw] of Object.entries(lendTo as Record<string, unknown>)) {
      if (!Object.hasOwn(users, consumer)) return sendError(res, 400, "invalid_request_error", `Unknown pool member: ${consumer}.`);
      if (consumer === caller) return sendError(res, 400, "invalid_request_error", "You cannot lend to yourself.");
      const rule = raw as { away?: unknown; working5h?: unknown } | null;
      if (typeof rule !== "object" || rule === null || typeof rule.away !== "boolean" || !isPercent(rule.working5h)) {
        return sendError(res, 400, "invalid_request_error", `lendTo.${consumer} must be {"away": true|false, "working5h": 0–100}.`);
      }
      rules[consumer] = { away: rule.away, working5h: rule.working5h };
    }
  }

  if (newPolicy) ledger.setPolicy(caller, newPolicy);
  if (rules) ledger.setLendRules(caller, { ...ledger.lendRules(caller), ...rules });
  const who = Object.keys(users).filter((name) => name !== caller)
    .map((name) => [name, ledger.lendRule(caller, name)] as const)
    .filter(([, r]) => r.away || r.working5h > 0)
    .map(([name, r]) => `${name} (${[r.away && "away", r.working5h > 0 && `working ≤${r.working5h}%`].filter(Boolean).join(", ")})`)
    .join(", ") || "nobody";
  const pol = ledger.policy(caller);
  console.log(`[pool] ${caller} lends to ${who}; away ≤${pol.away5h}% 5h, week ≤${pol.week}%, away after ${pol.awayAfterMinutes} min`);
  sendJson(res, 200, await status(caller));
}

// PUT /pool/presence {"away": true} — "I'm done for today"; {"away": false} — "I'm back".
async function setPresence(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  let away: unknown;
  try {
    away = JSON.parse(raw.toString()).away;
} catch (err) {
    return sendError(res, 400, "invalid_request_error", 'Send {"away": true} or {"away": false}.');
  }
  if (typeof away !== "boolean") return sendError(res, 400, "invalid_request_error", "away must be true or false.");
  ledger.setPresence(caller, away);
  console.log(`[pool] ${caller} is ${away ? "done for today — lending" : "back"}`);
  sendJson(res, 200, await status(caller));
}

// The local fallback agent forwards normal traffic straight to Anthropic. These two
// endpoints let it keep the pool's accounting in sync without prompts leaving the machine:
// metered spend for calibration/allowances, and "my own token just hit its usage limit".
async function reportDirectUsage(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { usd?: unknown; model?: unknown };
  try {
    body = JSON.parse(raw.toString());
} catch (err) {
    return sendError(res, 400, "invalid_request_error", "Send {\"usd\": 0.0123}.");
  }
  const usd = body.usd;
  if (typeof usd !== "number" || !Number.isFinite(usd) || usd < 0 || usd > 10) {
    return sendError(res, 400, "invalid_request_error", "usd must be a number from 0 to 10.");
  }
  if (usd > 0) {
    ledger.record(caller, caller, usd); // also marks the caller as working (see ledger.presence)
  }
  sendJson(res, 200, { ok: true });
}

async function reportDirectLimit(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { forMs?: unknown };
  try {
    body = JSON.parse(raw.toString());
} catch (err) {
    return sendError(res, 400, "invalid_request_error", "Send {\"forMs\": 60000}.");
  }
  const forMs = body.forMs;
  if (typeof forMs !== "number" || !Number.isFinite(forMs) || forMs < 0 || forMs > 6 * 60 * 60_000) {
    return sendError(res, 400, "invalid_request_error", "forMs must be between 0 and 6 hours.");
  }
  if (forMs === 0) ledger.unpark(caller);
  else ledger.park(caller, forMs);
  usageCache.delete(caller); // the borrow gate must see the limit, not a minute-old number
  sendJson(res, 200, { ok: true, parkedUntil: ledger.parkedUntil(caller) });
}

// Served unauthenticated from ./installer: the join script and the invite page's logo.
// The app itself always comes from GitHub releases, never from a pool.
const INSTALLER_DIR = new URL("../installer/", import.meta.url);

// Kept in memory, re-read when the file on disk changes (checked at most every few
// seconds): these are public, and a visitor must not cost the pool a disk read each.
const installerCache = new Map<string, { body: Buffer; mtimeMs: number; checkedAt: number }>();
function installerFile(file: string): Buffer | null {
  const now = Date.now();
  const cached = installerCache.get(file);
  if (cached && now - cached.checkedAt < 5_000) return cached.body;
  try {
    const url = new URL(file, INSTALLER_DIR);
    const { mtimeMs } = statSync(url);
    const body = cached?.mtimeMs === mtimeMs ? cached.body : readFileSync(url);
    installerCache.set(file, { body, mtimeMs, checkedAt: now });
    return body;
  } catch {
    installerCache.delete(file);
    return null;
  }
}

function serveInstaller(res: http.ServerResponse, file: string): void {
  const types: Record<string, string> = {
    "join.sh": "text/x-shellscript; charset=utf-8",
    "logo.png": "image/png", // for the invite page
  };
  if (!types[file]) return sendError(res, 404, "not_found_error", "Not found.");
  const body = installerFile(file);
  if (!body) return sendError(res, 404, "not_found_error", "Installer file missing on the server.");
  res.writeHead(200, { "content-type": types[file] });
  res.end(body);
}

async function setTokens(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { accessToken?: unknown; refreshToken?: unknown; expiresAt?: unknown };
  try {
    body = JSON.parse(raw.toString());
} catch (err) {
    return sendError(res, 400, "invalid_request_error", "Send accessToken, refreshToken, expiresAt from the login flow.");
  }
  const { accessToken, refreshToken, expiresAt } = body;
  const tokenShape = /^[A-Za-z0-9._~+/=-]{20,4096}$/;
  if (typeof accessToken !== "string" || typeof refreshToken !== "string" || !tokenShape.test(accessToken) || !tokenShape.test(refreshToken)) {
    return sendError(res, 400, "invalid_request_error", "accessToken and refreshToken must be OAuth tokens.");
  }
  let exp = typeof expiresAt === "number" && Number.isFinite(expiresAt) ? expiresAt : Date.now() + 3_600_000;
  if (exp < 1e12) exp *= 1000; // seconds -> ms
  if (exp > Date.now() + 366 * 86_400_000) exp = Date.now() + 3_600_000; // nothing lives a year
  newGeneration(caller);
  ledger.setOAuth(caller, { accessToken, refreshToken, expiresAt: exp });
  if (users[caller].invite || users[caller].claudeToken !== undefined) {
    delete users[caller].invite; // set up for real: their invite is used up
    delete users[caller].claudeToken; // the login replaces any setup token
    saveConfig();
  }
  usageCache.delete(caller);
  ledger.unpark(caller); // whatever the old login hit, this one hasn't
  console.log(`[pool] ${caller} connected their subscription (OAuth tokens stored)`);
  sendJson(res, 200, { ok: true });
}

// ---------- abuse limits (the pool may be reachable from the internet via Funnel) ----------

const FAILURE_WINDOW_MS = 10 * 60_000;
const MAX_FAILURES_PER_CLIENT = 10;
const MAX_TRACKED_CLIENTS = 10_000;
const failures = new Map<string, number[]>();

// Funnel traffic arrives from tailscaled on loopback with the real client in
// X-Forwarded-For; anything else is a direct tailnet connection. tailscaled is the
// only proxy in front of the pool, so the address it added (the last one) is the
// client's; anything before it the client wrote itself.
function clientId(req: http.IncomingMessage): string {
  const socketIp = req.socket.remoteAddress ?? "?";
  const loopback = socketIp === "127.0.0.1" || socketIp === "::1" || socketIp === "::ffff:127.0.0.1";
  const forwarded = req.headers["x-forwarded-for"];
  if (!loopback || typeof forwarded !== "string") return socketIp;
  const hops = forwarded.split(",").map((h) => h.trim()).filter(Boolean);
  return hops.at(-1) ?? socketIp;
}

function recent(times: number[], now = Date.now()): number[] {
  return times.filter((t) => t > now - FAILURE_WINDOW_MS);
}

function isBlocked(client: string): boolean {
  return recent(failures.get(client) ?? []).length >= MAX_FAILURES_PER_CLIENT;
}

function recordFailure(client: string): void {
  const times = [...recent(failures.get(client) ?? []), Date.now()];
  failures.set(client, times);
  if (failures.size > MAX_TRACKED_CLIENTS) {
    // Forget quiet clients first (their windows have passed), then the oldest.
    for (const [who, when] of failures) if (recent(when).length === 0) failures.delete(who);
    for (const who of failures.keys()) {
      if (failures.size <= MAX_TRACKED_CLIENTS / 2) break;
      failures.delete(who);
    }
  }
  if (times.length === MAX_FAILURES_PER_CLIENT) console.log(`[pool] blocking ${client} for 10 min after repeated failures`);
}

// No route buffers arbitrary uploads: settings and reports are small JSON.
class BodyTooLarge extends Error {
  constructor() { super("body too large"); }
}
async function readSmallBody(req: http.IncomingMessage, limit = 4096): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new BodyTooLarge();
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

// Fixed one-minute windows, one small record per key: counting a flood past the cap
// costs nothing and remembers nothing, so the limiter never adds to the load it stops.
type Window = { since: number; count: number };
function allow(table: Map<string, Window>, key: string, max: number, now = Date.now()): boolean {
  let window = table.get(key);
  if (!window || now - window.since >= 60_000) {
    window = { since: now, count: 0 };
    table.set(key, window);
  }
  if (window.count >= max) return false;
  window.count++;
  return true;
}

// Members: the app and agent write a few times a minute and read every 30 s.
const MAX_WRITES_PER_MINUTE = 120;
const MAX_READS_PER_MINUTE = 60;
const writes = new Map<string, Window>();
const reads = new Map<string, Window>();
const allowWrite = (caller: string) => allow(writes, caller, MAX_WRITES_PER_MINUTE);
const allowRead = (caller: string) => allow(reads, caller, MAX_READS_PER_MINUTE);

// Anyone: the invite page, its logo and the join script, per client address.
const MAX_PUBLIC_PER_MINUTE = 30;
const publicHits = new Map<string, Window>();
function allowPublic(client: string): boolean {
  const now = Date.now();
  if (publicHits.size > MAX_TRACKED_CLIENTS) {
    for (const [who, window] of publicHits) if (now - window.since >= 60_000) publicHits.delete(who);
    for (const who of publicHits.keys()) {
      if (publicHits.size <= MAX_TRACKED_CLIENTS / 2) break;
      publicHits.delete(who);
    }
  }
  return allow(publicHits, client, MAX_PUBLIC_PER_MINUTE, now);
}

function isAdmin(name: string): boolean {
  return config.admins?.includes(name) ?? false;
}

const INVITE_TTL_MS = 7 * 86_400_000;
const INVITE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o, 1/l/i lookalikes

// Written whole and renamed into place: a crash mid-write must not leave the one file
// with every member's token half there. 0600 throughout.
function saveConfig(): void {
  const tmp = `${CONFIG_PATH}.tmp`;
  writeFileSync(tmp, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, CONFIG_PATH);
}

// 16 characters from a 31-letter alphabet: ~79 bits, so guessing is hopeless even
// before the redeem rate limit kicks in.
function newInviteCode(): string {
  const chars: string[] = [];
  while (chars.length < 16) {
    // Rejection sampling: 256 isn't a multiple of 31, so bytes past the last full
    // multiple are thrown away rather than skew the first letters.
    for (const b of randomBytes(32)) if (b < 248 && chars.length < 16) chars.push(INVITE_ALPHABET[b % INVITE_ALPHABET.length]);
  }
  return chars.join("").match(/.{4}/g)!.join("-");
}

// Admins invite from the menu bar app. Nobody is added yet: the person only becomes a
// member (and gets a pool token) when they redeem the short one-time code.
async function invite(raw: Buffer, res: http.ServerResponse, caller: string): Promise<void> {
  if (!isAdmin(caller)) return sendError(res, 403, "permission_error", "Only pool admins can invite people.");
  let name: unknown;
  try {
    name = JSON.parse(raw.toString()).name;
} catch (err) {
    return sendError(res, 400, "invalid_request_error", "Send {\"name\": \"...\"}.");
  }
  if (typeof name !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(name)) {
    return sendError(res, 400, "invalid_request_error", "Use a short lowercase name (letters, digits, - or _).");
  }
  if (Object.hasOwn(users, name)) return sendError(res, 409, "invalid_request_error", `${name} is already in the pool.`);
  const now = Date.now();
  // Drop expired or malformed invites, and any older invite for the same name: the
  // newest code wins.
  config.invites = Object.fromEntries(Object.entries(config.invites ?? {})
    .filter(([code, i]) => findInvite(code) !== undefined && i.expiresAt > now && i.name !== name));
  const code = newInviteCode();
  config.invites[code] = { name, by: caller, expiresAt: now + INVITE_TTL_MS };
  saveConfig();
  console.log(`[pool] ${caller} invited ${name}`);
  sendJson(res, 200, { name, invite: `${poolBase()}/${code}`, expiresAt: now + INVITE_TTL_MS });
}

function poolBase(): string {
  return (config.publicUrl ?? `http://${host}:${port}`).replace(/\/$/, "");
}

// Where lembas lives; the invite page links here for people who'd rather download a release.
const PROJECT_URL = "https://github.com/bodino/lembas";

const INVITE_PATH = /^\/([a-z0-9]{4}(?:-[a-z0-9]{4}){3})$/;
const INVITE_CODE = /^[a-z0-9]{4}(?:-[a-z0-9]{4}){3}$/;
const MEMBER_NAME = /^[a-z][a-z0-9_-]{0,31}$/;

// An invite by its code, or nothing. `config.invites` is a plain object, so a bare
// index would also find `__proto__` and `constructor` (Object.prototype's members,
// truthy, with no expiry); only own keys of the right shape count, and the record is
// checked before anything trusts it.
function findInvite(code: string): { name: string; by?: string; expiresAt: number } | undefined {
  if (!INVITE_CODE.test(code) || !config.invites || !Object.hasOwn(config.invites, code)) return undefined;
  const invite = config.invites[code];
  if (typeof invite !== "object" || invite === null) return undefined;
  if (typeof invite.name !== "string" || !MEMBER_NAME.test(invite.name)) return undefined;
  if (typeof invite.expiresAt !== "number" || !Number.isFinite(invite.expiresAt)) return undefined;
  if (invite.by !== undefined && (typeof invite.by !== "string" || !MEMBER_NAME.test(invite.by))) return undefined;
  return invite;
}

// GET /<invite code>: the link people receive. A read-only landing page — download
// the app, then hand the code to it. Nothing is redeemed here, and an old link (used,
// expired) is an everyday thing, so it doesn't count toward the lockout; the codes
// have 79 bits, and redeeming is what's rate-limited.
function invitePage(req: http.IncomingMessage, res: http.ServerResponse, code: string): void {
  const client = clientId(req);
  const invite = findInvite(code);
  const valid = !isBlocked(client) && invite && invite.expiresAt > Date.now() && !Object.hasOwn(users, invite.name);
  const pretty = (name: string) => name.charAt(0).toUpperCase() + name.slice(1);
  const link = `${poolBase()}/${code}`;
  // Names are limited to [a-z0-9_-] and the code to [a-z0-9-], so nothing here needs escaping.
  const envelope = `<path d="M4 9.5 12 4l8 5.5v8.5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"/><path d="m4.5 10 7.5 5 7.5-5" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"/>`;
  const alert = `<path d="M12 7v6M12 16.5v.5" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>`;
  const body = valid
    ? `<div class="hero"><div class="icon"><svg viewBox="0 0 24 24" width="22" height="22">${envelope}</svg></div>
        <h1>${invite.by ? `${pretty(invite.by)} invited you` : "You're invited"}</h1>
        <p>to their lembas pool</p></div>
      <div class="card">
        <div class="row"><span class="step">1</span>
          <div class="text"><div>Download lembas</div><small>Unzip into Applications</small></div>
          <a class="button" href="${PROJECT_URL}/releases/latest/download/lembas.zip">Download</a></div>
        <div class="row"><span class="step">2</span>
          <div class="text"><div>Join the pool</div><small>Opens lembas with your invite</small></div>
          <a class="button" href="lembas://join?invite=${encodeURIComponent(link)}">Join</a></div>
      </div>
      <small class="note">First launch: System Settings › Privacy &amp; Security › Open Anyway.</small>
      <small class="label">Or paste into lembas</small>
      <div class="field"><code id="code">${link}</code>
        <button onclick="navigator.clipboard.writeText(document.getElementById('code').textContent);this.textContent='Copied'">Copy</button></div>`
    : `<div class="hero"><div class="icon warn"><svg viewBox="0 0 24 24" width="22" height="22">${alert}</svg></div>
        <h1>This invite isn't valid anymore</h1><p>Ask for a new one.</p></div>`;
  res.writeHead(valid ? 200 : 404, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  // Mirrors the app: 320 pt panel, the 13/12/11 type scale, system accent, quaternary
  // fills, checklist rows with small buttons, and the app's input field.
  res.end(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Join lembas</title>
<style>
  :root { --page: #ececec; --panel: #ffffff; --fill: rgba(0,0,0,.035); --line: rgba(0,0,0,.1);
          --field: #ffffff; --text: #1d1d1f; --muted: rgba(0,0,0,.5); --accent: #007aff; --warn: #ff9500;
          color-scheme: light dark; }
  @media (prefers-color-scheme: dark) {
    :root { --page: #161616; --panel: #242424; --fill: rgba(255,255,255,.05); --line: rgba(255,255,255,.1);
            --field: #1e1e1e; --text: #f5f5f7; --muted: rgba(255,255,255,.55); --accent: #0a84ff; }
  }
  * { box-sizing: border-box; margin: 0; }
  body { min-height: 100vh; display: grid; place-items: center; padding: 24px; background: var(--page);
         color: var(--text); font: 12px/1.35 -apple-system, BlinkMacSystemFont, sans-serif;
         -webkit-font-smoothing: antialiased; }
  main { width: 320px; padding: 10px 14px 18px; background: var(--panel); border: 1px solid var(--line);
         border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,.18); }
  header { display: flex; align-items: center; gap: 10px; font: 600 13px -apple-system, sans-serif; }
  header img { width: 28px; height: 28px; }
  .hero { text-align: center; margin: 24px 0 20px; }
  .icon { width: 48px; height: 48px; margin: 0 auto 12px; border-radius: 50%; background: var(--accent);
          display: grid; place-items: center; }
  .icon.warn { background: var(--warn); }
  h1 { font: 600 13px -apple-system, sans-serif; }
  .hero p { margin-top: 6px; color: var(--muted); }
  .card { background: var(--fill); border-radius: 10px; }
  .row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; }
  .row + .row { border-top: 1px solid var(--line); margin-left: 44px; padding-left: 0; }
  .row + .row .step { margin-left: -32px; }
  .step { flex: none; width: 22px; height: 22px; border-radius: 50%; border: 1.5px solid var(--line);
          color: var(--muted); font-size: 11px; font-weight: 600; display: grid; place-items: center; }
  .text { flex: 1; }
  small { display: block; font-size: 11px; color: var(--muted); }
  .button { flex: none; padding: 3px 10px; border-radius: 6px; background: var(--accent); color: #fff;
            font-size: 12px; text-decoration: none; }
  .note { margin: 10px 2px 0; }
  .label { margin: 18px 2px 6px; }
  .field { display: flex; align-items: center; gap: 8px; padding: 7px 7px 7px 12px; border-radius: 8px;
           background: var(--field); border: 1px solid var(--line); }
  .field code { flex: 1; min-width: 0; font: 11px ui-monospace, Menlo, monospace; overflow-wrap: anywhere; }
  .field button { flex: none; border: 1px solid var(--line); border-radius: 6px; padding: 2px 9px;
                  background: var(--fill); color: var(--text); font: 12px -apple-system, sans-serif; cursor: pointer; }
  footer { margin-top: 18px; text-align: center; }
  footer a { color: var(--accent); text-decoration: none; font-size: 11px; }
</style></head>
<body><main>
  <header><img src="/logo.png" alt="">lembas</header>
  ${body}
  <footer><a href="${PROJECT_URL}">Also on GitHub</a></footer>
</main></body></html>`);
}

// Unauthenticated by design: the invite code is the credential. It works once.
async function redeem(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  // Per client only: the codes have 79 bits, and a shared counter would let a few
  // addresses lock everyone out of joining.
  const client = clientId(req);
  if (isBlocked(client)) return sendError(res, 429, "rate_limit_error", "Too many attempts. Try again in a few minutes.");
  let code: unknown;
  try {
    code = JSON.parse((await readSmallBody(req)).toString()).code;
} catch (err) {
    if (err instanceof BodyTooLarge) throw err;
    return sendError(res, 400, "invalid_request_error", "Send {\"code\": \"...\"}.");
  }
  const key = typeof code === "string" ? code.trim().toLowerCase() : "";
  const invite = findInvite(key);
  if (!invite || invite.expiresAt < Date.now() || Object.hasOwn(users, invite.name)) {
    recordFailure(client);
    return sendError(res, 404, "not_found_error", "This invite code is not valid. Ask for a new one.");
  }
  const token = `pool-${randomBytes(24).toString("hex")}`;
  users[invite.name] = {
    token,
    invite: { code: key, by: invite.by, expiresAt: invite.expiresAt },
  };
  delete config.invites![key];
  saveConfig();
  console.log(`[pool] ${invite.name} joined with their invite`);
  sendJson(res, 200, { name: invite.name, token });
}

// Takes a member out of the pool: their pool token stops working immediately, and
// their subscription access (OAuth tokens), lending settings and presence are deleted.
function forgetMember(name: string): void {
  closeSessions(name, "You are no longer a member of this pool.");
  newGeneration(name);
  delete users[name];
  if (config.admins) config.admins = config.admins.filter((admin) => admin !== name);
  saveConfig();
  ledger.removeMember(name);
  usageCache.delete(name);
}

async function removeMember(res: http.ServerResponse, caller: string, name: string): Promise<void> {
  if (!isAdmin(caller)) return sendError(res, 403, "permission_error", "Only pool admins can remove people.");
  if (name === caller) return sendError(res, 400, "invalid_request_error", "You can't remove yourself.");
  if (!Object.hasOwn(users, name)) return sendError(res, 404, "not_found_error", `${name} is not in the pool.`);
  forgetMember(name);
  console.log(`[pool] ${caller} removed ${name}`);
  sendJson(res, 200, { ok: true });
}

// POST /pool/leave — a member leaves on their own. The last admin can't, so a pool
// always keeps someone who can invite and remove people.
async function leavePool(res: http.ServerResponse, caller: string): Promise<void> {
  const otherAdmins = (config.admins ?? []).filter((admin) => admin !== caller && Object.hasOwn(users, admin));
  if (isAdmin(caller) && otherAdmins.length === 0) {
    return sendError(res, 400, "invalid_request_error", "You're this pool's only admin, so you can't leave it.");
  }
  // Leaving during setup gives the invite back, so the same link works again. The
  // invite record is deleted the moment they connect (setTokens), so its presence is
  // the durable "never set up" flag; a login cleared since then doesn't revive it.
  const pending = users[caller].invite;
  forgetMember(caller);
  if (pending && pending.expiresAt > Date.now()) {
    (config.invites ??= {})[pending.code] = { name: caller, by: pending.by, expiresAt: pending.expiresAt };
    saveConfig();
    console.log(`[pool] ${caller} went back during setup; their invite works again`);
  } else {
    console.log(`[pool] ${caller} left the pool (their subscription access was deleted)`);
  }
  sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET") {
      const file = ["/join.sh", "/logo.png"].includes(req.url ?? "") ? req.url!.slice(1) : undefined;
      const inviteCode = req.url?.match(INVITE_PATH)?.[1];
      if (file || inviteCode) {
        // Public, so priced per visitor: one client can't keep the pool busy with them.
        if (!allowPublic(clientId(req))) return sendError(res, 429, "rate_limit_error", "Too many requests. Try again in a minute.");
        return file ? serveInstaller(res, file) : invitePage(req, res, inviteCode!);
      }
    }
    if (req.method === "POST" && req.url === "/pool/redeem") return await redeem(req, res);
    // Valid tokens always get through: the block only stops guessing, and members often
    // share an address (a home network, or this Mac reaching itself over the tailnet).
    const caller = authenticate(req);
    if (!caller) {
      if (isBlocked(clientId(req))) return sendError(res, 429, "rate_limit_error", "Too many failed attempts. Try again in a few minutes.");
      recordUnauthenticated(req);
      return sendError(res, 401, "authentication_error", "Unknown pool token.");
    }

    if (req.url === "/pool" && req.method === "GET") {
      // Status asks Anthropic about every member (cached a minute, one question in
      // flight each); a member hammering it still can't make the pool hammer Anthropic.
      if (!allowRead(caller)) return sendError(res, 429, "rate_limit_error", "Too many requests to the pool; slow down.");
      return sendJson(res, 200, await status(caller));
    }
    // Everything that writes: rate-limited per member before the body is even read,
    // then the body (bounded), then once more "still a member, same token?", since a
    // removal may have landed while it uploaded.
    if (req.method === "PUT" || req.method === "POST") {
      if (!allowWrite(caller)) return sendError(res, 429, "rate_limit_error", "Too many requests to the pool; slow down.");
      const token = users[caller].token;
      const raw = await readSmallBody(req, MAX_BODY);
      if (!Object.hasOwn(users, caller) || users[caller].token !== token) {
        return sendError(res, 401, "authentication_error", "You are no longer a member of this pool.");
      }
      if (req.url === "/pool/tokens" && req.method === "PUT") return await setTokens(raw, res, caller);
      if (req.url === "/pool/share" && req.method === "PUT") return await setShare(raw, res, caller);
      if (req.url === "/pool/presence" && req.method === "PUT") return await setPresence(raw, res, caller);
      if (req.url === "/pool/report" && req.method === "PUT") return await reportDirectUsage(raw, res, caller);
      if (req.url === "/pool/limit" && req.method === "PUT") return await reportDirectLimit(raw, res, caller);
      if (req.url === "/pool/invite" && req.method === "POST") return await invite(raw, res, caller);
      if (req.url === "/pool/leave" && req.method === "POST") return await leavePool(res, caller);
    }
    const member = req.url?.match(/^\/pool\/members\/([a-z][a-z0-9_-]{0,31})$/);
    if (member && req.method === "DELETE") return await removeMember(res, caller, member[1]);
    // Model calls used to be relayed here with a lender's token, readable by the pool.
    // They no longer are: borrowing is private only (the WebSocket below), and an
    // agent still sending these is an old lembas.
    if (req.url?.startsWith("/v1/") || req.url?.startsWith("/api/")) {
      return sendError(res, 410, "permission_error", "This pool only lends privately. Update lembas to borrow.");
    }
    sendError(res, 404, "not_found_error", "Not found.");
  } catch (err) {
    const e = err as Error & { code?: string };
    if (e instanceof BodyTooLarge) return sendError(res, 413, "invalid_request_error", "Request body too large.");
    if (e.name === "AbortError") return; // client went away mid-stream
    if (e.code === "ECONNRESET" || e.message === "aborted") {
      // The client dropped the request while we were reading it (Claude Code
      // cancelled); nothing of ours went wrong.
      console.log(`[pool] a client dropped its request mid-upload`);
      return;
    }
    console.error(err);
    if (!res.headersSent) sendError(res, 502, "api_error", "Pool server could not reach Anthropic.");
    else res.end();
  }
});

// Private borrowing arrives as a WebSocket upgrade on /pool/borrow, with the same token.
server.on("upgrade", (req, socket, head) => {
  // Node hands the socket over without its own error listener; a peer that has
  // already gone when the refusal is written would otherwise raise an unhandled
  // error and take the pool down with it.
  socket.on("error", () => {});
  const refuse = (status: string) => {
    socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
  };
  const caller = authenticate(req);
  if (!caller) {
    if (!isBlocked(clientId(req))) recordUnauthenticated(req);
    return refuse("401 Unauthorized");
  }
  if (req.url?.split("?")[0] !== "/pool/borrow") return refuse("404 Not Found");
  const ws = WebSocketConnection.accept(req, socket, head);
  if (!ws) return;
  ws.on("error", (err) => console.log(`[pool] ${caller}'s borrow socket: ${err.message}`));
  borrowPrivately(ws, caller, new URL(req.url ?? "/", "http://pool")).catch((err) => {
    console.error(err);
    ws.close(1011);
  });
});

// launchd stops the pool with SIGTERM (a restart, a logout): what the ledger has not
// written yet (a park, a presence change, the last reports) goes to disk first.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    ledger.flush();
    process.exit(0);
  });
}

const port = config.port ?? 8787;
const host = config.host ?? "127.0.0.1";
// The log names members and what they borrow; when stdout is a regular file (launchd's
// StandardOutPath), keep it to this user. A terminal, pipe or device is left alone.
try {
  if (fstatSync(1).isFile()) fchmodSync(1, 0o600);
} catch {
  // Nothing to protect.
}
// Slow clients on the public listener can't hold connections open for free.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 1000; // then reconnect: a kept-alive socket isn't a free firehose
server.maxConnections = 512;
server.on("error", (err) => {
  console.log(`[pool] cannot listen on ${host}:${port}: ${err.message}`);
  process.exit(1);
});
if (!mpcAvailable()) console.log(`[pool] WARNING: no MPC helper at ${MPC_HELPER}; this pool cannot lend until ./build.sh has built it`);
server.listen(port, host, () => console.log(`[pool] listening on http://${host}:${port} for ${Object.keys(users).join(", ")}; borrowing needs a member's own login at ${BORROW_AT_PERCENT}%`));
// Tailscale Funnel can only forward to localhost, so listen there too when it's in use
// and the main listener doesn't already cover loopback.
const coversLoopback = ["127.0.0.1", "0.0.0.0", "::", "localhost", "::1"].includes(host);
if (config.publicUrl && !coversLoopback) {
  const local = http.createServer(server.listeners("request")[0] as http.RequestListener);
  local.headersTimeout = server.headersTimeout;
  local.requestTimeout = server.requestTimeout;
  local.keepAliveTimeout = server.keepAliveTimeout;
  local.maxRequestsPerSocket = server.maxRequestsPerSocket;
  local.maxConnections = server.maxConnections;
  local.on("upgrade", server.listeners("upgrade")[0] as (...args: unknown[]) => void);
  local.on("error", (err) => console.log(`[pool] cannot also listen on 127.0.0.1:${port} for ${config.publicUrl}: ${err.message}`));
  local.listen(port, "127.0.0.1", () => console.log(`[pool] also on http://127.0.0.1:${port} for ${config.publicUrl}`));
}
