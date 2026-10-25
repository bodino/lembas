import http from "node:http";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { Ledger, type LendPolicy, type LendRule } from "./ledger.ts";
import { costUsd } from "./pricing.ts";
import { UsageTap } from "./usageTap.ts";

type User = {
  token: string; // what this person puts in Claude Code to talk to the pool
  claudeToken: string; // their sk-ant-oat01-... from `claude setup-token`, carries their Pro/Max subscription
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
  // Members allowed to invite and remove people from the menu bar app.
  admins?: string[];
  // Public HTTPS address from Tailscale Funnel, e.g. "https://mac.tail1234.ts.net".
  // When set, invite codes use it and the pool also listens on 127.0.0.1 for Funnel.
  publicUrl?: string;
  // One-time invite codes, redeemed by the menu bar app for that member's pool token.
  invites?: Record<string, { name: string; by?: string; expiresAt: number }>;
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
const ledger = new Ledger(config.statePath ?? "state.json");

// Claude Code's OAuth client. The login flow runs on each member's machine; the pool
// only ever talks to the token endpoint to refresh what they deposited.
const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token";

// Headers that belong to one hop, or that we replace, and must not be copied across.
const REQUEST_HEADERS_TO_DROP = new Set(["host", "connection", "content-length", "authorization", "x-api-key", "accept-encoding"]);
const RESPONSE_HEADERS_TO_DROP = new Set(["connection", "content-length", "content-encoding", "transfer-encoding", "keep-alive"]);

// ---------- which credential does this member use upstream? ----------

const refreshInFlight = new Map<string, Promise<string | null>>();

// Refresh a member's stored OAuth token (rotation: store the new refresh token).
async function refreshOAuth(name: string): Promise<string | null> {
  const existing = refreshInFlight.get(name);
  if (existing) return existing;
  const task = (async () => {
    const tokens = ledger.oauth(name);
    if (!tokens) return null;
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
      if (!res.ok) throw new Error(`refresh failed: HTTP ${res.status}`);
      const body = (await res.json()) as { access_token?: string; refresh_token?: string; expires_at?: number; expires_in?: number };
      if (!body.access_token || !body.refresh_token) throw new Error("refresh response missing tokens");
      let expiresAt = body.expires_at ?? Date.now() + (body.expires_in ?? 3600) * 1000;
      if (expiresAt < 1e12) expiresAt *= 1000; // seconds -> ms
      ledger.setOAuth(name, { accessToken: body.access_token, refreshToken: body.refresh_token, expiresAt });
      return body.access_token;
    } catch (err) {
      console.log(`[pool] ${name}'s OAuth refresh failed (${(err as Error).message}); falling back to setup token`);
      ledger.clearOAuth(name);
      return null;
    } finally {
      refreshInFlight.delete(name);
    }
  })();
  refreshInFlight.set(name, task);
  return task;
}

// The bearer token to use for `name` upstream: their OAuth token when available
// (refreshing if within 2 minutes of expiry), otherwise their setup token.
async function anthropicToken(name: string): Promise<string> {
  const tokens = ledger.oauth(name);
  if (tokens) {
    if (tokens.expiresAt - 120_000 > Date.now()) return tokens.accessToken;
    const refreshed = await refreshOAuth(name);
    if (refreshed) return refreshed;
  }
  return users[name].claudeToken;
}

// ---------- how much of each subscription is left ----------

type Utilization = {
  fiveHour: number;
  sevenDay: number;
  resetsAt: number | null;
  sevenDayResetsAt: number | null;
};
const usageCache = new Map<string, { at: number; usage: Utilization | null }>();

// Asks Anthropic the same thing Claude Code's /usage command asks: how full are this
// person's 5-hour and 7-day windows, as a percentage. Cached because Anthropic rate
// limits this endpoint hard. Returns null when it can't be measured.
async function fetchUtilization(name: string): Promise<Utilization | null> {
  const cached = usageCache.get(name);
  if (cached && Date.now() - cached.at < USAGE_CACHE_MS) return cached.usage;

  let usage: Utilization | null = null;
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
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const body = (await res.json()) as {
        five_hour?: { utilization?: number; resets_at?: string };
        seven_day?: { utilization?: number; resets_at?: string };
      };
      usage = {
        fiveHour: body.five_hour?.utilization ?? 0,
        sevenDay: body.seven_day?.utilization ?? 0,
        resetsAt: body.five_hour?.resets_at ? Date.parse(body.five_hour.resets_at) : null,
        sevenDayResetsAt: body.seven_day?.resets_at ? Date.parse(body.seven_day.resets_at) : null,
      };
    }
  } catch {
    // Network or parse failure; fall through with null.
  }
  usageCache.set(name, { at: Date.now(), usage });
  return usage;
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
  // What they allow minus what's used, per window. Room in both is required.
  const left5h = ceiling5h - usage.fiveHour;
  const leftWeek = policy.week - usage.sevenDay;
  // The week is a gate: once it's used up they can't lend, whatever the 5-hour room.
  if (leftWeek <= 0) return { headroom: 0, reason: "weekFull" };
  if (left5h <= 0) return { headroom: 0, reason: "full" };
  return { headroom: left5h, left5h, leftWeek, reason: away ? "away" : "working" };
}

// Own token first; then whoever is sharing with the most headroom left.
async function tokenOrder(caller: string): Promise<string[]> {
  const donors: Array<[string, number]> = [];
  for (const name of Object.keys(users)) {
    if (name === caller) continue;
    const { headroom } = await availability(name, caller);
    if (headroom > 0) donors.push([name, headroom]);
  }
  donors.sort((a, b) => b[1] - a[1]);
  const order = donors.map(([name]) => name);
  return ledger.isParked(caller) ? order : [caller, ...order];
}

// ---------- HTTP plumbing ----------

function authenticate(req: http.IncomingMessage): string | undefined {
  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const presented = (req.headers["x-api-key"] as string | undefined) ?? bearer;
  if (!presented) return undefined;
  return Object.keys(users).find((name) => safeEqual(presented, users[name].token));
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

// Same shape as Anthropic's own errors, so Claude Code displays them properly.
function sendError(res: http.ServerResponse, status: number, type: string, message: string): void {
  sendJson(res, status, { type: "error", error: { type, message } });
}

function errorSummary(body: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: { type?: string; message?: string }; request_id?: string };
    const type = parsed.error?.type ?? "unknown";
    const message = parsed.error?.message ?? "";
    return `${type}${message ? `: ${message.slice(0, 160)}` : ""}${parsed.request_id ? ` (req ${parsed.request_id})` : ""}`;
  } catch {
    return body.slice(0, 160) || "empty response";
  }
}

function upstreamHeaders(req: http.IncomingMessage, bearer: string): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined || REQUEST_HEADERS_TO_DROP.has(name)) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  headers.delete("x-api-key");
  headers.set("authorization", `Bearer ${bearer}`);

  // Subscription tokens are only accepted on requests that look like Claude Code.
  // Merge (never overwrite) the required beta flags so client betas survive.
  const betas = new Set(headers.get("anthropic-beta")?.split(",").map((b) => b.trim()).filter(Boolean) ?? []);
  betas.add("claude-code-20250219");
  betas.add("oauth-2025-04-20");
  headers.set("anthropic-beta", [...betas].join(","));

  if (!/^claude-cli\//.test(headers.get("user-agent") ?? "")) {
    headers.set("user-agent", "claude-cli/2.1.0 (external, cli)");
  }
  headers.set("accept-encoding", "identity"); // keep the stream readable so we can count tokens
  return headers;
}

// How long to skip this token after an upstream rejection, or null if it isn't one we handle.
// Anthropic also emits short-lived 429s ("rate_limit_error", no retry-after) that are not
// usage limits; those must be retried, not parked for 20 minutes.
function parkDuration(status: number, headers: Headers, body: string): number | null {
  if (status === 401) return 24 * 60 * 60_000; // dead/expired token: needs `claude setup-token` again
  if (status === 429) {
    const retryAfter = headers.get("retry-after");
    if (retryAfter) {
      const seconds = Number(retryAfter);
      const ms = Number.isFinite(seconds) && seconds !== 0
        ? seconds * 1000
        : Math.max(0, Date.parse(retryAfter) - Date.now());
      if (ms > 0) return Math.min(ms, 6 * 60 * 60_000);
    }
    if (/usage limit|limit reached/i.test(body)) return LIMIT_COOLDOWN_MS;
    return null; // transient rate limit: let Claude Code retry the same token
  }
  if ((status === 400 || status === 402 || status === 403) && /credit balance/i.test(body)) {
    return LIMIT_COOLDOWN_MS; // prepaid-key style failure, kept just in case
  }
  return null;
}

// ---------- routes ----------

async function proxy(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  const body = await readBody(req);
  let model: string | undefined;
  try {
    model = JSON.parse(body.toString()).model;
  } catch {
    // GET requests and non-JSON bodies have no model.
  }

  const order = await tokenOrder(caller);
  if (order.length === 0) {
    const until = ledger.parkedUntil(caller);
    const when = until ? ` until ${new Date(until).toLocaleString()}` : "";
    return sendError(
      res,
      429,
      "rate_limit_error",
      `Your token is parked by the pool${when} after a usage-limit response, and nobody in the pool has shared capacity to spare right now.`,
    );
  }

  const abort = new AbortController();
  res.on("close", () => {
    if (!res.writableFinished) abort.abort();
  });

  for (const [i, owner] of order.entries()) {
    const isLastOption = i === order.length - 1;
    const bearer = await anthropicToken(owner);
    const upstream = await fetch(UPSTREAM + req.url, {
      method: req.method,
      headers: upstreamHeaders(req, bearer),
      body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
      signal: abort.signal,
    });

    if (!upstream.ok) {
      const text = await upstream.text();
      if (upstream.status === 429 || upstream.status === 401) {
        console.log(`[pool] ${owner} got upstream ${upstream.status} — ${errorSummary(text)}`);
      }
      const park = parkDuration(upstream.status, upstream.headers, text);
      if (park !== null) {
        ledger.park(owner, park);
        console.log(`[pool] ${owner}'s token is ${upstream.status === 401 ? "dead (expired or revoked)" : "at its usage limit"}; parked for ${Math.round(park / 60_000)} min`);
        if (!isLastOption) continue;
      }
      res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      return void res.end(text);
    }

    upstream.headers.forEach((value, name) => {
      if (!RESPONSE_HEADERS_TO_DROP.has(name)) res.setHeader(name, value);
    });
    res.setHeader("x-pool-key-owner", owner);
    res.writeHead(upstream.status);

    const tap = new UsageTap(upstream.headers.get("content-type"));
    try {
      for await (const chunk of upstream.body ?? []) {
        tap.push(chunk);
        res.write(chunk);
      }
      res.end();
    } finally {
      // Runs on client disconnect too, so partially streamed replies still count.
      const usd = costUsd(model, tap.finish());
      if (usd > 0) {
        ledger.record(owner, caller, usd);
        const via = owner === caller ? "own token" : `${owner}'s token`;
        console.log(`[pool] ${caller} ${model ?? req.url} ~$${usd.toFixed(4)} via ${via}`);
      }
    }
    return;
  }
}

async function status(caller: string): Promise<unknown> {
  const out: Record<string, unknown> = { you: caller, canInvite: isAdmin(caller) };
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
        utilization: usage ? { fiveHour: usage.fiveHour, sevenDay: usage.sevenDay, fiveHourResetsAt: usage.resetsAt } : null,
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
// Either part may be sent alone. lendTo replaces the whole map; anyone omitted falls back
// to the default (may borrow while you're away), so send {"away": false} to turn someone off.
async function setShare(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { policy?: unknown; lendTo?: unknown };
  try {
    body = JSON.parse((await readBody(req)).toString());
  } catch {
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
      if (!(consumer in users)) return sendError(res, 400, "invalid_request_error", `Unknown pool member: ${consumer}.`);
      if (consumer === caller) return sendError(res, 400, "invalid_request_error", "You cannot lend to yourself.");
      const rule = raw as { away?: unknown; working5h?: unknown } | null;
      if (typeof rule !== "object" || rule === null || typeof rule.away !== "boolean" || !isPercent(rule.working5h)) {
        return sendError(res, 400, "invalid_request_error", `lendTo.${consumer} must be {"away": true|false, "working5h": 0–100}.`);
      }
      rules[consumer] = { away: rule.away, working5h: rule.working5h };
    }
  }

  if (newPolicy) ledger.setPolicy(caller, newPolicy);
  if (rules) ledger.setLendRules(caller, rules);
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
async function setPresence(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  let away: unknown;
  try {
    away = JSON.parse((await readSmallBody(req)).toString()).away;
  } catch {
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
async function reportDirectUsage(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { usd?: unknown; model?: unknown };
  try {
    body = JSON.parse((await readBody(req)).toString());
  } catch {
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

async function reportDirectLimit(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { forMs?: unknown };
  try {
    body = JSON.parse((await readBody(req)).toString());
  } catch {
    return sendError(res, 400, "invalid_request_error", "Send {\"forMs\": 60000}.");
  }
  const forMs = body.forMs;
  if (typeof forMs !== "number" || !Number.isFinite(forMs) || forMs < 0 || forMs > 6 * 60 * 60_000) {
    return sendError(res, 400, "invalid_request_error", "forMs must be between 0 and 6 hours.");
  }
  if (forMs === 0) ledger.unpark(caller);
  else ledger.park(caller, forMs);
  sendJson(res, 200, { ok: true, parkedUntil: ledger.parkedUntil(caller) });
}

// Installer files live in ./installer next to src/. Served unauthenticated:
// the pool is only reachable over the tailnet and these contain no secrets.
const INSTALLER_DIR = new URL("../installer/", import.meta.url);

function serveInstaller(req: http.IncomingMessage, res: http.ServerResponse, file: string): void {
  const types: Record<string, string> = {
    "join.sh": "text/x-shellscript; charset=utf-8",
    "login.mjs": "text/javascript; charset=utf-8",
    "agent.mjs": "text/javascript; charset=utf-8",
    "lembas.zip": "application/zip",
    "version.json": "application/json", // the build lembas.zip holds; apps poll it for updates
    "logo.png": "image/png", // for the invite page
  };
  if (!types[file]) return sendError(res, 404, "not_found_error", "Not found.");
  try {
    const body = readFileSync(new URL(file, INSTALLER_DIR));
    res.writeHead(200, { "content-type": types[file] });
    res.end(body);
  } catch {
    sendError(res, 404, "not_found_error", "Installer file missing on the server.");
  }
}

async function setTokens(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  let body: { accessToken?: unknown; refreshToken?: unknown; expiresAt?: unknown };
  try {
    body = JSON.parse((await readBody(req)).toString());
  } catch {
    return sendError(res, 400, "invalid_request_error", "Send accessToken, refreshToken, expiresAt from the login flow.");
  }
  const { accessToken, refreshToken, expiresAt } = body;
  if (typeof accessToken !== "string" || typeof refreshToken !== "string" || !accessToken || !refreshToken) {
    return sendError(res, 400, "invalid_request_error", "accessToken and refreshToken must be non-empty strings.");
  }
  let exp = typeof expiresAt === "number" ? expiresAt : Date.now() + 3_600_000;
  if (exp < 1e12) exp *= 1000; // seconds -> ms
  ledger.setOAuth(caller, { accessToken, refreshToken, expiresAt: exp });
  if (users[caller].invite) {
    delete users[caller].invite; // set up for real: their invite is used up
    saveConfig();
  }
  usageCache.delete(caller);
  console.log(`[pool] ${caller} connected their subscription (OAuth tokens stored)`);
  sendJson(res, 200, { ok: true });
}

// ---------- abuse limits (the pool may be reachable from the internet via Funnel) ----------

const FAILURE_WINDOW_MS = 10 * 60_000;
const MAX_FAILURES_PER_CLIENT = 10;
const MAX_FAILED_REDEEMS = 30; // across everyone: invite codes are the guessable secret
const failures = new Map<string, number[]>();
let failedRedeems: number[] = [];

// Funnel traffic arrives from tailscaled on loopback with the real client in
// X-Forwarded-For; anything else is a direct tailnet connection.
function clientId(req: http.IncomingMessage): string {
  const socketIp = req.socket.remoteAddress ?? "?";
  const loopback = socketIp === "127.0.0.1" || socketIp === "::1" || socketIp === "::ffff:127.0.0.1";
  const forwarded = req.headers["x-forwarded-for"];
  return loopback && typeof forwarded === "string" ? forwarded.split(",")[0].trim() : socketIp;
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
  if (times.length === MAX_FAILURES_PER_CLIENT) console.log(`[pool] blocking ${client} for 10 min after repeated failures`);
}

// Unauthenticated endpoints must not buffer arbitrary uploads.
async function readSmallBody(req: http.IncomingMessage, limit = 4096): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

function isAdmin(name: string): boolean {
  return config.admins?.includes(name) ?? false;
}

const INVITE_TTL_MS = 7 * 86_400_000;
const INVITE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o, 1/l/i lookalikes

function saveConfig(): void {
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(CONFIG_PATH, 0o600); // holds everyone's tokens
}

// 16 characters from a 31-letter alphabet: ~79 bits, so guessing is hopeless even
// before the redeem rate limit kicks in.
function newInviteCode(): string {
  const chars = [...randomBytes(16)].map((b) => INVITE_ALPHABET[b % INVITE_ALPHABET.length]).join("");
  return chars.match(/.{4}/g)!.join("-");
}

// Admins invite from the menu bar app. Nobody is added yet: the person only becomes a
// member (and gets a pool token) when they redeem the short one-time code.
async function invite(req: http.IncomingMessage, res: http.ServerResponse, caller: string): Promise<void> {
  if (!isAdmin(caller)) return sendError(res, 403, "permission_error", "Only pool admins can invite people.");
  let name: unknown;
  try {
    name = JSON.parse((await readBody(req)).toString()).name;
  } catch {
    return sendError(res, 400, "invalid_request_error", "Send {\"name\": \"...\"}.");
  }
  if (typeof name !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(name)) {
    return sendError(res, 400, "invalid_request_error", "Use a short lowercase name (letters, digits, - or _).");
  }
  if (users[name]) return sendError(res, 409, "invalid_request_error", `${name} is already in the pool.`);
  const now = Date.now();
  // Drop expired invites, and any older invite for the same name: the newest code wins.
  config.invites = Object.fromEntries(Object.entries(config.invites ?? {}).filter(([, i]) => i.expiresAt > now && i.name !== name));
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

// GET /<invite code>: the link people receive. A read-only landing page — download
// the app, then hand the code to it. Nothing is redeemed here; looking up wrong codes
// counts toward the same lockout as guessing them.
function invitePage(req: http.IncomingMessage, res: http.ServerResponse, code: string): void {
  const client = clientId(req);
  const invite = config.invites?.[code];
  const valid = !isBlocked(client) && invite && invite.expiresAt > Date.now() && !users[invite.name];
  if (!valid) recordFailure(client);
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
          <a class="button" href="/lembas.zip">Download</a></div>
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
  const client = clientId(req);
  failedRedeems = recent(failedRedeems);
  if (isBlocked(client) || failedRedeems.length >= MAX_FAILED_REDEEMS) {
    return sendError(res, 429, "rate_limit_error", "Too many attempts. Try again in a few minutes.");
  }
  let code: unknown;
  try {
    code = JSON.parse((await readSmallBody(req)).toString()).code;
  } catch {
    return sendError(res, 400, "invalid_request_error", "Send {\"code\": \"...\"}.");
  }
  const key = typeof code === "string" ? code.trim().toLowerCase() : "";
  const invite = config.invites?.[key];
  if (!invite || invite.expiresAt < Date.now() || users[invite.name]) {
    recordFailure(client);
    failedRedeems.push(Date.now());
    return sendError(res, 404, "not_found_error", "This invite code is not valid. Ask for a new one.");
  }
  const token = `pool-${randomBytes(24).toString("hex")}`;
  users[invite.name] = {
    token,
    claudeToken: `PASTE-${invite.name}-sk-ant-oat01-HERE`,
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
  delete users[name];
  if (config.admins) config.admins = config.admins.filter((admin) => admin !== name);
  saveConfig();
  ledger.removeMember(name);
  usageCache.delete(name);
}

async function removeMember(res: http.ServerResponse, caller: string, name: string): Promise<void> {
  if (!isAdmin(caller)) return sendError(res, 403, "permission_error", "Only pool admins can remove people.");
  if (name === caller) return sendError(res, 400, "invalid_request_error", "You can't remove yourself.");
  if (!users[name]) return sendError(res, 404, "not_found_error", `${name} is not in the pool.`);
  forgetMember(name);
  console.log(`[pool] ${caller} removed ${name}`);
  sendJson(res, 200, { ok: true });
}

// POST /pool/leave — a member leaves on their own. The last admin can't, so a pool
// always keeps someone who can invite and remove people.
async function leavePool(res: http.ServerResponse, caller: string): Promise<void> {
  const otherAdmins = (config.admins ?? []).filter((admin) => admin !== caller && users[admin]);
  if (isAdmin(caller) && otherAdmins.length === 0) {
    return sendError(res, 400, "invalid_request_error", "You're this pool's only admin, so you can't leave it.");
  }
  // Leaving during setup (never connected) gives the invite back, so the same link works
  // again; once they've connected, it stays used.
  const pending = users[caller].invite;
  const connected = Boolean(ledger.oauth(caller));
  forgetMember(caller);
  if (pending && pending.expiresAt > Date.now() && !connected) {
    (config.invites ??= {})[pending.code] = { name: caller, by: pending.by, expiresAt: pending.expiresAt };
    saveConfig();
    console.log(`[pool] ${caller} went back during setup; their invite works again`);
  } else {
    console.log(`[pool] ${caller} left the pool (their subscription access was deleted)`);
  }
  sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && ["/join.sh", "/lembas.zip", "/version.json", "/logo.png"].includes(req.url ?? "")) {
    return serveInstaller(req, res, req.url!.slice(1));
  }
  if (req.method === "POST" && req.url === "/pool/redeem") return await redeem(req, res);
  const inviteCode = req.method === "GET" ? req.url?.match(INVITE_PATH)?.[1] : undefined;
  if (inviteCode) return invitePage(req, res, inviteCode);
  // Valid tokens always get through: the block only stops guessing, and members often
  // share an address (a home network, or this Mac reaching itself over the tailnet).
  const caller = authenticate(req);
  if (!caller) {
    const client = clientId(req);
    if (isBlocked(client)) return sendError(res, 429, "rate_limit_error", "Too many failed attempts. Try again in a few minutes.");
    recordFailure(client);
    return sendError(res, 401, "authentication_error", "Unknown pool token.");
  }

  try {
    if (req.url === "/pool" && req.method === "GET") return sendJson(res, 200, await status(caller));
    if (req.url === "/pool/tokens" && req.method === "PUT") return await setTokens(req, res, caller);
    if (req.url === "/pool/share" && req.method === "PUT") return await setShare(req, res, caller);
    if (req.url === "/pool/presence" && req.method === "PUT") return await setPresence(req, res, caller);
    if (req.url === "/pool/report" && req.method === "PUT") return await reportDirectUsage(req, res, caller);
    if (req.url === "/pool/limit" && req.method === "PUT") return await reportDirectLimit(req, res, caller);
    if (req.url === "/pool/invite" && req.method === "POST") return await invite(req, res, caller);
    if (req.url === "/pool/leave" && req.method === "POST") return await leavePool(res, caller);
    const member = req.url?.match(/^\/pool\/members\/([a-z][a-z0-9_-]{0,31})$/);
    if (member && req.method === "DELETE") return await removeMember(res, caller, member[1]);
    // /v1/* are the model calls; /api/* covers Claude Code's own usage display.
    if (req.url?.startsWith("/v1/") || req.url?.startsWith("/api/")) return await proxy(req, res, caller);
    sendError(res, 404, "not_found_error", "Not found.");
  } catch (err) {
    if ((err as Error).name === "AbortError") return; // client went away mid-stream
    console.error(err);
    if (!res.headersSent) sendError(res, 502, "api_error", "Pool server could not reach Anthropic.");
    else res.end();
  }
});

const port = config.port ?? 8787;
const host = config.host ?? "127.0.0.1";
server.listen(port, host, () => console.log(`[pool] listening on http://${host}:${port} for ${Object.keys(users).join(", ")}`));
// Tailscale Funnel can only forward to localhost, so listen there too when it's in use.
if (config.publicUrl && host !== "127.0.0.1" && host !== "0.0.0.0") {
  http.createServer(server.listeners("request")[0] as http.RequestListener)
    .listen(port, "127.0.0.1", () => console.log(`[pool] also on http://127.0.0.1:${port} for ${config.publicUrl}`));
}
