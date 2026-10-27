import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

type State = {
  // Per owner -> per borrower: who may borrow, and when (see LendRule). Older state
  // files hold {fiveHour, sevenDay} slices here; the constructor converts them.
  lends: Record<string, Record<string, LendRule>>;
  // Per owner: their limits on lending, checked against Anthropic's live utilization.
  policies: Record<string, LendPolicy>;
  // Per owner: when they last pressed "I'm done for today" / "I'm back".
  presence: Record<string, { awayAt?: number; backAt?: number }>;
  // Epoch ms until which a token is skipped after hitting a limit or dying.
  parkedUntil: Record<string, number>;
  // month ("2026-10") -> token owner -> who used it -> USD (estimated API-equivalent cost).
  spend: Record<string, Record<string, Record<string, number>>>;
  // Timestamped log of friend borrowing (consumer !== owner), basis for 5h and weekly caps.
  borrowLog: Array<{ t: number; owner: string; consumer: string; usd: number }>;
  // Every pool request (own and borrowed) in the last 8 days. Used to attribute the
  // utilization points Anthropic reports between two samples to who caused them.
  usageLog: Array<{ t: number; owner: string; consumer: string; usd: number }>;
  // Per owner: when they last used Claude Code themselves (the newest own entry in
  // usageLog), so presence doesn't scan the log on every status.
  lastOwnUse: Record<string, number>;
  // Full OAuth credentials for members who connected their subscription via the login flow.
  // These carry user:profile scope, so the pool can read real utilization windows.
  oauth: Record<string, { accessToken: string; refreshToken: string; expiresAt: number }>;
};

// `away`: may borrow whenever the owner is away. `working5h`: may also borrow while the
// owner is working, until the owner's 5-hour window reaches this percentage (0 = never).
export type LendRule = { away: boolean; working5h: number };

// `away5h`: while away, lend until the 5-hour window reaches this percentage.
// `week`: never lend past this percentage of the 7-day window, away or not.
// `awayAfterMinutes`: count as away after this long without own Claude Code use.
export type LendPolicy = { away5h: number; week: number; awayAfterMinutes: number };
export const DEFAULT_POLICY: LendPolicy = { away5h: 70, week: 60, awayAfterMinutes: 30 };

// Pools start generous: everyone may borrow from everyone while they're away, within
// the default limits above. Turning someone off is stored as an explicit rule.
export const DEFAULT_RULE: LendRule = { away: true, working5h: 0 };

export type Presence = { away: boolean; manual: boolean; since: number | null };

export class Ledger {
  private state: State;
  private saveTimer: NodeJS.Timeout | undefined;
  private path: string;

  constructor(path: string) {
    this.path = path;
    // Defaults first so state files written by older versions keep loading.
    const loaded: Partial<State> = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {};
    this.state = {
      lends: {}, policies: {}, presence: {}, parkedUntil: {}, spend: {}, borrowLog: [], usageLog: [], lastOwnUse: {}, oauth: {},
      ...loaded,
    };
    // The marks are rebuilt from the log once, for a state file from before they
    // existed; after that the stored ones are what counts, so a mark deleted with a
    // removed member doesn't come back from the old log for a newcomer of that name.
    if (!("lastOwnUse" in loaded)) {
      for (const e of this.state.usageLog) {
        if (e.consumer === e.owner && e.t > (this.state.lastOwnUse[e.owner] ?? 0)) this.state.lastOwnUse[e.owner] = e.t;
      }
    }
    // Old per-borrower slices become "may borrow when I'm away".
    for (const rules of Object.values(this.state.lends)) {
      for (const [consumer, rule] of Object.entries(rules) as Array<[string, LendRule & { fiveHour?: number; sevenDay?: number }]>) {
        if (rule.away === undefined) rules[consumer] = { away: (rule.fiveHour ?? 0) > 0 && (rule.sevenDay ?? 0) > 0, working5h: 0 };
      }
    }
    this.pruneLog();
    // Pruning is periodic, not per record, so a member looping reports can't make
    // every write scan both logs; the logs are also capped outright.
    setInterval(() => this.pruneLog(), 60_000).unref();
  }

  lendRule(owner: string, consumer: string): LendRule {
    return this.state.lends[owner]?.[consumer] ?? DEFAULT_RULE;
  }

  lendRules(owner: string): Record<string, LendRule> {
    return this.state.lends[owner] ?? {};
  }

  setLendRules(owner: string, rules: Record<string, LendRule>): void {
    this.state.lends[owner] = rules;
    this.save();
  }

  policy(owner: string): LendPolicy {
    return { ...DEFAULT_POLICY, ...this.state.policies[owner] };
  }

  setPolicy(owner: string, policy: LendPolicy): void {
    this.state.policies[owner] = policy;
    this.save();
  }

  // Away = pressed "I'm done for today" since their last own Claude Code use, or no own
  // use for `awayAfterMinutes`. Own use comes from the agent's usage reports.
  presence(owner: string, now = Date.now()): Presence {
    const marks = this.state.presence[owner] ?? {};
    const lastUse = this.state.lastOwnUse[owner] ?? 0;
    const lastActive = Math.max(lastUse, marks.backAt ?? 0);
    if ((marks.awayAt ?? 0) > lastActive) return { away: true, manual: true, since: marks.awayAt! };
    const after = this.policy(owner).awayAfterMinutes * 60_000;
    if (now - lastActive >= after) return { away: true, manual: false, since: lastActive ? lastActive + after : null };
    return { away: false, manual: false, since: lastActive };
  }

  setPresence(owner: string, away: boolean, now = Date.now()): void {
    const marks = (this.state.presence[owner] ??= {});
    if (away) marks.awayAt = now;
    else marks.backAt = now;
    this.save();
  }

  // USD friends have spent on `owner`'s token in the last `ms` milliseconds (rolling).
  borrowedInLastOn(owner: string, ms: number, now = Date.now()): number {
    return sum(this.state.borrowLog.filter((e) => e.owner === owner && e.t >= now - ms).map((e) => e.usd));
  }

  // USD friends have spent on `owner`'s token since the start of this ISO week (Mon 00:00 UTC).
  borrowedThisWeekOn(owner: string, now = Date.now()): number {
    return sum(this.state.borrowLog.filter((e) => e.owner === owner && e.t >= weekStartTs(now)).map((e) => e.usd));
  }

  borrowedThisWeekBy(owner: string, now = Date.now()): Record<string, number> {
    const by: Record<string, number> = {};
    for (const e of this.state.borrowLog) if (e.owner === owner && e.t >= weekStartTs(now)) by[e.consumer] = (by[e.consumer] ?? 0) + e.usd;
    return by;
  }

  // The reverse direction: USD `consumer` has spent on friends' tokens, keyed by owner.
  // Pass `ms` for a rolling window instead of the current ISO week.
  // Estimated USD spent on `owner`'s subscription since `since`: everything, and the
  // part friends borrowed. Basis for splitting the owner's usage bars.
  spendSince(owner: string, since: number): { total: number; borrowed: number } {
    let total = 0;
    let borrowed = 0;
    for (const e of this.state.usageLog) {
      if (e.owner !== owner || e.t < since) continue;
      total += e.usd;
      if (e.consumer !== owner) borrowed += e.usd;
    }
    return { total, borrowed };
  }

  borrowedByFrom(consumer: string, ms?: number, now = Date.now()): Record<string, number> {
    const since = ms === undefined ? weekStartTs(now) : now - ms;
    const by: Record<string, number> = {};
    for (const e of this.state.borrowLog) if (e.consumer === consumer && e.t >= since) by[e.owner] = (by[e.owner] ?? 0) + e.usd;
    return by;
  }

  // USD friends spent on `owner`'s token between two timestamps (used for share windows).
  // Pass `consumer` to narrow it to one borrower.
  borrowedSince(owner: string, since: number, until = Date.now(), consumer?: string): number {
    return sum(this.state.borrowLog
      .filter((e) => e.owner === owner && e.t >= since && e.t <= until && (consumer === undefined || e.consumer === consumer))
      .map((e) => e.usd));
  }

  // Every status and every lease scans these logs, and every save writes them out, so
  // they are capped: in all, and per owner, so that one member looping reports can't
  // push everyone else's history out, only their own.
  private static readonly MAX_LOG = 100_000;
  private static readonly MAX_LOG_PER_OWNER = 20_000;

  private pruneLog(now = Date.now()): void {
    const cutoff = now - 8 * 86_400_000; // weekly caps need at most 7 days of history
    const prune = (log: State["usageLog"]) => {
      const kept: State["usageLog"] = [];
      const perOwner = new Map<string, number>();
      for (let i = log.length - 1; i >= 0 && kept.length < Ledger.MAX_LOG; i--) {
        const e = log[i];
        if (e.t < cutoff) continue;
        const n = (perOwner.get(e.owner) ?? 0) + 1;
        if (n > Ledger.MAX_LOG_PER_OWNER) continue;
        perOwner.set(e.owner, n);
        kept.push(e);
      }
      return kept.reverse();
    };
    this.state.borrowLog = prune(this.state.borrowLog);
    this.state.usageLog = prune(this.state.usageLog);
    // Monthly totals: this month and the last are read; older ones only grow the file.
    // The previous month by the calendar (31 days back from the 1st after a 30-day
    // month would skip it).
    const d = new Date(now);
    const keep = new Set([currentMonth(d), currentMonth(new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1)))]);
    for (const month of Object.keys(this.state.spend)) if (!keep.has(month)) delete this.state.spend[month];
  }

  // Forget everything tied to a member who left the pool. Spend history and logs stay,
  // since they are other members' records too and age out on their own.
  removeMember(name: string): void {
    delete this.state.lends[name];
    for (const rules of Object.values(this.state.lends)) delete rules[name];
    delete this.state.oauth[name];
    delete this.state.parkedUntil[name];
    delete this.state.policies[name];
    delete this.state.presence[name];
    delete this.state.lastOwnUse[name];
    this.saveNow(); // a revocation is not something to lose to a crash in the next half second
  }

  // Writes now whatever a debounced save still holds (the pool is stopping).
  flush(): void {
    if (this.saveTimer) this.saveNow();
  }

  oauth(name: string): { accessToken: string; refreshToken: string; expiresAt: number } | undefined {
    return this.state.oauth[name];
  }

  setOAuth(name: string, tokens: { accessToken: string; refreshToken: string; expiresAt: number }): void {
    this.state.oauth[name] = tokens;
    this.saveNow(); // never lose a login to a restart
  }

  clearOAuth(name: string): void {
    delete this.state.oauth[name];
    this.saveNow();
  }

  isParked(owner: string): boolean {
    return (this.state.parkedUntil[owner] ?? 0) > Date.now();
  }

  parkedUntil(owner: string): number | null {
    const until = this.state.parkedUntil[owner] ?? 0;
    return until > Date.now() ? until : null;
  }

  park(owner: string, forMs: number): void {
    this.state.parkedUntil[owner] = Date.now() + forMs;
    this.save();
  }

  unpark(owner: string): void {
    delete this.state.parkedUntil[owner];
    this.save();
  }

  record(owner: string, consumer: string, usd: number): void {
    const byOwner = (this.state.spend[currentMonth()] ??= {});
    const byConsumer = (byOwner[owner] ??= {});
    byConsumer[consumer] = (byConsumer[consumer] ?? 0) + usd;
    const t = Date.now();
    this.state.usageLog.push({ t, owner, consumer, usd });
    if (consumer !== owner) this.state.borrowLog.push({ t, owner, consumer, usd });
    else this.state.lastOwnUse[owner] = Math.max(this.state.lastOwnUse[owner] ?? 0, t);
    if (this.state.usageLog.length > Ledger.MAX_LOG || this.state.borrowLog.length > Ledger.MAX_LOG) this.pruneLog();
    this.save();
  }

  // Everything spent on `owner`'s token this month, keyed by who spent it.
  spendOn(owner: string): Record<string, number> {
    return this.state.spend[currentMonth()]?.[owner] ?? {};
  }

  totalSpentOn(owner: string): number {
    return sum(Object.values(this.spendOn(owner)));
  }

  spentByOthersOn(owner: string): number {
    return sum(Object.entries(this.spendOn(owner)).filter(([who]) => who !== owner).map(([, usd]) => usd));
  }

  private save(): void {
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => this.saveNow(), 500);
  }

  private saveNow(): void {
    clearTimeout(this.saveTimer);
    const tmp = `${this.path}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
      renameSync(tmp, this.path);
    } catch (err) {
      // A full disk must not take the pool down from a timer; the next write retries.
      console.log(`[pool] could not save ${this.path}: ${(err as Error).message}`);
    }
  }
}

function currentMonth(date = new Date()): string {
  return date.toISOString().slice(0, 7);
}

// ISO week start (Monday 00:00 UTC) as a timestamp.
function weekStartTs(now: number): number {
  const d = new Date(now);
  const utcMidnight = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  const day = new Date(utcMidnight).getUTCDay() || 7; // Mon=1..Sun=7
  return utcMidnight - (day - 1) * 86_400_000;
}

function sum(values: number[]): number {
  return values.reduce((a, b) => a + b, 0);
}
