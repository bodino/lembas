//! A peer: one Mac in a circle, lending and borrowing with no pool in between.
//!
//! Every Mac runs one of these. It listens on an iroh endpoint (QUIC, NAT
//! hole punching, a relay when that fails; the peer's Ed25519 key is both its
//! identity and its address) and speaks to other members over bidirectional
//! streams, the first byte of each saying what the stream is for:
//!
//! - **join**: a newcomer with an invite link asks the inviter in; the
//!   inviter signs its membership and hands it the circle.
//! - **sync**: members exchange the circle (signed memberships, merged) and
//!   their presence (away or working, lending or not, room to lend).
//! - **limit**: a member proves to this Mac, as a lender, that its own
//!   account is at its usage limit ([`crate::limit`]). The proof is kept
//!   until the window resets.
//! - **borrow**: a member borrows; this Mac runs the pool's side of the
//!   spliced token record ([`crate::session`]) with its own token, lending
//!   only to members it chose to lend to, with a fresh limit proof, while
//!   its own usage is under its limits.
//!
//! Borrowing is the other way round: the local HTTP proxy picks a lender from
//! the presence it heard, proves its limit to that lender if it has not
//! lately, and runs the borrower's side of a session over a borrow stream.
//!
//! A Mac can be in more than one circle: the one it founded or joined first,
//! which its invites are to, and any it joined later on a friend's invite.
//! Lending and borrowing go by being in a circle together, whichever it is.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey, endpoint::Connection};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info, warn};

use crate::{
    TOKEN_LEN,
    circle::{Circle, CircleId, CircleState, Invite, JoinReply, JoinRequest, Membership, Removal, now},
    limit::{self, Usage},
    link,
    local::{LocalListener, serve_client_for},
    session::{Connector, Lease, RequestRule, Session, TokenSource, run_pool},
};

/// The protocol every peer speaks.
pub const ALPN: &[u8] = b"lembas/p2p/1";
/// How often members sync.
pub const SYNC_EVERY: Duration = Duration::from_secs(30);
/// Presence older than this is not acted on.
pub const PRESENCE_TTL_SECS: u64 = 150;
/// How often this Mac reads its own usage.
pub const USAGE_EVERY: Duration = Duration::from_secs(60);
/// Longest a limit proof is trusted without a reset time to go by.
pub const PROOF_DEFAULT_SECS: u64 = 3600;
/// Longest a limit proof is trusted at all.
pub const PROOF_MAX_SECS: u64 = 6 * 3600;
/// Largest control message on a join or sync stream.
const MAX_MESSAGE: usize = 1 << 20;
/// Ledger entries older than this are dropped; the app shows a week.
const LEDGER_KEEP_SECS: u64 = 8 * 24 * 3600;
/// This Mac's own spend is kept per this many seconds.
const OWN_BUCKET_SECS: u64 = 300;
/// Most a single borrowed request may be reported to have cost, in dollars.
const MAX_REPORT_USD: f64 = 10.0;
/// And one of this Mac's own.
const MAX_OWN_USD: f64 = 100.0;
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// What a stream is for: its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Role {
    Join = 1,
    Sync = 2,
    Limit = 3,
    Borrow = 4,
}

impl Role {
    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            1 => Role::Join,
            2 => Role::Sync,
            3 => Role::Limit,
            4 => Role::Borrow,
            other => bail!("unknown stream role {other}"),
        })
    }
}

/// What one Mac tells its circle about itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Presence {
    pub at: u64,
    pub name: String,
    pub away: bool,
    /// Has a login and lending is on.
    pub lending: bool,
    pub five_hour: Option<f64>,
    pub seven_day: Option<f64>,
    /// Would lend to someone right now, by its own limits.
    pub room: bool,
}

/// What one borrowed request cost, as the borrower's agent metered it. The
/// lender takes the borrower's word, as the pool did: it cannot see the
/// response, and the borrower has little to gain from lying to a friend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub id: u64,
    pub at: u64,
    pub usd: f64,
    pub model: String,
}

/// A borrowed request in this Mac's own book: lent by `lender` to `borrower`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: u64,
    pub at: u64,
    pub lender: PublicKey,
    pub borrower: PublicKey,
    pub usd: f64,
    pub model: String,
}

/// What this Mac's own requests cost, as its agent metered them: dollars per
/// five minutes. It never leaves this Mac; it is the other half of the
/// friends' share of a window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OwnSpend {
    /// When metering began: nothing is known of what was spent before.
    since: u64,
    buckets: BTreeMap<u64, f64>,
}

/// One sync exchange, each way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMsg {
    pub circle: CircleId,
    pub state: CircleState,
    pub presence: Presence,
    pub addr: EndpointAddr,
    /// What the sender borrowed from the receiver lately.
    #[serde(default)]
    pub reports: Vec<Report>,
}

/// The owner's limits, the pool's numbers by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LendPolicy {
    /// Lend while away until the five-hour window reaches this.
    pub away5h: f64,
    /// Never lend past this much of the week.
    pub week: f64,
    /// A borrower must prove a window at or past this.
    pub borrow_at: f64,
    /// Idle this long and the owner counts as away (the app or agent flips
    /// the switch; the peer only keeps the number).
    #[serde(default = "default_away_after")]
    pub away_after_minutes: u32,
}

fn default_away_after() -> u32 {
    30
}

impl Default for LendPolicy {
    fn default() -> Self {
        Self {
            away5h: 70.0,
            week: 60.0,
            borrow_at: 90.0,
            away_after_minutes: 30,
        }
    }
}

/// What the owner decided, kept on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    pub policy: LendPolicy,
    /// Per member: lend to them? Unset is no, until the owner says so (the
    /// member this Mac invited is set to yes at the invite).
    pub lend_to: BTreeMap<PublicKey, bool>,
    /// Lend to them even while working?
    pub lend_while_working: BTreeMap<PublicKey, bool>,
    pub away: bool,
}

/// The API server this peer probes and lends for.
#[derive(Clone)]
pub struct ApiTarget {
    pub server: String,
    pub server_name: String,
    pub usage_path: String,
    pub roots: rustls::RootCertStore,
    /// The usage endpoint answers JSON with windows; a test server does not,
    /// and any 200 then passes as a limit.
    pub require_usage: bool,
    /// The requests this Mac lends its login to; `None` lends to any.
    pub lendable: Option<RequestRule>,
}

/// What a friend may borrow a login for: a model call, or the count of its
/// tokens. The login also opens its owner's profile and usage, and those stay
/// the owner's.
pub fn model_request(line: &str) -> bool {
    let mut parts = line.split(' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return false };
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    method == "POST" && matches!(path, "/v1/messages" | "/v1/messages/count_tokens")
}

impl ApiTarget {
    pub fn anthropic() -> Self {
        Self {
            server: "api.anthropic.com:443".into(),
            server_name: "api.anthropic.com".into(),
            usage_path: limit::USAGE_PATH.into(),
            roots: crate::mozilla_roots(),
            require_usage: true,
            lendable: Some(model_request),
        }
    }
}

pub struct PeerConfig {
    /// Where the key, the circle and the settings live.
    pub dir: PathBuf,
    pub name: String,
    /// This Mac's own subscription token, for lending and for proving.
    pub token: Option<String>,
    /// Or a JSON file with `accessToken`, read at each use so that whoever
    /// refreshes the login (the agent) need not restart the peer.
    pub token_file: Option<PathBuf>,
    pub api: ApiTarget,
    /// Use n0's relays and address lookup (off for local tests).
    pub relay: bool,
    /// Bind here instead of an ephemeral port on every interface.
    pub bind: Option<SocketAddr>,
}

/// A limit proof this Mac verified, as a lender.
#[derive(Debug, Clone, Serialize)]
pub struct Proof {
    pub usage: Option<Usage>,
    pub until: u64,
}

#[derive(Default)]
struct State {
    /// The circles this Mac is in. The first is its own: the one it founded
    /// or joined first, and the one its invites are to. The others it joined
    /// later, on an invite from someone in them. The app shows the people of
    /// all of them as one list.
    circles: Vec<Circle>,
    settings: Settings,
    /// Invites handed out: secret and expiry.
    invites: Vec<([u8; 16], u64)>,
    presence: BTreeMap<PublicKey, Presence>,
    addrs: BTreeMap<PublicKey, EndpointAddr>,
    proofs: BTreeMap<PublicKey, Proof>,
    /// Lenders that hold a proof of ours, until when.
    proved: BTreeMap<PublicKey, u64>,
    my_usage: Option<(Usage, u64)>,
    ledger: Vec<LedgerEntry>,
    own: OwnSpend,
}

impl State {
    /// Whether `who` is in a circle with this Mac.
    fn knows(&self, who: &PublicKey) -> bool {
        self.circles.iter().any(|c| c.is_member(who))
    }

    fn name_of(&self, who: &PublicKey) -> String {
        self.circles
            .iter()
            .find_map(|c| c.memberships.get(who))
            .map(|m| m.name.clone())
            .unwrap_or_else(|| who.fmt_short().to_string())
    }
}

/// A borrowing session with one lender.
struct Borrowing {
    session: Arc<Session>,
    _mux: mpz_common::Session,
    _close: oneshot::Sender<()>,
}

pub struct Peer {
    pub endpoint: Endpoint,
    secret: SecretKey,
    cfg: PeerConfig,
    state: Mutex<State>,
    connections: tokio::sync::Mutex<HashMap<PublicKey, Connection>>,
    borrowing: tokio::sync::Mutex<HashMap<PublicKey, Arc<Borrowing>>>,
    /// Proofs and borrows to one lender at a time.
    lender_locks: tokio::sync::Mutex<HashMap<PublicKey, Arc<tokio::sync::Mutex<()>>>>,
}

/// A snapshot for the app.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub me: PublicKey,
    pub name: String,
    /// This Mac's own circle, if it is in any.
    pub circle: Option<CircleId>,
    pub away: bool,
    pub lending: bool,
    pub usage: Option<Usage>,
    pub policy: LendPolicy,
    /// Dollars lent and borrowed, last 7 days and last 5 hours.
    pub lent_week: f64,
    pub borrowed_week: f64,
    pub lent_5h: f64,
    pub borrowed_5h: f64,
    /// The friends' part of each window's utilization, in points (estimate).
    pub lent_five_hour: Option<f64>,
    pub lent_seven_day: Option<f64>,
    pub members: Vec<MemberStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberStatus {
    pub id: PublicKey,
    pub name: String,
    pub lend_to: Option<bool>,
    pub lend_while_working: bool,
    pub presence: Option<Presence>,
    pub proof: Option<Proof>,
    pub proved_until: Option<u64>,
    pub lent_week: f64,
    pub borrowed_week: f64,
}

impl Peer {
    /// Loads or creates the identity, binds the endpoint, starts the loops.
    pub async fn start(cfg: PeerConfig) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&cfg.dir).with_context(|| format!("creating {}", cfg.dir.display()))?;
        let secret = load_or_create_key(&cfg.dir.join("peer.key"))?;
        let mut builder = if cfg.relay {
            Endpoint::builder(iroh::endpoint::presets::N0)
        } else {
            Endpoint::builder(iroh::endpoint::presets::Minimal)
        };
        builder = builder.secret_key(secret.clone()).alpns(vec![ALPN.to_vec()]);
        if let Some(bind) = cfg.bind {
            builder = builder.bind_addr(bind)?;
        }
        let endpoint = builder.bind().await?;
        info!(id = %endpoint.id(), name = cfg.name, "peer: up");

        let mut state = State::default();
        if let Ok(text) = std::fs::read(cfg.dir.join("circle.json")) {
            state.circles.extend(serde_json::from_slice::<Circle>(&text).ok());
        }
        if let Ok(text) = std::fs::read(cfg.dir.join("joined.json")) {
            state.circles.extend(serde_json::from_slice::<Vec<Circle>>(&text).unwrap_or_default());
        }
        if let Ok(text) = std::fs::read(cfg.dir.join("settings.json")) {
            state.settings = serde_json::from_slice(&text).unwrap_or_default();
        }
        if let Ok(text) = std::fs::read(cfg.dir.join("ledger.json")) {
            state.ledger = serde_json::from_slice(&text).unwrap_or_default();
        }
        if let Ok(text) = std::fs::read(cfg.dir.join("own.json")) {
            state.own = serde_json::from_slice(&text).unwrap_or_default();
        }
        let peer = Arc::new(Self {
            endpoint,
            secret,
            cfg,
            state: Mutex::new(state),
            connections: Default::default(),
            borrowing: Default::default(),
            lender_locks: Default::default(),
        });

        let p = peer.clone();
        tokio::spawn(async move {
            while let Some(incoming) = p.endpoint.accept().await {
                let p = p.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("peer: incoming connection failed: {e}");
                            return;
                        }
                    };
                    let remote = conn.remote_id();
                    loop {
                        let (send, recv) = match conn.accept_bi().await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!(%remote, "peer: connection over: {e}");
                                return;
                            }
                        };
                        let p = p.clone();
                        tokio::spawn(async move {
                            if let Err(e) = p.handle_stream(remote, send, recv).await {
                                debug!(%remote, "peer: stream: {e:#}");
                            }
                        });
                    }
                });
            }
        });
        let p = peer.clone();
        tokio::spawn(async move {
            loop {
                p.refresh_usage().await;
                tokio::time::sleep(USAGE_EVERY).await;
            }
        });
        let p = peer.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SYNC_EVERY).await;
                p.sync_all().await;
            }
        });
        Ok(peer)
    }

    pub fn id(&self) -> PublicKey {
        self.endpoint.id()
    }

    /// This Mac's own token, from the config or the token file.
    pub fn token(&self) -> Option<String> {
        if let Some(t) = &self.cfg.token {
            return Some(t.clone());
        }
        let path = self.cfg.token_file.as_ref()?;
        let text = std::fs::read(path).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&text).ok()?;
        v.get("accessToken")
            .and_then(|t| t.as_str())
            .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
            .map(str::to_string)
    }

    fn persist(&self, state: &State) {
        if let Some(c) = state.circles.first()
            && let Ok(json) = serde_json::to_vec_pretty(c)
        {
            let _ = std::fs::write(self.cfg.dir.join("circle.json"), json);
        }
        // The circles joined later, in a file of their own: `circle.json`
        // stays what it was before a Mac could be in more than one.
        let joined = self.cfg.dir.join("joined.json");
        if state.circles.len() > 1 {
            if let Ok(json) = serde_json::to_vec_pretty(&state.circles[1..]) {
                let _ = std::fs::write(joined, json);
            }
        } else {
            let _ = std::fs::remove_file(joined);
        }
        if let Ok(json) = serde_json::to_vec_pretty(&state.settings) {
            let _ = std::fs::write(self.cfg.dir.join("settings.json"), json);
        }
    }

    fn persist_ledger(&self, state: &mut State) {
        let keep = now().saturating_sub(LEDGER_KEEP_SECS);
        state.ledger.retain(|e| e.at >= keep);
        if let Ok(json) = serde_json::to_vec(&state.ledger) {
            let _ = std::fs::write(self.cfg.dir.join("ledger.json"), json);
        }
    }

    /// Dollars `who` lent or borrowed in the last `secs`, and per counterpart.
    fn sums(state: &State, me: &PublicKey, secs: u64) -> (f64, f64, BTreeMap<PublicKey, f64>, BTreeMap<PublicKey, f64>) {
        let since = now().saturating_sub(secs);
        let mut lent = 0.0;
        let mut borrowed = 0.0;
        let mut lent_to = BTreeMap::new();
        let mut borrowed_from = BTreeMap::new();
        for e in state.ledger.iter().filter(|e| e.at >= since) {
            if e.lender == *me {
                lent += e.usd;
                *lent_to.entry(e.borrower).or_insert(0.0) += e.usd;
            } else if e.borrower == *me {
                borrowed += e.usd;
                *borrowed_from.entry(e.lender).or_insert(0.0) += e.usd;
            }
        }
        (lent, borrowed, lent_to, borrowed_from)
    }

    /// The agent metered a request on this Mac's own login.
    pub fn spent(&self, usd: f64) -> Result<()> {
        ensure!(usd.is_finite() && usd >= 0.0, "a cost in dollars");
        let t = now();
        let mut st = self.state.lock().unwrap();
        if st.own.since == 0 {
            st.own.since = t;
        }
        *st.own.buckets.entry(t - t % OWN_BUCKET_SECS).or_insert(0.0) += usd.min(MAX_OWN_USD);
        let keep = t.saturating_sub(LEDGER_KEEP_SECS);
        st.own.buckets.retain(|at, _| *at >= keep);
        if let Ok(json) = serde_json::to_vec(&st.own) {
            let _ = std::fs::write(self.cfg.dir.join("own.json"), json);
        }
        Ok(())
    }

    /// The friends' part of a window's utilization, in points: the utilization
    /// split by dollars, theirs (the ledger) against this Mac's own (its
    /// agent's meter), since the window began. An estimate. Use outside lembas
    /// (claude.ai, the desktop app) isn't seen, so it reads high then. Where
    /// the meter is younger than the window, the split since the meter began
    /// stands for the whole window; before there is a meter, nothing is known.
    fn lent_share(state: &State, me: &PublicKey, window: &str, span: u64) -> Option<f64> {
        let (usage, _) = state.my_usage.as_ref()?;
        let utilization = *usage.windows.get(window)?;
        if state.own.since == 0 {
            return None;
        }
        let t = now();
        let began = match usage.resets_at.get(window).and_then(|s| parse_rfc3339(s)) {
            Some(resets) if resets > t => resets.saturating_sub(span),
            _ => t.saturating_sub(span),
        };
        let since = began.max(state.own.since);
        let lent: f64 = state.ledger.iter().filter(|e| e.lender == *me && e.at >= since).map(|e| e.usd).sum();
        let own: f64 = state.own.buckets.iter().filter(|(at, _)| **at + OWN_BUCKET_SECS > since).map(|(_, usd)| *usd).sum();
        if lent <= 0.0 {
            return Some(0.0);
        }
        Some((utilization.clamp(0.0, 100.0) * lent / (lent + own) * 10.0).round() / 10.0)
    }

    /// The borrower's agent metered a borrowed request: into the book, and to
    /// the lender on the next sync (started now).
    pub async fn report(self: &Arc<Self>, lender: PublicKey, usd: f64, model: String) -> Result<()> {
        ensure!(usd.is_finite() && (0.0..=MAX_REPORT_USD).contains(&usd), "a cost between 0 and {MAX_REPORT_USD} dollars");
        {
            let mut st = self.state.lock().unwrap();
            ensure!(st.knows(&lender), "not a member");
            st.ledger.push(LedgerEntry {
                id: rand::random(),
                at: now(),
                lender,
                borrower: self.id(),
                usd,
                model: model.chars().take(64).collect(),
            });
            self.persist_ledger(&mut st);
        }
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.sync_with(lender).await {
                debug!("peer: telling the lender what it cost: {e:#}");
            }
        });
        Ok(())
    }

    // ---- the circle --------------------------------------------------------

    /// Founds a circle, if this Mac is in none.
    pub fn found(&self) -> Result<CircleId> {
        let mut st = self.state.lock().unwrap();
        ensure!(st.circles.is_empty(), "already in a circle");
        let circle = Circle::found(&self.secret, &self.cfg.name)?;
        let id = circle.id;
        st.circles.push(circle);
        self.persist(&st);
        Ok(id)
    }

    /// An invite link, to this Mac's own circle; the inviter lends to whoever
    /// joins with it.
    pub async fn invite(&self) -> Result<String> {
        let circle = self.state.lock().unwrap().circles.first().map(|c| c.id).context("not in a circle")?;
        if self.cfg.relay {
            let _ = tokio::time::timeout(Duration::from_secs(10), self.endpoint.online()).await;
        }
        let addr = self.endpoint.addr();
        let secret: [u8; 16] = rand::random();
        let expires = now() + crate::circle::INVITE_TTL_SECS;
        self.state.lock().unwrap().invites.push((secret, expires));
        Ok(Invite {
            circle,
            inviter: self.id(),
            relay: addr.relay_urls().next().map(|u| u.to_string()),
            addrs: addr.ip_addrs().copied().collect(),
            secret,
            expires,
        }
        .to_link())
    }

    /// Joins the circle an invite link points to. A Mac already in a circle
    /// keeps it and is in both: its people are those of every circle it is
    /// in, and its own invites stay to its first.
    pub async fn join(self: &Arc<Self>, link: &str) -> Result<()> {
        let invite = Invite::from_link(link)?;
        let me = self.id();
        ensure!(invite.inviter != me, "that invite is your own");
        ensure!(
            !self.state.lock().unwrap().circles.iter().any(|c| c.id == invite.circle && c.is_member(&me)),
            "already in that circle"
        );
        let mut addr = EndpointAddr::new(invite.inviter);
        if let Some(relay) = &invite.relay
            && let Ok(url) = relay.parse()
        {
            addr = addr.with_relay_url(url);
        }
        for a in &invite.addrs {
            addr = addr.with_ip_addr(*a);
        }
        self.state.lock().unwrap().addrs.insert(invite.inviter, addr.clone());
        let conn = self.connect(invite.inviter).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_u8(Role::Join as u8).await?;
        send_json(
            &mut send,
            &JoinRequest {
                circle: invite.circle,
                secret: invite.secret,
                name: self.cfg.name.clone(),
            },
        )
        .await?;
        let reply: JoinReply = tokio::time::timeout(STREAM_TIMEOUT, recv_json(&mut recv))
            .await
            .context("the inviter did not answer")??;
        let _ = send.finish();
        match reply {
            JoinReply::Welcome { state } => {
                let circle = Circle::from_state(invite.circle, &state)?;
                ensure!(circle.is_member(&self.id()), "the inviter's circle does not have us in it");
                let mut st = self.state.lock().unwrap();
                match st.circles.iter_mut().find(|c| c.id == invite.circle) {
                    // Invited back after a removal.
                    Some(have) => {
                        have.merge(&state);
                    }
                    None => st.circles.push(circle),
                }
                // Whoever invited us lends to us; we lend back by default.
                st.settings.lend_to.insert(invite.inviter, true);
                self.persist(&st);
                info!(circle = ?invite.circle, "peer: joined");
            }
            JoinReply::Refused { reason } => bail!("the inviter refused: {reason}"),
        }
        self.sync_all().await;
        Ok(())
    }

    pub fn set_lend(&self, member: PublicKey, lend: bool, while_working: bool) {
        let mut st = self.state.lock().unwrap();
        st.settings.lend_to.insert(member, lend);
        st.settings.lend_while_working.insert(member, while_working);
        self.persist(&st);
    }

    pub fn set_policy(&self, policy: LendPolicy) {
        let mut st = self.state.lock().unwrap();
        st.settings.policy = policy;
        self.persist(&st);
    }

    pub fn set_away(&self, away: bool) {
        let mut st = self.state.lock().unwrap();
        st.settings.away = away;
        self.persist(&st);
    }

    /// Removes someone from every circle this Mac shares with them, and
    /// tells the others. Nobody removes a circle's founder: from a circle
    /// joined on a later invite this Mac takes itself out instead, and
    /// forgets that circle once the others have been told.
    pub async fn remove(&self, member: PublicKey) -> Result<()> {
        let me = self.id();
        ensure!(member != me, "that is this Mac");
        let mut left = Vec::new();
        {
            let mut st = self.state.lock().unwrap();
            let mut removed = false;
            for (i, circle) in st.circles.iter_mut().enumerate() {
                if !circle.is_member(&member) {
                    continue;
                }
                if circle.add_removal(&Removal::sign(circle.id, &self.secret, member)) {
                    removed = true;
                } else if i > 0 && circle.add_removal(&Removal::sign(circle.id, &self.secret, me)) {
                    left.push(circle.id);
                }
            }
            ensure!(removed || !left.is_empty(), "cannot remove them");
            st.settings.lend_to.insert(member, false);
            self.persist(&st);
        }
        self.sync_all().await;
        if !left.is_empty() {
            let mut st = self.state.lock().unwrap();
            st.circles.retain(|c| !left.contains(&c.id));
            self.persist(&st);
        }
        Ok(())
    }

    pub fn status(&self) -> Status {
        let st = self.state.lock().unwrap();
        let me = self.id();
        let (lent_week, borrowed_week, lent_to, borrowed_from) = Self::sums(&st, &me, 7 * 24 * 3600);
        let (lent_5h, borrowed_5h, _, _) = Self::sums(&st, &me, 5 * 3600);
        // The people of every circle, each once.
        let mut seen = std::collections::BTreeSet::from([me]);
        let members = st
            .circles
            .iter()
            .flat_map(|c| c.members())
            .filter(|m| seen.insert(m.member))
            .map(|m| MemberStatus {
                id: m.member,
                name: m.name.clone(),
                lend_to: st.settings.lend_to.get(&m.member).copied(),
                lend_while_working: st.settings.lend_while_working.get(&m.member).copied().unwrap_or(false),
                presence: st.presence.get(&m.member).cloned(),
                proof: st.proofs.get(&m.member).cloned(),
                proved_until: st.proved.get(&m.member).copied(),
                lent_week: lent_to.get(&m.member).copied().unwrap_or(0.0),
                borrowed_week: borrowed_from.get(&m.member).copied().unwrap_or(0.0),
            })
            .collect();
        Status {
            me: self.id(),
            name: self.cfg.name.clone(),
            circle: st.circles.first().map(|c| c.id),
            away: st.settings.away,
            lending: self.token().is_some(),
            usage: st.my_usage.as_ref().map(|(u, _)| u.clone()),
            policy: st.settings.policy.clone(),
            lent_week,
            borrowed_week,
            lent_5h,
            borrowed_5h,
            lent_five_hour: Self::lent_share(&st, &me, "five_hour", 5 * 3600),
            lent_seven_day: Self::lent_share(&st, &me, "seven_day", 7 * 24 * 3600),
            members,
        }
    }

    // ---- lending: this Mac's own limits ------------------------------------

    fn presence(&self, st: &State) -> Presence {
        let usage = st.my_usage.as_ref().map(|(u, _)| u);
        Presence {
            at: now(),
            name: self.cfg.name.clone(),
            away: st.settings.away,
            lending: self.token().is_some(),
            five_hour: usage.and_then(|u| u.windows.get("five_hour").copied()),
            seven_day: usage.and_then(|u| u.windows.get("seven_day").copied()),
            room: self.room(st, None).is_ok(),
        }
    }

    /// Whether this Mac would lend right now (to `to`, if given), by its own
    /// limits against its own live usage.
    fn room(&self, st: &State, to: Option<&PublicKey>) -> Result<(), String> {
        if self.token().is_none() {
            return Err("no login to lend".into());
        }
        let Some((usage, at)) = &st.my_usage else {
            return Err("own usage unknown".into());
        };
        if now().saturating_sub(*at) > 3 * USAGE_EVERY.as_secs() {
            return Err("own usage stale".into());
        }
        if usage.locked {
            return Err("own login is locked".into());
        }
        let policy = &st.settings.policy;
        let five = usage.windows.get("five_hour").copied().unwrap_or(100.0);
        let week = usage.windows.get("seven_day").copied().unwrap_or(100.0);
        if week >= policy.week {
            return Err(format!("week at {week:.0}%"));
        }
        if five >= policy.away5h {
            return Err(format!("five-hour window at {five:.0}%"));
        }
        if !st.settings.away
            && let Some(to) = to
            && !st.settings.lend_while_working.get(to).copied().unwrap_or(false)
        {
            return Err("working, and they may only borrow while away".into());
        }
        Ok(())
    }

    /// Whether to lend to `who` for one request right now.
    fn lending_gate(&self, who: &PublicKey) -> Result<String, String> {
        let st = self.state.lock().unwrap();
        if !st.knows(who) {
            return Err("not a member".into());
        }
        if !st.settings.lend_to.get(who).copied().unwrap_or(false) {
            return Err("not lending to them".into());
        }
        match st.proofs.get(who) {
            Some(p) if p.until > now() => {}
            _ => return Err("prove your limit first".into()),
        }
        self.room(&st, Some(who))?;
        Ok(self.token().ok_or("no login")?)
    }

    async fn refresh_usage(&self) {
        let Some(token) = self.token() else { return };
        if !self.cfg.api.require_usage {
            // A test server has no usage endpoint: pretend an idle account.
            let mut st = self.state.lock().unwrap();
            st.my_usage = Some((
                Usage {
                    windows: BTreeMap::from([("five_hour".into(), 0.0), ("seven_day".into(), 0.0)]),
                    resets_at: BTreeMap::new(),
                    locked: false,
                },
                now(),
            ));
            return;
        }
        let api = self.cfg.api.clone();
        match tokio::task::spawn_blocking(move || fetch_usage(&api, &token)).await {
            Ok(Ok(usage)) => {
                debug!(?usage, "peer: own usage");
                self.state.lock().unwrap().my_usage = Some((usage, now()));
            }
            Ok(Err(e)) => warn!("peer: reading own usage: {e:#}"),
            Err(e) => warn!("peer: reading own usage: {e}"),
        }
    }

    // ---- streams this Mac answers ------------------------------------------

    async fn handle_stream(
        self: &Arc<Self>,
        remote: PublicKey,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> Result<()> {
        let role = Role::from_byte(tokio::time::timeout(STREAM_TIMEOUT, recv.read_u8()).await??)?;
        let is_member = self.state.lock().unwrap().knows(&remote);
        match role {
            Role::Join => {
                let req: JoinRequest = tokio::time::timeout(STREAM_TIMEOUT, recv_json(&mut recv)).await??;
                let reply = self.admit(remote, &req);
                send_json(&mut send, &reply).await?;
                let _ = send.finish();
                let _ = tokio::time::timeout(STREAM_TIMEOUT, send.stopped()).await;
                if matches!(reply, JoinReply::Welcome { .. }) {
                    self.sync_all().await;
                }
                Ok(())
            }
            Role::Sync => {
                ensure!(is_member, "sync from a non-member");
                let theirs: SyncMsg = tokio::time::timeout(STREAM_TIMEOUT, recv_json(&mut recv)).await??;
                let mine = self.take_sync(remote, theirs)?;
                send_json(&mut send, &mine).await?;
                let _ = send.finish();
                let _ = tokio::time::timeout(STREAM_TIMEOUT, send.stopped()).await;
                Ok(())
            }
            Role::Limit => {
                ensure!(is_member, "limit proof from a non-member");
                let api = &self.cfg.api;
                let server = TcpStream::connect(&api.server)
                    .await
                    .with_context(|| format!("connecting to {}", api.server))?;
                server.set_nodelay(true)?;
                let io = tokio::io::join(recv, send).compat();
                let l = link(io)?;
                let driver = tokio::spawn(l.driver);
                let verified = limit::verify(l.mpc, l.up, l.down, server, &api.server_name, &api.usage_path, None).await;
                drop(l.session);
                let _ = l.close.send(());
                let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
                let verified = verified?;
                let (usage, until) = if api.require_usage {
                    let usage = verified.usage()?;
                    ensure!(
                        usage.at_limit(self.state.lock().unwrap().settings.policy.borrow_at),
                        "their login is not at a usage limit"
                    );
                    let until = proof_until(&usage);
                    (Some(usage), until)
                } else {
                    (None, now() + PROOF_DEFAULT_SECS)
                };
                let name = self.name_of(&remote);
                info!(member = name, until, "peer: limit proof accepted");
                self.state.lock().unwrap().proofs.insert(remote, Proof { usage, until });
                Ok(())
            }
            Role::Borrow => {
                ensure!(is_member, "borrow from a non-member");
                let name = self.name_of(&remote);
                info!(member = name, "peer: lending session");
                let io = tokio::io::join(recv, send).compat();
                let l = link(io)?;
                let driver = tokio::spawn(l.driver);
                let me = self.clone();
                let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let tokens: TokenSource = Arc::new(move || {
                    let me = me.clone();
                    let counter = counter.clone();
                    Box::pin(async move {
                        match me.lending_gate(&remote) {
                            Ok(token) => Ok(Some(Lease {
                                token,
                                req: counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
                            })),
                            Err(reason) => Err(anyhow::anyhow!("{reason}")),
                        }
                    })
                });
                let connector = tcp_connector(self.cfg.api.server.clone());
                let stats = run_pool(l.mpc, l.up, l.down, connector, &self.cfg.api.server_name, tokens, self.cfg.api.lendable, None, None).await;
                drop(l.session);
                let _ = l.close.send(());
                let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
                let stats = stats?;
                info!(member = name, ?stats, "peer: lending session over");
                Ok(())
            }
        }
    }

    fn admit(&self, remote: PublicKey, req: &JoinRequest) -> JoinReply {
        let mut st = self.state.lock().unwrap();
        let t = now();
        st.invites.retain(|(_, exp)| *exp > t);
        let Some(i) = st.invites.iter().position(|(s, _)| *s == req.secret) else {
            return JoinReply::Refused {
                reason: "unknown or expired invite".into(),
            };
        };
        let Some(circle) = st.circles.first() else {
            return JoinReply::Refused {
                reason: "not in a circle".into(),
            };
        };
        if circle.id != req.circle {
            return JoinReply::Refused {
                reason: "another circle".into(),
            };
        }
        let membership = match Membership::sign(circle.id, &self.secret, remote, &req.name) {
            Ok(m) => m,
            Err(e) => {
                return JoinReply::Refused {
                    reason: format!("{e:#}"),
                };
            }
        };
        st.invites.remove(i);
        let circle = &mut st.circles[0];
        if !circle.add_membership(&membership) {
            return JoinReply::Refused {
                reason: "membership not accepted".into(),
            };
        }
        let state = circle.state();
        // The inviter lends to whoever it invited.
        st.settings.lend_to.insert(remote, true);
        self.persist(&st);
        info!(member = req.name, "peer: admitted");
        JoinReply::Welcome { state }
    }

    /// Merges what a member sent and returns what to send back.
    fn take_sync(&self, remote: PublicKey, theirs: SyncMsg) -> Result<SyncMsg> {
        let mut st = self.state.lock().unwrap();
        let circle = st.circles.iter_mut().find(|c| c.id == theirs.circle).context("another circle")?;
        ensure!(circle.is_member(&remote), "sync from a non-member of that circle");
        let changed = circle.merge(&theirs.state);
        let state = circle.state();
        let id = circle.id;
        if theirs.addr.id == remote {
            st.addrs.insert(remote, theirs.addr);
        }
        if theirs.presence.at + PRESENCE_TTL_SECS > now() {
            st.presence.insert(remote, theirs.presence);
        }
        if changed {
            self.persist(&st);
        }
        // What they borrowed from us, by their count; new entries only.
        let me = self.id();
        let mut booked = false;
        for r in theirs.reports.iter().take(1000) {
            if !r.usd.is_finite() || !(0.0..=MAX_REPORT_USD).contains(&r.usd) || st.ledger.iter().any(|e| e.id == r.id) {
                continue;
            }
            st.ledger.push(LedgerEntry {
                id: r.id,
                at: r.at.min(now()),
                lender: me,
                borrower: remote,
                usd: r.usd,
                model: r.model.chars().take(64).collect(),
            });
            booked = true;
        }
        if booked {
            self.persist_ledger(&mut st);
        }
        Ok(SyncMsg {
            circle: id,
            state,
            presence: self.presence(&st),
            addr: self.endpoint.addr(),
            reports: Self::reports_for(&st, &me, &remote),
        })
    }

    /// What `me` borrowed from `lender` in the last week, to tell them.
    fn reports_for(st: &State, me: &PublicKey, lender: &PublicKey) -> Vec<Report> {
        let since = now().saturating_sub(7 * 24 * 3600);
        st.ledger
            .iter()
            .filter(|e| e.borrower == *me && e.lender == *lender && e.at >= since)
            .map(|e| Report {
                id: e.id,
                at: e.at,
                usd: e.usd,
                model: e.model.clone(),
            })
            .collect()
    }

    fn name_of(&self, who: &PublicKey) -> String {
        self.state.lock().unwrap().name_of(who)
    }

    // ---- streams this Mac opens --------------------------------------------

    async fn connect(&self, peer: PublicKey) -> Result<Connection> {
        let mut conns = self.connections.lock().await;
        if let Some(c) = conns.get(&peer)
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let addr = self
            .state
            .lock()
            .unwrap()
            .addrs
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::new(peer));
        let conn = tokio::time::timeout(STREAM_TIMEOUT, self.endpoint.connect(addr, ALPN))
            .await
            .context("connecting timed out")??;
        conns.insert(peer, conn.clone());
        Ok(conn)
    }

    /// Syncs with every member once.
    pub async fn sync_all(&self) {
        let members: std::collections::BTreeSet<PublicKey> = {
            let st = self.state.lock().unwrap();
            let me = self.id();
            st.circles.iter().flat_map(|c| c.members()).map(|m| m.member).filter(|m| *m != me).collect()
        };
        for m in members {
            if let Err(e) = self.sync_with(m).await {
                debug!(member = self.name_of(&m), "peer: sync: {e:#}");
            }
        }
    }

    /// Syncs with one member: once for each circle shared with them, since a
    /// sync carries one circle.
    pub async fn sync_with(&self, member: PublicKey) -> Result<()> {
        let shared: Vec<CircleId> = {
            let st = self.state.lock().unwrap();
            st.circles.iter().filter(|c| c.is_member(&member)).map(|c| c.id).collect()
        };
        ensure!(!shared.is_empty(), "no circle shared with them");
        for circle in shared {
            self.sync_in(circle, member).await?;
        }
        Ok(())
    }

    async fn sync_in(&self, circle: CircleId, member: PublicKey) -> Result<()> {
        let mine = {
            let st = self.state.lock().unwrap();
            let circle = st.circles.iter().find(|c| c.id == circle).context("not in that circle")?;
            SyncMsg {
                circle: circle.id,
                state: circle.state(),
                presence: self.presence(&st),
                addr: self.endpoint.addr(),
                reports: Self::reports_for(&st, &self.id(), &member),
            }
        };
        let conn = self.connect(member).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_u8(Role::Sync as u8).await?;
        send_json(&mut send, &mine).await?;
        let theirs: SyncMsg = tokio::time::timeout(STREAM_TIMEOUT, recv_json(&mut recv)).await??;
        let _ = send.finish();
        self.take_sync(member, theirs)?;
        Ok(())
    }

    async fn lender_lock(&self, lender: PublicKey) -> Arc<tokio::sync::Mutex<()>> {
        self.lender_locks.lock().await.entry(lender).or_default().clone()
    }

    /// Proves this Mac's limit to `lender`, with its own token.
    pub async fn prove_to(&self, lender: PublicKey) -> Result<()> {
        let token = self.token().context("no login to prove with")?;
        let conn = self.connect(lender).await?;
        let (mut send, recv) = conn.open_bi().await?;
        send.write_u8(Role::Limit as u8).await?;
        let io = tokio::io::join(recv, send).compat();
        let l = link(io)?;
        let driver = tokio::spawn(l.driver);
        let api = &self.cfg.api;
        let proven = limit::prove(l.mpc, l.up, l.down, &api.roots, &api.server_name, &api.usage_path, &token, None).await;
        drop(l.session);
        let _ = l.close.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
        let proven = proven?;
        ensure!(proven.accepted, "the lender refused the proof: {}", proven.detail);
        let until = self
            .state
            .lock()
            .unwrap()
            .my_usage
            .as_ref()
            .map(|(u, _)| proof_until(u))
            .unwrap_or(now() + PROOF_DEFAULT_SECS);
        self.state.lock().unwrap().proved.insert(lender, until);
        info!(lender = self.name_of(&lender), "peer: limit proven");
        Ok(())
    }

    /// A session for borrowing from `lender`, opened if there is none.
    pub async fn borrow_session(&self, lender: PublicKey) -> Result<Arc<Session>> {
        let mut sessions = self.borrowing.lock().await;
        if let Some(b) = sessions.get(&lender) {
            return Ok(b.session.clone());
        }
        let conn = self.connect(lender).await?;
        let (mut send, recv) = conn.open_bi().await?;
        send.write_u8(Role::Borrow as u8).await?;
        let io = tokio::io::join(recv, send).compat();
        let l = link(io)?;
        tokio::spawn(l.driver);
        let api = &self.cfg.api;
        let session = Session::start(l.mpc, l.up, l.down, &api.roots, &api.server_name, TOKEN_LEN).await?;
        let session = Arc::new(session);
        sessions.insert(
            lender,
            Arc::new(Borrowing {
                session: session.clone(),
                _mux: l.session,
                _close: l.close,
            }),
        );
        info!(lender = self.name_of(&lender), "peer: borrowing session ready");
        Ok(session)
    }

    /// Forgets a session that failed.
    pub async fn drop_borrow_session(&self, lender: PublicKey) {
        self.borrowing.lock().await.remove(&lender);
    }

    /// The member to borrow from now: lending, with room, heard from lately,
    /// the one with the most of its five-hour window left.
    pub fn pick_lender(&self) -> Option<PublicKey> {
        let st = self.state.lock().unwrap();
        let t = now();
        st.presence
            .iter()
            .filter(|(id, p)| {
                **id != self.id()
                    && p.lending
                    && p.room
                    && p.at + PRESENCE_TTL_SECS > t
                    && st.knows(id)
            })
            .min_by(|(_, a), (_, b)| {
                a.five_hour
                    .unwrap_or(100.0)
                    .partial_cmp(&b.five_hour.unwrap_or(100.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id)
    }

    /// Serves local HTTP clients, each request a borrowed one from the best
    /// lender, proving this Mac's limit to it first when needed.
    pub async fn serve_proxy(self: Arc<Self>, listener: LocalListener) -> Result<()> {
        info!("peer: proxy on {}", listener.describe());
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let lender = match me.pick_lender() {
                    Some(l) => l,
                    None => {
                        let (_, mut wr) = tokio::io::split(stream);
                        let _ = crate::local::respond_error(&mut wr, 503, "no_lender", "nobody in the circle can lend right now").await;
                        return;
                    }
                };
                let lock = me.lender_lock(lender).await;
                let session = {
                    let _g = lock.lock().await;
                    let proved = me.state.lock().unwrap().proved.get(&lender).copied().unwrap_or(0) > now();
                    if !proved
                        && let Err(e) = me.prove_to(lender).await
                    {
                        warn!(lender = me.name_of(&lender), "peer: limit proof: {e:#}");
                        let (_, mut wr) = tokio::io::split(stream);
                        let _ = crate::local::respond_error(&mut wr, 503, "limit_proof", &format!("{e:#}")).await;
                        return;
                    }
                    match me.borrow_session(lender).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(lender = me.name_of(&lender), "peer: borrowing session: {e:#}");
                            me.drop_borrow_session(lender).await;
                            let (_, mut wr) = tokio::io::split(stream);
                            let _ = crate::local::respond_error(&mut wr, 503, "lender", &format!("{e:#}")).await;
                            return;
                        }
                    }
                };
                if let Err(e) = serve_client_for(session, stream, Some(lender.to_string())).await {
                    debug!("peer: proxy client: {e:#}");
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------

fn load_or_create_key(path: &std::path::Path) -> Result<SecretKey> {
    if let Ok(text) = std::fs::read_to_string(path) {
        let bytes = data_encoding::HEXLOWER
            .decode(text.trim().as_bytes())
            .context("peer.key is not hex")?;
        let bytes: [u8; 32] = bytes.as_slice().try_into().context("peer.key length")?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    std::io::Write::write_all(&mut f, data_encoding::HEXLOWER.encode(&key.to_bytes()).as_bytes())?;
    Ok(key)
}

/// Opens a TCP connection to `server` for each borrowed connection.
pub fn tcp_connector(server: String) -> Connector<TcpStream> {
    Arc::new(move || {
        let server = server.clone();
        Box::pin(async move {
            let stream = TcpStream::connect(&server)
                .await
                .with_context(|| format!("connecting to {server}"))?;
            stream.set_nodelay(true)?;
            Ok(stream)
        })
    })
}

async fn send_json<T: Serialize, W: AsyncWrite + Unpin>(w: &mut W, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_MESSAGE, "message too large");
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

async fn recv_json<T: DeserializeOwned, R: AsyncRead + Unpin>(r: &mut R) -> Result<T> {
    let len = r.read_u32().await? as usize;
    ensure!(len <= MAX_MESSAGE, "message of {len} bytes");
    let mut bytes = vec![0u8; len];
    r.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Until when a proof of this usage holds: the earliest reset of a window at
/// the limit, within bounds.
fn proof_until(usage: &Usage) -> u64 {
    let t = now();
    let mut until = t + PROOF_DEFAULT_SECS;
    for (w, u) in &usage.windows {
        if *u >= 85.0
            && let Some(r) = usage.resets_at.get(w).and_then(|s| parse_rfc3339(s))
            && r > t
        {
            until = until.min(r);
        }
    }
    until.min(t + PROOF_MAX_SECS)
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` to Unix seconds.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
    }
    let offset = match b.get(i) {
        Some(b'Z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(i + 1..i + 3)?;
            let om = num(i + 4..i + 6)?;
            let o = oh * 3600 + om * 60;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let (y, mo) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * mo + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - offset;
    u64::try_from(secs).ok()
}

/// Reads the usage endpoint with this Mac's own token, directly.
fn fetch_usage(api: &ApiTarget, token: &str) -> Result<Usage> {
    use std::io::{Read as _, Write as _};
    let name = rustls::pki_types::ServerName::try_from(api.server_name.clone())?;
    let config = crate::splice::tls_config(&api.roots)?;
    let mut tls = rustls::ClientConnection::new(config, name)?;
    let mut tcp = std::net::TcpStream::connect(&api.server)?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
    stream.write_all(limit::request_text(&api.usage_path, &api.server_name, token).as_bytes())?;
    let mut response = Vec::new();
    let mut framer = crate::local::ResponseFramer::default();
    let mut buf = [0u8; 8192];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        response.extend_from_slice(&buf[..n]);
        framer.feed(&buf[..n])?;
        if framer.complete() {
            break;
        }
    }
    let status = framer.status().context("no status")?;
    ensure!(status == 200, "usage endpoint answered {status}");
    let body = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| crate::dechunk(&response[p + 4..]))
        .context("no body")?;
    Usage::parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parses_what_anthropic_sends() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-10-28T15:19:59.812915+00:00"), Some(1793200799));
        assert_eq!(parse_rfc3339("2026-10-28T17:19:59+02:00"), Some(1793200799));
        assert_eq!(parse_rfc3339("nope"), None);
    }

    #[test]
    fn only_model_requests_are_lendable() {
        for line in [
            "POST /v1/messages HTTP/1.1",
            "POST /v1/messages?beta=true HTTP/1.1",
            "POST /v1/messages/count_tokens?beta=true HTTP/1.1",
        ] {
            assert!(model_request(line), "{line}");
        }
        for line in [
            "GET /api/oauth/profile HTTP/1.1",
            "GET /api/oauth/usage HTTP/1.1",
            "GET /v1/messages HTTP/1.1",
            "POST /v1/messages/batches HTTP/1.1",
            "POST /v1/files HTTP/1.1",
            "POST /v1/messages/../../api/oauth/profile HTTP/1.1",
            "POST /v1/messages%2f..%2f..%2fapi/oauth/profile HTTP/1.1",
            "POST /v1/messages#/api/oauth/profile HTTP/1.1",
            "POST https://api.anthropic.com/v1/messages HTTP/1.1",
            "POST //v1/messages HTTP/1.1",
            "post /v1/messages HTTP/1.1",
            "",
        ] {
            assert!(!model_request(line), "{line}");
        }
    }

    /// A window's utilization splits by dollars: the friends' against this
    /// Mac's own, since the window or the meter began, whichever is later.
    #[test]
    fn friends_share_of_a_window() {
        let key = |n: u8| SecretKey::from_bytes(&[n; 32]).public();
        let (me, friend) = (key(1), key(2));
        let t = now();
        let lent = |at: u64, usd: f64| LedgerEntry { id: at, at, lender: me, borrower: friend, usd, model: String::new() };
        let mut st = State::default();
        st.my_usage = Some((
            Usage {
                windows: BTreeMap::from([("five_hour".into(), 40.0), ("seven_day".into(), 10.0)]),
                resets_at: BTreeMap::new(),
                locked: false,
            },
            t,
        ));
        st.ledger = vec![lent(t - 600, 1.0)];
        let share = |st: &State, w: &str, span: u64| Peer::lent_share(st, &me, w, span);
        // No meter yet: unknown, not "all of it".
        assert_eq!(share(&st, "five_hour", 5 * 3600), None);
        // $1 theirs against $3 mine: a quarter of each window.
        st.own = OwnSpend { since: t - 8 * 24 * 3600, buckets: BTreeMap::from([(t - t % OWN_BUCKET_SECS, 3.0)]) };
        assert_eq!(share(&st, "five_hour", 5 * 3600), Some(10.0));
        assert_eq!(share(&st, "seven_day", 7 * 24 * 3600), Some(2.5));
        // Lending the other way and before the window don't count.
        st.ledger.push(LedgerEntry { id: 2, at: t - 60, lender: friend, borrower: me, usd: 9.0, model: String::new() });
        st.ledger.push(lent(t - 6 * 3600, 2.0));
        assert_eq!(share(&st, "five_hour", 5 * 3600), Some(10.0));
        assert_eq!(share(&st, "seven_day", 7 * 24 * 3600), Some(5.0));
        // A window that began an hour ago, by its reset time: the loan before it is out.
        st.ledger = vec![lent(t - 2 * 3600, 1.0)];
        let usage = &mut st.my_usage.as_mut().unwrap().0;
        usage.resets_at.insert("five_hour".into(), "2999-01-01T00:00:00Z".into());
        let resets = parse_rfc3339("2999-01-01T00:00:00Z").unwrap();
        assert_eq!(Peer::lent_share(&st, &me, "five_hour", resets - (t - 3600)), Some(0.0));
        // A meter younger than the window: only what it saw is split.
        st.own.since = t - 3600;
        assert_eq!(share(&st, "seven_day", 7 * 24 * 3600), Some(0.0));
        // No such window.
        assert_eq!(share(&st, "seven_day_opus", 7 * 24 * 3600), None);
    }

    /// Someone already in a circle takes an invite to another: Bob, in
    /// Alice's, joins Carol's too. He has the people of both, his own invites
    /// stay to the first, and removing Carol, whose circle it is, takes him
    /// out of it again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mac_in_two_circles() {
        let api = ApiTarget {
            server: "127.0.0.1:1".into(),
            server_name: "localhost".into(),
            usage_path: "/".into(),
            roots: crate::fixture_roots().unwrap(),
            require_usage: false,
            lendable: None,
        };
        let tmp = std::env::temp_dir().join(format!("lembas-circles-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let mk = |who: &str| PeerConfig {
            dir: tmp.join(who),
            name: who.to_string(),
            token: None,
            token_file: None,
            api: api.clone(),
            relay: false,
            bind: Some("127.0.0.1:0".parse().unwrap()),
        };
        let alice = Peer::start(mk("Alice")).await.unwrap();
        let bob = Peer::start(mk("Bob")).await.unwrap();
        let carol = Peer::start(mk("Carol")).await.unwrap();
        let names = |p: &Peer| p.status().members.iter().map(|m| m.name.clone()).collect::<Vec<_>>();
        let first = alice.found().unwrap();
        bob.join(&alice.invite().await.unwrap()).await.unwrap();
        let second = carol.found().unwrap();
        assert!(bob.found().is_err(), "one circle of one's own");

        bob.join(&carol.invite().await.unwrap()).await.unwrap();
        assert_eq!(names(&bob), ["Alice", "Carol"]);
        assert_eq!(names(&alice), ["Bob"]);
        assert_eq!(names(&carol), ["Bob"]);
        assert!(carol.status().members.iter().all(|m| m.lend_to == Some(true)));
        assert!(bob.status().members.iter().all(|m| m.lend_to == Some(true)));
        // Each side takes him for a member, and they stay strangers.
        assert!(alice.lending_gate(&bob.id()).unwrap_err().contains("prove your limit"));
        assert!(carol.lending_gate(&bob.id()).unwrap_err().contains("prove your limit"));
        assert!(alice.lending_gate(&carol.id()).unwrap_err().contains("not a member"));
        bob.sync_with(alice.id()).await.unwrap();
        bob.sync_with(carol.id()).await.unwrap();
        assert!(alice.sync_with(carol.id()).await.is_err());

        // His own circle is still the first, and what he invites to.
        assert_eq!(bob.status().circle, Some(first));
        assert_eq!(Invite::from_link(&bob.invite().await.unwrap()).unwrap().circle, first);
        // An invite to a circle he is in is not spent.
        let again = carol.invite().await.unwrap();
        let err = bob.join(&again).await.unwrap_err();
        assert!(format!("{err:#}").contains("already in that circle"), "{err:#}");
        assert!(bob.join(&bob.invite().await.unwrap()).await.is_err(), "his own invite");

        // On disk: the first where it always was, the rest beside it.
        let read = |file: &str| std::fs::read(tmp.join("Bob").join(file));
        assert_eq!(serde_json::from_slice::<Circle>(&read("circle.json").unwrap()).unwrap().id, first);
        let joined: Vec<Circle> = serde_json::from_slice(&read("joined.json").unwrap()).unwrap();
        assert_eq!(joined.iter().map(|c| c.id).collect::<Vec<_>>(), [second]);

        // Nobody removes a founder, so removing Carol is leaving her circle;
        // Alice, the founder of his own, stays.
        bob.remove(carol.id()).await.unwrap();
        assert_eq!(names(&bob), ["Alice"]);
        assert!(names(&carol).is_empty());
        assert!(read("joined.json").is_err());
        assert!(carol.lending_gate(&bob.id()).unwrap_err().contains("not a member"));
        assert!(bob.remove(alice.id()).await.is_err());
        assert_eq!(names(&bob), ["Alice"]);

        // And Carol can have him back.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        bob.join(&again).await.unwrap();
        assert_eq!(names(&bob), ["Alice", "Carol"]);
        assert_eq!(names(&carol), ["Bob"]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Two Macs on one machine: Alice founds a circle and invites Bob; Bob
    /// joins, proves his limit to Alice and borrows from her, all over iroh
    /// with the test server standing in for the API.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_peers_lend_and_borrow() {
        let fixture = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fixture_addr = fixture.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = fixture.accept().await else { break };
                tokio::spawn(async move {
                    let _ = tls_server_fixture::bind_test_server_hyper(stream.compat()).await;
                });
            }
        });
        let api = ApiTarget {
            server: fixture_addr.to_string(),
            server_name: tls_server_fixture::SERVER_DOMAIN.into(),
            usage_path: "/".into(),
            roots: crate::fixture_roots().unwrap(),
            require_usage: false,
            lendable: Some(|line| line.starts_with("POST /echo ")),
        };
        let tmp = std::env::temp_dir().join(format!("lembas-peer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let token = "sk-ant-oat01-".to_string() + &"x".repeat(TOKEN_LEN - 13);
        let mk = |who: &str| PeerConfig {
            dir: tmp.join(who),
            name: who.to_string(),
            token: Some(token.clone()),
            token_file: None,
            api: api.clone(),
            relay: false,
            bind: Some("127.0.0.1:0".parse().unwrap()),
        };
        let alice = Peer::start(mk("Alice")).await.unwrap();
        let bob = Peer::start(mk("Bob")).await.unwrap();
        alice.found().unwrap();
        let link = alice.invite().await.unwrap();
        bob.join(&link).await.unwrap();
        assert!(alice.status().members.iter().any(|m| m.name == "Bob" && m.lend_to == Some(true)));
        assert!(bob.status().members.iter().any(|m| m.name == "Alice"));

        // Presence: Alice is working, so Bob may only borrow if allowed to.
        alice.refresh_usage().await;
        alice.set_away(true);
        bob.sync_with(alice.id()).await.unwrap();
        assert_eq!(bob.pick_lender(), Some(alice.id()));

        // Without a proof Alice refuses; with one she lends.
        let session = bob.borrow_session(alice.id()).await.unwrap();
        let template = "POST /echo HTTP/1.1\r\nHost: {host}\r\nContent-Length: {body_len}\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\n\r\n";
        let mut out = Vec::new();
        let err = session.request(template, b"hello".to_vec(), &mut out, |_| {}).await.unwrap_err();
        assert!(format!("{err:#}").contains("prove your limit first"), "{err:#}");
        bob.prove_to(alice.id()).await.unwrap();
        assert!(alice.status().members.iter().any(|m| m.name == "Bob" && m.proof.is_some()));
        let mut out = Vec::new();
        let response = session.request(template, b"hello".to_vec(), &mut out, |_| {}).await.unwrap();
        assert_eq!(response.status, Some(200));
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("hello"), "{text}");
        assert!(!text.contains(&token));

        // Alice lends her login to /echo and nothing else it opens: refused,
        // and the session carries on.
        for line in ["GET /echo", "POST /", "POST /echo/../profile"] {
            let other = template.replace("POST /echo", line);
            let mut out = Vec::new();
            let err = session.request(&other, b"hello".to_vec(), &mut out, |_| {}).await.unwrap_err();
            assert!(format!("{err:#}").contains("only model requests"), "{line}: {err:#}");
            assert!(out.is_empty(), "{line}");
        }
        let mut out = Vec::new();
        let response = session.request(template, b"still".to_vec(), &mut out, |_| {}).await.unwrap();
        assert_eq!(response.status, Some(200));

        // Alice stops lending to Bob: refused again, on the same session.
        alice.set_lend(bob.id(), false, false);
        let mut out = Vec::new();
        let err = session.request(template, b"again".to_vec(), &mut out, |_| {}).await.unwrap_err();
        assert!(format!("{err:#}").contains("not lending"), "{err:#}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
