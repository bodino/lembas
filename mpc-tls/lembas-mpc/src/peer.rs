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
    local::{LocalListener, serve_client},
    session::{Connector, Lease, Session, TokenSource, run_pool},
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

/// One sync exchange, each way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMsg {
    pub circle: CircleId,
    pub state: CircleState,
    pub presence: Presence,
    pub addr: EndpointAddr,
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
}

impl ApiTarget {
    pub fn anthropic() -> Self {
        Self {
            server: "api.anthropic.com:443".into(),
            server_name: "api.anthropic.com".into(),
            usage_path: limit::USAGE_PATH.into(),
            roots: crate::mozilla_roots(),
            require_usage: true,
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
    circle: Option<Circle>,
    settings: Settings,
    /// Invites handed out: secret and expiry.
    invites: Vec<([u8; 16], u64)>,
    presence: BTreeMap<PublicKey, Presence>,
    addrs: BTreeMap<PublicKey, EndpointAddr>,
    proofs: BTreeMap<PublicKey, Proof>,
    /// Lenders that hold a proof of ours, until when.
    proved: BTreeMap<PublicKey, u64>,
    my_usage: Option<(Usage, u64)>,
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
    pub circle: Option<CircleId>,
    pub away: bool,
    pub lending: bool,
    pub usage: Option<Usage>,
    pub policy: LendPolicy,
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
            state.circle = serde_json::from_slice(&text).ok();
        }
        if let Ok(text) = std::fs::read(cfg.dir.join("settings.json")) {
            state.settings = serde_json::from_slice(&text).unwrap_or_default();
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
        if let Some(c) = &state.circle
            && let Ok(json) = serde_json::to_vec_pretty(c)
        {
            let _ = std::fs::write(self.cfg.dir.join("circle.json"), json);
        }
        if let Ok(json) = serde_json::to_vec_pretty(&state.settings) {
            let _ = std::fs::write(self.cfg.dir.join("settings.json"), json);
        }
    }

    // ---- the circle --------------------------------------------------------

    /// Founds a circle, if this Mac is in none.
    pub fn found(&self) -> Result<CircleId> {
        let mut st = self.state.lock().unwrap();
        ensure!(st.circle.is_none(), "already in a circle");
        let circle = Circle::found(&self.secret, &self.cfg.name)?;
        let id = circle.id;
        st.circle = Some(circle);
        self.persist(&st);
        Ok(id)
    }

    /// An invite link; the inviter lends to whoever joins with it.
    pub async fn invite(&self) -> Result<String> {
        let circle = self.state.lock().unwrap().circle.as_ref().map(|c| c.id).context("not in a circle")?;
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

    /// Joins the circle an invite link points to.
    pub async fn join(self: &Arc<Self>, link: &str) -> Result<()> {
        ensure!(self.state.lock().unwrap().circle.is_none(), "already in a circle");
        let invite = Invite::from_link(link)?;
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
                st.circle = Some(circle);
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

    /// Removes someone from the circle, as far as this Mac is concerned, and
    /// tells the others.
    pub async fn remove(&self, member: PublicKey) -> Result<()> {
        {
            let mut st = self.state.lock().unwrap();
            let circle = st.circle.as_mut().context("not in a circle")?;
            let removal = Removal::sign(circle.id, &self.secret, member);
            ensure!(circle.add_removal(&removal), "cannot remove them");
            st.settings.lend_to.insert(member, false);
            self.persist(&st);
        }
        self.sync_all().await;
        Ok(())
    }

    pub fn status(&self) -> Status {
        let st = self.state.lock().unwrap();
        let members = st
            .circle
            .as_ref()
            .map(|c| {
                c.members()
                    .filter(|m| m.member != self.id())
                    .map(|m| MemberStatus {
                        id: m.member,
                        name: m.name.clone(),
                        lend_to: st.settings.lend_to.get(&m.member).copied(),
                        lend_while_working: st.settings.lend_while_working.get(&m.member).copied().unwrap_or(false),
                        presence: st.presence.get(&m.member).cloned(),
                        proof: st.proofs.get(&m.member).cloned(),
                        proved_until: st.proved.get(&m.member).copied(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Status {
            me: self.id(),
            name: self.cfg.name.clone(),
            circle: st.circle.as_ref().map(|c| c.id),
            away: st.settings.away,
            lending: self.token().is_some(),
            usage: st.my_usage.as_ref().map(|(u, _)| u.clone()),
            policy: st.settings.policy.clone(),
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
        let circle = st.circle.as_ref().ok_or("not in a circle")?;
        if !circle.is_member(who) {
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
        let is_member = self
            .state
            .lock()
            .unwrap()
            .circle
            .as_ref()
            .is_some_and(|c| c.is_member(&remote));
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
                let stats = run_pool(l.mpc, l.up, l.down, connector, &self.cfg.api.server_name, tokens, None, None).await;
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
        let Some(circle) = st.circle.as_ref() else {
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
        let circle = st.circle.as_mut().unwrap();
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
        let circle = st.circle.as_mut().context("not in a circle")?;
        ensure!(circle.id == theirs.circle, "another circle");
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
        Ok(SyncMsg {
            circle: id,
            state,
            presence: self.presence(&st),
            addr: self.endpoint.addr(),
        })
    }

    fn name_of(&self, who: &PublicKey) -> String {
        self.state
            .lock()
            .unwrap()
            .circle
            .as_ref()
            .map(|c| c.name_of(who))
            .unwrap_or_else(|| who.fmt_short().to_string())
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
        let members: Vec<PublicKey> = {
            let st = self.state.lock().unwrap();
            st.circle
                .as_ref()
                .map(|c| c.members().map(|m| m.member).filter(|m| *m != self.id()).collect())
                .unwrap_or_default()
        };
        for m in members {
            if let Err(e) = self.sync_with(m).await {
                debug!(member = self.name_of(&m), "peer: sync: {e:#}");
            }
        }
    }

    pub async fn sync_with(&self, member: PublicKey) -> Result<()> {
        let mine = {
            let st = self.state.lock().unwrap();
            let circle = st.circle.as_ref().context("not in a circle")?;
            SyncMsg {
                circle: circle.id,
                state: circle.state(),
                presence: self.presence(&st),
                addr: self.endpoint.addr(),
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
                    && st.circle.as_ref().is_some_and(|c| c.is_member(id))
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
                if let Err(e) = serve_client(session, stream).await {
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

        // Alice stops lending to Bob: refused again, on the same session.
        alice.set_lend(bob.id(), false, false);
        let mut out = Vec::new();
        let err = session.request(template, b"again".to_vec(), &mut out, |_| {}).await.unwrap_err();
        assert!(format!("{err:#}").contains("not lending"), "{err:#}");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
