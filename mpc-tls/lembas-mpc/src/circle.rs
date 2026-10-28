//! A circle: the people whose Macs lend to each other, with no server and no
//! leader.
//!
//! Each Mac has an Ed25519 key; its public half is its identity and, as the
//! iroh endpoint id, its address. A circle is a set of **memberships**, each
//! signed by the member who invited that person (the founder's by itself).
//! The set only grows and is merged peer to peer: a membership is accepted
//! when its signature checks and its inviter was a member at the time. A
//! **removal** is signed by any member; a later membership reinstates. Who
//! actually lends to whom is each Mac's own choice (see [`crate::peer`]) and
//! is not in the circle at all, so nothing here needs an authority.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail, ensure};
use iroh::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// A circle's identifier: random, picked by the founder.
pub type CircleId = [u8; 16];

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Longest a name may be.
pub const MAX_NAME: usize = 48;

/// Someone's membership, signed by whoever invited them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub circle: CircleId,
    pub member: PublicKey,
    pub name: String,
    pub invited_by: PublicKey,
    pub at: u64,
    pub sig: Vec<u8>,
}

/// Someone's removal, signed by a member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Removal {
    pub circle: CircleId,
    pub member: PublicKey,
    pub by: PublicKey,
    pub at: u64,
    pub sig: Vec<u8>,
}

fn membership_bytes(circle: &CircleId, member: &PublicKey, name: &str, invited_by: &PublicKey, at: u64) -> Vec<u8> {
    let mut v = b"lembas membership v1\0".to_vec();
    v.extend_from_slice(circle);
    v.extend_from_slice(member.as_bytes());
    v.extend_from_slice(&(name.len() as u32).to_be_bytes());
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(invited_by.as_bytes());
    v.extend_from_slice(&at.to_be_bytes());
    v
}

fn removal_bytes(circle: &CircleId, member: &PublicKey, by: &PublicKey, at: u64) -> Vec<u8> {
    let mut v = b"lembas removal v1\0".to_vec();
    v.extend_from_slice(circle);
    v.extend_from_slice(member.as_bytes());
    v.extend_from_slice(by.as_bytes());
    v.extend_from_slice(&at.to_be_bytes());
    v
}

fn check_name(name: &str) -> Result<()> {
    ensure!(
        !name.trim().is_empty() && name.len() <= MAX_NAME && !name.chars().any(|c| c.is_control()),
        "a name is 1 to {MAX_NAME} printable characters"
    );
    Ok(())
}

impl Membership {
    /// Signs `member` into `circle` as `inviter`.
    pub fn sign(circle: CircleId, inviter: &SecretKey, member: PublicKey, name: &str) -> Result<Self> {
        check_name(name)?;
        let at = now();
        let invited_by = inviter.public();
        let sig = inviter.sign(&membership_bytes(&circle, &member, name, &invited_by, at));
        Ok(Self {
            circle,
            member,
            name: name.to_string(),
            invited_by,
            at,
            sig: sig.to_bytes().to_vec(),
        })
    }

    fn verify(&self) -> Result<()> {
        check_name(&self.name)?;
        let sig: [u8; 64] = self.sig.as_slice().try_into().context("membership signature length")?;
        self.invited_by
            .verify(
                &membership_bytes(&self.circle, &self.member, &self.name, &self.invited_by, self.at),
                &iroh::Signature::from_bytes(&sig),
            )
            .map_err(|_| anyhow::anyhow!("membership signature does not verify"))
    }
}

impl Removal {
    pub fn sign(circle: CircleId, by: &SecretKey, member: PublicKey) -> Self {
        let at = now();
        let by_pub = by.public();
        let sig = by.sign(&removal_bytes(&circle, &member, &by_pub, at));
        Self {
            circle,
            member,
            by: by_pub,
            at,
            sig: sig.to_bytes().to_vec(),
        }
    }

    fn verify(&self) -> Result<()> {
        let sig: [u8; 64] = self.sig.as_slice().try_into().context("removal signature length")?;
        self.by
            .verify(
                &removal_bytes(&self.circle, &self.member, &self.by, self.at),
                &iroh::Signature::from_bytes(&sig),
            )
            .map_err(|_| anyhow::anyhow!("removal signature does not verify"))
    }
}

/// What travels between members: everything signed, merged on arrival.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircleState {
    pub memberships: Vec<Membership>,
    pub removals: Vec<Removal>,
}

/// A circle as this Mac knows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circle {
    pub id: CircleId,
    pub founder: PublicKey,
    /// Accepted memberships, one per member (the latest).
    pub memberships: BTreeMap<PublicKey, Membership>,
    /// Accepted removals, one per member (the latest).
    pub removals: BTreeMap<PublicKey, Removal>,
}

impl Circle {
    /// Founds a circle: the founder signs its own membership.
    pub fn found(founder: &SecretKey, name: &str) -> Result<Self> {
        let id: CircleId = rand::random();
        let me = founder.public();
        let membership = Membership::sign(id, founder, me, name)?;
        Ok(Self {
            id,
            founder: me,
            memberships: BTreeMap::from([(me, membership)]),
            removals: BTreeMap::new(),
        })
    }

    /// Builds a circle from a state received from another member: the
    /// founder is whoever signed their own membership earliest.
    pub fn from_state(id: CircleId, state: &CircleState) -> Result<Self> {
        let founder = state
            .memberships
            .iter()
            .filter(|m| m.circle == id && m.member == m.invited_by && m.verify().is_ok())
            .min_by_key(|m| m.at)
            .context("the circle state has no founder")?;
        let mut circle = Self {
            id,
            founder: founder.member,
            memberships: BTreeMap::from([(founder.member, founder.clone())]),
            removals: BTreeMap::new(),
        };
        circle.merge(state);
        Ok(circle)
    }

    /// Everything to send to another member.
    pub fn state(&self) -> CircleState {
        CircleState {
            memberships: self.memberships.values().cloned().collect(),
            removals: self.removals.values().cloned().collect(),
        }
    }

    /// Whether `who` is a member right now.
    pub fn is_member(&self, who: &PublicKey) -> bool {
        match (self.memberships.get(who), self.removals.get(who)) {
            (Some(_), None) => true,
            (Some(m), Some(r)) => m.at > r.at,
            _ => false,
        }
    }

    /// Current members with their names.
    pub fn members(&self) -> impl Iterator<Item = &Membership> {
        self.memberships.values().filter(|m| self.is_member(&m.member))
    }

    /// Adds a membership this Mac signed, or one received; false if it was
    /// not accepted (bad signature, unknown inviter, older than what we have).
    pub fn add_membership(&mut self, m: &Membership) -> bool {
        if m.circle != self.id || m.verify().is_err() {
            return false;
        }
        let inviter_ok = m.invited_by == self.founder
            || self
                .memberships
                .get(&m.invited_by)
                .is_some_and(|inv| inv.at <= m.at && self.removals.get(&m.invited_by).is_none_or(|r| r.at < m.at));
        if !inviter_ok {
            return false;
        }
        match self.memberships.get(&m.member) {
            Some(have) if have.at >= m.at => false,
            _ => {
                self.memberships.insert(m.member, m.clone());
                true
            }
        }
    }

    pub fn add_removal(&mut self, r: &Removal) -> bool {
        if r.circle != self.id || r.verify().is_err() || r.member == self.founder {
            return false;
        }
        let by_ok = self.memberships.get(&r.by).is_some_and(|b| b.at <= r.at)
            && self.removals.get(&r.by).is_none_or(|rr| rr.at < r.at);
        if !by_ok {
            return false;
        }
        match self.removals.get(&r.member) {
            Some(have) if have.at >= r.at => false,
            _ => {
                self.removals.insert(r.member, r.clone());
                true
            }
        }
    }

    /// Merges a received state; true if anything changed. Memberships are
    /// taken in rounds until none is new, so an invitee's inviter is seen
    /// first whatever the order they came in.
    pub fn merge(&mut self, state: &CircleState) -> bool {
        let mut changed = false;
        let mut pending: Vec<&Membership> = state.memberships.iter().collect();
        pending.sort_by_key(|m| m.at);
        loop {
            let before = pending.len();
            pending.retain(|m| !self.add_membership(m));
            if pending.len() == before {
                break;
            }
            changed = true;
        }
        for r in &state.removals {
            changed |= self.add_removal(r);
        }
        changed
    }

    /// The name of a member, or a short form of its key.
    pub fn name_of(&self, who: &PublicKey) -> String {
        self.memberships
            .get(who)
            .map(|m| m.name.clone())
            .unwrap_or_else(|| who.fmt_short().to_string())
    }
}

// ---------------------------------------------------------------------------
// Invites

/// How long an invite link works.
pub const INVITE_TTL_SECS: u64 = 7 * 24 * 3600;

/// What an invite link carries: enough to reach the inviter and prove the
/// invite was theirs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    pub circle: CircleId,
    pub inviter: PublicKey,
    /// Where the inviter can be reached: a relay URL and direct addresses.
    pub relay: Option<String>,
    pub addrs: Vec<std::net::SocketAddr>,
    /// One-time secret the joiner shows the inviter.
    pub secret: [u8; 16],
    pub expires: u64,
}

const LINK_PREFIX: &str = "lembas://join/";

impl Invite {
    pub fn to_link(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serializes");
        format!("{LINK_PREFIX}{}", data_encoding::BASE64URL_NOPAD.encode(&json))
    }

    pub fn from_link(link: &str) -> Result<Self> {
        let rest = link
            .trim()
            .strip_prefix(LINK_PREFIX)
            .context("not a lembas invite link")?;
        let json = data_encoding::BASE64URL_NOPAD
            .decode(rest.as_bytes())
            .context("invite link is not valid")?;
        let invite: Self = serde_json::from_slice(&json).context("invite link is not valid")?;
        if invite.expires < now() {
            bail!("the invite has expired");
        }
        Ok(invite)
    }
}

/// The joiner's first message on a join stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub circle: CircleId,
    pub secret: [u8; 16],
    pub name: String,
}

/// The inviter's answer: the circle, with the joiner's membership in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JoinReply {
    Welcome { state: CircleState },
    Refused { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memberships_chain_from_the_founder() {
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let c = SecretKey::generate();
        let stranger = SecretKey::generate();
        let mut circle = Circle::found(&a, "Alice").unwrap();
        let mb = Membership::sign(circle.id, &a, b.public(), "Bob").unwrap();
        assert!(circle.add_membership(&mb));
        assert!(!circle.add_membership(&mb), "the same membership twice is nothing new");
        // Bob may invite; a stranger may not.
        let mc = Membership::sign(circle.id, &b, c.public(), "Carol").unwrap();
        let bad = Membership::sign(circle.id, &stranger, c.public(), "Carol").unwrap();
        assert!(!circle.add_membership(&bad));
        assert!(circle.add_membership(&mc));
        assert_eq!(circle.members().count(), 3);
        // A tampered name fails its signature.
        let mut forged = mc.clone();
        forged.name = "Mallory".into();
        assert!(!circle.add_membership(&forged));

        // Another Mac builds the circle from the state and agrees.
        let other = Circle::from_state(circle.id, &circle.state()).unwrap();
        assert_eq!(other.founder, a.public());
        assert_eq!(other.members().count(), 3);

        // Bob removes Carol; Carol cannot remove anyone any more; a later
        // membership reinstates her.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let rc = Removal::sign(circle.id, &b, c.public());
        assert!(circle.add_removal(&rc));
        assert!(!circle.is_member(&c.public()));
        assert!(!circle.add_removal(&Removal::sign(circle.id, &c, b.public())));
        // Nobody removes the founder.
        assert!(!circle.add_removal(&Removal::sign(circle.id, &b, a.public())));
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let again = Membership::sign(circle.id, &a, c.public(), "Carol").unwrap();
        assert!(circle.add_membership(&again));
        assert!(circle.is_member(&c.public()));
        // Merging the other way round brings the other Mac up to date.
        let mut other = other;
        assert!(other.merge(&circle.state()));
        assert!(!other.merge(&circle.state()));
        assert_eq!(other.members().count(), 3);
    }

    #[test]
    fn invite_links_round_trip() {
        let a = SecretKey::generate();
        let invite = Invite {
            circle: [7; 16],
            inviter: a.public(),
            relay: Some("https://relay.example/".into()),
            addrs: vec!["192.0.2.1:4433".parse().unwrap()],
            secret: [9; 16],
            expires: now() + 60,
        };
        let link = invite.to_link();
        assert!(link.starts_with("lembas://join/"));
        assert_eq!(Invite::from_link(&link).unwrap(), invite);
        let expired = Invite { expires: 1, ..invite };
        assert!(Invite::from_link(&expired.to_link()).is_err());
        assert!(Invite::from_link("https://example/").is_err());
    }
}
