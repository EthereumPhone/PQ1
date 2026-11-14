//! A fixed-capacity set of Merkle-verified ERC-20 metadata for ONE sign
//! request, keyed by `(chain_id, contract)`.
//!
//! Before `CAP_ERC20_BUNDLE_SET` a request carried at most one ERC-20
//! bundle, so a call that moves two tokens (a Uniswap swap), a Safe batch
//! touching two tokens, or a Safe refund paid in a token could bind at most
//! one of them; the others showed as raw integers. The set lets the
//! companion attach one bundle per token, and every renderer resolves the
//! token it is about to show by the EXACT `(chain_id, contract)` the signed
//! data names ([`Erc20Set::lookup_exact`]). Display authority therefore
//! never comes from "a bundle was attached": an entry that no signed address
//! resolves to is never painted, so an unused (or companion-chosen) entry is
//! harmless and is ignored rather than refused.
//!
//! Wire (see `pqsigner_proto::ERC20_SET_MAGIC`):
//! `magic u16 BE | version u8 | count u8 ∈ 1..=6 | count × {len u16 BE ∈
//! 1..=1120, bundle}`, consumed exactly, total ≤ `ERC20_SET_MAX_LEN`.
//!
//! No heap: entries borrow the request snapshot.

use super::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use pqsigner_proto::{
    ERC20_BUNDLE_MAX_LEN, ERC20_SET_CAPACITY, ERC20_SET_HEADER_LEN, ERC20_SET_MAGIC,
    ERC20_SET_MAX_EXTRA, ERC20_SET_MAX_LEN, ERC20_SET_VERSION,
};

const _: () = assert!(ERC20_BUNDLE_MAX_LEN == MAX_ERC20_BUNDLE_LEN);
const _: () = assert!(ERC20_SET_CAPACITY <= 8, "Erc20Scope admits by u8 bitmask");

/// Framing error in an ERC-20 set envelope. Every variant refuses the
/// request: a malformed envelope is a companion bug or an attack, never a
/// reason to sign with less metadata than the companion meant to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erc20SetFrameError {
    /// Envelope longer than `ERC20_SET_MAX_LEN`.
    TooLong,
    /// Shorter than the header, or an entry runs past the end.
    Truncated,
    /// Wrong magic.
    BadMagic,
    /// Unknown version.
    BadVersion,
    /// `count` is 0 or above `ERC20_SET_MAX_EXTRA`.
    BadCount,
    /// An entry length is 0 or above `MAX_ERC20_BUNDLE_LEN`.
    BadEntryLen,
    /// Bytes left after the last entry.
    TrailingBytes,
}

/// The raw entries of a well-framed envelope (not yet Merkle-verified).
#[derive(Clone, Copy, Debug)]
pub struct Erc20SetFrame<'a> {
    pub entries: [&'a [u8]; ERC20_SET_MAX_EXTRA],
    pub count: usize,
}

/// Parse the envelope framing. Pure, no panics; consumes `env` exactly.
pub fn parse_erc20_set_envelope(env: &[u8]) -> Result<Erc20SetFrame<'_>, Erc20SetFrameError> {
    if env.len() > ERC20_SET_MAX_LEN {
        return Err(Erc20SetFrameError::TooLong);
    }
    if env.len() < ERC20_SET_HEADER_LEN {
        return Err(Erc20SetFrameError::Truncated);
    }
    if u16::from_be_bytes([env[0], env[1]]) != ERC20_SET_MAGIC {
        return Err(Erc20SetFrameError::BadMagic);
    }
    if env[2] != ERC20_SET_VERSION {
        return Err(Erc20SetFrameError::BadVersion);
    }
    let count = usize::from(env[3]);
    if count == 0 || count > ERC20_SET_MAX_EXTRA {
        return Err(Erc20SetFrameError::BadCount);
    }
    let mut frame = Erc20SetFrame { entries: [&[]; ERC20_SET_MAX_EXTRA], count };
    let mut p = ERC20_SET_HEADER_LEN;
    let mut i = 0;
    while i < count {
        if env.len() - p < 2 {
            return Err(Erc20SetFrameError::Truncated);
        }
        let len = usize::from(u16::from_be_bytes([env[p], env[p + 1]]));
        p += 2;
        if len == 0 || len > MAX_ERC20_BUNDLE_LEN {
            return Err(Erc20SetFrameError::BadEntryLen);
        }
        if env.len() - p < len {
            return Err(Erc20SetFrameError::Truncated);
        }
        frame.entries[i] = &env[p..p + len];
        p += len;
        i += 1;
    }
    if p != env.len() {
        return Err(Erc20SetFrameError::TrailingBytes);
    }
    Ok(frame)
}

/// Result of [`Erc20Set::insert`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Added,
    /// The same key with identical decimals, name and symbol is present.
    SameLeaf,
    /// The same key with DIFFERENT metadata is present (only possible with
    /// two different roots or a broken DB): always refused.
    Conflict,
    /// The set already holds `ERC20_SET_CAPACITY` tokens.
    Full,
}

/// How [`build_erc20_set`] treats a second bundle for a key already present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DupPolicy {
    /// Single sign and off-chain: one encoding per meaning, refuse.
    Refuse,
    /// Batch: an older companion may attach the same token to two members.
    CoalesceIdentical,
}

/// Why [`build_erc20_set`] refused the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erc20SetError {
    Frame(Erc20SetFrameError),
    Duplicate,
    Conflict,
    Full,
}

/// Verified ERC-20 metadata for one request, keyed by `(chain_id, contract)`.
#[derive(Clone, Copy)]
pub struct Erc20Set<'a> {
    entries: [Option<Erc20Metadata<'a>>; ERC20_SET_CAPACITY],
    len: usize,
}

fn same_meta(a: &Erc20Metadata<'_>, b: &Erc20Metadata<'_>) -> bool {
    a.chain_id == b.chain_id
        && a.contract == b.contract
        && a.decimals == b.decimals
        && a.name == b.name
        && a.symbol == b.symbol
}

impl<'a> Erc20Set<'a> {
    #[inline]
    pub const fn new() -> Self {
        Self { entries: [None; ERC20_SET_CAPACITY], len: 0 }
    }

    /// The pre-set single-bundle world: at most one entry.
    pub fn single(meta: Option<Erc20Metadata<'a>>) -> Self {
        let mut s = Self::new();
        if let Some(m) = meta {
            s.entries[0] = Some(m);
            s.len = 1;
        }
        s
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Entry `i` in insertion order.
    pub fn get(&self, i: usize) -> Option<&Erc20Metadata<'a>> {
        if i < self.len {
            self.entries[i].as_ref()
        } else {
            None
        }
    }

    /// Insert a verified entry, keyed by `(chain_id, contract)`.
    pub fn insert(&mut self, meta: Erc20Metadata<'a>) -> InsertOutcome {
        for slot in self.entries[..self.len].iter().flatten() {
            if slot.chain_id == meta.chain_id && slot.contract == meta.contract {
                return if same_meta(slot, &meta) {
                    InsertOutcome::SameLeaf
                } else {
                    InsertOutcome::Conflict
                };
            }
        }
        if self.len >= ERC20_SET_CAPACITY {
            return InsertOutcome::Full;
        }
        self.entries[self.len] = Some(meta);
        self.len += 1;
        InsertOutcome::Added
    }

    /// The entry for exactly this `(chain_id, contract)`, if any.
    pub fn lookup_exact(&self, chain_id: u64, contract: &[u8; 20]) -> Option<&Erc20Metadata<'a>> {
        self.entries[..self.len]
            .iter()
            .flatten()
            .find(|m| m.chain_id == chain_id && &m.contract == contract)
    }

    /// Field-by-field equality including the borrowed slices' addresses,
    /// for the fault-injection A/B rebuild proof (both sides must have
    /// borrowed the very same snapshot bytes, not merely equal ones).
    pub fn same_entries(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.entries[..self.len].iter().zip(other.entries[..other.len].iter()).all(|(a, b)| {
            match (a, b) {
                (Some(a), Some(b)) => {
                    same_meta(a, b)
                        && core::ptr::eq(a.name.as_ptr(), b.name.as_ptr())
                        && core::ptr::eq(a.symbol.as_ptr(), b.symbol.as_ptr())
                }
                _ => false,
            }
        })
    }

    /// A view admitting every entry.
    pub fn scope_all(&self) -> Erc20Scope<'_, 'a> {
        let admitted = if self.len >= 8 { u8::MAX } else { (1u8 << self.len) - 1 };
        Erc20Scope(ScopeRepr::Set { set: self, admitted })
    }

    /// A view admitting only the entries `keep` accepts.
    pub fn scope_where(&self, keep: impl Fn(&Erc20Metadata<'a>) -> bool) -> Erc20Scope<'_, 'a> {
        self.scope_all().restrict(keep)
    }
}

impl Default for Erc20Set<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// A read-only view of verified ERC-20 metadata for one render: either a
/// restricted view of an [`Erc20Set`] (a Safe flow admits only tokens the
/// SafeTx itself names) or the legacy single optional bundle. `Copy`, a few
/// words. Renderers only ever call [`Erc20Scope::lookup_exact`] with an
/// address the signed data names.
#[derive(Clone, Copy)]
pub struct Erc20Scope<'s, 'a>(ScopeRepr<'s, 'a>);

#[derive(Clone, Copy)]
enum ScopeRepr<'s, 'a> {
    Single(Option<&'s Erc20Metadata<'a>>),
    Set { set: &'s Erc20Set<'a>, admitted: u8 },
}

impl<'s, 'a> From<Option<&'s Erc20Metadata<'a>>> for Erc20Scope<'s, 'a> {
    fn from(m: Option<&'s Erc20Metadata<'a>>) -> Self {
        Erc20Scope(ScopeRepr::Single(m))
    }
}

impl<'s, 'a> Erc20Scope<'s, 'a> {
    /// A view with no entries.
    pub const fn empty() -> Self {
        Erc20Scope(ScopeRepr::Single(None))
    }

    /// The legacy single-bundle view.
    pub const fn single(m: Option<&'s Erc20Metadata<'a>>) -> Self {
        Erc20Scope(ScopeRepr::Single(m))
    }

    fn admits(self, i: usize, m: &Erc20Metadata<'_>, chain_id: u64, contract: &[u8; 20]) -> bool {
        let admitted = match self.0 {
            ScopeRepr::Set { admitted, .. } => admitted,
            ScopeRepr::Single(_) => return false,
        };
        admitted & (1 << i) != 0 && m.chain_id == chain_id && &m.contract == contract
    }

    /// The admitted entry for exactly this `(chain_id, contract)`.
    pub fn lookup_exact(self, chain_id: u64, contract: &[u8; 20]) -> Option<&'s Erc20Metadata<'a>> {
        match self.0 {
            ScopeRepr::Single(m) => m.filter(|m| m.chain_id == chain_id && &m.contract == contract),
            ScopeRepr::Set { set, .. } => set.entries[..set.len]
                .iter()
                .enumerate()
                .find_map(|(i, slot)| match slot {
                    Some(m) if self.admits(i, m, chain_id, contract) => Some(m),
                    _ => None,
                }),
        }
    }

    /// Number of admitted entries.
    pub fn count(self) -> usize {
        match self.0 {
            ScopeRepr::Single(m) => usize::from(m.is_some()),
            ScopeRepr::Set { admitted, .. } => admitted.count_ones() as usize,
        }
    }

    /// The single admitted entry, when exactly one is admitted. For legacy
    /// single-bundle call shapes only; new code must resolve by address.
    pub fn only(self) -> Option<&'s Erc20Metadata<'a>> {
        match self.0 {
            ScopeRepr::Single(m) => m,
            ScopeRepr::Set { set, admitted } => {
                if admitted.count_ones() != 1 {
                    return None;
                }
                set.get(admitted.trailing_zeros() as usize)
            }
        }
    }

    /// The `i`-th admitted entry (insertion order).
    pub fn nth(self, n: usize) -> Option<&'s Erc20Metadata<'a>> {
        match self.0 {
            ScopeRepr::Single(m) => if n == 0 { m } else { None },
            ScopeRepr::Set { set, admitted } => set.entries[..set.len]
                .iter()
                .enumerate()
                .filter_map(|(i, slot)| if admitted & (1 << i) != 0 { slot.as_ref() } else { None })
                .nth(n),
        }
    }

    /// A narrower view: the admitted entries `keep` accepts.
    pub fn restrict(self, keep: impl Fn(&Erc20Metadata<'a>) -> bool) -> Self {
        match self.0 {
            ScopeRepr::Single(m) => Erc20Scope(ScopeRepr::Single(m.filter(|m| keep(m)))),
            ScopeRepr::Set { set, admitted } => {
                let mut out = 0u8;
                for (i, slot) in set.entries[..set.len].iter().enumerate() {
                    if let Some(m) = slot {
                        if admitted & (1 << i) != 0 && keep(m) {
                            out |= 1 << i;
                        }
                    }
                }
                Erc20Scope(ScopeRepr::Set { set, admitted: out })
            }
        }
    }
}

/// Build the request's set from the primary slot (`slot0`, empty = none)
/// and an optional envelope (`env`, empty = none).
///
/// Verification policy is the one the primary slot always had: a bundle
/// whose Merkle proof fails, or whose `chain_id` is not the request's, is
/// DROPPED (that token then shows as a loud raw integer; a stale companion
/// DB must not block signing). Framing errors, a duplicate key (under
/// [`DupPolicy::Refuse`]), a conflicting duplicate and overflow refuse.
pub fn build_erc20_set<'a>(
    slot0: &'a [u8],
    env: &'a [u8],
    chain_id: u64,
    root: &[u8; 32],
    policy: DupPolicy,
) -> Result<Erc20Set<'a>, Erc20SetError> {
    let mut set = Erc20Set::new();
    if !slot0.is_empty() {
        insert_verified(&mut set, slot0, chain_id, root, policy)?;
    }
    if !env.is_empty() {
        let frame = parse_erc20_set_envelope(env).map_err(Erc20SetError::Frame)?;
        for bundle in &frame.entries[..frame.count] {
            insert_verified(&mut set, bundle, chain_id, root, policy)?;
        }
    }
    Ok(set)
}

/// Verify one bundle and insert it under `policy` (shared by the batch
/// handler, which collects bundles from several trailer records).
pub fn insert_verified<'a>(
    set: &mut Erc20Set<'a>,
    bundle: &'a [u8],
    chain_id: u64,
    root: &[u8; 32],
    policy: DupPolicy,
) -> Result<(), Erc20SetError> {
    let Some(meta) = verify_erc20_bundle(bundle, root) else {
        return Ok(());
    };
    if meta.chain_id != chain_id {
        return Ok(());
    }
    match set.insert(meta) {
        InsertOutcome::Added => Ok(()),
        InsertOutcome::SameLeaf => match policy {
            DupPolicy::Refuse => Err(Erc20SetError::Duplicate),
            DupPolicy::CoalesceIdentical => Ok(()),
        },
        InsertOutcome::Conflict => Err(Erc20SetError::Conflict),
        InsertOutcome::Full => Err(Erc20SetError::Full),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(chain: u64, c: u8, dec: u8, sym: &'static [u8]) -> Erc20Metadata<'static> {
        Erc20Metadata { chain_id: chain, contract: [c; 20], decimals: dec, name: b"Tok", symbol: sym }
    }

    fn env(entries: &[&[u8]]) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        v.extend_from_slice(&ERC20_SET_MAGIC.to_be_bytes());
        v.push(ERC20_SET_VERSION);
        v.push(entries.len() as u8);
        for e in entries {
            v.extend_from_slice(&(e.len() as u16).to_be_bytes());
            v.extend_from_slice(e);
        }
        v
    }

    #[test]
    fn envelope_framing_is_exact() {
        let a = [1u8; 10];
        let b = [2u8; 3];
        let ok = env(&[&a, &b]);
        let f = parse_erc20_set_envelope(&ok).unwrap();
        assert_eq!(f.count, 2);
        assert_eq!(f.entries[0], &a);
        assert_eq!(f.entries[1], &b);

        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(parse_erc20_set_envelope(&trailing).unwrap_err(), Erc20SetFrameError::TrailingBytes);
        assert_eq!(parse_erc20_set_envelope(&ok[..ok.len() - 1]).unwrap_err(), Erc20SetFrameError::Truncated);
        assert_eq!(parse_erc20_set_envelope(&ok[..3]).unwrap_err(), Erc20SetFrameError::Truncated);
        assert_eq!(parse_erc20_set_envelope(&[]).unwrap_err(), Erc20SetFrameError::Truncated);

        let mut bad = ok.clone();
        bad[0] ^= 1;
        assert_eq!(parse_erc20_set_envelope(&bad).unwrap_err(), Erc20SetFrameError::BadMagic);
        let mut bad = ok.clone();
        bad[2] = 2;
        assert_eq!(parse_erc20_set_envelope(&bad).unwrap_err(), Erc20SetFrameError::BadVersion);
        assert_eq!(parse_erc20_set_envelope(&env(&[])).unwrap_err(), Erc20SetFrameError::BadCount);
        let seven: std::vec::Vec<&[u8]> = (0..7).map(|_| &a[..]).collect();
        assert_eq!(parse_erc20_set_envelope(&env(&seven)).unwrap_err(), Erc20SetFrameError::BadCount);
        assert_eq!(parse_erc20_set_envelope(&env(&[&[]])).unwrap_err(), Erc20SetFrameError::BadEntryLen);
        let big = [0u8; MAX_ERC20_BUNDLE_LEN + 1];
        assert_eq!(parse_erc20_set_envelope(&env(&[&big])).unwrap_err(), Erc20SetFrameError::BadEntryLen);
        let max = [0u8; MAX_ERC20_BUNDLE_LEN];
        let four = env(&[&max, &max, &max, &max]);
        assert!(four.len() > ERC20_SET_MAX_LEN);
        assert_eq!(parse_erc20_set_envelope(&four).unwrap_err(), Erc20SetFrameError::TooLong);
    }

    #[test]
    fn insert_and_lookup_are_keyed_by_chain_and_contract() {
        let mut s = Erc20Set::new();
        assert_eq!(s.insert(meta(1, 0xaa, 18, b"A")), InsertOutcome::Added);
        assert_eq!(s.insert(meta(1, 0xbb, 6, b"B")), InsertOutcome::Added);
        assert_eq!(s.insert(meta(1, 0xaa, 18, b"A")), InsertOutcome::SameLeaf);
        assert_eq!(s.insert(meta(1, 0xaa, 6, b"A")), InsertOutcome::Conflict);
        assert_eq!(s.lookup_exact(1, &[0xbb; 20]).unwrap().decimals, 6);
        assert!(s.lookup_exact(10, &[0xbb; 20]).is_none(), "chain-bound");
        assert!(s.lookup_exact(1, &[0xcc; 20]).is_none());
        for c in 0..5u8 {
            assert_eq!(s.insert(meta(1, c, 0, b"X")), InsertOutcome::Added);
        }
        assert_eq!(s.len(), ERC20_SET_CAPACITY);
        assert_eq!(s.insert(meta(1, 0x77, 0, b"X")), InsertOutcome::Full);
    }

    #[test]
    fn scope_restricts_lookups() {
        let mut s = Erc20Set::new();
        s.insert(meta(1, 0xaa, 18, b"A"));
        s.insert(meta(1, 0xbb, 6, b"B"));
        let only_b = s.scope_where(|m| m.contract == [0xbb; 20]);
        assert!(only_b.lookup_exact(1, &[0xaa; 20]).is_none());
        assert_eq!(only_b.lookup_exact(1, &[0xbb; 20]).unwrap().decimals, 6);
        assert_eq!(only_b.count(), 1);
        assert_eq!(only_b.only().unwrap().contract, [0xbb; 20]);
        assert!(s.scope_all().only().is_none());
        assert_eq!(s.scope_all().count(), 2);
        assert_eq!(s.scope_all().nth(1).unwrap().contract, [0xbb; 20]);
        assert!(s.scope_all().nth(2).is_none());
        assert!(Erc20Scope::empty().lookup_exact(1, &[0xaa; 20]).is_none());
        let m = meta(1, 0xaa, 18, b"A");
        let single = Erc20Scope::from(Some(&m));
        assert!(single.lookup_exact(1, &[0xaa; 20]).is_some());
        assert!(single.lookup_exact(2, &[0xaa; 20]).is_none(), "single view is chain-bound too");
        assert!(single.restrict(|_| false).only().is_none());
        assert!(Erc20Set::single(None).is_empty());
        assert_eq!(Erc20Set::single(Some(meta(1, 1, 1, b"S"))).len(), 1);
    }

    #[test]
    fn same_entries_requires_the_same_borrowed_bytes() {
        let name_a = std::vec![b'N'];
        let name_b = std::vec![b'N'];
        let mk = |n: &'static [u8]| Erc20Metadata { chain_id: 1, contract: [1; 20], decimals: 1, name: n, symbol: b"S" };
        let na: &'static [u8] = std::boxed::Box::leak(name_a.into_boxed_slice());
        let nb: &'static [u8] = std::boxed::Box::leak(name_b.into_boxed_slice());
        let a = Erc20Set::single(Some(mk(na)));
        let a2 = Erc20Set::single(Some(mk(na)));
        let b = Erc20Set::single(Some(mk(nb)));
        assert!(a.same_entries(&a2));
        assert!(!a.same_entries(&b), "equal bytes elsewhere are not the same snapshot");
        assert!(!a.same_entries(&Erc20Set::new()));
    }

    // ── build_erc20_set over real Merkle proofs ──────────────────────

    type Row = (u64, u8, u8, &'static [u8]);

    fn canonical((chain, c, dec, sym): Row) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        v.extend_from_slice(&chain.to_le_bytes());
        v.extend_from_slice(&[c; 20]);
        v.push(dec);
        v.push(3);
        v.extend_from_slice(b"Tok");
        v.push(sym.len() as u8);
        v.extend_from_slice(sym);
        v
    }

    fn h(prefix: u8, parts: &[&[u8]]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update([prefix]);
        for p in parts {
            d.update(p);
        }
        d.finalize().into()
    }

    /// A 4-leaf tree over `rows`; returns the root and one bundle per row.
    fn tree(rows: [Row; 4]) -> ([u8; 32], std::vec::Vec<std::vec::Vec<u8>>) {
        let leaves: std::vec::Vec<[u8; 32]> = rows.iter().map(|r| h(0, &[&canonical(*r)])).collect();
        let n01 = h(1, &[&leaves[0], &leaves[1]]);
        let n23 = h(1, &[&leaves[2], &leaves[3]]);
        let root = h(1, &[&n01, &n23]);
        let bundles = (0..4)
            .map(|i| {
                let mut b = canonical(rows[i]);
                b.extend_from_slice(&(i as u32).to_le_bytes());
                b.extend_from_slice(&2u32.to_le_bytes());
                b.extend_from_slice(&leaves[i ^ 1]);
                b.extend_from_slice(if i < 2 { &n23 } else { &n01 });
                b
            })
            .collect();
        (root, bundles)
    }

    const ROWS: [Row; 4] = [(1, 0xa1, 6, b"AAA"), (1, 0xb2, 18, b"BBB"), (10, 0xc3, 8, b"CCC"), (1, 0xa1, 9, b"AAX")];

    #[test]
    fn built_set_holds_slot0_and_envelope_entries() {
        let (root, b) = tree(ROWS);
        let e = env(&[&b[1]]);
        let s = build_erc20_set(&b[0], &e, 1, &root, DupPolicy::Refuse).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.lookup_exact(1, &[0xa1; 20]).unwrap().decimals, 6);
        assert_eq!(s.lookup_exact(1, &[0xb2; 20]).unwrap().symbol, b"BBB");
        // Slot 0 empty + envelope is legal.
        let s = build_erc20_set(&[], &e, 1, &root, DupPolicy::Refuse).unwrap();
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn bad_proof_and_wrong_chain_entries_are_dropped_not_refused() {
        let (root, b) = tree(ROWS);
        let mut forged = b[1].clone();
        forged[28] = 2; // decimals 18 -> 2: proof no longer verifies
        let e = env(&[&forged, &b[2]]); // b[2] is chain 10
        let s = build_erc20_set(&b[0], &e, 1, &root, DupPolicy::Refuse).unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.lookup_exact(1, &[0xb2; 20]).is_none());
        assert!(s.lookup_exact(10, &[0xc3; 20]).is_none());
        let wrong_root = [0u8; 32];
        assert_eq!(build_erc20_set(&b[0], &e, 1, &wrong_root, DupPolicy::Refuse).unwrap().len(), 0);
    }

    #[test]
    fn duplicate_conflict_frame_and_overflow_refuse() {
        let (root, b) = tree(ROWS);
        let dup = env(&[&b[0]]);
        assert_eq!(build_erc20_set(&b[0], &dup, 1, &root, DupPolicy::Refuse).err(), Some(Erc20SetError::Duplicate));
        assert_eq!(build_erc20_set(&b[0], &dup, 1, &root, DupPolicy::CoalesceIdentical).unwrap().len(), 1);
        // Same (chain, contract), different decimals, both proven.
        let conflict = env(&[&b[3]]);
        assert_eq!(build_erc20_set(&b[0], &conflict, 1, &root, DupPolicy::CoalesceIdentical).err(), Some(Erc20SetError::Conflict));
        let mut bad = env(&[&b[1]]);
        bad[2] = 9;
        assert!(matches!(build_erc20_set(&b[0], &bad, 1, &root, DupPolicy::Refuse), Err(Erc20SetError::Frame(_))));

        // Batch path: an eighth distinct token overflows.
        let rows: std::vec::Vec<[Row; 4]> = (0..2u8)
            .map(|k| core::array::from_fn(|i| (1u64, 0x10 + k * 4 + i as u8, 6u8, &b"T"[..])))
            .collect();
        let mut set = Erc20Set::new();
        let trees: std::vec::Vec<_> = rows.iter().map(|r| tree(*r)).collect();
        let mut n = 0;
        for (root, bundles) in &trees {
            for bundle in bundles {
                n += 1;
                let r = insert_verified(&mut set, bundle, 1, root, DupPolicy::CoalesceIdentical);
                if n <= ERC20_SET_CAPACITY {
                    r.unwrap();
                } else {
                    assert_eq!(r.unwrap_err(), Erc20SetError::Full);
                }
            }
        }
        assert_eq!(set.len(), ERC20_SET_CAPACITY);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// The envelope parser never panics and, when it accepts, its entries
    /// tile the input exactly.
    #[kani::proof]
    #[kani::unwind(10)]
    fn envelope_parser_is_total_and_exact() {
        const N: usize = 24;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        if let Ok(f) = parse_erc20_set_envelope(&buf[..len]) {
            let mut sum = ERC20_SET_HEADER_LEN;
            for e in &f.entries[..f.count] {
                assert!(!e.is_empty());
                sum += 2 + e.len();
            }
            assert_eq!(sum, len);
        }
    }

    /// `lookup_exact` only ever returns an entry with that exact key.
    #[kani::proof]
    #[kani::unwind(9)]
    fn lookup_is_exact() {
        let mut s = Erc20Set::new();
        let n: u8 = kani::any();
        kani::assume(n <= 3);
        for _ in 0..n {
            let c: u8 = kani::any();
            let chain: u64 = kani::any();
            s.insert(Erc20Metadata { chain_id: chain, contract: [c; 20], decimals: 0, name: b"n", symbol: b"s" });
        }
        let qc: u8 = kani::any();
        let qchain: u64 = kani::any();
        if let Some(m) = s.lookup_exact(qchain, &[qc; 20]) {
            assert!(m.chain_id == qchain && m.contract == [qc; 20]);
        }
    }
}
