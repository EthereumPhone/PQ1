//! Stack-resident collection of Merkle-verified [`NameMeta`] entries
//! for the current sign operation.
//!
//! Built once in `cmd_sign_userop` after each supplied bundle has
//! passed the Merkle gate, then threaded by reference into the
//! trusted-UI display layer. The display primitives call
//! [`NameResolver::lookup`] for every address they would otherwise
//! render as 40 hex chars; a hit substitutes the verified name.
//!
//! No heap, no `Vec` — a fixed-capacity array.

use super::bundle::NameMeta;

/// Upper bound on verified name bundles per sign call. A typical
/// complex UserOp touches: `tx.to`, an ERC20 recipient/spender, a
/// paymaster, a factory — four is a safe ceiling for the curated DB
/// use-case, and capping here keeps the NS-side payload bounded too.
pub const MAX_NAME_BUNDLES: usize = 4;

pub struct NameResolver<'a> {
    entries: [Option<NameMeta<'a>>; MAX_NAME_BUNDLES],
    len: usize,
}

impl<'a> NameResolver<'a> {
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_NAME_BUNDLES],
            len: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a verified entry. Silently drops any overflow — the NS
    /// side caps at the same number, so overflow here would indicate
    /// a protocol violation we choose to ignore rather than fail the
    /// sign. An ignored entry just means the address renders as hex,
    /// which is always safe.
    pub fn push(&mut self, meta: NameMeta<'a>) {
        if self.len < MAX_NAME_BUNDLES {
            self.entries[self.len] = Some(meta);
            self.len += 1;
        }
    }

    /// Look up a verified name for `(chain_id, address)`. Two-phase:
    ///
    ///   1. exact `(chain_id, address)` match
    ///   2. fallback to `(0, address)` — chain-agnostic entries
    ///
    /// `chain_id = 0` is reserved as the wildcard sentinel (see
    /// `sphincs_tz_shared::db_format::NAMES_WILDCARD_CHAIN_ID`). Real
    /// EVM chain_ids start at 1, so the two-phase match cannot
    /// accidentally upgrade a chain-specific entry into a wildcard.
    pub fn lookup(&self, chain_id: u64, address: &[u8; 20]) -> Option<&'a [u8]> {
        // Phase 1: exact.
        for slot in &self.entries[..self.len] {
            if let Some(m) = slot {
                if m.chain_id == chain_id && &m.address == address {
                    return Some(m.name);
                }
            }
        }
        // Phase 2: wildcard.
        const WILD: u64 = sphincs_tz_shared::db_format::NAMES_WILDCARD_CHAIN_ID;
        if chain_id == WILD {
            return None;
        }
        for slot in &self.entries[..self.len] {
            if let Some(m) = slot {
                if m.chain_id == WILD && &m.address == address {
                    return Some(m.name);
                }
            }
        }
        None
    }
}

impl<'a> Default for NameResolver<'a> {
    fn default() -> Self {
        Self::new()
    }
}
