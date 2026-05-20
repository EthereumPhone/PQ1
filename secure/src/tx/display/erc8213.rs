//! ERC-8213 fingerprint pages — final pages every sign path adds
//! before [`crate::ui::confirm::confirm`].
//!
//! ERC-8213 mandates that wallets surface the full 32-byte hash being
//! signed so a user can cross-check it against off-device tools
//! (`cast`, `viem`, `safe-hash`, …). The page-byte budget (4 rows × 16
//! cols = 64 chars) is just barely enough for the kind label + 64
//! hex chars; we split the fingerprint across two pages — banner +
//! 32-byte hash in 4 rows of 16 hex (= 8 bytes per row).
//!
//! ## Two-page layout
//!
//! ```text
//!  Page F (banner)              Page F+1 (hash)
//!  ──────────────────────       ──────────────────────
//!  8213 Fingerprint             <16 hex of bytes [ 0.. 8]>
//!  <kind label>                 <16 hex of bytes [ 8..16]>
//!                               <16 hex of bytes [16..24]>
//!  > verify off-dev             <16 hex of bytes [24..32]>
//! ```
//!
//! Page-budget impact: 2 pages out of the 22-page max. The longest
//! existing renderer (typed-call selector) is 14 pages — 6 pages of
//! headroom remain after the fingerprint, well within the budget.
//!
//! ## Kinds
//!
//! - [`Kind::CalldataDigest`] — for `cmd_sign_userop` /
//!   `cmd_sign_userop_batch` per-tx pages and for `kind=0` raw32
//!   offchain signs. The hash is computed via
//!   [`pqsigner_tx_core::erc8213::calldata_digest`] (=
//!   `keccak256(uint256(len) || data)`).
//! - [`Kind::Eip712Final`] — for offchain `OFFCHAIN_KIND_EIP712_TYPED`
//!   signs. The hash is the standard EIP-712 final hash
//!   `keccak256(0x1901 || domain_sep || struct_hash)`.
//! - [`Kind::Raw32`] — for already-final 32-byte digests (raw32
//!   offchain sign).
//! - [`Kind::SafeTxHash`] — for the Safe v1 inner-tx path; the hash
//!   is the `safeTxHash` computed by `secure::tx::eip712::safe::
//!   verify`. Re-exported from the Safe renderer.

use super::Pages;
use super::primitives::write_line;
use crate::ui::DISPLAY_COLS;

/// Discriminator for the fingerprint kind + payload. All variants
/// carry the 32-byte hash itself; [`Kind::CalldataDigest`] gets the
/// digest computed for it at call-site to keep the embedder dumb.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    /// `keccak256(uint256(len) || calldata)`. Caller computes via
    /// [`pqsigner_tx_core::erc8213::calldata_digest`] and passes the
    /// resulting hash in.
    CalldataDigest([u8; 32]),
    /// `keccak256(0x1901 || domain_sep || struct_hash)`. Computed by
    /// the EIP-712 offchain sign path.
    Eip712Final([u8; 32]),
    /// Raw 32-byte digest (offchain kind=0). Passes through verbatim.
    Raw32([u8; 32]),
    /// Safe v1 `safeTxHash` (`crate::tx::eip712::safe::verify` already
    /// produces this — the renderer just re-surfaces it).
    SafeTxHash([u8; 32]),
}

impl Kind {
    fn hash(&self) -> &[u8; 32] {
        match self {
            Kind::CalldataDigest(h)
            | Kind::Eip712Final(h)
            | Kind::Raw32(h)
            | Kind::SafeTxHash(h) => h,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Kind::CalldataDigest(_) => "CalldataDigest",
            Kind::Eip712Final(_) => "EIP-712 Final",
            Kind::Raw32(_) => "Raw32 Hash",
            Kind::SafeTxHash(_) => "SafeTxHash",
        }
    }
}

/// Append the 2-page fingerprint banner + hash to `pages`. Returns
/// `Err(())` if appending overflows `MAX_PAGES`; callers may choose
/// to silently drop the fingerprint and proceed (the hash is also
/// available via off-device tools), but for current Phase 4 callers
/// the budget is always sufficient.
pub fn append_fingerprint_page(pages: &mut Pages, kind: Kind) -> Result<(), ()> {
    // Banner.
    let banner = pages.push_blank()?;
    write_line(pages.row_mut(banner, 0), "8213 Fingerprint");
    write_line(pages.row_mut(banner, 1), kind.label());
    write_line(pages.row_mut(banner, 3), "> verify off-dev");

    // Hash page — 4 rows of 16 hex chars (= 8 bytes per row).
    let hash_page = pages.push_blank()?;
    let h = kind.hash();
    let [r0, r1, r2, r3] = pages.page_mut(hash_page);
    write_hex_8(r0, &h[0..8]);
    write_hex_8(r1, &h[8..16]);
    write_hex_8(r2, &h[16..24]);
    write_hex_8(r3, &h[24..32]);

    Ok(())
}

fn write_hex_8(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    debug_assert!(bytes.len() == 8);
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    for (i, &b) in bytes.iter().enumerate() {
        row[i * 2] = hex_nibble(b >> 4);
        row[i * 2 + 1] = hex_nibble(b & 0x0F);
    }
}

#[inline]
fn hex_nibble(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        v => b'a' + (v - 10),
    }
}
