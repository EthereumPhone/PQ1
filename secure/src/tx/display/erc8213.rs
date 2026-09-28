//! ERC-8213 fingerprint pages — final pages every companion/dapp-supplied
//! signing path adds before [`crate::ui::confirm::confirm`].
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
//! Page-budget impact: every signing path reserves these two pages before
//! rendering. If the complete trusted display would exceed `MAX_PAGES`, the
//! request is refused; pages are never truncated to make the fingerprint fit.
//! The firmware-constructed Type-1 slot-rotation consent is the sole current
//! exemption: its exact calldata includes seed-derived slot-owner material
//! that intentionally does not exist before that cancellable consent boundary.
//! The dialog instead binds the complete slot index and bootstrap-use effect;
//! a synthetic digest is never presented as an ERC-8213 fingerprint.
//!
//! ## Kinds
//!
//! - [`Kind::CalldataDigest`] — for `cmd_sign_userop` /
//!   `cmd_sign_userop_batch` per-tx pages and personal-sign payloads.
//!   The hash is computed via
//!   [`pqsigner_tx_core::erc8213::calldata_digest`] (=
//!   `keccak256(uint256(len) || data)`).
//! - [`Kind::Eip712Final`] — for offchain `OFFCHAIN_KIND_EIP712_TYPED`
//!   signs. The hash is the standard EIP-712 final hash
//!   `keccak256(0x1901 || domain_sep || struct_hash)`.
//! - [`Kind::Raw32`] — for already-final 32-byte digests (raw32
//!   offchain sign).
//! - [`Kind::ReplaySafeHash`] — for the exact Solady replay-safe nested hash
//!   that the RAW32 path passes to the C10 signer.
//! - [`Kind::SafeTxHash`] — for the Safe v1 inner-tx path; the hash
//!   is the `safeTxHash` computed by `secure::tx::eip712::safe::
//!   verify`. Re-exported from the Safe renderer.

use super::primitives::write_line;
use super::Pages;
use crate::ui::DISPLAY_COLS;
use pqsigner_erc7730::display::erc8213_contract::{
    FINGERPRINT_PAGES, HASH_BYTES, HASH_BYTES_PER_ROW,
};

type FingerprintPage = [[u8; DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
type FingerprintPair = [FingerprintPage; FINGERPRINT_PAGES];

const FINGERPRINT_CFI_STEP: u32 = 0xE821_3CF1;
pub(crate) const FINGERPRINT_CFI_EXPECTED: u32 = crate::cfi_expected!(FINGERPRINT_CFI_STEP);

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
    /// Exact Solady replay-safe nested hash passed to the C10 signer for an
    /// explicit RAW32 request.
    ReplaySafeHash([u8; 32]),
    /// Safe v1 `safeTxHash` (`crate::tx::eip712::safe::verify` already
    /// produces this — the renderer just re-surfaces it).
    SafeTxHash([u8; 32]),
}

impl Kind {
    pub(crate) fn hash(&self) -> &[u8; 32] {
        match self {
            Kind::CalldataDigest(h)
            | Kind::Eip712Final(h)
            | Kind::Raw32(h)
            | Kind::ReplaySafeHash(h)
            | Kind::SafeTxHash(h) => h,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Kind::CalldataDigest(_) => "CalldataDigest",
            Kind::Eip712Final(_) => "EIP-712 Final",
            Kind::Raw32(_) => "Raw32 Hash",
            Kind::ReplaySafeHash(_) => "ReplaySafe Hash",
            Kind::SafeTxHash(_) => "SafeTxHash",
        }
    }
}

/// Append the 2-page fingerprint banner + hash with a caller-owned completion
/// receipt. Returns `Err(())` if both pages do not fit. Every signing caller
/// maps that error to refusal: off-device availability is never permission to
/// omit signed context from the trusted display. The CFI step is minted only
/// after both pages and the final length are visible, so a skipped whole call
/// cannot borrow a prior success.
#[inline(never)]
pub(crate) fn append_fingerprint_page(
    pages: &mut Pages,
    kind: Kind,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    let expected = build_fingerprint_pair(kind);
    // Atomic pre-check: either both pages fit or neither is pushed —
    // an orphan "8213 Fingerprint" banner with no hash page would read
    // as a rendering fault.
    if pages
        .as_slice()
        .len()
        .checked_add(FINGERPRINT_PAGES)
        .is_none_or(|len| len > super::MAX_PAGES)
    {
        return Err(());
    }
    let banner = pages.push_blank()?;
    pages.buf[banner] = expected[0];
    let hash_page = pages.push_blank()?;
    pages.buf[hash_page] = expected[1];
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(FINGERPRINT_CFI_STEP);
    Ok(())
}

pub(crate) fn build_fingerprint_pair(kind: Kind) -> FingerprintPair {
    let mut pair = [[[b' '; DISPLAY_COLS]; crate::ui::DISPLAY_ROWS]; FINGERPRINT_PAGES];

    write_line(&mut pair[0][0], "8213 Fingerprint");
    write_line(&mut pair[0][1], kind.label());
    write_line(&mut pair[0][3], "> verify off-dev");

    // Hash page — 4 rows of 16 hex chars (= 8 bytes per row).
    let h = kind.hash();
    const _: () = assert!(HASH_BYTES == 32);
    let [r0, r1, r2, r3] = &mut pair[1];
    write_hex_8(r0, &h[0..HASH_BYTES_PER_ROW]);
    write_hex_8(r1, &h[HASH_BYTES_PER_ROW..HASH_BYTES_PER_ROW * 2]);
    write_hex_8(r2, &h[HASH_BYTES_PER_ROW * 2..HASH_BYTES_PER_ROW * 3]);
    write_hex_8(r3, &h[HASH_BYTES_PER_ROW * 3..HASH_BYTES]);

    pair
}

fn fingerprint_page_exact(actual: &FingerprintPage, expected: &FingerprintPage) -> bool {
    let mut diff = 0u8;
    for row in 0..crate::ui::DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

/// Independent completion proof for the exact two-page append transition.
///
/// The caller records `prior_len`, invokes the non-inlined append operation,
/// scrubs the ABI sentinel register, and accepts only `OK_SENTINEL`. Both page
/// indices, the exact kind label, and every hash nibble are rebuilt here rather
/// than trusted from the append operation's return value.
#[inline(never)]
pub(crate) fn fingerprint_page_proof(pages: &Pages, prior_len: usize, kind: Kind) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let expected = build_fingerprint_pair(kind);
        prior_len
            .checked_add(FINGERPRINT_PAGES)
            .is_some_and(|expected_len| {
                core::hint::black_box(pages.len == expected_len)
                    && pages
                        .as_slice()
                        .get(prior_len)
                        .is_some_and(|actual| fingerprint_page_exact(actual, &expected[0]))
                    && pages
                        .as_slice()
                        .get(prior_len + 1)
                        .is_some_and(|actual| fingerprint_page_exact(actual, &expected[1]))
            })
    })
}

/// Final confirmation-boundary recheck of an already completed pair.
///
/// Later append-only mandatory pages may legitimately grow the transcript, so
/// this proof keeps the original two indices fixed but does not constrain the
/// final length. Callers invoke it immediately before `confirm_checked`.
#[inline(never)]
pub(crate) fn fingerprint_final_set_proof(pages: &Pages, expected_index: usize, kind: Kind) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let expected = build_fingerprint_pair(kind);
        pages
            .as_slice()
            .get(expected_index)
            .is_some_and(|actual| fingerprint_page_exact(actual, &expected[0]))
            && expected_index.checked_add(1).is_some_and(|hash_index| {
                pages
                    .as_slice()
                    .get(hash_index)
                    .is_some_and(|actual| fingerprint_page_exact(actual, &expected[1]))
            })
    })
}

fn write_hex_8(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    debug_assert!(bytes.len() == HASH_BYTES_PER_ROW);
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
