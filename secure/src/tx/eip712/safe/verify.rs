//! Top-level verifier for a `safe_v1` Safe-multisig clear-sign trailer.
//!
//! This is the single entry point `cmd_sign_userop` calls when it sees
//! an optional `safe_v1` trailer on a UserOp. Composes seven checks,
//! each load-bearing; first failure wins and the helper returns `None`
//! so the handler treats the trailer as absent (and the downgrade gate
//! rejects the UserOp outright when the inner calldata claims to be a
//! Safe `approveHash`).
//!
//! Pipeline (mirrors the documented attacker model in
//! `CLAUDE.md` invariant #5):
//!
//!   1. **Trailer length / framing** — at least 281 + 2 bytes, the
//!      declared `raw_data_len` fits inside the supplied bundle.
//!   2. **Selector** — `inner_data[..4] == approveHash(bytes32)`.
//!   3. **Calldata length** — `inner_data.len() == 36`.
//!   4. **Chain pinning** — `canonical.chain_id == userop.chain_id`.
//!      Prevents replaying a Mainnet canonical against a UserOp on
//!      another chain.
//!   5. **Safe-address pinning** — `canonical.safe_address ==
//!      userop.to`. The UserOp must call `approveHash` on the same
//!      Safe whose hash we're approving; otherwise something's wrong.
//!   6. **Operation gate** — only `0` (Call) is accepted in v1.
//!      DelegateCall (`1`) is refused outright since it replaces the
//!      Safe's code for the duration of the call and is not honestly
//!      clear-signable for a non-expert user.
//!   7. **Data-hash bind** — `keccak256(raw_data) == canonical.data_hash`.
//!      The raw inner-call bytes the firmware will render must hash
//!      to the value Safe baked into its EIP-712 typehash.
//!   8. **safeTxHash bind** — `compute_safe_tx_hash(canonical) ==
//!      inner_data[4..36]`. The 32-byte digest in the calldata is
//!      what the on-chain Safe will record; if it doesn't match what
//!      we just derived from the canonical, the canonical we'd render
//!      and the hash that gets approved would describe different
//!      transactions.
//!
//! Returns an owned copy of the canonical and a snap-borrowed slice
//! over `raw_data` so the renderer can run without copying up to 4 KB
//! out of the static snapshot buffer (the snap outlives the rendering
//! call).

use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, SAFE_V1_CANONICAL_LEN, SAFE_V1_RAW_DATA_MAX,
};

use super::{compute_safe_tx_hash, decode_canonical};
use crate::tx::eip712::keccak;

/// A `safe_v1` trailer that passed every verification step.
///
/// `raw_data` borrows from the gateway's TOCTOU snapshot buffer so we
/// can avoid a 4 KB copy. The borrow is sound because the snapshot
/// outlives the trusted-UI render that consumes it (the handler drops
/// the snapshot only after `confirm()` returns).
pub struct VerifiedSafeV1<'a> {
    pub canonical: [u8; SAFE_V1_CANONICAL_LEN],
    pub raw_data: &'a [u8],
}

/// End-to-end verification of a `safe_v1` trailer against the
/// surrounding UserOp.
///
/// * `safe_bundle` is the full snapshot slice starting at the
///   trailer's first payload byte (canonical || u16 raw_data_len ||
///   raw_data). Anything shorter than the canonical + 2-byte length
///   prefix is malformed and returns `None`.
/// * `inner_data` is the UserOp's inner calldata — must be the
///   36-byte `approveHash(bytes32)` payload for this trailer to apply.
/// * `chain_id` and `userop_to` come from the parsed header. They
///   pin the canonical to the UserOp's chain and to the Safe whose
///   `approveHash` is being called.
///
/// The helper never panics on short / malformed input — every slice
/// access is bounds-checked.
pub fn verify_and_bind_trailer<'a>(
    safe_bundle: &'a [u8],
    inner_data: &[u8],
    chain_id: u64,
    userop_to: &[u8; 20],
) -> Option<VerifiedSafeV1<'a>> {
    // ── 1. Trailer length / framing ────────────────────────────────
    if safe_bundle.len() < SAFE_V1_CANONICAL_LEN + 2 {
        return None;
    }
    let canonical_bytes: &[u8; SAFE_V1_CANONICAL_LEN] = safe_bundle[..SAFE_V1_CANONICAL_LEN]
        .try_into()
        .ok()?;
    let raw_len_lo = SAFE_V1_CANONICAL_LEN;
    let raw_len = u16::from_be_bytes([safe_bundle[raw_len_lo], safe_bundle[raw_len_lo + 1]])
        as usize;
    if raw_len > SAFE_V1_RAW_DATA_MAX {
        return None;
    }
    let raw_data_start = raw_len_lo + 2;
    let raw_data_end = raw_data_start.checked_add(raw_len)?;
    if raw_data_end > safe_bundle.len() {
        return None;
    }
    let raw_data: &[u8] = &safe_bundle[raw_data_start..raw_data_end];

    // ── 2. Selector ────────────────────────────────────────────────
    if inner_data.len() < 4 || inner_data[..4] != APPROVE_HASH_SELECTOR {
        return None;
    }

    // ── 3. Calldata length ─────────────────────────────────────────
    if inner_data.len() != APPROVE_HASH_CALLDATA_LEN {
        return None;
    }

    // ── 4 + 5 + 6: decode canonical and run field-level pins ──────
    let tx = decode_canonical(canonical_bytes).ok()?;

    // (4) chain pinning
    if tx.chain_id != chain_id {
        return None;
    }
    // (5) Safe address pinning
    if &tx.safe_address != userop_to {
        return None;
    }
    // (6) operation gate — only Call (0) accepted in v1
    if tx.operation != 0 {
        return None;
    }

    // ── 7. data_hash bind ──────────────────────────────────────────
    let computed_data_hash = keccak(raw_data);
    if computed_data_hash != tx.data_hash {
        return None;
    }

    // ── 8. safeTxHash bind ─────────────────────────────────────────
    let computed_safe_tx_hash = compute_safe_tx_hash(canonical_bytes).ok()?;
    if computed_safe_tx_hash.as_slice() != &inner_data[4..36] {
        return None;
    }

    let mut canonical = [0u8; SAFE_V1_CANONICAL_LEN];
    canonical.copy_from_slice(canonical_bytes);
    Some(VerifiedSafeV1 {
        canonical,
        raw_data,
    })
}
