//! Top-level verifier for a v3 CoW EIP-712 clear-sign trailer.
//!
//! This is the single entry point `cmd_sign_userop` calls when it sees
//! an optional `zk_v3` trailer on a UserOp. Composes five checks, each
//! load-bearing; first failure wins and the helper returns `None` so
//! the handler treats the trailer as absent (and the downgrade gate
//! rejects the UserOp outright for CoW setPreSignature).
//!
//! The pipeline stays named and ordered on purpose — every step maps
//! to a specific attacker model documented in
//! `CLAUDE.md` invariant #5:
//!
//!   1. **Groth16 + H_root pin** — `crate::zk::verify_clear_sign_proof_v3`
//!      verifies the Merkle-committed 3-pub VK bundle and pairs against
//!      the rodata-pinned `ERC20_POSEIDON_ROOT`. Closes the "custom
//!      H_root" attack.
//!   2. **Sentinel + chain binding** — the verified VK must claim the
//!      CoW v3 sentinel and the tx's `chain_id`. Prevents a valid proof
//!      for protocol A on chain A from being displayed against tx B on
//!      chain B.
//!   3. **Calldata length** — setPreSignature is always exactly 164 B;
//!      any other `inner_data.len()` cannot be a CoW flow and the v3
//!      display never gets applied.
//!   4. **Calldata shape** — selector / ABI offsets / `signed==true` /
//!      tail zero-pad (replaces the v1 circuit's bytes-level proof).
//!   5. **Cross-check** — rebuild the orderDigest from the canonical
//!      bytes (struct_hash covers every GPv2Order field) and byte-
//!      compare against `calldata[100..132]`, then check validTo and
//!      owner against the UserOp sender. Binds the displayed order to
//!      the exact orderUid the chain will see.
//!
//! Returns owned copies of `canonical` and `readable` so the handler
//! can drop the snapshot buffer before rendering (and so zeroize-on-
//! drop happens at a predictable scope).

use sphincs_tz_shared::{
    COWSWAP_EIP712_SENTINEL, EIP712_CANONICAL_LEN, EIP712_PROOF_LEN, EIP712_STRING_LEN,
    ZK_MAX_CALLDATA, ZK_V3_FIXED_LEN, ZK_V3_OFF_CANONICAL, ZK_V3_OFF_READABLE,
};

use super::{check_setpresig_calldata_shape, cross_check_setpresig_calldata};

/// A v3 trailer that passed every verification step. The caller keeps
/// the two fixed-size buffers on the stack until the trusted-UI render
/// is done; nothing else references them.
pub struct VerifiedCowswapV3 {
    pub canonical: [u8; EIP712_CANONICAL_LEN],
    pub readable: [u8; EIP712_STRING_LEN],
}

/// End-to-end verification of a v3 CoW EIP-712 trailer against the
/// surrounding UserOp.
///
/// * `v3_bundle` is the full snapshot slice starting at the trailer's
///   first byte of payload (proof + canonical + readable + VK bundle).
///   Its length must be at least `ZK_V3_FIXED_LEN`; anything shorter is
///   a malformed trailer and returns `None`.
/// * `inner_data` is the UserOp's inner calldata (the bytes that will
///   reach the on-chain settlement contract). Must be exactly 164 B
///   for a CoW setPreSignature; other lengths are treated as "not a
///   CoW flow".
/// * `chain_id` and `userop_sender` are pulled from the parsed header
///   and are the subjects of the sentinel + owner cross-checks.
///
/// Returns `Some(VerifiedCowswapV3)` only when every one of the five
/// pipeline steps succeeds; `None` otherwise. The helper never panics
/// on short / malformed input — length checks precede every slice
/// conversion.
pub fn verify_and_bind_trailer(
    v3_bundle: &[u8],
    inner_data: &[u8],
    chain_id: u64,
    userop_sender: &[u8; 20],
) -> Option<VerifiedCowswapV3> {
    if v3_bundle.len() < ZK_V3_FIXED_LEN {
        return None;
    }

    // ── 1. Groth16 + H_root pin ─────────────────────────────────────
    let proof_bytes: &[u8; EIP712_PROOF_LEN] =
        v3_bundle[..EIP712_PROOF_LEN].try_into().ok()?;
    let canonical_bytes: &[u8; EIP712_CANONICAL_LEN] = v3_bundle
        [ZK_V3_OFF_CANONICAL..ZK_V3_OFF_CANONICAL + EIP712_CANONICAL_LEN]
        .try_into()
        .ok()?;
    let readable_bytes: &[u8; EIP712_STRING_LEN] = v3_bundle
        [ZK_V3_OFF_READABLE..ZK_V3_OFF_READABLE + EIP712_STRING_LEN]
        .try_into()
        .ok()?;
    let vk_bundle = &v3_bundle[ZK_V3_FIXED_LEN..];

    let verified = crate::zk::verify_clear_sign_proof_v3(
        proof_bytes,
        canonical_bytes,
        readable_bytes,
        vk_bundle,
    )
    .ok()?;

    // ── 2. Sentinel + chain binding ────────────────────────────────
    if verified.chain_id != chain_id || verified.contract != COWSWAP_EIP712_SENTINEL {
        return None;
    }

    // ── 3. Calldata length ─────────────────────────────────────────
    //
    // setPreSignature calldata is always exactly 164 bytes. Any other
    // inner_data length cannot be a CoW setPreSignature flow — refuse
    // to apply the v3 display path to non-CoW tx.
    if inner_data.len() != ZK_MAX_CALLDATA {
        return None;
    }
    let calldata_array: &[u8; ZK_MAX_CALLDATA] = inner_data.try_into().ok()?;

    // ── 4. Calldata shape ──────────────────────────────────────────
    check_setpresig_calldata_shape(calldata_array).ok()?;

    // ── 5. Canonical → orderDigest / validTo / owner cross-check ──
    cross_check_setpresig_calldata(
        canonical_bytes,
        calldata_array,
        verified.chain_id,
        userop_sender,
    )
    .ok()?;

    let mut canonical = [0u8; EIP712_CANONICAL_LEN];
    canonical.copy_from_slice(canonical_bytes);
    let mut readable = [0u8; EIP712_STRING_LEN];
    readable.copy_from_slice(readable_bytes);
    Some(VerifiedCowswapV3 {
        canonical,
        readable,
    })
}
