//! Top-level verifier for a CoW order clear-sign trailer.
//!
//! This is the single entry point `cmd_sign_userop` calls when it sees
//! an optional CoW order trailer on a UserOp. The trust anchor is the
//! native keccak `cross_check_setpresig_calldata`: it rebuilds the
//! EIP-712 `struct_hash` over every GPv2Order field and byte-compares
//! the resulting orderDigest against the orderUid embedded in the signed
//! `setPreSignature` calldata. The C10 signature commits to that
//! calldata, so once the cross-check passes the displayed order is
//! provably the order the chain will act on — no SNARK involved.
//!
//! On top of that binding the verifier decodes each swap leg's token
//! metadata (symbol + decimals) ON-DEVICE: the companion attaches an
//! ERC-20 Merkle bundle per leg, the firmware verifies it against the
//! rodata-pinned `ERC20_DB_ROOT` (the same root the ERC-20 transfer
//! clear-sign path uses) and cross-checks the bundle's `(contract,
//! chain_id)` against the canonical leg token + chain. A leg with no
//! bundle — or whose bundle fails any check — degrades to `AddrHex`
//! (raw address + uint256 hex), never a rejection. Token-metadata trust
//! is therefore anchored in a firmware-pinned Merkle root; the host cannot
//! forge symbol/decimals for an address outside the committed set.
//!
//! Pipeline (first failure that touches the *binding* wins → `None`;
//! leg-decode failures only downgrade the leg):
//!
//!   1. **Calldata length** — setPreSignature is always exactly 164 B.
//!   2. **Calldata shape** — selector / ABI offsets / `signed==true` /
//!      tail zero-pad.
//!   3. **Cross-check** — rebuild orderDigest from canonical and
//!      byte-compare against `calldata[100..132]`; check validTo + owner.
//!   4. **Per-leg decode** — Merkle-verify each attached bundle and
//!      cross-check its token/chain against canonical.
//!
//! Returns an owned copy of `canonical` plus the two decoded legs so the
//! handler can drop the snapshot buffer before rendering.

use sphincs_tz_shared::{EIP712_CANONICAL_LEN, COW_PRESIGN_CALLDATA_LEN};

use super::{
    check_setpresig_calldata_shape, cross_check_setpresig_calldata, decode_canonical,
};

/// Maximum on-device token symbol length (matches
/// `pqsigner_tx::erc20::bundle`'s `MAX_DISPLAY_FIELD`).
pub const COW_LEG_SYMBOL_MAX: usize = 64;

/// Maximum on-device token name length (matches
/// `pqsigner_tx::erc20::bundle`'s `MAX_DISPLAY_FIELD`).
pub const COW_LEG_NAME_MAX: usize = 64;

/// How a single swap leg should be rendered.
///
///   * `Decoded` — the leg's ERC-20 bundle Merkle-verified against
///     `ERC20_DB_ROOT` and its `(contract, chain_id)` matched the
///     canonical leg token + chain. The trusted UI shows
///     `<amount> <symbol>` with `decimals` applied, plus a page that
///     restates the `<symbol>` and the human-readable `<name>` (so a
///     symbol-only collision in the DB is visible to the user).
///   * `AddrHex` — no usable bundle: render the raw 20-byte token
///     address + the full uint256 amount as hex. Still fully bound
///     (canonical → orderDigest → calldata.uid), just unformatted.
#[derive(Clone, Copy, Debug)]
pub enum CowLeg {
    Decoded {
        decimals: u8,
        /// Symbol bytes, owned so the snapshot buffer can be dropped
        /// before render. Only the first `symbol_len` are valid.
        symbol: [u8; COW_LEG_SYMBOL_MAX],
        symbol_len: u8,
        /// Name bytes, owned so the snapshot buffer can be dropped
        /// before render. Only the first `name_len` are valid.
        /// Clean ASCII, 1..=64 bytes (enforced by `verify_erc20_bundle`).
        name: [u8; COW_LEG_NAME_MAX],
        name_len: u8,
    },
    AddrHex,
}

impl CowLeg {
    #[must_use]
    pub fn is_decoded(&self) -> bool {
        matches!(self, CowLeg::Decoded { .. })
    }
}

/// A CoW order trailer that passed the binding cross-check. The caller
/// keeps `canonical` on the stack until the trusted-UI render is done.
pub struct VerifiedCowswapV3 {
    pub canonical: [u8; EIP712_CANONICAL_LEN],
    pub sell: CowLeg,
    pub buy: CowLeg,
}

/// Decode one leg from its optional bundle slice. Returns `AddrHex`
/// whenever the bundle is absent, fails Merkle verification, or its
/// `(contract, chain_id)` does not match the canonical leg token + chain.
pub(crate) fn decode_leg(bundle: Option<&[u8]>, expected_token: &[u8; 20], chain_id: u64) -> CowLeg {
    let Some(bundle) = bundle else {
        return CowLeg::AddrHex;
    };
    let Some(meta) = crate::erc20::bundle::verify_erc20_bundle(bundle) else {
        return CowLeg::AddrHex;
    };
    // Cross-check: the bundle must describe THIS leg's token on THIS
    // chain, otherwise NS could attach a valid (USDC, 6) bundle to
    // mislabel an arbitrary attacker token.
    if &meta.contract != expected_token || meta.chain_id != chain_id {
        return CowLeg::AddrHex;
    }
    let sym = meta.symbol;
    if sym.is_empty() || sym.len() > COW_LEG_SYMBOL_MAX {
        return CowLeg::AddrHex;
    }
    let mut symbol = [0u8; COW_LEG_SYMBOL_MAX];
    symbol[..sym.len()].copy_from_slice(sym);
    // `verify_erc20_bundle` already guarantees `name` is clean ASCII and
    // 1..=64 bytes; clamp defensively in case the bound ever diverges.
    let nm = meta.name;
    if nm.is_empty() || nm.len() > COW_LEG_NAME_MAX {
        return CowLeg::AddrHex;
    }
    let mut name = [0u8; COW_LEG_NAME_MAX];
    name[..nm.len()].copy_from_slice(nm);
    CowLeg::Decoded {
        decimals: meta.decimals,
        symbol,
        symbol_len: sym.len() as u8,
        name,
        name_len: nm.len() as u8,
    }
}

/// Read a `u16` BE length prefix at `off`, then the `len`-byte slice that
/// follows, advancing the cursor. Returns `None` on any out-of-bounds
/// (so a malformed trailer degrades to no-bundle rather than panicking).
fn read_len_prefixed<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let lo = *off;
    let len = usize::from(u16::from_be_bytes([*buf.get(lo)?, *buf.get(lo + 1)?]));
    let start = lo + 2;
    let end = start.checked_add(len)?;
    let slice = buf.get(start..end)?;
    *off = end;
    Some(slice)
}

/// End-to-end verification of a CoW order trailer against the
/// surrounding UserOp.
///
/// * `cow_bundle` is the trailer payload: `canonical(204)` optionally
///   followed by `sell_len(u16 BE) || sell_bundle || buy_len(u16 BE) ||
///   buy_bundle`. A bare 204-byte payload renders both legs `AddrHex`.
/// * `inner_data` is the UserOp's inner calldata; must be exactly 164 B
///   (a setPreSignature call) or the trailer is treated as "not CoW".
/// * `chain_id` / `userop_sender` are the cross-check subjects.
///
/// Returns `Some(VerifiedCowswapV3)` only when the calldata
/// length/shape/cross-check all pass; `None` otherwise. Never panics on
/// short/malformed input — every slice access is bounds-checked.
pub fn verify_and_bind_trailer(
    cow_bundle: &[u8],
    inner_data: &[u8],
    chain_id: u64,
    userop_sender: &[u8; 20],
) -> Option<VerifiedCowswapV3> {
    // Canonical is the fixed 204-byte prefix; anything shorter is malformed.
    if cow_bundle.len() < EIP712_CANONICAL_LEN {
        return None;
    }
    let canonical_bytes: &[u8; EIP712_CANONICAL_LEN] =
        cow_bundle[..EIP712_CANONICAL_LEN].try_into().ok()?;

    // ── 1. Calldata length ──────────────────────────────────────────
    if inner_data.len() != COW_PRESIGN_CALLDATA_LEN {
        return None;
    }
    let calldata_array: &[u8; COW_PRESIGN_CALLDATA_LEN] = inner_data.try_into().ok()?;

    // ── 2. Calldata shape ───────────────────────────────────────────
    check_setpresig_calldata_shape(calldata_array).ok()?;

    // ── 3. Canonical → orderDigest / validTo / owner cross-check ────
    //
    // THE trust anchor. struct_hash covers every GPv2Order field, so
    // byte equality against calldata[100..132] locks the entire order
    // into the calldata the chain will see. The C10 sig commits to that
    // calldata; everything below is display-only.
    cross_check_setpresig_calldata(canonical_bytes, calldata_array, chain_id, userop_sender)
        .ok()?;

    // ── 4. Per-leg on-device token decode (display only) ────────────
    //
    // decode_canonical re-validates the enum byte ranges and yields the
    // leg token addresses; the cross-check above already ran it, so this
    // cannot fail here, but we fall back to AddrHex rather than reject if
    // it somehow does — the binding is intact regardless.
    let (sell_bundle, buy_bundle) = if cow_bundle.len() > EIP712_CANONICAL_LEN {
        let mut off = EIP712_CANONICAL_LEN;
        let s = read_len_prefixed(cow_bundle, &mut off);
        let b = read_len_prefixed(cow_bundle, &mut off);
        // A non-empty len==0 slice means "no bundle for this leg".
        (
            s.filter(|sl| !sl.is_empty()),
            b.filter(|sl| !sl.is_empty()),
        )
    } else {
        (None, None)
    };

    let (sell, buy) = match decode_canonical(canonical_bytes) {
        Ok(order) => (
            decode_leg(sell_bundle, &order.sell_token, order.chain_id),
            decode_leg(buy_bundle, &order.buy_token, order.chain_id),
        ),
        Err(_) => (CowLeg::AddrHex, CowLeg::AddrHex),
    };

    let mut canonical = [0u8; EIP712_CANONICAL_LEN];
    canonical.copy_from_slice(canonical_bytes);
    Some(VerifiedCowswapV3 {
        canonical,
        sell,
        buy,
    })
}

/// Verify an off-chain CoW order (`SIGN_OFFCHAIN` kind 5, the CoW `eip1271`
/// signing scheme with this wallet as the owner) and return it with the
/// order digest the device recomputed from it.
///
/// There is no `setPreSignature` calldata to bind to: the signature itself
/// commits to the recomputed digest (the handler signs
/// `replay_safe_hash(digest)`), and the digest's GPv2Settlement domain binds
/// the chain. [`super::compute_digest`] decodes the canonical (enum ranges)
/// and refuses `canonical.chain_id != chain_id`. Each leg bundle is decoded
/// exactly as on the on-chain route: an empty, unverifiable or mismatched
/// bundle degrades that leg to `AddrHex`, never a refusal.
pub fn verify_offchain_cow_order(
    canonical_bytes: &[u8; EIP712_CANONICAL_LEN],
    sell_bundle: &[u8],
    buy_bundle: &[u8],
    chain_id: u64,
) -> Option<(VerifiedCowswapV3, [u8; 32])> {
    let digest = super::compute_digest(canonical_bytes, chain_id).ok()?;
    let order = decode_canonical(canonical_bytes).ok()?;
    let sell = decode_leg(Some(sell_bundle).filter(|b| !b.is_empty()), &order.sell_token, order.chain_id);
    let buy = decode_leg(Some(buy_bundle).filter(|b| !b.is_empty()), &order.buy_token, order.chain_id);
    let mut canonical = [0u8; EIP712_CANONICAL_LEN];
    canonical.copy_from_slice(canonical_bytes);
    Some((VerifiedCowswapV3 { canonical, sell, buy }, digest))
}
