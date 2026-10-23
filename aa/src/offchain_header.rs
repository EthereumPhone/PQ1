//! Pure framing parser for the off-chain `EIP712_TYPED` / `EIP712_TYPED_V3`
//! sign-request payload.
//!
//! Extracted **verbatim and behaviour-identical** from the inline walker in
//! `secure/src/nsc/cmd_sign_offchain.rs` so the untrusted-companion-bytes
//! framing decode — the first thing the secure world does with the payload of
//! a `CMD_SIGN_OFFCHAIN` typed-data request — is host-compilable and
//! Kani-bounded (`cargo kani -p pqsigner-aa`). The secure caller keeps the
//! same upstream `payload_len` min/max gate in the kind dispatch and then
//! calls [`parse_eip712_typed_frame`]; on `Err` it maps
//! [`Eip712FrameError::status_str`] to the same `show_status` banner it showed
//! before and refuses. The downstream (ERC-7730 bundle verify, FI-hardened
//! binding, keccak digest) stays in the secure world and consumes the frame's
//! slices unchanged.
//!
//! Wire layout (all lengths `u16` big-endian):
//! ```text
//!   [dsep_present:2][domain_separator:32][primary_type_hash:32]
//!   [encoded_data_len:2][encoded_data:encoded_data_len]
//!   (V3 only) [witness_blob_len:2][witness_blob:witness_blob_len]
//!   [trailer_len:2][trailer:trailer_len]
//! ```
//! The final `trailer` MUST end exactly at `payload.len()` — the wire-level
//! EXACT-consumption guard: every byte is accounted, no hidden trailing data.

use pqsigner_proto::{MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN, MAX_OFFCHAIN_EIP712_NESTED_LEN};

/// The five sections a typed-data frame decodes to. `encoded_data` /
/// `nested_blob` / `trailer` borrow from the input payload; the two 32-byte
/// hashes are copied out (the caller folds them into the EIP-712 digest).
#[derive(Debug)]
pub struct Eip712TypedFrame<'a> {
    /// Companion-supplied EIP-712 `domainSeparator` (folded into the final hash).
    pub domain_separator: [u8; 32],
    /// EIP-712 `primaryType` type hash.
    pub primary_type_hash: [u8; 32],
    /// ABI-encoded struct data (`keccak256(typehash || encoded_data)`).
    pub encoded_data: &'a [u8],
    /// V3 descriptor-selected display-witness blob (DISPLAY-only; empty for
    /// non-V3). The retained field name is wire/API compatibility; authenticated
    /// IR selects nested-struct versus string-preimage record grammar.
    pub nested_blob: &'a [u8],
    /// The ERC-7730 descriptor bundle trailer.
    pub trailer: &'a [u8],
}

/// Why a typed-data frame was refused. `status_str` is the ≤16-col banner the
/// secure `show_status` shows — byte-identical to the pre-extraction messages.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Eip712FrameError {
    /// Payload shorter than the fixed header (`dsep_present + dsep + pth +
    /// edl + trailer_len`, or `+ nested_len` for V3).
    ShortHeader,
    /// `dsep_present == 0` — no domain separator supplied.
    MissingDomainSep,
    /// `encoded_data_len` over the cap or past the payload end.
    BadEncodedDataLen,
    /// V3: no room for the `nested_blob_len` word.
    NoNestedLen,
    /// V3: `nested_blob_len` over the cap or past the payload end.
    BadNestedLen,
    /// No room for the `trailer_len` word.
    NoTrailerLen,
    /// `trailer_len == 0`.
    EmptyTrailer,
    /// `trailer_len` does not consume the payload EXACTLY (hidden bytes).
    BadTrailerLen,
}

impl Eip712FrameError {
    /// The exact `show_status` banner the inline walker showed for this reason.
    #[must_use]
    pub fn status_str(self) -> &'static str {
        match self {
            Eip712FrameError::ShortHeader => "typed too short",
            Eip712FrameError::MissingDomainSep => "7730 missing ds",
            Eip712FrameError::BadEncodedDataLen => "bad ed_len",
            Eip712FrameError::NoNestedLen => "no nested len",
            Eip712FrameError::BadNestedLen => "bad nested len",
            Eip712FrameError::NoTrailerLen => "no trailer",
            Eip712FrameError::EmptyTrailer => "empty trailer",
            Eip712FrameError::BadTrailerLen => "bad trailer_len",
        }
    }
}

#[inline]
fn read_u16(payload: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([payload[p], payload[p + 1]])
}

/// Strictly decode the typed-data framing. Panic/OOB-free for ANY input: every
/// read is bounds-checked, so a truncated or over-claiming length returns `Err`
/// rather than indexing out of bounds. `Ok` guarantees the trailer ends exactly
/// at `payload.len()` (no hidden trailing bytes).
pub fn parse_eip712_typed_frame(
    payload: &[u8],
    is_v3: bool,
) -> Result<Eip712TypedFrame<'_>, Eip712FrameError> {
    // Fixed header: dsep_present(2) + dsep(32) + pth(32) + edl(2) +
    // trailer_len(2) [+ nested_blob_len(2) for V3]. This makes every fixed-word
    // read below in-bounds without a per-read length test.
    let min = 2 + 32 + 32 + 2 + 2 + if is_v3 { 2 } else { 0 };
    if payload.len() < min {
        return Err(Eip712FrameError::ShortHeader);
    }

    let mut p = 0usize;
    let domain_sep_present = read_u16(payload, p) != 0;
    p += 2;
    if !domain_sep_present {
        return Err(Eip712FrameError::MissingDomainSep);
    }
    let mut domain_separator = [0u8; 32];
    domain_separator.copy_from_slice(&payload[p..p + 32]);
    p += 32;
    let mut primary_type_hash = [0u8; 32];
    primary_type_hash.copy_from_slice(&payload[p..p + 32]);
    p += 32;

    let encoded_data_len = read_u16(payload, p) as usize;
    p += 2;
    if encoded_data_len > MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN
        || p + encoded_data_len > payload.len()
    {
        return Err(Eip712FrameError::BadEncodedDataLen);
    }
    let encoded_data = &payload[p..p + encoded_data_len];
    p += encoded_data_len;

    let nested_blob: &[u8] = if is_v3 {
        if p + 2 > payload.len() {
            return Err(Eip712FrameError::NoNestedLen);
        }
        let nb_len = read_u16(payload, p) as usize;
        p += 2;
        if nb_len > MAX_OFFCHAIN_EIP712_NESTED_LEN || p + nb_len > payload.len() {
            return Err(Eip712FrameError::BadNestedLen);
        }
        let nb = &payload[p..p + nb_len];
        p += nb_len;
        nb
    } else {
        &[]
    };

    if p + 2 > payload.len() {
        return Err(Eip712FrameError::NoTrailerLen);
    }
    let trailer_len = read_u16(payload, p) as usize;
    p += 2;
    if trailer_len == 0 {
        return Err(Eip712FrameError::EmptyTrailer);
    }
    // EXACT consumption: the trailer must be the rest of the payload.
    if p + trailer_len != payload.len() {
        return Err(Eip712FrameError::BadTrailerLen);
    }
    let trailer = &payload[p..p + trailer_len];

    Ok(Eip712TypedFrame {
        domain_separator,
        primary_type_hash,
        encoded_data,
        nested_blob,
        trailer,
    })
}

// ---------------------------------------------------------------------------
// Structured off-chain kinds: SafeTx (4), CoW order (5) and Permit2 (6)
// ---------------------------------------------------------------------------

use pqsigner_proto::{
    COW_ORDER_BUNDLE_MAX, COW_ORDER_TRAILER_MAX_LEN, EIP712_CANONICAL_LEN,
    OFFCHAIN_MAX_NAME_BUNDLES, OFFCHAIN_NAME_BUNDLE_MAX_LEN, PERMIT2_ALLOWANCE_HEAD_LEN,
    PERMIT2_ENTRY_LEN, PERMIT2_MAX_NAME_BUNDLES, PERMIT2_MAX_TOKENS, PERMIT2_TRANSFER_HEAD_LEN,
    PERMIT2_VARIANT_BATCH, PERMIT2_VARIANT_BATCH_TRANSFER, PERMIT2_VARIANT_SINGLE,
    PERMIT2_VARIANT_TRANSFER, SAFE_V1_CANONICAL_LEN, SAFE_V1_PAYLOAD_MAX,
};

/// The sections of an `OFFCHAIN_KIND_SAFE_TX` payload. Every slice borrows
/// from the input payload.
#[derive(Debug)]
pub struct SafeTxFrame<'a> {
    /// The on-chain `safe_v1` trailer encoding: `canonical(281) ||
    /// raw_len(2) || raw_data`, with `raw_data` ending EXACTLY at the end of
    /// this slice.
    pub safe_bundle: &'a [u8],
    /// Optional ERC-20 metadata bundle for the SafeTx inner call (empty =
    /// none).
    pub erc20: &'a [u8],
    /// Optional CoW order trailer for a Safe-wrapped `setPreSignature`
    /// (empty = none). Required-iff is decided by the secure world.
    pub cow: &'a [u8],
    /// Name bundles; only the first `names_count` are meaningful.
    pub names: [&'a [u8]; OFFCHAIN_MAX_NAME_BUNDLES],
    /// How many entries of `names` are present.
    pub names_count: usize,
}

/// The sections of an `OFFCHAIN_KIND_COW_ORDER` payload.
#[derive(Debug)]
pub struct CowOrderFrame<'a> {
    /// The 204-byte canonical GPv2Order.
    pub canonical: &'a [u8; EIP712_CANONICAL_LEN],
    /// Sell-leg ERC-20 bundle (empty = none).
    pub sell: &'a [u8],
    /// Buy-leg ERC-20 bundle (empty = none).
    pub buy: &'a [u8],
}

/// The sections of an `OFFCHAIN_KIND_PERMIT2` payload (layout in
/// `pqsigner_proto::MAX_OFFCHAIN_PERMIT2_LEN`).
#[derive(Debug)]
pub struct Permit2Frame<'a> {
    /// The packed permit (`head + count * 52` bytes); decoded by
    /// `pqsigner_tx::permit2::decode_core`.
    pub core: &'a [u8],
    /// Token count announced by the core (the number of ERC-20 slots).
    pub count: usize,
    /// Per-token ERC-20 bundles; slot `i` belongs to token `i`, only the
    /// first `count` are meaningful, empty = none.
    pub erc20: [&'a [u8]; PERMIT2_MAX_TOKENS],
    /// The spender's name bundle (empty = none).
    pub name: &'a [u8],
}

/// Why a structured off-chain frame was refused. `status_str` is the
/// ≤16-column banner the secure world shows.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StructuredFrameError {
    /// A length word or its section runs past the payload end.
    Truncated,
    /// The Safe section is shorter than canonical + raw_len, or over the cap.
    BadSafeLen,
    /// The Safe section's `raw_len` does not end exactly at its end.
    BadSafeRawLen,
    /// The ERC-20 bundle is over the cap.
    BadErc20Len,
    /// The CoW section is non-empty but outside the trailer bounds.
    BadCowLen,
    /// More name bundles than the cap.
    BadNamesCount,
    /// A name bundle is empty or over the cap.
    BadNameLen,
    /// A CoW leg bundle is over the cap.
    BadLegLen,
    /// Bytes remain after the last section (hidden trailing data).
    TrailingBytes,
    /// A Permit2 variant byte outside 0..=3.
    BadPermit2Variant,
    /// A Permit2 token count outside its variant's range.
    BadPermit2Count,
}

impl StructuredFrameError {
    /// The exact `show_status` banner for this reason.
    #[must_use]
    pub fn status_str(self) -> &'static str {
        match self {
            StructuredFrameError::Truncated => "struct truncated",
            StructuredFrameError::BadSafeLen => "bad safe len",
            StructuredFrameError::BadSafeRawLen => "bad safe raw len",
            StructuredFrameError::BadErc20Len => "bad erc20 len",
            StructuredFrameError::BadCowLen => "bad cow len",
            StructuredFrameError::BadNamesCount => "bad names count",
            StructuredFrameError::BadNameLen => "bad name len",
            StructuredFrameError::BadLegLen => "bad leg len",
            StructuredFrameError::TrailingBytes => "struct trailing",
            StructuredFrameError::BadPermit2Variant => "permit2 variant",
            StructuredFrameError::BadPermit2Count => "permit2 count",
        }
    }
}

/// Read `[u16 len][len bytes]` at `*p`, bounded by `max`; advances `*p`.
#[inline]
fn take_u16_prefixed<'a>(
    payload: &'a [u8],
    p: &mut usize,
    max: usize,
    too_long: StructuredFrameError,
) -> Result<&'a [u8], StructuredFrameError> {
    if *p > payload.len() || payload.len() - *p < 2 {
        return Err(StructuredFrameError::Truncated);
    }
    let len = read_u16(payload, *p) as usize;
    *p += 2;
    if len > max {
        return Err(too_long);
    }
    if payload.len() - *p < len {
        return Err(StructuredFrameError::Truncated);
    }
    let out = &payload[*p..*p + len];
    *p += len;
    Ok(out)
}

/// Strictly decode an `OFFCHAIN_KIND_SAFE_TX` payload (layout in
/// `pqsigner_proto::MAX_OFFCHAIN_SAFE_TX_LEN`). Panic/OOB-free for ANY
/// input; `Ok` guarantees every byte is consumed (no hidden trailing data)
/// and that the Safe section's `raw_data` ends exactly at the section end.
pub fn parse_safe_tx_frame(payload: &[u8]) -> Result<SafeTxFrame<'_>, StructuredFrameError> {
    let mut p = 0usize;
    let safe_bundle = take_u16_prefixed(
        payload,
        &mut p,
        SAFE_V1_PAYLOAD_MAX,
        StructuredFrameError::BadSafeLen,
    )?;
    if safe_bundle.len() < SAFE_V1_CANONICAL_LEN + 2 {
        return Err(StructuredFrameError::BadSafeLen);
    }
    let raw_len = read_u16(safe_bundle, SAFE_V1_CANONICAL_LEN) as usize;
    if SAFE_V1_CANONICAL_LEN + 2 + raw_len != safe_bundle.len() {
        return Err(StructuredFrameError::BadSafeRawLen);
    }
    let erc20 = take_u16_prefixed(
        payload,
        &mut p,
        COW_ORDER_BUNDLE_MAX,
        StructuredFrameError::BadErc20Len,
    )?;
    let cow = take_u16_prefixed(
        payload,
        &mut p,
        COW_ORDER_TRAILER_MAX_LEN,
        StructuredFrameError::BadCowLen,
    )?;
    if !cow.is_empty() && cow.len() < EIP712_CANONICAL_LEN {
        return Err(StructuredFrameError::BadCowLen);
    }
    if p >= payload.len() {
        return Err(StructuredFrameError::Truncated);
    }
    let names_count = payload[p] as usize;
    p += 1;
    if names_count > OFFCHAIN_MAX_NAME_BUNDLES {
        return Err(StructuredFrameError::BadNamesCount);
    }
    let mut names: [&[u8]; OFFCHAIN_MAX_NAME_BUNDLES] = [&[]; OFFCHAIN_MAX_NAME_BUNDLES];
    // An index loop bounded by `names_count <= 4` (not an iterator chain), so
    // a bounded model checker unwinds it in at most five steps.
    let mut i = 0usize;
    while i < names_count {
        let n = take_u16_prefixed(
            payload,
            &mut p,
            OFFCHAIN_NAME_BUNDLE_MAX_LEN,
            StructuredFrameError::BadNameLen,
        )?;
        if n.is_empty() {
            return Err(StructuredFrameError::BadNameLen);
        }
        names[i] = n;
        i += 1;
    }
    if p != payload.len() {
        return Err(StructuredFrameError::TrailingBytes);
    }
    Ok(SafeTxFrame {
        safe_bundle,
        erc20,
        cow,
        names,
        names_count,
    })
}

/// Strictly decode an `OFFCHAIN_KIND_COW_ORDER` payload: `canonical(204) ||
/// sell_len(2) || sell || buy_len(2) || buy`, consumed EXACTLY. Panic/OOB-
/// free for ANY input.
pub fn parse_cow_order_frame(payload: &[u8]) -> Result<CowOrderFrame<'_>, StructuredFrameError> {
    if payload.len() < EIP712_CANONICAL_LEN {
        return Err(StructuredFrameError::Truncated);
    }
    let Ok(canonical) = <&[u8; EIP712_CANONICAL_LEN]>::try_from(&payload[..EIP712_CANONICAL_LEN])
    else {
        return Err(StructuredFrameError::Truncated);
    };
    let mut p = EIP712_CANONICAL_LEN;
    let sell = take_u16_prefixed(payload, &mut p, COW_ORDER_BUNDLE_MAX, StructuredFrameError::BadLegLen)?;
    let buy = take_u16_prefixed(payload, &mut p, COW_ORDER_BUNDLE_MAX, StructuredFrameError::BadLegLen)?;
    if p != payload.len() {
        return Err(StructuredFrameError::TrailingBytes);
    }
    Ok(CowOrderFrame { canonical, sell, buy })
}

/// Strictly decode an `OFFCHAIN_KIND_PERMIT2` payload: the packed permit
/// core, `count` length-prefixed ERC-20 slots and at most one non-empty
/// name bundle, consumed EXACTLY. Panic/OOB-free for ANY input. The core's
/// fields are decoded (and its policy refusals applied) by
/// `pqsigner_tx::permit2::decode_core`; this checks only the framing.
pub fn parse_permit2_frame(payload: &[u8]) -> Result<Permit2Frame<'_>, StructuredFrameError> {
    let Some(&variant) = payload.first() else {
        return Err(StructuredFrameError::Truncated);
    };
    let (head, batch) = match variant {
        PERMIT2_VARIANT_SINGLE => (PERMIT2_ALLOWANCE_HEAD_LEN, false),
        PERMIT2_VARIANT_BATCH => (PERMIT2_ALLOWANCE_HEAD_LEN, true),
        PERMIT2_VARIANT_TRANSFER => (PERMIT2_TRANSFER_HEAD_LEN, false),
        PERMIT2_VARIANT_BATCH_TRANSFER => (PERMIT2_TRANSFER_HEAD_LEN, true),
        _ => return Err(StructuredFrameError::BadPermit2Variant),
    };
    if payload.len() < head {
        return Err(StructuredFrameError::Truncated);
    }
    let count = payload[head - 1] as usize;
    let count_ok = if batch { (1..=PERMIT2_MAX_TOKENS).contains(&count) } else { count == 1 };
    if !count_ok {
        return Err(StructuredFrameError::BadPermit2Count);
    }
    let core_len = head + count * PERMIT2_ENTRY_LEN;
    if payload.len() < core_len {
        return Err(StructuredFrameError::Truncated);
    }
    let mut p = core_len;
    let mut erc20: [&[u8]; PERMIT2_MAX_TOKENS] = [&[]; PERMIT2_MAX_TOKENS];
    // Index loops bounded by `count <= 6` and `names <= 1` so a bounded model
    // checker unwinds them (see `parse_safe_tx_frame`).
    let mut i = 0usize;
    while i < count {
        erc20[i] = take_u16_prefixed(payload, &mut p, COW_ORDER_BUNDLE_MAX, StructuredFrameError::BadLegLen)?;
        i += 1;
    }
    if p >= payload.len() {
        return Err(StructuredFrameError::Truncated);
    }
    let names_count = payload[p] as usize;
    p += 1;
    if names_count > PERMIT2_MAX_NAME_BUNDLES {
        return Err(StructuredFrameError::BadNamesCount);
    }
    let mut name: &[u8] = &[];
    if names_count == 1 {
        name = take_u16_prefixed(
            payload,
            &mut p,
            OFFCHAIN_NAME_BUNDLE_MAX_LEN,
            StructuredFrameError::BadNameLen,
        )?;
        if name.is_empty() {
            return Err(StructuredFrameError::BadNameLen);
        }
    }
    if p != payload.len() {
        return Err(StructuredFrameError::TrailingBytes);
    }
    Ok(Permit2Frame {
        core: &payload[..core_len],
        count,
        erc20,
        name,
    })
}

#[cfg(test)]
mod structured_tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn safe_payload(raw: &[u8], erc20: &[u8], cow: &[u8], names: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        let safe_len = SAFE_V1_CANONICAL_LEN + 2 + raw.len();
        v.extend_from_slice(&(safe_len as u16).to_be_bytes());
        v.extend_from_slice(&[0x11; SAFE_V1_CANONICAL_LEN]);
        v.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        v.extend_from_slice(raw);
        v.extend_from_slice(&(erc20.len() as u16).to_be_bytes());
        v.extend_from_slice(erc20);
        v.extend_from_slice(&(cow.len() as u16).to_be_bytes());
        v.extend_from_slice(cow);
        v.push(names.len() as u8);
        for n in names {
            v.extend_from_slice(&(n.len() as u16).to_be_bytes());
            v.extend_from_slice(n);
        }
        v
    }

    #[test]
    fn safe_frame_minimal_and_full_accept() {
        let p = safe_payload(&[], &[], &[], &[]);
        assert_eq!(p.len(), pqsigner_proto::MIN_OFFCHAIN_SAFE_TX_LEN);
        let f = parse_safe_tx_frame(&p).unwrap();
        assert_eq!(f.safe_bundle.len(), SAFE_V1_CANONICAL_LEN + 2);
        assert!(f.erc20.is_empty() && f.cow.is_empty() && f.names_count == 0);

        let cow = [0x22; EIP712_CANONICAL_LEN + 4];
        let p = safe_payload(&[1, 2, 3], &[9; 10], &cow, &[&[7; 5], &[8; 6]]);
        let f = parse_safe_tx_frame(&p).unwrap();
        assert_eq!(&f.safe_bundle[SAFE_V1_CANONICAL_LEN + 2..], &[1, 2, 3]);
        assert_eq!(f.erc20, &[9; 10]);
        assert_eq!(f.cow, &cow);
        assert_eq!((f.names_count, f.names[0], f.names[1]), (2, &[7u8; 5][..], &[8u8; 6][..]));
    }

    #[test]
    fn safe_frame_refusals() {
        let good = safe_payload(&[1, 2, 3], &[], &[], &[]);
        let mut t = good.clone();
        t.push(0);
        assert_eq!(parse_safe_tx_frame(&t).unwrap_err(), StructuredFrameError::TrailingBytes);
        for cut in 0..good.len() {
            assert!(parse_safe_tx_frame(&good[..cut]).is_err(), "cut {cut}");
        }
        // raw_len that does not end at the Safe section end.
        let mut r = good.clone();
        r[2 + SAFE_V1_CANONICAL_LEN + 1] = 2;
        assert_eq!(parse_safe_tx_frame(&r).unwrap_err(), StructuredFrameError::BadSafeRawLen);
        // A CoW section shorter than the canonical.
        let short_cow = safe_payload(&[], &[], &[0; 10], &[]);
        assert_eq!(parse_safe_tx_frame(&short_cow).unwrap_err(), StructuredFrameError::BadCowLen);
        // Too many names; an empty name.
        let five: [&[u8]; 5] = [&[1], &[1], &[1], &[1], &[1]];
        assert_eq!(
            parse_safe_tx_frame(&safe_payload(&[], &[], &[], &five)).unwrap_err(),
            StructuredFrameError::BadNamesCount
        );
        assert_eq!(
            parse_safe_tx_frame(&safe_payload(&[], &[], &[], &[&[]])).unwrap_err(),
            StructuredFrameError::BadNameLen
        );
        // An over-cap ERC-20 bundle.
        let big = std::vec![0u8; COW_ORDER_BUNDLE_MAX + 1];
        assert_eq!(
            parse_safe_tx_frame(&safe_payload(&[], &big, &[], &[])).unwrap_err(),
            StructuredFrameError::BadErc20Len
        );
    }

    #[test]
    fn cow_frame_exact() {
        let mut p = std::vec![0x33u8; EIP712_CANONICAL_LEN];
        p.extend_from_slice(&3u16.to_be_bytes());
        p.extend_from_slice(&[1, 2, 3]);
        p.extend_from_slice(&0u16.to_be_bytes());
        let f = parse_cow_order_frame(&p).unwrap();
        assert_eq!((f.sell, f.buy), (&[1u8, 2, 3][..], &[][..]));
        assert_eq!(f.canonical, &[0x33; EIP712_CANONICAL_LEN]);
        let mut t = p.clone();
        t.push(0);
        assert_eq!(parse_cow_order_frame(&t).unwrap_err(), StructuredFrameError::TrailingBytes);
        for cut in 0..p.len() {
            assert!(parse_cow_order_frame(&p[..cut]).is_err(), "cut {cut}");
        }
        // The bare 204-byte canonical (no leg words) is NOT the kind-5 shape.
        assert!(parse_cow_order_frame(&p[..EIP712_CANONICAL_LEN]).is_err());
    }

    fn permit2_payload(variant: u8, count: u8, slots: &[&[u8]], name: Option<&[u8]>) -> Vec<u8> {
        let head = if variant < 2 { PERMIT2_ALLOWANCE_HEAD_LEN } else { PERMIT2_TRANSFER_HEAD_LEN };
        let mut v = std::vec![0x44u8; head + usize::from(count) * PERMIT2_ENTRY_LEN];
        v[0] = variant;
        v[head - 1] = count;
        for s in slots {
            v.extend_from_slice(&(s.len() as u16).to_be_bytes());
            v.extend_from_slice(s);
        }
        match name {
            Some(n) => {
                v.push(1);
                v.extend_from_slice(&(n.len() as u16).to_be_bytes());
                v.extend_from_slice(n);
            }
            None => v.push(0),
        }
        v
    }

    #[test]
    fn permit2_frame_minimal_and_full_accept() {
        let p = permit2_payload(PERMIT2_VARIANT_SINGLE, 1, &[&[]], None);
        assert_eq!(p.len(), pqsigner_proto::MIN_OFFCHAIN_PERMIT2_LEN);
        let f = parse_permit2_frame(&p).unwrap();
        assert_eq!((f.core.len(), f.count, f.name.len()), (114, 1, 0));

        let p = permit2_payload(PERMIT2_VARIANT_BATCH_TRANSFER, 3, &[&[1, 2], &[], &[3]], Some(&[9; 4]));
        let f = parse_permit2_frame(&p).unwrap();
        assert_eq!(f.core.len(), PERMIT2_TRANSFER_HEAD_LEN + 3 * PERMIT2_ENTRY_LEN);
        assert_eq!((f.erc20[0], f.erc20[1], f.erc20[2]), (&[1u8, 2][..], &[][..], &[3u8][..]));
        assert_eq!(f.name, &[9; 4]);
    }

    #[test]
    fn permit2_frame_refusals() {
        use StructuredFrameError::*;
        let good = permit2_payload(PERMIT2_VARIANT_BATCH, 2, &[&[1], &[2]], Some(&[7]));
        for cut in 0..good.len() {
            assert!(parse_permit2_frame(&good[..cut]).is_err(), "cut {cut}");
        }
        let mut t = good.clone();
        t.push(0);
        assert_eq!(parse_permit2_frame(&t).unwrap_err(), TrailingBytes);
        let mut v = good.clone();
        v[0] = 4;
        assert_eq!(parse_permit2_frame(&v).unwrap_err(), BadPermit2Variant);
        assert_eq!(
            parse_permit2_frame(&permit2_payload(PERMIT2_VARIANT_SINGLE, 2, &[&[], &[]], None)).unwrap_err(),
            BadPermit2Count
        );
        assert_eq!(
            parse_permit2_frame(&permit2_payload(PERMIT2_VARIANT_BATCH, 0, &[], None)).unwrap_err(),
            BadPermit2Count
        );
        let seven: [&[u8]; 7] = [&[]; 7];
        assert_eq!(
            parse_permit2_frame(&permit2_payload(PERMIT2_VARIANT_BATCH_TRANSFER, 7, &seven, None)).unwrap_err(),
            BadPermit2Count
        );
        assert_eq!(
            parse_permit2_frame(&permit2_payload(PERMIT2_VARIANT_TRANSFER, 1, &[&[]], Some(&[]))).unwrap_err(),
            BadNameLen
        );
        let mut two_names = permit2_payload(PERMIT2_VARIANT_TRANSFER, 1, &[&[]], None);
        *two_names.last_mut().unwrap() = 2;
        assert_eq!(parse_permit2_frame(&two_names).unwrap_err(), BadNamesCount);
        let big = std::vec![0u8; COW_ORDER_BUNDLE_MAX + 1];
        assert_eq!(
            parse_permit2_frame(&permit2_payload(PERMIT2_VARIANT_SINGLE, 1, &[&big], None)).unwrap_err(),
            BadLegLen
        );
        // The largest legal frame is exactly the proto maximum.
        let full = std::vec![0u8; COW_ORDER_BUNDLE_MAX];
        let slots: [&[u8]; 6] = [&full; 6];
        let name = std::vec![0u8; OFFCHAIN_NAME_BUNDLE_MAX_LEN];
        let max = permit2_payload(PERMIT2_VARIANT_BATCH_TRANSFER, 6, &slots, Some(&name));
        assert_eq!(max.len(), pqsigner_proto::MAX_OFFCHAIN_PERMIT2_LEN);
        assert!(parse_permit2_frame(&max).is_ok());
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Panic / arithmetic-overflow / slice-OOB freedom AND framing-exactness for
    /// the untrusted `EIP712_TYPED` / `_V3` header over symbolic payloads of
    /// length ≤ N. No crafted payload — any lengths, any content — can index the
    /// decoder out of bounds (it returns `Err` instead), and on ACCEPT the
    /// trailer ends EXACTLY at `payload.len()` (`p_after_walk == len`), so no
    /// hidden trailing bytes ride an accepted frame. Bounded N=90 admits the
    /// fixed header (70/72 B) + short variable tails; the framing logic is
    /// length-uniform (each section is a `read_u16` + a `p + n > len` gate), so
    /// N=90 is representative of the OOB/exactness surface.
    #[kani::proof]
    #[kani::unwind(4)]
    fn parse_frame_panic_free_and_exact() {
        const N: usize = 90;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let is_v3: bool = kani::any();
        let payload = &buf[..len];

        if let Ok(f) = parse_eip712_typed_frame(payload, is_v3) {
            // Every returned slice lies inside the payload …
            let base = payload.as_ptr() as usize;
            let ed = f.encoded_data.as_ptr() as usize;
            let tr = f.trailer.as_ptr() as usize;
            assert!(ed >= base && ed + f.encoded_data.len() <= base + len);
            assert!(tr >= base && tr + f.trailer.len() <= base + len);
            // … and the trailer ends EXACTLY at the payload end (exact consumption).
            assert_eq!(tr + f.trailer.len(), base + len);
            // is_v3 ⟺ a nested blob section was parsed (possibly empty).
            if !is_v3 {
                assert!(f.nested_blob.is_empty());
            }
        }
    }

    /// Non-vacuity (positive control): a concrete minimal well-formed non-V3
    /// frame (empty encoded_data, 1-byte trailer) is ACCEPTED and the trailer is
    /// the final byte.
    #[kani::proof]
    fn parse_frame_accepts_minimal() {
        // dsep_present=1, dsep(32)=0, pth(32)=0, edl=0, trailer_len=1, trailer=[0xAB]
        let mut buf = [0u8; 71];
        buf[1] = 1; // dsep_present low byte
        // edl word @ 66..68 = 0 (already). trailer_len word @ 68..70 = 1.
        buf[69] = 1;
        buf[70] = 0xAB;
        let f = parse_eip712_typed_frame(&buf, false).expect("minimal frame accepts");
        assert_eq!(f.trailer, &[0xAB]);
        assert!(f.encoded_data.is_empty() && f.nested_blob.is_empty());
    }

    /// Sum of the lengths of a Safe frame's sections plus their length words.
    fn safe_frame_consumed(f: &SafeTxFrame<'_>) -> usize {
        let mut n = 2 + f.safe_bundle.len() + 2 + f.erc20.len() + 2 + f.cow.len() + 1;
        let mut i = 0;
        while i < f.names_count {
            n += 2 + f.names[i].len();
            i += 1;
        }
        n
    }

    /// `OFFCHAIN_KIND_SAFE_TX` framing: panic/OOB-free over symbolic payloads
    /// of length ≤ N, and on ACCEPT every byte is consumed (sections + length
    /// words == payload length), the Safe section's `raw_len` ends exactly at
    /// its end, and the name count is within the cap. N=300 admits the
    /// 290-byte minimum plus short variable sections; every section is the
    /// same `take_u16_prefixed` gate, so the bound is representative. (The
    /// name loop is an index loop on purpose: as an iterator chain CBMC did
    /// not bound it and this harness never finished.)
    #[kani::proof]
    #[kani::unwind(6)]
    fn parse_safe_tx_frame_panic_free_and_exact() {
        const N: usize = 300;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let payload = &buf[..len];
        if let Ok(f) = parse_safe_tx_frame(payload) {
            assert_eq!(safe_frame_consumed(&f), len);
            assert!(f.names_count <= OFFCHAIN_MAX_NAME_BUNDLES);
            let raw_len = read_u16(f.safe_bundle, SAFE_V1_CANONICAL_LEN) as usize;
            assert_eq!(SAFE_V1_CANONICAL_LEN + 2 + raw_len, f.safe_bundle.len());
        }
    }

    /// `OFFCHAIN_KIND_COW_ORDER` framing: panic/OOB-free, and on ACCEPT the
    /// canonical + both length-prefixed legs consume the payload EXACTLY.
    #[kani::proof]
    #[kani::unwind(4)]
    fn parse_cow_order_frame_panic_free_and_exact() {
        const N: usize = EIP712_CANONICAL_LEN + 12;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let payload = &buf[..len];
        if let Ok(f) = parse_cow_order_frame(payload) {
            assert_eq!(EIP712_CANONICAL_LEN + 2 + f.sell.len() + 2 + f.buy.len(), len);
        }
    }

    /// `OFFCHAIN_KIND_PERMIT2` framing: panic/OOB-free over symbolic payloads
    /// of length ≤ N, and on ACCEPT the core, the `count` ERC-20 slots and the
    /// optional name consume the payload EXACTLY, the core is exactly
    /// `head + count * 52` bytes and the count is in its variant's range.
    /// N admits a two-token transfer core plus short sections.
    #[kani::proof]
    #[kani::unwind(8)]
    fn parse_permit2_frame_panic_free_and_exact() {
        const N: usize = PERMIT2_TRANSFER_HEAD_LEN + 2 * PERMIT2_ENTRY_LEN + 8;
        let buf: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let payload = &buf[..len];
        if let Ok(f) = parse_permit2_frame(payload) {
            let head = if payload[0] < 2 { PERMIT2_ALLOWANCE_HEAD_LEN } else { PERMIT2_TRANSFER_HEAD_LEN };
            assert!(payload[0] <= 3);
            assert_eq!(f.count, payload[head - 1] as usize);
            assert!(f.count >= 1 && f.count <= PERMIT2_MAX_TOKENS);
            assert!(payload[0] == PERMIT2_VARIANT_BATCH || payload[0] == PERMIT2_VARIANT_BATCH_TRANSFER || f.count == 1);
            assert_eq!(f.core.len(), head + f.count * PERMIT2_ENTRY_LEN);
            let mut n = f.core.len() + 1;
            let mut i = 0;
            while i < f.count {
                n += 2 + f.erc20[i].len();
                i += 1;
            }
            if !f.name.is_empty() {
                n += 2 + f.name.len();
            }
            assert_eq!(n, len);
        }
    }

    /// Non-vacuity: the minimal well-formed frames are ACCEPTED.
    #[kani::proof]
    #[kani::unwind(6)]
    fn structured_frames_accept_minimal() {
        let mut safe = [0u8; pqsigner_proto::MIN_OFFCHAIN_SAFE_TX_LEN];
        let safe_len = (SAFE_V1_CANONICAL_LEN + 2) as u16;
        safe[..2].copy_from_slice(&safe_len.to_be_bytes());
        let f = parse_safe_tx_frame(&safe).expect("minimal SafeTx frame accepts");
        assert_eq!(f.names_count, 0);
        let cow = [0u8; pqsigner_proto::MIN_OFFCHAIN_COW_ORDER_LEN];
        let f = parse_cow_order_frame(&cow).expect("minimal CoW frame accepts");
        assert!(f.sell.is_empty() && f.buy.is_empty());
        let mut permit2 = [0u8; pqsigner_proto::MIN_OFFCHAIN_PERMIT2_LEN];
        permit2[PERMIT2_ALLOWANCE_HEAD_LEN - 1] = 1;
        let f = parse_permit2_frame(&permit2).expect("minimal Permit2 frame accepts");
        assert!(f.count == 1 && f.erc20[0].is_empty() && f.name.is_empty());
    }
}
