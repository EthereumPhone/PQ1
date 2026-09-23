//! WYSIWYS end-to-end glue harness — render ↔ signed-buffer identity.
//!
//! # What this binds (and what it does not)
//!
//! The per-decoder and per-renderer layers are separately proven (Kani
//! byte-bindings, render-faithfulness host tests, golden grids), but until
//! 2026-07-06 the DISPATCHER GLUE had no harness: `pick_sign_pages` (the
//! priority ladder + the dispatcher-level value/gas splice gates) had never
//! executed on a host, and nothing bound "the pages the user confirms" to
//! "the bytes `cmd_sign_userop` hashes into the SPHINCS digest".
//!
//! This harness drives, for a corpus of frozen-wire sign requests
//! (`docs`/CLAUDE.md "Unified sign input"), BOTH consumers of the handler's
//! single parse:
//!
//!   * the display path — the REAL `pick_sign_pages` body (mounted at
//!     `super::dispatch`), followed by the handler's real splice gates in
//!     handler order (paymaster, signer identity, target identity, nonce lane,
//!     the handler-owned exact gas lane, ERC-8213 fingerprint);
//!   * the signature path — the REAL `reconstruct_execute_calldata` +
//!     `compute_sphincs_digest_v06` (pqsigner-aa, the exact functions the
//!     handler calls at §10/§14).
//!
//! and then checks them against each other through an INDEPENDENT oracle:
//!
//!   * the signed `executeWithOffchainCount(...)` calldata is re-decoded by
//!     a test-local strict ABI decoder (selector recomputed from the
//!     Solidity signature via keccak — not imported from production);
//!   * every load-bearing value shown on the returned pages (recipient
//!     EIP-55 rows, ETH amount, token amount, selector hex, the ERC-8213
//!     fingerprint rows) is asserted equal to the value decoded FROM THE
//!     SIGNED BYTES — not from the wire input — so any glue-level
//!     divergence (render buffer A, hash buffer B) fails the suite;
//!   * the SPHINCS digest is recomputed by a test-local sha2 chain over the
//!     documented preimage, from the mirror-parsed wire fields and a
//!     test-local re-encoding of the exec calldata.
//!
//! The handler's inline glue (§6 `tx_for_display` construction, §8 render
//! order, §10/§14 digest inputs) cannot itself be linked on host (it lives
//! inside the `unsafe` CMSE handler), so this file REPLICATES it and pins
//! the replication against the handler source with whitespace-normalised
//! `include_str!` fragments — if the handler glue drifts, the pins fire.
//!
//! ## Honest scope — what this does NOT bind
//!
//!   * The handler's §4 wire parse itself (offsets → locals). Structurally
//!     the handler parses ONCE and both paths consume the same locals, so a
//!     parse bug shifts display and digest together; the wire offsets are
//!     additionally pinned by `nsc_sign_userop_pure_tests`.
//!   * Deploy / rotation extras (initCode, Type-1 `addOwnerBytes` digest)
//!     and the batch handler's per-tx nonce/digest loop.
//!   * `display_gas_limit` remains a saturated aggregate for the friendly fee
//!     envelope, but the separately handler-owned page binds all three exact
//!     signed gas words. The ordinary nonce row shows `nonce[24..32]` (the
//!     64-bit sequence), while the mandatory conditional nonce-lane gate
//!     renders the high 192-bit key in full whenever it is non-zero.
//!   * CoW v3 / Safe v1 (approveHash) / ERC-7730 ladder rungs (need heavier
//!     fixtures; their verify+bind layers carry their own host suites).
//!   * pages → pixels (`confirm_checked`, LCD) — te-2 golden-grid + the
//!     firmware `ui/golden.rs` gate own that layer.

#![cfg(test)]

use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use super::dispatch::{legacy_fee_pages_required, pick_sign_pages, DispatchPageProofs};
use super::erc8213;
use super::nonce_lane::{enforce_nonce_lane_page, nonce_lane_page_proof, NONCE_LANE_CFI_EXPECTED};
use super::userop_gas_lane::{
    enforce_userop_gas_page, userop_gas_final_set_proof, userop_gas_page_proof,
};
use super::value_page::{
    enforce_from_page, enforce_paymaster_page, enforce_target_page, from_page_proof,
    paymaster_final_set_proof, paymaster_page_proof, target_page_proof,
    PAYMASTER_PAGE_CFI_EXPECTED, SIGNER_PAGE_CFI_EXPECTED, TARGET_PAGE_CFI_EXPECTED,
};
use super::Pages;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, UserOpDisplayFields, U256};
use crate::ui::DISPLAY_COLS;
use sphincs_tz_shared::{EXEC_TRANSACTION_SELECTOR, SIGN_USEROP_HEADER_LEN};

// ─────────────────────────────────────────────────────────────────────
// Wire corpus: the frozen "Unified sign input" layout
// ─────────────────────────────────────────────────────────────────────

/// A sign request in the frozen wire layout (header fields only — the
/// trailers are out of scope for the ladder rungs this corpus drives;
/// absent trailers are legal).
#[derive(Clone)]
struct WireSignRequest {
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    entry_point: [u8; 20],
    nonce: [u8; 32],
    call_gas_limit: [u8; 32],
    verification_gas_limit: [u8; 32],
    pre_verification_gas: [u8; 32],
    max_fee_per_gas: [u8; 32],
    max_priority_fee_per_gas: [u8; 32],
    paymaster_and_data_hash: [u8; 32],
    to: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

fn be_u256_from_u64(n: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    out
}

impl WireSignRequest {
    /// A plausible normal (non-deploy, non-rotation) T2 sign request.
    fn base() -> Self {
        WireSignRequest {
            chain_id: 8453, // Base
            account_index: 0,
            slot_index: 0,
            sender: [0x51; 20],
            entry_point: ENTRY_POINT_V06,
            nonce: be_u256_from_u64(7),
            call_gas_limit: be_u256_from_u64(200_000),
            verification_gas_limit: be_u256_from_u64(3_000_000),
            pre_verification_gas: be_u256_from_u64(60_000),
            max_fee_per_gas: be_u256_from_u64(30_000_000_000), // 30 gwei
            max_priority_fee_per_gas: be_u256_from_u64(1_500_000_000),
            paymaster_and_data_hash: SHA256_EMPTY,
            to: [0x12; 20],
            value: [0u8; 32],
            data: Vec::new(),
        }
    }

    /// Encode per the frozen "Unified sign input" offset table. Written
    /// from the spec, NOT from the handler source.
    fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; SIGN_USEROP_HEADER_LEN + self.data.len()];
        buf[0..8].copy_from_slice(&self.chain_id.to_be_bytes());
        // flags: no INCLUDE_INIT_CODE / REGISTER_SLOT; account index in bits
        // 29..22, slot index in bits 21..0.
        let flags: u32 = ((self.account_index & 0xff) << 22) | (self.slot_index & 0x003F_FFFF);
        buf[8..12].copy_from_slice(&flags.to_be_bytes());
        buf[12..32].copy_from_slice(&self.sender);
        buf[32..52].copy_from_slice(&self.entry_point);
        buf[52..84].copy_from_slice(&self.nonce);
        buf[84..116].copy_from_slice(&self.call_gas_limit);
        buf[116..148].copy_from_slice(&self.verification_gas_limit);
        buf[148..180].copy_from_slice(&self.pre_verification_gas);
        buf[180..212].copy_from_slice(&self.max_fee_per_gas);
        buf[212..244].copy_from_slice(&self.max_priority_fee_per_gas);
        buf[244..276].copy_from_slice(&self.paymaster_and_data_hash);
        buf[276..296].copy_from_slice(&self.to);
        buf[296..328].copy_from_slice(&self.value);
        buf[328..330].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf[330..].copy_from_slice(&self.data);
        buf
    }
}

/// Independent mirror parse of the frozen wire layout. Deliberately a
/// SECOND implementation of the offset table (assertions between this
/// and the builder catch harness self-inconsistency; the handler's own
/// offsets are pinned by `nsc_sign_userop_pure_tests`).
struct MirrorParsed {
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    entry_point: [u8; 20],
    nonce: [u8; 32],
    gas: [[u8; 32]; 5], // call, verification, pre_verification, max_fee, max_prio
    paymaster_and_data_hash: [u8; 32],
    to: [u8; 20],
    value: [u8; 32],
    inner: Vec<u8>,
}

fn mirror_parse(buf: &[u8]) -> MirrorParsed {
    assert!(buf.len() >= SIGN_USEROP_HEADER_LEN, "short wire buffer");
    let take = |lo: usize, hi: usize| -> Vec<u8> { buf[lo..hi].to_vec() };
    let arr32 = |lo: usize| -> [u8; 32] { buf[lo..lo + 32].try_into().unwrap() };
    let arr20 = |lo: usize| -> [u8; 20] { buf[lo..lo + 20].try_into().unwrap() };
    let flags = u32::from_be_bytes(buf[8..12].try_into().unwrap());
    let data_len = u16::from_be_bytes(buf[328..330].try_into().unwrap()) as usize;
    assert_eq!(
        buf.len(),
        SIGN_USEROP_HEADER_LEN + data_len,
        "corpus buffers carry no trailers"
    );
    MirrorParsed {
        chain_id: u64::from_be_bytes(buf[0..8].try_into().unwrap()),
        account_index: (flags >> 22) & 0xff,
        slot_index: flags & 0x003F_FFFF,
        sender: arr20(12),
        entry_point: arr20(32),
        nonce: arr32(52),
        gas: [arr32(84), arr32(116), arr32(148), arr32(180), arr32(212)],
        paymaster_and_data_hash: arr32(244),
        to: arr20(276),
        value: arr32(296),
        inner: take(SIGN_USEROP_HEADER_LEN, SIGN_USEROP_HEADER_LEN + data_len),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Handler-glue replication (§6 display shim, §8 render order,
// §10/§14 digest inputs) — pinned against the handler source below.
// ─────────────────────────────────────────────────────────────────────

/// Fixed per-slot off-chain count for the corpus. In the handler this
/// comes from flash page 123; it is baked into the signed calldata but
/// (by design) never displayed — a documented residual of this harness.
const NEW_OFFCHAIN_COUNT: u64 = 41;

/// Mirror of the handler's private `u128_saturating_from_u256`.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    u128::from_be_bytes(bytes[16..32].try_into().unwrap())
}

/// Replicates the handler's §6 `tx_for_display` construction.
fn tx_for_display(p: &MirrorParsed) -> Eip1559Tx {
    let display_nonce = u64::from_be_bytes(p.nonce[24..32].try_into().unwrap());
    let call_gas_u128 = u128_saturating_from_u256(&p.gas[0]);
    let ver_gas_u128 = u128_saturating_from_u256(&p.gas[1]);
    let pre_ver_u128 = u128_saturating_from_u256(&p.gas[2]);
    let display_gas_limit: u64 = ver_gas_u128
        .saturating_add(call_gas_u128)
        .saturating_add(pre_ver_u128)
        .min(u64::MAX as u128) as u64;
    Eip1559Tx {
        chain_id: p.chain_id,
        nonce: display_nonce,
        max_priority_fee_per_gas: U256(p.gas[4]),
        max_fee_per_gas: U256(p.gas[3]),
        gas_limit: display_gas_limit,
        to: Some(p.to),
        value: U256(p.value),
        data_len: p.inner.len(),
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: Some(UserOpDisplayFields {
            nonce: U256(p.nonce),
            call_gas_limit: U256(p.gas[0]),
            verification_gas_limit: U256(p.gas[1]),
            pre_verification_gas: U256(p.gas[2]),
        }),
    }
}

/// Optional verified contexts for the ladder rungs this corpus drives.
#[derive(Default)]
struct Contexts<'a> {
    erc20: Option<Erc20Metadata<'a>>,
    safe_exec_calldata: bool,
}

struct GlueOutcome {
    pages: Pages,
    t2_exec: Vec<u8>,
    digest: [u8; 32],
    dispatch_pages_len: usize,
    paymaster_page_index: Option<usize>,
    signer_page_index: usize,
    target_page_index: usize,
    nonce_lane_page_index: Option<usize>,
    gas_page_index: usize,
}

/// Drive both consumers of the (mirror-parsed) request exactly the way
/// `cmd_sign_userop::run` does: REAL `pick_sign_pages` → REAL
/// `enforce_paymaster_page` → REAL handler gas-page splice/proof → REAL
/// ERC-8213 fingerprint append for the display side; REAL
/// `reconstruct_execute_calldata` → REAL
/// `compute_sphincs_digest_v06` for the signature side.
fn drive_glue(p: &MirrorParsed, ctx: &Contexts<'_>) -> GlueOutcome {
    assert_eq!(
        p.entry_point, ENTRY_POINT_V06,
        "valid corpus must pass the handler's frozen EntryPoint gate"
    );
    let tx = tx_for_display(p);
    let resolver = NameResolver::new();

    // Safe execTransaction context — through the REAL verifier the
    // handler calls (§7c-bis), not a hand-built struct.
    let safe_exec = if ctx.safe_exec_calldata {
        let v =
            crate::tx::eip712::safe::exec_decode::verify_and_bind_exec(&p.inner, p.chain_id, &p.to);
        assert!(v.is_some(), "corpus execTransaction must verify");
        v
    } else {
        None
    };

    // §8 — render + append-only mandatory gates, in handler order.
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();
    let legacy_fees_required = legacy_fee_pages_required(false, false, safe_exec.is_some());
    let mut pages = pick_sign_pages(
        &tx,
        &p.inner,
        &p.sender,
        None,
        None,
        safe_exec.as_ref(),
        None,
        ctx.erc20.as_ref(),
        None,
        &resolver,
        &mut dispatch_proofs,
    )
    .expect("corpus renders must not refuse");
    let dispatch_pages_len = pages.len;
    let paymaster_page_index =
        (p.paymaster_and_data_hash != SHA256_EMPTY).then_some(dispatch_pages_len);
    let paymaster_pages_before = pages.len;
    let mut paymaster_cfi = crate::fi::CfiCounter::new();
    enforce_paymaster_page(&mut pages, &p.paymaster_and_data_hash, &mut paymaster_cfi)
        .expect("paymaster page must fit");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        paymaster_cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "paymaster append/skip must complete caller-owned CFI"
    );
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        paymaster_page_proof(&pages, paymaster_pages_before, &p.paymaster_and_data_hash,),
        crate::fi::OK_SENTINEL,
        "paymaster transition must match the signed presence hash"
    );
    let signer_pages_before = pages.len;
    let signer_page_index = signer_pages_before;
    let mut signer_cfi = crate::fi::CfiCounter::new();
    enforce_from_page(&mut pages, p.account_index, &p.sender, &mut signer_cfi)
        .expect("mandatory signer page must fit");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        signer_cfi.check_into_sentinel(SIGNER_PAGE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "mandatory signer append must complete caller-owned CFI"
    );
    assert_eq!(
        from_page_proof(&pages, signer_pages_before, p.account_index, &p.sender),
        crate::fi::OK_SENTINEL,
        "mandatory signer page must match parsed account/address exactly once"
    );
    let target_pages_before = pages.len;
    let target_page_index = target_pages_before;
    let mut target_cfi = crate::fi::CfiCounter::new();
    enforce_target_page(&mut pages, &p.to, &mut target_cfi)
        .expect("mandatory target page must fit");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        target_cfi.check_into_sentinel(TARGET_PAGE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "mandatory target append must complete caller-owned CFI"
    );
    assert_eq!(
        target_page_proof(&pages, target_pages_before, &p.to),
        crate::fi::OK_SENTINEL,
        "mandatory target page must match parsed target"
    );
    let nonce_lane_pages_before = pages.len;
    let nonce_lane_page_index = p.nonce[..24]
        .iter()
        .any(|&byte| byte != 0)
        .then_some(nonce_lane_pages_before);
    let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
    enforce_nonce_lane_page(&mut pages, &p.nonce, &mut nonce_lane_cfi)
        .expect("nonce lane page must fit");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        nonce_lane_cfi.check_into_sentinel(NONCE_LANE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "nonce append/skip must complete caller-owned CFI"
    );
    assert_eq!(
        nonce_lane_page_proof(&pages, nonce_lane_pages_before, &p.nonce),
        crate::fi::OK_SENTINEL
    );
    let gas_lane_pages_before = pages.len;
    let mut gas_lane_cfi = crate::fi::CfiCounter::new();
    enforce_userop_gas_page(
        &mut pages,
        &p.gas[0],
        &p.gas[1],
        &p.gas[2],
        &mut gas_lane_cfi,
    )
    .expect("handler-owned gas page must fit exactly once");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        gas_lane_cfi.check_into_sentinel(super::userop_gas_lane::USEROP_GAS_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "handler gas append must complete caller-owned CFI"
    );
    assert_eq!(
        userop_gas_page_proof(
            &pages,
            gas_lane_pages_before,
            &p.gas[0],
            &p.gas[1],
            &p.gas[2],
        ),
        crate::fi::OK_SENTINEL,
        "handler gas completion proof must establish global uniqueness"
    );
    let gas_page_index = gas_lane_pages_before;
    let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(&p.inner);
    let fingerprint_pages_before = pages.len;
    let fingerprint_kind = erc8213::Kind::CalldataDigest(calldata_fingerprint);
    let mut fingerprint_cfi = crate::fi::CfiCounter::new();
    erc8213::append_fingerprint_page(&mut pages, fingerprint_kind, &mut fingerprint_cfi)
        .expect("fingerprint pages must fit");
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        fingerprint_cfi.check_into_sentinel(erc8213::FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "handler fingerprint append must complete caller-owned CFI"
    );
    assert_eq!(
        erc8213::fingerprint_page_proof(&pages, fingerprint_pages_before, fingerprint_kind),
        crate::fi::OK_SENTINEL,
        "handler fingerprint completion proof must bind both exact pages"
    );
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        gas_lane_cfi.check_into_sentinel(super::userop_gas_lane::USEROP_GAS_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "final handler boundary must retain caller-owned gas CFI"
    );
    assert_eq!(
        userop_gas_final_set_proof(&pages, gas_page_index, &p.gas[0], &p.gas[1], &p.gas[2],),
        crate::fi::OK_SENTINEL,
        "complete final page set must retain exactly one canonical gas page"
    );
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        paymaster_cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "final handler boundary must retain caller-owned paymaster CFI"
    );
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        paymaster_final_set_proof(&pages, paymaster_pages_before, &p.paymaster_and_data_hash,),
        crate::fi::OK_SENTINEL,
        "complete final page set must retain the exact paymaster warning state"
    );
    crate::fi::scrub_sentinel_register();
    let mut dispatch_final_verdict_slot = crate::fi::FAIL_SENTINEL;
    dispatch_proofs.final_set_proof(
        &pages,
        &tx,
        legacy_fees_required,
        &mut dispatch_final_verdict_slot,
    );
    assert_eq!(
        dispatch_final_verdict_slot,
        crate::fi::OK_SENTINEL,
        "final handler boundary must retain native/legacy-fee receipts and exact pages"
    );
    crate::fi::scrub_sentinel_register();
    assert_eq!(
        erc8213::fingerprint_final_set_proof(&pages, fingerprint_pages_before, fingerprint_kind,),
        crate::fi::OK_SENTINEL,
        "final handler boundary must retain the exact fingerprint pair"
    );

    // §10 + §14 — the signed bytes and the SPHINCS digest.
    let t2_owner_index = u64::from(p.slot_index) + 1;
    let t2_exec = reconstruct_execute_calldata(t2_owner_index, NEW_OFFCHAIN_COUNT, &tx, &p.inner)
        .expect("corpus exec calldata must reconstruct");
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_params = AaUserOpParamsV06Sha256 {
        sender: p.sender,
        entry_point: ENTRY_POINT_V06,
        chain_id: p.chain_id,
        nonce: U256(p.nonce),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: U256(p.gas[0]),
        verification_gas_limit: U256(p.gas[1]),
        pre_verification_gas: U256(p.gas[2]),
        max_fee_per_gas: U256(p.gas[3]),
        max_priority_fee_per_gas: U256(p.gas[4]),
        paymaster_and_data_digest: p.paymaster_and_data_hash,
    };
    let digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);

    GlueOutcome {
        pages,
        t2_exec: t2_exec.as_slice().to_vec(),
        digest,
        dispatch_pages_len,
        paymaster_page_index,
        signer_page_index,
        target_page_index,
        nonce_lane_page_index,
        gas_page_index,
    }
}

// ─────────────────────────────────────────────────────────────────────
// Independent oracle — keccak/sha2 recomputations, test-local ABI
// decode of the SIGNED calldata, test-local EIP-55.
// ─────────────────────────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

fn selector_of(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

struct OracleExec {
    owner_index: u64,
    new_offchain_count: u64,
    target: [u8; 20],
    value: [u8; 32],
    data: Vec<u8>,
}

/// Strict, test-local decode of `executeWithOffchainCount(uint256,
/// uint256,address,uint256,bytes)` calldata — the bytes whose SHA-256
/// is folded into the signed SPHINCS digest.
fn oracle_decode_execute(cd: &[u8]) -> OracleExec {
    let sel = selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)");
    assert!(cd.len() >= 4 + 6 * 32, "exec calldata too short");
    assert_eq!(&cd[..4], &sel, "signed calldata selector mismatch");
    let word = |i: usize| -> [u8; 32] { cd[4 + i * 32..4 + (i + 1) * 32].try_into().unwrap() };
    let word_u64 = |w: [u8; 32]| -> u64 {
        assert!(w[..24].iter().all(|&b| b == 0), "u64 word overflow");
        u64::from_be_bytes(w[24..32].try_into().unwrap())
    };
    let owner_index = word_u64(word(0));
    let new_offchain_count = word_u64(word(1));
    let target_word = word(2);
    assert!(
        target_word[..12].iter().all(|&b| b == 0),
        "non-canonical target address padding"
    );
    let target: [u8; 20] = target_word[12..32].try_into().unwrap();
    let value = word(3);
    let offset = word_u64(word(4));
    assert_eq!(offset, 0xa0, "bytes head offset must be 0xa0");
    let data_len = word_u64(word(5)) as usize;
    let data_start = 4 + 6 * 32;
    let padded = (data_len + 31) & !31usize;
    assert_eq!(cd.len(), data_start + padded, "exact ABI framing");
    let data = cd[data_start..data_start + data_len].to_vec();
    assert!(
        cd[data_start + data_len..].iter().all(|&b| b == 0),
        "tail padding must be zero"
    );
    OracleExec {
        owner_index,
        new_offchain_count,
        target,
        value,
        data,
    }
}

/// Test-local re-encoding of the exec calldata from oracle values —
/// asserted byte-equal against the production reconstruction so the
/// digest recomputation below covers the whole preimage.
fn oracle_encode_execute(o: &OracleExec) -> Vec<u8> {
    let sel = selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)");
    let padded = (o.data.len() + 31) & !31usize;
    let mut cd = vec![0u8; 4 + 6 * 32 + padded];
    cd[..4].copy_from_slice(&sel);
    cd[4 + 24..4 + 32].copy_from_slice(&o.owner_index.to_be_bytes());
    cd[36 + 24..36 + 32].copy_from_slice(&o.new_offchain_count.to_be_bytes());
    cd[68 + 12..68 + 32].copy_from_slice(&o.target);
    cd[100..132].copy_from_slice(&o.value);
    cd[132 + 31] = 0xa0;
    cd[164 + 24..164 + 32].copy_from_slice(&(o.data.len() as u64).to_be_bytes());
    cd[196..196 + o.data.len()].copy_from_slice(&o.data);
    cd
}

/// Test-local SPHINCS digest chain per the documented v0.6 preimage.
#[allow(clippy::too_many_arguments)]
fn oracle_sphincs_digest(p: &MirrorParsed, exec_calldata: &[u8]) -> [u8; 32] {
    let empty_sha: [u8; 32] = Sha256::digest([]).into();
    let call_data_digest: [u8; 32] = Sha256::digest(exec_calldata).into();
    let mut chain_word = [0u8; 32];
    chain_word[24..32].copy_from_slice(&p.chain_id.to_be_bytes());
    let mut h = Sha256::new();
    h.update(p.sender);
    h.update(p.nonce);
    h.update(empty_sha); // no initCode in the corpus
    h.update(call_data_digest);
    h.update(p.gas[0]);
    h.update(p.gas[1]);
    h.update(p.gas[2]);
    h.update(p.gas[3]);
    h.update(p.gas[4]);
    h.update(p.paymaster_and_data_hash);
    h.update(ENTRY_POINT_V06);
    h.update(chain_word);
    h.finalize().into()
}

/// ERC-8213 calldata digest recomputed test-locally:
/// `keccak256(uint256(len) || data)`.
fn oracle_erc8213_digest(data: &[u8]) -> [u8; 32] {
    let mut pre = vec![0u8; 32 + data.len()];
    pre[24..32].copy_from_slice(&(data.len() as u64).to_be_bytes());
    pre[32..].copy_from_slice(data);
    keccak256(&pre)
}

/// Test-local EIP-55 checksummed hex of an address (mixed case) — the
/// format `write_addr_full` paints when no name-DB entry matches.
fn oracle_eip55(addr: &[u8; 20]) -> String {
    let lower: String = addr.iter().map(|b| format!("{b:02x}")).collect();
    let h = keccak256(lower.as_bytes());
    lower
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let nibble = (h[i / 2] >> (4 * (1 - (i % 2)))) & 0x0F;
            if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

// ─── Page-text helpers ───────────────────────────────────────────────

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    String::from_utf8(row[..end].to_vec()).expect("rows are ASCII by construction")
}

/// All rows of all used pages, flattened in display order.
fn all_rows(pages: &Pages) -> Vec<String> {
    pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter().map(row_str))
        .collect()
}

fn rows_contain(rows: &[String], needle: &str) -> bool {
    rows.iter().any(|r| r.contains(needle))
}

fn oracle_u256_decimal(mut value: [u8; 32]) -> String {
    if value.iter().all(|&byte| byte == 0) {
        return "0".to_string();
    }
    let mut reversed = Vec::new();
    while value.iter().any(|&byte| byte != 0) {
        let mut remainder = 0u16;
        for byte in &mut value {
            let limb = remainder * 256 + u16::from(*byte);
            *byte = (limb / 10) as u8;
            remainder = limb % 10;
        }
        reversed.push(b'0' + remainder as u8);
    }
    reversed.reverse();
    String::from_utf8(reversed).expect("decimal oracle emits ASCII")
}

fn oracle_gas_row(prefix: &str, value: &str) -> [u8; DISPLAY_COLS] {
    let text = format!("{prefix}{value}");
    assert!(text.len() <= DISPLAY_COLS, "gas row exceeds device width");
    let mut row = [b' '; DISPLAY_COLS];
    row[..text.len()].copy_from_slice(text.as_bytes());
    row
}

fn oracle_gas_page(p: &MirrorParsed) -> [[u8; DISPLAY_COLS]; 4] {
    let total = u128_saturating_from_u256(&p.gas[0])
        .saturating_add(u128_saturating_from_u256(&p.gas[1]))
        .saturating_add(u128_saturating_from_u256(&p.gas[2]))
        .min(u128::from(u64::MAX));
    [
        oracle_gas_row("Call:", &oracle_u256_decimal(p.gas[0])),
        oracle_gas_row("Verify:", &oracle_u256_decimal(p.gas[1])),
        oracle_gas_row("PreVer:", &oracle_u256_decimal(p.gas[2])),
        oracle_gas_row("Total:", &total.to_string()),
    ]
}

fn oracle_gas_marker_count(page: &[[u8; DISPLAY_COLS]; 4]) -> usize {
    usize::from(page[0].starts_with(b"Call:"))
        + usize::from(page[1].starts_with(b"Verify:"))
        + usize::from(page[2].starts_with(b"PreVer:"))
        + usize::from(page[3].starts_with(b"Total:"))
}

fn assert_handler_gas_page(p: &MirrorParsed, out: &GlueOutcome) {
    let expected = oracle_gas_page(p);
    let exact_count = out
        .pages
        .as_slice()
        .iter()
        .filter(|page| **page == expected)
        .count();
    let near_count = out
        .pages
        .as_slice()
        .iter()
        .filter(|page| **page != expected && oracle_gas_marker_count(page) >= 2)
        .count();
    assert_eq!(
        exact_count, 1,
        "final handler page set must contain one exact gas page"
    );
    assert_eq!(
        near_count, 0,
        "final handler page set contains a conflicting gas shape"
    );
    assert_eq!(
        out.pages.as_slice()[out.gas_page_index],
        expected,
        "handler gas page moved from its append-only boundary"
    );
    assert_eq!(
        out.gas_page_index + 3,
        out.pages.len,
        "the gas page must be followed only by the complete two-page ERC-8213 fingerprint"
    );
}

/// The three rows `write_addr_full` paints for `addr` (EIP-55, split
/// 0x+14 / 16 / 10) — recomputed test-locally.
fn oracle_addr_rows(addr: &[u8; 20]) -> [String; 3] {
    let hex = oracle_eip55(addr);
    [
        format!("0x{}", &hex[0..14]),
        hex[14..30].to_string(),
        hex[30..40].to_string(),
    ]
}

/// Assert the full 40-hex EIP-55 address is painted somewhere on the
/// pages as three consecutive rows within one page (rows 1..3, after a
/// label row).
fn assert_addr_shown(pages: &Pages, addr: &[u8; 20], what: &str) {
    let want = oracle_addr_rows(addr);
    let found = pages.as_slice().iter().any(|page| {
        (0..2).any(|start| {
            row_str(&page[start + 1]) == want[0]
                && row_str(&page[start + 2]) == want[1]
                && page.len() > start + 3
                && row_str(&page[start + 3]) == want[2]
        }) || (row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2])
    });
    assert!(
        found,
        "{what}: address rows {want:?} not found on any page:\n{:#?}",
        all_rows(pages)
    );
}

fn assert_signer_page_shown(pages: &Pages, account_index: u32, sender: &[u8; 20]) {
    let label = format!("Signer acct #{account_index}");
    let want = oracle_addr_rows(sender);
    let found = pages.as_slice().iter().any(|page| {
        row_str(&page[0]) == label
            && row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2]
    });
    assert!(
        found,
        "signer page {label} + {want:?} not found:\n{:#?}",
        all_rows(pages)
    );
}

fn assert_target_page_shown(pages: &Pages, target: &[u8; 20]) {
    let want = oracle_addr_rows(target);
    let found = pages.as_slice().iter().any(|page| {
        row_str(&page[0]) == "Target contract:"
            && row_str(&page[1]) == want[0]
            && row_str(&page[2]) == want[1]
            && row_str(&page[3]) == want[2]
    });
    assert!(
        found,
        "mandatory target page {want:?} not found:\n{:#?}",
        all_rows(pages)
    );
}

/// Assert the final two pages are the ERC-8213 banner + the exact hash
/// rows of `digest` (lowercase hex, 8 bytes per row).
fn assert_fingerprint_pages(pages: &Pages, digest: &[u8; 32]) {
    let slice = pages.as_slice();
    assert!(slice.len() >= 2, "need banner + hash page");
    let banner = &slice[slice.len() - 2];
    assert_eq!(row_str(&banner[0]), "8213 Fingerprint");
    assert_eq!(row_str(&banner[1]), "CalldataDigest");
    let hash_page = &slice[slice.len() - 1];
    for (i, row) in hash_page.iter().enumerate() {
        let want: String = digest[i * 8..(i + 1) * 8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            row_str(row),
            want,
            "fingerprint hash row {i} diverges from the SIGNED calldata digest"
        );
    }
}

/// Full differential check shared by every corpus flow: decode the
/// SIGNED bytes with the independent oracle and bind wire ↔ signed ↔
/// shown ↔ digest.
fn assert_core_bindings(p: &MirrorParsed, out: &GlueOutcome) -> OracleExec {
    // (1) The signed calldata decodes strictly and its embedded fields
    //     equal the wire fields the display shim was built from.
    let oracle = oracle_decode_execute(&out.t2_exec);
    assert_eq!(oracle.owner_index, u64::from(p.slot_index) + 1);
    assert_eq!(oracle.new_offchain_count, NEW_OFFCHAIN_COUNT);
    assert_eq!(oracle.target, p.to, "signed target != wire to");
    assert_eq!(oracle.value, p.value, "signed value != wire value");
    assert_eq!(oracle.data, p.inner, "signed data != wire inner data");

    // (2) Re-encoding the oracle view reproduces the production bytes
    //     exactly, so the digest recomputation covers the whole preimage.
    assert_eq!(
        oracle_encode_execute(&oracle),
        out.t2_exec,
        "independent exec re-encode != production reconstruct_execute_calldata"
    );

    // (3) Independent SPHINCS-digest recomputation from wire fields.
    assert_eq!(
        oracle_sphincs_digest(p, &out.t2_exec),
        out.digest,
        "independent digest chain != production compute_sphincs_digest_v06"
    );

    // (4) The ERC-8213 fingerprint pages show the digest OF THE SIGNED
    //     BYTES (recomputed test-locally from the oracle-decoded data).
    assert_fingerprint_pages(&out.pages, &oracle_erc8213_digest(&oracle.data));

    // (5) The signed target is painted in full EIP-55 on some page.
    assert_addr_shown(&out.pages, &oracle.target, "signed exec target");

    // (6) The account selector and mnemonic-derived/bound sender are painted
    //     together on their mandatory full-address identity page.
    assert_signer_page_shown(&out.pages, p.account_index, &p.sender);
    assert_target_page_shown(&out.pages, &oracle.target);

    // (7) The complete post-handler page set contains exactly one canonical
    //     gas page derived independently from the three signed words. This is
    //     intentionally checked after the later ERC-8213 append, at the final
    //     confirmation boundary represented by this harness.
    assert_handler_gas_page(p, out);

    oracle
}

// ─────────────────────────────────────────────────────────────────────
// Corpus flows
// ─────────────────────────────────────────────────────────────────────

#[test]
fn wysiwys_value_transfer_binds_pages_to_signed_bytes() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    // The signed native value renders with the fixed-width ETH format on
    // the renderer's Value page AND the dispatcher's loud splice page.
    assert!(oracle.value == be_u256_from_u64(1_000_000_000_000_000_000));
    assert!(rows_contain(&rows, "Send ETH?"), "value-transfer banner");
    assert!(
        rows_contain(&rows, "1.000000 ETH"),
        "signed 1 ETH amount shown"
    );
    assert!(
        rows_contain(&rows, "! NATIVE ETH"),
        "dispatcher value splice"
    );
    // No paymaster in this flow → no paymaster page.
    assert!(
        !rows_contain(&rows, "PAYMASTER"),
        "no phantom paymaster page"
    );
}

#[test]
fn wysiwys_erc20_unknown_transfer_binds_recipient_from_signed_bytes() {
    let recipient: [u8; 20] = [0xB7; 20];
    let mut req = WireSignRequest::base();
    req.to = [0xAA; 20]; // token contract
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&recipient);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    // Independent decode of the transfer INSIDE the signed calldata.
    assert_eq!(&oracle.data[..4], &selector_of("transfer(address,uint256)"));
    let signed_recipient: [u8; 20] = oracle.data[16..36].try_into().unwrap();
    assert_eq!(signed_recipient, recipient);

    let rows = all_rows(&out.pages);
    assert!(
        rows_contain(&rows, "! Unknown token"),
        "unknown-token banner"
    );
    assert!(rows_contain(&rows, "Recipient:"), "recipient label");
    assert_addr_shown(&out.pages, &signed_recipient, "signed ERC-20 recipient");
}

#[test]
fn wysiwys_erc20_known_metadata_binds_amount_and_recipient() {
    let token = [0xAA; 20];
    let recipient: [u8; 20] = [0xB7; 20];
    let mut req = WireSignRequest::base();
    req.to = token;
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&recipient);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        erc20: Some(Erc20Metadata {
            chain_id: 8453,
            contract: token,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }),
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    let oracle = assert_core_bindings(&p, &out);

    // 500000 raw at 6 decimals = 0.5 — fixed 6-frac policy.
    let signed_amount = u64::from_be_bytes(oracle.data[60..68].try_into().unwrap());
    assert_eq!(signed_amount, 500_000);
    let rows = all_rows(&out.pages);
    assert!(
        rows_contain(&rows, "0.500000 USDC"),
        "signed token amount shown"
    );
    let signed_recipient: [u8; 20] = oracle.data[16..36].try_into().unwrap();
    assert_addr_shown(&out.pages, &signed_recipient, "signed ERC-20 recipient");
}

#[test]
fn wysiwys_erc20_known_unrenderable_amount_refuses_before_pages_escape() {
    let token = [0xAA; 20];
    let recipient = [0xB7; 20];
    let amount_word = be_u256_from_u64(10_000_000_000_000_001);
    // An 11-byte symbol leaves too little of row 2 for even the wrapped
    // exact form (`10.00000000000000>` / `>0001 ABCDEFGHIJK` = 18 cols).
    let meta = Erc20Metadata {
        chain_id: 8453,
        contract: token,
        decimals: 18,
        name: b"Token",
        symbol: b"ABCDEFGHIJK",
    };
    assert!(
        !super::primitives::token_amount_is_exactly_renderable(&U256(amount_word), &meta),
        "fixture must exceed the exact scaled, labelled base-unit and wrapped widths"
    );

    let mut req = WireSignRequest::base();
    req.to = token;
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&recipient);
    data[4 + 32..4 + 64].copy_from_slice(&amount_word);
    req.data = data;
    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    let resolver = NameResolver::new();
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();

    assert!(
        pick_sign_pages(
            &tx,
            &parsed.inner,
            &parsed.sender,
            None,
            None,
            None,
            None,
            Some(&meta),
            None,
            &resolver,
            &mut dispatch_proofs,
        )
        .is_err(),
        "known-token rounding risk must refuse before a Pages value escapes dispatch"
    );
}

#[test]
fn wysiwys_erc20_known_unlimited_approve_remains_allowed() {
    let token = [0xAA; 20];
    let spender = [0xB7; 20];
    let amount_word = [0xFF; 32];
    let meta = Erc20Metadata {
        chain_id: 8453,
        contract: token,
        decimals: 18,
        name: b"Token",
        symbol: b"TOK",
    };
    assert!(crate::erc20::calldata::is_unlimited_amount(&U256(
        amount_word
    )));
    assert!(
        !super::primitives::token_amount_is_exactly_renderable(&U256(amount_word), &meta),
        "the test must exercise the explicit unlimited-approve semantic path"
    );

    let mut req = WireSignRequest::base();
    req.to = token;
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("approve(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&spender);
    data[4 + 32..4 + 64].copy_from_slice(&amount_word);
    req.data = data;
    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    let resolver = NameResolver::new();
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();

    let pages = pick_sign_pages(
        &tx,
        &parsed.inner,
        &parsed.sender,
        None,
        None,
        None,
        None,
        Some(&meta),
        None,
        &resolver,
        &mut dispatch_proofs,
    )
    .expect("unlimited approve has an explicit, exact semantic rendering");
    let rows = all_rows(&pages);
    assert!(rows_contain(&rows, "unlimited"));
    assert!(!rows_contain(&rows, "!AMOUNT OVERFLOW"));
}

#[test]
fn wysiwys_legacy_fee_unrenderable_budget_refuses_before_pages_escape() {
    let mut req = WireSignRequest::base();
    req.max_fee_per_gas = be_u256_from_u64(1);
    req.max_priority_fee_per_gas = be_u256_from_u64(1);
    req.call_gas_limit = be_u256_from_u64(1_000_000_000_001);
    req.verification_gas_limit = [0u8; 32];
    req.pre_verification_gas = [0u8; 32];

    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    assert!(
        !super::primitives::legacy_fee_rows_are_exactly_renderable(
            &tx.max_fee_per_gas,
            &tx.max_priority_fee_per_gas,
            tx.gas_limit,
            tx.chain_id,
        ),
        "fixture must cross the exact full-row fee-budget boundary"
    );

    let resolver = NameResolver::new();
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &tx,
            &parsed.inner,
            &parsed.sender,
            None,
            None,
            None,
            None,
            None,
            None,
            &resolver,
            &mut dispatch_proofs,
        )
        .is_err(),
        "an inexact legacy fee envelope must refuse before a Pages value escapes dispatch"
    );
}

#[test]
fn wysiwys_legacy_fee_unrenderable_gas_refuses_before_pages_escape() {
    let mut req = WireSignRequest::base();
    req.max_fee_per_gas = [0u8; 32];
    req.max_priority_fee_per_gas = [0u8; 32];
    req.call_gas_limit = be_u256_from_u64(1_000_000_000);
    req.verification_gas_limit = [0u8; 32];
    req.pre_verification_gas = [0u8; 32];

    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    assert!(
        !super::primitives::legacy_fee_rows_are_exactly_renderable(
            &tx.max_fee_per_gas,
            &tx.max_priority_fee_per_gas,
            tx.gas_limit,
            tx.chain_id,
        ),
        "zero fee prices must not hide a lossy signed gas-limit marker"
    );

    let resolver = NameResolver::new();
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &tx,
            &parsed.inner,
            &parsed.sender,
            None,
            None,
            None,
            None,
            None,
            None,
            &resolver,
            &mut dispatch_proofs,
        )
        .is_err(),
        "an inexact signed gas limit must refuse before a Pages value escapes dispatch"
    );
}

#[test]
fn wysiwys_unknown_chain_legacy_fees_render_exact_raw_base_units() {
    let mut req = WireSignRequest::base();
    req.chain_id = 4_242_424_242;
    req.max_fee_per_gas = be_u256_from_u64(30_000_000_001);
    req.max_priority_fee_per_gas = be_u256_from_u64(1_234_567_890);
    req.call_gas_limit = be_u256_from_u64(30_000_000);
    req.verification_gas_limit = [0u8; 32];
    req.pre_verification_gas = [0u8; 32];

    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    let resolver = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let pages = pick_sign_pages(
        &tx,
        &parsed.inner,
        &parsed.sender,
        None,
        None,
        None,
        None,
        None,
        None,
        &resolver,
        &mut proofs,
    )
    .expect("a realistic unknown-chain raw fee envelope must render exactly");

    let fee_index = pages
        .as_slice()
        .iter()
        .position(|page| &page[0][..15] == b"Base: max / tip")
        .expect("legacy raw fee page");
    assert_eq!(&pages.buf[fee_index][1][..11], b"30000000001");
    assert_eq!(&pages.buf[fee_index][2][..10], b"1234567890");
    assert_eq!(&pages.buf[fee_index + 1][0], b"Worst-case/base:");
    let rows = all_rows(&pages);
    assert!(!rows_contain(&rows, "gwei"));
    assert!(!rows_contain(&rows, " ETH"));

    req.max_fee_per_gas = be_u256_from_u64(30_000_000_002);
    let adjacent = mirror_parse(&req.encode());
    let adjacent_tx = tx_for_display(&adjacent);
    let mut adjacent_proofs = DispatchPageProofs::new();
    adjacent_proofs.fail_initialize();
    let adjacent_pages = pick_sign_pages(
        &adjacent_tx,
        &adjacent.inner,
        &adjacent.sender,
        None,
        None,
        None,
        None,
        None,
        None,
        &resolver,
        &mut adjacent_proofs,
    )
    .expect("the adjacent exact raw fee must also render");
    assert_ne!(
        pages.as_slice(),
        adjacent_pages.as_slice(),
        "adjacent signed fee operands must have distinct trusted-display transcripts"
    );
}

#[test]
fn wysiwys_unknown_chain_inexact_legacy_fees_refuse_before_pages_escape() {
    for max_fee in [be_u256_from_u64(10_000_000_000_000_000), [0xff; 32]] {
        let mut req = WireSignRequest::base();
        req.chain_id = 4_242_424_242;
        req.max_fee_per_gas = max_fee;
        req.max_priority_fee_per_gas = be_u256_from_u64(1);
        req.call_gas_limit = be_u256_from_u64(2);
        req.verification_gas_limit = [0u8; 32];
        req.pre_verification_gas = [0u8; 32];

        let parsed = mirror_parse(&req.encode());
        let tx = tx_for_display(&parsed);
        assert!(!super::primitives::legacy_fee_rows_are_exactly_renderable(
            &tx.max_fee_per_gas,
            &tx.max_priority_fee_per_gas,
            tx.gas_limit,
            tx.chain_id,
        ));

        let resolver = NameResolver::new();
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &parsed.inner,
                &parsed.sender,
                None,
                None,
                None,
                None,
                None,
                None,
                &resolver,
                &mut proofs,
            )
            .is_err(),
            "an overwide or overflowing raw envelope must refuse before Pages escapes"
        );
    }
}

/// The dispatcher's direct-path metadata gate: metadata for token T must
/// NOT label a transfer whose signed target is token Y (glue-level
/// mis-attribution — audit 2026-06-28).
#[test]
fn wysiwys_erc20_metadata_contract_mismatch_downgrades_to_unknown() {
    let mut req = WireSignRequest::base();
    req.to = [0x99; 20]; // signed target: token Y
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&[0xB7; 20]);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        // Metadata claims token T ([0xAA;20]) — does NOT match tx.to.
        erc20: Some(Erc20Metadata {
            chain_id: 8453,
            contract: [0xAA; 20],
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }),
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    assert!(
        rows_contain(&rows, "! Unknown token"),
        "mismatched metadata must downgrade to the unknown-token render"
    );
    assert!(
        !rows_contain(&rows, "USDC"),
        "token T's symbol must never label a transfer signed for token Y"
    );
}

#[test]
fn wysiwys_erc20_metadata_chain_mismatch_downgrades_to_unknown() {
    let token = [0xAA; 20];
    let mut req = WireSignRequest::base();
    req.to = token;
    let mut data = vec![0u8; 4 + 64];
    data[..4].copy_from_slice(&selector_of("transfer(address,uint256)"));
    data[4 + 12..4 + 32].copy_from_slice(&[0xB7; 20]);
    data[4 + 32 + 24..4 + 64].copy_from_slice(&500_000u64.to_be_bytes());
    req.data = data;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        erc20: Some(Erc20Metadata {
            chain_id: 1, // Signed request is Base (8453).
            contract: token,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        }),
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    assert!(rows_contain(&rows, "! Unknown token"));
    assert!(
        !rows_contain(&rows, "USDC"),
        "metadata authenticated for a different chain must not label the signed call"
    );
}

#[test]
fn wysiwys_blind_sign_shows_signed_selector_and_fingerprint() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(250_000_000_000_000_000); // 0.25 ETH rides along
    req.data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let oracle = assert_core_bindings(&p, &out);

    let rows = all_rows(&out.pages);
    // Selector row is painted from the same bytes that got signed.
    assert_eq!(&oracle.data[..4], &[0xde, 0xad, 0xbe, 0xef]);
    assert!(
        rows_contain(&rows, "Sel: 0xdeadbeef"),
        "signed selector shown"
    );
    // The native value on a blind-signed call is the C-1 drain class —
    // the dispatcher splice must fire.
    assert!(
        rows_contain(&rows, "! NATIVE ETH"),
        "value splice on blind sign"
    );
    assert!(rows_contain(&rows, "0.250000 ETH"), "signed 0.25 ETH shown");
}

/// Runtime regression for the firmware-pinned known-call membership gate.
///
/// WETH `deposit()` is present in the compiled ERC-7730 catalogue. A hostile
/// companion that strips (or supplies a malformed proof for) that descriptor
/// leaves `erc7730 == None` at dispatch. The request must hard-refuse instead
/// of downgrading the known call to a reassuring value/typed/blind page set.
#[test]
fn wysiwys_known_weth_deposit_without_descriptor_hard_refuses() {
    let mut req = WireSignRequest::base();
    req.chain_id = 1;
    req.to = [
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9,
        0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ];
    req.data = vec![0xd0, 0xe3, 0x0d, 0xb0]; // deposit()
    let parsed = mirror_parse(&req.encode());
    let tx = tx_for_display(&parsed);
    let resolver = NameResolver::new();
    let mut dispatch_proofs = DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();

    let outcome = pick_sign_pages(
        &tx,
        &parsed.inner,
        &parsed.sender,
        None,
        None,
        None,
        None, // companion omitted / failed to verify the descriptor
        None,
        None,
        &resolver,
        &mut dispatch_proofs,
    );
    assert!(
        outcome.is_err(),
        "known WETH deposit without its Merkle proof must never reach blind-sign"
    );
}

#[test]
fn wysiwys_safe_exec_renders_safe_surface_with_spliced_gas_pages() {
    let safe_addr = [0x5A; 20];
    let inner_to: [u8; 20] = [0xC3; 20];
    let inner_value = be_u256_from_u64(50_000_000_000_000_000); // 0.05 ETH
    let exec_calldata = encode_exec_transaction(
        &inner_to,
        &inner_value,
        &[],
        0,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 20],
        &[0u8; 20],
        &[0x41; 65],
    );
    let mut req = WireSignRequest::base();
    req.to = safe_addr;
    req.data = exec_calldata;
    let p = mirror_parse(&req.encode());
    let ctx = Contexts {
        safe_exec_calldata: true,
        ..Default::default()
    };
    let out = drive_glue(&p, &ctx);
    let oracle = assert_core_bindings(&p, &out);

    // Independent re-decode of the SafeTx fields from the SIGNED bytes.
    assert_eq!(&oracle.data[..4], &EXEC_TRANSACTION_SELECTOR);
    let signed_inner_to: [u8; 20] = oracle.data[4 + 12..4 + 32].try_into().unwrap();
    let signed_inner_value: [u8; 32] = oracle.data[4 + 32..4 + 64].try_into().unwrap();
    assert_eq!(signed_inner_to, inner_to);
    assert_eq!(signed_inner_value, inner_value);

    let rows = all_rows(&out.pages);
    // The Safe surface renders (not a generic blind-sign of the exec
    // calldata) and the inner target/value come from the signed bytes.
    assert!(
        rows.iter().any(|r| r.contains("Safe")),
        "Safe surface banner expected:\n{rows:#?}"
    );
    assert_addr_shown(&out.pages, &signed_inner_to, "signed Safe inner target");
    assert!(
        rows_contain(&rows, "0.050000 ETH"),
        "signed inner ETH shown"
    );
    // The dispatcher's gas splice must fire for the Safe surface (the
    // renderer itself is gas-less; hiding fees is the 2026-06-19 fee-bomb).
    assert!(
        rows_contain(&rows, "Fees: max / tip"),
        "gas pages spliced for Safe"
    );
    assert!(
        rows_contain(&rows, "Worst-case:"),
        "worst-case fee page spliced"
    );
}

#[test]
fn wysiwys_paymaster_page_spliced_iff_hash_nonempty() {
    // With a paymaster: loud page present, and the digest commits the hash.
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000); // exact 0.000001 ETH
    req.paymaster_and_data_hash = [0x77; 32];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    assert_core_bindings(&p, &out);
    let rows = all_rows(&out.pages);
    assert!(
        rows.iter().any(|r| r.contains("PAYMASTER")),
        "paymaster page must be spliced when the signed hash is non-empty:\n{rows:#?}"
    );

    // Digest sensitivity: the same request without the paymaster signs a
    // DIFFERENT digest (the hash is inside the signed preimage).
    let mut req2 = req.clone();
    req2.paymaster_and_data_hash = SHA256_EMPTY;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());
    assert_core_bindings(&p2, &out2);
    assert_ne!(
        out.digest, out2.digest,
        "paymaster hash must move the digest"
    );
    let rows2 = all_rows(&out2.pages);
    assert!(
        !rows2.iter().any(|r| r.contains("PAYMASTER")),
        "no phantom paymaster page when the signed hash is SHA256_EMPTY"
    );
}

#[test]
fn append_only_combined_transcripts_have_exact_mandatory_suffix_order() {
    let mut rich = WireSignRequest::base();
    rich.value = be_u256_from_u64(1_000_000_000_000); // exact 0.000001 ETH
    rich.paymaster_and_data_hash = [0x77; 32];
    rich.nonce[0] = 0xAB;
    let rich_parsed = mirror_parse(&rich.encode());
    let rich_out = drive_glue(&rich_parsed, &Contexts::default());

    assert_eq!(
        row_str(&rich_out.pages.as_slice()[rich_out.dispatch_pages_len - 1][0]),
        "! NATIVE ETH",
        "dispatcher native page must be the last dispatcher suffix page"
    );
    assert_eq!(
        rich_out.paymaster_page_index,
        Some(rich_out.dispatch_pages_len)
    );
    assert_eq!(rich_out.signer_page_index, rich_out.dispatch_pages_len + 1);
    assert_eq!(rich_out.target_page_index, rich_out.signer_page_index + 1);
    assert_eq!(
        rich_out.nonce_lane_page_index,
        Some(rich_out.target_page_index + 1)
    );
    assert_eq!(rich_out.gas_page_index, rich_out.target_page_index + 2);
    assert_eq!(rich_out.gas_page_index + 3, rich_out.pages.len);
    assert_eq!(
        row_str(&rich_out.pages.as_slice()[rich_out.paymaster_page_index.unwrap()][0]),
        "! PAYMASTER SET"
    );
    assert_eq!(
        row_str(&rich_out.pages.as_slice()[rich_out.signer_page_index][0]),
        "Signer acct #0"
    );
    assert_eq!(
        row_str(&rich_out.pages.as_slice()[rich_out.target_page_index][0]),
        "Target contract:"
    );
    assert_eq!(
        row_str(&rich_out.pages.as_slice()[rich_out.nonce_lane_page_index.unwrap()][0]),
        "Nonce lane key:"
    );

    let safe_addr = [0x5A; 20];
    let safe_exec = encode_exec_transaction(
        &[0xC3; 20],
        &be_u256_from_u64(0),
        &[],
        0,
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 20],
        &[0u8; 20],
        &[0x41; 65],
    );
    let mut safe = WireSignRequest::base();
    safe.to = safe_addr;
    safe.data = safe_exec;
    let safe_parsed = mirror_parse(&safe.encode());
    let safe_out = drive_glue(
        &safe_parsed,
        &Contexts {
            safe_exec_calldata: true,
            ..Default::default()
        },
    );
    assert_eq!(
        row_str(&safe_out.pages.as_slice()[safe_out.dispatch_pages_len - 2][0]),
        "Fees: max / tip"
    );
    assert_eq!(
        row_str(&safe_out.pages.as_slice()[safe_out.dispatch_pages_len - 1][0]),
        "Worst-case:"
    );
    assert_eq!(safe_out.paymaster_page_index, None);
    assert_eq!(safe_out.signer_page_index, safe_out.dispatch_pages_len);
    assert_eq!(safe_out.target_page_index, safe_out.signer_page_index + 1);
    assert_eq!(safe_out.nonce_lane_page_index, None);
    assert_eq!(safe_out.gas_page_index, safe_out.target_page_index + 1);
    assert_eq!(safe_out.gas_page_index + 3, safe_out.pages.len);
}

// ─────────────────────────────────────────────────────────────────────
// Divergence probes (non-vacuity): every byte the user sees moves the
// digest, and every displayed-fact flip is caught.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn divergence_probe_inner_data_byte_flip_moves_digest_and_fingerprint() {
    let mut req = WireSignRequest::base();
    req.data = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.data[6] ^= 0x01; // flip one byte of the signed inner data
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(
        out.digest, out2.digest,
        "inner-data flip must move the digest"
    );
    // The fingerprint page — the display-side commitment to the signed
    // calldata — must move with it.
    let fp1 = all_rows(&out.pages);
    let fp2 = all_rows(&out2.pages);
    let tail1: Vec<_> = fp1.iter().rev().take(4).collect();
    let tail2: Vec<_> = fp2.iter().rev().take(4).collect();
    assert_ne!(
        tail1, tail2,
        "fingerprint page must move with the signed bytes"
    );
}

#[test]
fn divergence_probe_account_flip_moves_mandatory_signer_page() {
    let req = WireSignRequest::base();
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());
    let mut req2 = req.clone();
    req2.account_index = 1;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());
    assert_signer_page_shown(&out.pages, 0, &p.sender);
    assert_signer_page_shown(&out2.pages, 1, &p2.sender);
    assert_ne!(out.pages.as_slice(), out2.pages.as_slice());
}

#[test]
fn divergence_probe_nonce_lane_flip_cannot_hide_behind_same_sequence() {
    let mut req = WireSignRequest::base();
    req.nonce[0] = 1; // lane key 0x01 || 23 zero bytes; sequence remains 7
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.nonce[0] = 2; // independently executable lane, same sequence
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    let lane1 = out
        .pages
        .as_slice()
        .iter()
        .find(|page| row_str(&page[0]) == "Nonce lane key:")
        .expect("non-zero lane must have an exact key page");
    let lane2 = out2
        .pages
        .as_slice()
        .iter()
        .find(|page| row_str(&page[0]) == "Nonce lane key:")
        .expect("second non-zero lane must have an exact key page");
    assert_eq!(row_str(&lane1[1]), "0100000000000000");
    assert_eq!(row_str(&lane1[2]), "0000000000000000");
    assert_eq!(row_str(&lane1[3]), "0000000000000000");
    assert_eq!(row_str(&lane2[1]), "0200000000000000");
    assert_ne!(
        lane1, lane2,
        "lane-distinct confirmations must not be identical"
    );

    let rows1 = all_rows(&out.pages);
    let rows2 = all_rows(&out2.pages);
    assert!(rows_contain(&rows1, "Nonce: 7"));
    assert!(rows_contain(&rows2, "Nonce: 7"));
    assert_ne!(
        out.digest, out2.digest,
        "full signed nonce must move the digest"
    );

    let zero = drive_glue(
        &mirror_parse(&WireSignRequest::base().encode()),
        &Contexts::default(),
    );
    assert!(
        !all_rows(&zero.pages)
            .iter()
            .any(|row| row == "Nonce lane key:"),
        "lane zero must retain the compact confirmation path"
    );
}

#[test]
fn divergence_probe_gas_permutation_moves_handler_page_and_digest() {
    let req = WireSignRequest::base();
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    core::mem::swap(&mut req2.call_gas_limit, &mut req2.verification_gas_limit);
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_eq!(
        row_str(&out.pages.as_slice()[out.gas_page_index][3]),
        row_str(&out2.pages.as_slice()[out2.gas_page_index][3]),
        "permutation keeps the friendly aggregate total unchanged"
    );
    assert_ne!(
        out.pages.as_slice()[out.gas_page_index],
        out2.pages.as_slice()[out2.gas_page_index],
        "ordered signed gas components must move the handler-owned page"
    );
    assert_ne!(
        out.digest, out2.digest,
        "gas permutation must move the signed digest"
    );
}

#[test]
fn divergence_probe_recipient_flip_moves_both_pages_and_digest() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000);
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.to[19] ^= 0x01;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(out.digest, out2.digest, "target flip must move the digest");
    // The displayed To-page rows must differ (the flipped address renders
    // differently) — a dispatcher that kept showing the OLD address while
    // signing the new one is exactly the divergence this harness exists
    // to catch.
    assert_addr_shown(&out.pages, &p.to, "original target");
    assert_addr_shown(&out2.pages, &p2.to, "flipped target");
    assert_target_page_shown(&out.pages, &p.to);
    assert_target_page_shown(&out2.pages, &p2.to);
    assert_ne!(
        oracle_addr_rows(&p.to),
        oracle_addr_rows(&p2.to),
        "sanity: rows differ"
    );
}

#[test]
fn divergence_probe_value_flip_moves_value_page_and_digest() {
    let mut req = WireSignRequest::base();
    req.value = be_u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.value = be_u256_from_u64(2_000_000_000_000_000_000); // 2 ETH
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_ne!(out.digest, out2.digest, "value flip must move the digest");
    let rows = all_rows(&out.pages);
    let rows2 = all_rows(&out2.pages);
    assert!(rows_contain(&rows, "1.000000 ETH") && !rows_contain(&rows, "2.000000 ETH"));
    assert!(rows_contain(&rows2, "2.000000 ETH") && !rows_contain(&rows2, "1.000000 ETH"));
}

#[test]
fn divergence_probe_account_flip_moves_mandatory_from_page() {
    let req = WireSignRequest::base();
    let p = mirror_parse(&req.encode());
    let out = drive_glue(&p, &Contexts::default());

    let mut req2 = req.clone();
    req2.account_index = 1;
    let p2 = mirror_parse(&req2.encode());
    let out2 = drive_glue(&p2, &Contexts::default());

    assert_signer_page_shown(&out.pages, 0, &p.sender);
    assert_signer_page_shown(&out2.pages, 1, &p2.sender);
    assert_ne!(
        out.pages.as_slice(),
        out2.pages.as_slice(),
        "changing only account_index must change confirmed display bytes"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Handler-source pins — hold the replicated glue honest. If
// `cmd_sign_userop.rs` changes how it builds `tx_for_display`, routes
// the render, or assembles the digest inputs, these fire and the
// replication above must be re-audited.
// ─────────────────────────────────────────────────────────────────────

const HANDLER_SRC: &str = include_str!("../nsc/cmd_sign_userop.rs");
const BATCH_HANDLER_SRC: &str = include_str!("../nsc/cmd_sign_userop_batch.rs");
const DISPATCH_SRC: &str = include_str!("../tx/display/dispatch.rs");

fn squash_ws(s: &str) -> String {
    s.split_whitespace().collect::<String>().replace(",)", ")")
}

#[test]
fn pin_handler_display_shim_construction_matches_replication() {
    let src = squash_ws(HANDLER_SRC);
    assert!(
        src.contains(&squash_ws(
            "let tx_for_display = Eip1559Tx { chain_id, nonce: display_nonce,
             max_priority_fee_per_gas: display_max_prio, max_fee_per_gas: display_max_fee,
             gas_limit: display_gas_limit, to: Some(to_address), value: U256(value),
             data_len, access_list_count: 0, signing_hash: [0u8; 32],
             userop_fields: Some(UserOpDisplayFields {
             // This display object describes the Type-2 transaction the user
             // is authorizing.  During slot rotation the companion-supplied
             // base nonce belongs to the preceding Type-1 registration, while
             // the transaction is signed at base+1.
             nonce: U256(type2_nonce),
             call_gas_limit: U256(call_gas_limit),
             verification_gas_limit: U256(verification_gas_limit),
             pre_verification_gas: U256(pre_verification_gas), }), };"
        )),
        "handler §6 tx_for_display construction drifted — re-audit tx_for_display() here"
    );
}

#[test]
fn pin_handler_render_and_digest_glue_matches_replication() {
    let src = squash_ws(HANDLER_SRC);
    for (frag, why) in [
        (
            "let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();
             dispatch_page_proofs.fail_initialize();",
            "handler dispatcher receipt must start from a materialized fail state",
        ),
        (
            "let mut pages = match pick_sign_pages_with_erc7730_evidence( &tx_for_display, inner_data, &sender,
             cow_order_verified.as_ref(), safe_v1_verified.as_ref(), safe_exec_verified.as_ref(),
             erc7730_verified.as_ref(), erc7730_nested_binding.as_ref(),
             chain_verified_meta.as_ref(), selector_verified.as_ref(),
             &resolver, &mut dispatch_page_proofs, )",
            "handler §8 render dispatch drifted",
        ),
        (
            "if crate::tx::display::enforce_paymaster_page(&mut pages,
             &paymaster_and_data_hash, &mut paymaster_cfi,).is_err()",
            "handler §8 paymaster splice drifted",
        ),
        (
            "let paymaster_cfi_verdict = paymaster_cfi.check_into_sentinel(
             crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);",
            "handler §8 paymaster caller-owned CFI drifted",
        ),
        (
            "let paymaster_page_verdict = crate::tx::display::paymaster_page_proof(
             &pages, paymaster_pages_before, &paymaster_and_data_hash,);",
            "handler §8 paymaster completion proof drifted",
        ),
        (
            "if crate::tx::display::enforce_from_page(&mut pages, account_index, &sender,
             &mut signer_cfi,).is_err()",
            "handler §8 mandatory signer-page append drifted",
        ),
        (
            "let signer_cfi_verdict = signer_cfi.check_into_sentinel(
             crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);",
            "handler §8 signer-page caller-owned CFI drifted",
        ),
        (
            "let signer_page_verdict = crate::tx::display::from_page_proof(&pages,
             signer_pages_before, account_index, &sender);",
            "handler §8 signer-page FI proof drifted",
        ),
        (
            "if crate::tx::display::enforce_target_page(&mut pages, &to_address,
             &mut target_cfi).is_err()",
            "handler §8 mandatory target-page append drifted",
        ),
        (
            "let target_cfi_verdict = target_cfi.check_into_sentinel(
             crate::tx::display::TARGET_PAGE_CFI_EXPECTED);",
            "handler §8 target-page caller-owned CFI drifted",
        ),
        (
            "let target_page_verdict = crate::tx::display::target_page_proof(
             &pages, target_pages_before, &to_address);",
            "handler §8 target-page FI proof drifted",
        ),
        (
            "if crate::tx::display::enforce_nonce_lane_page(&mut pages, &type2_nonce,
             &mut nonce_lane_cfi,).is_err()",
            "handler §8 conditional nonce-lane append drifted",
        ),
        (
            "let nonce_lane_cfi_verdict = nonce_lane_cfi.check_into_sentinel(
             crate::tx::display::NONCE_LANE_CFI_EXPECTED);",
            "handler §8 nonce-lane caller-owned CFI drifted",
        ),
        (
            "let nonce_lane_page_verdict = crate::tx::display::nonce_lane_page_proof(
             &pages, nonce_lane_pages_before, &type2_nonce, );",
            "handler §8 nonce-lane completion/skip proof drifted",
        ),
        (
            "let mut gas_lane_cfi = crate::fi::CfiCounter::new();",
            "handler §8 caller-owned gas CFI initialization drifted",
        ),
        (
            "if crate::tx::display::enforce_userop_gas_page( &mut pages,
             &call_gas_limit, &verification_gas_limit, &pre_verification_gas,
             &mut gas_lane_cfi, ).is_err()",
            "handler §8 append-only exact gas-page ownership drifted",
        ),
        (
            "let gas_lane_cfi_verdict = gas_lane_cfi.check_into_sentinel(
             crate::tx::display::USEROP_GAS_CFI_EXPECTED);",
            "handler §8 gas append CFI gate drifted",
        ),
        (
            "let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof( &pages,
             gas_lane_pages_before, &call_gas_limit, &verification_gas_limit,
             &pre_verification_gas, );",
            "handler §8 global gas-page proof drifted",
        ),
        (
            "let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(inner_data);",
            "handler §8 fingerprint input drifted",
        ),
        (
            "let gas_lane_final_cfi_verdict = gas_lane_cfi.check_into_sentinel(
             crate::tx::display::USEROP_GAS_CFI_EXPECTED);",
            "handler §8 final-boundary gas CFI gate drifted",
        ),
        (
            "let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
             &pages, gas_lane_pages_before, &call_gas_limit, &verification_gas_limit,
             &pre_verification_gas, );",
            "handler §8 final-confirmation gas proof drifted",
        ),
        (
            "let paymaster_final_cfi_verdict = paymaster_cfi.check_into_sentinel(
             crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);",
            "handler §8 final-boundary paymaster CFI gate drifted",
        ),
        (
            "let paymaster_final_verdict = crate::tx::display::paymaster_final_set_proof(
             &pages, paymaster_pages_before, &paymaster_and_data_hash, );",
            "handler §8 final-confirmation paymaster proof drifted",
        ),
        (
            "core::ptr::write_volatile(&mut dispatch_final_verdict_slot,
             crate::fi::FAIL_SENTINEL,);",
            "handler final dispatcher proof output must fail-in",
        ),
        (
            "dispatch_page_proofs.final_set_proof(&pages, &tx_for_display,
             legacy_fee_pages_required, &mut dispatch_final_verdict_slot,);",
            "handler §8 final display/publication proof drifted",
        ),
        (
            "let dispatch_final_verdict_a = unsafe {
             core::ptr::read_volatile(&dispatch_final_verdict_slot) };",
            "handler final display proof needs volatile read A",
        ),
        (
            "let dispatch_final_verdict_b = unsafe {
             core::ptr::read_volatile(&dispatch_final_verdict_slot) };",
            "handler final display proof needs volatile read B",
        ),
        (
            "if dispatch_final_gate_a != crate::fi::OK_SENTINEL",
            "handler final display proof needs refusal gate A",
        ),
        (
            "if dispatch_final_gate_b != crate::fi::OK_SENTINEL",
            "handler final display proof needs refusal gate B",
        ),
        (
            "let t2_exec = match reconstruct_execute_calldata( t2_owner_index,
             new_offchain_count, &tx_for_display, inner_data, )",
            "handler §10 signed-calldata inputs drifted",
        ),
        (
            "let t2_call_digest = sha256_bytes(t2_exec.as_slice());",
            "handler §14 calldata digest drifted",
        ),
        (
            "let t2_digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);",
            "handler §14 digest call drifted",
        ),
        (
            "let t2_params = AaUserOpParamsV06Sha256 { sender,
             entry_point: ENTRY_POINT_V06, chain_id,
             nonce: U256(type2_nonce), init_code_digest: t2_init_code_digest,
             call_gas_limit: U256(call_gas_limit),
             verification_gas_limit: U256(verification_gas_limit),
             pre_verification_gas: U256(pre_verification_gas),
             max_fee_per_gas: U256(max_fee_per_gas),
             max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
             paymaster_and_data_digest: paymaster_and_data_hash, };",
            "handler §14 digest params drifted",
        ),
        (
            "let t2_owner_index = (slot_index as u64) + 1;",
            "handler §10 owner-index derivation drifted",
        ),
    ] {
        assert!(src.contains(&squash_ws(frag)), "{why}: `{frag}`");
    }
}

#[test]
fn pin_append_only_handler_suffix_order_and_completion_receipts() {
    assert_eq!(
        HANDLER_SRC.matches("PAYMASTER_PAGE_CFI_EXPECTED").count(),
        2
    );
    assert_eq!(HANDLER_SRC.matches("paymaster_page_proof(").count(), 1);
    assert_eq!(HANDLER_SRC.matches("paymaster_final_set_proof(").count(), 1);
    assert_eq!(HANDLER_SRC.matches("SIGNER_PAGE_CFI_EXPECTED").count(), 2);
    assert_eq!(HANDLER_SRC.matches("TARGET_PAGE_CFI_EXPECTED").count(), 1);
    assert_eq!(HANDLER_SRC.matches("NONCE_LANE_CFI_EXPECTED").count(), 2);
    assert_eq!(HANDLER_SRC.matches("DispatchPageProofs::new()").count(), 1);
    assert_eq!(
        HANDLER_SRC
            .matches("dispatch_page_proofs.fail_initialize()")
            .count(),
        1
    );
    assert_eq!(
        HANDLER_SRC
            .matches("dispatch_page_proofs.final_set_proof(")
            .count(),
        1
    );
    assert_eq!(
        HANDLER_SRC
            .matches("read_volatile(&dispatch_final_verdict_slot)")
            .count(),
        2,
        "single final receipt needs two independently emitted volatile loads"
    );
    assert_eq!(HANDLER_SRC.matches("dispatch_final_gate_a").count(), 2);
    assert_eq!(HANDLER_SRC.matches("dispatch_final_gate_b").count(), 2);

    let single_start = HANDLER_SRC
        .find("let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();")
        .expect("single dispatcher proof owner");
    let single = &HANDLER_SRC[single_start..];
    let paymaster = single.find("enforce_paymaster_page(").unwrap();
    let signer = single.find("let signer_pages_before = pages.len;").unwrap();
    let target = single.find("let target_pages_before = pages.len;").unwrap();
    let nonce = single
        .find("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let gas = single
        .find("let gas_lane_pages_before = pages.len;")
        .unwrap();
    let fingerprint = single.find("append_fingerprint_page(").unwrap();
    let final_paymaster = single.find("paymaster_final_set_proof(").unwrap();
    let final_dispatch = single
        .find("dispatch_page_proofs.final_set_proof(")
        .unwrap();
    let final_read_a = single.find("let dispatch_final_verdict_a").unwrap();
    let final_gate_a = single
        .find("if dispatch_final_gate_a != crate::fi::OK_SENTINEL")
        .unwrap();
    let final_read_b = single.find("let dispatch_final_verdict_b").unwrap();
    let final_gate_b = single
        .find("if dispatch_final_gate_b != crate::fi::OK_SENTINEL")
        .unwrap();
    let confirm = single.find("confirm_checked(pages.as_slice())").unwrap();
    assert!(
        paymaster < signer
            && signer < target
            && target < nonce
            && nonce < gas
            && gas < fingerprint
            && fingerprint < final_paymaster
            && final_paymaster < final_dispatch
            && final_dispatch < final_read_a
            && final_read_a < final_gate_a
            && final_gate_a < final_read_b
            && final_read_b < final_gate_b
            && final_gate_b < confirm,
        "single mandatory suffix/order or final-boundary proof drifted"
    );
    let after_final_proof = &single[final_dispatch..confirm];
    assert!(!after_final_proof.contains("&mut pages"));
    assert!(!after_final_proof.contains("pages.buf"));
    assert!(!after_final_proof.contains("pages.push_blank"));
    assert!(single[final_gate_a..final_read_b].contains("crate::fi::wait_random();"));
    assert!(single[final_gate_a..final_read_b].contains("compiler_fence"));

    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("SIGNER_PAGE_CFI_EXPECTED")
            .count(),
        3
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("TARGET_PAGE_CFI_EXPECTED")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("NONCE_LANE_CFI_EXPECTED").count(),
        3
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("PAYMASTER_PAGE_CFI_EXPECTED")
            .count(),
        2
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("paymaster_page_proof(").count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("paymaster_final_set_proof(")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("DispatchPageProofs::new()")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("dispatch_page_proofs.fail_initialize()")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("dispatch_page_proofs.shift_indices(1)")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("dispatch_page_proofs.final_set_proof(")
            .count(),
        1
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("read_volatile(&dispatch_final_verdict_slot)")
            .count(),
        2,
        "batch-member final receipt needs two independent volatile loads"
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("dispatch_final_gate_a").count(),
        2
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("dispatch_final_gate_b").count(),
        2
    );
    let member_start = BATCH_HANDLER_SRC
        .find("let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();")
        .expect("batch-member dispatcher proof owner");
    let member = &BATCH_HANDLER_SRC[member_start..];
    let shift = member
        .find("dispatch_page_proofs.shift_indices(1)")
        .unwrap();
    let signer = member.find("let signer_pages_before = pages.len;").unwrap();
    let target = member.find("let target_pages_before = pages.len;").unwrap();
    let nonce = member
        .find("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let gas = member
        .find("let gas_lane_pages_before = pages.len;")
        .unwrap();
    let fingerprint = member.find("append_fingerprint_page(").unwrap();
    let final_dispatch = member
        .find("dispatch_page_proofs.final_set_proof(")
        .unwrap();
    let final_read_a = member.find("let dispatch_final_verdict_a").unwrap();
    let final_gate_a = member
        .find("if dispatch_final_gate_a != crate::fi::OK_SENTINEL")
        .unwrap();
    let final_read_b = member.find("let dispatch_final_verdict_b").unwrap();
    let final_gate_b = member
        .find("if dispatch_final_gate_b != crate::fi::OK_SENTINEL")
        .unwrap();
    let confirm = member.find("confirm_checked(pages.as_slice())").unwrap();
    assert!(
        shift < signer
            && signer < target
            && target < nonce
            && nonce < gas
            && gas < fingerprint
            && fingerprint < final_dispatch
            && final_dispatch < final_read_a
            && final_read_a < final_gate_a
            && final_gate_a < final_read_b
            && final_read_b < final_gate_b
            && final_gate_b < confirm,
        "batch-member mandatory suffix/order or shifted final proof drifted"
    );
    let after_final_proof = &member[final_dispatch..confirm];
    assert!(!after_final_proof.contains("&mut pages"));
    assert!(!after_final_proof.contains("pages.buf"));
    assert!(!after_final_proof.contains("pages.push_blank"));
    assert!(member[final_gate_a..final_read_b].contains("crate::fi::wait_random();"));
    assert!(member[final_gate_a..final_read_b].contains("compiler_fence"));

    assert_eq!(
        DISPATCH_SRC.matches("render_contract_pass_into(").count(),
        2,
        "the secure ERC-7730 route must perform two complete renders"
    );
    assert!(DISPATCH_SRC.contains("pages.volatile_poison_and_reset();"));
    assert!(DISPATCH_SRC.contains("self.receipt.exact_match(second)"));
    assert!(DISPATCH_SRC.contains("self.range_matches(second, pages, 0)"));
    assert!(DISPATCH_SRC.contains(
        "self.range_matches(&self.receipt, pages, self.start_index)"
    ));
    assert!(DISPATCH_SRC.contains("receipt.range_matches_with_nested("));

    let final_start = BATCH_HANDLER_SRC
        .find("let mut final_pages = build_final_summary_pages(batch_count);")
        .expect("batch-final summary");
    let final_summary = &BATCH_HANDLER_SRC[final_start..];
    let paymaster = final_summary.find("enforce_paymaster_page(").unwrap();
    let paymaster_proof = final_summary.find("paymaster_page_proof(").unwrap();
    let signer = final_summary
        .find("let signer_pages_before = final_pages.len;")
        .unwrap();
    let fingerprint = final_summary.find("append_fingerprint_page(").unwrap();
    let final_paymaster = final_summary.find("paymaster_final_set_proof(").unwrap();
    let confirm = final_summary
        .find("confirm_checked(final_pages.as_slice())")
        .unwrap();
    assert!(
        paymaster < paymaster_proof
            && paymaster_proof < signer
            && signer < fingerprint
            && fingerprint < final_paymaster
            && final_paymaster < confirm,
        "batch-final paymaster completion/final-boundary order drifted"
    );
}

#[test]
fn pin_every_gas_bearing_confirmation_has_a_final_global_proof() {
    assert_eq!(
        HANDLER_SRC.matches("let mut gas_lane_cfi").count(),
        2,
        "single handler confirmations each need a caller-owned gas CFI counter"
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("let mut gas_lane_cfi").count(),
        3,
        "batch confirmations each need a caller-owned gas CFI counter"
    );
    assert_eq!(
        HANDLER_SRC.matches("enforce_userop_gas_page(").count(),
        2,
        "single handler confirmations each need the append-only gas owner"
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("enforce_userop_gas_page(")
            .count(),
        3,
        "batch confirmations each need the append-only gas owner"
    );
    assert_eq!(
        HANDLER_SRC.matches("userop_gas_final_set_proof(").count(),
        2,
        "single handler rotation and main confirmations each need a final gas proof"
    );
    assert_eq!(
        BATCH_HANDLER_SRC
            .matches("userop_gas_final_set_proof(")
            .count(),
        3,
        "batch rotation, member, and final confirmations each need a final gas proof"
    );
    assert_eq!(
        HANDLER_SRC.matches("USEROP_GAS_CFI_EXPECTED").count(),
        4,
        "single confirmations must check gas CFI after append and at the final boundary"
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("USEROP_GAS_CFI_EXPECTED").count(),
        6,
        "batch confirmations must check gas CFI after append and at the final boundary"
    );
    assert_eq!(
        HANDLER_SRC.matches("confirm_checked(").count(),
        2,
        "single rotation and main confirmations require explicit gas-boundary decisions"
    );
    assert_eq!(
        BATCH_HANDLER_SRC.matches("confirm_checked(").count(),
        3,
        "new batch confirmations require an explicit gas-boundary decision"
    );
}

/// The exec selector the on-chain wallet dispatches on equals
/// keccak("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)")
/// — pins the production encoder's magic constant to the Solidity
/// signature (independent recomputation).
#[test]
fn pin_exec_selector_matches_solidity_signature() {
    let tx = tx_for_display(&mirror_parse(&WireSignRequest::base().encode()));
    let exec = reconstruct_execute_calldata(1, 0, &tx, &[]).unwrap();
    assert_eq!(
        &exec.as_slice()[..4],
        &selector_of("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)"),
    );
    // Same pin for the Safe exec selector used by the corpus.
    assert_eq!(
        EXEC_TRANSACTION_SELECTOR,
        selector_of(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
        ),
    );
}

// ─────────────────────────────────────────────────────────────────────
// Safe execTransaction test encoder (test-local; layout per the Safe
// v1.3.0 ABI, independent of `exec_decode.rs`).
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn encode_exec_transaction(
    to: &[u8; 20],
    value: &[u8; 32],
    data: &[u8],
    operation: u8,
    safe_tx_gas: &[u8; 32],
    base_gas: &[u8; 32],
    gas_price: &[u8; 32],
    gas_token: &[u8; 20],
    refund_receiver: &[u8; 20],
    signatures: &[u8],
) -> Vec<u8> {
    let head_len = 10 * 32;
    let data_padded = (data.len() + 31) & !31usize;
    let sigs_padded = (signatures.len() + 31) & !31usize;
    let data_off = head_len;
    let sigs_off = head_len + 32 + data_padded;
    let total = 4 + head_len + 32 + data_padded + 32 + sigs_padded;
    let mut cd = vec![0u8; total];
    cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
    let head = &mut cd[4..];
    let w = |i: usize| i * 32;
    head[w(0) + 12..w(0) + 32].copy_from_slice(to);
    head[w(1)..w(1) + 32].copy_from_slice(value);
    head[w(2) + 24..w(2) + 32].copy_from_slice(&(data_off as u64).to_be_bytes());
    head[w(3) + 31] = operation;
    head[w(4)..w(4) + 32].copy_from_slice(safe_tx_gas);
    head[w(5)..w(5) + 32].copy_from_slice(base_gas);
    head[w(6)..w(6) + 32].copy_from_slice(gas_price);
    head[w(7) + 12..w(7) + 32].copy_from_slice(gas_token);
    head[w(8) + 12..w(8) + 32].copy_from_slice(refund_receiver);
    head[w(9) + 24..w(9) + 32].copy_from_slice(&(sigs_off as u64).to_be_bytes());
    // tails
    let data_tail = 4 + head_len;
    cd[data_tail + 24..data_tail + 32].copy_from_slice(&(data.len() as u64).to_be_bytes());
    cd[data_tail + 32..data_tail + 32 + data.len()].copy_from_slice(data);
    let sigs_tail = 4 + sigs_off;
    cd[sigs_tail + 24..sigs_tail + 32].copy_from_slice(&(signatures.len() as u64).to_be_bytes());
    cd[sigs_tail + 32..sigs_tail + 32 + signatures.len()].copy_from_slice(signatures);
    cd
}
