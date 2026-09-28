//! Terminal forced-blind branch for `CMD_SIGN_USEROP`.
//!
//! This module is reachable only from the direct, steady-state Type-2 handler
//! after that handler has completed its ordinary wire, EntryPoint, sender,
//! trailer, Safe, and CoW classification.  It never participates in batch,
//! off-chain, EIP-712, deployment, or rotation commands.
//!
//! The branch is deliberately terminal: affirmative exact membership in the
//! firmware-embedded refused-known P73K set enters one fixed raw ceremony and
//! returns from the command.  No failure below may fall back to an ordinary
//! renderer or a weaker signing route.

use sphincs_tz_shared::{
    NscStatus, APPROVE_HASH_SELECTOR, COW_ORDER_TRAILER_MAX_LEN, ERC7730_MAX_TRAILER_LEN,
    EXEC_TRANSACTION_SELECTOR, GPV2_SETTLEMENT_ADDRESS, MAX_SIGN_RESPONSE_LEN,
    MULTISEND_CALL_ONLY_ADDRESSES, MULTI_SEND_SELECTOR, SAFE_V1_PAYLOAD_MAX,
    SET_PRE_SIGNATURE_SELECTOR, SIGN_USEROP_HEADER_LEN, SIG_WRAPPER_LEN,
};
use zeroize::{Zeroize, Zeroizing};

use super::ptr_validate::validate_ns_write_ptr;
use super::state::{CachedSlot, ForcedAttemptPhase};
use super::{GatewayArgs, SIGN_SNAP_BUF};
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use crate::erc20::bundle::MAX_ERC20_BUNDLE_LEN;
use crate::selectors::{MAX_SELECTOR_BUNDLE_LEN, MAX_SELF_ATTEST_BUNDLE_LEN};
use crate::tx::display::forced_blind::{
    consume_forced_receipts_once, forced_transcript_proof, render_forced_transcript, FinalReceipt,
    ForcedTranscriptInput, WarningReceipt, FORCED_TRANSCRIPT_PAGES, FORCED_WARNING_PAGES,
};
use crate::tx::eip1559::{Eip1559Tx, U256};

/// Exact fixed response for a steady Type-2 forced sign:
/// count(8) || init_len(4=0) || type1_len(4=0) ||
/// type2_len(4=4128) || type2_wrapper(4128).
pub(super) const FORCED_SIGN_RESPONSE_LEN: usize = 8 + 4 + 4 + 4 + SIG_WRAPPER_LEN;
const _: () = assert!(FORCED_SIGN_RESPONSE_LEN == 4_148);
const _: () = assert!(FORCED_SIGN_RESPONSE_LEN <= MAX_SIGN_RESPONSE_LEN);

const CFI_PREFLIGHT_ELIGIBILITY: u32 = 0x19A7_4C32;
const CFI_PREFLIGHT_COUNTERS: u32 = 0xE658_B3CD;
const CFI_PREFLIGHT_DIGEST: u32 = 0x42D9_71A6;
const CFI_PREFLIGHT_CAPACITY: u32 = 0xBD26_8E59;
const CFI_PREFLIGHT_KEY: u32 = 0x73C4_1AF0;
const CFI_PREFLIGHT_RATE: u32 = 0x8C3B_E50F;
const CFI_PREFLIGHT_TRANSCRIPT: u32 = 0x2E91_D647;
const CFI_ATTEMPT_CHARGED: u32 = 0xD16E_29B8;
const CFI_WARNING_RECEIPT: u32 = 0x57A3_C18D;
const CFI_FINAL_RECEIPT: u32 = 0xA85C_3E72;
const CFI_RECHECK_ELIGIBILITY: u32 = 0x34F2_8B61;
const CFI_RECHECK_COUNTERS: u32 = 0xCB0D_749E;
const CFI_RECHECK_DIGEST: u32 = 0x6D58_A2C7;
const CFI_RECHECK_CAPACITY: u32 = 0x92A7_5D38;
const CFI_RECHECK_RATE: u32 = 0x1BC6_E94A;
const CFI_RECEIPTS_CONSUMED: u32 = 0xE439_16B5;
const CFI_CANDIDATE_CONSUMED: u32 = 0x4F82_D3A9;
const CFI_SIGN_VERIFIED: u32 = 0xB07D_2C56;
const CFI_TALLY_DURABLE: u32 = 0x25E9_87C3;
const CFI_RELEASE_GATE: u32 = 0xDA16_783C;

const CFI_TALLY_CAPACITY_CONSUMED: u32 = 0x61B4_2D9E;
const CFI_TALLY_FINAL_READ_A: u32 = 0x9E4B_D261;
const CFI_TALLY_FINAL_READ_B: u32 = 0x37C8_A54D;
const CFI_TALLY_FINAL_MATCH: u32 = 0xC837_5AB2;
const CFI_TALLY_VERDICT_PUBLISHED: u32 = 0x54E1_8F3B;
const CFI_TALLY_PREPUBLISH_EXPECTED: u32 = crate::cfi_expected!(
    CFI_TALLY_CAPACITY_CONSUMED,
    CFI_TALLY_FINAL_READ_A,
    CFI_TALLY_FINAL_READ_B,
    CFI_TALLY_FINAL_MATCH,
);
const CFI_TALLY_COMMIT_EXPECTED: u32 = crate::cfi_expected!(
    CFI_TALLY_CAPACITY_CONSUMED,
    CFI_TALLY_FINAL_READ_A,
    CFI_TALLY_FINAL_READ_B,
    CFI_TALLY_FINAL_MATCH,
    CFI_TALLY_VERDICT_PUBLISHED,
);

const CFI_PREWARNING_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
);
const CFI_PRESIGN_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
);
const CFI_PREKEY_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
    CFI_TALLY_DURABLE,
);
const CFI_PRERELEASE_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
    CFI_SIGN_VERIFIED,
    CFI_TALLY_DURABLE,
);
const CFI_RELEASE_EXPECTED: u32 = crate::cfi_expected!(
    CFI_PREFLIGHT_ELIGIBILITY,
    CFI_PREFLIGHT_COUNTERS,
    CFI_PREFLIGHT_DIGEST,
    CFI_PREFLIGHT_CAPACITY,
    CFI_PREFLIGHT_KEY,
    CFI_PREFLIGHT_RATE,
    CFI_PREFLIGHT_TRANSCRIPT,
    CFI_ATTEMPT_CHARGED,
    CFI_WARNING_RECEIPT,
    CFI_FINAL_RECEIPT,
    CFI_RECHECK_ELIGIBILITY,
    CFI_RECHECK_COUNTERS,
    CFI_RECHECK_DIGEST,
    CFI_RECHECK_CAPACITY,
    CFI_RECHECK_RATE,
    CFI_RECEIPTS_CONSUMED,
    CFI_CANDIDATE_CONSUMED,
    CFI_SIGN_VERIFIED,
    CFI_TALLY_DURABLE,
    CFI_RELEASE_GATE,
);

/// Closed result of forced classification.  `ContinueOrdinary` preserves the
/// pre-existing renderer only for calls outside F.  Once exact-F membership is
/// established, every mode or semantic exclusion is fatal and cannot fall back
/// to ordinary signing.  Only `Candidate` enters this module's terminal signer.
pub(super) enum ForcedRoute {
    ContinueOrdinary,
    Candidate(ForcedEligibility),
    Fatal,
}

/// Raw request-derived facts that decide every forced-flow exclusion.
///
/// This deliberately stores source values, not collapsed eligibility booleans.
/// The terminal handler reparses the secure snapshot and compares the complete
/// facts before and after consent, so a skipped classifier rejection cannot
/// leave an exact-F-only token that still authorizes signing.
#[derive(Eq, PartialEq)]
struct ForcedWireFacts {
    total_len: usize,
    data_len: usize,
    flags: u32,
    chain_id: u64,
    target: [u8; 20],
    selector: [u8; 4],
    paymaster_and_data_hash: [u8; 32],
    cow_order_len: usize,
    safe_v1_len: usize,
    erc7730_header_offset: usize,
    erc7730_header: Option<[u8; 2]>,
    erc7730_len: usize,
}

enum ForcedWireFactsError {
    ShortSelector,
    Invalid,
}

/// Positive exact-F evidence.  It is intentionally private and non-Copy.
pub(super) struct ForcedEligibility {
    facts: ForcedWireFacts,
}

/// Values already frozen by the direct handler.  There is no host text,
/// descriptor, resolver, selector name, or alternate response mode here.
pub(super) struct ForcedRequest<'a> {
    /// Complete immutable S-world TOCTOU snapshot. Eligibility reparses this
    /// rather than trusting caller-computed booleans or trailer offsets.
    pub(super) wire: &'a [u8],
    pub(super) account_index: u32,
    pub(super) slot_index: u32,
    pub(super) sender: [u8; 20],
    pub(super) chain_id: u64,
    pub(super) nonce: [u8; 32],
    pub(super) call_gas_limit: [u8; 32],
    pub(super) verification_gas_limit: [u8; 32],
    pub(super) pre_verification_gas: [u8; 32],
    pub(super) max_fee_per_gas: [u8; 32],
    pub(super) max_priority_fee_per_gas: [u8; 32],
    pub(super) target: [u8; 20],
    pub(super) value: [u8; 32],
    pub(super) tx: &'a Eip1559Tx,
    pub(super) calldata: &'a [u8],
}

#[inline(never)]
fn derive_wire_facts(wire: &[u8]) -> Result<ForcedWireFacts, ForcedWireFactsError> {
    let total_len = wire.len();
    if total_len < SIGN_USEROP_HEADER_LEN {
        return Err(ForcedWireFactsError::Invalid);
    }
    let data_len = crate::aa::userop::validate_data_len(
        total_len,
        u16::from_be_bytes([wire[328], wire[329]]),
    )
    .ok_or(ForcedWireFactsError::Invalid)?;
    if data_len < 4 {
        return Err(ForcedWireFactsError::ShortSelector);
    }

    let chain_id = u64::from_be_bytes([
        wire[0], wire[1], wire[2], wire[3], wire[4], wire[5], wire[6], wire[7],
    ]);
    let flags = u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]);
    let mut paymaster_and_data_hash = [0u8; 32];
    paymaster_and_data_hash.copy_from_slice(&wire[244..276]);
    let mut target = [0u8; 20];
    target.copy_from_slice(&wire[276..296]);
    let selector_offset = SIGN_USEROP_HEADER_LEN;
    let selector = [
        wire[selector_offset],
        wire[selector_offset + 1],
        wire[selector_offset + 2],
        wire[selector_offset + 3],
    ];

    // Re-walk every preceding length field. In particular, never trust a
    // caller-provided ERC-7730 offset: pointing at an unrelated zero word
    // would otherwise forge "clean absence".
    let mut cursor = SIGN_USEROP_HEADER_LEN
        .checked_add(data_len)
        .ok_or(ForcedWireFactsError::Invalid)?;
    let erc20 = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        MAX_ERC20_BUNDLE_LEN,
        "forced erc20 frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = erc20.next_cursor;
    let reserved = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        0,
        "forced reserved frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = reserved.next_cursor;
    let cow_order = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        COW_ORDER_TRAILER_MAX_LEN,
        "forced cow frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = cow_order.next_cursor;
    let safe_v1 = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        SAFE_V1_PAYLOAD_MAX,
        "forced safe frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = safe_v1.next_cursor;
    let selector_trailer = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        MAX_SELECTOR_BUNDLE_LEN,
        "forced selector frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = selector_trailer.next_cursor;
    let self_attest = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        MAX_SELF_ATTEST_BUNDLE_LEN,
        "forced self frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;
    cursor = self_attest.next_cursor;

    let erc7730_header_offset = cursor;
    let erc7730_header = cursor
        .checked_add(2)
        .filter(|end| *end <= total_len)
        .map(|_| [wire[cursor], wire[cursor + 1]]);
    let erc7730 = super::trailer::read_optional_u16_prefixed(
        wire,
        cursor,
        total_len,
        ERC7730_MAX_TRAILER_LEN,
        "forced 7730 frame",
    )
    .map_err(|_| ForcedWireFactsError::Invalid)?;

    Ok(ForcedWireFacts {
        total_len,
        data_len,
        flags,
        chain_id,
        target,
        selector,
        paymaster_and_data_hash,
        cow_order_len: cow_order.len,
        safe_v1_len: safe_v1.len,
        erc7730_header_offset,
        erc7730_header,
        erc7730_len: erc7730.len,
    })
}

#[inline(never)]
fn exclusions_hold(facts: &ForcedWireFacts, request: &ForcedRequest<'_>) -> bool {
    let (include_init_code, register_slot, account_index, slot_index) =
        crate::aa::userop::decode_flags(facts.flags);
    let protected_selector = facts.selector == APPROVE_HASH_SELECTOR
        || facts.selector == EXEC_TRANSACTION_SELECTOR
        || facts.selector == SET_PRE_SIGNATURE_SELECTOR
        || facts.selector == MULTI_SEND_SELECTOR;
    let protected_target = facts.target == GPV2_SETTLEMENT_ADDRESS
        || MULTISEND_CALL_ONLY_ADDRESSES
            .iter()
            .any(|address| address == &facts.target);

    facts.total_len == request.wire.len()
        && facts.data_len == request.calldata.len()
        && facts.chain_id == request.chain_id
        && facts.target == request.target
        && request.calldata.len() >= 4
        && facts.selector == request.calldata[..4]
        && !include_init_code
        && !register_slot
        && account_index == request.account_index
        && slot_index == request.slot_index
        && facts.paymaster_and_data_hash == SHA256_EMPTY
        && facts.cow_order_len == 0
        && facts.safe_v1_len == 0
        && facts.erc7730_header == Some([0, 0])
        && facts.erc7730_len == 0
        && !protected_selector
        && !protected_target
}

/// Determine whether an absent-descriptor request may enter the terminal
/// forced branch. Exact-F membership is resolved before exclusions: an exact-F
/// request with missing/nonempty metadata or another excluded shape is fatal,
/// while only an exact-F-negative tuple may resume ordinary dispatch.
#[inline(never)]
pub(super) fn classify(request: &ForcedRequest<'_>) -> ForcedRoute {
    let facts = match derive_wire_facts(request.wire) {
        Ok(facts) => facts,
        Err(ForcedWireFactsError::ShortSelector) => return ForcedRoute::ContinueOrdinary,
        Err(ForcedWireFactsError::Invalid) => return ForcedRoute::Fatal,
    };
    let parsed = match pqsigner_erc7730::forced_eligible::ForcedEligibleSet::from_bytes(
        &crate::db_roots::PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET,
    ) {
        Ok(set) => set,
        Err(_) => return ForcedRoute::Fatal,
    };
    if !parsed.contains(facts.chain_id, &facts.target, &facts.selector) {
        return ForcedRoute::ContinueOrdinary;
    }

    // Once exact-F membership is established, every exclusion is terminal.
    // The decision consumes raw request facts, never caller-collapsed booleans.
    if !exclusions_hold(&facts, request) {
        return ForcedRoute::Fatal;
    }

    let mut verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique initialized local.  Volatile fail-in means a skipped
    // proof call cannot inherit an affirmative register value.
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    crate::tx::erc7730::prove_forced_eligible_contract_call(
        facts.chain_id,
        &facts.target,
        &facts.selector,
        &mut verdict,
        &mut cfi,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: local remains live and the proof borrow ended.
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    if published != crate::fi::OK_SENTINEL
        || cfi.check_into_sentinel(crate::tx::erc7730::CFI_FORCED_ELIGIBLE_EXPECTED)
            != crate::fi::OK_SENTINEL
    {
        return ForcedRoute::Fatal;
    }

    ForcedRoute::Candidate(ForcedEligibility { facts })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CounterSnapshot {
    local_offchain: u64,
    last_userop: u64,
    userop_sigs: u64,
    new_offchain_count: u64,
}

struct ForcedPrepared {
    transcript: ForcedTranscriptInput,
    request_digest: [u8; 32],
    slot_key: [u8; 8],
    counters: CounterSnapshot,
    capacity: crate::offchain_state::ForcedCapacityReceipt,
    rate: crate::sign_rate::ForcedRateReceipt,
}

const CANDIDATE_LIVE: u32 = 0xA6C9_3C53;
const CANDIDATE_CONSUMED: u32 = 0x5936_C3AC;

/// Request-bound, exact-once permit minted only after every deterministic
/// preflight succeeds.  Drop invalidates it on every return path.
struct ForcedCandidate {
    state: u32,
    state_inv: u32,
    eligibility: ForcedEligibility,
    request_digest: [u8; 32],
}

impl ForcedCandidate {
    #[inline(never)]
    fn bind(
        eligibility: ForcedEligibility,
        request_digest: [u8; 32],
        request: &ForcedRequest<'_>,
    ) -> Result<Self, ()> {
        if !full_eligibility_holds(&eligibility, request) {
            return Err(());
        }
        Ok(Self {
            state: CANDIDATE_LIVE,
            state_inv: !CANDIDATE_LIVE,
            eligibility,
            request_digest,
        })
    }

    fn digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    #[inline(never)]
    fn consume(
        &mut self,
        request_digest: &[u8; 32],
        request: &ForcedRequest<'_>,
        flow_cfi: &mut crate::fi::CfiCounter,
    ) -> u32 {
        if !full_eligibility_holds(&self.eligibility, request) {
            return crate::fi::FAIL_SENTINEL;
        }
        let state = unsafe { core::ptr::read_volatile(&self.state) };
        let state_inv = unsafe { core::ptr::read_volatile(&self.state_inv) };
        let mut diff = 0u8;
        for index in 0..32 {
            diff |= self.request_digest[index] ^ request_digest[index];
        }
        if crate::fi::check_true_into_sentinel(|| {
            state == CANDIDATE_LIVE && state_inv == !CANDIDATE_LIVE && diff == 0
        }) != crate::fi::OK_SENTINEL
        {
            return crate::fi::FAIL_SENTINEL;
        }
        unsafe {
            core::ptr::write_volatile(&mut self.state, CANDIDATE_CONSUMED);
            core::ptr::write_volatile(&mut self.state_inv, !CANDIDATE_CONSUMED);
        }
        let state = unsafe { core::ptr::read_volatile(&self.state) };
        let state_inv = unsafe { core::ptr::read_volatile(&self.state_inv) };
        let consumed = crate::fi::check_true_into_sentinel(|| {
            state == CANDIDATE_CONSUMED && state_inv == !CANDIDATE_CONSUMED
        });
        if consumed == crate::fi::OK_SENTINEL {
            // The terminal CFI stage is born inside the successful state
            // transition. A skipped outer reject cannot synthesize it.
            flow_cfi.bump(CFI_CANDIDATE_CONSUMED);
        }
        consumed
    }
}

impl Drop for ForcedCandidate {
    fn drop(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.state, 0);
            core::ptr::write_volatile(&mut self.state_inv, 0);
            for byte in &mut self.request_digest {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Wipes the shared request snapshot on every terminal forced return.  The
/// outer handler's ordinary success-only cleanup is bypassed by this branch.
struct ForcedCleanup;

impl Drop for ForcedCleanup {
    fn drop(&mut self) {
        // SAFETY: the outer HandlerGuard and single dispatcher make this the
        // sole live sign handler; no peer can access the shared snapshot.
        unsafe {
            let buf = &mut *core::ptr::addr_of_mut!(SIGN_SNAP_BUF);
            for byte in buf.iter_mut() {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[inline(never)]
fn full_eligibility_holds(
    eligibility: &ForcedEligibility,
    request: &ForcedRequest<'_>,
) -> bool {
    let Ok(facts) = derive_wire_facts(request.wire) else {
        return false;
    };
    if facts != eligibility.facts || !exclusions_hold(&facts, request) {
        return false;
    }

    let Ok(set) = pqsigner_erc7730::forced_eligible::ForcedEligibleSet::from_bytes(
        &crate::db_roots::PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET,
    ) else {
        return false;
    };
    if !set.contains(facts.chain_id, &facts.target, &facts.selector) {
        return false;
    }

    let mut verdict = crate::fi::FAIL_SENTINEL;
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    crate::tx::erc7730::prove_forced_eligible_contract_call(
        facts.chain_id,
        &facts.target,
        &facts.selector,
        &mut verdict,
        &mut cfi,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    published == crate::fi::OK_SENTINEL
        && cfi.check_into_sentinel(crate::tx::erc7730::CFI_FORCED_ELIGIBLE_EXPECTED)
            == crate::fi::OK_SENTINEL
}

#[inline(never)]
fn prove_flow_eligibility(
    eligibility: &ForcedEligibility,
    request: &ForcedRequest<'_>,
    flow_cfi: &mut crate::fi::CfiCounter,
    stage: u32,
) -> bool {
    if !full_eligibility_holds(eligibility, request) {
        return false;
    }
    flow_cfi.bump(stage);
    true
}

#[inline(never)]
fn prove_candidate_eligibility(
    candidate: &ForcedCandidate,
    request: &ForcedRequest<'_>,
    flow_cfi: &mut crate::fi::CfiCounter,
) -> bool {
    prove_flow_eligibility(
        &candidate.eligibility,
        request,
        flow_cfi,
        CFI_RECHECK_ELIGIBILITY,
    )
}

/// Read-only, independently repeated few-time-key projection.  This function
/// never repairs/promotes the journal; any write before physical consent would
/// make a hostile warning request persistent.
#[inline(never)]
unsafe fn read_counter_snapshot(slot_key: &[u8; 8]) -> Result<CounterSnapshot, NscStatus> {
    let local_a = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    crate::fi::wait_random();
    let local_b = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    if local_a != local_b || local_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let last_a = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    crate::fi::wait_random();
    let last_b = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    if last_a != last_b || last_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let tally_a = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    crate::fi::wait_random();
    let tally_b = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    if tally_a != tally_b || tally_a == u64::MAX {
        return Err(NscStatus::InternalError);
    }

    let effective = crate::aa::offchain_gate::effective_offchain_count(local_a, last_a);
    if !crate::aa::offchain_gate::userop_cap_ok(effective, tally_a) {
        return Err(NscStatus::OffchainCapExceeded);
    }
    crate::fi::wait_random();
    let effective_check = crate::aa::offchain_gate::effective_offchain_count(
        core::hint::black_box(local_b),
        core::hint::black_box(last_b),
    );
    if effective != effective_check
        || !crate::aa::offchain_gate::userop_cap_ok(effective_check, core::hint::black_box(tally_b))
    {
        return Err(NscStatus::InternalError);
    }

    Ok(CounterSnapshot {
        local_offchain: local_a,
        last_userop: last_a,
        userop_sigs: tally_a,
        new_offchain_count: effective,
    })
}

/// Own the 4,352-byte canonical execute buffer only in this non-inlined frame.
/// It ends before the 1,988-byte page set is created and is invoked again only
/// after that page-owning consent frame has returned.
#[inline(never)]
fn compute_type2_digest(
    request: &ForcedRequest<'_>,
    new_offchain_count: u64,
) -> Result<[u8; 32], NscStatus> {
    let owner_index = u64::from(request.slot_index) + 1;
    let execute = reconstruct_execute_calldata(
        owner_index,
        new_offchain_count,
        request.tx,
        request.calldata,
    )
    .map_err(|_| NscStatus::CryptoError)?;
    let call_digest = sha256_bytes(execute.as_slice());
    let params = AaUserOpParamsV06Sha256 {
        sender: request.sender,
        entry_point: ENTRY_POINT_V06,
        chain_id: request.chain_id,
        nonce: U256(request.nonce),
        init_code_digest: SHA256_EMPTY,
        call_gas_limit: U256(request.call_gas_limit),
        verification_gas_limit: U256(request.verification_gas_limit),
        pre_verification_gas: U256(request.pre_verification_gas),
        max_fee_per_gas: U256(request.max_fee_per_gas),
        max_priority_fee_per_gas: U256(request.max_priority_fee_per_gas),
        paymaster_and_data_digest: SHA256_EMPTY,
    };
    Ok(compute_sphincs_digest_v06(&params, &call_digest))
}

fn transcript_input(
    request: &ForcedRequest<'_>,
    new_offchain_count: u64,
    final_type2_digest: [u8; 32],
) -> ForcedTranscriptInput {
    ForcedTranscriptInput {
        account_index: request.account_index,
        slot_index: request.slot_index,
        signer: request.sender,
        target: request.target,
        chain_id: request.chain_id,
        selector: [
            request.calldata[0],
            request.calldata[1],
            request.calldata[2],
            request.calldata[3],
        ],
        calldata_len: request.calldata.len() as u32,
        new_offchain_count,
        value: request.value,
        nonce: request.nonce,
        max_fee_per_gas: request.max_fee_per_gas,
        max_priority_fee_per_gas: request.max_priority_fee_per_gas,
        call_gas_limit: request.call_gas_limit,
        verification_gas_limit: request.verification_gas_limit,
        pre_verification_gas: request.pre_verification_gas,
        erc8213_calldata_digest: pqsigner_tx_core::erc8213::calldata_digest(request.calldata),
        final_type2_digest,
    }
}

#[inline(never)]
unsafe fn capacity_receipt(
    slot_key: &[u8; 8],
    request_digest: &[u8; 32],
) -> Result<crate::offchain_state::ForcedCapacityReceipt, NscStatus> {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    let mut cfi = crate::fi::CfiCounter::new();
    let receipt = unsafe {
        crate::offchain_state::forced_capacity_preflight(
            slot_key,
            request_digest,
            &mut verdict,
            &mut cfi,
        )
    }
    .map_err(|_| NscStatus::OffchainCapExceeded)?;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let published = unsafe { core::ptr::read_volatile(&verdict) };
    if published != crate::fi::OK_SENTINEL
        || cfi.check_into_sentinel(crate::offchain_state::CFI_FORCED_CAPACITY_EXPECTED)
            != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    Ok(receipt)
}

/// Complete key derivation/cache population before the severe warning.  This
/// is SRAM-only preparation; no page-123 or other persistent state is touched.
#[inline(never)]
unsafe fn ensure_slot_key(request: &ForcedRequest<'_>) -> Result<(), NscStatus> {
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|state| state.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let secure_element = unsafe { &mut *core::ptr::addr_of_mut!(crate::SE) };
        secure_element
            .read_entropy_blob(&mut *entropy_blob)
            .map_err(|_| NscStatus::InternalError)?
    };
    let entropy = Zeroizing::new(
        crate::crypto::decrypt_entropy_blob(&entropy_blob[..entropy_blob_len], &*master_secret)
            .map_err(|_| NscStatus::CryptoError)?,
    );
    let slot_master = Zeroizing::new(crate::crypto::slot_master_entropy_from_entropy(
        &*entropy,
        request.account_index,
    ));

    let need_keygen = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => {
            cached.account_index != request.account_index
                || cached.chain_id != request.chain_id
                || cached.slot_index != request.slot_index
        }
        None => true,
    };
    if need_keygen {
        crate::ui::show_progress("Forced keygen", 0);
        let (key, _, _) = crate::crypto::derive_c10_slot_keypair_with_progress(
            &*slot_master,
            request.chain_id,
            request.slot_index,
            forced_keygen_progress,
        );
        unsafe {
            *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
                account_index: request.account_index,
                chain_id: request.chain_id,
                slot_index: request.slot_index,
                key,
            });
        }
        super::state::with_state(|state| {
            state.slot_master_entropy.zeroize();
            crate::fi::zeroize_barrier();
            state.slot_master_entropy = *slot_master;
            state.slot_master_derived.set_true();
        });
    }

    let identity_a = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => (cached.account_index, cached.chain_id, cached.slot_index),
        None => return Err(NscStatus::InternalError),
    };
    crate::fi::wait_random();
    let identity_b = match unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) } {
        Some(cached) => (cached.account_index, cached.chain_id, cached.slot_index),
        None => return Err(NscStatus::InternalError),
    };
    let expected = (request.account_index, request.chain_id, request.slot_index);
    if identity_a != expected || identity_b != expected {
        return Err(NscStatus::InternalError);
    }
    Ok(())
}

fn forced_keygen_progress(percent: u8) {
    crate::ui::show_progress("Forced keygen", percent);
}

struct PoisonPages(crate::tx::display::Pages);

impl Drop for PoisonPages {
    fn drop(&mut self) {
        self.0.volatile_poison_and_reset();
    }
}

struct CollectedConsent {
    deadline: crate::timeout::ForcedDeadline,
    warning: WarningReceipt,
    final_receipt: FinalReceipt,
}

#[inline(never)]
fn collect_consent(
    transcript: &ForcedTranscriptInput,
    request_digest: &[u8; 32],
    flow_cfi: &mut crate::fi::CfiCounter,
) -> Result<CollectedConsent, NscStatus> {
    use crate::ui::confirm::{confirm_forced_checked, ForcedConfirmResult};

    let mut gas_cfi = crate::fi::CfiCounter::new();
    let mut pages = PoisonPages(
        render_forced_transcript(transcript, &mut gas_cfi).map_err(|_| NscStatus::InternalError)?,
    );
    if pages.0.len != FORCED_TRANSCRIPT_PAGES
        || forced_transcript_proof(&pages.0, transcript) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_PREFLIGHT_TRANSCRIPT);
    if flow_cfi.check_into_sentinel(CFI_PREWARNING_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    let mut warning = WarningReceipt::default();
    warning.fail_initialize();
    let mut final_receipt = FinalReceipt::default();
    final_receipt.fail_initialize();

    // Start conservatively just before the charge, so the measured interval
    // begins no later than the Armed -> Spent transition.  No host-visible UI
    // occurs between these two operations.
    let deadline =
        crate::timeout::ForcedDeadline::start_verified().map_err(|_| NscStatus::InternalError)?;
    let charged =
        super::state::with_state(|state| state.forced_attempt.charge_forced_attempt_for_warning());
    if charged != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_ATTEMPT_CHARGED);

    let mut deadline_expired = || deadline.expired_verified().unwrap_or(true);
    let (warning_result, warning_sentinel) =
        confirm_forced_checked(&FORCED_WARNING_PAGES, &mut deadline_expired);
    match warning_result {
        ForcedConfirmResult::Confirmed => {}
        ForcedConfirmResult::Cancelled => return Err(NscStatus::UserRejected),
        ForcedConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return Err(NscStatus::IdleWipe);
        }
        ForcedConfirmResult::DeadlineExpired => return Err(NscStatus::InternalError),
    }
    warning
        .record_confirmed(
            request_digest,
            true,
            warning_sentinel,
            &mut deadline_expired,
        )
        .map_err(|_| NscStatus::InternalError)?;
    if warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_WARNING_RECEIPT);

    // Re-prove the complete fixed grid at the exact final-confirm boundary.
    if deadline_expired() || forced_transcript_proof(&pages.0, transcript) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    let (final_result, final_sentinel) =
        confirm_forced_checked(pages.0.as_slice(), &mut deadline_expired);
    match final_result {
        ForcedConfirmResult::Confirmed => {}
        ForcedConfirmResult::Cancelled => return Err(NscStatus::UserRejected),
        ForcedConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return Err(NscStatus::IdleWipe);
        }
        ForcedConfirmResult::DeadlineExpired => return Err(NscStatus::InternalError),
    }
    final_receipt
        .record_confirmed(
            &warning,
            request_digest,
            true,
            final_sentinel,
            &mut deadline_expired,
        )
        .map_err(|_| NscStatus::InternalError)?;
    if warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL
        || final_receipt.completion_proof(request_digest) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    flow_cfi.bump(CFI_FINAL_RECEIPT);

    // Force the poison before returning so the parent frame can reconstruct
    // the 4,352-byte calldata without a live Pages allocation.
    pages.0.volatile_poison_and_reset();
    Ok(CollectedConsent {
        deadline,
        warning,
        final_receipt,
    })
}

/// Conservatively reserve one signature use after final consent and before any
/// key use.  A later signer failure may consume a phantom use, but no power,
/// flash, verification, or cache-fault path can produce an unjournaled key use.
/// The tally is written first, so a later high-water repair failure cannot erase
/// that reservation.  The second write is either COUNT promotion or USEROP
/// publication; never both, keeping the frozen two-append capacity projection
/// exact as an upper bound.
///
/// `capacity` is the fresh, non-`Copy` post-consent receipt minted for
/// `request_digest`. It is consumed exactly once by the helper below before
/// the first append. `verdict_out` must be fail-initialized by the caller. The
/// function publishes OK only after independently re-reading the durable tally
/// twice after every possible page-123 mutation and completing the local CFI
/// transcript.
#[inline(never)]
fn consume_capacity_receipt_once(
    capacity: crate::offchain_state::ForcedCapacityReceipt,
    request_digest: &[u8; 32],
    initial_verdict: u32,
    cfi: &mut crate::fi::CfiCounter,
) -> u32 {
    let capacity_bound = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(*capacity.request_digest()) == core::hint::black_box(*request_digest)
            && core::hint::black_box(initial_verdict) == crate::fi::FAIL_SENTINEL
            && core::hint::black_box(capacity.slot_present())
            && !core::hint::black_box(capacity.requires_compaction())
            && core::hint::black_box(capacity.blank_qws())
                >= crate::offchain_state::FORCED_CAPACITY_REQUIRED_APPENDS as u16
    });
    if capacity_bound == crate::fi::OK_SENTINEL {
        // The tally CFI stage is born inside the successful by-value
        // consumption. Safe Rust cannot retain or replay this receipt.
        cfi.bump(CFI_TALLY_CAPACITY_CONSUMED);
    }
    capacity_bound
}

#[inline(never)]
unsafe fn commit_durable_tally(
    slot_key: &[u8; 8],
    counters: CounterSnapshot,
    capacity: crate::offchain_state::ForcedCapacityReceipt,
    request_digest: &[u8; 32],
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), NscStatus> {
    let initial_verdict = unsafe { core::ptr::read_volatile(verdict_out) };
    if consume_capacity_receipt_once(
        capacity,
        request_digest,
        initial_verdict,
        cfi,
    ) != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }

    let next_tally = counters
        .userop_sigs
        .checked_add(1)
        .ok_or(NscStatus::InternalError)?;
    unsafe { crate::offchain_state::userop_sigs_bump(slot_key, next_tally) }
        .map_err(|_| NscStatus::InternalError)?;

    if counters.new_offchain_count > counters.local_offchain {
        unsafe {
            crate::offchain_state::offchain_count_promote_to(slot_key, counters.new_offchain_count)
        }
        .map_err(|_| NscStatus::InternalError)?;
    } else if counters.new_offchain_count > counters.last_userop {
        unsafe {
            crate::offchain_state::last_userop_count_set(slot_key, counters.new_offchain_count)
        }
        .map_err(|_| NscStatus::InternalError)?;
    }

    let local = unsafe { crate::offchain_state::offchain_count_read(slot_key) };
    let last = unsafe { crate::offchain_state::last_userop_count_read(slot_key) };
    if crate::aa::offchain_gate::effective_offchain_count(local, last)
        != counters.new_offchain_count
    {
        return Err(NscStatus::InternalError);
    }

    // This must remain the final page-123 operation before key use. The fresh
    // capacity receipt above proves both appends were direct (no compaction);
    // these independent post-mutation reads then prove the earlier
    // USEROP_SIGS reservation survived the complete commit.
    let tally_a = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    cfi.bump(CFI_TALLY_FINAL_READ_A);
    crate::fi::wait_random();
    let tally_b = unsafe { crate::offchain_state::userop_sigs_read(slot_key) };
    cfi.bump(CFI_TALLY_FINAL_READ_B);
    if crate::offchain_state::forced_final_tally_pair_proof(next_tally, tally_a, tally_b)
        != crate::fi::OK_SENTINEL
    {
        return Err(NscStatus::InternalError);
    }
    cfi.bump(CFI_TALLY_FINAL_MATCH);
    if cfi.check_into_sentinel(CFI_TALLY_PREPUBLISH_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    // SAFETY: the caller supplied a unique valid mutable reference and
    // fail-initialized it immediately before this call.
    unsafe { core::ptr::write_volatile(verdict_out, crate::fi::OK_SENTINEL) };
    cfi.bump(CFI_TALLY_VERDICT_PUBLISHED);
    Ok(())
}

#[inline(never)]
unsafe fn publish_forced_response(
    args: &GatewayArgs,
    new_offchain_count: u64,
    wrapper: &[u8; SIG_WRAPPER_LEN],
    deadline: &crate::timeout::ForcedDeadline,
    flow_cfi: &mut crate::fi::CfiCounter,
) -> Result<(), NscStatus> {
    if flow_cfi.check_into_sentinel(CFI_PRERELEASE_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    // Retain the legacy full-maximum pointer proof, then independently bind
    // the exact fixed forced extent.  Both are repeated around a randomized
    // gap before the irreversible first byte write.
    let full_a = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    let exact_a = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, FORCED_SIGN_RESPONSE_LEN)
    });
    crate::fi::wait_random();
    let full_b = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    let exact_b = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, FORCED_SIGN_RESPONSE_LEN)
    });
    let window_a = deadline
        .release_window_open_verified()
        .map_err(|_| NscStatus::InternalError)?;
    crate::fi::wait_random();
    let window_b = deadline
        .release_window_open_verified()
        .map_err(|_| NscStatus::InternalError)?;
    if full_a != crate::fi::OK_SENTINEL
        || full_b != crate::fi::OK_SENTINEL
        || exact_a != crate::fi::OK_SENTINEL
        || exact_b != crate::fi::OK_SENTINEL
        || !window_a
        || !window_b
    {
        return Err(NscStatus::InvalidPointer);
    }
    flow_cfi.bump(CFI_RELEASE_GATE);
    if flow_cfi.check_into_sentinel(CFI_RELEASE_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(NscStatus::InternalError);
    }

    // This is the explicit irreversible release point.  A hostile NS DMA bus
    // master may observe every byte as it lands; later scrub is diagnostic,
    // never revocation.
    let out = args.arg1 as *mut u8;
    let count = new_offchain_count.to_be_bytes();
    let type2_len = (SIG_WRAPPER_LEN as u32).to_be_bytes();
    for position in 0..FORCED_SIGN_RESPONSE_LEN {
        let byte = match position {
            0..=7 => count[position],
            8..=15 => 0,
            16..=19 => type2_len[position - 16],
            _ => wrapper[position - 20],
        };
        unsafe { core::ptr::write_volatile(out.add(position), byte) };
    }

    // Diagnostic only: bytes may already have escaped through hostile DMA.
    // Scrub the exact current extent and reset rather than claiming rollback.
    if deadline.expired_verified().unwrap_or(true) {
        for index in 0..FORCED_SIGN_RESPONSE_LEN {
            unsafe { core::ptr::write_volatile(out.add(index), 0) };
        }
        super::zeroize_sensitive_state();
        cortex_m::peripheral::SCB::sys_reset();
    }
    Ok(())
}

fn forced_sign_progress(percent: u8) {
    crate::ui::show_progress("Forced C10 sign", percent);
}

/// Consume one exact-F candidate through the fixed ceremony, sign once, tally
/// durably, and release one exact 4,148-byte response.  Every return is
/// terminal to the outer command; callers must never resume ordinary dispatch.
///
/// # Safety
///
/// Called inside `cmd_sign_userop::run` while its HandlerGuard owns the
/// single-threaded dispatcher.  `args.arg1` passed both top-of-handler pointer
/// gates; this function independently repeats the full and exact gates at the
/// irreversible publication boundary.
#[inline(never)]
pub(super) unsafe fn run(
    args: &GatewayArgs,
    eligibility: ForcedEligibility,
    request: ForcedRequest<'_>,
) -> u32 {
    let _cleanup = ForcedCleanup;
    let mut flow_cfi = crate::fi::CfiCounter::new();

    if !prove_flow_eligibility(
        &eligibility,
        &request,
        &mut flow_cfi,
        CFI_PREFLIGHT_ELIGIBILITY,
    ) {
        crate::ui::show_status("Forced refused", "eligibility fault");
        return NscStatus::InternalError as u32;
    }

    let armed = super::state::peek_state(|state| state.forced_attempt.phase());
    if armed != Ok(ForcedAttemptPhase::Armed) {
        if armed.is_err() {
            super::zeroize_sensitive_state();
        }
        crate::ui::show_status("Forced refused", "PIN unlock needed");
        return NscStatus::UserRejected as u32;
    }

    let slot_key = crate::offchain_state::slot_key_compute(
        request.account_index as u8,
        request.chain_id,
        request.slot_index,
    );
    let counters = match unsafe { read_counter_snapshot(&slot_key) } {
        Ok(snapshot) => snapshot,
        Err(status) => return status as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_COUNTERS);

    let final_digest = match compute_type2_digest(&request, counters.new_offchain_count) {
        Ok(digest) => digest,
        Err(status) => return status as u32,
    };
    let transcript = transcript_input(&request, counters.new_offchain_count, final_digest);
    let request_digest = match transcript.request_digest() {
        Ok(digest) => digest,
        Err(_) => return NscStatus::InternalError as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_DIGEST);

    let capacity = match unsafe { capacity_receipt(&slot_key, &request_digest) } {
        Ok(receipt) => receipt,
        Err(status) => return status as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_CAPACITY);

    if unsafe { ensure_slot_key(&request) }.is_err() {
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_PREFLIGHT_KEY);

    let rate = match crate::sign_rate::forced_rate_preflight(&request_digest) {
        Ok(receipt) => receipt,
        Err(_) => return NscStatus::CryptoError as u32,
    };
    flow_cfi.bump(CFI_PREFLIGHT_RATE);

    let prepared = ForcedPrepared {
        transcript,
        request_digest,
        slot_key,
        counters,
        capacity,
        rate,
    };
    let mut candidate =
        match ForcedCandidate::bind(eligibility, prepared.request_digest, &request) {
            Ok(candidate) => candidate,
            Err(_) => return NscStatus::InternalError as u32,
        };
    let mut consent = match collect_consent(&prepared.transcript, candidate.digest(), &mut flow_cfi)
    {
        Ok(consent) => consent,
        Err(status) => return status as u32,
    };

    // Everything below is nonblocking and independently re-derived from the
    // frozen S-world snapshot before the sole key-use call.
    if !prove_candidate_eligibility(&candidate, &request, &mut flow_cfi) {
        return NscStatus::InternalError as u32;
    }

    let counters_check = match unsafe { read_counter_snapshot(&prepared.slot_key) } {
        Ok(snapshot) => snapshot,
        Err(status) => return status as u32,
    };
    if counters_check != prepared.counters {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_COUNTERS);

    let digest_check = match compute_type2_digest(&request, prepared.counters.new_offchain_count) {
        Ok(digest) => digest,
        Err(status) => return status as u32,
    };
    let transcript_check =
        transcript_input(&request, prepared.counters.new_offchain_count, digest_check);
    let request_digest_check = match transcript_check.request_digest() {
        Ok(digest) => digest,
        Err(_) => return NscStatus::InternalError as u32,
    };
    if digest_check != prepared.transcript.final_type2_digest
        || request_digest_check != prepared.request_digest
        || request_digest_check != *candidate.digest()
    {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_DIGEST);

    let capacity_check =
        match unsafe { capacity_receipt(&prepared.slot_key, &request_digest_check) } {
            Ok(receipt) => receipt,
            Err(status) => return status as u32,
        };
    if capacity_check != prepared.capacity {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_CAPACITY);

    if crate::sign_rate::forced_rate_recheck(&prepared.rate, &request_digest_check).is_err() {
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_RECHECK_RATE);

    let mut deadline_expired = || consent.deadline.expired_verified().unwrap_or(true);
    if deadline_expired()
        || consent.warning.completion_proof(&request_digest_check) != crate::fi::OK_SENTINEL
        || consent
            .final_receipt
            .completion_proof(&request_digest_check)
            != crate::fi::OK_SENTINEL
    {
        return NscStatus::InternalError as u32;
    }
    if consume_forced_receipts_once(
        &mut consent.warning,
        &mut consent.final_receipt,
        &request_digest_check,
        &mut deadline_expired,
    ) != crate::fi::OK_SENTINEL
    {
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_RECEIPTS_CONSUMED);

    if super::state::peek_state(|state| state.forced_attempt.phase())
        != Ok(ForcedAttemptPhase::Spent)
        || candidate.consume(&request_digest_check, &request, &mut flow_cfi)
            != crate::fi::OK_SENTINEL
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }
    if flow_cfi.check_into_sentinel(CFI_PRESIGN_EXPECTED) != crate::fi::OK_SENTINEL
        || deadline_expired()
    {
        return NscStatus::InternalError as u32;
    }

    // Reserve the frozen +1 durably before entering any function that can use
    // the few-time key.  This intentionally prefers a phantom tally on a later
    // failure over an unaccounted key use.  A second deadline/CFI gate below
    // prevents signing after a slow or faulted journal operation.
    let mut tally_verdict = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut tally_verdict, crate::fi::FAIL_SENTINEL);
    }
    let mut tally_cfi = crate::fi::CfiCounter::new();
    let tally_commit = unsafe {
        commit_durable_tally(
            &prepared.slot_key,
            prepared.counters,
            capacity_check,
            &request_digest_check,
            &mut tally_verdict,
            &mut tally_cfi,
        )
    };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let tally_published = unsafe { core::ptr::read_volatile(&tally_verdict) };
    if tally_commit.is_err()
        || tally_published != crate::fi::OK_SENTINEL
        || tally_cfi.check_into_sentinel(CFI_TALLY_COMMIT_EXPECTED) != crate::fi::OK_SENTINEL
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }
    flow_cfi.bump(CFI_TALLY_DURABLE);
    if flow_cfi.check_into_sentinel(CFI_PREKEY_EXPECTED) != crate::fi::OK_SENTINEL
        || deadline_expired()
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }

    let signature = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot = match cached {
            Some(cached)
                if cached.account_index == request.account_index
                    && cached.chain_id == request.chain_id
                    && cached.slot_index == request.slot_index =>
            {
                &cached.key
            }
            _ => return NscStatus::InternalError as u32,
        };
        match crate::crypto::c10_sign_verified_forced_with_progress(
            slot,
            &digest_check,
            crate::progress_halves!(forced_sign_progress),
            &prepared.rate,
            &request_digest_check,
        ) {
            Ok(signature) => signature,
            Err(_) => {
                // The frozen use was already reserved durably. No response
                // bytes are reachable from this arm.
                super::zeroize_sensitive_state();
                return NscStatus::CryptoError as u32;
            }
        }
    };

    let outer_verified = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot = match cached {
            Some(cached)
                if cached.account_index == request.account_index
                    && cached.chain_id == request.chain_id
                    && cached.slot_index == request.slot_index =>
            {
                &cached.key
            }
            _ => {
                // Key use is already durably reserved; wipe the session and
                // withhold output on a post-sign cache-identity fault.
                super::zeroize_sensitive_state();
                return NscStatus::InternalError as u32;
            }
        };
        let first = sphincs_c10::verify(slot.pk_seed(), slot.pk_root(), &digest_check, &signature);
        crate::fi::wait_random();
        let second = sphincs_c10::verify(slot.pk_seed(), slot.pk_root(), &digest_check, &signature);
        crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(first) && core::hint::black_box(second)
        }) == crate::fi::OK_SENTINEL
    };

    // The frozen +1 was durable before key use. A failed outer verification
    // therefore withholds output without creating an unjournaled signature.
    if !outer_verified {
        super::zeroize_sensitive_state();
        return NscStatus::CryptoError as u32;
    }
    flow_cfi.bump(CFI_SIGN_VERIFIED);

    let mut wrapper = Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    super::sig_wrapper::encode_signature_wrapper(
        &mut *wrapper,
        u64::from(request.slot_index) + 1,
        &signature,
    );
    // Expiry during the expensive signature preserves the precharged durable
    // use tally but withholds every response byte.
    if deadline_expired() {
        return NscStatus::InternalError as u32;
    }
    if let Err(status) = unsafe {
        publish_forced_response(
            args,
            prepared.counters.new_offchain_count,
            &*wrapper,
            &consent.deadline,
            &mut flow_cfi,
        )
    } {
        return status as u32;
    }

    wrapper.zeroize();
    crate::fi::zeroize_barrier();
    crate::timeout::reset_activity();
    crate::ui::show_status("Forced signed", "UNVERIFIED CALL");
    NscStatus::Ok as u32
}
