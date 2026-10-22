//! Fixed trusted-display transcript and consent receipts for forced blind.
//!
//! This module is deliberately a raw renderer, not another transaction
//! decoder.  Its only variable input is [`ForcedTranscriptInput`]: fixed-width
//! values already frozen by the direct Type-2 handler.  There is no descriptor,
//! ABI, resolver, token, selector-name, or host-text input.  The renderer emits
//! the exact 29-page architecture-owned grid and delegates page 5 to the
//! existing handler-owned canonical UserOperation gas-lane helper.
//!
//! This file does not route a request, mint eligibility, sign, write an NS
//! response, or grant release authority.  Those remain handler concerns.

use super::userop_gas_lane::{
    enforce_userop_gas_page, userop_gas_final_set_proof, userop_gas_page_matches,
    userop_gas_page_proof, USEROP_GAS_CFI_EXPECTED,
};
use super::Pages;
use crate::aa::userop::{ENTRY_POINT_V06, SHA256_EMPTY};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use sha2::{Digest, Sha256};

type ForcedPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

pub(crate) const FORCED_TRANSCRIPT_PAGES: usize = 29;
const FORCED_PREFIX_PAGES: usize = 5;
const FORCED_GAS_PAGE_INDEX: usize = 5;
const FORCED_POST_GAS_FIRST_PAGE: usize = 6;

const MAX_FORCED_ACCOUNT_INDEX: u32 = sphincs_tz_shared::MAX_ACCOUNT_INDEX;
const MAX_FORCED_SLOT_INDEX: u32 = sphincs_tz_shared::SLOT_INDEX_MASK;
const MIN_SELECTOR_CALLDATA_LEN: u32 = 4;
const MAX_FORCED_CALLDATA_LEN: u32 = sphincs_tz_shared::MAX_TX_LEN as u32;

const FORCED_REQUEST_DOMAIN: &[u8] = b"PQSigner/forced-blind/request/v1";

/// The severe warning is a read-only static in flash and never consumes a
/// second [`Pages`] allocation while the final transcript is live.
pub(crate) static FORCED_WARNING_PAGES: [ForcedPage; 2] = [
    [
        *b"!! DANGER !!    ",
        *b"CLEAR SIGNING   ",
        *b"UNAVAILABLE     ",
        *b"R=Hold Continue ",
    ],
    [
        *b"BLIND SIGN CAN  ",
        *b"DRAIN WALLET    ",
        *b"RAW DATA ONLY   ",
        *b"L=Cancel R=Hold ",
    ],
];

/// Canonical fixed-width public values used by both the forced request digest
/// and the final 29-page raw transcript.
///
/// `owner_index` is intentionally not an independent input: it is derived as
/// `slot_index + 1`, matching the wallet's Type-2 owner numbering.  This makes
/// it impossible for a caller to hash one slot while displaying another owner.
pub(crate) struct ForcedTranscriptInput {
    pub(crate) account_index: u32,
    pub(crate) slot_index: u32,
    pub(crate) signer: [u8; 20],
    pub(crate) target: [u8; 20],
    pub(crate) chain_id: u64,
    pub(crate) selector: [u8; 4],
    pub(crate) calldata_len: u32,
    pub(crate) new_offchain_count: u64,
    pub(crate) value: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) max_fee_per_gas: [u8; 32],
    pub(crate) max_priority_fee_per_gas: [u8; 32],
    pub(crate) call_gas_limit: [u8; 32],
    pub(crate) verification_gas_limit: [u8; 32],
    pub(crate) pre_verification_gas: [u8; 32],
    pub(crate) erc8213_calldata_digest: [u8; 32],
    pub(crate) final_type2_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForcedRenderError {
    AccountIndex,
    SlotIndex,
    CalldataLength,
    Width,
    PageBudget,
    GasLane,
    TranscriptProof,
}

impl ForcedTranscriptInput {
    fn validate(&self) -> Result<(), ForcedRenderError> {
        if self.account_index > MAX_FORCED_ACCOUNT_INDEX {
            return Err(ForcedRenderError::AccountIndex);
        }
        if self.slot_index > MAX_FORCED_SLOT_INDEX {
            return Err(ForcedRenderError::SlotIndex);
        }
        if !(MIN_SELECTOR_CALLDATA_LEN..=MAX_FORCED_CALLDATA_LEN).contains(&self.calldata_len) {
            return Err(ForcedRenderError::CalldataLength);
        }
        Ok(())
    }

    #[must_use]
    fn owner_index(&self) -> u64 {
        u64::from(self.slot_index) + 1
    }

    /// Exact architecture-owned request digest bound into both physical
    /// receipts.  Fixed constants are supplied here, never by the host.
    pub(crate) fn request_digest(&self) -> Result<[u8; 32], ForcedRenderError> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(FORCED_REQUEST_DOMAIN);
        h.update(self.account_index.to_be_bytes());
        h.update(self.slot_index.to_be_bytes());
        h.update(self.owner_index().to_be_bytes());
        h.update(self.signer);
        h.update(self.target);
        h.update(self.chain_id.to_be_bytes());
        h.update(ENTRY_POINT_V06);
        h.update(self.selector);
        h.update(self.calldata_len.to_be_bytes());
        h.update(self.new_offchain_count.to_be_bytes());
        h.update(self.value);
        h.update(self.nonce);
        h.update(self.max_fee_per_gas);
        h.update(self.max_priority_fee_per_gas);
        h.update(self.call_gas_limit);
        h.update(self.verification_gas_limit);
        h.update(self.pre_verification_gas);
        h.update(SHA256_EMPTY); // initCode = empty
        h.update(SHA256_EMPTY); // paymasterAndData = empty
        h.update(self.erc8213_calldata_digest);
        h.update(self.final_type2_digest);
        Ok(h.finalize().into())
    }
}

/// Build exactly one 29-page transcript.  The caller owns the gas-lane CFI
/// counter; it is bumped only by the existing canonical gas-page producer.
#[inline(never)]
pub(crate) fn render_forced_transcript(
    input: &ForcedTranscriptInput,
    gas_cfi: &mut crate::fi::CfiCounter,
) -> Result<Pages, ForcedRenderError> {
    input.validate()?;

    let mut pages = Pages::with_len(FORCED_PREFIX_PAGES);
    for index in 0..FORCED_PREFIX_PAGES {
        pages.buf[index] = build_non_gas_page(input, index)?;
    }
    if pages.len != FORCED_PREFIX_PAGES {
        return Err(ForcedRenderError::PageBudget);
    }

    enforce_userop_gas_page(
        &mut pages,
        &input.call_gas_limit,
        &input.verification_gas_limit,
        &input.pre_verification_gas,
        gas_cfi,
    )
    .map_err(|_| ForcedRenderError::GasLane)?;
    if pages.len != FORCED_POST_GAS_FIRST_PAGE
        || gas_cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED) != crate::fi::OK_SENTINEL
        || userop_gas_page_proof(
            &pages,
            FORCED_GAS_PAGE_INDEX,
            &input.call_gas_limit,
            &input.verification_gas_limit,
            &input.pre_verification_gas,
        ) != crate::fi::OK_SENTINEL
    {
        return Err(ForcedRenderError::GasLane);
    }

    for index in FORCED_POST_GAS_FIRST_PAGE..FORCED_TRANSCRIPT_PAGES {
        let published = pages
            .push_blank()
            .map_err(|_| ForcedRenderError::PageBudget)?;
        if published != index {
            return Err(ForcedRenderError::PageBudget);
        }
        pages.buf[index] = build_non_gas_page(input, index)?;
    }

    if forced_transcript_proof(&pages, input) != crate::fi::OK_SENTINEL {
        return Err(ForcedRenderError::TranscriptProof);
    }
    Ok(pages)
}

/// Independent complete-grid proof without allocating a second [`Pages`].
/// Each non-gas page is reconstructed into one 64-byte scratch page, while the
/// canonical gas page is proved by the distinct handler-owned scanner.
#[inline(never)]
pub(crate) fn forced_transcript_proof(pages: &Pages, input: &ForcedTranscriptInput) -> u32 {
    if input.validate().is_err()
        || pages.len != FORCED_TRANSCRIPT_PAGES
        || userop_gas_final_set_proof(
            pages,
            FORCED_GAS_PAGE_INDEX,
            &input.call_gas_limit,
            &input.verification_gas_limit,
            &input.pre_verification_gas,
        ) != crate::fi::OK_SENTINEL
    {
        return crate::fi::FAIL_SENTINEL;
    }

    let mut diff_forward = 0u8;
    for index in 0..FORCED_TRANSCRIPT_PAGES {
        if index == FORCED_GAS_PAGE_INDEX {
            if !userop_gas_page_matches(
                pages,
                index,
                &input.call_gas_limit,
                &input.verification_gas_limit,
                &input.pre_verification_gas,
            ) {
                return crate::fi::FAIL_SENTINEL;
            }
            continue;
        }
        let Ok(expected) = build_non_gas_page(input, index) else {
            return crate::fi::FAIL_SENTINEL;
        };
        for row in 0..DISPLAY_ROWS {
            for col in 0..DISPLAY_COLS {
                diff_forward |= pages.buf[index][row][col] ^ expected[row][col];
            }
        }
    }

    crate::fi::wait_random();
    let mut diff_reverse = 0u8;
    for index in (0..FORCED_TRANSCRIPT_PAGES).rev() {
        if index == FORCED_GAS_PAGE_INDEX {
            continue;
        }
        let Ok(expected) = build_non_gas_page(input, index) else {
            return crate::fi::FAIL_SENTINEL;
        };
        for row in (0..DISPLAY_ROWS).rev() {
            for col in (0..DISPLAY_COLS).rev() {
                diff_reverse |= pages.buf[index][row][col] ^ expected[row][col];
            }
        }
    }
    crate::fi::check_true_into_sentinel(|| diff_forward == 0 && diff_reverse == 0)
}

fn build_non_gas_page(
    input: &ForcedTranscriptInput,
    index: usize,
) -> Result<ForcedPage, ForcedRenderError> {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    match index {
        0 => {
            page = [
                *b"! FORCED BLIND  ",
                *b"UNVERIFIED CALL ",
                *b"RAW DATA ONLY   ",
                *b"> inspect       ",
            ];
        }
        1 => build_identity_page(&mut page, input)?,
        2 => {
            write_fixed(&mut page[0], b"OFFCHAIN COUNT")?;
            write_hex(&mut page[1], &input.new_offchain_count.to_be_bytes())?;
        }
        3 => build_address_page(&mut page, b"TARGET", &input.target)?,
        4 => {
            write_fixed(&mut page[0], b"CHAIN ID HEX")?;
            write_hex(&mut page[1], &input.chain_id.to_be_bytes())?;
        }
        6 => build_address_page(&mut page, b"ENTRYPOINT", &ENTRY_POINT_V06)?,
        7 => build_call_shape_page(&mut page, input)?,
        8 | 9 => build_word_page(&mut page, b"VALUE", &input.value, index - 8)?,
        10 | 11 => build_word_page(&mut page, b"NONCE", &input.nonce, index - 10)?,
        12 | 13 => build_word_page(&mut page, b"MAX FEE", &input.max_fee_per_gas, index - 12)?,
        14 | 15 => build_word_page(
            &mut page,
            b"MAX PRIORITY",
            &input.max_priority_fee_per_gas,
            index - 14,
        )?,
        16 | 17 => build_word_page(&mut page, b"CALL GAS", &input.call_gas_limit, index - 16)?,
        18 | 19 => build_word_page(
            &mut page,
            b"VERIFY GAS",
            &input.verification_gas_limit,
            index - 18,
        )?,
        20 | 21 => build_word_page(
            &mut page,
            b"PREVER GAS",
            &input.pre_verification_gas,
            index - 20,
        )?,
        22 => {
            write_fixed(&mut page[0], b"PAYMASTER EMPTY")?;
            write_hex(&mut page[1], &SHA256_EMPTY[..8])?;
            write_hex(&mut page[2], &SHA256_EMPTY[8..16])?;
        }
        23 => {
            write_fixed(&mut page[0], b"PAY HASH 2/2")?;
            write_hex(&mut page[1], &SHA256_EMPTY[16..24])?;
            write_hex(&mut page[2], &SHA256_EMPTY[24..32])?;
            write_fixed(&mut page[3], b"> next")?;
        }
        24 | 25 => build_word_page(
            &mut page,
            b"ERC8213",
            &input.erc8213_calldata_digest,
            index - 24,
        )?,
        26 | 27 => build_word_page(
            &mut page,
            b"FINAL DIGEST",
            &input.final_type2_digest,
            index - 26,
        )?,
        28 => {
            page = [
                *b"FORCED BLIND    ",
                *b"UNVERIFIED      ",
                *b"L=Cancel        ",
                *b"R=Hold to Sign  ",
            ];
        }
        _ => return Err(ForcedRenderError::PageBudget),
    }
    Ok(page)
}

fn build_identity_page(
    page: &mut ForcedPage,
    input: &ForcedTranscriptInput,
) -> Result<(), ForcedRenderError> {
    let mut row = [b' '; DISPLAY_COLS];
    let mut cursor = 0usize;
    cursor = append_fixed(&mut row, cursor, b"A")?;
    cursor = append_decimal(&mut row, cursor, u64::from(input.account_index))?;
    cursor = append_fixed(&mut row, cursor, b" O")?;
    let _ = append_decimal(&mut row, cursor, input.owner_index())?;
    page[0] = row;

    write_fixed(&mut page[1], b"S:")?;
    write_hex_at(&mut page[1], 2, &input.signer[..7])?;
    write_hex(&mut page[2], &input.signer[7..15])?;
    write_hex(&mut page[3], &input.signer[15..])?;
    Ok(())
}

fn build_address_page(
    page: &mut ForcedPage,
    label: &[u8],
    address: &[u8; 20],
) -> Result<(), ForcedRenderError> {
    write_fixed(&mut page[0], label)?;
    write_hex(&mut page[1], &address[..8])?;
    write_hex(&mut page[2], &address[8..16])?;
    write_hex(&mut page[3], &address[16..])?;
    Ok(())
}

fn build_call_shape_page(
    page: &mut ForcedPage,
    input: &ForcedTranscriptInput,
) -> Result<(), ForcedRenderError> {
    write_fixed(&mut page[0], b"SINGLE TYPE-2")?;
    write_fixed(&mut page[1], b"INITCODE: EMPTY")?;
    write_fixed(&mut page[2], b"Sel: 0x")?;
    write_hex_at(&mut page[2], 7, &input.selector)?;
    let mut cursor = append_fixed(&mut page[3], 0, b"Data: ")?;
    cursor = append_decimal(&mut page[3], cursor, u64::from(input.calldata_len))?;
    let _ = append_fixed(&mut page[3], cursor, b" B")?;
    Ok(())
}

fn build_word_page(
    page: &mut ForcedPage,
    label: &[u8],
    word: &[u8; 32],
    half: usize,
) -> Result<(), ForcedRenderError> {
    if half > 1 {
        return Err(ForcedRenderError::PageBudget);
    }
    let mut cursor = append_fixed(&mut page[0], 0, label)?;
    cursor = append_fixed(
        &mut page[0],
        cursor,
        if half == 0 { b" 1/2" } else { b" 2/2" },
    )?;
    let _ = cursor;
    let start = half * 16;
    write_hex(&mut page[1], &word[start..start + 8])?;
    write_hex(&mut page[2], &word[start + 8..start + 16])?;
    write_fixed(&mut page[3], b"> next")?;
    Ok(())
}

fn append_fixed(
    row: &mut [u8; DISPLAY_COLS],
    offset: usize,
    bytes: &[u8],
) -> Result<usize, ForcedRenderError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(ForcedRenderError::Width)?;
    if end > DISPLAY_COLS {
        return Err(ForcedRenderError::Width);
    }
    row[offset..end].copy_from_slice(bytes);
    Ok(end)
}

fn write_fixed(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) -> Result<(), ForcedRenderError> {
    let _ = append_fixed(row, 0, bytes)?;
    Ok(())
}

fn append_decimal(
    row: &mut [u8; DISPLAY_COLS],
    offset: usize,
    value: u64,
) -> Result<usize, ForcedRenderError> {
    let mut decimal = [0u8; 20];
    let len = super::primitives::format_u64(value, &mut decimal).ok_or(ForcedRenderError::Width)?;
    append_fixed(row, offset, &decimal[..len])
}

fn write_hex(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) -> Result<(), ForcedRenderError> {
    write_hex_at(row, 0, bytes)
}

fn write_hex_at(
    row: &mut [u8; DISPLAY_COLS],
    offset: usize,
    bytes: &[u8],
) -> Result<(), ForcedRenderError> {
    let width = bytes.len().checked_mul(2).ok_or(ForcedRenderError::Width)?;
    if offset
        .checked_add(width)
        .is_none_or(|end| end > DISPLAY_COLS)
    {
        return Err(ForcedRenderError::Width);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        row[offset + index * 2] = hex_nibble(byte >> 4);
        row[offset + index * 2 + 1] = hex_nibble(byte & 0x0f);
    }
    Ok(())
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

// -------------------------------------------------------------------------
// Two distinct request-bound physical receipts.
// -------------------------------------------------------------------------

const RECEIPT_EMPTY: u32 = 0x6996_9669;
const RECEIPT_PUBLISHED: u32 = 0xA55A_3CC3;
const RECEIPT_CONSUMED: u32 = 0xC33C_5AA5;
const RECEIPT_FAIL_DIGEST: [u8; 32] = [0xA7; 32];

const WARNING_DOMAIN: u32 = 0x5741_524E; // "WARN"
const FINAL_DOMAIN: u32 = 0x4649_4E4C; // "FINL"
const WARNING_CFI_PUBLISH: u32 = 0x715A_C311;
const WARNING_CFI_CONSUME: u32 = 0x715A_C322;
const FINAL_CFI_PUBLISH: u32 = 0xF17A_C411;
const FINAL_CFI_CONSUME: u32 = 0xF17A_C422;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForcedReceiptError {
    DeadlineExpired,
    NotConfirmed,
    NotFailInitialized,
    AlreadyPublished,
    WarningMissing,
}

struct RawForcedReceipt {
    state: u32,
    state_inv: u32,
    domain: u32,
    request_digest: [u8; 32],
    cfi: crate::fi::CfiCounter,
}

impl RawForcedReceipt {
    const fn invalid() -> Self {
        // (0, 0) is not a complement pair and therefore cannot authorize or
        // even be published.  The caller must explicitly fail-initialize.
        Self {
            state: 0,
            state_inv: 0,
            domain: 0,
            request_digest: [0u8; 32],
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    #[inline(never)]
    fn fail_initialize(&mut self, domain: u32) {
        // SAFETY: each field is uniquely borrowed and has no destructor.
        unsafe {
            core::ptr::write_volatile(&mut self.state, RECEIPT_EMPTY);
            core::ptr::write_volatile(&mut self.state_inv, !RECEIPT_EMPTY);
            core::ptr::write_volatile(&mut self.domain, domain);
            core::ptr::write_volatile(&mut self.request_digest, RECEIPT_FAIL_DIGEST);
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn publish(
        &mut self,
        expected_domain: u32,
        publish_cfi: u32,
        request_digest: &[u8; 32],
        confirmed: bool,
        confirm_sentinel: u32,
        deadline_expired: &mut dyn FnMut() -> bool,
    ) -> Result<(), ForcedReceiptError> {
        if deadline_expired() {
            return Err(ForcedReceiptError::DeadlineExpired);
        }
        if crate::fi::check_true_into_sentinel(|| {
            confirmed && confirm_sentinel == crate::fi::OK_SENTINEL
        }) != crate::fi::OK_SENTINEL
        {
            return Err(ForcedReceiptError::NotConfirmed);
        }

        // SAFETY: immutable volatile samples of a uniquely borrowed live slot.
        let (state, state_inv, domain) = unsafe {
            (
                core::ptr::read_volatile(&self.state),
                core::ptr::read_volatile(&self.state_inv),
                core::ptr::read_volatile(&self.domain),
            )
        };
        if state == RECEIPT_PUBLISHED && state_inv == !RECEIPT_PUBLISHED {
            return Err(ForcedReceiptError::AlreadyPublished);
        }
        if state != RECEIPT_EMPTY || state_inv != !RECEIPT_EMPTY || domain != expected_domain {
            return Err(ForcedReceiptError::NotFailInitialized);
        }

        // The last operation before publication is a fresh forced-deadline
        // sample.  Button activity never mutates that predicate.
        if deadline_expired() {
            return Err(ForcedReceiptError::DeadlineExpired);
        }
        unsafe {
            core::ptr::write_volatile(&mut self.request_digest, *request_digest);
            core::ptr::write_volatile(&mut self.state, RECEIPT_PUBLISHED);
            core::ptr::write_volatile(&mut self.state_inv, !RECEIPT_PUBLISHED);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(publish_cfi);
        Ok(())
    }

    #[inline(never)]
    fn completion_proof(
        &self,
        expected_domain: u32,
        publish_cfi: u32,
        request_digest: &[u8; 32],
    ) -> u32 {
        // SAFETY: immutable samples from a live receipt.  Two complete reads
        // around a randomized gap keep one corrupt load from authorizing.
        let first = unsafe {
            (
                core::ptr::read_volatile(&self.state),
                core::ptr::read_volatile(&self.state_inv),
                core::ptr::read_volatile(&self.domain),
                core::ptr::read_volatile(&self.request_digest),
            )
        };
        crate::fi::wait_random();
        let second = unsafe {
            (
                core::ptr::read_volatile(&self.state),
                core::ptr::read_volatile(&self.state_inv),
                core::ptr::read_volatile(&self.domain),
                core::ptr::read_volatile(&self.request_digest),
            )
        };
        let mut diff_first = 0u8;
        let mut diff_second = 0u8;
        for index in 0..32 {
            diff_first |= first.3[index] ^ request_digest[index];
            diff_second |= second.3[index] ^ request_digest[index];
        }
        let cfi_ok = self
            .cfi
            .check_into_sentinel(crate::fi::CfiCounter::INIT_VALUE.wrapping_add(publish_cfi));
        crate::fi::check_true_into_sentinel(|| {
            first.0 == RECEIPT_PUBLISHED
                && first.1 == !RECEIPT_PUBLISHED
                && first.2 == expected_domain
                && second.0 == RECEIPT_PUBLISHED
                && second.1 == !RECEIPT_PUBLISHED
                && second.2 == expected_domain
                && diff_first == 0
                && diff_second == 0
                && cfi_ok == crate::fi::OK_SENTINEL
        })
    }

    #[inline(never)]
    fn consume(
        &mut self,
        expected_domain: u32,
        publish_cfi: u32,
        consume_cfi: u32,
        request_digest: &[u8; 32],
    ) -> u32 {
        if self.completion_proof(expected_domain, publish_cfi, request_digest)
            != crate::fi::OK_SENTINEL
        {
            return crate::fi::FAIL_SENTINEL;
        }
        unsafe {
            core::ptr::write_volatile(&mut self.state, RECEIPT_CONSUMED);
            core::ptr::write_volatile(&mut self.state_inv, !RECEIPT_CONSUMED);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(consume_cfi);
        let expected_cfi = crate::fi::CfiCounter::INIT_VALUE
            .wrapping_add(publish_cfi)
            .wrapping_add(consume_cfi);
        let cfi_ok = self.cfi.check_into_sentinel(expected_cfi);
        // SAFETY: read back the just-published consumed codeword.
        let state = unsafe { core::ptr::read_volatile(&self.state) };
        let state_inv = unsafe { core::ptr::read_volatile(&self.state_inv) };
        crate::fi::check_true_into_sentinel(|| {
            state == RECEIPT_CONSUMED
                && state_inv == !RECEIPT_CONSUMED
                && cfi_ok == crate::fi::OK_SENTINEL
        })
    }
}

impl Drop for RawForcedReceipt {
    fn drop(&mut self) {
        // Receipt authority is stack-local and exact-once, but cancellation
        // and every early return must still actively destroy it.  Volatile
        // invalidation prevents an optimized handler epilogue from leaving a
        // live published codeword in its reusable stack frame.
        unsafe {
            core::ptr::write_volatile(&mut self.state, 0);
            core::ptr::write_volatile(&mut self.state_inv, 0);
            core::ptr::write_volatile(&mut self.domain, 0);
            for byte in &mut self.request_digest {
                core::ptr::write_volatile(byte, 0);
            }
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// First physical-confirmation receipt.  It cannot be substituted for the
/// final receipt because the type, domain, and CFI constants are distinct.
pub(crate) struct WarningReceipt(RawForcedReceipt);

impl Default for WarningReceipt {
    fn default() -> Self {
        Self(RawForcedReceipt::invalid())
    }
}

impl WarningReceipt {
    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        self.0.fail_initialize(WARNING_DOMAIN);
    }

    #[inline(never)]
    pub(crate) fn record_confirmed(
        &mut self,
        request_digest: &[u8; 32],
        confirmed: bool,
        confirm_sentinel: u32,
        deadline_expired: &mut dyn FnMut() -> bool,
    ) -> Result<(), ForcedReceiptError> {
        self.0.publish(
            WARNING_DOMAIN,
            WARNING_CFI_PUBLISH,
            request_digest,
            confirmed,
            confirm_sentinel,
            deadline_expired,
        )
    }

    #[inline(never)]
    pub(crate) fn completion_proof(&self, request_digest: &[u8; 32]) -> u32 {
        self.0
            .completion_proof(WARNING_DOMAIN, WARNING_CFI_PUBLISH, request_digest)
    }
}

/// Second physical-confirmation receipt.  Publication requires a live,
/// request-matching [`WarningReceipt`], pinning warning-before-final order.
pub(crate) struct FinalReceipt(RawForcedReceipt);

impl Default for FinalReceipt {
    fn default() -> Self {
        Self(RawForcedReceipt::invalid())
    }
}

impl FinalReceipt {
    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        self.0.fail_initialize(FINAL_DOMAIN);
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub(crate) fn record_confirmed(
        &mut self,
        warning: &WarningReceipt,
        request_digest: &[u8; 32],
        confirmed: bool,
        confirm_sentinel: u32,
        deadline_expired: &mut dyn FnMut() -> bool,
    ) -> Result<(), ForcedReceiptError> {
        if warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL {
            return Err(ForcedReceiptError::WarningMissing);
        }
        self.0.publish(
            FINAL_DOMAIN,
            FINAL_CFI_PUBLISH,
            request_digest,
            confirmed,
            confirm_sentinel,
            deadline_expired,
        )
    }

    #[inline(never)]
    pub(crate) fn completion_proof(&self, request_digest: &[u8; 32]) -> u32 {
        self.0
            .completion_proof(FINAL_DOMAIN, FINAL_CFI_PUBLISH, request_digest)
    }
}

/// Consume both distinct receipts exactly once after proving their common
/// request digest.  A partial/faulted consumption stays fail-closed and cannot
/// be retried into success because at least one receipt is already consumed.
#[inline(never)]
pub(crate) fn consume_forced_receipts_once(
    warning: &mut WarningReceipt,
    final_receipt: &mut FinalReceipt,
    request_digest: &[u8; 32],
    deadline_expired: &mut dyn FnMut() -> bool,
) -> u32 {
    if deadline_expired()
        || warning.completion_proof(request_digest) != crate::fi::OK_SENTINEL
        || final_receipt.completion_proof(request_digest) != crate::fi::OK_SENTINEL
        || deadline_expired()
    {
        return crate::fi::FAIL_SENTINEL;
    }
    let warning_ok = warning.0.consume(
        WARNING_DOMAIN,
        WARNING_CFI_PUBLISH,
        WARNING_CFI_CONSUME,
        request_digest,
    );
    let final_ok = final_receipt.0.consume(
        FINAL_DOMAIN,
        FINAL_CFI_PUBLISH,
        FINAL_CFI_CONSUME,
        request_digest,
    );
    crate::fi::check_true_into_sentinel(|| {
        warning_ok == crate::fi::OK_SENTINEL && final_ok == crate::fi::OK_SENTINEL
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(seed: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }

    fn u256(value: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn fixture() -> ForcedTranscriptInput {
        ForcedTranscriptInput {
            account_index: 255,
            slot_index: sphincs_tz_shared::SLOT_INDEX_MASK,
            signer: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
            ],
            target: [
                0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ],
            chain_id: 0x0123_4567_89ab_cdef,
            selector: [0xba, 0x0e, 0x04, 0x2a],
            calldata_len: 4096,
            new_offchain_count: 0xfedc_ba98_7654_3210,
            value: word(0x00),
            nonce: word(0x20),
            max_fee_per_gas: word(0x40),
            max_priority_fee_per_gas: word(0x60),
            call_gas_limit: u256(100_000),
            verification_gas_limit: u256(200_000),
            pre_verification_gas: u256(21_000),
            erc8213_calldata_digest: word(0x80),
            final_type2_digest: word(0xa0),
        }
    }

    fn render(input: &ForcedTranscriptInput) -> Result<Pages, ForcedRenderError> {
        let mut cfi = crate::fi::CfiCounter::new();
        render_forced_transcript(input, &mut cfi)
    }

    fn row(text: &[u8]) -> [u8; DISPLAY_COLS] {
        assert!(text.len() <= DISPLAY_COLS);
        let mut out = [b' '; DISPLAY_COLS];
        out[..text.len()].copy_from_slice(text);
        out
    }

    #[test]
    fn exact_29_page_golden_grid() {
        let input = fixture();
        let pages = render(&input).expect("fixture must render");
        assert_eq!(pages.len, FORCED_TRANSCRIPT_PAGES);

        let expected: [[&[u8]; DISPLAY_ROWS]; FORCED_TRANSCRIPT_PAGES] = [
            [
                b"! FORCED BLIND",
                b"UNVERIFIED CALL",
                b"RAW DATA ONLY",
                b"> inspect",
            ],
            [
                b"A255 O4194304",
                b"S:00112233445566",
                b"778899aabbccddee",
                b"ff10203040",
            ],
            [b"OFFCHAIN COUNT", b"fedcba9876543210", b"", b""],
            [
                b"TARGET",
                b"deadbeef00112233",
                b"445566778899aabb",
                b"ccddeeff",
            ],
            [b"CHAIN ID HEX", b"0123456789abcdef", b"", b""],
            [
                b"Call:100000",
                b"Verify:200000",
                b"PreVer:21000",
                b"Total:321000",
            ],
            [
                b"ENTRYPOINT",
                b"5ff137d4b0fdcd49",
                b"dca30c7cf57e578a",
                b"026d2789",
            ],
            [
                b"SINGLE TYPE-2",
                b"INITCODE: EMPTY",
                b"Sel: 0xba0e042a",
                b"Data: 4096 B",
            ],
            [
                b"VALUE 1/2",
                b"0001020304050607",
                b"08090a0b0c0d0e0f",
                b"> next",
            ],
            [
                b"VALUE 2/2",
                b"1011121314151617",
                b"18191a1b1c1d1e1f",
                b"> next",
            ],
            [
                b"NONCE 1/2",
                b"2021222324252627",
                b"28292a2b2c2d2e2f",
                b"> next",
            ],
            [
                b"NONCE 2/2",
                b"3031323334353637",
                b"38393a3b3c3d3e3f",
                b"> next",
            ],
            [
                b"MAX FEE 1/2",
                b"4041424344454647",
                b"48494a4b4c4d4e4f",
                b"> next",
            ],
            [
                b"MAX FEE 2/2",
                b"5051525354555657",
                b"58595a5b5c5d5e5f",
                b"> next",
            ],
            [
                b"MAX PRIORITY 1/2",
                b"6061626364656667",
                b"68696a6b6c6d6e6f",
                b"> next",
            ],
            [
                b"MAX PRIORITY 2/2",
                b"7071727374757677",
                b"78797a7b7c7d7e7f",
                b"> next",
            ],
            [
                b"CALL GAS 1/2",
                b"0000000000000000",
                b"0000000000000000",
                b"> next",
            ],
            [
                b"CALL GAS 2/2",
                b"0000000000000000",
                b"00000000000186a0",
                b"> next",
            ],
            [
                b"VERIFY GAS 1/2",
                b"0000000000000000",
                b"0000000000000000",
                b"> next",
            ],
            [
                b"VERIFY GAS 2/2",
                b"0000000000000000",
                b"0000000000030d40",
                b"> next",
            ],
            [
                b"PREVER GAS 1/2",
                b"0000000000000000",
                b"0000000000000000",
                b"> next",
            ],
            [
                b"PREVER GAS 2/2",
                b"0000000000000000",
                b"0000000000005208",
                b"> next",
            ],
            [
                b"PAYMASTER EMPTY",
                b"e3b0c44298fc1c14",
                b"9afbf4c8996fb924",
                b"",
            ],
            [
                b"PAY HASH 2/2",
                b"27ae41e4649b934c",
                b"a495991b7852b855",
                b"> next",
            ],
            [
                b"ERC8213 1/2",
                b"8081828384858687",
                b"88898a8b8c8d8e8f",
                b"> next",
            ],
            [
                b"ERC8213 2/2",
                b"9091929394959697",
                b"98999a9b9c9d9e9f",
                b"> next",
            ],
            [
                b"FINAL DIGEST 1/2",
                b"a0a1a2a3a4a5a6a7",
                b"a8a9aaabacadaeaf",
                b"> next",
            ],
            [
                b"FINAL DIGEST 2/2",
                b"b0b1b2b3b4b5b6b7",
                b"b8b9babbbcbdbebf",
                b"> next",
            ],
            [
                b"FORCED BLIND",
                b"UNVERIFIED",
                b"L=Cancel",
                b"R=Hold to Sign",
            ],
        ];
        for page in 0..FORCED_TRANSCRIPT_PAGES {
            for line in 0..DISPLAY_ROWS {
                assert_eq!(
                    pages.buf[page][line],
                    row(expected[page][line]),
                    "golden mismatch at page {page}, row {line}"
                );
            }
        }
        assert_eq!(
            forced_transcript_proof(&pages, &input),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn warning_pages_are_static_severe_and_exact() {
        assert_eq!(FORCED_WARNING_PAGES.len(), 2);
        assert_eq!(FORCED_WARNING_PAGES[0][1], *b"CLEAR SIGNING   ");
        assert_eq!(FORCED_WARNING_PAGES[0][2], *b"UNAVAILABLE     ");
        assert_eq!(FORCED_WARNING_PAGES[1][0], *b"BLIND SIGN CAN  ");
        assert_eq!(FORCED_WARNING_PAGES[1][1], *b"DRAIN WALLET    ");
    }

    #[test]
    fn bounds_refuse_before_any_partial_transcript() {
        let mut input = fixture();
        input.account_index = 256;
        assert_eq!(render(&input).err(), Some(ForcedRenderError::AccountIndex));
        input = fixture();
        input.slot_index = sphincs_tz_shared::SLOT_INDEX_MASK + 1;
        assert_eq!(render(&input).err(), Some(ForcedRenderError::SlotIndex));
        input = fixture();
        input.calldata_len = 3;
        assert_eq!(
            render(&input).err(),
            Some(ForcedRenderError::CalldataLength)
        );
        input.calldata_len = sphincs_tz_shared::MAX_TX_LEN as u32 + 1;
        assert_eq!(
            render(&input).err(),
            Some(ForcedRenderError::CalldataLength)
        );
        // The per-call cap (8192 since 2026-10-22) itself renders.
        input.calldata_len = sphincs_tz_shared::MAX_TX_LEN as u32;
        assert!(render(&input).is_ok());
        input = fixture();
        input.call_gas_limit = [0xff; 32];
        assert_eq!(render(&input).err(), Some(ForcedRenderError::GasLane));
    }

    fn transcript_hash(input: &ForcedTranscriptInput) -> Option<[u8; 32]> {
        let pages = render(input).ok()?;
        let mut h = Sha256::new();
        h.update((pages.len as u32).to_be_bytes());
        for page in pages.as_slice() {
            for line in page {
                h.update(line);
            }
        }
        Some(h.finalize().into())
    }

    #[test]
    fn every_variable_input_bit_changes_digest_and_transcript_or_refuses() {
        let baseline = fixture();
        let baseline_request = baseline.request_digest().unwrap();
        let baseline_grid = transcript_hash(&baseline).unwrap();

        macro_rules! flip_scalar {
            ($field:ident, $bits:expr) => {{
                for bit in 0..$bits {
                    let mut changed = fixture();
                    changed.$field ^= 1 << bit;
                    if let Ok(digest) = changed.request_digest() {
                        assert_ne!(digest, baseline_request, "{} bit {bit}", stringify!($field));
                    }
                    if let Some(grid) = transcript_hash(&changed) {
                        assert_ne!(grid, baseline_grid, "{} bit {bit}", stringify!($field));
                    }
                }
            }};
        }
        macro_rules! flip_bytes {
            ($field:ident) => {{
                for byte in 0..fixture().$field.len() {
                    for bit in 0..8 {
                        let mut changed = fixture();
                        changed.$field[byte] ^= 1 << bit;
                        assert_ne!(changed.request_digest().unwrap(), baseline_request);
                        if let Some(grid) = transcript_hash(&changed) {
                            assert_ne!(
                                grid,
                                baseline_grid,
                                "{}[{byte}] bit {bit}",
                                stringify!($field)
                            );
                        }
                    }
                }
            }};
        }

        flip_scalar!(account_index, 32);
        flip_scalar!(slot_index, 32);
        flip_bytes!(signer);
        flip_bytes!(target);
        flip_scalar!(chain_id, 64);
        flip_bytes!(selector);
        flip_scalar!(calldata_len, 32);
        flip_scalar!(new_offchain_count, 64);
        flip_bytes!(value);
        flip_bytes!(nonce);
        flip_bytes!(max_fee_per_gas);
        flip_bytes!(max_priority_fee_per_gas);
        flip_bytes!(call_gas_limit);
        flip_bytes!(verification_gas_limit);
        flip_bytes!(pre_verification_gas);
        flip_bytes!(erc8213_calldata_digest);
        flip_bytes!(final_type2_digest);
    }

    #[test]
    fn page_mutation_or_reordering_fails_complete_proof() {
        let input = fixture();
        let mut pages = render(&input).unwrap();
        pages.buf[10][2][7] ^= 1;
        assert_eq!(
            forced_transcript_proof(&pages, &input),
            crate::fi::FAIL_SENTINEL
        );

        let mut pages = render(&input).unwrap();
        pages.buf.swap(24, 26);
        assert_eq!(
            forced_transcript_proof(&pages, &input),
            crate::fi::FAIL_SENTINEL
        );

        let mut pages = render(&input).unwrap();
        pages.len = 28;
        assert_eq!(
            forced_transcript_proof(&pages, &input),
            crate::fi::FAIL_SENTINEL
        );
    }

    #[test]
    fn receipts_require_fail_init_confirmation_deadline_and_exact_order() {
        let digest = fixture().request_digest().unwrap();
        let mut warning = WarningReceipt::default();
        let mut final_receipt = FinalReceipt::default();
        let mut live = || false;

        assert_eq!(warning.completion_proof(&digest), crate::fi::FAIL_SENTINEL);
        assert_eq!(
            final_receipt.completion_proof(&digest),
            crate::fi::FAIL_SENTINEL
        );
        assert_eq!(
            warning.record_confirmed(&digest, true, crate::fi::OK_SENTINEL, &mut live),
            Err(ForcedReceiptError::NotFailInitialized)
        );

        warning.fail_initialize();
        final_receipt.fail_initialize();
        assert_eq!(
            final_receipt.record_confirmed(
                &warning,
                &digest,
                true,
                crate::fi::OK_SENTINEL,
                &mut live,
            ),
            Err(ForcedReceiptError::WarningMissing)
        );
        assert_eq!(
            warning.record_confirmed(&digest, false, crate::fi::OK_SENTINEL, &mut live),
            Err(ForcedReceiptError::NotConfirmed)
        );
        assert!(warning
            .record_confirmed(&digest, true, crate::fi::OK_SENTINEL, &mut live)
            .is_ok());
        assert_eq!(warning.completion_proof(&digest), crate::fi::OK_SENTINEL);
        assert!(final_receipt
            .record_confirmed(&warning, &digest, true, crate::fi::OK_SENTINEL, &mut live,)
            .is_ok());
        assert_eq!(
            final_receipt.completion_proof(&digest),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn receipt_deadline_and_exact_digest_fail_closed() {
        let digest = fixture().request_digest().unwrap();
        let mut warning = WarningReceipt::default();
        warning.fail_initialize();
        let mut expired = || true;
        assert_eq!(
            warning.record_confirmed(&digest, true, crate::fi::OK_SENTINEL, &mut expired,),
            Err(ForcedReceiptError::DeadlineExpired)
        );

        let mut samples = [false, true].into_iter();
        let mut expires_immediately_before_publish = || samples.next().unwrap_or(true);
        assert_eq!(
            warning.record_confirmed(
                &digest,
                true,
                crate::fi::OK_SENTINEL,
                &mut expires_immediately_before_publish,
            ),
            Err(ForcedReceiptError::DeadlineExpired)
        );
        assert_eq!(warning.completion_proof(&digest), crate::fi::FAIL_SENTINEL);

        warning.fail_initialize();
        let mut live = || false;
        warning
            .record_confirmed(&digest, true, crate::fi::OK_SENTINEL, &mut live)
            .unwrap();
        let mut other = digest;
        other[7] ^= 1;
        assert_eq!(warning.completion_proof(&other), crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn receipt_pair_consumes_exactly_once() {
        let digest = fixture().request_digest().unwrap();
        let mut warning = WarningReceipt::default();
        let mut final_receipt = FinalReceipt::default();
        warning.fail_initialize();
        final_receipt.fail_initialize();
        let mut live = || false;
        warning
            .record_confirmed(&digest, true, crate::fi::OK_SENTINEL, &mut live)
            .unwrap();
        final_receipt
            .record_confirmed(&warning, &digest, true, crate::fi::OK_SENTINEL, &mut live)
            .unwrap();
        assert_eq!(
            consume_forced_receipts_once(&mut warning, &mut final_receipt, &digest, &mut live,),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            consume_forced_receipts_once(&mut warning, &mut final_receipt, &digest, &mut live,),
            crate::fi::FAIL_SENTINEL
        );
    }

    #[test]
    fn renderer_input_surface_has_no_dynamic_text_or_decoder_dependencies() {
        let source = include_str!("forced_blind.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let input_start = production
            .find("pub(crate) struct ForcedTranscriptInput")
            .unwrap();
        let input_end = production[input_start..].find("}\n\n#[derive").unwrap() + input_start;
        let input_decl = &production[input_start..input_end];
        assert!(!input_decl.contains("&str"));
        assert!(!input_decl.contains("String"));
        assert!(!production.contains("use crate::tx::typed_call"));
        assert!(!production.contains("use crate::tx::erc7730"));
        assert!(!production.contains("use crate::selectors"));
        assert!(!production.contains("use crate::names"));
        assert_eq!(production.matches("let mut pages = Pages::").count(), 1);
    }
}
