//! EIP-1271 off-chain signature confirmation pages.
//!
//! Two flows:
//!
//!   * `render_eip1271_personal_sign_pages` — surfaces the actual
//!     `personal_sign` message text (paginated as printable ASCII)
//!     plus the wallet address that will be doing the signing. The
//!     firmware itself recomputes the replay-safe hash from this
//!     message, so what the user reads here is byte-equivalent to
//!     what gets signed.
//!
//!   * `render_eip1271_raw32_pages` — fallback for the raw-hash path
//!     (e.g. an EIP-712 typed-data digest the firmware can't break
//!     apart). Shows the 32 hex bytes split across two pages.
//!
//! Both render the same chain / account / slot context and the same
//! per-slot off-chain budget summary (`local + 1 / cap`, gap to next
//! UserOp).

use super::primitives::{hex_nibble, write_addr_full, write_chain, write_line};
use super::Pages;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use sha2::{Digest, Sha256};

type ContextPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Handler-owned suffix appended to any off-chain request whose base renderer
/// does not already prove this complete signing context. Structured
/// EIP-712/ERC-7730 and explicit RAW32 both use it.
/// Three pages are sufficient to show the complete signing identity, response
/// mode, and post-sign few-time budget without increasing `MAX_PAGES`.
pub(crate) const OFFCHAIN_CONTEXT_PAGES: usize = 3;

const OFFCHAIN_CONTEXT_CFI_STEP: u32 = 0x1271_C7A1;
pub(crate) const OFFCHAIN_CONTEXT_CFI_EXPECTED: u32 =
    crate::cfi_expected!(OFFCHAIN_CONTEXT_CFI_STEP);

const OFFCHAIN_CONFIRM_CFI_STEP: u32 = 0x1271_C0F1;
const OFFCHAIN_CONFIRM_FAIL_DIGEST: [u8; 32] = [0xA5; 32];
const OFFCHAIN_CONFIRM_DOMAIN: &[u8] = b"PQSigner/offchain-confirm/v1";

/// Exact public context authorized by one off-chain confirmation.
///
/// The receipt below hashes this fixed-width record. In particular, the
/// confirmation cannot be reused across a kind, account, slot, wallet,
/// response mode, counter state, or signed hash even if a conditional control
/// flow edge is fault-skipped later in the handler.
#[derive(Clone, Copy)]
pub(crate) struct OffchainConfirmContext {
    kind: u8,
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    wallet_addr: [u8; 20],
    account_deployed: bool,
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
    hash_to_sign: [u8; 32],
}

impl OffchainConfirmContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        kind: u8,
        chain_id: u64,
        account_index: u32,
        slot_index: u32,
        wallet_addr: [u8; 20],
        account_deployed: bool,
        local_offchain_after: u64,
        last_userop: u64,
        cap: u64,
        hash_to_sign: [u8; 32],
    ) -> Self {
        Self {
            kind,
            chain_id,
            account_index,
            slot_index,
            wallet_addr,
            account_deployed,
            local_offchain_after,
            last_userop,
            cap,
            hash_to_sign,
        }
    }

    /// The derived wallet (proxy) address the context names.
    pub(crate) fn wallet_addr(&self) -> &[u8; 20] {
        &self.wallet_addr
    }

    /// Whether the wallet is deployed (`false` = ERC-6492 wrapped).
    pub(crate) fn account_deployed(&self) -> bool {
        self.account_deployed
    }

    fn receipt_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(OFFCHAIN_CONFIRM_DOMAIN);
        h.update([self.kind]);
        h.update(self.chain_id.to_be_bytes());
        h.update(self.account_index.to_be_bytes());
        h.update(self.slot_index.to_be_bytes());
        h.update(self.wallet_addr);
        h.update([u8::from(self.account_deployed)]);
        h.update(self.local_offchain_after.to_be_bytes());
        h.update(self.last_userop.to_be_bytes());
        h.update(self.cap.to_be_bytes());
        h.update(self.hash_to_sign);
        h.finalize().into()
    }
}

/// Fail-initialized, domain-separated authority receipt carried from the
/// affirmative trusted-UI branch to the common off-chain signing gate.
pub(crate) struct OffchainConfirmReceipt {
    confirmed: u32,
    context_digest: [u8; 32],
    cfi: crate::fi::CfiCounter,
}

impl OffchainConfirmReceipt {
    pub(crate) const fn new() -> Self {
        Self {
            confirmed: 0,
            context_digest: OFFCHAIN_CONFIRM_FAIL_DIGEST,
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    /// Materialize a fail state at the caller boundary. Stale stack contents
    /// from an earlier request therefore cannot authorize a later signature.
    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        // SAFETY: every field is uniquely borrowed and has no destructor.
        unsafe {
            core::ptr::write_volatile(&mut self.confirmed, 0);
            core::ptr::write_volatile(&mut self.context_digest, OFFCHAIN_CONFIRM_FAIL_DIGEST);
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Mint exactly one receipt after `confirm_checked` returned both
    /// `Confirmed` and its affirmative sentinel. Duplicate publication fails.
    #[inline(never)]
    pub(crate) fn record_confirmed(&mut self, context: &OffchainConfirmContext) -> Result<(), ()> {
        // SAFETY: unique live receipt; volatile state remains independently
        // observable from the CFI accumulator under LTO.
        let current = unsafe { core::ptr::read_volatile(&self.confirmed) };
        if current != 0 {
            return Err(());
        }
        let digest = context.receipt_digest();
        unsafe {
            core::ptr::write_volatile(&mut self.context_digest, digest);
            core::ptr::write_volatile(&mut self.confirmed, 1);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(OFFCHAIN_CONFIRM_CFI_STEP);
        Ok(())
    }

    /// Reconstruct the expected context at the common signing boundary and
    /// prove one affirmative publication, exact digest equality, and one
    /// domain-specific CFI step.
    #[inline(never)]
    pub(crate) fn completion_proof(&self, context: &OffchainConfirmContext) -> u32 {
        // SAFETY: immutable live receipt, sampled twice around a randomized
        // gap so one corrupt load cannot forge the authority state.
        let confirmed_a = unsafe { core::ptr::read_volatile(&self.confirmed) };
        let digest_a = unsafe { core::ptr::read_volatile(&self.context_digest) };
        crate::fi::wait_random();
        let confirmed_b = unsafe { core::ptr::read_volatile(&self.confirmed) };
        let digest_b = unsafe { core::ptr::read_volatile(&self.context_digest) };

        let expected = context.receipt_digest();
        let mut diff_a = 0u8;
        let mut diff_b = 0u8;
        for i in 0..expected.len() {
            diff_a |= digest_a[i] ^ expected[i];
            diff_b |= digest_b[i] ^ expected[i];
        }
        let expected_cfi =
            crate::fi::CfiCounter::INIT_VALUE.wrapping_add(OFFCHAIN_CONFIRM_CFI_STEP);
        crate::fi::scrub_sentinel_register();
        let cfi_verdict = self.cfi.check_into_sentinel(expected_cfi);
        let all_ok = confirmed_a == 1
            && confirmed_b == 1
            && diff_a == 0
            && diff_b == 0
            && cfi_verdict == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(all_ok))
    }
}

/// Append the complete handler-owned context for an off-chain request.
/// The operation is atomic with respect to the page budget and publishes a
/// caller-owned CFI step only after all three exact pages are present.
#[inline(never)]
pub(crate) fn append_eip1271_context_pages(
    pages: &mut Pages,
    context: &OffchainConfirmContext,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    let expected = build_context_pages(context);
    if pages
        .len
        .checked_add(OFFCHAIN_CONTEXT_PAGES)
        .is_none_or(|len| len > super::MAX_PAGES)
    {
        return Err(());
    }
    for expected_page in expected {
        let index = pages.push_blank()?;
        pages.buf[index] = expected_page;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(OFFCHAIN_CONTEXT_CFI_STEP);
    Ok(())
}

/// Exact insertion and uniqueness proof immediately after append.
#[inline(never)]
pub(crate) fn eip1271_context_page_proof(
    pages: &Pages,
    prior_len: usize,
    context: &OffchainConfirmContext,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| context_matches(pages, prior_len, context, true))
}

/// Independent final-set proof run after every other handler-owned suffix and
/// immediately before the trusted confirmation boundary.
#[inline(never)]
pub(crate) fn eip1271_context_final_set_proof(
    pages: &Pages,
    expected_index: usize,
    context: &OffchainConfirmContext,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        context_matches(pages, expected_index, context, true)
    })
}

pub(crate) fn build_context_pages(
    context: &OffchainConfirmContext,
) -> [ContextPage; OFFCHAIN_CONTEXT_PAGES] {
    let mut out = [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; OFFCHAIN_CONTEXT_PAGES];

    write_line(&mut out[0][0], "Offchain signer");
    write_acct_row(&mut out[0][1], context.account_index);
    write_slot_row(&mut out[0][2], context.slot_index);
    write_line(&mut out[0][3], "> next");

    write_line(&mut out[1][0], "Signing wallet");
    {
        let [_label, first, second, third] = &mut out[1];
        write_addr_full(first, second, third, &context.wallet_addr);
    }

    if context.account_deployed {
        write_line(&mut out[2][0], "DEPLOYED EIP1271");
    } else {
        write_line(&mut out[2][0], "ERC-6492 WRAPPED");
    }
    write_used_budget_row(&mut out[2][1], context.local_offchain_after, context.cap);
    write_gap_row(
        &mut out[2][2],
        context.local_offchain_after,
        context.last_userop,
    );
    write_line(&mut out[2][3], "L cancel/R sign");
    out
}

fn context_page_exact(actual: &ContextPage, expected: &ContextPage) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

fn context_matches(
    pages: &Pages,
    expected_index: usize,
    context: &OffchainConfirmContext,
    require_final_len: bool,
) -> bool {
    let expected = build_context_pages(context);
    let Some(end) = expected_index.checked_add(OFFCHAIN_CONTEXT_PAGES) else {
        return false;
    };
    if end > pages.len || (require_final_len && end != pages.len) {
        return false;
    }
    for (offset, expected_page) in expected.iter().enumerate() {
        if !pages
            .as_slice()
            .get(expected_index + offset)
            .is_some_and(|actual| context_page_exact(actual, expected_page))
        {
            return false;
        }
        let mut occurrences = 0usize;
        for actual in pages.as_slice() {
            if context_page_exact(actual, expected_page) {
                occurrences += 1;
            }
        }
        if occurrences != 1 {
            return false;
        }
    }
    true
}

/// Render the PersonalSign EIP-1271 confirmation flow.
///
/// `wallet_addr` is the on-chain proxy address signing the message
/// (the verifying contract bound into the EIP-712 domain separator).
/// `msg` is the raw `personal_sign` message — printable ASCII bytes
/// render as themselves; non-printable bytes render as `?`.
pub fn render_eip1271_personal_sign_pages(
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    wallet_addr: &[u8; 20],
    msg: &[u8],
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
    account_deployed: bool,
) -> Pages {
    // 5 fixed pages (banner / chain / account / wallet addr / final
    // confirm) + the message body. Each message page surfaces 3 rows
    // × 16 cols = 48 chars; the 4th row is a "Msg N/M > next" footer.
    const TEXT_ROWS_PER_PAGE: usize = 3;
    const CHARS_PER_PAGE: usize = TEXT_ROWS_PER_PAGE * DISPLAY_COLS;

    let msg_pages = if msg.is_empty() {
        1
    } else {
        (msg.len() + CHARS_PER_PAGE - 1) / CHARS_PER_PAGE
    };
    let total = 5 + msg_pages;
    // `Pages::with_len` will assert if MAX_PAGES is too small. The
    // bound matches the static cap on `MAX_OFFCHAIN_PERSONAL_SIGN_LEN`
    // / CHARS_PER_PAGE + 5 fixed pages.
    let mut pages = Pages::with_len(total);

    // ── Page 0: banner ─────────────────────────────────────────────
    write_line(&mut pages.buf[0][0], "EIP-1271 Sign?");
    write_line(&mut pages.buf[0][1], "personal_sign");
    if account_deployed {
        write_line(&mut pages.buf[0][2], "Verify on dapp");
    } else {
        // ERC-6492: the dapp will receive a wrapped sig that
        // counterfactually deploys this wallet on first use.
        // MEDIUM-1 (audit counter-replay 20260611): legible, fit-to-width
        // counterfactual warning (the old "! Pre-deploy 6492" truncated to
        // "! Pre-deploy 649"). account_deployed==0 means the firmware is
        // treating this wallet as never-deployed and resets its off-chain
        // budget view to zero — correct for a genuinely new wallet, but a
        // RED FLAG for a user who restored a wallet they have used before
        // (a companion lying about account_deployed to reset the slot's
        // few-time budget). "Undeployed" reads as obviously-wrong to such a
        // returning user, who can then cancel.
        write_line(&mut pages.buf[0][2], "! Undeployed sig");
    }
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: chain ──────────────────────────────────────────────
    write_line(&mut pages.buf[1][0], "Chain:");
    {
        let [_label, id, continuation_or_name, _foot] = &mut pages.buf[1];
        write_chain(id, continuation_or_name, chain_id);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // ── Page 2: account + slot ─────────────────────────────────────
    write_acct_row(&mut pages.buf[2][0], account_index);
    write_slot_row(&mut pages.buf[2][1], slot_index);
    write_line(&mut pages.buf[2][2], "");
    write_line(&mut pages.buf[2][3], "> next");

    // ── Page 3: wallet address (the EIP-712 verifyingContract) ─────
    write_line(&mut pages.buf[3][0], "Signer:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[3];
        write_addr_full(a, b, c, wallet_addr);
    }

    // ── Pages 4..4+msg_pages: message text ─────────────────────────
    for p in 0..msg_pages {
        let page_idx = 4 + p;
        let off = p * CHARS_PER_PAGE;
        let end = core::cmp::min(off + CHARS_PER_PAGE, msg.len());
        let chunk = &msg[off..end];
        for r in 0..TEXT_ROWS_PER_PAGE {
            let row_off = r * DISPLAY_COLS;
            let row_end = core::cmp::min(row_off + DISPLAY_COLS, chunk.len());
            let row = &mut pages.buf[page_idx][r];
            *row = [b' '; DISPLAY_COLS];
            if row_off < chunk.len() {
                let slice = &chunk[row_off..row_end];
                for (i, &b) in slice.iter().enumerate() {
                    row[i] = sanitise_byte(b);
                }
            }
        }
        // Footer: "Msg N/M  > next" or "Msg N/M  > sign" on the last
        // text page; the very last page (final confirm) has its own
        // L=Cancel / R=Confirm prompts.
        write_msg_footer(&mut pages.buf[page_idx][3], p + 1, msg_pages);
    }

    // ── Final page: budget + confirm ───────────────────────────────
    let last_page = total - 1;
    write_budget_row(&mut pages.buf[last_page][0], local_offchain_after, cap);
    write_gap_row(
        &mut pages.buf[last_page][1],
        local_offchain_after,
        last_userop,
    );
    write_line(&mut pages.buf[last_page][2], "L=Cancel");
    write_line(&mut pages.buf[last_page][3], "R=Confirm");

    pages
}

/// Render the raw-hash EIP-1271 confirmation flow (fallback when the
/// companion only has the final 32-byte hash, no message).
pub fn render_eip1271_raw32_pages(
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    hash: &[u8; 32],
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
    account_deployed: bool,
) -> Pages {
    let mut pages = Pages::with_len(6);

    write_line(&mut pages.buf[0][0], "EIP-1271 Sign?");
    write_line(&mut pages.buf[0][1], "! BLIND RAW32");
    if account_deployed {
        write_line(&mut pages.buf[0][2], "Verify on dapp");
    } else {
        // MEDIUM-1 (audit counter-replay 20260611): legible, fit-to-width
        // counterfactual warning (the old "! Pre-deploy 6492" truncated to
        // "! Pre-deploy 649"). account_deployed==0 means the firmware is
        // treating this wallet as never-deployed and resets its off-chain
        // budget view to zero — correct for a genuinely new wallet, but a
        // RED FLAG for a user who restored a wallet they have used before
        // (a companion lying about account_deployed to reset the slot's
        // few-time budget). "Undeployed" reads as obviously-wrong to such a
        // returning user, who can then cancel.
        write_line(&mut pages.buf[0][2], "! Undeployed sig");
    }
    write_line(&mut pages.buf[0][3], "> next");

    write_line(&mut pages.buf[1][0], "Chain:");
    {
        let [_label, id, continuation_or_name, _foot] = &mut pages.buf[1];
        write_chain(id, continuation_or_name, chain_id);
    }
    write_line(&mut pages.buf[1][3], "> next");

    write_acct_row(&mut pages.buf[2][0], account_index);
    write_slot_row(&mut pages.buf[2][1], slot_index);
    write_line(&mut pages.buf[2][2], "");
    write_line(&mut pages.buf[2][3], "> next");

    write_line(&mut pages.buf[3][0], "Hash 1/2:");
    write_hex_row(&mut pages.buf[3][1], &hash[0..8]);
    write_hex_row(&mut pages.buf[3][2], &hash[8..16]);
    write_line(&mut pages.buf[3][3], "> next");

    write_line(&mut pages.buf[4][0], "Hash 2/2:");
    write_hex_row(&mut pages.buf[4][1], &hash[16..24]);
    write_hex_row(&mut pages.buf[4][2], &hash[24..32]);
    write_line(&mut pages.buf[4][3], "> next");

    write_budget_row(&mut pages.buf[5][0], local_offchain_after, cap);
    write_gap_row(&mut pages.buf[5][1], local_offchain_after, last_userop);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}

// ───────────────────────────── helpers ──────────────────────────────

fn sanitise_byte(b: u8) -> u8 {
    // Render printable ASCII as-is; everything else (control bytes, hi-
    // bit / UTF-8 continuation bytes) becomes '?' so the trusted
    // display can never paint a glyph the user couldn't read on a
    // standard ASCII rendering of the dapp's message.
    if (0x20..=0x7E).contains(&b) {
        b
    } else {
        b'?'
    }
}

fn write_hex_row(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS / 2);
    for i in 0..n {
        row[i * 2] = hex_nibble(bytes[i] >> 4);
        row[i * 2 + 1] = hex_nibble(bytes[i] & 0x0f);
    }
}

fn write_acct_row(row: &mut [u8; DISPLAY_COLS], account_index: u32) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Account: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, account_index as u64);
    let _ = pos;
}

fn write_slot_row(row: &mut [u8; DISPLAY_COLS], slot_index: u32) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Slot: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, slot_index as u64);
    let _ = pos;
}

fn write_budget_row(row: &mut [u8; DISPLAY_COLS], used: u64, cap: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    pos = write_decimal(row, pos, used);
    if pos < DISPLAY_COLS {
        row[pos] = b'/';
        pos += 1;
    }
    pos = write_decimal(row, pos, cap);
    let _ = pos;
}

fn write_used_budget_row(row: &mut [u8; DISPLAY_COLS], used: u64, cap: u64) {
    *row = [b' '; DISPLAY_COLS];
    row[..4].copy_from_slice(b"Use ");
    let mut pos = write_decimal(row, 4, used);
    if pos < DISPLAY_COLS {
        row[pos] = b'/';
        pos += 1;
    }
    let _ = write_decimal(row, pos, cap);
}

fn write_gap_row(row: &mut [u8; DISPLAY_COLS], local_after: u64, last_userop: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Gap: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let gap = local_after.saturating_sub(last_userop);
    pos = write_decimal(row, pos, gap);
    let _ = pos;
}

fn write_msg_footer(row: &mut [u8; DISPLAY_COLS], page: usize, total: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    let prefix = b"Msg ";
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, page as u64);
    if pos < DISPLAY_COLS {
        row[pos] = b'/';
        pos += 1;
    }
    pos = write_decimal(row, pos, total as u64);
    // Tail "> next" if there's room.
    let nav = b"  > next";
    if pos + nav.len() <= DISPLAY_COLS {
        row[pos..pos + nav.len()].copy_from_slice(nav);
    }
}

fn write_decimal(row: &mut [u8; DISPLAY_COLS], pos: usize, mut n: u64) -> usize {
    let mut buf = [0u8; 20];
    let mut len = 0usize;
    if n == 0 {
        if pos < DISPLAY_COLS {
            row[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut p = pos;
    for i in 0..len {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = buf[len - 1 - i];
        p += 1;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(deployed: bool) -> OffchainConfirmContext {
        OffchainConfirmContext::new(
            3, 1, 7, 11, [0x55; 20], deployed, 42, 37, 65_536, [0xA7; 32],
        )
    }

    fn trimmed(row: &[u8; DISPLAY_COLS]) -> &str {
        let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        core::str::from_utf8(&row[..end]).unwrap()
    }

    #[test]
    fn offchain_context_suffix_is_complete_exact_and_mode_distinct() {
        let deployed = context(true);
        let mut pages = Pages::with_len(2);
        let prior = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        append_eip1271_context_pages(&mut pages, &deployed, &mut cfi).unwrap();

        assert_eq!(pages.len, prior + OFFCHAIN_CONTEXT_PAGES);
        assert_eq!(trimmed(&pages.buf[prior][0]), "Offchain signer");
        assert_eq!(trimmed(&pages.buf[prior][1]), "Account: 7");
        assert_eq!(trimmed(&pages.buf[prior][2]), "Slot: 11");
        assert_eq!(trimmed(&pages.buf[prior + 1][0]), "Signing wallet");
        let mut rendered_addr = [0u8; 42];
        rendered_addr[..16].copy_from_slice(&pages.buf[prior + 1][1]);
        rendered_addr[16..32].copy_from_slice(&pages.buf[prior + 1][2]);
        rendered_addr[32..42].copy_from_slice(&pages.buf[prior + 1][3][..10]);
        assert_eq!(&rendered_addr[..2], b"0x");
        assert_eq!(rendered_addr.len(), 42);
        assert_eq!(trimmed(&pages.buf[prior + 2][0]), "DEPLOYED EIP1271");
        assert_eq!(trimmed(&pages.buf[prior + 2][1]), "Use 42/65536");
        assert_eq!(trimmed(&pages.buf[prior + 2][2]), "Gap: 5");
        assert_eq!(trimmed(&pages.buf[prior + 2][3]), "L cancel/R sign");

        assert_eq!(
            cfi.check_into_sentinel(OFFCHAIN_CONTEXT_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            eip1271_context_page_proof(&pages, prior, &deployed),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            eip1271_context_final_set_proof(&pages, prior, &deployed),
            crate::fi::OK_SENTINEL
        );

        let undeployed = context(false);
        assert_ne!(
            eip1271_context_final_set_proof(&pages, prior, &undeployed),
            crate::fi::OK_SENTINEL
        );
        let mut undeployed_pages = Pages::with_len(0);
        let mut undeployed_cfi = crate::fi::CfiCounter::new();
        append_eip1271_context_pages(&mut undeployed_pages, &undeployed, &mut undeployed_cfi)
            .unwrap();
        assert_eq!(trimmed(&undeployed_pages.buf[2][0]), "ERC-6492 WRAPPED");
    }

    #[test]
    fn offchain_context_proofs_reject_corruption_duplicate_and_page_overflow() {
        let context = context(true);
        let mut pages = Pages::with_len(1);
        let prior = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        append_eip1271_context_pages(&mut pages, &context, &mut cfi).unwrap();
        pages.buf[prior + 1][2][4] ^= 1;
        assert_ne!(
            eip1271_context_page_proof(&pages, prior, &context),
            crate::fi::OK_SENTINEL
        );

        let expected = build_context_pages(&context);
        let mut duplicate = Pages::with_len(1);
        duplicate.buf[0] = expected[0];
        let duplicate_prior = duplicate.len;
        let mut duplicate_cfi = crate::fi::CfiCounter::new();
        append_eip1271_context_pages(&mut duplicate, &context, &mut duplicate_cfi).unwrap();
        assert_ne!(
            eip1271_context_page_proof(&duplicate, duplicate_prior, &context),
            crate::fi::OK_SENTINEL
        );

        let mut full = Pages::with_len(super::super::MAX_PAGES - 2);
        let before = full.len;
        let mut full_cfi = crate::fi::CfiCounter::new();
        assert!(append_eip1271_context_pages(&mut full, &context, &mut full_cfi).is_err());
        assert_eq!(full.len, before, "page-budget refusal must be atomic");
    }

    #[test]
    fn offchain_confirmation_receipt_is_fail_initialized_and_context_bound() {
        let expected = context(true);
        let mut receipt = OffchainConfirmReceipt::new();
        receipt.fail_initialize();
        assert_ne!(receipt.completion_proof(&expected), crate::fi::OK_SENTINEL);

        receipt.record_confirmed(&expected).unwrap();
        assert_eq!(receipt.completion_proof(&expected), crate::fi::OK_SENTINEL);
        assert!(receipt.record_confirmed(&expected).is_err());

        let mut wrong_kind = expected;
        wrong_kind.kind ^= 1;
        let mut wrong_account = expected;
        wrong_account.account_index ^= 1;
        let mut wrong_slot = expected;
        wrong_slot.slot_index ^= 1;
        let mut wrong_wallet = expected;
        wrong_wallet.wallet_addr[0] ^= 1;
        let mut wrong_mode = expected;
        wrong_mode.account_deployed = false;
        let mut wrong_budget = expected;
        wrong_budget.local_offchain_after += 1;
        let mut wrong_hash = expected;
        wrong_hash.hash_to_sign[31] ^= 1;
        for changed in [
            wrong_kind,
            wrong_account,
            wrong_slot,
            wrong_wallet,
            wrong_mode,
            wrong_budget,
            wrong_hash,
        ] {
            assert_ne!(receipt.completion_proof(&changed), crate::fi::OK_SENTINEL);
        }

        receipt.fail_initialize();
        assert_ne!(receipt.completion_proof(&expected), crate::fi::OK_SENTINEL);
    }
}
