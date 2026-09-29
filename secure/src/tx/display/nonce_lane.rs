//! EntryPoint v0.6 nonce-lane trusted-display binding.
//!
//! A v0.6 nonce is `uint192 key || uint64 sequence`. The ordinary
//! transaction renderers show the sequence, but two otherwise-identical
//! UserOps on different keys are independently executable. Hiding the key
//! therefore lets a hostile companion present a second payment as a harmless
//! retry on the same `Nonce: 0` screen.
//!
//! Lane zero remains the compact/common path. For every non-zero lane this
//! module appends one exact page containing all 24 key bytes (48 lowercase
//! hex characters). The handler then calls [`nonce_lane_page_proof`] before
//! confirmation: it independently proves either that the key is zero and no
//! page was inserted, or that exactly one byte-for-byte-correct page was
//! inserted. A skipped conditional, inserter call, or proof call therefore
//! fails closed.

use super::primitives;
use super::Pages;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Worst-case page budget reserved by UserOp renderers. The page is emitted
/// only for a non-zero lane, but reserving it unconditionally keeps the
/// multiSend budget independent of a faultable skip predicate.
pub(crate) const NONZERO_NONCE_LANE_PAGES: usize = 1;

const NONCE_LANE_CFI_STEP: u32 = 0xC715_2AE3;
pub(crate) const NONCE_LANE_CFI_EXPECTED: u32 = crate::cfi_expected!(NONCE_LANE_CFI_STEP);

type NonceLanePage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Append the exact 192-bit EntryPoint nonce key when it is non-zero.
///
/// The page is written exactly at the caller-recorded prior length. Lane zero
/// appends nothing but still publishes the caller-owned completion receipt. A
/// required page that cannot fit returns `Err(())`; every caller maps that to
/// refusal. Append-only construction never shifts a signer/target page after
/// that page's independent FI completion proof.
#[inline(never)]
pub(crate) fn enforce_nonce_lane_page(
    pages: &mut Pages,
    nonce: &[u8; 32],
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    // The safe fast path is taken only after two independently-evaluated
    // zero-lane checks produce the Hamming-distant OK sentinel. Scrub first
    // so a skipped sentinel call cannot reuse an earlier display proof's r0.
    crate::fi::scrub_sentinel_register();
    let may_skip =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(nonce_lane_is_zero(nonce)));
    if may_skip == crate::fi::OK_SENTINEL {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        cfi.bump(NONCE_LANE_CFI_STEP);
        return Ok(());
    }

    let page = build_nonce_lane_page(nonce);
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(NONCE_LANE_CFI_STEP);
    Ok(())
}

/// Exact all-64-byte predicate for the non-zero nonce-lane page.
pub(crate) fn nonce_lane_page_matches(pages: &Pages, page_index: usize, nonce: &[u8; 32]) -> bool {
    let expected = build_nonce_lane_page(nonce);
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    nonce_page_exact(actual, &expected)
}

/// Exact completed-skip proof for the compact lane-zero path.
#[inline(never)]
pub(crate) fn nonce_lane_skip_proof(pages: &Pages, prior_len: usize, nonce: &[u8; 32]) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(nonce_lane_is_zero(nonce))
            && core::hint::black_box(pages.len == prior_len)
    })
}

/// FI-hardened completion/skip proof for [`enforce_nonce_lane_page`].
///
/// The caller records `prior_len`, calls the non-inlined inserter, scrubs the
/// ABI return register, and accepts only [`crate::fi::OK_SENTINEL`] here.
/// The predicate recomputes the high-192 zero test on both internal FI passes:
///
/// * lane zero requires the page count to remain exactly unchanged;
/// * a non-zero lane requires exactly one new page at the deterministic
///   insertion index, with all 64 bytes matching the signed nonce key.
#[inline(never)]
pub(crate) fn nonce_lane_page_proof(pages: &Pages, prior_len: usize, nonce: &[u8; 32]) -> u32 {
    let expected = build_nonce_lane_page(nonce);
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(nonce_lane_is_zero(nonce)) {
            core::hint::black_box(pages.len == prior_len)
        } else {
            prior_len
                .checked_add(NONZERO_NONCE_LANE_PAGES)
                .is_some_and(|expected_len| {
                    core::hint::black_box(pages.len == expected_len)
                        && nonce_lane_page_matches(pages, prior_len, nonce)
                        && nonce_page_occurrences(pages, &expected) == 1
                })
        }
    })
}

pub(crate) fn nonce_lane_is_zero(nonce: &[u8; 32]) -> bool {
    let mut aggregate = 0u8;
    for &byte in &nonce[..24] {
        aggregate |= byte;
    }
    aggregate == 0
}

pub(crate) fn build_nonce_lane_page(nonce: &[u8; 32]) -> NonceLanePage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    primitives::write_line(&mut page[0], "Nonce lane key:");
    for (i, &byte) in nonce[..24].iter().enumerate() {
        let row = 1 + i / 8;
        let col = (i % 8) * 2;
        page[row][col] = primitives::hex_nibble(byte >> 4);
        page[row][col + 1] = primitives::hex_nibble(byte & 0x0f);
    }
    page
}

fn nonce_page_exact(actual: &NonceLanePage, expected: &NonceLanePage) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

fn nonce_page_occurrences(pages: &Pages, expected: &NonceLanePage) -> usize {
    pages
        .as_slice()
        .iter()
        .filter(|actual| nonce_page_exact(actual, expected))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_nonce(pages: &mut Pages, nonce: &[u8; 32]) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_nonce_lane_page(pages, nonce, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(NONCE_LANE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn nonzero_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        for (i, byte) in nonce[..24].iter_mut().enumerate() {
            *byte = i as u8;
        }
        nonce[0] = 0xab;
        nonce[24..].copy_from_slice(&7u64.to_be_bytes());
        nonce
    }

    #[test]
    fn zero_lane_appends_nothing_and_proves_skip() {
        let mut nonce = [0u8; 32];
        nonce[24..].copy_from_slice(&99u64.to_be_bytes());
        let mut pages = Pages::with_len(3);
        append_nonce(&mut pages, &nonce);
        assert_eq!(pages.len, 3);
        assert_eq!(
            nonce_lane_page_proof(&pages, 3, &nonce),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn nonzero_lane_shows_all_192_bits_exactly() {
        let nonce = nonzero_nonce();
        let mut pages = Pages::with_len(3);
        append_nonce(&mut pages, &nonce);
        assert_eq!(pages.len, 4);
        assert_eq!(&pages.buf[3][0], b"Nonce lane key: ");
        assert_eq!(&pages.buf[3][1], b"ab01020304050607");
        assert_eq!(&pages.buf[3][2], b"08090a0b0c0d0e0f");
        assert_eq!(&pages.buf[3][3], b"1011121314151617");
        assert!(nonce_lane_page_matches(&pages, 3, &nonce));
        assert_eq!(
            nonce_lane_page_proof(&pages, 3, &nonce),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn every_lane_byte_is_bound_but_sequence_is_not_duplicated() {
        let nonce = nonzero_nonce();
        let mut pages = Pages::with_len(1);
        append_nonce(&mut pages, &nonce);
        for i in 0..24 {
            let mut changed = nonce;
            changed[i] ^= 1;
            assert!(!nonce_lane_page_matches(&pages, 1, &changed));
        }
        for i in 24..32 {
            let mut changed = nonce;
            changed[i] ^= 1;
            assert!(nonce_lane_page_matches(&pages, 1, &changed));
        }
    }

    #[test]
    fn zero_detector_requires_all_24_lane_bytes_to_be_zero() {
        for i in 0..24 {
            let mut nonce = [0u8; 32];
            nonce[i] = 1;
            let mut pages = Pages::with_len(1);
            append_nonce(&mut pages, &nonce);
            assert_eq!(pages.len, 2, "lane byte {i} was ignored");
            assert_eq!(
                nonce_lane_page_proof(&pages, 1, &nonce),
                crate::fi::OK_SENTINEL,
                "lane byte {i} did not prove"
            );
        }
    }

    #[test]
    fn proof_rejects_skipped_or_corrupted_nonzero_page() {
        let nonce = nonzero_nonce();
        let mut pages = Pages::with_len(2);
        assert_ne!(
            nonce_lane_page_proof(&pages, 2, &nonce),
            crate::fi::OK_SENTINEL
        );
        append_nonce(&mut pages, &nonce);
        assert_eq!(
            nonce_lane_page_proof(&pages, 2, &nonce),
            crate::fi::OK_SENTINEL
        );
        pages.buf[2][3][15] ^= 1;
        assert_ne!(
            nonce_lane_page_proof(&pages, 2, &nonce),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn nonzero_lane_fails_closed_when_full_but_zero_lane_still_fits() {
        let mut full = Pages::with_len(super::super::MAX_PAGES);
        let mut nonzero_cfi = crate::fi::CfiCounter::new();
        assert!(enforce_nonce_lane_page(&mut full, &nonzero_nonce(), &mut nonzero_cfi).is_err());
        assert_eq!(full.len, super::super::MAX_PAGES);
        let mut zero_cfi = crate::fi::CfiCounter::new();
        assert!(enforce_nonce_lane_page(&mut full, &[0u8; 32], &mut zero_cfi).is_ok());
        assert_eq!(full.len, super::super::MAX_PAGES);
    }

    #[test]
    fn target_and_nonce_lane_coexist_without_post_proof_shift() {
        let mut pages = Pages::with_len(1);
        let sender = [0x11; 20];
        let target = [0x22; 20];
        let nonce = nonzero_nonce();

        let signer_prior = pages.len;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        super::super::value_page::enforce_from_page(&mut pages, 0, &sender, &mut signer_cfi)
            .unwrap();
        assert_eq!(
            super::super::value_page::from_page_proof(&pages, signer_prior, 0, &sender),
            crate::fi::OK_SENTINEL
        );

        let target_prior = pages.len;
        let mut target_cfi = crate::fi::CfiCounter::new();
        super::super::value_page::enforce_target_page(&mut pages, &target, &mut target_cfi)
            .unwrap();
        assert_eq!(
            super::super::value_page::target_page_proof(&pages, target_prior, &target),
            crate::fi::OK_SENTINEL
        );

        let lane_prior = pages.len;
        append_nonce(&mut pages, &nonce);
        assert_eq!(
            nonce_lane_page_proof(&pages, lane_prior, &nonce),
            crate::fi::OK_SENTINEL
        );
        assert!(super::super::value_page::target_page_matches(
            &pages, 2, &target
        ));
        assert!(nonce_lane_page_matches(&pages, 3, &nonce));

        pages.buf[2][1][0] ^= 1;
        assert!(!super::super::value_page::target_page_matches(
            &pages, 2, &target
        ));
        pages.buf[2][1][0] ^= 1;
        pages.buf[3][1][0] ^= 1;
        assert!(!nonce_lane_page_matches(&pages, 3, &nonce));
    }

    #[test]
    fn nonce_append_preserves_unique_prefix_and_uses_exact_fit_slot() {
        let nonce = nonzero_nonce();
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        for page_index in 0..pages.len {
            let marker = 0x20u8.wrapping_add(page_index as u8);
            for row in &mut pages.buf[page_index] {
                row.fill(marker);
            }
        }
        let prior_len = pages.len;
        let before = pages.buf;
        append_nonce(&mut pages, &nonce);
        assert_eq!(pages.len, super::super::MAX_PAGES);
        assert_eq!(&pages.buf[..prior_len], &before[..prior_len]);
        assert_eq!(
            nonce_lane_page_proof(&pages, prior_len, &nonce),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn nonce_zero_skip_needs_completion_cfi_even_when_structure_matches() {
        let mut nonce = [0u8; 32];
        nonce[31] = 9;
        let mut pages = Pages::with_len(2);
        let prior_len = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        assert_eq!(
            nonce_lane_skip_proof(&pages, prior_len, &nonce),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            cfi.check_into_sentinel(NONCE_LANE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "a skipped whole enforcer must leave caller-owned CFI short"
        );
        enforce_nonce_lane_page(&mut pages, &nonce, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(NONCE_LANE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            nonce_lane_page_proof(&pages, prior_len, &nonce),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn nonce_proof_rejects_right_content_at_wrong_index_and_duplicates() {
        let nonce = nonzero_nonce();
        let mut pages = Pages::with_len(2);
        for row in &mut pages.buf[0] {
            row.fill(b'A');
        }
        for row in &mut pages.buf[1] {
            row.fill(b'B');
        }
        let prior_len = pages.len;
        append_nonce(&mut pages, &nonce);
        pages.buf.swap(0, prior_len);
        assert_ne!(
            nonce_lane_page_proof(&pages, prior_len, &nonce),
            crate::fi::OK_SENTINEL
        );

        pages.buf.swap(0, prior_len);
        pages.buf[0] = pages.buf[prior_len];
        assert_ne!(
            nonce_lane_page_proof(&pages, prior_len, &nonce),
            crate::fi::OK_SENTINEL
        );
    }
}
