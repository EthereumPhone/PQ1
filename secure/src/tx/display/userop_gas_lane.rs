//! EntryPoint v0.6 UserOperation gas-triple trusted-display binding (finding F10).
//!
//! The signed userOpHash commits `callGasLimit`, `verificationGasLimit`, and
//! `preVerificationGas` as three independent, ordered 256-bit words
//! (`aa::userop::compute_sphincs_digest_v06`). The generic Safe/CoW envelope
//! renderer previously showed only their saturated `u64` aggregate
//! (`tx.gas_limit`), so two UserOperations whose gas triple is a permutation
//! with the same sum — e.g. `(call=100000, verification=200000)` vs
//! `(call=200000, verification=100000)` — produced byte-identical confirmation
//! pages even though the signed digest differed. A hostile companion could thus
//! misallocate gas (inner-call OOG griefing / bundler over-pay via
//! preVerificationGas) behind an unchanged screen — a WYSIWYS-injectivity break.
//!
//! This lane renders all three exact values (plus their `Total:`, the same
//! aggregate the envelope shows) on one page, and the handler independently
//! FI-proves that page materialized. Unlike the nonce lane there is no
//! compact/skip fast path: the page is ALWAYS inserted and ALWAYS proved, so a
//! skipped inserter or proof call fails closed. The handler is the only
//! producer, including for ERC-7730. Every UserOp dispatch branch (value
//! transfer, ERC-20, Safe v1/exec, CoW, ERC-7730, blind, typed-call) relies on
//! this handler-level gate for gas injectivity.

use super::Pages;
use crate::tx::eip1559::U256;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Page budget reserved by every UserOp renderer for the gas triple (F10).
/// Unlike [`super::nonce_lane::NONZERO_NONCE_LANE_PAGES`] this is unconditional
/// — the page is always emitted, so the reservation is always one.
pub(crate) const USEROP_GAS_PAGES: usize = 1;

type GasLanePage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GasScan {
    exact: usize,
    near_shaped: usize,
}

impl GasScan {
    const EMPTY: Self = Self {
        exact: 0,
        near_shaped: 0,
    };
}

const USEROP_GAS_CFI_STEP: u32 = 0x94C2_6B3D;
pub(crate) const USEROP_GAS_CFI_EXPECTED: u32 = crate::cfi_expected!(USEROP_GAS_CFI_STEP);

/// Append the exact call / verification / pre-verification gas page after all
/// already-rendered semantic pages and before the handler-owned fingerprint.
///
/// Returns `Err(())` if the page buffer is full, any gas value is too wide to
/// render faithfully in `DISPLAY_COLS`, or the pre-insertion set already
/// contains an exact/near-shaped gas page. Every caller maps that to refusal
/// (fail closed — the finding's "render the exact three gas values … or refuse"
/// contract). The forward/reverse pre-scan is deliberately repeated by the
/// independently called completion proof after insertion. Appending at the
/// prior length is load-bearing: unlike an in-place splice, it cannot drop or
/// corrupt an already-rendered semantic page if a shift loop is faulted. The
/// caller-owned CFI counter is bumped only after the page and length have been
/// published, so a skipped whole call remains observable at confirmation.
#[inline(never)]
pub(crate) fn enforce_userop_gas_page(
    pages: &mut Pages,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    let page = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas).ok_or(())?;
    let forward = scan_gas_pages_forward(pages, &page);
    let reverse = scan_gas_pages_reverse(pages, &page);
    if forward != GasScan::EMPTY || reverse != GasScan::EMPTY || forward != reverse {
        return Err(());
    }
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(USEROP_GAS_CFI_STEP);
    Ok(())
}

/// Exact all-4-row predicate for the gas page.
pub(crate) fn userop_gas_page_matches(
    pages: &Pages,
    page_index: usize,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> bool {
    let Some(expected) = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas)
    else {
        return false;
    };
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    gas_page_exact(actual, &expected)
}

fn gas_page_exact(actual: &GasLanePage, expected: &GasLanePage) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

fn row_starts_with(row: &[u8; DISPLAY_COLS], prefix: &[u8]) -> bool {
    prefix.len() <= DISPLAY_COLS && row[..prefix.len()] == *prefix
}

/// A non-canonical page is "near-shaped" when at least two of the four gas
/// lane labels remain in their canonical rows. This catches a conflicting gas
/// split or a single-fault-corrupted canonical page without treating a generic
/// semantic page containing only a `Total:` row as a second gas lane.
fn gas_page_near_shaped(page: &GasLanePage) -> bool {
    let markers = usize::from(row_starts_with(&page[0], b"Call:"))
        + usize::from(row_starts_with(&page[1], b"Verify:"))
        + usize::from(row_starts_with(&page[2], b"PreVer:"))
        + usize::from(row_starts_with(&page[3], b"Total:"));
    markers >= 2
}

fn classify_gas_page(page: &GasLanePage, expected: &GasLanePage, scan: &mut GasScan) {
    if gas_page_exact(page, expected) {
        scan.exact += 1;
    } else if gas_page_near_shaped(page) {
        scan.near_shaped += 1;
    }
}

/// First half of the A/B global scan. Kept non-inlined so the forward and
/// reverse traversals remain distinct operations in optimized firmware.
#[inline(never)]
fn scan_gas_pages_forward(pages: &Pages, expected: &GasLanePage) -> GasScan {
    let mut scan = GasScan::EMPTY;
    for page in pages.as_slice() {
        classify_gas_page(page, expected, &mut scan);
    }
    scan
}

/// Second half of the A/B global scan, walking the visible set in reverse.
#[inline(never)]
fn scan_gas_pages_reverse(pages: &Pages, expected: &GasLanePage) -> GasScan {
    let mut scan = GasScan::EMPTY;
    for page in pages.as_slice().iter().rev() {
        classify_gas_page(page, expected, &mut scan);
    }
    scan
}

/// FI-hardened completion proof for [`enforce_userop_gas_page`].
///
/// The caller records `prior_len`, calls the non-inlined inserter, scrubs the
/// ABI return register, and accepts only [`crate::fi::OK_SENTINEL`] here. The
/// predicate requires exactly one new page, the canonical page at the
/// append-only prior-length index, exactly one canonical match across the full
/// visible set, and no near-shaped conflict. The expected bytes and both global
/// scans are recomputed independently of the inserter. A skipped inserter,
/// duplicate/conflicting producer, length error, or proof call fails closed.
#[inline(never)]
pub(crate) fn userop_gas_page_proof(
    pages: &Pages,
    prior_len: usize,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let Some(expected) = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas)
        else {
            return false;
        };
        let forward = scan_gas_pages_forward(pages, &expected);
        let reverse = scan_gas_pages_reverse(pages, &expected);
        prior_len
            .checked_add(USEROP_GAS_PAGES)
            .is_some_and(|expected_len| {
                core::hint::black_box(pages.len == expected_len)
                    && core::hint::black_box(forward == reverse)
                    && core::hint::black_box(
                        forward
                            == GasScan {
                                exact: 1,
                                near_shaped: 0,
                            },
                    )
                    && pages
                        .as_slice()
                        .get(prior_len)
                        .is_some_and(|actual| gas_page_exact(actual, &expected))
            })
    })
}

/// Final-confirmation boundary proof for the complete page set.
///
/// Callers append all later mandatory pages (currently the complete ERC-8213
/// fingerprint) and then invoke this immediately before `confirm_checked`.
/// Unlike [`userop_gas_page_proof`], this does not require `prior_len + 1`
/// because later append-only gates legitimately grow the set. It independently
/// rebuilds the canonical page and A/B scans every final visible page, accepting
/// exactly one canonical match and no near-shaped conflict.
#[inline(never)]
pub(crate) fn userop_gas_final_set_proof(
    pages: &Pages,
    expected_index: usize,
    call_gas: &[u8; 32],
    verification_gas: &[u8; 32],
    pre_verification_gas: &[u8; 32],
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let Some(expected) = build_gas_lane_page(call_gas, verification_gas, pre_verification_gas)
        else {
            return false;
        };
        let forward = scan_gas_pages_forward(pages, &expected);
        let reverse = scan_gas_pages_reverse(pages, &expected);
        core::hint::black_box(forward == reverse)
            && core::hint::black_box(
                forward
                    == GasScan {
                        exact: 1,
                        near_shaped: 0,
                    },
            )
            && pages
                .as_slice()
                .get(expected_index)
                .is_some_and(|actual| gas_page_exact(actual, &expected))
    })
}

/// Big-endian `[u8; 32]` → `u128`, saturating when the high 128 bits are set.
fn to_u128_saturating(v: &[u8; 32]) -> u128 {
    if v[..16].iter().any(|&b| b != 0) {
        return u128::MAX;
    }
    match v[16..].try_into() {
        Ok(a) => u128::from_be_bytes(a),
        Err(_) => u128::MAX,
    }
}

/// Saturating `u64` total — the same value as the handler's `display_gas_limit`
/// and the envelope's aggregate gas page, so `Total:` here reconciles with it.
fn gas_total_u64(call: &[u8; 32], verify: &[u8; 32], prever: &[u8; 32]) -> u64 {
    to_u128_saturating(call)
        .saturating_add(to_u128_saturating(verify))
        .saturating_add(to_u128_saturating(prever))
        .min(u64::MAX as u128) as u64
}

pub(crate) fn build_gas_lane_page(
    call: &[u8; 32],
    verify: &[u8; 32],
    prever: &[u8; 32],
) -> Option<GasLanePage> {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    write_gas_row(&mut page[0], b"Call:", &U256(*call))?;
    write_gas_row(&mut page[1], b"Verify:", &U256(*verify))?;
    write_gas_row(&mut page[2], b"PreVer:", &U256(*prever))?;
    let total = gas_total_u64(call, verify, prever);
    let mut total_bytes = [0u8; 32];
    total_bytes[24..].copy_from_slice(&total.to_be_bytes());
    write_gas_row(&mut page[3], b"Total:", &U256(total_bytes))?;
    Some(page)
}

/// Render `prefix` followed by the decimal of `value` into one row, space-padded.
///
/// `None` if `prefix.len() + digits` does not fit `DISPLAY_COLS` (a gas value too
/// large to show faithfully → the caller refuses). This is the sole canonical
/// gas-triple row writer; semantic renderers must leave this lane to the handler.
fn write_gas_row(row: &mut [u8; DISPLAY_COLS], prefix: &[u8], value: &U256) -> Option<()> {
    *row = [b' '; DISPLAY_COLS];
    let mut digits = [0u8; 80];
    let n = value.format_decimal(0, 0, false, &mut digits)?;
    if prefix.len().checked_add(n)? > DISPLAY_COLS {
        return None;
    }
    row[..prefix.len()].copy_from_slice(prefix);
    row[prefix.len()..prefix.len() + n].copy_from_slice(&digits[..n]);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gas(n: u64) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[24..].copy_from_slice(&n.to_be_bytes());
        v
    }

    fn enforce_with_cfi(
        pages: &mut Pages,
        call: &[u8; 32],
        verification: &[u8; 32],
        pre_verification: &[u8; 32],
    ) -> Result<crate::fi::CfiCounter, ()> {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_userop_gas_page(pages, call, verification, pre_verification, &mut cfi)?;
        assert_eq!(
            cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "successful append must complete the caller-owned CFI receipt"
        );
        Ok(cfi)
    }

    #[test]
    fn gas_page_inserted_and_proved() {
        let (c, v, p) = (gas(100_000), gas(200_000), gas(21_000));
        let mut pages = Pages::with_len(4);
        assert!(enforce_with_cfi(&mut pages, &c, &v, &p).is_ok());
        assert_eq!(pages.len, 5);
        assert_eq!(&pages.buf[4][0], b"Call:100000     ");
        assert_eq!(&pages.buf[4][1], b"Verify:200000   ");
        assert_eq!(&pages.buf[4][2], b"PreVer:21000    ");
        assert_eq!(&pages.buf[4][3], b"Total:321000    ");
        assert_eq!(
            userop_gas_page_proof(&pages, 4, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn permuted_gas_triple_yields_distinct_pages() {
        // (call, verification) swapped, same sum: the aggregate `Total:` is
        // identical but the component rows differ, so the page is NOT the same —
        // exactly the collision the old aggregate-only display allowed.
        let a = build_gas_lane_page(&gas(100_000), &gas(200_000), &gas(21_000)).unwrap();
        let b = build_gas_lane_page(&gas(200_000), &gas(100_000), &gas(21_000)).unwrap();
        assert_eq!(a[3], b[3], "totals must match (same sum)");
        assert_ne!(a, b, "permuting the gas split must change the page");

        let mut pages = Pages::with_len(4);
        enforce_with_cfi(&mut pages, &gas(100_000), &gas(200_000), &gas(21_000)).unwrap();
        assert!(userop_gas_page_matches(
            &pages,
            4,
            &gas(100_000),
            &gas(200_000),
            &gas(21_000)
        ));
        assert!(!userop_gas_page_matches(
            &pages,
            4,
            &gas(200_000),
            &gas(100_000),
            &gas(21_000)
        ));
    }

    #[test]
    fn every_component_is_bound() {
        let (c, v, p) = (gas(111), gas(222), gas(333));
        let mut pages = Pages::with_len(1);
        enforce_with_cfi(&mut pages, &c, &v, &p).unwrap();
        assert!(userop_gas_page_matches(&pages, 1, &c, &v, &p));
        assert!(!userop_gas_page_matches(&pages, 1, &gas(112), &v, &p));
        assert!(!userop_gas_page_matches(&pages, 1, &c, &gas(223), &p));
        assert!(!userop_gas_page_matches(&pages, 1, &c, &v, &gas(334)));
    }

    #[test]
    fn proof_rejects_skipped_or_corrupted_page() {
        let (c, v, p) = (gas(1), gas(2), gas(3));
        let mut pages = Pages::with_len(2);
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        enforce_with_cfi(&mut pages, &c, &v, &p).unwrap();
        assert_eq!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        pages.buf[2][0][5] ^= 1;
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn append_only_preserves_every_existing_semantic_page_and_cfi() {
        let (c, v, p) = (gas(10), gas(20), gas(30));
        let mut pages = Pages::with_len(6);
        for index in 0..pages.len {
            pages.buf[index] = [[b'A' + index as u8; DISPLAY_COLS]; DISPLAY_ROWS];
        }
        let before = pages.buf;

        let cfi = enforce_with_cfi(&mut pages, &c, &v, &p).unwrap();
        assert_eq!(pages.len, 7);
        assert_eq!(
            &pages.buf[..6],
            &before[..6],
            "append-only gas ownership must never shift or rewrite semantic pages"
        );
        assert_eq!(
            userop_gas_page_proof(&pages, 6, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            userop_gas_final_set_proof(&pages, 6, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            userop_gas_final_set_proof(&pages, 4, &c, &v, &p),
            crate::fi::OK_SENTINEL,
            "the final boundary must retain the append-only position"
        );

        let skipped_call_cfi = crate::fi::CfiCounter::new();
        assert_ne!(
            skipped_call_cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "a skipped whole append call must leave caller-owned CFI short"
        );
    }

    #[test]
    fn inserter_rejects_preexisting_exact_page() {
        let (c, v, p) = (gas(1), gas(2), gas(3));
        let mut pages = Pages::with_len(1);
        pages.buf[0] = build_gas_lane_page(&c, &v, &p).unwrap();
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_userop_gas_page(&mut pages, &c, &v, &p, &mut cfi).is_err());
        assert_ne!(
            cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            pages.len, 1,
            "pre-existing exact page must remain unchanged"
        );
    }

    #[test]
    fn inserter_rejects_preexisting_near_shaped_page() {
        let (c, v, p) = (gas(10), gas(20), gas(30));
        let mut conflict = build_gas_lane_page(&c, &v, &p).unwrap();
        conflict[1][7] = b'9'; // `Verify:20` -> a conflicting `Verify:90`.
        assert!(gas_page_near_shaped(&conflict));
        assert!(!gas_page_exact(
            &conflict,
            &build_gas_lane_page(&c, &v, &p).unwrap()
        ));

        let mut pages = Pages::with_len(2);
        pages.buf[1] = conflict;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_userop_gas_page(&mut pages, &c, &v, &p, &mut cfi).is_err());
        assert_ne!(
            cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            pages.len, 2,
            "near-shaped conflict must not be spliced around"
        );
    }

    #[test]
    fn global_proof_rejects_duplicate_exact_page() {
        let (c, v, p) = (gas(7), gas(8), gas(9));
        let canonical = build_gas_lane_page(&c, &v, &p).unwrap();
        let mut pages = Pages::with_len(3);
        pages.buf[0] = canonical;
        pages.buf[2] = canonical;
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL,
            "a correct expected slot must not hide a second global copy"
        );
    }

    #[test]
    fn global_proof_rejects_near_shaped_conflict() {
        let (c, v, p) = (gas(7), gas(8), gas(9));
        let canonical = build_gas_lane_page(&c, &v, &p).unwrap();
        let mut conflict = canonical;
        conflict[3][6] = b'0'; // Wrong total, intact canonical shape.
        let mut pages = Pages::with_len(3);
        pages.buf[0] = conflict;
        pages.buf[2] = canonical;
        assert_ne!(
            userop_gas_page_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL,
            "a correct page must not coexist with a conflicting gas-shaped page"
        );
    }

    #[test]
    fn final_set_proof_accepts_later_unrelated_pages() {
        let (c, v, p) = (gas(7), gas(8), gas(9));
        let mut pages = Pages::with_len(2);
        let cfi = enforce_with_cfi(&mut pages, &c, &v, &p).unwrap();
        pages.push_blank().unwrap();
        pages.push_blank().unwrap();
        assert_eq!(
            cfi.check_into_sentinel(USEROP_GAS_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            userop_gas_final_set_proof(&pages, 2, &c, &v, &p),
            crate::fi::OK_SENTINEL,
            "later fingerprint pages must preserve the unique gas proof"
        );
    }

    #[test]
    fn final_set_proof_rejects_late_duplicate_or_conflict() {
        let (c, v, p) = (gas(7), gas(8), gas(9));
        let canonical = build_gas_lane_page(&c, &v, &p).unwrap();
        let mut pages = Pages::with_len(1);
        enforce_with_cfi(&mut pages, &c, &v, &p).unwrap();

        let duplicate = pages.push_blank().unwrap();
        pages.buf[duplicate] = canonical;
        assert_ne!(
            userop_gas_final_set_proof(&pages, 1, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );

        pages.buf[duplicate] = canonical;
        pages.buf[duplicate][0][5] = b'6';
        assert_ne!(
            userop_gas_final_set_proof(&pages, 1, &c, &v, &p),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn single_marker_is_not_a_near_shaped_gas_page() {
        let mut semantic_total = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        semantic_total[3][..6].copy_from_slice(b"Total:");
        assert!(!gas_page_near_shaped(&semantic_total));
    }

    #[test]
    fn oversized_gas_value_fails_closed() {
        // ~78-digit value cannot be shown faithfully in DISPLAY_COLS.
        let huge = [0xFFu8; 32];
        let mut pages = Pages::with_len(1);
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_userop_gas_page(&mut pages, &huge, &gas(1), &gas(1), &mut cfi).is_err());
        assert_eq!(pages.len, 1, "no page inserted on refuse");
    }

    #[test]
    fn fails_closed_when_buffer_full() {
        let mut full = Pages::with_len(super::super::MAX_PAGES);
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_userop_gas_page(&mut full, &gas(1), &gas(2), &gas(3), &mut cfi).is_err());
        assert_eq!(full.len, super::super::MAX_PAGES);
    }
}
