//! End-to-end render tests for the Safe-mgmt OLED renderer.
//!
//! The production renderer at `tx::display::safe_mgmt` is gated
//! `#[cfg(not(test))]` (it lives under the same `tx::display` cfg
//! umbrella the rest of the renderers do). This module pulls the
//! source in via the parallel scaffold at
//! `crate::display_under_test::safe_mgmt` and asserts the resulting
//! 4-row × 16-col OLED pages byte-for-byte against the strings a user
//! would actually see on the device.
//!
//! Why this exists: existing tests cover the host-runnable parser
//! (`tx::eip712::safe::mgmt_decode::tests`) and the bind+classify
//! e2e chain (`tx::eip712::safe::extra_tests::safe_mgmt_*_e2e`).
//! Neither exercises the OLED row strings. A regression that changed
//! `"! MULTISIG OFF"` to `"MULTISIG OFF"` or swapped two address
//! pages would not have been caught by any unit test. These tests
//! pin the user-visible text.

use crate::names::NameResolver;
use crate::tx::eip712::safe::mgmt_decode::{SafeMgmtOp, ThresholdValue};
use crate::ui::DISPLAY_COLS;

use super::safe_mgmt::render_safe_mgmt_pages;
use super::Pages;

// ───────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────

const FIXTURE_CHAIN_ID: u64 = 1; // Mainnet
const FIXTURE_SAFE_ADDR: [u8; 20] = [
    0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
];
const ADDR_A: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];
const ADDR_B: [u8; 20] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x02, 0x03, 0x04,
];
const ADDR_C: [u8; 20] = [
    0xfe, 0xed, 0xfa, 0xce, 0xba, 0xbe, 0xca, 0xfe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42,
];
/// Safe's singly-linked-list sentinel marking "first item in the list".
const SENTINEL: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 0x01;
    a
};

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    // The renderer ASCII-pads every row to DISPLAY_COLS with spaces.
    // Convert to string for readable assertions; rtrim trailing spaces
    // so tests can assert on the meaningful prefix.
    let s = std::str::from_utf8(row).expect("every row is ASCII");
    s.trim_end_matches(' ').to_string()
}

fn render(op: &SafeMgmtOp, pages_needed: usize) -> Pages {
    // Caller allocates exactly the number of pages the op needs.
    let mut pages = Pages::with_len(pages_needed);
    let resolver = NameResolver::new();
    let next = render_safe_mgmt_pages(
        &mut pages,
        0,
        op,
        FIXTURE_CHAIN_ID,
        &FIXTURE_SAFE_ADDR,
        &resolver,
    );
    assert_eq!(
        next, pages_needed,
        "renderer must fill exactly `pages_needed` slots"
    );
    pages
}

// ───────────────────────────────────────────────────────────────────────
// addOwnerWithThreshold
// ───────────────────────────────────────────────────────────────────────

#[test]
fn add_owner_with_threshold_pages_no_risk() {
    let op = SafeMgmtOp::AddOwnerWithThreshold {
        new_owner: ADDR_A,
        new_threshold: ThresholdValue::Fits(3),
    };
    let pages = render(&op, 2);

    // P0: intent + threshold + (no risk row) + nav
    assert_eq!(row_str(&pages.buf[0][0]), "Add Safe owner");
    assert_eq!(row_str(&pages.buf[0][1]), "New thrshld: 3");
    assert_eq!(row_str(&pages.buf[0][2]), ""); // no risk
    assert_eq!(row_str(&pages.buf[0][3]), "> next");

    // P1: "New owner:" label + full address (3 rows of 8+8+4 hex)
    assert_eq!(row_str(&pages.buf[1][0]), "New owner:");
    // The address render uses write_addr_full_or_name; on a resolver miss
    // it falls through to write_addr_full (raw hex). We only check that
    // the rows contain the expected hex prefix and suffix — the exact
    // layout is asserted at row-level so refactors don't silently break.
    let p1r1 = row_str(&pages.buf[1][1]);
    // `write_addr_full` row1 = "0x" + first 7 bytes of address = 16 cols
    // exact (2 + 14 hex chars).
    assert_eq!(p1r1, "0xa0b86991c6218b");
}

#[test]
fn add_owner_with_threshold_one_renders_multisig_off_risk() {
    let op = SafeMgmtOp::AddOwnerWithThreshold {
        new_owner: ADDR_A,
        new_threshold: ThresholdValue::Fits(1),
    };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "Add Safe owner");
    assert_eq!(row_str(&pages.buf[0][1]), "New thrshld: 1");
    assert_eq!(row_str(&pages.buf[0][2]), "! MULTISIG OFF");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");
}

#[test]
fn add_owner_with_threshold_overflow_surfaces_marker() {
    let op = SafeMgmtOp::AddOwnerWithThreshold {
        new_owner: ADDR_A,
        new_threshold: ThresholdValue::Overflow,
    };
    let pages = render(&op, 2);
    // `"New thrshld: " + "!>2^16"` packs into 16 cols: 13 + 6 = 19 → the
    // formatter truncates the suffix to fit the remaining 3 cols.
    let r1 = row_str(&pages.buf[0][1]);
    assert!(
        r1.starts_with("New thrshld: "),
        "overflow row must keep prefix label: got {r1:?}"
    );
    assert!(
        r1.contains("!>"),
        "overflow row must carry the >2^16 marker: got {r1:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// removeOwner
// ───────────────────────────────────────────────────────────────────────

#[test]
fn remove_owner_pages_with_sentinel_prev() {
    let op = SafeMgmtOp::RemoveOwner {
        prev_owner: SENTINEL,
        owner: ADDR_A,
        new_threshold: ThresholdValue::Fits(2),
    };
    let pages = render(&op, 3);

    // P0: intent + threshold + (no risk) + nav
    assert_eq!(row_str(&pages.buf[0][0]), "Remove Safe ownr");
    assert_eq!(row_str(&pages.buf[0][1]), "New thrshld: 2");
    assert_eq!(row_str(&pages.buf[0][2]), "");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");

    // P1: owner being removed — label + full address
    assert_eq!(row_str(&pages.buf[1][0]), "Removing:");

    // P2: linked-list pointer — label + SENTINEL marker + nav
    assert_eq!(row_str(&pages.buf[2][0]), "Prev (list ptr):");
    assert_eq!(row_str(&pages.buf[2][1]), "prev: SENTINEL");
    assert_eq!(row_str(&pages.buf[2][2]), "");
    assert_eq!(row_str(&pages.buf[2][3]), "> next");
}

#[test]
fn remove_owner_with_non_sentinel_prev_uses_short_form() {
    // Prev points to a real owner address (not the linked-list start).
    // The renderer falls back to the `prv:0xAABB..CCDD` short form.
    let op = SafeMgmtOp::RemoveOwner {
        prev_owner: ADDR_B,
        owner: ADDR_A,
        new_threshold: ThresholdValue::Fits(2),
    };
    let pages = render(&op, 3);

    let row = row_str(&pages.buf[2][1]);
    assert!(
        row.starts_with("prv:0x"),
        "non-sentinel prev row must use short-form label: got {row:?}"
    );
    assert!(
        row.contains(".."),
        "short-form must include `..` ellipsis: got {row:?}"
    );
    // Includes leading and trailing bytes of ADDR_B (00 11 .. 03 04).
    assert!(
        row.contains("0011") && row.contains("0304"),
        "short-form must include first 2 and last 2 bytes of ADDR_B: got {row:?}"
    );
}

#[test]
fn remove_owner_to_one_renders_multisig_off_risk() {
    let op = SafeMgmtOp::RemoveOwner {
        prev_owner: SENTINEL,
        owner: ADDR_A,
        new_threshold: ThresholdValue::Fits(1),
    };
    let pages = render(&op, 3);
    assert_eq!(row_str(&pages.buf[0][2]), "! MULTISIG OFF");
}

// ───────────────────────────────────────────────────────────────────────
// swapOwner
// ───────────────────────────────────────────────────────────────────────

#[test]
fn swap_owner_pages_show_old_and_new() {
    let op = SafeMgmtOp::SwapOwner {
        prev_owner: ADDR_B,
        old_owner: ADDR_A,
        new_owner: ADDR_C,
    };
    let pages = render(&op, 3);
    assert_eq!(row_str(&pages.buf[0][0]), "Swap Safe owner");
    let prev_row = row_str(&pages.buf[0][2]);
    assert!(
        prev_row.starts_with("prv:0x"),
        "swapOwner P0 must hint the prev pointer on row 2: got {prev_row:?}"
    );
    assert_eq!(row_str(&pages.buf[1][0]), "Old owner:");
    assert_eq!(row_str(&pages.buf[2][0]), "New owner:");
    // ADDR_C starts with feedfaceba — confirm the full-address renderer
    // routed to the new-owner page, not the old-owner page.
    let r1 = row_str(&pages.buf[2][1]);
    assert!(
        r1.starts_with("0xfeedfaceba"),
        "new-owner page must render ADDR_C, not ADDR_A: got {r1:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// changeThreshold
// ───────────────────────────────────────────────────────────────────────

#[test]
fn change_threshold_no_risk() {
    let op = SafeMgmtOp::ChangeThreshold {
        new_threshold: ThresholdValue::Fits(3),
    };
    let pages = render(&op, 1);
    assert_eq!(row_str(&pages.buf[0][0]), "Change thrshld");
    assert_eq!(row_str(&pages.buf[0][1]), "New thrshld: 3");
    assert_eq!(row_str(&pages.buf[0][2]), "");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");
}

#[test]
fn change_threshold_one_renders_multisig_off_risk() {
    let op = SafeMgmtOp::ChangeThreshold {
        new_threshold: ThresholdValue::Fits(1),
    };
    let pages = render(&op, 1);
    assert_eq!(row_str(&pages.buf[0][2]), "! MULTISIG OFF");
}

#[test]
fn change_threshold_zero_renders_thrshld_zero_risk() {
    // Safe rejects N=0 on-chain but the firmware must still surface
    // it faithfully — a faithful display + an unmistakable warning
    // is the right behaviour here (cf. plan: "faithful render even
    // when on-chain would revert").
    let op = SafeMgmtOp::ChangeThreshold {
        new_threshold: ThresholdValue::Fits(0),
    };
    let pages = render(&op, 1);
    assert_eq!(row_str(&pages.buf[0][1]), "New thrshld: 0");
    assert_eq!(row_str(&pages.buf[0][2]), "! THRSHLD = 0");
}

// ───────────────────────────────────────────────────────────────────────
// enableModule
// ───────────────────────────────────────────────────────────────────────

#[test]
fn enable_module_always_loud_banner() {
    let op = SafeMgmtOp::EnableModule { module: ADDR_A };
    let pages = render(&op, 2);
    // P0: loud risk banner — modules can exec any tx on the Safe
    assert_eq!(row_str(&pages.buf[0][0]), "! ENABLE MODULE");
    assert_eq!(row_str(&pages.buf[0][1]), "Grants exec auth");
    assert_eq!(row_str(&pages.buf[0][2]), "to module addr");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");
    // P1: module address (full)
    assert_eq!(row_str(&pages.buf[1][0]), "Module addr:");
    let r1 = row_str(&pages.buf[1][1]);
    assert!(
        r1.starts_with("0xa0b86991"),
        "enableModule must show full module address: got {r1:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// disableModule
// ───────────────────────────────────────────────────────────────────────

#[test]
fn disable_module_shows_prev_hint_and_full_module() {
    let op = SafeMgmtOp::DisableModule {
        prev_module: SENTINEL,
        module: ADDR_A,
    };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "Disable module");
    assert_eq!(row_str(&pages.buf[0][2]), "prev: SENTINEL");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");
    assert_eq!(row_str(&pages.buf[1][0]), "Module addr:");
}

// ───────────────────────────────────────────────────────────────────────
// setGuard
// ───────────────────────────────────────────────────────────────────────

#[test]
fn set_guard_install_loud_banner_plus_full_address() {
    let op = SafeMgmtOp::SetGuard { guard: ADDR_C };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "! CHANGE GUARD");
    assert_eq!(row_str(&pages.buf[0][1]), "Grants veto/log");
    assert_eq!(row_str(&pages.buf[0][2]), "on every tx");
    assert_eq!(row_str(&pages.buf[0][3]), "> next");
    assert_eq!(row_str(&pages.buf[1][0]), "Guard addr:");
    let r1 = row_str(&pages.buf[1][1]);
    assert!(
        r1.starts_with("0xfeedfaceba"),
        "guard address page must render ADDR_C: got {r1:?}"
    );
}

#[test]
fn set_guard_zero_renders_removing_guard() {
    let op = SafeMgmtOp::SetGuard {
        guard: [0u8; 20],
    };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "! CHANGE GUARD");
    assert_eq!(row_str(&pages.buf[0][1]), "REMOVING GUARD");
    assert_eq!(row_str(&pages.buf[1][0]), "Guard addr:");
    // For removal, the renderer prints a literal "(none / cleared)" on
    // row 1 of P1 rather than the address-full layout — the user should
    // see the human-readable cleared marker, not 60 zero hex chars.
    assert_eq!(row_str(&pages.buf[1][1]), "(none / cleared)");
}

// ───────────────────────────────────────────────────────────────────────
// setFallbackHandler
// ───────────────────────────────────────────────────────────────────────

#[test]
fn set_fallback_handler_install_loud_banner() {
    let op = SafeMgmtOp::SetFallbackHandler { handler: ADDR_C };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "! CHG FALLBACK");
    assert_eq!(row_str(&pages.buf[0][1]), "Runs unkn calls");
    assert_eq!(row_str(&pages.buf[1][0]), "Handler addr:");
    let r1 = row_str(&pages.buf[1][1]);
    assert!(r1.starts_with("0xfeedfaceba"));
}

#[test]
fn set_fallback_handler_zero_renders_removing_fb() {
    let op = SafeMgmtOp::SetFallbackHandler {
        handler: [0u8; 20],
    };
    let pages = render(&op, 2);
    assert_eq!(row_str(&pages.buf[0][0]), "! CHG FALLBACK");
    assert_eq!(row_str(&pages.buf[0][1]), "REMOVING FB");
    assert_eq!(row_str(&pages.buf[1][1]), "(none / cleared)");
}

// ───────────────────────────────────────────────────────────────────────
// Universal invariants — every page is ASCII, every row exactly 16 cols
// ───────────────────────────────────────────────────────────────────────

#[test]
fn every_rendered_row_is_ascii_and_padded_to_16() {
    // Sweep every variant once; assert no renderer ever writes a non-
    // printable byte or leaves a row at a length other than 16.
    let zero = [0u8; 20];
    let ops: [(SafeMgmtOp, usize); 12] = [
        (
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner: ADDR_A,
                new_threshold: ThresholdValue::Fits(3),
            },
            2,
        ),
        (
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner: ADDR_A,
                new_threshold: ThresholdValue::Fits(1),
            },
            2,
        ),
        (
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner: ADDR_A,
                new_threshold: ThresholdValue::Overflow,
            },
            2,
        ),
        (
            SafeMgmtOp::RemoveOwner {
                prev_owner: SENTINEL,
                owner: ADDR_A,
                new_threshold: ThresholdValue::Fits(2),
            },
            3,
        ),
        (
            SafeMgmtOp::SwapOwner {
                prev_owner: ADDR_B,
                old_owner: ADDR_A,
                new_owner: ADDR_C,
            },
            3,
        ),
        (
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(2),
            },
            1,
        ),
        (
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(1),
            },
            1,
        ),
        (
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(0),
            },
            1,
        ),
        (SafeMgmtOp::EnableModule { module: ADDR_A }, 2),
        (
            SafeMgmtOp::DisableModule {
                prev_module: SENTINEL,
                module: ADDR_A,
            },
            2,
        ),
        (SafeMgmtOp::SetGuard { guard: zero }, 2),
        (SafeMgmtOp::SetFallbackHandler { handler: ADDR_C }, 2),
    ];

    for (op, count) in &ops {
        let pages = render(op, *count);
        for (pi, p) in pages.as_slice().iter().enumerate() {
            for (ri, row) in p.iter().enumerate() {
                assert_eq!(
                    row.len(),
                    DISPLAY_COLS,
                    "page {pi} row {ri} not 16 cols wide"
                );
                for (ci, &b) in row.iter().enumerate() {
                    assert!(
                        b == b' ' || (0x21..=0x7e).contains(&b),
                        "page {pi} row {ri} col {ci} non-printable byte 0x{b:02x}"
                    );
                }
            }
        }
    }
}
