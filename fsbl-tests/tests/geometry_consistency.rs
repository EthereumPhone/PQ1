//! Geometry-consistency pins tying the linker scripts and the FSBL legacy
//! layout to the frozen §5 flash-geometry registry (`pqsigner-geometry`).
//!
//! Foundation A slice FA-1.1 (issue #540). Two geometry worlds exist:
//!
//!   * The FROZEN §5 registry (`geometry/src/lib.rs`) — the cutover target.
//!   * The deliberate LEGACY bench layout that the live code encodes today
//!     (manifests at bank-1 pages 4/5, boot-state page 6, secure slots
//!     7–64/65–122, NS slots bank-2 0–63/64–127, 32 KiB FSBL pages 0–3).
//!     It is production-fenced and serves already-signed legacy artifacts.
//!
//! These tests pin, in the `source_invariants.rs` textual style:
//!
//!   1. `secure/memory-stm32u585.x` — the secure link already ends at
//!      bank-1 page 123, exactly where the registry's persistent-data
//!      pages (123–127) begin; the script's comment page-table must match
//!      the registry's owners for those pages.
//!   2. `nonsecure/memory-stm32u585.x` — ORIGIN/LENGTH pinned as
//!      DELIBERATE LEGACY (whole-bank NS link predates the frozen
//!      geometry; cutover tracked in #540).
//!   3. `fsbl/memory-stm32u585.x` — 32K FLASH LENGTH pinned as
//!      DELIBERATE LEGACY (same pointer).
//!   4. `fsbl/src/slot.rs` — the legacy slot layout constants pinned as
//!      DELIBERATE LEGACY. These pins MUST fail if anyone silently shifts
//!      them toward or away from the registry outside the cutover slice.

#![forbid(unsafe_code)]

use pqsigner_geometry::{owner_of, page_addr, updater_must_preserve, Bank, Owner, BANK1_BASE, PAGE_SIZE};
use std::fs;

fn read_workspace_file(rel: &str) -> String {
    // Walk up to the workspace root, same shape as source_invariants.rs.
    let mut p = std::env::current_dir().expect("cwd");
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            let s = fs::read_to_string(&candidate).unwrap_or_default();
            if s.contains("[workspace]") {
                return fs::read_to_string(p.join(rel))
                    .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            }
        }
        if !p.pop() {
            panic!("no [workspace] Cargo.toml above cwd");
        }
    }
}

// ---------------------------------------------------------------------------
// 1. secure/memory-stm32u585.x — secure FLASH ends where registry pages
//    123–127 begin, and the comment page-table matches the registry owners.
// ---------------------------------------------------------------------------

#[test]
fn secure_linker_flash_origin_and_length_match_registry() {
    let src = read_workspace_file("secure/memory-stm32u585.x");
    assert!(
        src.contains("FLASH : ORIGIN = 0x0C000000, LENGTH = 984K"),
        "secure FLASH must start at the bank-1 secure alias and stop before \
         the persistent-data pages (123–127)"
    );
    assert_eq!(BANK1_BASE, 0x0C00_0000);
    // 984 KiB = bank-1 pages 0..123: the link region ends exactly at the
    // first registry-owned persistent-data page (123, off-chain journal).
    assert_eq!(page_addr(Bank::One, 123) - BANK1_BASE, 984 * 1024);
    assert_eq!(PAGE_SIZE, 0x2000);
}

#[test]
fn secure_linker_comment_page_table_matches_registry_owners() {
    let src = read_workspace_file("secure/memory-stm32u585.x");
    // (page, registry owner, linker-script comment line)
    let expected: [(u8, Owner, &str); 5] = [
        (
            123,
            Owner::OffchainJournal,
            "page 123 (0x0C0F6000) = per-slot off-chain/UserOp signature journal",
        ),
        (
            124,
            Owner::McuPinState,
            "page 124 (0x0C0F8000) = MCU PIN-attempt counter",
        ),
        (
            125,
            Owner::AdminWipeDuress,
            "page 125 (0x0C0FA000) = SE050 admin-wipe state (PIN at QW0, flag at QW1)",
        ),
        (
            126,
            Owner::WrappedBhk,
            "page 126 (0x0C0FC000) = wrapped SE050 BHK (`bhk` only; otherwise reserved)",
        ),
        (
            127,
            Owner::FirstBootJournal,
            "page 127 (0x0C0FE000) = first-boot provisioning journal",
        ),
    ];
    for (page, owner, comment_line) in expected {
        assert!(
            src.contains(comment_line),
            "secure/memory-stm32u585.x must document page {page} as: {comment_line}"
        );
        assert_eq!(
            owner_of(Bank::One, page),
            Some(owner),
            "registry owner of bank-1 page {page} must be {owner:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. nonsecure/memory-stm32u585.x — DELIBERATE LEGACY whole-bank link.
// ---------------------------------------------------------------------------

#[test]
fn nonsecure_linker_whole_bank_link_is_deliberate_legacy() {
    // DELIBERATE LEGACY: the NS image links against the whole 1 MiB bank 2,
    // predating the frozen §5 geometry (which splits bank 2 into an FSBL
    // mirror, two NS slots, and a reserved page). Production-fenced; do NOT
    // "fix" toward the registry here — cutover tracked in issue #540.
    let src = read_workspace_file("nonsecure/memory-stm32u585.x");
    assert!(
        src.contains("FLASH : ORIGIN = 0x08100000, LENGTH = 1024K"),
        "DELIBERATE LEGACY whole-bank NS link (predates frozen geometry; \
         cutover tracked in #540)"
    );
}

// ---------------------------------------------------------------------------
// 3. fsbl/memory-stm32u585.x — DELIBERATE LEGACY 32K FSBL region.
// ---------------------------------------------------------------------------

#[test]
fn fsbl_linker_32k_flash_region_is_deliberate_legacy() {
    // DELIBERATE LEGACY: the bench FSBL occupies the first 32 KiB of bank 1
    // (pages 0–3), predating the frozen §5 FSBL_SPAN (5 pages, 40,960 B).
    // Production-fenced; cutover tracked in issue #540.
    let src = read_workspace_file("fsbl/memory-stm32u585.x");
    assert!(
        src.contains("FLASH : ORIGIN = 0x0C000000, LENGTH = 32K"),
        "DELIBERATE LEGACY 32 KiB FSBL link region (predates frozen \
         geometry; cutover tracked in #540)"
    );
}

// ---------------------------------------------------------------------------
// 4. fsbl/src/slot.rs — DELIBERATE LEGACY slot layout constants.
// ---------------------------------------------------------------------------

#[test]
fn fsbl_slot_layout_constants_are_deliberate_legacy() {
    // DELIBERATE LEGACY bench layout. `pqsigner-geometry`'s REGISTRY is the
    // cutover target (issue #540); until that slice lands these pins MUST
    // fail if anyone silently shifts the layout toward or away from the
    // registry.
    let src = read_workspace_file("fsbl/src/slot.rs");
    for pin in [
        "const MANIFEST_A_ADDR: usize = 0x0C00_8000;",
        "const MANIFEST_B_ADDR: usize = 0x0C00_A000;",
        "const SLOT_A_SECURE_ADDR: usize = 0x0C00_E000;",
        "const SLOT_B_SECURE_ADDR: usize = 0x0C08_2000;",
        "const SLOT_A_NS_ADDR: usize = 0x0810_0000;",
        "const SLOT_B_NS_ADDR: usize = 0x0818_0000;",
    ] {
        assert!(
            src.contains(pin),
            "DELIBERATE LEGACY fsbl/src/slot.rs layout constant changed: {pin} \
             (cutover target is the pqsigner-geometry registry, issue #540)"
        );
    }
}

/// The live NS slot A OVERLAPS the frozen registry's bank-2 FSBL mirror, and
/// the updater would therefore erase pages the registry says it must preserve.
///
/// This is the #540 cutover conflict, pinned rather than fixed. Today it is
/// HARMLESS — no recipe writes an FSBL copy to bank 2 (`make bootproof-hw` and
/// `tools/flash-evt-dfu.sh` both put only `nonsecure.bin` at `0x0810_0000`,
/// which is bank-2 page 0), so `erase_slot(Slot::A)` destroys nothing. It stops
/// being harmless the moment the mirror is actually written, which is part of
/// the cutover this test exists to make un-silent.
///
/// Recorded because it was nearly mis-triaged twice: once as a live
/// invariant-#10 violation (it is not, today), and once as "a known legacy
/// deviation" whose CONSEQUENCE — that the updater's erase range covers
/// `Owner::Fsbl` pages — is not written down anywhere the cutover would find
/// it. The deviation is pinned in this file's other tests; the consequence was
/// not.
#[test]
fn ns_slot_a_overlaps_the_registry_fsbl_mirror_until_540() {
    let flash = read_workspace_file("secure/src/hw/flash.rs");

    // The LIVE legacy NS slot A spans bank-2 pages 0..=63.
    assert!(
        flash.contains("pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;"),
        "legacy NS slot A must still start at bank-2 page 0, or this pin is stale"
    );
    assert!(flash.contains("pub const SLOT_A_NS_LAST_PAGE: u32 = 63;"));

    // The REGISTRY says bank-2 pages 0..=4 are the FSBL mirror, and that the
    // updater must preserve them.
    for page in 0..=4u8 {
        assert_eq!(
            owner_of(Bank::Two, page),
            Some(Owner::Fsbl),
            "registry: bank-2 page {page} is the FSBL mirror"
        );
        assert!(
            updater_must_preserve(Bank::Two, page),
            "registry: the updater must preserve bank-2 page {page}"
        );
    }

    // Therefore the live erase range covers registry-preserved pages. When the
    // cutover moves NS slot A off page 0 this assertion flips and the test
    // fails — which is the signal to delete it and enable a real guard in
    // `erase_slot`, not to widen it.
    assert!(
        updater_must_preserve(Bank::Two, 0),
        "CONFLICT (#540): live NS slot A starts at bank-2 page 0, which the \
         registry owns as the FSBL mirror and marks updater-preserved. Harmless \
         only because nothing writes that mirror yet. If you are reading this \
         because the test failed, the cutover has happened: replace this pin \
         with an `updater_must_preserve` guard inside `erase_slot`."
    );
}
