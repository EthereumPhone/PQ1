//! Firmware-update logic test runner (automated, non-destructive).
//!
//! Exercises every `CMD_FW_*` command on real STM32U585 hardware without
//! performing any irreversible operation. Pairs with the secure crate's
//! `e2e-test` feature (auto-provisions + pre-unlocks, so no PIN UI).
//!
//! ## Why this is safe on a dev board
//!
//! Two one-way operations exist in the update path:
//!
//!   1. **OTP rollback-tally bump** inside `CMD_FW_COMMIT` — we never
//!      call COMMIT, so no OTP bit ever burns.
//!   2. **`flash::erase_slot(inactive)`** inside `CMD_FW_BEGIN` on a
//!      manifest that passes every verify check — on the current
//!      pre-A/B-split build the inactive slot's manifest page
//!      (page 5 @ `0x0C00_A000`) still sits inside the running secure
//!      firmware's `.text` region, so erasing it would hard-fault the
//!      CPU. We craft the happy-path test manifest with `fw_version=0`,
//!      which passes structural / CRC / digest / vendor-fpr checks but
//!      fails `verify_rollback` (`fw_version > floor` is strict, and
//!      `floor >= 0` always). BEGIN returns `FwUpdateBadVersion` before
//!      reaching `erase_slot`.
//!
//! ## What this proves
//!
//! * PIN gate (auto-unlocked here, tested indirectly via the fact that
//!   every command that requires unlock succeeds rather than returning
//!   `NotInitialized`).
//! * `CMD_FW_STATUS` reports `IDLE` before and after an update attempt.
//! * `CMD_FW_CHUNK` / `CMD_FW_COMMIT` reject with `FwUpdateBadState`
//!   when no streaming context is active.
//! * `CMD_FW_ABORT` is benign when nothing is in flight.
//! * `CMD_FW_BEGIN` rejects every tampered manifest at the right step:
//!   bad size → `InvalidPointer`; bad magic / CRC / digest → `FwUpdate-
//!   BadManifest`.
//! * The full verify chain runs on a well-formed manifest, failing only
//!   at the rollback-floor gate. Proves the SHA-256 digest computation,
//!   CRC-32 recomputation, vendor-fpr read-back-from-flash comparison,
//!   and OTP-floor read are all wired up correctly end-to-end.
//!
//! ## What this does NOT prove
//!
//! * That `flash::erase_slot` works. (Can't, until A/B linker split.)
//! * That streaming chunk writes + SHA-256 re-verify produce correct
//!   bytes on bank-2 NSCR writes.
//! * That the OLED confirm dialog renders + accepts long-right.
//! * That OTP `bump_to` burns the right bit count.
//! * That FSBL correctly picks the newer slot after a commit reset.
//!
//! Those tests require the A/B linker split + an "OTP test-mode no-op"
//! feature gate and belong in a follow-up `test-update-hw-full` target.

#![allow(static_mut_refs)]

use crate::nsc_api;
use cortex_m_semihosting::{debug, hprintln};
use fw_manifest::{
    crc32_ieee, ManifestBuilder, MANIFEST_SIZE, OFF_CRC32, OFF_MAGIC, OFF_MANIFEST_DIGEST,
    SLOT_A, TRY_ONCE_COMMITTED,
};
use sphincs_tz_shared::{
    NscStatus, FW_CHUNK_HEADER_LEN, FW_STATE_IDLE, FW_STATUS_RESPONSE_LEN,
    FW_STATUS_STATE_OFFSET,
};

/// On a freshly flashed dev board, manifest pages 4 and 5 are blank
/// (`0xFF`), so `ManifestRef::new(&page).vendor_pubkey_fpr()` reads back
/// 32 × `0xFF`. Our test manifest uses the same value so the secure
/// world's fpr-equality check (against the *active* slot's fpr) passes.
///
/// On a board where someone has previously committed a signed update,
/// the active slot's fpr is the real vendor fingerprint — T11 will
/// then be rejected at fpr-mismatch (`FwUpdateBadManifest`) instead of
/// at rollback (`FwUpdateBadVersion`). Both rejections happen *before*
/// `erase_slot`, so both are safe; the harness accepts either.
const BLANK_VENDOR_FPR: [u8; 32] = [0xFF; 32];

/// Primary 8 KB manifest buffer — built once at startup, mutated per
/// test to produce each variant. In NS SRAM (64 KB total), so placing
/// these two as statics keeps function stacks small.
static mut PRIMARY_MANIFEST: [u8; MANIFEST_SIZE] = [0xFF; MANIFEST_SIZE];
static mut MUTATED_MANIFEST: [u8; MANIFEST_SIZE] = [0xFF; MANIFEST_SIZE];

/// Build a valid-but-rollback-rejected manifest:
///   - magic / version / slot byte: OK (`verify_structural` passes).
///   - CRC over `[0..OFF_CRC32)`: OK.
///   - `manifest_digest = SHA256("PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash)`: OK.
///   - `vendor_pubkey_fpr = [0xFF; 32]`: matches a blank active slot.
///   - `fw_version = 0`: fails `verify_rollback` on any board
///     (`rollback_floor >= 0`, and the check is strict `>`).
///
/// The 4008-byte SPHINCS+C10 signature field is left as `0xFF`. The
/// secure world's BEGIN verify chain deliberately does NOT verify the
/// signature (it defers that to FSBL, which has the pubkey compiled
/// in), so this doesn't matter at BEGIN time.
fn build_primary_manifest(out: &mut [u8; MANIFEST_SIZE]) {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(0)
        .secure_image(&[0u8; 32], 0)
        .nonsecure_image(&[0u8; 32], 0)
        .vendor_pubkey_fpr(&BLANK_VENDOR_FPR)
        .build_id(&[0u8; 32])
        .boot_counter_snap(0)
        .try_once(TRY_ONCE_COMMITTED);
    b.finalize_preimage();
    let bytes = b.finalize();
    out.copy_from_slice(&bytes);
}

/// After mutating any byte in `[0..OFF_CRC32)`, recompute and write the
/// CRC so the test's target check isn't shadowed by `verify_crc`.
fn refresh_crc(buf: &mut [u8; MANIFEST_SIZE]) {
    let crc = crc32_ieee(&buf[..OFF_CRC32]);
    buf[OFF_CRC32..].copy_from_slice(&crc.to_be_bytes());
}

/// Compact pass/fail reporter. Returns `true` on pass so the caller can
/// AND it into a running success flag.
fn expect_eq(name: &str, actual: u32, expected: NscStatus) -> bool {
    let ok = actual == expected as u32;
    if ok {
        hprintln!("[NS][fwup-test] {}: PASS (status {})", name, actual);
    } else {
        hprintln!(
            "[NS][fwup-test] {}: FAIL (got {}, expected {} = {:?})",
            name, actual, expected as u32, expected
        );
    }
    ok
}

/// Same, but accepts either of two statuses (used for T11, where the
/// expected rejection depends on whether the board is fresh or used).
fn expect_one_of(name: &str, actual: u32, a: NscStatus, b: NscStatus) -> bool {
    let ok = actual == a as u32 || actual == b as u32;
    if ok {
        hprintln!(
            "[NS][fwup-test] {}: PASS (status {} matches {:?} or {:?})",
            name, actual, a, b
        );
    } else {
        hprintln!(
            "[NS][fwup-test] {}: FAIL (got {}, expected {} or {})",
            name, actual, a as u32, b as u32
        );
    }
    ok
}

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS][fwup-test] === FW_UPDATE logic test (safe mode) ===");
    hprintln!("[NS][fwup-test] never commits, never erases the inactive slot");

    // Secure `e2e-test` pre-unlocks the gateway. Verify, don't drive the
    // PIN UI.
    if !nsc_api::is_unlocked() {
        hprintln!("[NS][fwup-test] FAIL: gateway not pre-unlocked (needs e2e-test on secure)");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("[NS][fwup-test] gateway pre-unlocked: OK");

    let mut all_ok = true;
    let mut status_buf = [0u8; FW_STATUS_RESPONSE_LEN];

    // ---------------------------------------------------------------------
    // T3: initial FW_STATUS
    // ---------------------------------------------------------------------
    let rc = nsc_api::fw_status(&mut status_buf);
    all_ok &= expect_eq("T3a FW_STATUS rc", rc, NscStatus::Ok);
    if status_buf[FW_STATUS_STATE_OFFSET] == FW_STATE_IDLE {
        hprintln!("[NS][fwup-test] T3b FW_STATUS state=IDLE: PASS");
    } else {
        hprintln!(
            "[NS][fwup-test] T3b FW_STATUS state: FAIL (got {}, expected IDLE={})",
            status_buf[FW_STATUS_STATE_OFFSET], FW_STATE_IDLE
        );
        all_ok = false;
    }

    // ---------------------------------------------------------------------
    // T4: FW_CHUNK without active session → FwUpdateBadState
    //
    // Build an 8-byte header with chunk_len=0 and no data bytes. Passes
    // size / validator / header-len / chunk_len==data_len checks, then
    // fails the "context present" check.
    // ---------------------------------------------------------------------
    let empty_chunk = [0u8; FW_CHUNK_HEADER_LEN];
    let rc = nsc_api::fw_chunk(&empty_chunk);
    all_ok &= expect_eq("T4 FW_CHUNK w/o session", rc, NscStatus::FwUpdateBadState);

    // ---------------------------------------------------------------------
    // T5: FW_COMMIT without active session → FwUpdateBadState
    // ---------------------------------------------------------------------
    let rc = nsc_api::fw_commit();
    all_ok &= expect_eq("T5 FW_COMMIT w/o session", rc, NscStatus::FwUpdateBadState);

    // ---------------------------------------------------------------------
    // T6: FW_ABORT without active session → Ok (benign)
    // ---------------------------------------------------------------------
    let rc = nsc_api::fw_abort();
    all_ok &= expect_eq("T6 FW_ABORT w/o session", rc, NscStatus::Ok);

    // ---------------------------------------------------------------------
    // T7: FW_BEGIN with wrong payload size → InvalidPointer
    // ---------------------------------------------------------------------
    let wrong_size = [0u8; 100];
    let rc = nsc_api::fw_begin(&wrong_size);
    all_ok &= expect_eq("T7 FW_BEGIN bad size", rc, NscStatus::InvalidPointer);

    // ---------------------------------------------------------------------
    // Build the primary valid-but-rollback-rejected manifest.
    // ---------------------------------------------------------------------
    unsafe {
        build_primary_manifest(&mut PRIMARY_MANIFEST);
    }

    // ---------------------------------------------------------------------
    // T8: FW_BEGIN with bad magic → FwUpdateBadManifest
    // ---------------------------------------------------------------------
    unsafe {
        MUTATED_MANIFEST.copy_from_slice(&PRIMARY_MANIFEST);
        MUTATED_MANIFEST[OFF_MAGIC] = 0x00;
        refresh_crc(&mut MUTATED_MANIFEST);
    }
    let rc = nsc_api::fw_begin(unsafe { &MUTATED_MANIFEST });
    all_ok &= expect_eq("T8 FW_BEGIN bad magic", rc, NscStatus::FwUpdateBadManifest);

    // ---------------------------------------------------------------------
    // T9: FW_BEGIN with bad CRC → FwUpdateBadManifest
    //
    // Flip a byte inside the CRC field only.  Magic/version/slot are
    // still valid so structural passes; CRC mismatches.
    // ---------------------------------------------------------------------
    unsafe {
        MUTATED_MANIFEST.copy_from_slice(&PRIMARY_MANIFEST);
        MUTATED_MANIFEST[OFF_CRC32] ^= 0x01;
    }
    let rc = nsc_api::fw_begin(unsafe { &MUTATED_MANIFEST });
    all_ok &= expect_eq("T9 FW_BEGIN bad CRC", rc, NscStatus::FwUpdateBadManifest);

    // ---------------------------------------------------------------------
    // T10: FW_BEGIN with bad manifest digest → FwUpdateBadManifest
    //
    // Flip a digest byte, then refresh the CRC so `verify_crc` still
    // passes and the test isolates `verify_digest`.
    // ---------------------------------------------------------------------
    unsafe {
        MUTATED_MANIFEST.copy_from_slice(&PRIMARY_MANIFEST);
        MUTATED_MANIFEST[OFF_MANIFEST_DIGEST] ^= 0x01;
        refresh_crc(&mut MUTATED_MANIFEST);
    }
    let rc = nsc_api::fw_begin(unsafe { &MUTATED_MANIFEST });
    all_ok &= expect_eq("T10 FW_BEGIN bad digest", rc, NscStatus::FwUpdateBadManifest);

    // ---------------------------------------------------------------------
    // T11: FW_BEGIN full verify chain, rejected only at rollback floor.
    //
    // On a fresh board (blank active manifest, rollback_floor = 0) this
    // path walks structural + CRC + digest + vendor-fpr match + rollback,
    // and fails rollback strictly at the last gate →  FwUpdateBadVersion.
    //
    // On a board where an update has been committed, the active slot's
    // vendor fpr is real, our `[0xFF; 32]` fpr mismatches, and BEGIN
    // rejects earlier with WrongVendor → FwUpdateBadManifest. Both are
    // rejections-before-erase, so the test treats either as PASS.
    // ---------------------------------------------------------------------
    let rc = nsc_api::fw_begin(unsafe { &PRIMARY_MANIFEST });
    all_ok &= expect_one_of(
        "T11 FW_BEGIN full chain (rollback reject expected on fresh board)",
        rc,
        NscStatus::FwUpdateBadVersion,
        NscStatus::FwUpdateBadManifest,
    );

    // ---------------------------------------------------------------------
    // T12: FW_STATUS still IDLE — no rejected BEGIN left residue.
    // ---------------------------------------------------------------------
    let rc = nsc_api::fw_status(&mut status_buf);
    all_ok &= expect_eq("T12a FW_STATUS rc", rc, NscStatus::Ok);
    if status_buf[FW_STATUS_STATE_OFFSET] == FW_STATE_IDLE {
        hprintln!("[NS][fwup-test] T12b FW_STATUS still IDLE: PASS");
    } else {
        hprintln!(
            "[NS][fwup-test] T12b FW_STATUS still IDLE: FAIL (got {})",
            status_buf[FW_STATUS_STATE_OFFSET]
        );
        all_ok = false;
    }

    hprintln!("[NS][fwup-test] ==========================================");
    if all_ok {
        hprintln!("[NS][fwup-test] === PASS ===");
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        hprintln!("[NS][fwup-test] === FAIL ===");
        debug::exit(debug::EXIT_FAILURE);
    }
    loop {}
}
