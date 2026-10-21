//! CMD_FW_COMMIT — legacy V1 staged-update finalizer (bench only).
//!
//! **Production-blocked:** this handler predates Draft 1.1. It used to
//! advance the rejected unary OTP floor before candidate health and
//! therefore did not provide the promised A/B rollback contract.
//! **FA-1.5 (Draft 1.1 §14 L4375, L4388–4390): the runtime floor writer
//! is REMOVED.** The legacy unary `otp::bump_to` re-programs one
//! one-program-only ECC quad-word — not retry-safe on STM32U585 — and no
//! reviewed rollback backend exists until OPEN-OTP-1..3, OPEN-ECC-1,
//! OPEN-JRN-HW-1, and OPEN-JRN-DUR-1 close. COMMIT therefore has NO
//! epoch-bump success path in any build: after the retained pre-commit
//! re-verification gates it ends in a FAIL-CLOSED REFUSAL — no OTP
//! program, no durable floor write, no reset into the staged slot BY
//! THIS HANDLER. That refusal is scoped to this handler: FSBL slot
//! selection is UNCHANGED (it re-verifies vendor fpr, signature, and
//! rollback admissibility at every boot, and the floor never moved), so
//! a staged slot whose boot-state write failed or tore can STILL be
//! selected at the next reset under the legacy try-once fall-through.
//! That is a staging-diagnosis state, not an authorization break:
//! FSBL's own re-verification is the gate, and no floor was written.
//! Production and real-vendor-key builds still compile-fail at the
//! build-script quarantine (`FW_ROLLBACK_PRODUCTION_BLOCKED` /
//! `FW_ROLLBACK_FACTORY_BLOCKED` in `secure/build.rs`).
//!
//! Runs the heavyweight checks that BEGIN could only partially do:
//!
//!   1. Drain the context (or bail if there isn't one).
//!   2. Confirm `received_*_len == expected_*_len`.
//!   3. Re-hash the written images from flash and compare against the
//!      manifest's signed hashes. Any mismatch → abort.
//!   4. Display the new measurement (8 BIP-39 words) + "Confirm
//!      update?" prompt on the NV3007 LCD. Wait for long-right.
//!   5. On confirm: write the target manifest page (`try_once = TRIED`),
//!      point the boot-state page at the new slot, re-verify from flash
//!      that the new slot is a legacy FSBL candidate, then REFUSE
//!      fail-closed (the floor write that used to follow is removed).
//!      The retained manifest/boot-state writes stage the slot for
//!      pre-production diagnosis; the handler itself performs NO
//!      activation (no floor write, no reset). FSBL slot selection is
//!      unchanged, so a torn or failed boot-state write can still leave
//!      the staged slot selected at the next reset — gated by FSBL's own
//!      manifest re-verification, never by this handler.
//!   6. On cancel: drop the context; the inactive slot stays erased.

use fw_manifest::{ManifestRef, MANIFEST_SIZE, TRY_ONCE_TRIED};
use sphincs_tz_shared::NscStatus;

use super::state::{peek_state, FW_UPDATE};
use super::{GatewayArgs, HandlerGuard};
use crate::fw_update::{self, verify::ImageCheckError};
use crate::hw::{boot_state, flash};
use crate::timeout;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. The body
/// touches the static-mut `FW_UPDATE` and OTP/flash programming
/// primitives; preconditions for each are documented at the call site.
pub(super) unsafe fn run(_args: &GatewayArgs) -> u32 {
    let _busy = HandlerGuard::enter();

    // PIN gate.
    if peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    // SAFETY: category 5 — read-only borrow of `static mut FW_UPDATE`.
    // The non-reentrant dispatcher + `HandlerGuard` above mean no
    // other code path can mutate this slot while we hold `ctx_ref`.
    let ctx_ref = unsafe { (*core::ptr::addr_of!(FW_UPDATE)).as_ref() };
    let Some(ctx) = ctx_ref else {
        return NscStatus::FwUpdateBadState as u32;
    };

    // Reset the idle activity timer — the contract documented in
    // `cmd_fw_chunk.rs` ("CHUNK does NOT reset the idle timer — BEGIN
    // already did, and COMMIT will again"). Reaching here means a live
    // FW_UPDATE context exists, i.e. this COMMIT finalizes a real,
    // user-confirmed BEGIN — not companion keepalive spam, so the
    // no-context `FwUpdateBadState` path above deliberately does NOT
    // reset (that would reopen the X17-UI3 idle-window-extension
    // pattern). The reset matters on the failure paths below: they drop
    // the context and let the host re-BEGIN, which needs a fresh 120 s
    // window rather than whatever the BEGIN→…→COMMIT transfer left over.
    timeout::reset_activity();

    // Re-hash + compare. A successful verify_images proves the bytes
    // streamed into the inactive slot match the vendor-signed manifest
    // the user already confirmed at BEGIN.
    let manifest = ManifestRef::new(&ctx.manifest_bytes);
    if let Err(e) = fw_update::verify::verify_images(ctx, &manifest) {
        // Glitch-resistance (audit: FW-COMMIT single-fault bypass). A
        // mismatch means the slot's bytes do NOT match the confirmed
        // manifest — flash corruption (brown-out) OR an attacker trying
        // to land a fault on the (now FI-hardened) `verify_images`
        // binding. DROP the streaming context either way: previously it
        // was left intact with no failure counter, so a glitch rig could
        // re-issue CMD_FW_COMMIT indefinitely — zero user interaction per
        // attempt — until a fault landed and an unsigned image committed.
        // With the context dropped, a retry requires a fresh CMD_FW_BEGIN,
        // which re-runs the F-7 manifest-signature verify AND the
        // trusted-display verifier authorization + detailed install confirm
        // before re-streaming every chunk. Each glitch attempt is now a full,
        // user-gated re-BEGIN + re-stream — not a tight in-place loop.
        //
        // We deliberately never arm the admin wipe from update failures.
        // A mismatch has benign causes (flash corruption, flaky transfer,
        // brown-out), and untrusted companion input must not be able to
        // destroy wallet state. The context drop is the non-destructive bound.
        //
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher + `HandlerGuard`. The dropped
        // `FwUpdateCtx` zeroizes its bookkeeping via `ZeroizeOnDrop`. The
        // `ctx`/`manifest` borrows are not used after this point — we
        // return immediately below.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        secure_log!(
            "[S][fwup] COMMIT verify_images FAIL ({:?}) — streaming context dropped",
            e
        );
        return match e {
            ImageCheckError::LengthMismatch | ImageCheckError::StreamingHashMismatch => {
                NscStatus::FwUpdateBadChunk as u32
            }
            ImageCheckError::SecureMismatch | ImageCheckError::NonsecureMismatch => {
                NscStatus::FwUpdateBadImage as u32
            }
        };
    }

    // No user prompt at COMMIT — finding A moved that to CMD_FW_BEGIN
    // (see fw_update::confirm_install). If `verify_images` above
    // succeeded, the bytes streamed into the inactive slot match the
    // manifest's signed hashes — the same hashes whose fingerprint
    // the user already confirmed at BEGIN — so we have everything we
    // need to commit. A `verify_images` failure already returned
    // FwUpdateBadImage/BadChunk above; COMMIT only reaches here on a
    // bit-perfect verified install.

    // Transport e2e gate (finding #25 / make fwup-transport-hw): the
    // over-USB transport test wants to validate the FULL state machine
    // + verify_images on real bytes-from-host, but MUST stop here —
    // the durable manifest/boot-state staging below is not wanted on a
    // reflashable bench chip, and the handler no longer contains an OTP
    // bump or reset arm at all (FA-1.5). Under `fwup-transport-e2e`
    // we drop the streaming ctx (zeroizing via ZeroizeOnDrop) and
    // return Ok WITHOUT writing the manifest / writing
    // boot-state / resetting. The host test interprets Ok-without-
    // reset as PASS. Fenced out of mode-production (see nsc/mod.rs).
    #[cfg(feature = "fwup-transport-e2e")]
    {
        secure_log!("[S][fwup-transport-e2e] verify_images PASS — stopping before OTP/reset");
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher. The dropped value's
        // ZeroizeOnDrop wipes the manifest copy and running hashers.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return NscStatus::Ok as u32;
    }

    // Dev units (`devunit-ab`, never production): stage the slot through the
    // dev-unit boot-log protocol and reset into the FSBL. The handler-level
    // properties above all still hold — PIN gate, verify_images first, the
    // context dropped on every exit — and `devunit::commit` zeroizes the
    // unlocked session BEFORE it schedules the reset, so no secret crosses it
    // (the boot-side scrub of a Software reset stays the second belt).
    #[cfg(feature = "devunit-ab")]
    {
        let inactive: flash::Slot = ctx.inactive.into();
        // SAFETY: `inactive` is the slot BEGIN erased and streamed, and the
        // manifest bytes are the ones BEGIN verified and the user confirmed.
        let status = unsafe { crate::fw_update::devunit::commit(inactive, &ctx.manifest_bytes) };
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher + `HandlerGuard`; `ctx` is not
        // used after this point.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return status as u32;
    }

    // -- Commit -----------------------------------------------------

    let inactive: flash::Slot = ctx.inactive.into();
    let new_version = manifest.fw_version();

    // The rollback floor a reviewed establishment path would have to land
    // at is `new_version - 1`, NOT `new_version`. `verify_rollback` (run
    // by both FSBL at boot and BEGIN) accepts a manifest only when
    // `fw_version > floor` (strict), so a floor equal to the just-
    // installed version would make FSBL reject THIS slot on the next boot
    // (`V > V` is false) and brick the device, while a floor of `V - 1`
    // lets V boot yet still rejects every release `<= V - 1` (full
    // anti-downgrade). We derive the floor from the SIGNED `fw_version`,
    // never from the manifest's unsigned `boot_counter_snap` field:
    // trusting that field would let a hostile companion lower the floor
    // at BEGIN and re-open a downgrade window. `saturating_sub` is
    // defensive — `new_version >= 1` always holds here (BEGIN's
    // `verify_rollback` already rejected `fw_version <= floor`, and
    // `floor >= 0`). Post-FA-1.5 the value feeds ONLY the retained
    // from-flash admissibility gate below; nothing programs it anywhere.
    let new_rollback_floor = new_version.saturating_sub(1);

    // LEGACY ORDERING ONLY — PARTIAL FLOW POST-FA-1.5. Moving the floor
    // write after the manifest had closed the older "floor advanced
    // before any new candidate exists" window; it never made the
    // transaction brick-safe. Draft 1.1 replaces this sequence with
    // PENDING -> ATTEMPTED -> health -> CONFIRMED -> FSBL-owned
    // establishment, and FA-1.5 removed the runtime floor writer
    // entirely: the steps below stage the slot and re-verify it, then
    // REFUSE — no OTP program, no reset.

    // 1. Write the target manifest page. The try_once_flag in the
    //    signed manifest should have been COMMITTED; we re-write it
    //    as TRIED here because the slot has not yet confirmed it
    //    boots cleanly. FSBL on the next reset sees TRIED + our
    //    matching boot-state entry. The current single-candidate selector does
    //    not provide a reliable revert after the floor excludes the old slot.
    let mut manifest_copy = ctx.manifest_bytes;
    manifest_copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED;
    // Recompute CRC since we mutated a byte.
    let new_crc = fw_manifest::crc32_ieee(&manifest_copy[..fw_manifest::OFF_CRC32]);
    manifest_copy[fw_manifest::OFF_CRC32..].copy_from_slice(&new_crc.to_be_bytes());

    // Program the manifest as 512 consecutive QWs (8 KB / 16 B).
    let manifest_addr = flash::manifest_addr(inactive);
    for qw in 0..(MANIFEST_SIZE / 16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&manifest_copy[qw * 16..qw * 16 + 16]);
        // SAFETY: `write_quadword_verified` is `unsafe fn` (bank-2
        // flash mutation, irreversible per-page). Precondition: the
        // target page lives in the inactive slot's manifest region —
        // `manifest_addr(inactive)` derives the base from
        // `ctx.inactive`, which is the slot BEGIN erased. Each call
        // here advances `qw * 16` within that erased page span, so we
        // are programming only pre-erased flash.
        if unsafe { flash::write_quadword_verified((manifest_addr + (qw * 16) as u32), &buf) }
            .is_err()
        {
            // Terminal failure: drop the context like the other failure
            // exits — retaining it would let every retried COMMIT pass
            // the live-context guard and re-reset the idle timer (an
            // X17-UI3-style keepalive; GPT-5.6 wave finding).
            // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
            // under the non-reentrant dispatcher + `HandlerGuard`.
            unsafe {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 2. Point the boot-state page at the new (tried) slot. Written only
    //    after the manifest is fully programmed (above), so the on-disk
    //    pointer can never reference a half-written manifest. This used to
    //    preserve the old slot only until the floor write that followed;
    //    post-FA-1.5 no floor write ever follows — the handler refuses
    //    instead — and this staging is diagnostic-only, not the reviewed
    //    probation contract.
    let new_boot_state = boot_state::BootState {
        active_slot: inactive,
        last_good_version: new_version,
    };
    // SAFETY: `boot_state::write` is `unsafe fn` because it programs
    // the boot-state flash page. The page lives outside both slot
    // regions and is owned exclusively by the boot-state driver; we
    // call it once, just after the manifest has been programmed, so
    // the on-disk pointer can never reference a half-written manifest.
    if unsafe { boot_state::write(&new_boot_state) }.is_err() {
        // Same terminal-failure rule as the manifest-write path above:
        // the context must not survive this return (keepalive guard).
        // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
        // under the non-reentrant dispatcher + `HandlerGuard`.
        unsafe {
            *core::ptr::addr_of_mut!(FW_UPDATE) = None;
        }
        return NscStatus::FwUpdateFlashError as u32;
    }

    // 3. Anti-brick gate: PROVE, from the bytes physically in flash, that
    //    the new slot is now a valid FSBL candidate UNDER the floor a
    //    reviewed establishment path would write. The per-quadword
    //    `write_quadword_verified` above already read each QW back, so
    //    re-running the manifest's own structural / CRC / digest checks
    //    here validates the assembled whole, and the strict
    //    `verify_rollback(new_rollback_floor)` is the keystone: it confirms
    //    `fw_version > floor` still holds for the just-committed slot.
    //    We also confirm the boot-state pointer resolves to the new slot.
    //    Any failure aborts before the (removed) floor-write point. This
    //    protects the staged-candidate case only; it is not a global
    //    brick-safety claim for the handler.
    {
        // SAFETY: `manifest_addr` is the 8 KB memory-mapped manifest page of
        // the inactive slot, fully programmed just above and not mutated
        // concurrently (non-reentrant dispatcher + `HandlerGuard`). The cast
        // yields a shared reference to readable flash for the verify only;
        // `ManifestRef` reads, never writes.
        let flash_manifest: &[u8; MANIFEST_SIZE] =
            unsafe { &*(manifest_addr as *const [u8; MANIFEST_SIZE]) };
        let committed = ManifestRef::new(flash_manifest);
        // FI-hardening (X17-FW1 / playbook FW11): RETAINED per the FI-
        // retention acceptance row (Draft 1.1 §14 L4396–4398) — the
        // reviewed sentinel/double-evaluation checks on signed digest /
        // image binding and rollback admission stay in every build this
        // campaign produces, even though the unary floor bump they once
        // guarded is removed (the gate now precedes the fail-closed
        // refusal below). HONEST SCOPE (merge wave-2 MEDIUM): post-removal
        // the gate-fail arm and the fall-through refusal have identical
        // side effects and status, so the retained checks are SOURCE-LEVEL
        // retention pending the reviewed backend that will gate a real
        // epoch-bump — they are not live FI coverage today, and the pin
        // test asserts their presence and wiring, not a behavioural
        // delta. Route both verdicts through
        // `check_true_into_sentinel` (double-evaluated + Hamming-distant
        // sentinel) with `scrub_sentinel_register` between the paired
        // callsites (stale-r0 defence, F-15.r1), matching
        // `verify_images`' aggregate-gate pattern. The closures RE-RUN
        // the verifications; `black_box` stops LLVM from proving a
        // re-evaluation redundant (F-1).
        crate::fi::wait_random();
        let manifest_gate = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(committed.verify_structural().is_ok())
                && core::hint::black_box(committed.verify_crc().is_ok())
                && core::hint::black_box(committed.verify_digest().is_ok())
                && core::hint::black_box(committed.verify_rollback(new_rollback_floor).is_ok())
        });
        crate::fi::scrub_sentinel_register();
        let pointer_gate = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(matches!(
                boot_state::read(),
                Ok(bs) if bs.active_slot == inactive && bs.last_good_version == new_version
            ))
        });
        if manifest_gate != crate::fi::OK_SENTINEL || pointer_gate != crate::fi::OK_SENTINEL {
            // No floor write has happened: the old slot still boots. Drop
            // the streaming context so a retry goes through a fresh,
            // user-gated BEGIN (which re-erases + re-streams the inactive
            // slot).
            // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
            // under the non-reentrant dispatcher + `HandlerGuard`.
            unsafe {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
            secure_log!(
                "[S][fwup] COMMIT pre-commit re-verify FAIL — aborting staged slot (old slot stays bootable)"
            );
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // 4. FAIL-CLOSED REFUSAL (FA-1.5; Draft 1.1 §14 L4375 "runtime floor
    //    writer removal", L4388–4390 "production and real-vendor-key builds
    //    compile-fail on every epoch-bump success path").
    //
    //    The legacy unary floor update (`otp::bump_to`) is REMOVED from
    //    this handler, and with it the ambiguous-launch handling (a QW
    //    program whose post-reset state cannot be classified) and the
    //    `FwUpdateOtpExhausted` status. STM32U585 OTP quad-words are
    //    one-program-only and an interrupted program is not retry-safe,
    //    and no reviewed rollback backend exists while OPEN-OTP-1..3,
    //    OPEN-ECC-1, OPEN-JRN-HW-1, and OPEN-JRN-DUR-1 remain open
    //    (§14 L4368–4370, L4385–4390). COMMIT therefore has NO epoch-bump
    //    success path in any build: the floor is never raised at runtime,
    //    and the handler never resets into the staged slot. Activation is
    //    refused BY THIS HANDLER only: FSBL slot selection is unchanged,
    //    so a staged slot whose boot-state write failed or tore can still
    //    be selected at the next reset (legacy try-once fall-through),
    //    gated by FSBL's own fpr/signature/rollback re-verification — not
    //    an authorization break, since the floor never moved.
    //
    //    The 57d54657 zeroize-before-reset semantics are intact by
    //    construction: no path below resets, so no reset hand-off can
    //    carry the unlocked session into a successor image. The boot-side
    //    defensive scrub (`ResetCause::requires_secret_scrub`, including
    //    `Software`) is unchanged and stays pinned in
    //    `main_sau_pure_tests.rs`.
    //
    //    Drop the streaming context so a retry goes through a fresh,
    //    user-gated BEGIN (which re-erases + re-streams the inactive
    //    slot), and surface the same generic failure bucket as the other
    //    COMMIT aborts — no new wire status is introduced with the
    //    removal.
    // SAFETY: category 5 — exclusive write to `static mut FW_UPDATE`
    // under the non-reentrant dispatcher + `HandlerGuard`. The dropped
    // `FwUpdateCtx` zeroizes its manifest copy and running hashes via
    // `ZeroizeOnDrop`.
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }
    secure_log!(
        "[S][fwup] COMMIT fail-closed refusal: runtime rollback-floor writer removed (FA-1.5) — no OTP program, no floor write, no reset BY THIS HANDLER; FSBL slot selection unchanged (a torn stage can still be selected at next reset under FSBL re-verification)"
    );
    return NscStatus::FwUpdateFlashError as u32;
}
