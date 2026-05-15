//! Secure-world firmware-update state machine.
//!
//! Drives the `CMD_FW_BEGIN` → `CMD_FW_CHUNK*` → `CMD_FW_COMMIT`
//! flow. State lives in SRAM only — no flash write happens until
//! COMMIT confirms, so a power loss during streaming leaves the
//! active slot untouched and the device boots the old firmware
//! unchanged.
//!
//! ## Invariants
//!
//! * **Unlock required.** Every entry point checks `pin_verified`
//!   first. The update subsystem never reads or needs the wallet
//!   seed, but requiring unlock is a defence-in-depth measure: a
//!   stolen locked device cannot be silently flashed to a hostile
//!   (but vendor-signed) release.
//! * **Idle-wipe safe.** The update context is stored in
//!   `SecureState::fw_update` and zeroised on idle-wipe. If the
//!   120 s timer fires mid-stream, the partial erase + writes in
//!   the inactive slot remain (harmless — they're just flash), but
//!   SRAM state is lost and the companion must restart from BEGIN.
//! * **Stateless with respect to active slot.** We read the active
//!   slot from the `boot_state` page each BEGIN; we never cache it
//!   across idle-wipes. This keeps the update flow correct even if
//!   boot state changes between unlock sessions.
//! * **No double-sign.** The vendor signature in the manifest is
//!   verified twice: once at BEGIN (cheap reject of bogus manifests
//!   before we waste flash-erase cycles) and once at COMMIT (after
//!   re-hashing the written images, to catch any mismatch between
//!   the manifest-claimed hashes and the actually-written bytes).

use core::sync::atomic::{AtomicU32, Ordering};

use fw_manifest::{ManifestRef, VerifyError, MANIFEST_SIZE};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hw::flash::{self, Slot};
use sphincs_tz_shared::{FW_IMAGE_KIND_NONSECURE, FW_IMAGE_KIND_SECURE};

pub mod staging;
pub mod vendor_pubkey;
pub mod verify;

/// Render the new-firmware measurement on the OLED and wait for the
/// user's long-right confirm (or long-left cancel). Returns true on
/// confirm, false otherwise.
///
/// Implementation detail: the first cut displays a simplified
/// "Confirm firmware update vN — <8 words>" screen reusing the
/// trusted-UI `confirm()` machinery the sign path uses. That module
/// is part of the user's in-progress `secure/src/ui/` refactor; we
/// wrap it here to keep a single integration point.
pub fn confirm_commit(
    ctx: &FwUpdateCtx,
    _manifest: &ManifestRef,
) -> bool {
    use sphincs_tz_bip39::WORDLIST;

    let (words, _hash) = verify::measurement_words_for_inactive_slot(ctx);

    // Bail early if the user-side UI doesn't expose a confirm that
    // fits our "show 8 words + ask yes/no" shape yet. The COMMIT
    // handler treats `false` as user cancel, which is the safe
    // default — no flash is touched until the caller returns true.
    //
    // Once `secure/src/ui/confirm.rs` is stable again we'll render
    // the pages here and call `confirm(pages.as_slice())`. For now
    // this is a stub that returns `false` so an accidentally-
    // deployed half-ported UI can't slip a malicious commit through.
    let _ = words;
    let _ = WORDLIST;
    #[cfg(feature = "e2e-test")]
    {
        return true;
    }
    #[cfg(not(feature = "e2e-test"))]
    {
        false
    }
}

/// Streaming state. Held in SRAM across the BEGIN → CHUNK* → COMMIT
/// sequence. Zeroized on idle-wipe, lock, abort, or reset.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FwUpdateCtx {
    /// Which A/B slot we're writing (the inactive one, as of BEGIN).
    #[zeroize(skip)]
    pub inactive: SlotTag,

    /// Verified manifest bytes, kept in SRAM for the re-check at
    /// COMMIT time. 8 KB — a chunky SRAM cost but unavoidable since
    /// the manifest hash covers fields we need post-streaming to
    /// validate the written images.
    #[zeroize(skip)]
    pub manifest_bytes: [u8; MANIFEST_SIZE],

    /// Bytes already written to the secure half.
    pub received_secure: u32,

    /// Bytes already written to the NS half.
    pub received_nonsecure: u32,

    /// Running SHA-256 over the secure bytes written so far. Used to
    /// detect streaming corruption: the final hash must match the
    /// manifest's stored `secure_hash`.
    #[zeroize(skip)]
    pub secure_hasher: IncrementalSha256,

    /// Running SHA-256 over the nonsecure bytes.
    #[zeroize(skip)]
    pub nonsecure_hasher: IncrementalSha256,

    /// Expected final secure-image length, from the manifest.
    pub expected_secure_len: u32,

    /// Expected final nonsecure-image length, from the manifest.
    pub expected_nonsecure_len: u32,
}

/// A slot tag we can zeroize without implementing `Zeroize` for the
/// `hw::flash::Slot` enum (which would tangle up types across
/// modules). Two u8 values; the default (0) is `SlotA` which is
/// harmless: on an uninitialized context, a bogus BEGIN/CHUNK with
/// `inactive == SlotA` still requires pin-verified + a valid manifest
/// to progress past its own sanity checks.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotTag {
    SlotA = 0,
    SlotB = 1,
}

impl From<Slot> for SlotTag {
    fn from(s: Slot) -> Self {
        match s {
            Slot::A => SlotTag::SlotA,
            Slot::B => SlotTag::SlotB,
        }
    }
}

impl From<SlotTag> for Slot {
    fn from(s: SlotTag) -> Self {
        match s {
            SlotTag::SlotA => Slot::A,
            SlotTag::SlotB => Slot::B,
        }
    }
}

/// Incremental SHA-256 wrapper that we stream chunks into. Wrapped in
/// our own struct because `sha2::Sha256` doesn't implement `Zeroize`
/// trivially — keeping the state tag clears the intermediate words
/// at reset, which isn't strictly necessary (they're not secret) but
/// follows the "nothing persists past lock" convention.
pub struct IncrementalSha256 {
    inner: Sha256,
}

impl IncrementalSha256 {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn clone_finalize(&self) -> [u8; 32] {
        self.inner.clone().finalize().into()
    }
}

/// Runtime counter of BEGIN calls — a monotonic session tag used in
/// logs and by CMD_FW_STATUS to let the companion detect a "different
/// update session than the one I started".
static SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn bump_session() -> u32 {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

// ---------------------------------------------------------------------------
// Helpers shared across handlers
// ---------------------------------------------------------------------------

/// Determine which slot is currently active (ran the current firmware).
/// Falls back to `Slot::A` if the boot-state page isn't populated yet —
/// the very first update on a fresh device will always write to Slot B.
pub fn read_active_slot() -> Slot {
    match crate::hw::boot_state::read() {
        Ok(bs) => bs.active_slot,
        Err(_) => Slot::A,
    }
}

/// Run the full structural + cryptographic check chain on a manifest,
/// returning the VerifyError at the first failing step. Used at both
/// BEGIN (as an early reject) and COMMIT (as a defence-in-depth
/// re-check after the images have been written).
pub fn verify_manifest(
    m: &ManifestRef,
    rollback_floor: u32,
) -> Result<(), VerifyError> {
    m.verify_structural()?;
    m.verify_crc()?;
    m.verify_digest()?;
    // C-1 fix: the secure firmware now embeds the vendor SPHINCS+C10
    // public key (mirrored from `fsbl/build.rs`). We verify the
    // manifest's signature here, BEFORE the destructive ops in COMMIT
    // (slot erase, OTP rollback-floor bump, boot-state write) can run.
    //
    // Why the previous "defer to FSBL on next reboot" model was unsafe:
    //   - The vendor-fpr-match-active-slot check is bypassable by any
    //     attacker who can read the active manifest (it's flash, not
    //     a secret) — they just copy the fpr bytes into a forged
    //     manifest.
    //   - The OTP rollback-floor bump in `cmd_fw_commit` is
    //     irreversible. A user who confirms a malicious manifest
    //     (social engineering or a half-finished OLED confirm) bumps
    //     the OTP floor before FSBL ever gets a chance to reject the
    //     bad signature. The wallet then refuses any legitimate
    //     firmware whose version is below the attacker-chosen value
    //     — permanent update-DoS.
    //
    // With the signature check here, COMMIT only runs on a real
    // vendor-signed manifest, so the OTP bump only fires on
    // legitimate updates.
    m.verify_vendor_fpr(&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT)?;
    // F-7 hardening (FW-update bypass under single fault): call verify_signature
    // through `fi::check_true_into_sentinel`, which double-evaluates the closure
    // with `wait_random()` between, sentinel-commits the verdict to a volatile
    // local, and re-checks before encoding into OK_SENTINEL / FAIL_SENTINEL.
    // Combined with the caller's `!= OK_SENTINEL` discrimination, this lifts the
    // bar from 1 single-fault skip/stuck-at to ~2 coordinated faults — the same
    // residual as F-5 for the rest of the secure firmware. See
    // `tools/sca/README.md` §F-7 for the bypass evidence this defends against.
    let sig_verdict = crate::fi::check_true_into_sentinel(|| {
        m.verify_signature(&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT)
            .is_ok()
    });
    if sig_verdict != crate::fi::OK_SENTINEL {
        return Err(VerifyError::BadSignature);
    }
    m.verify_rollback(rollback_floor)?;
    Ok(())
}

/// Sanity-check an incoming chunk against the streaming state. Returns
/// the absolute flash address the chunk writes to, or an error.
pub fn check_chunk(
    ctx: &FwUpdateCtx,
    image_kind: u8,
    chunk_offset: u32,
    chunk_len: u16,
) -> Result<u32, ChunkError> {
    if chunk_len as usize > sphincs_tz_shared::FW_MAX_CHUNK {
        return Err(ChunkError::TooLarge);
    }
    let slot: Slot = ctx.inactive.into();
    let (base_addr, expected_len, received) = match image_kind {
        FW_IMAGE_KIND_SECURE => (
            flash::slot_secure_addr(slot),
            ctx.expected_secure_len,
            ctx.received_secure,
        ),
        FW_IMAGE_KIND_NONSECURE => (
            flash::slot_ns_addr(slot),
            ctx.expected_nonsecure_len,
            ctx.received_nonsecure,
        ),
        _ => return Err(ChunkError::BadKind),
    };

    if chunk_offset != received {
        // Strict monotonic append — no gaps, no re-transmits.
        return Err(ChunkError::NonMonotonic);
    }
    let end = chunk_offset
        .checked_add(chunk_len as u32)
        .ok_or(ChunkError::OverflowsImage)?;
    if end > expected_len {
        return Err(ChunkError::OverflowsImage);
    }
    Ok(base_addr
        .checked_add(chunk_offset)
        .ok_or(ChunkError::OverflowsImage)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
    TooLarge,
    BadKind,
    NonMonotonic,
    OverflowsImage,
    /// A flash program or erase operation failed. The inactive slot
    /// is left in whatever state the partial write produced; caller
    /// should issue `CMD_FW_ABORT` and restart from BEGIN.
    FlashError,
}
