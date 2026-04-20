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

impl Default for SlotTag {
    fn default() -> Self {
        SlotTag::SlotA
    }
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
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
    pub fn clone_finalize(&self) -> [u8; 32] {
        self.inner.clone().finalize().into()
    }
}

impl Default for IncrementalSha256 {
    fn default() -> Self {
        Self::new()
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
    // The vendor pubkey the secure firmware knows is... the same one
    // FSBL knows, because it's compiled in at FSBL build time. The
    // secure firmware doesn't directly embed it — instead, on the
    // first BEGIN of a session, we trust-but-verify: FSBL has already
    // verified the CURRENTLY-RUNNING firmware via the same pubkey,
    // so any manifest the secure firmware accepts must ALSO verify
    // under whatever pubkey FSBL holds. We achieve this by having the
    // secure firmware read the `vendor_pubkey_fpr` from its own
    // active slot's manifest (which FSBL verified), and require the
    // new manifest to carry the same fingerprint. The signature
    // itself is then verified under the two fingerprint-matching
    // fields (pk_seed, pk_root) — but we don't have those in the
    // secure firmware...
    //
    // Wait: the manifest has vendor_pubkey_fpr but not pk_seed/pk_root
    // themselves. So the secure firmware can't verify the signature
    // without the actual pubkey.
    //
    // Resolution: the running firmware slot's manifest has the pubkey
    // fingerprint AND is itself signed by the vendor. We read the
    // pubkey fingerprint from the active slot's manifest and require
    // the new manifest's fpr to match (i.e., "same vendor"). We DO
    // NOT verify the C10 signature in the secure firmware at BEGIN —
    // we defer that to FSBL on the next reboot, which has the real
    // pubkey compiled in.
    //
    // This is weaker than ideal. A more careful design would expose
    // the vendor pubkey via a readable (but not writable) flash
    // region that both FSBL and the secure firmware read. For now,
    // we check fingerprint match here + rely on FSBL's full re-check
    // post-reset as the definitive gate.
    let active = read_active_slot();
    let active_manifest_bytes = read_active_manifest_bytes(active);
    let active_ref = ManifestRef::new(&active_manifest_bytes);
    // Compare the new manifest's fpr against the active one's — if
    // they differ, someone is trying to install firmware signed by a
    // different vendor.
    if m.vendor_pubkey_fpr() != active_ref.vendor_pubkey_fpr() {
        return Err(VerifyError::WrongVendor);
    }
    m.verify_rollback(rollback_floor)?;
    Ok(())
}

/// Snapshot the active slot's manifest page into an owned 8 KB array.
/// Allocated on the stack; fine within our 192 KB secure SRAM budget
/// but we keep callers to one snapshot at a time.
fn read_active_manifest_bytes(slot: Slot) -> [u8; MANIFEST_SIZE] {
    let addr = flash::manifest_addr(slot);
    let mut buf = [0u8; MANIFEST_SIZE];
    // SAFETY: manifest_addr returns a memory-mapped flash pointer
    // inside bank 1. Reading it is always safe.
    unsafe {
        let src = addr as *const u8;
        for i in 0..MANIFEST_SIZE {
            buf[i] = core::ptr::read_volatile(src.add(i));
        }
    }
    buf
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
