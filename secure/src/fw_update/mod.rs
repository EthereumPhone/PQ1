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
/// The confirm dialog has four pages (navigated by short L/R taps):
///   1. Version: "to vA.B.C.D" + UPGRADE / SAME VERSION / DOWNGRADE
///   2. New-firmware fingerprint (8 BIP-39 words, "Nf abcde" format)
///   3. Signing-key fingerprint (same format, "Nk abcde")
///   4. Final yes/no confirm prompt
///
/// The user gets a defense-in-depth signal at three layers:
///   * version + direction — catches accidental downgrade attempts
///     (the verify chain also rejects them; this is user-visible)
///   * firmware fingerprint — catches "valid sig for the WRONG
///     release" (e.g. a release a different team member signed)
///   * signing-key fingerprint — catches CI signing-key compromise.
///     This fingerprint is the SAME on every legit release; if it
///     differs from the value the user wrote down at first boot,
///     the signer is compromised even though the chain verifies.
///
/// Per work-todo §31b.
/// Trusted-display install confirm. Called from `CMD_FW_BEGIN` AFTER
/// `verify_manifest` has accepted the bundle's vendor signature, version,
/// and length bounds, and BEFORE any destructive flash op (erase / OTP /
/// boot-state). Renders four OLED pages — version+floor, firmware
/// fingerprint, vendor-key fingerprint, confirm prompt — and waits for
/// the user's physical button press. A user-cancel (or the
/// inactivity-timeout's `IdleWipe`) returns `false`, the BEGIN handler
/// then aborts without erasing.
///
/// The firmware fingerprint shown here is derived from the **signed**
/// `secure_hash` field of the manifest — the same value `verify_images`
/// will re-check against the bytes streamed into flash at COMMIT.
/// COMMIT itself runs silently after `verify_images`: if the streamed
/// bytes match the signed hash the install proceeds; if they don't,
/// COMMIT auto-aborts with no further prompt (the user has already given
/// their consent at BEGIN; an integrity failure is the device's
/// responsibility to detect and report). See finding A in
/// `docs/usb-fw-update-hardening.md` — moves the confirm forward from
/// COMMIT to BEGIN so a user-cancel costs zero flash work + zero
/// inactive-slot churn (matches Trezor's wf_firmware_update.c pattern).
pub fn confirm_install(manifest: &ManifestRef) -> bool {
    #[cfg(feature = "e2e-test")]
    {
        let _ = manifest;
        return true;
    }
    #[cfg(not(feature = "e2e-test"))]
    {
        use crate::ui::confirm::{confirm, ConfirmResult, Page};
        use sphincs_tz_bip39::hash_to_word_indices;

        let new_version = manifest.fw_version();
        let floor = crate::hw::otp::rollback_floor();
        // Derive 8 BIP-39 words from the manifest's SIGNED secure-image
        // hash — what the user is being asked to install. The device's
        // COMMIT-time `verify_images` re-hashes the streamed bytes
        // against this same field; an attacker who substitutes the
        // streamed bytes will trip that check (silent abort) without
        // ever reaching another user prompt.
        let fw_words = hash_to_word_indices(manifest.secure_hash());

        // The signing key fingerprint is the SHA-256 of the vendor
        // pubkey (`pk_seed || pk_root`), precomputed at build time so
        // the runtime cost is just a memcpy of the 32 bytes.
        let key_fpr: [u8; 32] = vendor_pubkey::VENDOR_PK_FPR;
        let key_words = hash_to_word_indices(&key_fpr);

        let pages: [Page; 4] = [
            build_version_page(new_version, floor),
            build_fingerprint_page(&fw_words, b'f'),
            build_fingerprint_page(&key_words, b'k'),
            build_confirm_prompt_page(),
        ];

        matches!(confirm(&pages), ConfirmResult::Confirmed)
    }
}

#[cfg(not(feature = "e2e-test"))]
fn build_version_page(new_version: u32, floor: u32) -> crate::ui::confirm::Page {
    use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
    let mut p: crate::ui::confirm::Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];

    // Row 0: title.
    let r0 = b"FW UPDATE";
    p[0][..r0.len()].copy_from_slice(r0);

    // Row 1: "to vA.B.C.D" where bytes A..D are the manifest version's
    // big-endian byte chunks. Mirrors Trezor's MAJOR.MINOR.PATCH.BUILD.
    let bytes = new_version.to_be_bytes();
    p[1][..3].copy_from_slice(b"to ");
    let mut col = 3usize;
    if col < DISPLAY_COLS {
        p[1][col] = b'v';
        col += 1;
    }
    for (i, &b) in bytes.iter().enumerate() {
        let mut tmp = [0u8; 3];
        let n = format_u8_decimal(b, &mut tmp);
        let take = core::cmp::min(n, DISPLAY_COLS.saturating_sub(col));
        p[1][col..col + take].copy_from_slice(&tmp[..take]);
        col += take;
        if i < 3 && col < DISPLAY_COLS {
            p[1][col] = b'.';
            col += 1;
        }
    }

    // Row 2: direction indicator. The verify chain already rejects
    // downgrades at BEGIN, so the DOWNGRADE label is unreachable in
    // practice — keep it for defensive completeness.
    let dir: &[u8] = if new_version > floor {
        b"UPGRADE"
    } else if new_version == floor {
        b"SAME VERSION"
    } else {
        b"DOWNGRADE!"
    };
    let n = core::cmp::min(dir.len(), DISPLAY_COLS);
    p[2][..n].copy_from_slice(&dir[..n]);

    // Row 3: nav hint.
    let r3 = b"R-tap = next";
    p[3][..r3.len()].copy_from_slice(r3);

    p
}

/// Render 8 BIP-39 words across 4 rows × 2 columns. The `discriminator`
/// byte (`b'f'` for firmware hash, `b'k'` for signing-key fingerprint)
/// appears next to each digit so the two fingerprint pages can't be
/// visually confused with each other.
///
/// Per-cell layout (8 cols):
///   col 0  digit ('1'..='4' on left half, '5'..='8' on right half)
///   col 1  discriminator
///   col 2  space
///   col 3..7  word truncated to 5 chars
///
/// BIP-39 English wordlist has unique 4-letter prefixes by spec, so
/// 5-char truncation always disambiguates.
#[cfg(not(feature = "e2e-test"))]
fn build_fingerprint_page(
    words: &[u16; 8],
    discriminator: u8,
) -> crate::ui::confirm::Page {
    use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
    use sphincs_tz_bip39::word_bytes_at;
    let mut p: crate::ui::confirm::Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];

    for row in 0..DISPLAY_ROWS {
        // Left half: word index = row (0..=3) → display digit '1'..='4'.
        let li = row;
        p[row][0] = b'1' + row as u8;
        p[row][1] = discriminator;
        // col 2 stays blank
        let (lw, llen) = word_bytes_at(words[li]);
        let lmax = core::cmp::min(llen as usize, 5);
        p[row][3..3 + lmax].copy_from_slice(&lw[..lmax]);

        // Right half: word index = row + 4 → display digit '5'..='8'.
        let ri = row + 4;
        p[row][8] = b'5' + row as u8;
        p[row][9] = discriminator;
        // col 10 stays blank
        let (rw, rlen) = word_bytes_at(words[ri]);
        let rmax = core::cmp::min(rlen as usize, 5);
        p[row][11..11 + rmax].copy_from_slice(&rw[..rmax]);
    }

    p
}

#[cfg(not(feature = "e2e-test"))]
fn build_confirm_prompt_page() -> crate::ui::confirm::Page {
    use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
    let mut p: crate::ui::confirm::Page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    let r0 = b"Confirm update?";
    let r1 = b"R-hold = YES";
    let r2 = b"L-hold = NO";
    let r3 = b"L-tap = review";
    p[0][..r0.len()].copy_from_slice(r0);
    p[1][..r1.len()].copy_from_slice(r1);
    p[2][..r2.len()].copy_from_slice(r2);
    p[3][..r3.len()].copy_from_slice(r3);
    p
}

/// Write `n` as ASCII decimal into `out`, return bytes written. Local
/// because the existing `format_u64_decimal` lives in a sibling module
/// (`tx::eip712::cowswap_display`) that pulls in EIP-712-specific code;
/// duplicating these 14 lines keeps fw_update self-contained.
#[cfg(not(feature = "e2e-test"))]
fn format_u8_decimal(mut n: u8, out: &mut [u8]) -> usize {
    if n == 0 {
        if !out.is_empty() {
            out[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut buf = [0u8; 3];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + n % 10;
        n /= 10;
        i += 1;
    }
    let len = core::cmp::min(i, out.len());
    for j in 0..len {
        out[j] = buf[i - 1 - j];
    }
    len
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
