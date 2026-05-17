//! Host-side test suite for the `secure-fw-update-boot` slice.
//!
//! # Scope
//!
//! Three production files plus the small helper module under
//! `secure/src/fw_update/`:
//!
//!   * `secure/src/fw_update/mod.rs`           — streaming state machine
//!     types (`FwUpdateCtx`, `IncrementalSha256`, `SlotTag`,
//!     `ChunkError`), `verify_manifest` (FI-hardened signature chain),
//!     `check_chunk` (monotonic-append bounds check), `confirm_commit`
//!     (user-facing measurement confirm), `bump_session`,
//!     `read_active_slot`.
//!   * `secure/src/fw_update/staging.rs`       — `write_chunk` (QW-aligned
//!     program of the inactive slot, last-chunk pad-with-0xFF rule).
//!   * `secure/src/fw_update/verify.rs`        — COMMIT-time defence in
//!     depth: re-read the inactive slot from flash and compare against
//!     both (a) the running hash and (b) the manifest-signed hashes.
//!   * `secure/src/fw_update/vendor_pubkey.rs` — `include!`s the
//!     `VENDOR_PK_SEED` / `VENDOR_PK_ROOT` constants emitted by
//!     `secure/build.rs` so both this slice and the FSBL share an
//!     identical vendor-pubkey image.
//!   * `secure/src/measured_boot.rs`           — boot-time SHA-256 of the
//!     secure firmware flash region, displayed to the user as
//!     8 BIP-39 fingerprint words ("OS Fingerprint").
//!   * `secure/src/boot_ns.rs`                 — final unsafe asm hop
//!     that programs `VTOR_NS`, scrubs the register file, and `bxns`-es
//!     into the non-secure world.
//!
//! # Why source-text invariants dominate this file
//!
//! Every file in scope is `#[cfg(not(test))]` or
//! `#[cfg(all(feature = "stm32u585", not(test)))]` at the crate root
//! (see `secure/src/main.rs:69-130`). The host `cargo test` build does
//! not link any of them — they depend on `crate::hw::flash`,
//! `crate::hw::boot_state`, `crate::ui`, `crate::timeout`, and
//! `core::arch::asm!` ARM instructions that don't compile on x86_64.
//!
//! The companion `nsc_fw_update_pure_tests.rs` slice already covers the
//! five `cmd_fw_*` NSC handlers under `nsc/`. This file targets the
//! *inner* slice — the state-machine types and helpers under
//! `fw_update/`, plus the two boot-handover files (`measured_boot`,
//! `boot_ns`). To stay independent of the existing scaffold the
//! assertions either:
//!
//!   * pin source-text invariants via `include_str!` (the load-bearing
//!     guards each file claims to enforce); or
//!   * run pure-logic mirrors of the file's algorithms against
//!     reference vectors and adversarial inputs.
//!
//! Negative tests name the assumption being attacked and the attack
//! that would succeed if the guard were silently removed — see CLAUDE.md
//! "Non-Negotiable Invariants" #6 (bootstrap C10 keys immutable),
//! "What NOT to do" (single C10 signer, no plaintext secrets in NS,
//! no skipping verify-before-release), and the slice's per-file
//! docstrings.

#![cfg(test)]

use fw_manifest::{MANIFEST_SIZE, OFF_CRC32, OFF_SIGNATURE, OFF_TRY_ONCE, TRY_ONCE_TRIED};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use sphincs_tz_shared::{FW_IMAGE_KIND_NONSECURE, FW_IMAGE_KIND_SECURE, FW_MAX_CHUNK};

// ─────────────────────────────────────────────────────────────────────
// 0. Source fixtures.
//
// Loaded via include_str! so the test binary rebuilds when the
// underlying source files change. A future refactor that renames or
// deletes any of these paths surfaces here as a compile error.
// ─────────────────────────────────────────────────────────────────────

const FW_MOD_SRC: &str = include_str!("fw_update/mod.rs");
const STAGING_SRC: &str = include_str!("fw_update/staging.rs");
const VERIFY_SRC: &str = include_str!("fw_update/verify.rs");
const VENDOR_SRC: &str = include_str!("fw_update/vendor_pubkey.rs");
const MEASURED_BOOT_SRC: &str = include_str!("measured_boot.rs");
const BOOT_NS_SRC: &str = include_str!("boot_ns.rs");
const MAIN_SRC: &str = include_str!("main.rs");

// ═════════════════════════════════════════════════════════════════════
// SECTION A — `fw_update/mod.rs`
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// A1. Positive: types & values that callers rely on.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_slot_tag_repr_values_match_protocol_byte_codes() {
    // `SlotTag` is `#[repr(u8)]` with explicit discriminants 0 and 1.
    // Companion / FSBL talks the same `SLOT_A = 0x00`, `SLOT_B = 0x01`
    // numbering. Pin the textual discriminants so a silent renumber
    // would surface here.
    assert!(
        FW_MOD_SRC.contains("#[repr(u8)]"),
        "SlotTag must be #[repr(u8)] so cross-world casts stay byte-stable"
    );
    assert!(
        FW_MOD_SRC.contains("SlotA = 0,"),
        "SlotTag::SlotA must be discriminant 0 (matches fw_manifest::SLOT_A)"
    );
    assert!(
        FW_MOD_SRC.contains("SlotB = 1,"),
        "SlotTag::SlotB must be discriminant 1 (matches fw_manifest::SLOT_B)"
    );
    assert_eq!(fw_manifest::SLOT_A, 0);
    assert_eq!(fw_manifest::SLOT_B, 1);
}

#[test]
fn positive_chunk_error_variants_are_documented() {
    // Mirror of the public `ChunkError` enum. The companion's error
    // path table depends on every variant remaining present; a
    // refactor that collapsed `NonMonotonic` into `OverflowsImage`
    // would lose the discriminator companion-side and break retry UX.
    for variant in &[
        "TooLarge",
        "BadKind",
        "NonMonotonic",
        "OverflowsImage",
        "FlashError",
    ] {
        assert!(
            FW_MOD_SRC.contains(variant),
            "ChunkError must keep the `{variant}` variant — companion error router depends on it"
        );
    }
}

#[test]
fn positive_fw_update_ctx_field_layout_pinned() {
    // The CHUNK / COMMIT handlers index `FwUpdateCtx` by these exact
    // field names. A rename without companion-side coordination would
    // surface here.
    for field in &[
        "pub inactive: SlotTag",
        "pub manifest_bytes: [u8; MANIFEST_SIZE]",
        "pub received_secure: u32",
        "pub received_nonsecure: u32",
        "pub secure_hasher: IncrementalSha256",
        "pub nonsecure_hasher: IncrementalSha256",
        "pub expected_secure_len: u32",
        "pub expected_nonsecure_len: u32",
    ] {
        assert!(
            FW_MOD_SRC.contains(field),
            "FwUpdateCtx must expose `{field}` — handlers read/write it by name"
        );
    }
}

#[test]
fn positive_session_counter_is_monotonic_atomic() {
    // `bump_session` is an `AtomicU32::fetch_add(1, Relaxed)`. We
    // can't call it on host (the module is `#[cfg(stm32u585)]`), so
    // mirror the behaviour and assert the spec.
    assert!(
        FW_MOD_SRC.contains("static SESSION_COUNTER: AtomicU32 = AtomicU32::new(0);"),
        "session counter must start at 0"
    );
    assert!(
        FW_MOD_SRC.contains("SESSION_COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(1)"),
        "bump_session must atomically fetch_add(1) and return prev+1"
    );
}

// ─────────────────────────────────────────────────────────────────────
// A2. Positive: `IncrementalSha256` reference vectors via the same
//     `sha2::Sha256` building block the production type wraps.
//
// The production type is a thin wrapper that delegates `update` to
// `sha2::Sha256::update` and `clone_finalize` to
// `sha2::Sha256::clone().finalize()`. We replay the wrapper here
// against the standard "abc" / empty / multi-update vectors so that:
//
//   * the wrapper's behaviour is pinned against a known-good reference
//     (NIST SHA-256 vectors); and
//   * the `clone_finalize` semantics — "non-destructive finalize that
//     keeps the running state alive for the next chunk" — are asserted.
//     This is load-bearing: `verify_images` calls `clone_finalize()`
//     mid-stream and the next chunk update must still mutate the
//     original hasher's state, not a forked copy.
// ─────────────────────────────────────────────────────────────────────

struct MirrorIncSha256 {
    inner: Sha256,
}

impl MirrorIncSha256 {
    fn new() -> Self {
        Self { inner: Sha256::new() }
    }
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn clone_finalize(&self) -> [u8; 32] {
        self.inner.clone().finalize().into()
    }
}

#[test]
fn positive_incremental_sha256_matches_one_shot_abc() {
    // NIST SHA-256("abc") = ba7816bf8f01cfea4141 40de5dae2223b00361a3 96177a9cb410ff61f200 15ad
    let mut h = MirrorIncSha256::new();
    h.update(b"abc");
    let digest = h.clone_finalize();
    let expected = Sha256::digest(b"abc");
    assert_eq!(&digest, expected.as_slice());
    // First 4 bytes of the well-known vector.
    assert_eq!(&digest[..4], &[0xba, 0x78, 0x16, 0xbf]);
}

#[test]
fn positive_incremental_sha256_matches_one_shot_empty() {
    let h = MirrorIncSha256::new();
    let digest = h.clone_finalize();
    let expected = Sha256::digest(b"");
    assert_eq!(&digest, expected.as_slice());
    // SHA-256("") starts with e3b0c442…
    assert_eq!(&digest[..4], &[0xe3, 0xb0, 0xc4, 0x42]);
}

#[test]
fn positive_incremental_sha256_multi_update_equals_concatenation() {
    let mut h = MirrorIncSha256::new();
    h.update(b"abc");
    h.update(b"def");
    h.update(b"ghi");
    let actual = h.clone_finalize();
    let expected: [u8; 32] = Sha256::digest(b"abcdefghi").into();
    assert_eq!(actual, expected);
}

#[test]
fn positive_clone_finalize_does_not_consume_hasher() {
    // verify_images calls clone_finalize on a borrow then the caller
    // could in principle keep streaming. Pin that property.
    let mut h = MirrorIncSha256::new();
    h.update(b"abc");
    let mid = h.clone_finalize();
    h.update(b"def");
    let full = h.clone_finalize();
    assert_eq!(mid, <[u8; 32]>::from(Sha256::digest(b"abc")));
    assert_eq!(full, <[u8; 32]>::from(Sha256::digest(b"abcdef")));
    assert_ne!(mid, full, "second update must mutate the original state");
}

// ─────────────────────────────────────────────────────────────────────
// A3. Negative: zeroize wiring on `FwUpdateCtx`.
//
// CLAUDE.md §"Code Conventions": every secret-bearing type derives
// `ZeroizeOnDrop`. The manifest copy is not strictly secret (it's
// vendor-signed and public), but the running hashers carry partial
// SHA-256 state that an attacker could ratchet against; the convention
// is "wipe everything on Drop".
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_fw_update_ctx_derives_zeroize_on_drop() {
    assert!(
        FW_MOD_SRC.contains("#[derive(Zeroize, ZeroizeOnDrop)]"),
        "FwUpdateCtx must derive Zeroize + ZeroizeOnDrop so abort / commit / idle-wipe \
         scrub the SRAM ctx — see CLAUDE.md 'no secrets persist past lock'"
    );
}

#[test]
fn negative_fw_update_ctx_zeroize_skip_marks_are_intentional() {
    // `manifest_bytes` is large (8 KB) and not secret — the slow path
    // explicitly opts it out of the per-field zeroize sweep via
    // `#[zeroize(skip)]`. Same for `inactive: SlotTag` (the `Slot`
    // enum has no Zeroize impl; nothing to wipe in a single byte).
    // Pin both skips so a refactor that drops them doesn't silently
    // multiply the abort latency by 8 KB.
    assert!(
        FW_MOD_SRC.contains("#[zeroize(skip)]\n    pub inactive: SlotTag,"),
        "FwUpdateCtx.inactive must keep #[zeroize(skip)] — the enum has no Zeroize impl"
    );
    assert!(
        FW_MOD_SRC.contains("#[zeroize(skip)]\n    pub manifest_bytes: [u8; MANIFEST_SIZE],"),
        "FwUpdateCtx.manifest_bytes must keep #[zeroize(skip)] — 8 KB sweep would slow abort path"
    );
    assert!(
        FW_MOD_SRC.contains("#[zeroize(skip)]\n    pub secure_hasher: IncrementalSha256,"),
        "secure_hasher must keep #[zeroize(skip)] — sha2::Sha256 lacks a Zeroize derive"
    );
    assert!(
        FW_MOD_SRC.contains("#[zeroize(skip)]\n    pub nonsecure_hasher: IncrementalSha256,"),
        "nonsecure_hasher must keep #[zeroize(skip)] — sha2::Sha256 lacks a Zeroize derive"
    );
}

// ─────────────────────────────────────────────────────────────────────
// A4. Negative: `verify_manifest` chain shape.
//
// CLAUDE.md §"What NOT to do" — "No skipping verify-before-release on
// Type 1 / Type 2 sigs"; the same logic applies to FW updates. The
// signature verify must run *before* the rollback check (so a forged
// manifest can't probe the OTP floor) and via the FI-hardened sentinel
// (so a single fault can't flip the verdict).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_manifest_uses_fi_hardened_signature_check() {
    assert!(
        FW_MOD_SRC.contains("crate::fi::check_true_into_sentinel"),
        "verify_manifest must wrap verify_signature in check_true_into_sentinel — \
         F-7 single-fault defence (see tools/sca/README.md §F-7)"
    );
    assert!(
        FW_MOD_SRC.contains("crate::fi::OK_SENTINEL"),
        "verify_manifest must compare verdict against OK_SENTINEL (sentinel-encoded), \
         not a raw bool — F-5 stuck-at defence"
    );
    assert!(
        FW_MOD_SRC.contains("return Err(VerifyError::BadSignature);"),
        "verify_manifest must fail-closed to VerifyError::BadSignature on sentinel mismatch"
    );
}

#[test]
fn negative_verify_manifest_runs_full_chain_in_documented_order() {
    // Cheap structural checks first, expensive signature last, rollback
    // floor *after* signature so a forged manifest cannot probe the OTP
    // floor.  The order is pinned because a future refactor that put
    // verify_rollback first would let an attacker enumerate the OTP
    // floor via a chosen-version oracle.
    let order = [
        "m.verify_structural()?;",
        "m.verify_crc()?;",
        "m.verify_digest()?;",
        "m.verify_vendor_fpr(",
        "check_true_into_sentinel",
        "m.verify_rollback(rollback_floor)?;",
    ];
    let mut last = 0usize;
    for step in order {
        let pos = FW_MOD_SRC
            .find(step)
            .unwrap_or_else(|| panic!("verify_manifest must call `{step}`"));
        assert!(
            pos >= last,
            "verify_manifest step `{step}` is out of order — security-critical chain \
             ordering must not silently regress"
        );
        last = pos;
    }
}

#[test]
fn negative_verify_manifest_uses_baked_in_vendor_pubkey() {
    // Both verify_vendor_fpr and verify_signature must pull pk_seed /
    // pk_root from the build-time-baked constants — never from caller
    // input. An attacker who could supply the pubkey would forge
    // a manifest trivially.
    assert!(
        FW_MOD_SRC.contains("&vendor_pubkey::VENDOR_PK_SEED, &vendor_pubkey::VENDOR_PK_ROOT"),
        "verify_manifest must pin the vendor pubkey from the build-time include — \
         no caller-supplied pubkey path may exist"
    );
}

// ─────────────────────────────────────────────────────────────────────
// A5. Negative: `confirm_commit` fail-closed semantics.
//
// The OLED confirm UI for FW updates was ported mid-refactor; the
// current stub returns `false` (= user cancel) so an accidentally-
// deployed half-ported UI cannot slip a malicious commit through.
// The only exception is the `e2e-test` build, which returns `true`
// unconditionally so the automated suite can exercise the COMMIT path.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_confirm_commit_defaults_to_user_cancel_outside_e2e_test() {
    let body = FW_MOD_SRC
        .find("pub fn confirm_commit(")
        .expect("confirm_commit must exist as a pub fn");
    let body = &FW_MOD_SRC[body..];
    // `false` for non-e2e-test builds, `true` for e2e-test.
    let non_e2e_pos = body
        .find("#[cfg(not(feature = \"e2e-test\"))]")
        .expect("confirm_commit must gate its non-e2e branch on cfg(not(feature = \"e2e-test\"))");
    let e2e_pos = body
        .find("#[cfg(feature = \"e2e-test\")]")
        .expect("confirm_commit must gate its e2e branch on cfg(feature = \"e2e-test\")");
    // Production path returns `false`.
    let non_e2e_block = &body[non_e2e_pos..];
    assert!(
        non_e2e_block.contains("false"),
        "confirm_commit non-e2e branch must return `false` — a half-ported UI must NOT \
         accidentally confirm a malicious manifest"
    );
    // The e2e short-circuit returns `true` for test automation.
    let e2e_block = &body[e2e_pos..non_e2e_pos.max(e2e_pos + 1)];
    assert!(
        e2e_block.contains("return true;"),
        "confirm_commit under e2e-test must short-circuit to true so the e2e suite \
         can exercise the COMMIT path"
    );
}

// ─────────────────────────────────────────────────────────────────────
// A6. `check_chunk` decision tree — pure-logic mirror.
//
// We mirror the function body without the `flash::slot_*_addr` calls
// so the decision shape is testable on host. A refactor that drifted
// the production tree would also need to be reflected in this mirror.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum MirrorChunkError {
    TooLarge,
    BadKind,
    NonMonotonic,
    OverflowsImage,
}

struct MirrorCtx {
    expected_secure_len: u32,
    expected_nonsecure_len: u32,
    received_secure: u32,
    received_nonsecure: u32,
}

fn mirror_check_chunk(
    ctx: &MirrorCtx,
    image_kind: u8,
    chunk_offset: u32,
    chunk_len: u16,
) -> Result<(), MirrorChunkError> {
    if chunk_len as usize > FW_MAX_CHUNK {
        return Err(MirrorChunkError::TooLarge);
    }
    let (expected_len, received) = match image_kind {
        FW_IMAGE_KIND_SECURE => (ctx.expected_secure_len, ctx.received_secure),
        FW_IMAGE_KIND_NONSECURE => (ctx.expected_nonsecure_len, ctx.received_nonsecure),
        _ => return Err(MirrorChunkError::BadKind),
    };
    if chunk_offset != received {
        return Err(MirrorChunkError::NonMonotonic);
    }
    let end = chunk_offset
        .checked_add(chunk_len as u32)
        .ok_or(MirrorChunkError::OverflowsImage)?;
    if end > expected_len {
        return Err(MirrorChunkError::OverflowsImage);
    }
    Ok(())
}

fn fixture_ctx() -> MirrorCtx {
    MirrorCtx {
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
        received_secure: 0,
        received_nonsecure: 0,
    }
}

#[test]
fn positive_check_chunk_accepts_max_size_chunk_at_zero() {
    let ctx = fixture_ctx();
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 0, FW_MAX_CHUNK as u16).is_ok());
}

#[test]
fn positive_check_chunk_accepts_zero_length_chunk() {
    // A zero-length chunk is degenerate but well-defined: it does
    // nothing. The handler accepts it; the staging layer pads to QW
    // alignment, which means a zero-length write is a no-op. We pin
    // the acceptance so a future refactor that rejected `chunk_len ==
    // 0` outright doesn't break a benign companion-side rounding.
    let ctx = fixture_ctx();
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 0, 0).is_ok());
}

#[test]
fn positive_check_chunk_accepts_final_chunk_exact_fit() {
    let ctx = MirrorCtx {
        expected_secure_len: 4096,
        received_secure: 3072,
        expected_nonsecure_len: 0,
        received_nonsecure: 0,
    };
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 3072, 1024).is_ok());
}

#[test]
fn negative_check_chunk_rejects_chunk_one_byte_past_max() {
    // Attack: feed `chunk_len = FW_MAX_CHUNK + 1` to overflow the
    // 1 KB secure-stack snapshot buffer in cmd_fw_chunk. The handler's
    // `total_len` gate is one defence; `check_chunk::TooLarge` is the
    // second, defence-in-depth layer.
    let ctx = fixture_ctx();
    assert_eq!(
        mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 0, (FW_MAX_CHUNK as u16) + 1),
        Err(MirrorChunkError::TooLarge),
        "check_chunk must reject chunk_len > FW_MAX_CHUNK"
    );
}

#[test]
fn negative_check_chunk_rejects_unknown_image_kind() {
    // Attack: image_kind ∉ {0, 1} would route the chunk to an
    // undefined base address. Reject before any flash touch.
    let ctx = fixture_ctx();
    for bad in [2u8, 3, 0x10, 0x80, 0xFE, 0xFF] {
        assert_eq!(
            mirror_check_chunk(&ctx, bad, 0, 16),
            Err(MirrorChunkError::BadKind),
            "check_chunk must reject image_kind {bad}"
        );
    }
}

#[test]
fn negative_check_chunk_rejects_offset_gap() {
    let ctx = MirrorCtx {
        expected_secure_len: 4096,
        received_secure: 1024,
        expected_nonsecure_len: 0,
        received_nonsecure: 0,
    };
    assert_eq!(
        mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 2048, 1024),
        Err(MirrorChunkError::NonMonotonic),
        "check_chunk must enforce strict monotonic append — no gaps"
    );
}

#[test]
fn negative_check_chunk_rejects_offset_replay() {
    // Attack: re-send a chunk at offset < received to overwrite bytes
    // the running hash has already absorbed. The streaming digest
    // would diverge from the re-read flash digest at COMMIT time, but
    // we reject earlier here.
    let ctx = MirrorCtx {
        expected_secure_len: 4096,
        received_secure: 2048,
        expected_nonsecure_len: 0,
        received_nonsecure: 0,
    };
    assert_eq!(
        mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 1024, 1024),
        Err(MirrorChunkError::NonMonotonic),
        "check_chunk must enforce strict monotonic append — no replay"
    );
}

#[test]
fn negative_check_chunk_rejects_end_past_expected_length() {
    // Use a chunk_len ≤ FW_MAX_CHUNK so the TooLarge gate doesn't
    // short-circuit; OverflowsImage is what we want to exercise.
    let ctx = MirrorCtx {
        expected_secure_len: 4000,
        received_secure: 3072,
        expected_nonsecure_len: 0,
        received_nonsecure: 0,
    };
    assert_eq!(
        mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 3072, 1024),
        Err(MirrorChunkError::OverflowsImage),
        "check_chunk must reject end > expected_secure_len"
    );
}

#[test]
fn negative_check_chunk_uses_checked_add_against_u32_wrap() {
    // Attack: chunk_offset = u32::MAX - 4, chunk_len = 8. Naive
    // addition wraps to 4; checked_add rejects. The production code
    // uses .checked_add — pin both the result here and the textual
    // use in mod.rs.
    let ctx = MirrorCtx {
        expected_secure_len: u32::MAX,
        received_secure: u32::MAX - 4,
        expected_nonsecure_len: 0,
        received_nonsecure: 0,
    };
    assert_eq!(
        mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, u32::MAX - 4, 8),
        Err(MirrorChunkError::OverflowsImage),
        "check_chunk must use checked_add to defend chunk_offset + chunk_len wrap"
    );
    assert!(
        FW_MOD_SRC.contains(".checked_add(chunk_len as u32)"),
        "check_chunk source must contain .checked_add(chunk_len as u32) — a `+` regression \
         would silently wrap"
    );
}

#[test]
fn negative_check_chunk_source_pins_base_addr_via_checked_add() {
    // The final `base_addr + chunk_offset` is also wrapped in
    // `checked_add` (rare in practice — base_addr is a fixed flash
    // address, chunk_offset is bounded — but defence in depth).
    assert!(
        FW_MOD_SRC.contains("base_addr\n        .checked_add(chunk_offset)"),
        "check_chunk must compute the final address via checked_add(chunk_offset)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// A7. Negative: `read_active_slot` falls back safely.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_read_active_slot_falls_back_to_slot_a_on_unpopulated_state() {
    // Documented in fw_update/mod.rs:185-193: a fresh device with no
    // boot_state page treats Slot::A as active so the *first* update
    // always writes Slot::B. The reverse fallback (default to Slot::B)
    // would corrupt the bootloader on every fresh device's first
    // update. Pin the fallback direction.
    assert!(
        FW_MOD_SRC.contains("Err(_) => Slot::A,"),
        "read_active_slot must fall back to Slot::A on a fresh device — \
         BEGIN flips to Slot::B for the inactive target"
    );
}

// ═════════════════════════════════════════════════════════════════════
// SECTION B — `fw_update/staging.rs`
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// B1. Positive: `write_chunk` API surface.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_write_chunk_is_unsafe_and_returns_chunk_error() {
    // The function is `unsafe` because it programs flash. A `safe`
    // signature would invite misuse from a future caller that forgot
    // to bound-check first.
    assert!(
        STAGING_SRC.contains("pub unsafe fn write_chunk(\n    ctx: &mut FwUpdateCtx,\n    image_kind: u8,\n    chunk_offset: u32,\n    data: &[u8],\n) -> Result<(), ChunkError>"),
        "write_chunk must keep its `pub unsafe fn ... -> Result<(), ChunkError>` signature"
    );
}

#[test]
fn positive_write_chunk_dispatches_on_both_image_kinds() {
    assert!(STAGING_SRC.contains("FW_IMAGE_KIND_SECURE => flash::slot_secure_addr(slot),"));
    assert!(STAGING_SRC.contains("FW_IMAGE_KIND_NONSECURE => flash::slot_ns_addr(slot),"));
}

// ─────────────────────────────────────────────────────────────────────
// B2. Negative: QW-alignment guard.
//
// STM32U5 flash programs in 16-byte quadwords. A chunk at a non-QW
// offset would either misalign the program target (and silently
// fail-program a partial word) or trash neighbouring 16-byte regions.
// The guard rejects unaligned offsets up-front.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_write_chunk_rejects_non_qw_aligned_offset() {
    assert!(
        STAGING_SRC.contains("if chunk_offset & 0xF != 0 {"),
        "write_chunk must reject chunk_offset that's not QW-aligned (lower 4 bits set)"
    );
    assert!(
        STAGING_SRC.contains("return Err(ChunkError::NonMonotonic);"),
        "non-QW-aligned offsets must surface as NonMonotonic (companion-actionable)"
    );
}

#[test]
fn negative_write_chunk_only_accepts_short_final_chunk() {
    // The "short last chunk" branch must equal `expected - received`
    // — anything else is a malformed companion-side framing and the
    // handler must reject. This is the only path that bypasses the
    // QW-multiple length rule.
    assert!(
        STAGING_SRC.contains("if data.len() & 0xF != 0 {"),
        "write_chunk must guard the short-chunk path with a length-mismatch check"
    );
    assert!(
        STAGING_SRC.contains("let remaining = expected - ctx.received(image_kind);"),
        "the short-chunk path must compute `expected - received` as the only valid short length"
    );
    assert!(
        STAGING_SRC.contains("if (data.len() as u32) != remaining {"),
        "write_chunk must reject any short-chunk whose length != (expected - received)"
    );
}

#[test]
fn negative_write_chunk_pads_short_quadword_with_ff() {
    // NOR flash 1→0 constraint: erase leaves 0xFF, programming
    // clears bits to 0. A short final chunk is padded to a full QW
    // with 0xFF so the pad bytes are no-ops over erased flash.
    assert!(
        STAGING_SRC.contains("let mut qw = [0xFFu8; 16];"),
        "write_chunk's QW staging buffer must default to 0xFF (NOR erased) so pad bytes \
         don't violate the 1→0 program constraint"
    );
}

#[test]
fn negative_write_chunk_uses_verified_flash_primitive() {
    // The "verified" variant reads back after every QW program and
    // bails on mismatch. A regression to plain `write_quadword` (no
    // verify) would let a torn-write past the streaming hasher's
    // visibility — the COMMIT-time re-read would catch it eventually,
    // but the right place to fail is at the write site.
    assert!(
        STAGING_SRC.contains("flash::write_slot_quadword_verified(qw_addr, &qw)"),
        "write_chunk must use write_slot_quadword_verified (read-back + verify) — \
         the unverified variant must NOT regress in"
    );
    assert!(
        STAGING_SRC.contains(".map_err(|_| ChunkError::FlashError)?;"),
        "verified-write failure must surface as ChunkError::FlashError (distinct from BadChunk)"
    );
}

#[test]
fn negative_write_chunk_updates_hasher_after_successful_write() {
    // If the verified-write fails we DON'T want the running hasher
    // bumped — otherwise the next chunk's hasher would commit to a
    // byte that never reached flash. The hasher update must run only
    // after all QW writes have succeeded.
    let write_pos = STAGING_SRC
        .find("flash::write_slot_quadword_verified")
        .expect("write_chunk must call write_slot_quadword_verified");
    let hasher_pos = STAGING_SRC
        .find("ctx.secure_hasher.update(data);")
        .expect("write_chunk must update secure_hasher on success");
    assert!(
        write_pos < hasher_pos,
        "secure_hasher must be bumped AFTER write_slot_quadword_verified — a failed write \
         must not let the hasher diverge from what landed in flash"
    );
    let ns_hasher_pos = STAGING_SRC
        .find("ctx.nonsecure_hasher.update(data);")
        .expect("write_chunk must update nonsecure_hasher on success");
    assert!(
        write_pos < ns_hasher_pos,
        "nonsecure_hasher must be bumped AFTER write_slot_quadword_verified"
    );
}

#[test]
fn negative_write_chunk_received_counter_bumped_with_actual_byte_count() {
    // `received_*` must be incremented by `data.len()` (not by 16, not
    // by `chunk_len & !0xF`). A regression to a QW-rounded bump would
    // shift the next chunk_offset off-by-one for short final chunks
    // and break the monotonic-append invariant.
    assert!(
        STAGING_SRC.contains("ctx.received_secure += data.len() as u32;"),
        "received_secure must bump by data.len(), not by a rounded multiple of 16"
    );
    assert!(
        STAGING_SRC.contains("ctx.received_nonsecure += data.len() as u32;"),
        "received_nonsecure must bump by data.len(), not by a rounded multiple of 16"
    );
}

#[test]
fn negative_write_chunk_received_helper_returns_zero_on_unknown_kind() {
    // The `FwUpdateCtx::received` helper has a `_ => 0` arm. Combined
    // with the early `BadKind` reject before reaching this code path,
    // the helper's only role for `image_kind ∉ {0, 1}` is to return
    // a safe zero — never to panic or leak SRAM. Pin the arm.
    assert!(
        STAGING_SRC.contains("FW_IMAGE_KIND_SECURE => self.received_secure,")
            && STAGING_SRC.contains("FW_IMAGE_KIND_NONSECURE => self.received_nonsecure,")
            && STAGING_SRC.contains("_ => 0,"),
        "FwUpdateCtx::received must return 0 for unknown image_kind — not panic, not leak"
    );
}

// ═════════════════════════════════════════════════════════════════════
// SECTION C — `fw_update/verify.rs`
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// C1. Positive: error surface.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_image_check_error_variants_documented() {
    for variant in &[
        "StreamingHashMismatch",
        "SecureMismatch",
        "NonsecureMismatch",
        "LengthMismatch",
    ] {
        assert!(
            VERIFY_SRC.contains(variant),
            "ImageCheckError must keep `{variant}` — companion error router needs every variant"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// C2. Negative: `verify_images` ordering.
//
// COMMIT's defence in depth is "re-read flash and assert both running
// hash and signed hash agree". The order of checks matters: length
// before hash so we cheap-reject a torn image; streaming-vs-fresh
// before manifest-vs-fresh so we discriminate "flash hardware
// misbehaved" from "manifest disagrees with what we wrote".
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_images_checks_lengths_before_hashing() {
    let length_pos = VERIFY_SRC
        .find("if ctx.received_secure != m.secure_len() {")
        .expect("verify_images must compare received_secure against m.secure_len");
    let hash_pos = VERIFY_SRC
        .find("let streaming_secure = ctx.secure_hasher.clone_finalize();")
        .expect("verify_images must compute streaming_secure");
    assert!(
        length_pos < hash_pos,
        "verify_images must check length BEFORE doing any hash work — cheap reject of \
         truncated images"
    );
}

#[test]
fn negative_verify_images_compares_streaming_hash_before_manifest_hash() {
    // A regression that compared manifest hash first would conflate
    // "flash torn" with "manifest forged". Companion needs to
    // distinguish: streaming-vs-fresh disagreement means hardware
    // (stop, contact support); manifest-vs-fresh means bytes don't
    // match the signed preimage (refresh release & retry).
    let streaming_check_pos = VERIFY_SRC
        .find("if streaming_secure != fresh_secure {")
        .expect("verify_images must compare streaming vs fresh secure");
    let manifest_check_pos = VERIFY_SRC
        .find("if &fresh_secure != m.secure_hash() {")
        .expect("verify_images must compare fresh vs manifest secure_hash");
    assert!(
        streaming_check_pos < manifest_check_pos,
        "streaming-vs-fresh comparison must precede manifest-vs-fresh — they surface as \
         distinct ImageCheckError variants the companion routes differently"
    );
}

#[test]
fn negative_verify_images_distinguishes_secure_vs_nonsecure_mismatch() {
    // Companion uses the variant to point the user at the right half
    // of the bundle to re-fetch. A single "BothMismatch" arm would
    // lose that signal.
    assert!(
        VERIFY_SRC.contains("ImageCheckError::SecureMismatch")
            && VERIFY_SRC.contains("ImageCheckError::NonsecureMismatch"),
        "verify_images must distinguish secure vs nonsecure mismatch via separate variants"
    );
}

// ─────────────────────────────────────────────────────────────────────
// C3. Negative: `hash_flash` uses `read_volatile`.
//
// CLAUDE.md "Code Conventions": NS-supplied / flash-resident bytes
// must be loaded via byte-by-byte `read_volatile` so the compiler
// can't fold "we just wrote X, so X is the value" optimisations and
// elide the freshly-read-from-flash check.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_hash_flash_reads_via_byte_read_volatile_loop() {
    assert!(
        VERIFY_SRC.contains("use core::ptr::read_volatile;"),
        "verify.rs must import core::ptr::read_volatile"
    );
    assert!(
        VERIFY_SRC.contains("chunk[i] = read_volatile(src.add(i));"),
        "hash_flash must read each flash byte via read_volatile — a memcpy lowering \
         could elide the fresh-read defence the COMMIT path depends on"
    );
}

#[test]
fn negative_hash_flash_streams_in_bounded_buffer() {
    // The temporary buffer is `[0u8; 256]`. A regression that grew
    // the buffer to MANIFEST_SIZE or the full slot length would risk
    // SRAM exhaustion under the secure-world stack budget.
    assert!(
        VERIFY_SRC.contains("let mut chunk = [0u8; 256];"),
        "hash_flash must stream in a 256-byte staging buffer — bounded SRAM use"
    );
}

#[test]
fn negative_measurement_words_delegates_to_bip39_helper() {
    // The measurement words shown to the user MUST match the same
    // mapping FSBL uses (otherwise the OS-Fingerprint UX is broken —
    // user sees different words than the host-side fwmeasure tool).
    // The mapping is `sphincs_tz_bip39::hash_to_word_indices(&hash)`.
    assert!(
        VERIFY_SRC.contains("sphincs_tz_bip39::hash_to_word_indices(&hash)"),
        "measurement_words_for_inactive_slot must delegate to the canonical \
         hash_to_word_indices helper — every renderer must agree on the mapping"
    );
}

#[test]
fn negative_hash_to_word_indices_returns_eight_in_range_indices() {
    // Reference vector for the BIP-39 mapping. Every index must fit
    // inside the 2048-word wordlist; failing here would produce
    // out-of-range `WORDLIST[idx]` indexing — a panic the firmware
    // can't recover from.
    let hash = [0xAAu8; 32];
    let idx = hash_to_word_indices(&hash);
    assert_eq!(idx.len(), 8, "exactly 8 fingerprint words");
    for i in idx.iter() {
        assert!((*i as usize) < WORDLIST.len(), "word index out of wordlist range");
    }
}

#[test]
fn positive_measurement_words_use_first_88_bits_of_hash() {
    // The mapping consumes the first 88 bits (8 × 11) of the SHA-256.
    // Two hashes that agree on the first 88 bits but differ in the
    // remaining bits must produce identical words.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for i in 0..11 {
        a[i] = i as u8;
        b[i] = i as u8;
    }
    // Disagree in tail bytes (≥ byte 11).
    for i in 11..32 {
        a[i] = 0xAA;
        b[i] = 0x55;
    }
    assert_eq!(
        hash_to_word_indices(&a),
        hash_to_word_indices(&b),
        "the first 11 bytes (= 88 bits) of the hash must fully determine the 8 words"
    );
}

// ═════════════════════════════════════════════════════════════════════
// SECTION D — `fw_update/vendor_pubkey.rs`
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_vendor_pubkey_is_build_script_include() {
    // The whole file is `include!(concat!(env!("OUT_DIR"), "...")).
    // Keeping the body to that single line ensures the pubkey bytes
    // never get checked into git (they come from build.rs reading
    // FSBL_VENDOR_PUBKEY at compile time).
    assert!(
        VENDOR_SRC.contains("include!(concat!(env!(\"OUT_DIR\"), \"/vendor_pubkey_bytes.rs\"));"),
        "vendor_pubkey.rs must remain a single include! line — pubkey bytes must come from \
         build.rs, never from a checked-in literal"
    );
}

#[test]
fn negative_vendor_pubkey_does_not_inline_classical_keys() {
    // Defensive: no caller of this module ever needs an ECDSA / Ed25519
    // public key alongside the C10 vendor key. A regression that
    // pulled secp256k1 / Ed25519 helpers into this file would violate
    // invariant #5 (single C10 signer) at the FW-update boundary.
    let forbidden = ["secp256k1", "ECDSA", "Ed25519", "p256", "P256", "RSA"];
    for f in forbidden {
        assert!(
            !VENDOR_SRC.contains(f),
            "vendor_pubkey.rs must not mention banned signer `{f}` — invariant #5"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// SECTION E — `measured_boot.rs`
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// E1. Positive: flash region constants & shape.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_flash_base_addresses_pinned() {
    // The two FLASH_BASE addresses are load-bearing for the
    // OS-Fingerprint reproducibility check: `fwmeasure` host-side
    // and `firmware_hash` on-device MUST hash the same region for
    // the words to match.
    assert!(
        MEASURED_BOOT_SRC.contains("const FLASH_BASE: usize = 0x0C00_0000;"),
        "stm32u585 FLASH_BASE must remain 0x0C00_0000 — secure flash alias on Cortex-M33 \
         non-secure flag set"
    );
    assert!(
        MEASURED_BOOT_SRC.contains("const FLASH_BASE: usize = 0x1000_0000;"),
        "QEMU FLASH_BASE must remain 0x1000_0000 — matches mps2-an505 secure flash"
    );
}

#[test]
fn positive_title_and_words_durations_pinned() {
    // The boot UI flow shows "OS Fingerprint" for 1.5 s then renders
    // the 8 words for 4 s. The companion's `fwmeasure` regression
    // test expects this exact pacing. A regression to 0 s would
    // visually flash past the user.
    assert!(
        MEASURED_BOOT_SRC.contains("const TITLE_MS: u32 = 1_500;"),
        "TITLE_MS must remain 1500 — UX-stability pin"
    );
    assert!(
        MEASURED_BOOT_SRC.contains("const WORDS_MS: u32 = 4_000;"),
        "WORDS_MS must remain 4000 — UX-stability pin"
    );
}

#[test]
fn positive_firmware_hash_uses_sha256_over_flash_region() {
    assert!(
        MEASURED_BOOT_SRC.contains("Sha256::digest(flash).into();"),
        "firmware_hash must use Sha256::digest — same primitive fwmeasure uses host-side"
    );
    assert!(
        MEASURED_BOOT_SRC.contains("core::slice::from_raw_parts(FLASH_BASE as *const u8, size)"),
        "firmware_hash must hash a slice rooted at FLASH_BASE — fwmeasure expects this"
    );
}

// ─────────────────────────────────────────────────────────────────────
// E2. Negative: OS Fingerprint is NOT a seed word screen.
//
// The user's mental model is: "8 words on screen = my seed phrase".
// The OS-Fingerprint screen also shows 8 words. Confusion here is
// dangerous — users could read back the firmware fingerprint thinking
// they're verifying their seed.  The title screen ("OS Fingerprint")
// is what disambiguates. Pin it.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_measured_boot_title_distinguishes_fingerprint_from_seed_phrase() {
    assert!(
        MEASURED_BOOT_SRC.contains("show_status(\"OS Fingerprint\", \"\");"),
        "boot UI must show \"OS Fingerprint\" as the title — disambiguates from seed-phrase \
         screens that also use 8-word layouts"
    );
}

#[test]
fn negative_measured_boot_words_derive_from_firmware_hash_not_entropy() {
    // The function calls hash_to_word_indices(&hash) where `hash` is
    // `firmware_hash()` — never the bip39 entropy. A regression that
    // accidentally fed the entropy bytes through this same renderer
    // would leak the seed words to a "boot screen" the user has been
    // trained to ignore.
    let body_pos = MEASURED_BOOT_SRC
        .find("pub fn run() {")
        .expect("measured_boot must have a `pub fn run`");
    let body = &MEASURED_BOOT_SRC[body_pos..];
    let hash_pos = body
        .find("let hash = firmware_hash();")
        .expect("measured_boot::run must compute hash via firmware_hash()");
    let map_pos = body
        .find("let indices = hash_to_word_indices(&hash);")
        .expect("measured_boot::run must derive indices via hash_to_word_indices(&hash)");
    assert!(
        hash_pos < map_pos,
        "indices must be computed from the firmware hash, never from any other source"
    );
    // And explicitly: no `bip39::Mnemonic` / `to_seed` mentions.
    assert!(
        !MEASURED_BOOT_SRC.contains("Mnemonic"),
        "measured_boot must never reference the BIP-39 Mnemonic struct — that would risk \
         conflating fingerprint-words with seed-words"
    );
    assert!(
        !MEASURED_BOOT_SRC.contains("to_seed"),
        "measured_boot must never call bip39 ::to_seed — fingerprint is not a seed phrase"
    );
    assert!(
        !MEASURED_BOOT_SRC.contains("entropy"),
        "measured_boot must never reference entropy — fingerprint comes from firmware bytes only"
    );
}

#[test]
fn negative_measured_boot_render_uses_wordlist_indexed_by_bip39_indices() {
    // Indices feeding `WORDLIST[idx as usize]` must come from
    // `hash_to_word_indices`. Pin the textual access pattern.
    assert!(
        MEASURED_BOOT_SRC.contains("WORDLIST[indices[li] as usize].as_bytes();"),
        "render_all_words must look up the left-column word via WORDLIST[indices[li]]"
    );
    assert!(
        MEASURED_BOOT_SRC.contains("WORDLIST[indices[ri] as usize].as_bytes();"),
        "render_all_words must look up the right-column word via WORDLIST[indices[ri]]"
    );
}

#[test]
fn negative_measured_boot_layout_matches_8x4_two_column_grid() {
    // Two columns of 4 rows; left column at cols 0–7, right at 8–15.
    // A regression that put the right column at col 7 (no gap) would
    // collide the two halves at the screen mid-line.
    assert!(MEASURED_BOOT_SRC.contains("for row in 0..4 {"));
    assert!(MEASURED_BOOT_SRC.contains("buf[0] = b'1' + row as u8;"));
    assert!(MEASURED_BOOT_SRC.contains("buf[8] = b'5' + row as u8;"));
    assert!(MEASURED_BOOT_SRC.contains("let lmax = core::cmp::min(lw.len(), 6);"));
    assert!(MEASURED_BOOT_SRC.contains("let rmax = core::cmp::min(rw.len(), 6);"));
}

#[test]
fn negative_measured_boot_module_is_test_gated_out_at_crate_root() {
    // The module pulls in `crate::ui` and `crate::timeout` which are
    // both `#[cfg(not(test))]`. main.rs must keep `measured_boot`
    // behind the same gate or the host test build will fail to link.
    assert!(
        MAIN_SRC.contains("#[cfg(not(test))]\nmod measured_boot;"),
        "main.rs must gate `mod measured_boot;` on cfg(not(test)) — pulls in hw-only peers"
    );
}

// ═════════════════════════════════════════════════════════════════════
// SECTION F — `boot_ns.rs`
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// F1. Positive: VTOR_NS / register-clear / BXNS shape.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_vtor_ns_address_pinned() {
    // ARMv8-M Architecture Reference Manual: VTOR_NS is at
    // 0xE002_ED08. A regression to 0xE000_ED08 (the secure VTOR)
    // would set up the NS world to vector through secure flash.
    assert!(
        BOOT_NS_SRC.contains("const VTOR_NS: *mut u32 = 0xE002_ED08 as *mut u32;"),
        "VTOR_NS must be 0xE002_ED08 — ARMv8-M architectural NS Vector Table Offset Register"
    );
}

#[test]
fn positive_boot_ns_function_is_unsafe_no_return() {
    assert!(
        BOOT_NS_SRC.contains("pub unsafe fn boot(ns_vector_table: u32) -> !"),
        "boot fn must remain `pub unsafe fn boot(ns_vector_table: u32) -> !`"
    );
}

// ─────────────────────────────────────────────────────────────────────
// F2. Negative: register scrubbing before crossing the NS boundary.
//
// Cortex-M33's BXNS does NOT auto-clear general-purpose registers when
// branching from S to NS (unlike the SG/veneer-return path). The boot
// code must manually scrub every GPR + lr or the secure-world
// intermediates would leak into NS via the register file.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_boot_ns_scrubs_every_general_purpose_register() {
    // r0..r12 must each get a `mov rN, #0`. Pin every line.
    for r in 0..=12 {
        let pattern = format!("\"mov r{}", r);
        assert!(
            BOOT_NS_SRC.contains(&pattern),
            "boot_ns must scrub r{r} before crossing into the non-secure world — \
             secure-world intermediates must not leak via the GP register file"
        );
    }
}

#[test]
fn negative_boot_ns_loads_lr_with_entry_target_and_branches_via_bxns() {
    // The asm block puts ns_entry into lr and then `bxns lr`. A
    // regression that branched via plain BX (no NS) or via BLX would
    // not cross into the NS state at all, or would push the wrong
    // return target.
    assert!(
        BOOT_NS_SRC.contains("\"mov lr, {entry}\","),
        "boot_ns must load lr with the NS entry target (ns_entry)"
    );
    assert!(
        BOOT_NS_SRC.contains("\"bxns lr\","),
        "boot_ns must branch via `bxns lr` — only BXNS triggers the S→NS state transition"
    );
}

#[test]
fn negative_boot_ns_clears_thumb_bit_of_ns_entry() {
    // Cortex-M is always Thumb, so vector-table entries have bit 0
    // set. BXNS expects the target without the Thumb bit (it switches
    // state implicitly). A regression that branched to `ns_reset`
    // unmasked would HardFault.
    assert!(
        BOOT_NS_SRC.contains("let ns_entry = ns_reset & !1u32;"),
        "boot_ns must strip the Thumb bit from the NS reset vector before passing to bxns"
    );
}

#[test]
fn negative_boot_ns_sets_msp_ns_and_psp_ns_before_branch() {
    // MSP_NS must be the NS initial stack pointer; PSP_NS must be 0
    // so a future NS task that switches to PSP can't accidentally
    // inherit a secure-world stack. Pin both.
    assert!(
        BOOT_NS_SRC.contains("\"msr MSP_NS, {0}\","),
        "boot_ns must program MSP_NS via msr"
    );
    assert!(
        BOOT_NS_SRC.contains("\"msr PSP_NS, {1}\","),
        "boot_ns must program PSP_NS via msr"
    );
    assert!(
        BOOT_NS_SRC.contains("in(reg) ns_msp,") && BOOT_NS_SRC.contains("in(reg) 0u32,"),
        "boot_ns must pass ns_msp into MSP_NS and 0 into PSP_NS — never the other way round"
    );
}

#[test]
fn negative_boot_ns_clears_control_ns_before_branch() {
    // CONTROL_NS bit 1 = SPSEL (0 = MSP, 1 = PSP). We want MSP_NS for
    // the initial reset. Bit 0 = nPRIV (0 = privileged). NS world
    // starts privileged. Pin the zero load.
    assert!(
        BOOT_NS_SRC.contains("\"msr CONTROL_NS, {0}\","),
        "boot_ns must clear CONTROL_NS (privileged thread mode, MSP) before BXNS"
    );
}

#[test]
fn negative_boot_ns_programs_vtor_ns_before_reading_vector_table() {
    // The MPC must already be set up so the NS-flash alias is
    // readable. The function programs VTOR_NS via write_volatile,
    // then reads through `vt = ns_vector_table as *const u32`. Pin
    // the ordering — a regression that read first would risk reading
    // through a stale VTOR_NS (whose default 0x0000_0000 might point
    // at NS-reserved RAM).
    let vtor_pos = BOOT_NS_SRC
        .find("core::ptr::write_volatile(VTOR_NS, ns_vector_table);")
        .expect("boot_ns must write VTOR_NS before reading the vector table");
    let read_pos = BOOT_NS_SRC
        .find("core::ptr::read_volatile(vt);")
        .expect("boot_ns must read the NS MSP from vt[0]");
    assert!(
        vtor_pos < read_pos,
        "VTOR_NS must be programmed BEFORE the NS vector table is dereferenced"
    );
}

#[test]
fn negative_boot_ns_asm_block_is_noreturn() {
    // The final `bxns lr` does not return to Rust. Marking the asm
    // block `options(noreturn)` tells the compiler not to emit a
    // post-asm return path that would crash on re-entry from NS.
    assert!(
        BOOT_NS_SRC.contains("options(noreturn),"),
        "boot_ns's final asm! must carry options(noreturn)"
    );
}

#[test]
fn negative_boot_ns_module_is_test_gated_out_at_crate_root() {
    // boot_ns uses ARM-only `core::arch::asm!` mnemonics (msr MSP_NS,
    // bxns) and can't link on x86_64. main.rs must keep the module
    // behind `cfg(not(test))`.
    assert!(
        MAIN_SRC.contains("#[cfg(not(test))]\nmod boot_ns;"),
        "main.rs must gate `mod boot_ns;` on cfg(not(test)) — ARM-only asm"
    );
}

#[test]
fn negative_boot_ns_does_not_clear_fpu_registers_today() {
    // The current build does not enable the FPU. The file
    // explicitly notes that FPU register clear is omitted. If the
    // FPU is ever enabled this comment must be paired with new
    // `vmov.f32 sN, #0` clears — pin the docstring so the requirement
    // is impossible to miss.
    assert!(
        BOOT_NS_SRC.contains("FPU register clear is omitted because cortex-m-rt does not"),
        "boot_ns must document its FPU-register-clear gap — flipping FPU on without \
         adding `vmov.f32 sN, #0` clears would leak secure FPU state into NS"
    );
}

// ═════════════════════════════════════════════════════════════════════
// SECTION G — Cross-cutting invariants
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_slice_has_no_classical_signers() {
    // Invariant #5 — SPHINCS+C10 is the only signature primitive.
    // Pin the absence of classical-signer names across every file in
    // the slice.
    let banned = [
        "secp256k1",
        "ECDSA",
        "ed25519",
        "Ed25519",
        "p256",
        "P256",
        "RSA",
        "fors_c",
        "FORS_C",
    ];
    let files = &[
        ("fw_update/mod.rs", FW_MOD_SRC),
        ("fw_update/staging.rs", STAGING_SRC),
        ("fw_update/verify.rs", VERIFY_SRC),
        ("fw_update/vendor_pubkey.rs", VENDOR_SRC),
        ("measured_boot.rs", MEASURED_BOOT_SRC),
        ("boot_ns.rs", BOOT_NS_SRC),
    ];
    for (name, src) in files {
        for b in banned {
            assert!(
                !src.contains(b),
                "{name} must not mention banned signer `{b}` — invariant #5 (single C10 signer)"
            );
        }
    }
}

#[test]
fn negative_slice_does_not_introduce_rotation_or_reset_paths() {
    // Invariant #6 (bootstrap key immutable) and #7 (caps unresettable):
    // the FW-update slice must not expose any rotateMasterKeys / reset*
    // / increaseMax* helper.
    let banned = [
        "rotateMasterKeys",
        "resetBootstrapUses",
        "resetSlotUses",
        "increaseMaxBootstrap",
        "increaseMaxSlot",
    ];
    let files = &[
        ("fw_update/mod.rs", FW_MOD_SRC),
        ("fw_update/staging.rs", STAGING_SRC),
        ("fw_update/verify.rs", VERIFY_SRC),
        ("fw_update/vendor_pubkey.rs", VENDOR_SRC),
        ("measured_boot.rs", MEASURED_BOOT_SRC),
        ("boot_ns.rs", BOOT_NS_SRC),
    ];
    for (name, src) in files {
        for b in banned {
            assert!(
                !src.contains(b),
                "{name} must not introduce `{b}` — invariants #6/#7"
            );
        }
    }
}

#[test]
fn negative_slice_does_not_reference_ns_pin_or_entropy() {
    // CLAUDE.md invariant #4: no secrets in NS world; no PIN compare
    // in MCU. The FW-update slice is unlock-gated but the actual
    // secrets (PIN, entropy, master) must never appear in any of its
    // files.
    let banned = [
        "master_secret",
        "entropy_half_O",
        "entropy_half_E",
        "BIP-39 entropy",
    ];
    let files = &[
        ("fw_update/mod.rs", FW_MOD_SRC),
        ("fw_update/staging.rs", STAGING_SRC),
        ("fw_update/verify.rs", VERIFY_SRC),
        ("fw_update/vendor_pubkey.rs", VENDOR_SRC),
        ("measured_boot.rs", MEASURED_BOOT_SRC),
        ("boot_ns.rs", BOOT_NS_SRC),
    ];
    for (name, src) in files {
        for b in banned {
            assert!(
                !src.contains(b),
                "{name} must not reference `{b}` — FW-update path must touch zero secret state"
            );
        }
    }
}

#[test]
fn negative_main_rs_gates_fw_update_on_stm32u585() {
    // The whole `fw_update` tree depends on bank-2 flash + OTP
    // primitives only the real STM32U585 has. main.rs must keep the
    // mod-decl behind `feature = "stm32u585"` so QEMU and host builds
    // don't accidentally link a half-working version.
    assert!(
        MAIN_SRC.contains("#[cfg(all(feature = \"stm32u585\", not(test)))]\nmod fw_update;"),
        "main.rs must gate `mod fw_update;` on (feature = \"stm32u585\", not(test))"
    );
}

// ─────────────────────────────────────────────────────────────────────
// G2. Frozen-format pins for the manifest layout the COMMIT and
//     verify paths depend on. The slice itself doesn't redefine
//     these constants — but a future refactor to `fw_manifest` that
//     shifted any of them would silently break the COMMIT path.
//     Pin the byte-exact layout here too.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_manifest_layout_pins_used_by_commit_path() {
    // OFF_TRY_ONCE and OFF_CRC32 are the two offsets the slice's
    // COMMIT handler writes to. MANIFEST_SIZE is the snapshot buffer
    // length. OFF_SIGNATURE is what verify_signature consumes.
    assert_eq!(MANIFEST_SIZE, 8192);
    assert_eq!(OFF_TRY_ONCE, 4192);
    assert_eq!(OFF_CRC32, MANIFEST_SIZE - 4);
    assert_eq!(OFF_CRC32, 8188);
    assert_eq!(TRY_ONCE_TRIED, 0xAA);
    // OFF_SIGNATURE sits between OFF_MANIFEST_DIGEST and OFF_BOOT_CTR_SNAP.
    assert!(OFF_SIGNATURE > 0 && OFF_SIGNATURE < OFF_TRY_ONCE);
}

// ─────────────────────────────────────────────────────────────────────
// G3. Reference vector: a freshly-built manifest's `verify_*` chain.
//
// `fw_update::verify_manifest` is the integration point that calls
// each of these `ManifestRef` methods in turn. We can't call
// `verify_manifest` on host (it pulls in `crate::hw::flash` and the
// FI module's `rng::byte` via the `not(feature = "e2e-test")` path),
// but we CAN exercise every individual verify method via the same
// `fw_manifest` builder + `ManifestRef` API the secure code uses.
// This pins the per-step error mapping for every VerifyError variant
// the slice can produce.
// ─────────────────────────────────────────────────────────────────────

fn well_formed_manifest_bytes() -> [u8; MANIFEST_SIZE] {
    use fw_manifest::ManifestBuilder;
    let mut b = ManifestBuilder::new();
    b.init(fw_manifest::SLOT_B);
    b.fw_version(2);
    b.secure_image(&[0x11; 32], 4096);
    b.nonsecure_image(&[0x22; 32], 8192);
    b.vendor_pubkey_fpr(&[0x33; 32]);
    b.build_id(&[0x44; 32]);
    b.boot_counter_snap(0);
    b.try_once(fw_manifest::TRY_ONCE_COMMITTED);
    b.finalize_preimage();
    // Bogus signature — we don't have the vendor SK on host. The
    // structural / CRC / digest checks below run independently.
    b.set_signature(&[0u8; sphincs_c10::params::SIGNATURE_LEN]);
    b.finalize()
}

#[test]
fn positive_well_formed_manifest_passes_structural_crc_digest() {
    let bytes = well_formed_manifest_bytes();
    let m = fw_manifest::ManifestRef::new(&bytes);
    assert_eq!(m.verify_structural(), Ok(()));
    assert_eq!(m.verify_crc(), Ok(()));
    assert_eq!(m.verify_digest(), Ok(()));
}

#[test]
fn negative_manifest_bad_magic_rejected_by_structural_check() {
    let mut bytes = well_formed_manifest_bytes();
    // Stomp the magic. The CRC will of course also fail, but the
    // structural check fires first and surfaces BadMagic — which is
    // what the slice's BEGIN handler maps to FwUpdateBadManifest.
    bytes[fw_manifest::OFF_MAGIC] ^= 0xFF;
    let m = fw_manifest::ManifestRef::new(&bytes);
    assert_eq!(m.verify_structural(), Err(fw_manifest::VerifyError::BadMagic));
}

#[test]
fn negative_manifest_bad_crc_detected_after_byte_flip() {
    let mut bytes = well_formed_manifest_bytes();
    // Flip a byte well clear of magic/version/slot/CRC so structural
    // passes and only CRC fails.
    bytes[fw_manifest::OFF_BUILD_ID] ^= 0x01;
    let m = fw_manifest::ManifestRef::new(&bytes);
    assert_eq!(m.verify_structural(), Ok(()));
    assert_eq!(m.verify_crc(), Err(fw_manifest::VerifyError::BadCrc));
}

#[test]
fn negative_manifest_bad_digest_detected_after_hash_tamper() {
    // After finalize_preimage writes the canonical digest, manually
    // stomp the stored manifest_digest. verify_digest should reject.
    let mut bytes = well_formed_manifest_bytes();
    bytes[fw_manifest::OFF_MANIFEST_DIGEST] ^= 0xAA;
    // Re-compute CRC so we isolate the digest failure.
    let new_crc = fw_manifest::crc32_ieee(&bytes[..fw_manifest::OFF_CRC32]);
    bytes[fw_manifest::OFF_CRC32..fw_manifest::OFF_CRC32 + 4]
        .copy_from_slice(&new_crc.to_be_bytes());
    let m = fw_manifest::ManifestRef::new(&bytes);
    assert_eq!(m.verify_crc(), Ok(()));
    assert_eq!(m.verify_digest(), Err(fw_manifest::VerifyError::BadDigest));
}

#[test]
fn negative_manifest_rollback_check_rejects_equal_version() {
    // `verify_rollback(floor)` rejects when fw_version <= floor.
    // A manifest at exactly the floor must be refused — otherwise an
    // attacker could replay the current release indefinitely.
    let bytes = well_formed_manifest_bytes();
    let m = fw_manifest::ManifestRef::new(&bytes);
    // fw_version was set to 2 above.
    assert_eq!(
        m.verify_rollback(2),
        Err(fw_manifest::VerifyError::BelowRollback),
        "verify_rollback must reject fw_version == floor (replay defence)"
    );
    assert_eq!(
        m.verify_rollback(1),
        Ok(()),
        "verify_rollback must accept fw_version > floor"
    );
    assert_eq!(
        m.verify_rollback(99),
        Err(fw_manifest::VerifyError::BelowRollback),
        "verify_rollback must reject fw_version < floor"
    );
}

#[test]
fn negative_manifest_vendor_fpr_mismatch_rejected() {
    // verify_vendor_fpr compares the manifest's fpr field against
    // SHA256(pk_seed || pk_root). Different pubkey → mismatch.
    let bytes = well_formed_manifest_bytes();
    let m = fw_manifest::ManifestRef::new(&bytes);
    // Wrong vendor pubkey — fpr was set to [0x33; 32] above, doesn't
    // match SHA256 of any natural pubkey pair.
    let pk_seed = [0u8; sphincs_c10::params::N];
    let pk_root = [0u8; sphincs_c10::params::N];
    assert_eq!(
        m.verify_vendor_fpr(&pk_seed, &pk_root),
        Err(fw_manifest::VerifyError::WrongVendor),
        "verify_vendor_fpr must reject when fpr field disagrees with SHA256(pk_seed||pk_root)"
    );
}
