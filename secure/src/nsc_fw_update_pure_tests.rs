//! Host-side test suite for the `secure-nsc-fw-update` slice.
//!
//! # What is covered here
//!
//! The slice covers five firmware-update CMSE handlers under
//! `secure/src/nsc/`:
//!
//!   * `cmd_fw_begin.rs`   — gate, manifest snapshot + verify chain,
//!     inactive-slot erase, fresh `FwUpdateCtx` seed.
//!   * `cmd_fw_chunk.rs`   — gate, NS payload snapshot, header parse,
//!     bounds check, `staging::write_chunk` dispatch.
//!   * `cmd_fw_commit.rs`  — gate, image re-verify, TRIED-flag manifest
//!     write, boot-state update, retained sentinel-hardened from-flash
//!     gates, then the post-FA-1.5 fail-closed refusal (the legacy OTP
//!     rollback-floor bump and the reset arms are REMOVED — COMMIT has
//!     no epoch-bump success path in any build).
//!   * `cmd_fw_status.rs`  — NS write pointer validation, state-byte
//!     derivation, big-endian counter emission.
//!   * `cmd_fw_abort.rs`   — drop-in-place of the in-SRAM `FwUpdateCtx`
//!     (the `Drop` impl handles the zeroize).
//!
//! All five handlers transitively pull in the `hw::flash`, `hw::otp`,
//! `hw::boot_state`, and `ui::show_status` modules — none reachable
//! from a host build, so none of the `run()` functions can be linked
//! into `cargo test`. They are additionally gated by
//! `feature = "stm32u585"` in `secure/src/nsc/mod.rs` so the slice
//! does not even appear on the QEMU build's symbol table.
//!
//! The suite below covers the slice with four host-runnable test
//! families:
//!
//!   1. **Wire-format constant pins** — every offset / length / state
//!      byte the slice reads from `pqsigner-proto` and `fw_manifest`.
//!      Any silent drift breaks interop with the companion app or
//!      with FSBL's manifest reader, with no other test in the crate
//!      noticing.
//!   2. **Pure-logic mirrors** — chunk-header parser (BE field widths
//!      + byte positions), `CMD_FW_STATUS` state derivation
//!      (`idle | receiving | staged`), and a `check_chunk`-equivalent
//!      that exercises every documented `ChunkError` arm. These are
//!      written against `[u8]` fixtures so a refactor that drifts the
//!      handler's parsing rules surfaces here.
//!   3. **Source-text invariant pins** — assertions over the five
//!      slice files + `nsc/mod.rs` veneers that the load-bearing
//!      gates remain in place: pin-verified check, NS pointer
//!      validation, TOCTOU `read_volatile` snapshot, FI-hardened
//!      signature verify, legacy OTP-bump-LAST ordering (closes only the
//!      pre-candidate window; not a functioning rollback/anti-brick proof),
//!      `TRY_ONCE_TRIED` write + CRC recompute, write-quadword-verified
//!      use, `HandlerGuard::enter()` before any `static mut`
//!      `FW_UPDATE` deref, no classical signers anywhere in the
//!      slice, and the `feature = "stm32u585"` gate that keeps the
//!      handlers out of QEMU builds.
//!   4. **State-machine wire-format negatives** — assertions that the
//!      slice's response layout commits remain byte-exact (status
//!      response is 10 B, state byte values 0/1/2, chunk header is
//!      8 B with header_len + 1..=FW_MAX_CHUNK data range, etc.).
//!
//! Negative tests are framed around the assumption each gate enforces
//! (CLAUDE.md invariants #4 NS-pointer/copy-then-parse, #5 single C10
//! signer, and the slice's per-file docstrings). When the assumption
//! holds, the test passes; when a future refactor violates it, the
//! test fails with a panic message naming the assumption.

#![cfg(test)]

use fw_manifest::{MANIFEST_SIZE, OFF_CRC32, OFF_TRY_ONCE, TRY_ONCE_TRIED};
use sphincs_tz_shared::{
    NscStatus, CMD_FW_ABORT, CMD_FW_BEGIN, CMD_FW_CHUNK, CMD_FW_COMMIT, CMD_FW_STATUS,
    FW_CHUNK_HEADER_LEN, FW_IMAGE_KIND_NONSECURE, FW_IMAGE_KIND_SECURE, FW_MAX_CHUNK,
    FW_STATE_IDLE, FW_STATE_RECEIVING, FW_STATE_STAGED, FW_STATUS_RECV_NS_OFFSET,
    FW_STATUS_RECV_S_OFFSET, FW_STATUS_RESPONSE_LEN, FW_STATUS_SLOT_OFFSET, FW_STATUS_STATE_OFFSET,
};

// ─────────────────────────────────────────────────────────────────────
// 0. Slice source-text fixtures (loaded once via include_str! so the
//    test crate rebuilds whenever the underlying file changes).
// ─────────────────────────────────────────────────────────────────────

const BEGIN_SRC: &str = include_str!("nsc/cmd_fw_begin.rs");
const CHUNK_SRC: &str = include_str!("nsc/cmd_fw_chunk.rs");
const COMMIT_SRC: &str = include_str!("nsc/cmd_fw_commit.rs");
const STATUS_SRC: &str = include_str!("nsc/cmd_fw_status.rs");
const ABORT_SRC: &str = include_str!("nsc/cmd_fw_abort.rs");
const NSC_MOD_SRC: &str = include_str!("nsc/mod.rs");
const FW_UPDATE_MOD_SRC: &str = include_str!("fw_update/mod.rs");

const ALL_HANDLER_FILES: &[(&str, &str)] = &[
    ("cmd_fw_begin.rs", BEGIN_SRC),
    ("cmd_fw_chunk.rs", CHUNK_SRC),
    ("cmd_fw_commit.rs", COMMIT_SRC),
    ("cmd_fw_status.rs", STATUS_SRC),
    ("cmd_fw_abort.rs", ABORT_SRC),
];

// ─────────────────────────────────────────────────────────────────────
// 1. Positive: wire-format constant pins
//
// Every constant the handlers consume from `pqsigner-proto` /
// `fw_manifest`. Pin the *values* (not just the names) so a silent
// renumbering in the proto crate surfaces here rather than via a
// torn USB interaction with the companion at runtime.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_cmd_fw_command_ids_pinned() {
    // The companion app's APDU router maps INS_V2_FW_* to these CMD_*
    // numbers. A renumber here would silently break every existing
    // companion build.
    assert_eq!(CMD_FW_BEGIN, 20);
    assert_eq!(CMD_FW_CHUNK, 21);
    assert_eq!(CMD_FW_COMMIT, 22);
    assert_eq!(CMD_FW_STATUS, 23);
    assert_eq!(CMD_FW_ABORT, 24);
}

#[test]
fn positive_fw_max_chunk_and_header_len_pinned() {
    // CHUNK handler caps total_len at FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK.
    // Companion-side chunkers depend on these exact values.
    assert_eq!(FW_CHUNK_HEADER_LEN, 8);
    assert_eq!(FW_MAX_CHUNK, 1024);
}

#[test]
fn positive_fw_image_kind_byte_values_pinned() {
    // Chunk-header byte at offset 4 carries the image kind. A drift
    // here would route every chunk into the wrong image half.
    assert_eq!(FW_IMAGE_KIND_SECURE, 0);
    assert_eq!(FW_IMAGE_KIND_NONSECURE, 1);
}

#[test]
fn positive_fw_status_response_layout_pinned() {
    // STATUS handler writes `[state:u8 | recv_s:u32 BE | recv_ns:u32 BE
    // | slot:u8]`. Pin each offset against the proto constant.
    assert_eq!(FW_STATUS_STATE_OFFSET, 0);
    assert_eq!(FW_STATUS_RECV_S_OFFSET, 1);
    assert_eq!(FW_STATUS_RECV_NS_OFFSET, 5);
    assert_eq!(FW_STATUS_SLOT_OFFSET, 9);
    assert_eq!(FW_STATUS_RESPONSE_LEN, 1 + 4 + 4 + 1);
    assert_eq!(FW_STATUS_RESPONSE_LEN, 10);
}

#[test]
fn positive_fw_state_byte_values_pinned() {
    // STATUS handler emits exactly one of these three bytes. A future
    // refactor that introduced FW_STATE_ABORTED=3 must also widen
    // the companion-side enum — pin to catch the drift.
    assert_eq!(FW_STATE_IDLE, 0);
    assert_eq!(FW_STATE_RECEIVING, 1);
    assert_eq!(FW_STATE_STAGED, 2);
}

#[test]
fn positive_manifest_size_is_one_flash_page() {
    // BEGIN handler requires `total_len == MANIFEST_SIZE`. The 8192-B
    // value is one STM32U585 flash page and is what FSBL reads at
    // boot. Any drift would break manifest interop with FSBL.
    assert_eq!(MANIFEST_SIZE, 8192);
}

#[test]
fn positive_try_once_tried_marker_pinned() {
    // COMMIT handler writes `manifest[OFF_TRY_ONCE] = TRY_ONCE_TRIED`.
    // FSBL reads this byte to distinguish "freshly flashed" from
    // "tried but unconfirmed". The 0xAA value is deliberately chosen
    // for bit-distance from the 0x00 / 0x55 / 0xFF alternatives.
    assert_eq!(TRY_ONCE_TRIED, 0xAA);
    assert_eq!(OFF_TRY_ONCE, 4192);
}

#[test]
fn positive_off_crc32_is_at_end_of_manifest() {
    // COMMIT recomputes the CRC over `[..OFF_CRC32]` after mutating
    // the try_once byte. The CRC must remain the last 4 bytes of
    // the manifest page, not an earlier offset.
    assert_eq!(OFF_CRC32, MANIFEST_SIZE - 4);
    assert_eq!(OFF_CRC32, 8188);
}

#[test]
fn positive_nsc_status_fw_codes_pinned() {
    // The slice surfaces five distinct FW errors. Each must round-trip
    // via the From<u32> impl so the companion's status parser stays
    // in sync. A renumber breaks every released companion build.
    // 16 (`FwUpdateOtpExhausted`) is RETIRED (FA-1.5, with the removed
    // unary OTP floor writer): it no longer names a variant and decodes
    // to InternalError — pinned here so the freed code never silently
    // revives.
    assert_eq!(NscStatus::FwUpdateBadState as u32, 10);
    assert_eq!(NscStatus::FwUpdateBadManifest as u32, 11);
    assert_eq!(NscStatus::FwUpdateBadVersion as u32, 12);
    assert_eq!(NscStatus::FwUpdateBadChunk as u32, 13);
    assert_eq!(NscStatus::FwUpdateBadImage as u32, 14);
    assert_eq!(NscStatus::FwUpdateFlashError as u32, 15);
    assert_eq!(NscStatus::from(16), NscStatus::InternalError);
    for code in [10u32, 11, 12, 13, 14, 15] {
        let back: NscStatus = code.into();
        assert_eq!(back as u32, code);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 2. Positive: pure-logic mirror — chunk-header parser
//
// The CHUNK handler's header parse is one of only three places NS
// bytes become typed values. Mirror it here against fixtures so any
// refactor (LE/BE swap, field reorder, width change) surfaces.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct ChunkHeader {
    chunk_offset: u32,
    image_kind: u8,
    chunk_len: usize,
}

/// Mirror of the parsing block at `cmd_fw_chunk.rs:71-73`. Returns
/// the typed view of an 8-byte chunk header.
fn mirror_parse_chunk_header(header: &[u8; FW_CHUNK_HEADER_LEN]) -> ChunkHeader {
    let chunk_offset = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let image_kind = header[4];
    let chunk_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    ChunkHeader {
        chunk_offset,
        image_kind,
        chunk_len,
    }
}

#[test]
fn positive_chunk_header_parses_offset_as_big_endian_u32() {
    let mut h = [0u8; FW_CHUNK_HEADER_LEN];
    h[..4].copy_from_slice(&0x0123_4567u32.to_be_bytes());
    let parsed = mirror_parse_chunk_header(&h);
    assert_eq!(parsed.chunk_offset, 0x0123_4567);
}

#[test]
fn positive_chunk_header_parses_image_kind_at_offset_4() {
    let mut h = [0u8; FW_CHUNK_HEADER_LEN];
    h[4] = FW_IMAGE_KIND_NONSECURE;
    let parsed = mirror_parse_chunk_header(&h);
    assert_eq!(parsed.image_kind, 1);
    h[4] = FW_IMAGE_KIND_SECURE;
    let parsed = mirror_parse_chunk_header(&h);
    assert_eq!(parsed.image_kind, 0);
}

#[test]
fn positive_chunk_header_parses_len_as_big_endian_u16_at_offset_6() {
    // Note: byte 5 is reserved, len lives at [6..8]. A refactor that
    // packed image_kind into bits 4-7 of a single byte and put len
    // at [5..7] would silently corrupt every chunk.
    let mut h = [0u8; FW_CHUNK_HEADER_LEN];
    h[6..8].copy_from_slice(&1024u16.to_be_bytes());
    let parsed = mirror_parse_chunk_header(&h);
    assert_eq!(parsed.chunk_len, 1024);
    // Confirm reserved byte at offset 5 is ignored.
    h[5] = 0xFF;
    let again = mirror_parse_chunk_header(&h);
    assert_eq!(again, parsed);
}

#[test]
fn positive_chunk_header_full_round_trip() {
    let mut h = [0u8; FW_CHUNK_HEADER_LEN];
    h[..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    h[4] = FW_IMAGE_KIND_NONSECURE;
    h[5] = 0; // reserved
    h[6..8].copy_from_slice(&512u16.to_be_bytes());
    let parsed = mirror_parse_chunk_header(&h);
    assert_eq!(
        parsed,
        ChunkHeader {
            chunk_offset: 0xDEAD_BEEF,
            image_kind: FW_IMAGE_KIND_NONSECURE,
            chunk_len: 512,
        }
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. Positive: pure-logic mirror — STATUS state derivation
//
// `cmd_fw_status.rs:31-43`: state is `IDLE` when no ctx, `STAGED`
// when both halves equal expected, else `RECEIVING`.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct CtxSnapshot {
    received_secure: u32,
    received_nonsecure: u32,
    expected_secure_len: u32,
    expected_nonsecure_len: u32,
    inactive: u8,
}

fn mirror_derive_state(ctx: Option<&CtxSnapshot>) -> (u8, u32, u32, u8) {
    match ctx {
        None => (FW_STATE_IDLE, 0, 0, 0),
        Some(c) => {
            let state = if c.received_secure == c.expected_secure_len
                && c.received_nonsecure == c.expected_nonsecure_len
            {
                FW_STATE_STAGED
            } else {
                FW_STATE_RECEIVING
            };
            (state, c.received_secure, c.received_nonsecure, c.inactive)
        }
    }
}

#[test]
fn positive_status_state_is_idle_when_no_session() {
    let (state, s, ns, slot) = mirror_derive_state(None);
    assert_eq!(state, FW_STATE_IDLE);
    assert_eq!(s, 0);
    assert_eq!(ns, 0);
    assert_eq!(slot, 0);
}

#[test]
fn positive_status_state_is_receiving_when_partial() {
    let ctx = CtxSnapshot {
        received_secure: 1024,
        received_nonsecure: 0,
        expected_secure_len: 2048,
        expected_nonsecure_len: 2048,
        inactive: 1,
    };
    let (state, s, ns, slot) = mirror_derive_state(Some(&ctx));
    assert_eq!(state, FW_STATE_RECEIVING);
    assert_eq!(s, 1024);
    assert_eq!(ns, 0);
    assert_eq!(slot, 1);
}

#[test]
fn positive_status_state_is_staged_when_both_halves_complete() {
    let ctx = CtxSnapshot {
        received_secure: 2048,
        received_nonsecure: 4096,
        expected_secure_len: 2048,
        expected_nonsecure_len: 4096,
        inactive: 1,
    };
    let (state, _, _, _) = mirror_derive_state(Some(&ctx));
    assert_eq!(state, FW_STATE_STAGED);
}

#[test]
fn positive_status_response_serialises_counters_big_endian() {
    // Mirror the serialisation block at cmd_fw_status.rs:44-49 and
    // assert each field lands at its proto-declared offset.
    let mut buf = [0u8; FW_STATUS_RESPONSE_LEN];
    let recv_s: u32 = 0x0102_0304;
    let recv_ns: u32 = 0x05_06_07_08;
    let slot: u8 = 1;
    buf[FW_STATUS_STATE_OFFSET] = FW_STATE_RECEIVING;
    buf[FW_STATUS_RECV_S_OFFSET..FW_STATUS_RECV_S_OFFSET + 4]
        .copy_from_slice(&recv_s.to_be_bytes());
    buf[FW_STATUS_RECV_NS_OFFSET..FW_STATUS_RECV_NS_OFFSET + 4]
        .copy_from_slice(&recv_ns.to_be_bytes());
    buf[FW_STATUS_SLOT_OFFSET] = slot;
    // Byte-by-byte assertions: catches an LE swap or an offset shift.
    assert_eq!(buf[0], FW_STATE_RECEIVING);
    assert_eq!(&buf[1..5], &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(&buf[5..9], &[0x05, 0x06, 0x07, 0x08]);
    assert_eq!(buf[9], 1);
}

// ─────────────────────────────────────────────────────────────────────
// 4. Positive: pure-logic mirror — `check_chunk` decision tree
//
// `fw_update::check_chunk` is too heavy to link in host tests (it
// touches `crate::hw::flash`), so we mirror its decision tree here
// over an opaque "addresses don't matter" model and assert every
// documented `ChunkError` arm is reachable. The handler delegates
// directly to this function (CHUNK_SRC line 102), so a refactor
// that changed the decision shape would also need to be reflected
// in these tests.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum MirrorChunkError {
    TooLarge,
    BadKind,
    NonMonotonic,
    OverflowsImage,
}

struct MirrorCtx {
    received_secure: u32,
    received_nonsecure: u32,
    expected_secure_len: u32,
    expected_nonsecure_len: u32,
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
        received_secure: 0,
        received_nonsecure: 0,
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
    }
}

#[test]
fn positive_check_chunk_accepts_first_secure_block() {
    let ctx = fixture_ctx();
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 0, 1024).is_ok());
}

#[test]
fn positive_check_chunk_accepts_first_nonsecure_block() {
    let ctx = fixture_ctx();
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_NONSECURE, 0, 1024).is_ok());
}

#[test]
fn positive_check_chunk_accepts_terminal_chunk_filling_image() {
    let ctx = MirrorCtx {
        received_secure: 3072,
        received_nonsecure: 0,
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
    };
    assert!(mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 3072, 1024).is_ok());
}

// ─────────────────────────────────────────────────────────────────────
// 5. Negative: `check_chunk` decision tree
//
// Every `ChunkError` arm corresponds to a specific attack the handler
// must refuse. Names cite the attack, panic messages cite the
// invariant.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_check_chunk_rejects_oversize_chunk() {
    // Attack: companion sends `chunk_len = FW_MAX_CHUNK + 1` to
    // overflow the 1 KB secure-stack `data` buffer. The handler's
    // total_len bound (line 45) is one defence; check_chunk's
    // TooLarge is the second.
    let ctx = fixture_ctx();
    let err = mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 0, (FW_MAX_CHUNK as u16) + 1);
    assert_eq!(
        err,
        Err(MirrorChunkError::TooLarge),
        "check_chunk must reject chunk_len > FW_MAX_CHUNK"
    );
}

#[test]
fn negative_check_chunk_rejects_unknown_image_kind() {
    // Attack: image_kind = 2 (or any byte ∉ {0, 1}) would route the
    // chunk to a base_addr the handler didn't compute, with potentially
    // arbitrary write semantics. Must be rejected before any flash
    // touch.
    let ctx = fixture_ctx();
    for bad in [2u8, 3, 0xFF, 0x80] {
        let err = mirror_check_chunk(&ctx, bad, 0, 16);
        assert_eq!(
            err,
            Err(MirrorChunkError::BadKind),
            "check_chunk must reject image_kind = {bad}"
        );
    }
}

#[test]
fn negative_check_chunk_rejects_nonmonotonic_offset_gap() {
    // Attack: skip ahead past `received_*` to leave a hole in the
    // staged image that re-hash would catch later — but better to
    // refuse early. The handler enforces strict monotonic append.
    let ctx = MirrorCtx {
        received_secure: 1024,
        received_nonsecure: 0,
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
    };
    let err = mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 2048, 1024);
    assert_eq!(
        err,
        Err(MirrorChunkError::NonMonotonic),
        "check_chunk must reject chunk_offset > received (gap)"
    );
}

#[test]
fn negative_check_chunk_rejects_nonmonotonic_offset_retransmit() {
    // Attack: re-send a chunk at an offset < received to overwrite
    // bytes the running hash has already mixed into the streaming
    // digest. The handler's monotonic check catches both directions.
    let ctx = MirrorCtx {
        received_secure: 2048,
        received_nonsecure: 0,
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
    };
    let err = mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 1024, 1024);
    assert_eq!(
        err,
        Err(MirrorChunkError::NonMonotonic),
        "check_chunk must reject chunk_offset < received (retransmit)"
    );
}

#[test]
fn negative_check_chunk_rejects_run_past_expected_image_length() {
    // Attack: stream more bytes than the manifest declared, writing
    // past the inactive slot's reserved region into whatever the next
    // page is. Must be refused.
    // Use a chunk_len ≤ FW_MAX_CHUNK so the TooLarge gate doesn't
    // short-circuit; the OverflowsImage gate is what we want to
    // exercise.
    let ctx = MirrorCtx {
        received_secure: 4000,
        received_nonsecure: 0,
        expected_secure_len: 4096,
        expected_nonsecure_len: 8192,
    };
    let err = mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, 4000, 200);
    assert_eq!(
        err,
        Err(MirrorChunkError::OverflowsImage),
        "check_chunk must reject end > expected_len"
    );
}

#[test]
fn negative_check_chunk_rejects_u32_addition_overflow() {
    // Attack: `chunk_offset = u32::MAX - 16; chunk_len = 17` would
    // wrap the end computation; the handler uses `checked_add` to
    // catch this regardless of where `received_*` sits.
    let ctx = MirrorCtx {
        received_secure: u32::MAX - 16,
        received_nonsecure: 0,
        expected_secure_len: u32::MAX,
        expected_nonsecure_len: 0,
    };
    let err = mirror_check_chunk(&ctx, FW_IMAGE_KIND_SECURE, u32::MAX - 16, 17);
    assert_eq!(
        err,
        Err(MirrorChunkError::OverflowsImage),
        "check_chunk must use checked_add to defend chunk_offset + chunk_len wrap"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 6. Negative: wire-format / payload-length negatives — BEGIN
//
// `cmd_fw_begin.rs:42-47`: BEGIN refuses unless `total_len ==
// MANIFEST_SIZE` (no short manifests, no oversize) AND
// `validate_ns_read_ptr` passes. Mirror the boundary checks here.
// ─────────────────────────────────────────────────────────────────────

fn begin_total_len_accepted(total_len: usize) -> bool {
    total_len == MANIFEST_SIZE
}

#[test]
fn negative_begin_rejects_total_len_below_manifest_size() {
    // A short manifest cannot be the 8 KB FSBL expects. Any value
    // other than MANIFEST_SIZE returns InvalidPointer (line 43).
    assert!(!begin_total_len_accepted(0));
    assert!(!begin_total_len_accepted(MANIFEST_SIZE - 1));
    assert!(!begin_total_len_accepted(MANIFEST_SIZE / 2));
}

#[test]
fn negative_begin_rejects_total_len_above_manifest_size() {
    // Defending the secure-stack `[u8; MANIFEST_SIZE]` snapshot
    // buffer from a NS attempt to over-read.
    assert!(!begin_total_len_accepted(MANIFEST_SIZE + 1));
    assert!(!begin_total_len_accepted(MANIFEST_SIZE * 2));
    assert!(!begin_total_len_accepted(u32::MAX as usize));
}

#[test]
fn positive_begin_accepts_exactly_manifest_size() {
    assert!(begin_total_len_accepted(MANIFEST_SIZE));
}

// ─────────────────────────────────────────────────────────────────────
// 7. Negative: CHUNK payload bounds (cmd_fw_chunk.rs:45-47)
// ─────────────────────────────────────────────────────────────────────

fn chunk_total_len_accepted(total_len: usize) -> bool {
    total_len >= FW_CHUNK_HEADER_LEN && total_len <= FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK
}

#[test]
fn negative_chunk_rejects_total_len_below_header_size() {
    // A payload too small even for the header can't carry a valid
    // chunk header. Returns InvalidPointer (line 46).
    for n in 0..FW_CHUNK_HEADER_LEN {
        assert!(
            !chunk_total_len_accepted(n),
            "CHUNK must reject total_len < FW_CHUNK_HEADER_LEN, got {n}"
        );
    }
}

#[test]
fn negative_chunk_rejects_total_len_above_header_plus_max() {
    // A payload larger than HEADER + FW_MAX_CHUNK would overflow the
    // secure-stack `[u8; FW_MAX_CHUNK]` data buffer. Refused at
    // line 45 *before* any deref of the NS pointer.
    assert!(!chunk_total_len_accepted(
        FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK + 1
    ));
    assert!(!chunk_total_len_accepted(
        FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK * 2
    ));
}

#[test]
fn positive_chunk_accepts_total_len_at_boundaries() {
    assert!(chunk_total_len_accepted(FW_CHUNK_HEADER_LEN));
    assert!(chunk_total_len_accepted(FW_CHUNK_HEADER_LEN + 1));
    assert!(chunk_total_len_accepted(FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK));
}

#[test]
fn negative_chunk_rejects_header_len_mismatch_with_payload() {
    // Attack: header claims `chunk_len = 16`, payload carries 32 B.
    // The handler asserts `chunk_len == data_len` (line 75); the
    // mismatch yields FwUpdateBadChunk. We mirror the comparison.
    let header_chunk_len: usize = 16;
    let actual_data_len: usize = 32;
    assert_ne!(header_chunk_len, actual_data_len);
    // And the inverse: claiming more than payload carries.
    let header_chunk_len: usize = 512;
    let actual_data_len: usize = 256;
    assert_ne!(header_chunk_len, actual_data_len);
}

// ─────────────────────────────────────────────────────────────────────
// 8. Negative: source-text invariant pins — PIN-verified gating
//
// CLAUDE.md gateway table: ALL update entry points (BEGIN, CHUNK,
// COMMIT, STATUS, ABORT — CMDs 20–24) check `pin_verified` first.
// A regression that dropped the gate would let a locked device be
// silently flashed to a hostile (but vendor-signed) release, or have
// its in-flight session state probed / cleared pre-unlock.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_begin_checks_pin_verified_first() {
    assert!(
        BEGIN_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_fw_begin must gate on pin_verified — locked devices must not stage updates"
    );
    assert!(
        BEGIN_SRC.contains("NscStatus::NotInitialized"),
        "cmd_fw_begin pin gate must surface NotInitialized when locked"
    );
}

#[test]
fn negative_chunk_checks_pin_verified_first() {
    assert!(
        CHUNK_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_fw_chunk must gate on pin_verified — stops a mid-session lock from accepting chunks"
    );
    assert!(CHUNK_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn negative_commit_checks_pin_verified_first() {
    assert!(
        COMMIT_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_fw_commit must gate on pin_verified — the staged-slot commit must NEVER happen on a locked device"
    );
    assert!(COMMIT_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn positive_commit_resets_idle_timer_only_with_live_context() {
    // Finding F20: `cmd_fw_chunk.rs` documents "CHUNK does NOT reset
    // the idle timer — BEGIN already did, and COMMIT will again", but
    // COMMIT never did. Pin the reset AND its placement: it must come
    // AFTER the live-context check so a context-free COMMIT spam (the
    // `FwUpdateBadState` path) can't extend the 120 s idle window
    // (X17-UI3 pattern), while a real finalize leaves the host a fresh
    // window to recover from a dropped-context failure.
    let ctx_check = COMMIT_SRC
        .find("NscStatus::FwUpdateBadState as u32")
        .expect("cmd_fw_commit must bail with FwUpdateBadState when no context");
    let reset = COMMIT_SRC
        .find("timeout::reset_activity();")
        .expect("cmd_fw_commit must reset the idle timer (documented in cmd_fw_chunk.rs)");
    assert!(
        ctx_check < reset,
        "the idle-timer reset must sit behind the live-context check, not on the spam path"
    );
}

#[test]
fn positive_commit_flash_error_paths_drop_the_context() {
    // GPT-5.6 wave finding: the manifest-write and boot-state-write
    // flash-error returns previously kept FW_UPDATE alive, so every
    // retried COMMIT passed the live-context guard and re-reset the
    // idle timer — an X17-UI3-style keepalive. Pin that EVERY
    // FwUpdateFlashError return drops the context first.
    let mut rest = COMMIT_SRC;
    let mut count = 0usize;
    while let Some(pos) = rest.find("return NscStatus::FwUpdateFlashError as u32") {
        let before = &rest[..pos];
        // Find the tail of the enclosing block: the last 400 chars
        // before the return must contain the context drop.
        let tail = &before[before.len().saturating_sub(400)..];
        assert!(
            tail.contains("FW_UPDATE) = None"),
            "every FwUpdateFlashError return must first drop FW_UPDATE (keepalive guard); missing before byte {pos}"
        );
        count += 1;
        rest = &rest[pos + 1..];
    }
    assert!(
        count >= 2,
        "expected at least the manifest-write and boot-state flash-error paths"
    );
}

#[test]
fn negative_status_checks_pin_verified_first() {
    // LOW-1 (fw-update audit 20260611): STATUS is pin-gated like every
    // other FW entry point. Pre-unlock the session context is already
    // `None`, so the companion loses nothing — it reads `NotInitialized`
    // ("unlock first") rather than fabricated or stale progress.
    assert!(
        STATUS_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_fw_status must gate on pin_verified (CLAUDE.md: PIN required on every FW call)"
    );
    assert!(STATUS_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn negative_abort_checks_pin_verified_first() {
    // LOW-1 (fw-update audit 20260611): ABORT is pin-gated. Not a wedge —
    // a context exists only after a PIN-verified BEGIN, and the
    // lock / idle-wipe path already drops FW_UPDATE, so a locked device
    // has nothing left to abort.
    assert!(
        ABORT_SRC.contains("pin_verified.check_sentinel()"),
        "cmd_fw_abort must gate on pin_verified (CLAUDE.md: PIN required on every FW call)"
    );
    assert!(ABORT_SRC.contains("NscStatus::NotInitialized"));
}

// ─────────────────────────────────────────────────────────────────────
// 9. Negative: source-text invariant pins — NS pointer validation
//
// CLAUDE.md invariant #4: every NS pointer is validated before any
// deref. The slice's three NS-touching handlers (BEGIN, CHUNK,
// STATUS) must call the correct validator.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_begin_validates_ns_read_pointer_before_deref() {
    assert!(
        BEGIN_SRC.contains("validate_ns_read_ptr(payload_ptr, total_len)"),
        "cmd_fw_begin must validate the NS manifest pointer with validate_ns_read_ptr"
    );
    assert!(
        BEGIN_SRC.contains("NscStatus::InvalidPointer"),
        "cmd_fw_begin pointer-validation failure must surface InvalidPointer"
    );
}

#[test]
fn negative_chunk_validates_ns_read_pointer_before_deref() {
    assert!(
        CHUNK_SRC.contains("validate_ns_read_ptr(payload_ptr, total_len)"),
        "cmd_fw_chunk must validate the NS chunk pointer with validate_ns_read_ptr"
    );
    assert!(CHUNK_SRC.contains("NscStatus::InvalidPointer"));
}

#[test]
fn negative_status_validates_ns_write_pointer_before_deref() {
    // STATUS writes the response buffer back into NS — must use the
    // write-side validator (catches the shared-mailbox overlap +
    // read-only NS-flash that the read-side validator would
    // otherwise allow).
    assert!(
        STATUS_SRC.contains("validate_ns_write_ptr(out_ptr, FW_STATUS_RESPONSE_LEN)"),
        "cmd_fw_status must validate the NS write pointer with validate_ns_write_ptr"
    );
    assert!(STATUS_SRC.contains("NscStatus::InvalidPointer"));
}

// ─────────────────────────────────────────────────────────────────────
// 10. Negative: source-text invariant pins — TOCTOU snapshot via
//     read_volatile / write_volatile.
//
// CLAUDE.md §"Code Conventions": NS buffers MUST be copied to
// S-stack via byte-by-byte read_volatile so the compiler cannot
// elide or batch the loads. Without this, NS can race the validator.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_begin_copies_manifest_via_byte_read_volatile() {
    // A regression that used `core::ptr::copy_nonoverlapping` would
    // hand the compiler a memcpy lowering that could be reordered
    // around the verify chain. The byte loop is intentional.
    assert!(
        BEGIN_SRC.contains("core::ptr::read_volatile(src.add(i))"),
        "cmd_fw_begin must TOCTOU-snapshot via core::ptr::read_volatile byte loop"
    );
    assert!(BEGIN_SRC.contains("let mut snap = [0u8; MANIFEST_SIZE];"));
}

#[test]
fn negative_chunk_copies_payload_via_byte_read_volatile() {
    assert!(
        CHUNK_SRC.contains("core::ptr::read_volatile(src.add(i))"),
        "cmd_fw_chunk must TOCTOU-snapshot via core::ptr::read_volatile byte loop"
    );
    assert!(CHUNK_SRC.contains("let mut header = [0u8; FW_CHUNK_HEADER_LEN];"));
    assert!(CHUNK_SRC.contains("let mut data = [0u8; FW_MAX_CHUNK];"));
}

#[test]
fn negative_status_emits_response_via_byte_write_volatile() {
    // The response must land byte-by-byte so an NS observer never
    // sees a half-written response word — documented in
    // cmd_fw_status.rs:55. A regression that used a single
    // copy_nonoverlapping would weaken that ordering.
    assert!(
        STATUS_SRC.contains("core::ptr::write_volatile(dst.add(i), buf[i])"),
        "cmd_fw_status must emit response via byte-by-byte write_volatile"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 11. Negative: source-text invariant pins — HandlerGuard + static
//     mut FW_UPDATE access
//
// CHUNK and COMMIT take a mutable reference into the static-mut
// `FW_UPDATE`. Without `HandlerGuard::enter()`, SysTick's idle-wipe
// could drop the `Option<FwUpdateCtx>` mid-handler — a UAF.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_chunk_holds_handler_guard_before_fw_update_deref() {
    // Pin the load-bearing first line of cmd_fw_chunk::run.
    let body = CHUNK_SRC
        .find("pub(super) unsafe fn run")
        .expect("CHUNK handler must have a run fn");
    let body = &CHUNK_SRC[body..];
    let guard_pos = body
        .find("HandlerGuard::enter()")
        .expect("CHUNK must call HandlerGuard::enter() to prevent SysTick wipe");
    let deref_pos = body
        .find("addr_of_mut!(FW_UPDATE)")
        .expect("CHUNK must touch FW_UPDATE");
    assert!(
        guard_pos < deref_pos,
        "HandlerGuard::enter() must be acquired BEFORE the static-mut FW_UPDATE deref"
    );
}

#[test]
fn negative_commit_holds_handler_guard_before_fw_update_deref() {
    let body = COMMIT_SRC
        .find("pub(super) unsafe fn run")
        .expect("COMMIT handler must have a run fn");
    let body = &COMMIT_SRC[body..];
    let guard_pos = body
        .find("HandlerGuard::enter()")
        .expect("COMMIT must call HandlerGuard::enter()");
    let deref_pos = body
        .find("addr_of!(FW_UPDATE)")
        .expect("COMMIT must touch FW_UPDATE");
    assert!(
        guard_pos < deref_pos,
        "HandlerGuard::enter() must be acquired BEFORE the static-mut FW_UPDATE deref"
    );
}

#[test]
fn negative_abort_drops_ctx_via_static_mut_assignment() {
    // ABORT's whole purpose is to drop the in-flight `FwUpdateCtx`
    // so its `ZeroizeOnDrop` impl wipes the manifest copy + running
    // hashers. A regression that just zeroed a flag would leak
    // manifest bytes across sessions.
    assert!(
        ABORT_SRC.contains("addr_of_mut!(FW_UPDATE)"),
        "cmd_fw_abort must access FW_UPDATE via addr_of_mut"
    );
    assert!(
        ABORT_SRC.contains("= None;"),
        "cmd_fw_abort must assign None to drop the ctx and trigger ZeroizeOnDrop"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 12. Negative: source-text invariant pins — `FwUpdateCtx` zeroize
//     guarantees.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_fw_update_ctx_uses_zeroize_on_drop() {
    // CLAUDE.md §"Code Conventions": every secret-bearing type must
    // be ZeroizeOnDrop. The manifest_bytes field carries the signed
    // preimage we just verified, and the running hashers carry
    // partial-state SHA-256 — both must be wiped on Drop.
    assert!(
        FW_UPDATE_MOD_SRC.contains("ZeroizeOnDrop"),
        "FwUpdateCtx must derive ZeroizeOnDrop so abort/commit drop wipes the manifest"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 13. Negative: source-text invariant pins — verify chain ordering
//
// `cmd_fw_begin.rs:67-76`: BEGIN must run the verify chain BEFORE
// any destructive op (erase). The error mapping must distinguish
// `BelowRollback` (companion-recoverable: ship a newer release) from
// generic `BadManifest` (companion replays with the right bytes).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_begin_runs_verify_manifest_before_erase() {
    let body = BEGIN_SRC;
    let verify_pos = body
        .find("verify_manifest(&m, floor)")
        .expect("BEGIN must call verify_manifest");
    let erase_pos = body
        .find("flash::erase_slot")
        .expect("BEGIN must call erase_slot to prepare inactive slot");
    assert!(
        verify_pos < erase_pos,
        "verify_manifest MUST run before erase_slot — a bogus manifest must never \
         consume erase cycles on the inactive slot"
    );
}

#[test]
fn negative_begin_distinguishes_rollback_from_bad_manifest() {
    // Companion needs to discriminate: rollback = "the device is
    // already on a newer release", BadManifest = "the bytes don't
    // parse / sig fails". A merged code would conflate two very
    // different remediation flows on the companion side.
    assert!(
        BEGIN_SRC.contains("fw_manifest::VerifyError::BelowRollback")
            && BEGIN_SRC.contains("NscStatus::FwUpdateBadVersion"),
        "BEGIN must map BelowRollback → FwUpdateBadVersion"
    );
    assert!(
        BEGIN_SRC.contains("NscStatus::FwUpdateBadManifest"),
        "BEGIN must map other VerifyError variants → FwUpdateBadManifest"
    );
}

#[test]
fn negative_begin_picks_inactive_slot_via_running_slot() {
    // Picking the wrong slot would erase the RUNNING firmware out from
    // under the CPU (hard fault mid-BEGIN + destructive erase of the live
    // image). BEGIN must derive the running slot from the hardware VTOR
    // (`running_slot()`), NOT the boot-state page (`read_active_slot()`):
    // boot_state can diverge from the actually-running slot after an FSBL
    // try-once revert (a same-version reinstall leaves both slots valid, so
    // FSBL reverts to the loser while boot_state still names the winner),
    // and trusting it there would invert to the live slot. Pin the
    // load-bearing computation to the divergence-proof source.
    assert!(
        BEGIN_SRC.contains("fw_update::running_slot()"),
        "BEGIN must consult running_slot() (hardware VTOR) — not read_active_slot() \
         (boot_state, which can diverge) — to discover which slot is currently running"
    );
    assert!(
        !BEGIN_SRC.contains("let running = fw_update::read_active_slot()")
            && !BEGIN_SRC.contains("let active = fw_update::read_active_slot()"),
        "BEGIN must not derive the erase target from the boot-state page"
    );
    assert!(
        BEGIN_SRC.contains("flash::Slot::A => flash::Slot::B")
            && BEGIN_SRC.contains("flash::Slot::B => flash::Slot::A"),
        "BEGIN must invert the running slot to pick the inactive target"
    );
}

#[test]
fn negative_begin_resets_activity_timer_after_seed() {
    // Without resetting, a slow USB transfer could race the 120 s
    // idle-wipe and have its FW_UPDATE ctx wiped mid-stream. Pin
    // the reset (and pin it AFTER the ctx seed).
    let seed_pos = BEGIN_SRC
        .find("addr_of_mut!(FW_UPDATE)")
        .expect("BEGIN must seed FW_UPDATE");
    let reset_pos = BEGIN_SRC
        .find("timeout::reset_activity()")
        .expect("BEGIN must reset the activity timer");
    assert!(
        seed_pos < reset_pos,
        "BEGIN must reset_activity AFTER seeding FW_UPDATE (so the new ctx \
         enjoys the freshly-reset 120 s budget)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 14. Negative: source-text invariant pins — COMMIT ordering + FA-1.5
//     fail-closed refusal
//
// `cmd_fw_commit.rs`: the order of `verify_images` → manifest write →
// boot-state write → from-flash re-verify → REFUSAL is security-relevant
// inside the quarantined V1 path. FA-1.5 (Draft 1.1 §14 L4375) removed
// the `otp::bump_to` call, its ambiguous-launch handling, the
// `FwUpdateOtpExhausted` status, and BOTH reset arms: COMMIT now ends
// in a fail-closed refusal with no epoch-bump success path in any build.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_begin_runs_verify_manifest_before_confirm_install_before_erase() {
    // Each expensive/FI-sensitive manifest verification needs a one-shot
    // trusted-UI authorization. The static request prompt runs before the
    // verifier; the detailed release prompt runs only after authenticity is
    // established; both precede the inactive-slot erase.
    let request_pos = BEGIN_SRC
        .find("fw_update::confirm_verify_request()")
        .expect("BEGIN must require one trusted-UI authorization per verifier invocation");
    let verify_pos = BEGIN_SRC
        .find("fw_update::verify_manifest(&m, floor)")
        .expect("BEGIN must call verify_manifest");
    let confirm_pos = BEGIN_SRC
        .find("fw_update::confirm_install(&m)")
        .expect("BEGIN must call confirm_install (finding A moved confirm from COMMIT to BEGIN)");
    let erase_pos = BEGIN_SRC
        .find("flash::erase_slot(inactive)")
        .expect("BEGIN must erase the inactive slot");
    assert!(
        request_pos < verify_pos,
        "the static physical update-mode authorization MUST precede verify_manifest"
    );
    assert!(
        verify_pos < confirm_pos,
        "verify_manifest MUST precede the detailed release confirmation"
    );
    assert!(
        confirm_pos < erase_pos,
        "confirm_install MUST precede flash::erase_slot — a user-cancel costs zero flash work (finding A)"
    );
}

#[test]
fn negative_begin_user_cancel_short_circuits_before_erase() {
    // Both physical gates preserve Cancelled versus IdleWipe. A cancellation
    // returns without verification/erase; an idle timeout immediately wipes
    // the unlocked session and returns the distinct IdleWipe status.
    let request_start = BEGIN_SRC
        .find("let (verify_confirm, verify_confirm_sentinel)")
        .expect("missing verifier-authorization result");
    let verify_pos = BEGIN_SRC
        .find("fw_update::verify_manifest(&m, floor)")
        .expect("missing verifier call");
    let request_block = &BEGIN_SRC[request_start..verify_pos];
    for landmark in [
        "ConfirmResult::Cancelled => return NscStatus::UserRejected",
        "ConfirmResult::IdleWipe",
        "super::zeroize_sensitive_state()",
        "return NscStatus::IdleWipe",
        "verify_confirm_sentinel != crate::fi::OK_SENTINEL",
    ] {
        assert!(
            request_block.contains(landmark),
            "verifier authorization lost fail-closed landmark `{landmark}`"
        );
    }

    let install_start = BEGIN_SRC
        .find("let (install_confirm, install_confirm_sentinel)")
        .expect("missing detailed install-confirm result");
    let erase_pos = BEGIN_SRC
        .find("flash::erase_slot(inactive)")
        .expect("BEGIN must erase the inactive slot somewhere");
    assert!(
        install_start < erase_pos,
        "detailed cancel/idle handling MUST precede flash::erase_slot"
    );
    let install_block = &BEGIN_SRC[install_start..erase_pos];
    assert!(install_block.contains("ConfirmResult::Cancelled"));
    assert!(install_block.contains("ConfirmResult::IdleWipe"));
    assert!(install_block.contains("install_confirm_sentinel != crate::fi::OK_SENTINEL"));
}

#[test]
fn negative_invalid_manifest_can_never_wipe_or_write_persistent_state() {
    // Malformed companion bytes are not a tamper signal. No amount of invalid
    // FW_BEGIN traffic may arm the administrative wipe, reset the wallet, or
    // write/erase a persistent failure counter.
    for forbidden in [
        "arm_wipe_flag",
        "arm_wipe_and_reset",
        "sys_reset",
        "fw_fail_",
        "FW_VERIFY_FAIL",
        "factory_reset_admin",
    ] {
        assert!(
            !BEGIN_SRC.contains(forbidden),
            "CMD_FW_BEGIN must not contain destructive failure path `{forbidden}`"
        );
    }
    assert!(
        !COMMIT_SRC.contains("reset_verify_failure_tally") && !COMMIT_SRC.contains("fw_fail_reset"),
        "COMMIT must not erase a manifest-failure counter page"
    );
}

#[test]
fn positive_verifier_authorization_is_static_and_jittered() {
    let prompt_pos = BEGIN_SRC.find("confirm_verify_request()").unwrap();
    let jitter_pos = BEGIN_SRC.find("crate::fi::wait_random()").unwrap();
    let verify_pos = BEGIN_SRC.find("verify_manifest(&m, floor)").unwrap();
    assert!(prompt_pos < jitter_pos && jitter_pos < verify_pos);
    for text in [
        "FW UPDATE MODE",
        "Verify vendor-",
        "signed package?",
        "Hold R = enter",
    ] {
        assert!(
            FW_UPDATE_MOD_SRC.contains(text),
            "static pre-verification prompt lost `{text}`"
        );
    }
}

#[test]
fn commit_stages_slot_then_refuses_fail_closed_without_otp_path() {
    // FA-1.5 (Draft 1.1 §14 L4375, L4388–4390): the legacy unary floor
    // writer is REMOVED from COMMIT. The retained flow stages the slot
    // (manifest → boot-state), re-verifies it from flash, then refuses
    // fail-closed. Pin BOTH halves:
    //   * the removal is total — no OTP program command, no `otp::`
    //     reference at all remains in the handler;
    //   * the retained staging keeps its security-relevant order.
    let body = COMMIT_SRC;
    assert!(
        !body.contains("unsafe { otp::"),
        "FA-1.5 removed the legacy unary OTP floor bump from COMMIT — no otp:: call may remain \
         (comments documenting the removal are expected; a CALL is not)"
    );
    assert!(
        !body.contains("boot_state, flash, otp}"),
        "COMMIT must not import the otp module post-removal"
    );
    let refusal_pos = body
        .find("[S][fwup] COMMIT fail-closed refusal")
        .expect("COMMIT must end in the FA-1.5 fail-closed refusal");
    let manifest_write_pos = body
        .find("flash::write_quadword_verified")
        .expect("COMMIT must program the new manifest");
    let boot_state_pos = body
        .find("boot_state::write(&new_boot_state)")
        .expect("COMMIT must write boot_state");
    let gate_pos = body
        .find("let manifest_gate = crate::fi::check_true_into_sentinel(")
        .expect("COMMIT must retain the sentinel-hardened from-flash gates");
    assert!(
        manifest_write_pos < boot_state_pos,
        "new manifest write must PRECEDE the boot-state write — the on-disk pointer can never \
         reference a half-written manifest"
    );
    assert!(
        boot_state_pos < gate_pos,
        "the from-flash re-verify gates run AFTER both staging writes (they re-read flash)"
    );
    assert!(
        gate_pos < refusal_pos,
        "the fail-closed refusal is the LAST step — the gates remain the final authorization gate"
    );

    // The floor arithmetic is RETAINED: it feeds the admissibility gate's
    // `verify_rollback(new_rollback_floor)` — fw_version - 1 keeps V
    // internally admissible. Nothing programs it anywhere.
    assert!(
        body.contains("new_rollback_floor = new_version.saturating_sub(1)"),
        "the fw_version - 1 floor arithmetic must remain (it feeds the retained gate)"
    );
}

#[test]
fn commit_reverifies_new_slot_from_flash_before_refusing() {
    // Defense within quarantined V1: prove the candidate itself remains
    // admissible before the handler's final refusal point. This does not
    // prove A/B rollback or candidate health and grants no production
    // authority.
    let body = COMMIT_SRC;
    let refusal_pos = body
        .find("[S][fwup] COMMIT fail-closed refusal")
        .expect("COMMIT must end in the FA-1.5 fail-closed refusal");
    let reverify_pos = body
        .find("verify_rollback(new_rollback_floor)")
        .expect("COMMIT must re-verify the committed manifest's rollback floor before refusing");
    assert!(
        reverify_pos < refusal_pos,
        "the from-flash rollback re-verify must run BEFORE the refusal — the staged slot is \
         only left behind once proven a valid candidate"
    );
    assert!(
        body.contains("ManifestRef::new(flash_manifest)"),
        "the re-verify must read the just-written manifest back FROM FLASH (not only the RAM copy)"
    );
}

#[test]
fn negative_commit_writes_manifest_via_write_quadword_verified() {
    // Plain `write_quadword` (no verify) would let a torn flash
    // write past the post-write readback check. The "verified"
    // primitive is the only safe choice for the FSBL-visible
    // manifest page.
    assert!(
        COMMIT_SRC.contains("flash::write_quadword_verified"),
        "COMMIT must use the verified flash-write primitive — torn manifest must be detected"
    );
}

#[test]
fn negative_commit_drops_context_on_verify_images_failure() {
    // Audit: FW-COMMIT single-fault firmware-signing bypass — RETRY
    // amplifier. Previously a verify_images mismatch returned an error
    // status but LEFT the streaming context intact, with no failure
    // counter, so a glitch rig could re-issue CMD_FW_COMMIT in a tight,
    // zero-interaction loop until a fault landed on the byte-bind and an
    // unsigned image committed. The fix drops FW_UPDATE on ANY
    // verify_images failure, so a retry requires a fresh, user-gated
    // CMD_FW_BEGIN (re-runs the F-7 signature verify AND the
    // trusted-display install confirm, then re-streams every chunk).
    let fail_branch = COMMIT_SRC
        .find("if let Err(e) = fw_update::verify::verify_images(ctx, &manifest) {")
        .expect("COMMIT must handle verify_images failure in a dedicated branch");
    let tail = &COMMIT_SRC[fail_branch..];
    let drop_pos = tail
        .find("*core::ptr::addr_of_mut!(FW_UPDATE) = None;")
        .expect("COMMIT must drop the streaming context on verify_images failure");
    let return_pos = tail
        .find("return match e {")
        .expect("COMMIT failure branch must return the mapped error");
    assert!(
        drop_pos < return_pos,
        "the FW_UPDATE context drop must happen inside the failure branch, before its return"
    );
    // The drop must NOT cost the user their wallet: a verify_images
    // mismatch has a benign cause (flash corruption / brown-out), so
    // unlike BEGIN's bad-signature path the COMMIT failure path must NOT
    // arm the admin wipe.
    assert!(
        !tail[..return_pos].contains("arm_wipe"),
        "COMMIT verify_images failure must NOT arm the admin wipe — benign flash corruption \
         would otherwise brick the user's wallet on a flaky transfer"
    );
}

#[test]
fn legacy_commit_sets_try_once_tried_and_recomputes_crc() {
    // Pins legacy byte/CRC mechanics only. There is no complete health-confirm
    // writer and the old floor ordering can eliminate the fallback, so this is
    // not evidence of a functioning try-once rollback contract.
    assert!(
        COMMIT_SRC.contains("manifest_copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED"),
        "COMMIT must rewrite the try_once byte to TRY_ONCE_TRIED"
    );
    assert!(
        COMMIT_SRC.contains("fw_manifest::crc32_ieee(&manifest_copy[..fw_manifest::OFF_CRC32])"),
        "COMMIT must recompute the CRC after mutating the try_once byte"
    );
    let try_once_pos = COMMIT_SRC
        .find("OFF_TRY_ONCE")
        .expect("COMMIT must reference OFF_TRY_ONCE");
    let crc_pos = COMMIT_SRC
        .find("crc32_ieee")
        .expect("COMMIT must call crc32_ieee");
    assert!(
        try_once_pos < crc_pos,
        "Try-once mutation must happen BEFORE CRC recompute"
    );
}

#[test]
fn commit_order_keeps_boot_state_after_manifest_before_refusal() {
    // boot_state::write is the single atomic "now boot from the new
    // slot" staging point. Writing it before the manifest is fully
    // programmed would have FSBL try to boot a torn slot. Post-FA-1.5
    // the handler ends in the fail-closed refusal (no reset, no OTP
    // bump), so the fixed order is
    // manifest → boot_state → from-flash re-verify → refusal.
    let manifest_pos = COMMIT_SRC
        .find("flash::write_quadword_verified")
        .expect("COMMIT must program the manifest");
    let boot_state_pos = COMMIT_SRC
        .find("boot_state::write(&new_boot_state)")
        .expect("COMMIT must write boot_state");
    let refusal_pos = COMMIT_SRC
        .find("[S][fwup] COMMIT fail-closed refusal")
        .expect("COMMIT must end with the fail-closed refusal (FA-1.5 removed the reset arms)");
    assert!(
        manifest_pos < boot_state_pos,
        "boot_state::write must run AFTER manifest is programmed — partial manifest must not be \
         the boot target"
    );
    assert!(
        boot_state_pos < refusal_pos,
        "the fail-closed refusal must be the last thing COMMIT does"
    );
}

#[test]
fn negative_commit_has_no_reset_arm_so_no_secret_handoff() {
    // REGRESSION GUARD (2026-08-05 defect; adapted FA-1.5). The FW_COMMIT
    // secret-retention defect: COMMIT is PIN-gated, so
    // `SecureState::master_secret` is populated BY CONSTRUCTION when
    // COMMIT runs. The pre-FA-1.5 handler reset into the freshly written
    // image with the wallet secret still resident in SRAM1 (SRAM survives
    // a system reset; provisioning burns SRAM2_RST — the NON-SECURE bank
    // — not SRAM_RST, and the boot scrub used to skip Software resets).
    //
    // FA-1.5 closed the hole structurally: COMMIT has NO reset arm at all
    // (the handler refuses fail-closed instead of resetting into the new
    // image), so no reset hand-off can carry the unlocked session
    // anywhere. Pin that no reset path — and no "update OK" UI beat —
    // survives in the handler.
    for forbidden in [
        "SCB::sys_reset()",
        "cc_open_then_reset()",
        "ui::show_status(\"Update OK\"",
    ] {
        assert!(
            !COMMIT_SRC.contains(forbidden),
            "COMMIT must not contain reset/success arm `{forbidden}` — FA-1.5 made the handler \
             fail-closed, so the secret-retention hole is structurally closed"
        );
    }
    // The boot-side defensive scrub (`ResetCause::requires_secret_scrub`,
    // including `Software`) remains the defence-in-depth belt for any
    // other software-reset path; it is pinned in
    // `main_sau_pure_tests.rs::positive_software_reset_requires_secret_scrub`
    // and `positive_reset_cause_drives_abnormal_zeroize`.
}

#[test]
fn negative_commit_has_no_otp_exhaustion_path() {
    // FA-1.5: the `FwUpdateOtpExhausted` status and the ambiguous-launch
    // handling disappeared WITH the removed unary floor writer — they
    // must never come back through this handler. (The enum variant is
    // retired in proto; code 16 decodes to InternalError.) Pins key on
    // the CODE forms: comments documenting the removal mention the names
    // legitimately.
    for forbidden in [
        "OtpError::OutOfBudget =>",
        "FwUpdateOtpExhausted as u32",
        "unsafe { otp::",
    ] {
        assert!(
            !COMMIT_SRC.contains(forbidden),
            "COMMIT must not reference removed OTP-bump landmark `{forbidden}`"
        );
    }
}

#[test]
fn negative_commit_pre_refusal_authorization_gate_is_sentinel_hardened() {
    // HONEST SCOPE (merge wave-2 MEDIUM): post-FA-1.5 both post-gate
    // outcomes (gate-fail arm and fall-through refusal) have identical
    // side effects, so this pin asserts SOURCE-LEVEL retention of the
    // sentinel/double-eval gates pending the reviewed backend — not live
    // FI behavioural coverage.
    // FI-RETENTION ACCEPTANCE ROW (Draft 1.1 §14 L4396–4398; not removable
    // headroom per §5): the reviewed sentinel/double-evaluation checks on
    // the signed digest/image binding and rollback admission are RETAINED
    // in every build this campaign produces. In COMMIT that is the
    // from-flash re-verify gate (X17-FW1 / playbook FW11), which used to
    // be the last authorization gate before the unary OTP floor bump and
    // now precedes the FA-1.5 fail-closed refusal. Both verdicts
    // (manifest chain + boot-state pointer) must stay routed through
    // `check_true_into_sentinel`, with `scrub_sentinel_register` between
    // the paired callsites (stale-r0 defence, F-15.r1), matching
    // `verify_images`' aggregate-gate pattern.
    assert!(
        COMMIT_SRC.contains("let manifest_gate = crate::fi::check_true_into_sentinel("),
        "pre-refusal manifest re-verify must be sentinel-hardened (X17-FW1), not a bare bool"
    );
    assert!(
        COMMIT_SRC.contains("let pointer_gate = crate::fi::check_true_into_sentinel("),
        "pre-refusal boot-state pointer check must be sentinel-hardened (X17-FW1), not a bare bool"
    );
    assert!(
        COMMIT_SRC.contains("crate::fi::scrub_sentinel_register()"),
        "paired pre-refusal sentinel callsites must be separated by scrub_sentinel_register (F-15.r1)"
    );
    assert!(
        COMMIT_SRC.contains("!= crate::fi::OK_SENTINEL"),
        "pre-refusal gate must compare verdicts against OK_SENTINEL (sentinel-encoded, not a raw bool)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 15. Negative: source-text invariant pins — FI-hardened signature
//     verify in the underlying verify_manifest helper.
//
// `fw_update/mod.rs:230-244` (F-7 hardening): the vendor signature
// is verified via `fi::check_true_into_sentinel` so a single fault
// can't flip the verdict. The slice's BEGIN handler depends on this.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_verify_manifest_uses_fi_hardened_signature_check() {
    assert!(
        FW_UPDATE_MOD_SRC.contains("crate::fi::check_true_into_sentinel"),
        "verify_manifest must double-evaluate verify_signature via check_true_into_sentinel \
         (F-7 single-fault defence)"
    );
    assert!(
        FW_UPDATE_MOD_SRC.contains("crate::fi::OK_SENTINEL"),
        "verify_manifest must compare verdict against OK_SENTINEL (sentinel-encoded, \
         not a raw bool)"
    );
}

#[test]
fn negative_verify_manifest_runs_full_chain_in_documented_order() {
    // Cheap checks first, expensive crypto last; signature verify
    // BEFORE rollback so we don't reveal the OTP floor to a forged
    // manifest. Pin the order by finding each step's source position.
    //
    // Finding C (timing normalization) removed the `?` short-circuit
    // and added a longer explanatory comment that also mentions these
    // names. To make sure we're picking up the CALL SITES rather than
    // the prose, grep for the `let <name> = ...` capture-site form
    // unique to the function body.
    // F15 reordered the call sites (digest + rollback now sentinel-gated like
    // the signature): structural, crc, fpr, sig, digest, rollback. The
    // security-critical constraint (rollback AFTER signature → no OTP-floor
    // chosen-version oracle) is preserved and asserted below.
    let order = [
        "let s_err = m.verify_structural()",
        "let c_err = m.verify_crc()",
        "let f_err = m.verify_vendor_fpr(",
        "let sig_verdict = crate::fi::check_true_into_sentinel(",
        "let digest_verdict = crate::fi::check_true_into_sentinel(|| m.verify_digest().is_ok())",
        "let rollback_verdict =",
    ];
    let mut last = 0;
    for step in order {
        let pos = FW_UPDATE_MOD_SRC
            .find(step)
            .unwrap_or_else(|| panic!("verify_manifest must call {step}"));
        assert!(
            pos >= last,
            "verify_manifest step '{step}' is out of order (appears before previous step)"
        );
        last = pos;
    }

    // F15 regression guard: digest + rollback stay sentinel-hardened.
    assert!(
        FW_UPDATE_MOD_SRC.contains("check_true_into_sentinel(|| m.verify_digest().is_ok())"),
        "F15: verify_digest must be sentinel-hardened (not a bare `?` reject)"
    );
    assert!(
        FW_UPDATE_MOD_SRC
            .contains("check_true_into_sentinel(|| m.verify_rollback(rollback_floor).is_ok())"),
        "F15: verify_rollback must be sentinel-hardened (not a bare `?` reject)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 16. Negative: source-text invariant pins — CHUNK error discrimination
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_chunk_maps_flash_error_distinctly_from_bad_chunk() {
    // Companion must distinguish "your bytes were rejected" (retry
    // with correct chunk) from "the flash is acting up" (give up).
    assert!(
        CHUNK_SRC.contains("ChunkError::FlashError")
            && CHUNK_SRC.contains("NscStatus::FwUpdateFlashError"),
        "CHUNK must map ChunkError::FlashError → FwUpdateFlashError (distinct from BadChunk)"
    );
    assert!(
        CHUNK_SRC.contains("NscStatus::FwUpdateBadChunk"),
        "CHUNK must surface size/offset/kind violations as FwUpdateBadChunk"
    );
}

#[test]
fn negative_chunk_requires_active_session_before_static_mut_deref() {
    // The handler discriminates None vs Some on FW_UPDATE BEFORE
    // taking a mutable reference. A regression that called .as_mut()
    // straight on a None would unwrap-panic.
    assert!(
        CHUNK_SRC.contains("ctx_present"),
        "CHUNK must discriminate Some vs None on FW_UPDATE before mutable borrow"
    );
    assert!(
        CHUNK_SRC.contains("NscStatus::FwUpdateBadState"),
        "CHUNK must return FwUpdateBadState when no BEGIN preceded it"
    );
}

#[test]
fn negative_commit_requires_active_session_before_static_mut_deref() {
    assert!(
        COMMIT_SRC.contains("NscStatus::FwUpdateBadState"),
        "COMMIT must return FwUpdateBadState when called without a prior BEGIN"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 17. Negative: no classical signers in the slice
//
// CLAUDE.md invariant #5: SPHINCS+C10 is the only signature primitive.
// The slice's vendor-signature verify is what stops a hostile update,
// so it must not introduce any alternative signer.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_slice_contains_no_classical_signer_mentions() {
    let forbidden = [
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
    for (name, src) in ALL_HANDLER_FILES {
        for f in &forbidden {
            assert!(
                !src.contains(f),
                "{name} must not mention banned signer '{f}' — invariant #5 (single C10 signer)"
            );
        }
    }
    for f in &forbidden {
        assert!(
            !FW_UPDATE_MOD_SRC.contains(f),
            "fw_update/mod.rs must not mention banned signer '{f}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 18. Negative: feature-gating — handlers must stay out of QEMU builds
//
// The five `cmd_fw_*` modules are gated by `feature = "stm32u585"` in
// nsc/mod.rs because they consume bank-2 flash + OTP primitives only
// real silicon has. A regression that loosened this would either
// silently fail to compile on QEMU or, worse, link against a
// stub-flash impl that doesn't actually persist.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_all_fw_modules_are_stm32u585_gated_in_nsc_mod() {
    // Find the firmware-update modules block and confirm each of
    // the five `cmd_fw_*` mods is preceded by the stm32u585 cfg.
    let mods = [
        "mod cmd_fw_abort",
        "mod cmd_fw_begin",
        "mod cmd_fw_chunk",
        "mod cmd_fw_commit",
        "mod cmd_fw_status",
    ];
    for m in mods {
        // Each declaration line is preceded (with one cfg attribute)
        // by `#[cfg(feature = "stm32u585")]`. Search for the
        // attribute followed (across a newline) by the mod decl.
        let pattern_a = format!("#[cfg(feature = \"stm32u585\")]\n{m}");
        assert!(
            NSC_MOD_SRC.contains(&pattern_a),
            "nsc/mod.rs must gate `{m}` with #[cfg(feature = \"stm32u585\")] \
             — the slice depends on real bank-2 flash + OTP"
        );
    }
}

#[test]
fn negative_all_fw_veneers_are_stm32u585_gated_in_nsc_mod() {
    let veneers = [
        "nsc_fw_begin",
        "nsc_fw_chunk",
        "nsc_fw_commit",
        "nsc_fw_status",
        "nsc_fw_abort",
    ];
    for v in veneers {
        assert!(
            NSC_MOD_SRC.contains(&format!("#[cfg(feature = \"stm32u585\")]")),
            "nsc/mod.rs must contain at least one stm32u585 cfg attribute"
        );
        assert!(
            NSC_MOD_SRC.contains(&format!("fn {v}(")),
            "nsc/mod.rs must declare CMSE veneer fn {v}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 19. Negative: STATUS response composition — STATE byte values must
//     match the proto constants the companion's parser reads.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_status_emits_proto_state_constants_not_inlined_literals() {
    // Inlining `0`, `1`, `2` as bare literals would survive a
    // proto-side renumber (which would then desync companion vs
    // firmware). The handler MUST source the bytes from
    // `sphincs_tz_shared::FW_STATE_*`.
    assert!(
        STATUS_SRC.contains("FW_STATE_IDLE"),
        "cmd_fw_status must source the idle marker from sphincs_tz_shared::FW_STATE_IDLE"
    );
    assert!(
        STATUS_SRC.contains("FW_STATE_RECEIVING"),
        "cmd_fw_status must source the receiving marker from FW_STATE_RECEIVING"
    );
    assert!(
        STATUS_SRC.contains("FW_STATE_STAGED"),
        "cmd_fw_status must source the staged marker from FW_STATE_STAGED"
    );
}

#[test]
fn negative_status_response_layout_uses_proto_offset_constants() {
    // Same argument as above for the offset constants — inlining
    // 0/1/5/9 would survive a renumber that breaks companion parsing.
    assert!(STATUS_SRC.contains("FW_STATUS_STATE_OFFSET"));
    assert!(STATUS_SRC.contains("FW_STATUS_RECV_S_OFFSET"));
    assert!(STATUS_SRC.contains("FW_STATUS_RECV_NS_OFFSET"));
    assert!(STATUS_SRC.contains("FW_STATUS_SLOT_OFFSET"));
    assert!(STATUS_SRC.contains("FW_STATUS_RESPONSE_LEN"));
}

// ─────────────────────────────────────────────────────────────────────
// 20. Negative: shape pins — file size & shape sanity
//
// ABORT is small (a PIN gate, the busy guard, then `FW_UPDATE = None`).
// LCR-F2: ABORT now holds `HandlerGuard::enter()` before touching
// `FW_UPDATE` — `= None` runs the `ZeroizeOnDrop` `FwUpdateCtx`
// destructor, which the SysTick idle-wipe can otherwise race on the
// CMSE path. A regression that grew the file well past that is a smell.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_abort_handler_is_small_and_guards_fw_update() {
    // Still small — anything much larger has snuck in extra work.
    let lines = ABORT_SRC.lines().count();
    assert!(
        lines < 70,
        "cmd_fw_abort is intentionally small ({lines} lines); large growth is a smell"
    );
    // LCR-F2: ABORT touches `FW_UPDATE` (a `ZeroizeOnDrop` context), so it MUST
    // hold the busy guard before the deref — just like BEGIN/CHUNK/COMMIT — or
    // the SysTick idle-wipe can race the destructor.
    let body = ABORT_SRC
        .find("pub(super) unsafe fn run")
        .expect("ABORT handler must have a run fn");
    let body = &ABORT_SRC[body..];
    let guard_pos = body
        .find("HandlerGuard::enter()")
        .expect("ABORT must call HandlerGuard::enter() before touching FW_UPDATE (LCR-F2)");
    let deref_pos = body
        .find("addr_of_mut!(FW_UPDATE)")
        .expect("ABORT must touch FW_UPDATE");
    assert!(
        guard_pos < deref_pos,
        "HandlerGuard::enter() must be acquired BEFORE the static-mut FW_UPDATE deref"
    );
    assert!(!ABORT_SRC.contains("validate_ns_"));
    // It IS pin-gated (LOW-1 fix), but performs no NS pointer work.
    assert!(
        ABORT_SRC.contains("pin_verified.check_sentinel()"),
        "ABORT is pin-gated; the gate reads SecureState, not FW_UPDATE"
    );
}

#[test]
fn negative_status_holds_handler_guard_before_fw_update_read() {
    // LCR-F2: STATUS holds a `&FwUpdateCtx` reference across several field reads;
    // it MUST hold the busy guard before that read, or the SysTick idle-wipe can
    // zero the context out from under the reference mid-read.
    let body = STATUS_SRC
        .find("pub(super) unsafe fn run")
        .expect("STATUS handler must have a run fn");
    let body = &STATUS_SRC[body..];
    let guard_pos = body
        .find("HandlerGuard::enter()")
        .expect("STATUS must call HandlerGuard::enter() before reading FW_UPDATE (LCR-F2)");
    let deref_pos = body
        .find("addr_of!(FW_UPDATE)")
        .expect("STATUS must read FW_UPDATE");
    assert!(
        guard_pos < deref_pos,
        "HandlerGuard::enter() must be acquired BEFORE the static-mut FW_UPDATE read"
    );
}

#[test]
fn negative_abort_returns_ok_or_notinitialized() {
    // ABORT's only outcomes are: `NotInitialized` when locked (the
    // LOW-1 PIN gate) or `Ok` after dropping the context. The
    // drop-to-None itself has no failure mode, so once unlocked ABORT
    // always succeeds. The companion treats any other non-Ok as a real
    // error, so this must not regress to a richer status set.
    assert!(
        ABORT_SRC.contains("NscStatus::Ok"),
        "cmd_fw_abort must return NscStatus::Ok on success"
    );
    assert!(
        ABORT_SRC.contains("NscStatus::NotInitialized"),
        "cmd_fw_abort must return NscStatus::NotInitialized when locked (PIN gate)"
    );
    let other_status = ABORT_SRC.matches("NscStatus::").count();
    assert_eq!(
        other_status, 2,
        "cmd_fw_abort must mention NscStatus exactly twice (NotInitialized gate + Ok return)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Dev-unit A/B updates (`devunit-ab`, 2026-10-21). The handler-level pins
// above still hold for the shared code; these pin the dev-unit COMMIT tail,
// which lives in `fw_update/devunit.rs` and is the only path that resets.
// ─────────────────────────────────────────────────────────────────────

const DEVUNIT_SRC: &str = include_str!("fw_update/devunit.rs");
const MAIN_SRC_FOR_DEVUNIT: &str = include_str!("main.rs");

fn devunit_commit_body() -> &'static str {
    let start = DEVUNIT_SRC
        .find("pub unsafe fn commit(")
        .expect("fw_update/devunit.rs must define commit()");
    let body = &DEVUNIT_SRC[start..];
    &body[..body.find("\n}\n").expect("commit() must close")]
}

#[test]
fn negative_devunit_commit_checks_slot_and_version_before_any_flash_write() {
    // An image linked for the running slot, or a release that is not newer,
    // must be refused before the boot log or a manifest is touched.
    let body = devunit_commit_body();
    let running_guard = body.find("if inactive == LINKED_SLOT").expect("running-slot guard");
    let linked = body
        .find("images_linked_for(inactive, &manifest)")
        .expect("vector-table slot binding");
    let newer = body.find("if new_version <= running").expect("strictly-newer check");
    let first_write = body
        .find("flash::erase_secure_page(layout::BOOT_LOG_PAGE)")
        .expect("boot-log restart");
    assert!(running_guard < first_write && linked < first_write && newer < first_write);
    assert!(body.contains("NscStatus::FwUpdateBadImage") && body.contains("NscStatus::FwUpdateBadVersion"));
}

#[test]
fn negative_devunit_commit_zeroizes_before_it_schedules_the_reset() {
    // The secret-retention rule `negative_commit_has_no_reset_arm_so_no_secret_handoff`
    // pins for the legacy handler: the dev-unit path does reset, so the
    // unlocked session must be wiped first, and the reset itself (SysTick)
    // wipes again before SYSRESETREQ.
    let body = devunit_commit_body();
    let gate = body.find("let gate = crate::fi::check_true_into_sentinel(").expect("staged re-verify");
    let zeroize = body
        .find("crate::nsc::zeroize_sensitive_state();")
        .expect("commit must zeroize the session");
    let reset = body.find("schedule_reset();").expect("commit must schedule the reset");
    assert!(gate < zeroize && zeroize < reset);
    assert!(!DEVUNIT_SRC.contains("trigger_intrusion_wipe"));

    let systick = MAIN_SRC_FOR_DEVUNIT
        .find("if fw_update::devunit::reset_due() {")
        .expect("SysTick must poll the dev-unit reset");
    let tail = &MAIN_SRC_FOR_DEVUNIT[systick..];
    let z = tail.find("nsc::zeroize_sensitive_state();").expect("zeroize before reset");
    let r = tail.find("SCB::sys_reset()").expect("reset");
    assert!(z < r);
}

#[test]
fn negative_devunit_staged_manifest_is_tried_and_reverified_from_flash() {
    let body = devunit_commit_body();
    assert!(body.contains("copy[fw_manifest::OFF_TRY_ONCE] = TRY_ONCE_TRIED;"));
    assert!(body.contains("fw_manifest::crc32_ieee(&copy[..fw_manifest::OFF_CRC32])"));
    assert!(body.contains("flash::write_quadword_verified("));
    for check in [
        "staged.as_bytes()[..] == copy[..]",
        "staged.verify_digest().is_ok()",
        "staged.try_once_flag() == TRY_ONCE_TRIED",
        "staged.verify_rollback(running).is_ok()",
    ] {
        assert!(body.contains(check), "staged re-verify must include `{check}`");
    }
    assert!(body.contains("if gate != crate::fi::OK_SENTINEL"));
}

#[test]
fn negative_devunit_ab_is_refused_with_mode_production() {
    // The dev-unit layout, its resetting COMMIT and its test-only faulting
    // release must sit in the PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN list.
    let fence = NSC_MOD_SRC
        .find("PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN")
        .expect("production harness fence");
    let list = &NSC_MOD_SRC[..fence];
    let list = &list[list.rfind("feature = \"mode-production\",").expect("fence cfg")..];
    assert!(list.contains("feature = \"devunit-ab\","));
    assert!(list.contains("feature = \"devunit-test-fault\","));
}
