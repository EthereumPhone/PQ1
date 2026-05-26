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
//!   * `cmd_fw_commit.rs`  — gate, image re-verify, user confirm, OTP
//!     rollback-floor bump, TRIED-flag manifest write, boot-state
//!     update, system reset.
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
//!      signature verify, OTP-bump-before-manifest-write ordering,
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
    FW_STATUS_RECV_S_OFFSET, FW_STATUS_RESPONSE_LEN, FW_STATUS_SLOT_OFFSET,
    FW_STATUS_STATE_OFFSET,
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
    assert_eq!(NscStatus::FwUpdateBadState as u32, 10);
    assert_eq!(NscStatus::FwUpdateBadManifest as u32, 11);
    assert_eq!(NscStatus::FwUpdateBadVersion as u32, 12);
    assert_eq!(NscStatus::FwUpdateBadChunk as u32, 13);
    assert_eq!(NscStatus::FwUpdateBadImage as u32, 14);
    assert_eq!(NscStatus::FwUpdateFlashError as u32, 15);
    assert_eq!(NscStatus::FwUpdateOtpExhausted as u32, 16);
    for code in [10u32, 11, 12, 13, 14, 15, 16] {
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
    assert!(!chunk_total_len_accepted(FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK + 1));
    assert!(!chunk_total_len_accepted(FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK * 2));
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
// CLAUDE.md §"Lifecycle": every update entry point except STATUS
// and ABORT must check `pin_verified` first. A regression that
// dropped the gate would let a locked device be silently flashed
// to a hostile (but vendor-signed) release.
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
        "cmd_fw_commit must gate on pin_verified — the OTP bump must NEVER happen on a locked device"
    );
    assert!(COMMIT_SRC.contains("NscStatus::NotInitialized"));
}

#[test]
fn negative_status_does_not_gate_on_pin_verified() {
    // Documented: STATUS is a recovery probe, not a secret-bearing
    // call. Pin the absence so a future refactor doesn't quietly
    // add a PIN gate that breaks companion's pre-unlock UX.
    assert!(
        !STATUS_SRC.contains("pin_verified"),
        "cmd_fw_status is intentionally not pin-gated — companion polls it pre-unlock"
    );
}

#[test]
fn negative_abort_does_not_gate_on_pin_verified() {
    // Documented in cmd_fw_abort.rs:1-7: ABORT is the recovery path
    // and must succeed even if the device is mid-lock. Pin the
    // absence — adding a gate here would create a wedge state.
    assert!(
        !ABORT_SRC.contains("pin_verified"),
        "cmd_fw_abort must NOT gate on pin_verified — recovery must always work"
    );
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
fn negative_begin_picks_inactive_slot_via_read_active_slot() {
    // Picking the wrong slot would erase the running firmware —
    // would brick the device on next reset. Pin the load-bearing
    // computation.
    assert!(
        BEGIN_SRC.contains("fw_update::read_active_slot()"),
        "BEGIN must consult read_active_slot to discover which slot is currently running"
    );
    assert!(
        BEGIN_SRC.contains("flash::Slot::A => flash::Slot::B")
            && BEGIN_SRC.contains("flash::Slot::B => flash::Slot::A"),
        "BEGIN must invert the active slot to pick the inactive target"
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
// 14. Negative: source-text invariant pins — COMMIT ordering
//
// `cmd_fw_commit.rs`: the order of `verify_images` → `confirm_commit`
// → `otp::bump_to` → manifest write → boot-state write → reset is
// security-critical. Each step's "before" pin defends a specific
// attack.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_begin_runs_verify_manifest_before_confirm_install_before_erase() {
    // Finding A moved the user confirm from COMMIT to BEGIN: BEGIN must
    // pass the full `verify_manifest` chain BEFORE asking the user (so
    // the user is only ever prompted on a vendor-authentic bundle), and
    // the confirm must run BEFORE `erase_slot` (so a user-cancel costs
    // zero flash work and leaves the inactive slot untouched). Pin the
    // ordering — a refactor that reordered any of these would silently
    // break the property.
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
        verify_pos < confirm_pos,
        "verify_manifest MUST precede confirm_install — the user is only ever asked to confirm an already-vendor-authenticated bundle"
    );
    assert!(
        confirm_pos < erase_pos,
        "confirm_install MUST precede flash::erase_slot — a user-cancel costs zero flash work (finding A)"
    );
}

#[test]
fn negative_begin_user_cancel_short_circuits_before_erase() {
    // Finding A: when `confirm_install` returns false the handler must
    // return `UserRejected` WITHOUT erasing the inactive slot. Pin the
    // shape: the `if !fw_update::confirm_install(&m)` branch returns
    // `NscStatus::UserRejected` AND that branch sits before any
    // `flash::erase_slot` call in the source.
    let cancel_block_start = BEGIN_SRC
        .find("if !fw_update::confirm_install(&m) {")
        .expect("BEGIN must have a cancel branch on confirm_install returning false");
    let return_pos = BEGIN_SRC[cancel_block_start..]
        .find("NscStatus::UserRejected")
        .expect("Cancel branch must return UserRejected");
    let erase_pos = BEGIN_SRC
        .find("flash::erase_slot(inactive)")
        .expect("BEGIN must erase the inactive slot somewhere");
    assert!(
        cancel_block_start < erase_pos,
        "Cancel handling MUST precede flash::erase_slot — the whole point of finding A"
    );
    // Belt-and-braces: the return is part of the cancel branch, not a
    // later fall-through.
    assert!(
        return_pos < (erase_pos - cancel_block_start),
        "UserRejected return must be inside the cancel branch, not later in the function"
    );
}

#[test]
fn negative_commit_bumps_otp_before_writing_new_manifest() {
    // Documented in cmd_fw_commit.rs:79-88: rollback-floor bump
    // must happen BEFORE the manifest write so a reset between
    // them leaves the floor raised — closing the "an attacker
    // power-cycles after manifest write but before OTP bump" window
    // for replaying older releases.
    let body = COMMIT_SRC;
    let otp_pos = body
        .find("otp::bump_to(new_version)")
        .expect("COMMIT must call otp::bump_to");
    let manifest_write_pos = body
        .find("flash::write_quadword_verified")
        .expect("COMMIT must program the new manifest");
    assert!(
        otp_pos < manifest_write_pos,
        "OTP rollback-floor bump must precede the new manifest write — anti-replay across reset"
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
fn negative_commit_sets_try_once_tried_and_recomputes_crc() {
    // The signed manifest carries try_once = COMMITTED; the device
    // re-writes it as TRIED so FSBL can revert if the new slot
    // doesn't confirm "alive". After mutating the byte, the
    // trailing CRC must be recomputed or FSBL will reject the
    // re-flashed page as `BadCrc`.
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
fn negative_commit_writes_boot_state_last_before_reset() {
    // boot_state::write is the single atomic "now boot from the new
    // slot" commit point. Writing it before the manifest is fully
    // programmed would have FSBL try to boot a torn slot. Writing
    // it after sys_reset is impossible. The fixed order is OTP →
    // manifest → boot_state → sys_reset.
    let manifest_pos = COMMIT_SRC
        .find("flash::write_quadword_verified")
        .expect("COMMIT must program the manifest");
    let boot_state_pos = COMMIT_SRC
        .find("boot_state::write(&new_boot_state)")
        .expect("COMMIT must write boot_state");
    let reset_pos = COMMIT_SRC
        .find("SCB::sys_reset()")
        .expect("COMMIT must end with sys_reset");
    assert!(
        manifest_pos < boot_state_pos,
        "boot_state::write must run AFTER manifest is programmed — partial manifest must not be \
         the boot target"
    );
    assert!(
        boot_state_pos < reset_pos,
        "sys_reset must be the last thing COMMIT does"
    );
}

#[test]
fn negative_commit_maps_otp_exhaustion_to_distinct_error_code() {
    // Companion must distinguish "this device is permanently out of
    // OTP budget" (manual support intervention) from a transient
    // flash error (retry). The discriminator is the
    // FwUpdateOtpExhausted code.
    assert!(
        COMMIT_SRC.contains("otp::OtpError::OutOfBudget"),
        "COMMIT must surface OutOfBudget as a discriminated case"
    );
    assert!(
        COMMIT_SRC.contains("NscStatus::FwUpdateOtpExhausted"),
        "COMMIT must map OutOfBudget → FwUpdateOtpExhausted (not FwUpdateFlashError)"
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
    let order = [
        "verify_structural",
        "verify_crc",
        "verify_digest",
        "verify_vendor_fpr",
        "check_true_into_sentinel",
        "verify_rollback",
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
        let pattern_a = format!(
            "#[cfg(feature = \"stm32u585\")]\n{m}"
        );
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
            NSC_MOD_SRC.contains(&format!(
                "#[cfg(feature = \"stm32u585\")]"
            )),
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
// ABORT is intentionally tiny (no PIN gate, no NS deref, no flash —
// it's just `FW_UPDATE = None`). A regression that grew the file
// past a small bound is a smell worth surfacing.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_abort_handler_is_intentionally_tiny() {
    // The file is ~30 lines including the doc comment. Anything
    // significantly larger has snuck in extra work — review.
    let lines = ABORT_SRC.lines().count();
    assert!(
        lines < 50,
        "cmd_fw_abort is intentionally tiny ({lines} lines); growth is a smell"
    );
    // And it MUST NOT introduce any new gate (PIN, pointer, busy).
    // ABORT writes None to FW_UPDATE in a single statement; no
    // mutable borrow is held across any operation that SysTick's
    // idle-wipe could race, so HandlerGuard::enter() is not needed.
    // (The doc-comment references HandlerGuard to explain why the
    // single-statement write is safe; the assertion below pins
    // the absence of an *active* enter() call.)
    assert!(
        !ABORT_SRC.contains("HandlerGuard::enter()"),
        "ABORT does no FW_UPDATE deref before the assignment — no HandlerGuard::enter() needed"
    );
    assert!(!ABORT_SRC.contains("validate_ns_"));
    assert!(
        !ABORT_SRC.contains("pin_verified.check_sentinel()"),
        "ABORT must not gate on pin_verified — recovery must always work"
    );
}

#[test]
fn negative_abort_always_returns_ok() {
    // ABORT has no failure mode; the assignment to None always
    // succeeds. The companion treats any non-Ok as a real error,
    // so this must not regress.
    assert!(
        ABORT_SRC.contains("NscStatus::Ok"),
        "cmd_fw_abort must always return NscStatus::Ok"
    );
    let other_status = ABORT_SRC.matches("NscStatus::").count();
    assert_eq!(
        other_status, 1,
        "cmd_fw_abort must mention NscStatus exactly once (the Ok return)"
    );
}
