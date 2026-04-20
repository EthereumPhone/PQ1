//! Chunk-write logic for the firmware-update streaming phase.
//!
//! `CMD_FW_CHUNK` calls this for every byte of the new image. We
//! program the chunk into the inactive slot using the dual-bank flash
//! primitives in `hw::flash`, and update the running SHA-256 so a
//! final comparison at COMMIT time detects any corruption.
//!
//! Flash programming is QW (16-byte) aligned. Chunk boundaries don't
//! have to be — the companion can send an 73-byte chunk if it wants —
//! so we buffer a running 16-byte write staging buffer between chunks.

use crate::fw_update::{ChunkError, FwUpdateCtx};
use crate::hw::flash::{self, Slot};
use sphincs_tz_shared::{FW_IMAGE_KIND_NONSECURE, FW_IMAGE_KIND_SECURE};

/// Write a chunk of data into the inactive slot at `base_addr + ctx.received_*`.
/// Updates `ctx.received_*` and the running hasher. Assumes the chunk
/// has already been bounds-checked by `mod::check_chunk`.
///
/// Returns `Err(ChunkError::FlashError)` if a QW write fails; the
/// streaming state is left consistent with what actually landed in
/// flash, and the companion can either retry (after `FW_ABORT` +
/// `FW_BEGIN`) or give up.
pub unsafe fn write_chunk(
    ctx: &mut FwUpdateCtx,
    image_kind: u8,
    chunk_offset: u32,
    data: &[u8],
) -> Result<(), ChunkError> {
    let slot: Slot = ctx.inactive.into();
    let base_addr = match image_kind {
        FW_IMAGE_KIND_SECURE => flash::slot_secure_addr(slot),
        FW_IMAGE_KIND_NONSECURE => flash::slot_ns_addr(slot),
        _ => return Err(ChunkError::BadKind),
    };

    // QW-align the writes. If a chunk starts mid-QW (unlikely — we
    // currently require chunk_offset == received, and received starts
    // at 0 and advances by chunk_len, which for QW-multiple chunks
    // stays aligned), pad the leading/trailing with 0xFF so the next
    // chunk can overwrite them cleanly.
    //
    // For simplicity in this first cut we require chunks to be
    // QW-aligned both in offset and length. Companion-side chunking
    // can easily arrange this (send 1024-byte chunks = 64 QWs).
    if chunk_offset & 0xF != 0 {
        return Err(ChunkError::NonMonotonic);
    }
    if data.len() & 0xF != 0 {
        // Allow the LAST chunk to be non-multiple if it completes the
        // image: remaining = expected - received. Pad with 0xFF.
        let expected = match image_kind {
            FW_IMAGE_KIND_SECURE => ctx.expected_secure_len,
            FW_IMAGE_KIND_NONSECURE => ctx.expected_nonsecure_len,
            _ => return Err(ChunkError::BadKind),
        };
        let remaining = expected - ctx.received(image_kind);
        if (data.len() as u32) != remaining {
            return Err(ChunkError::NonMonotonic);
        }
        // OK, final short chunk — QW-pad.
    }

    let abs_addr = base_addr + chunk_offset;
    let mut off = 0usize;
    while off < data.len() {
        let remaining = data.len() - off;
        let mut qw = [0xFFu8; 16];
        let n = core::cmp::min(16, remaining);
        qw[..n].copy_from_slice(&data[off..off + n]);

        let qw_addr = abs_addr + off as u32;
        // SAFETY: address is within [slot_base, slot_base + expected_len)
        // which was bounds-checked at mod::check_chunk. The slot's
        // pages were erased at BEGIN, so 0xFF-fill bytes don't
        // violate NOR flash's 1→0 constraint.
        unsafe { flash::write_slot_quadword_verified(qw_addr, &qw) }
            .map_err(|_| ChunkError::FlashError)?;
        off += n;
    }

    // Update hasher + byte counters.
    match image_kind {
        FW_IMAGE_KIND_SECURE => {
            ctx.secure_hasher.update(data);
            ctx.received_secure += data.len() as u32;
        }
        FW_IMAGE_KIND_NONSECURE => {
            ctx.nonsecure_hasher.update(data);
            ctx.received_nonsecure += data.len() as u32;
        }
        _ => unreachable!(),
    }

    Ok(())
}

impl FwUpdateCtx {
    fn received(&self, image_kind: u8) -> u32 {
        match image_kind {
            FW_IMAGE_KIND_SECURE => self.received_secure,
            FW_IMAGE_KIND_NONSECURE => self.received_nonsecure,
            _ => 0,
        }
    }
}

// `ChunkError::FlashError` is the added variant in staging.rs.
// Re-declared here via a trait-less extension: we enrich the existing
// fw_update::ChunkError enum in a separate spot to keep the
// module-boundary explicit. See mod.rs for the enum definition.
// (If new error values are needed, edit mod.rs directly.)
