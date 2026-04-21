//! Optional length-prefixed trailer parsing for CMD_SIGN_USEROP.
//!
//! The unified sign payload ends in a sequence of independently optional
//! trailers (ERC-20 bundle, ZK v1 bundle, v3 CoW EIP-712 bundle, …). Each
//! one is introduced by a 2-byte big-endian length field followed by that
//! many bytes of content. Absence collapses to a zero-length header or
//! an outright missing header at `cursor == total_len`.
//!
//! Every parse site used to open-code the same five steps: check room for
//! the 2-byte length, read it, bounds-check the content against a
//! per-trailer max, bounds-check against `total_len`, advance the cursor.
//! Those sites drifted — different error labels, slightly different
//! bounds shapes — so the audit surface is larger than it needs to be.
//! This helper is the single implementation every site calls.

use sphincs_tz_shared::NscStatus;

use crate::ui;

/// Result of parsing one optional `[u16 BE len][payload]` trailer.
///
/// `len == 0` either because the trailer was absent (we hit `total_len`
/// before the 2-byte header) or because the header advertised a
/// zero-length payload. Callers treat both as "skip this section".
pub struct Trailer {
    /// Byte offset of the payload within the snapshot buffer. `0` when
    /// `len == 0` is also fine — callers never index with it unless
    /// `len > 0`.
    pub start: usize,
    /// Number of payload bytes. Zero when the trailer is absent.
    pub len: usize,
    /// Cursor position AFTER the trailer (or unchanged when absent, so
    /// the next parse step sees the same `cursor` it would have without
    /// the helper).
    pub next_cursor: usize,
}

/// Read an optional 2-byte-BE length-prefixed trailer from
/// `snap[cursor..total_len]`.
///
/// Contract:
///   * Returns `Trailer { len: 0, start: cursor, next_cursor: cursor }`
///     when fewer than 2 bytes remain — the caller just keeps going.
///   * Returns `Err(NscStatus::InvalidPointer as u32)` when the length
///     header is present but the advertised payload would exceed
///     either `max_len` or the remaining bytes in the snapshot. On
///     error the `error_label` is shown on the trusted UI so a user
///     debugging a companion-side payload misformat gets a specific
///     reason instead of a generic failure.
///   * Otherwise the payload is valid: `start` points into `snap` at
///     the first payload byte, `len` is the declared length, and
///     `next_cursor` is already advanced past the payload.
///
/// Security note: the helper never dereferences `snap` with a bounds
/// wider than `total_len`. Callers must still verify that `total_len`
/// itself came from a TOCTOU snapshot of the NS-supplied length — the
/// helper trusts the caller on that.
pub fn read_optional_u16_prefixed(
    snap: &[u8],
    cursor: usize,
    total_len: usize,
    max_len: usize,
    error_label: &str,
) -> Result<Trailer, u32> {
    if cursor + 2 > total_len {
        return Ok(Trailer {
            start: cursor,
            len: 0,
            next_cursor: cursor,
        });
    }
    let len = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
    let payload_start = cursor + 2;
    if len > max_len || payload_start + len > total_len {
        ui::show_status("Sign", error_label);
        return Err(NscStatus::InvalidPointer as u32);
    }
    Ok(Trailer {
        start: payload_start,
        len,
        next_cursor: payload_start + len,
    })
}
