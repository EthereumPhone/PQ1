//! Companion-stub function-selector → text-signature DB lookup.
//!
//! Unlike the ERC-20 / Names DBs, the **production** firmware does not
//! ship the selectors blob — it lives on the host (companion app,
//! future) and is forwarded over USB HID. This module exists for the
//! `e2e-test` build only: it `include_bytes!`s the host blob from
//! `tools/companion-stub/selectors_db.bin` so the QEMU NS test driver
//! can act as a dev-only companion stub. Production NS builds compile
//! this module out (see `nonsecure/src/main.rs`).
//!
//! Wire format and trust model are identical to the ERC-20 / Names
//! pattern: NS walks the sorted-by-selector index, builds a
//! `(selector, text_sig, leaf_index, proof)` bundle, and the secure
//! world Merkle-verifies it against `SELECTOR_DB_ROOT` plus
//! cross-checks `bundle.selector == calldata[0..4]` before display.

use sphincs_tz_shared::db_format::{
    read_u32_le, SELECTOR_DB_ENTRY_LEN, SELECTOR_DB_HEADER_LEN, SELECTOR_DB_MAGIC,
    SELECTOR_DB_VERSION, SELECTOR_ENTRY_OFF_SELECTOR, SELECTOR_ENTRY_OFF_TEXT_OFF,
    SELECTOR_HDR_OFF_ENTRY_CNT, SELECTOR_HDR_OFF_POOL_OFF, SELECTOR_HDR_OFF_PROOFS_OFF,
    SELECTOR_HDR_OFF_PROOF_DEPTH, SELECTOR_HDR_OFF_VERSION,
};

/// Pulled from `tools/companion-stub/` rather than `nonsecure/src/`
/// because, conceptually, the blob lives on the host. The
/// `include_bytes!` is gated by the `e2e-test` feature in
/// `nonsecure/src/main.rs` so production NS images never bake it in.
///
/// Under `e2e-test` the secure crate compiles in `SELECTOR_DB_ROOT_E2E`
/// (see `dbgen::render_db_roots`), and we point the include here at
/// the matching `selectors_db_e2e.bin` fixture (a few entries —
/// transfer, approve, …). The full ~775 KB production blob would
/// overflow NS flash and is the wrong fit for QEMU bring-up; the
/// real companion app holds it instead.
static SELECTOR_DB: &[u8] =
    include_bytes!("../../tools/companion-stub/selectors_db_e2e.bin");

/// Build a selector bundle for `selector`. Writes into `out` and
/// returns the number of bytes written, or `None` if the entry isn't
/// in the DB or `out` is too small.
///
/// Wire layout (must match `secure/src/selectors/bundle.rs`):
///
/// ```text
///   selector       [u8; 4]
///   text_sig_len   u8
///   text_sig       [u8; text_sig_len]
///   leaf_index     u32 LE
///   proof_depth    u32 LE
///   proof          [u8; proof_depth * 32]
/// ```
pub fn build_bundle(selector: &[u8; 4], out: &mut [u8]) -> Option<usize> {
    let view = open(SELECTOR_DB)?;
    let idx = view.find_index(selector)?;
    let entry_off = SELECTOR_DB_HEADER_LEN + idx * SELECTOR_DB_ENTRY_LEN;

    let text_off = read_u32_le(view.blob, entry_off + SELECTOR_ENTRY_OFF_TEXT_OFF) as usize;
    let text_sig = read_pool_string(view.blob, view.pool_off + text_off)?;

    let needed = 4 + 1 + text_sig.len() + 4 + 4 + view.proof_depth * 32;
    if out.len() < needed {
        return None;
    }

    let mut p = 0usize;
    out[p..p + 4].copy_from_slice(selector);
    p += 4;
    out[p] = text_sig.len() as u8;
    p += 1;
    out[p..p + text_sig.len()].copy_from_slice(text_sig);
    p += text_sig.len();
    out[p..p + 4].copy_from_slice(&(idx as u32).to_le_bytes());
    p += 4;
    out[p..p + 4].copy_from_slice(&(view.proof_depth as u32).to_le_bytes());
    p += 4;

    let proof_base = view.proofs_off + idx * view.proof_depth * 32;
    let proof_size = view.proof_depth * 32;
    out[p..p + proof_size].copy_from_slice(&view.blob[proof_base..proof_base + proof_size]);
    p += proof_size;

    Some(p)
}

struct DbView {
    blob: &'static [u8],
    entry_cnt: usize,
    pool_off: usize,
    proof_depth: usize,
    proofs_off: usize,
}

fn open(blob: &'static [u8]) -> Option<DbView> {
    if blob.len() < SELECTOR_DB_HEADER_LEN {
        return None;
    }
    if blob[..4] != SELECTOR_DB_MAGIC {
        return None;
    }
    if read_u32_le(blob, SELECTOR_HDR_OFF_VERSION) != SELECTOR_DB_VERSION {
        return None;
    }
    let entry_cnt = read_u32_le(blob, SELECTOR_HDR_OFF_ENTRY_CNT) as usize;
    let pool_off = read_u32_le(blob, SELECTOR_HDR_OFF_POOL_OFF) as usize;
    let proof_depth = read_u32_le(blob, SELECTOR_HDR_OFF_PROOF_DEPTH) as usize;
    let proofs_off = read_u32_le(blob, SELECTOR_HDR_OFF_PROOFS_OFF) as usize;
    Some(DbView {
        blob,
        entry_cnt,
        pool_off,
        proof_depth,
        proofs_off,
    })
}

impl DbView {
    fn find_index(&self, selector: &[u8; 4]) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.entry_cnt;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let off = SELECTOR_DB_HEADER_LEN + mid * SELECTOR_DB_ENTRY_LEN;
            let mid_sel: &[u8] = &self.blob
                [off + SELECTOR_ENTRY_OFF_SELECTOR..off + SELECTOR_ENTRY_OFF_SELECTOR + 4];
            let cmp = mid_sel.cmp(&selector[..]);
            match cmp {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }
}

fn read_pool_string(blob: &'static [u8], at: usize) -> Option<&'static [u8]> {
    let len = *blob.get(at)? as usize;
    blob.get(at + 1..at + 1 + len)
}
