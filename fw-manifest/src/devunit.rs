//! Dev-unit A/B firmware updates — pre-production DVTs handed to outside
//! testers (owner request 2026-10-21).
//!
//! **Not the production design.** Production firmware update is blocked on the
//! unapproved Draft 1.1 rollback work and the open flash-geometry decision
//! (#540, #752, #908). This module is the smallest working update path for
//! dev units that ship with the pixel UI, which does not fit the frozen 57-page
//! secure slot. Every consumer compiles it in only behind its `devunit-ab`
//! feature, and that feature is fenced out of `mode-production` in the FSBL,
//! the secure world and the build scripts.
//!
//! Everything here is pure (no MMIO), so the slot choice, the boot log and the
//! vector-table binding are host-tested below.
//!
//! ## Flash map
//!
//! | bank | pages     | address (alias)          | owner                         |
//! |------|-----------|--------------------------|-------------------------------|
//! | 1    | 0..=3     | `0x0C00_0000` (S)        | FSBL (legacy 32 KiB)          |
//! | 1    | 4         | `0x0C00_8000` (S)        | manifest A                    |
//! | 1    | 5         | `0x0C00_A000` (S)        | manifest B                    |
//! | 1    | 6         | `0x0C00_C000` (S)        | boot log (this module)        |
//! | 1    | 7..=86    | `0x0C00_E000` (S)        | secure slot A, 640 KiB        |
//! | 1    | 87..=122  | —                        | unused                        |
//! | 1    | 123..=127 | `0x0C0F_6000` (S)        | per-device pages (unchanged)  |
//! | 2    | 0..=23    | `0x0810_0000` (NS)       | non-secure slot A, 192 KiB    |
//! | 2    | 24..=47   | `0x0813_0000` (NS)       | non-secure slot B, 192 KiB    |
//! | 2    | 48..=127  | `0x0C16_0000` (S)        | secure slot B, 640 KiB        |
//!
//! Bank 2 pages 48..=127 are made secure with `SECWM2_PSTRT = 48`,
//! `SECWM2_PEND = 127`. Non-secure slot A sits exactly where every monolithic
//! bench image already links its non-secure world, and the per-device pages
//! (wallet counters, PIN salt, admin flags) do not move, so a dev unit keeps
//! its wallet across updates.
//!
//! Images are not position independent, so every release is built twice, once
//! linked for each slot, and both builds are signed. The device writes the
//! variant for its INACTIVE slot and refuses one linked for the other slot
//! (see [`vectors_in_slot`]).
//!
//! ## Probation
//!
//! A manifest written by `CMD_FW_COMMIT` carries `try_once = TRIED`; a manifest
//! flashed at the factory carries the signed default `COMMITTED`. The boot log
//! (page 6) is an append-only list of 16-byte records:
//!
//! * the running secure world appends `ATTEMPT(slot, version)` early in boot
//!   while its own manifest is `TRIED` and not yet confirmed;
//! * it appends `CONFIRM(slot, version)` once the wallet has unlocked;
//! * `CMD_FW_COMMIT` erases the page and starts it with `CONFIRM` for the
//!   running slot before it writes the new manifest.
//!
//! The FSBL boots the higher version unless that slot is still `TRIED`, has no
//! `CONFIRM`, and already has [`MAX_UNCONFIRMED_BOOTS`] attempts; then it falls
//! back to the other slot. A new image that hangs or faults before the PIN
//! prompt therefore rolls back after three power cycles. The FSBL never writes
//! flash: the log is written only by the secure world.

use crate::{SLOT_A, SLOT_B, TRY_ONCE_COMMITTED, TRY_ONCE_TRIED};

// ---------------------------------------------------------------------------
// Flash map
// ---------------------------------------------------------------------------

/// STM32U585 flash page size.
pub const PAGE_SIZE: u32 = 8 * 1024;

/// Secure slot capacity: 80 pages in either bank.
pub const SECURE_SLOT_PAGES: u32 = 80;
/// Non-secure slot capacity: 24 pages in bank 2.
pub const NS_SLOT_PAGES: u32 = 24;

/// Largest secure image either slot can hold (655,360 B).
pub const SECURE_SLOT_CAPACITY: u32 = SECURE_SLOT_PAGES * PAGE_SIZE;
/// Largest non-secure image either slot can hold (196,608 B).
pub const NS_SLOT_CAPACITY: u32 = NS_SLOT_PAGES * PAGE_SIZE;

/// Secure slot A: bank 1 pages 7..=86, secure alias.
pub const SLOT_A_SECURE_ADDR: u32 = 0x0C00_E000;
pub const SLOT_A_SECURE_FIRST_PAGE: u32 = 7;
/// Secure slot B: bank 2 pages 48..=127, secure alias.
pub const SLOT_B_SECURE_ADDR: u32 = 0x0C16_0000;
pub const SLOT_B_SECURE_FIRST_PAGE: u32 = 48;
/// Non-secure slot A: bank 2 pages 0..=23, non-secure alias.
pub const SLOT_A_NS_ADDR: u32 = 0x0810_0000;
pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;
/// Non-secure slot B: bank 2 pages 24..=47, non-secure alias.
pub const SLOT_B_NS_ADDR: u32 = 0x0813_0000;
pub const SLOT_B_NS_FIRST_PAGE: u32 = 24;

/// Manifest pages (bank 1), unchanged from the legacy bench layout.
pub const MANIFEST_A_ADDR: u32 = 0x0C00_8000;
pub const MANIFEST_B_ADDR: u32 = 0x0C00_A000;
/// The boot log: bank-1 page 6, the legacy boot-state page.
pub const BOOT_LOG_ADDR: u32 = 0x0C00_C000;
pub const BOOT_LOG_PAGE: u32 = 6;

/// `SECWM2` field values that make bank-2 pages 48..=127 (secure slot B)
/// secure and leave pages 0..=47 (both non-secure slots) non-secure.
pub const SECWM2_PSTRT: u32 = SLOT_B_SECURE_FIRST_PAGE;
pub const SECWM2_PEND: u32 = SLOT_B_SECURE_FIRST_PAGE + SECURE_SLOT_PAGES - 1;

/// Secure SRAM1 as the secure linker scripts declare it: the initial stack
/// pointer of a secure image must lie in `(SECURE_SRAM_BASE, SECURE_SRAM_END]`.
pub const SECURE_SRAM_BASE: u32 = 0x3000_0000;
pub const SECURE_SRAM_END: u32 = 0x3003_0000;
/// Non-secure SRAM2: same rule for the non-secure image.
pub const NS_SRAM_BASE: u32 = 0x2003_0000;
pub const NS_SRAM_END: u32 = 0x2004_0000;

const _: () = assert!(SLOT_A_SECURE_ADDR == 0x0C00_0000 + SLOT_A_SECURE_FIRST_PAGE * PAGE_SIZE);
// Slot A ends at page 86, well below the per-device pages at 123.
const _: () = assert!(SLOT_A_SECURE_FIRST_PAGE + SECURE_SLOT_PAGES - 1 == 86);
const _: () = assert!(SLOT_B_SECURE_ADDR == 0x0C10_0000 + SLOT_B_SECURE_FIRST_PAGE * PAGE_SIZE);
// Slot B ends exactly at the last page of bank 2.
const _: () = assert!(SECWM2_PEND == 127);
const _: () = assert!(SLOT_A_NS_ADDR == 0x0810_0000 + SLOT_A_NS_FIRST_PAGE * PAGE_SIZE);
const _: () = assert!(SLOT_B_NS_ADDR == 0x0810_0000 + SLOT_B_NS_FIRST_PAGE * PAGE_SIZE);
// The two non-secure slots end where the secure watermark starts.
const _: () = assert!(SLOT_B_NS_FIRST_PAGE + NS_SLOT_PAGES == SECWM2_PSTRT);
const _: () = assert!(SLOT_A_NS_FIRST_PAGE + NS_SLOT_PAGES == SLOT_B_NS_FIRST_PAGE);
const _: () = assert!(BOOT_LOG_ADDR == 0x0C00_0000 + BOOT_LOG_PAGE * PAGE_SIZE);

/// Secure image base for a slot id (`SLOT_A` / `SLOT_B`).
#[must_use]
pub const fn secure_base(slot: u8) -> u32 {
    if slot == SLOT_B {
        SLOT_B_SECURE_ADDR
    } else {
        SLOT_A_SECURE_ADDR
    }
}

/// Non-secure image base for a slot id.
#[must_use]
pub const fn ns_base(slot: u8) -> u32 {
    if slot == SLOT_B {
        SLOT_B_NS_ADDR
    } else {
        SLOT_A_NS_ADDR
    }
}

/// Manifest page address for a slot id.
#[must_use]
pub const fn manifest_addr(slot: u8) -> u32 {
    if slot == SLOT_B {
        MANIFEST_B_ADDR
    } else {
        MANIFEST_A_ADDR
    }
}

/// The other slot.
#[must_use]
pub const fn other(slot: u8) -> u8 {
    if slot == SLOT_B {
        SLOT_A
    } else {
        SLOT_B
    }
}

// ---------------------------------------------------------------------------
// Vector-table binding
// ---------------------------------------------------------------------------

/// Is an image's vector table consistent with running from `[base, base+len)`?
///
/// The signed manifest binds the image bytes, and those bytes include the
/// absolute addresses the image was linked at, so this check is what binds a
/// signed image to a slot: an image linked for slot A that was written into
/// slot B carries slot-A addresses and fails here. `initial_sp` must point
/// into the expected SRAM (a stack top may equal the region end) and the reset
/// handler, with its Thumb bit, must lie inside the image.
#[must_use]
pub const fn vectors_in_slot(
    initial_sp: u32,
    reset: u32,
    base: u32,
    len: u32,
    sram_base: u32,
    sram_end: u32,
) -> bool {
    if initial_sp <= sram_base || initial_sp > sram_end || initial_sp % 8 != 0 {
        return false;
    }
    if reset & 1 == 0 {
        return false;
    }
    let target = reset & !1;
    let end = match base.checked_add(len) {
        Some(end) => end,
        None => return false,
    };
    // The vector table itself occupies the first bytes of the image, so a
    // reset handler AT the base is not code.
    target > base && target < end
}

// ---------------------------------------------------------------------------
// Boot log
// ---------------------------------------------------------------------------

/// Bytes per boot-log record: one flash quad-word, one atomic program.
pub const RECORD_LEN: usize = 16;
/// Records per log page.
pub const LOG_CAPACITY: usize = (PAGE_SIZE as usize) / RECORD_LEN;

const RECORD_MAGIC: [u8; 4] = *b"PQBL";

/// The secure world of `(slot, version)` started booting while unconfirmed.
pub const KIND_ATTEMPT: u8 = 0x01;
/// `(slot, version)` reached an unlocked wallet; it is settled.
pub const KIND_CONFIRM: u8 = 0x02;

/// Boots the FSBL grants an unconfirmed (`TRIED`) image before it falls back.
pub const MAX_UNCONFIRMED_BOOTS: u32 = 3;

/// One decoded record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: u8,
    pub slot: u8,
    pub fw_version: u32,
}

/// Encode a record: `"PQBL" | kind | slot | 0 0 | version BE | crc32 BE`.
#[must_use]
pub fn encode_record(kind: u8, slot: u8, fw_version: u32) -> [u8; RECORD_LEN] {
    let mut r = [0u8; RECORD_LEN];
    r[..4].copy_from_slice(&RECORD_MAGIC);
    r[4] = kind;
    r[5] = slot;
    r[8..12].copy_from_slice(&fw_version.to_be_bytes());
    let crc = crate::crc32_ieee(&r[..12]);
    r[12..].copy_from_slice(&crc.to_be_bytes());
    r
}

/// Decode a record. `None` for an erased quad-word, a torn program, or any
/// record that is not exactly what [`encode_record`] writes.
#[must_use]
pub fn parse_record(r: &[u8; RECORD_LEN]) -> Option<Record> {
    if r[..4] != RECORD_MAGIC || r[6] != 0 || r[7] != 0 {
        return None;
    }
    if r[4] != KIND_ATTEMPT && r[4] != KIND_CONFIRM {
        return None;
    }
    if r[5] != SLOT_A && r[5] != SLOT_B {
        return None;
    }
    let crc = u32::from_be_bytes([r[12], r[13], r[14], r[15]]);
    if crc != crate::crc32_ieee(&r[..12]) {
        return None;
    }
    Some(Record {
        kind: r[4],
        slot: r[5],
        fw_version: u32::from_be_bytes([r[8], r[9], r[10], r[11]]),
    })
}

/// Is this quad-word still erased (programmable)?
#[must_use]
pub fn is_erased(r: &[u8; RECORD_LEN]) -> bool {
    r.iter().all(|&b| b == 0xFF)
}

/// What the log says about one `(slot, version)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub attempts: u32,
    pub confirmed: bool,
}

impl Tally {
    /// Fold one raw quad-word into the tally for `(slot, fw_version)`.
    /// Records for other slots or versions, and anything that does not
    /// parse, are ignored.
    pub fn observe(&mut self, raw: &[u8; RECORD_LEN], slot: u8, fw_version: u32) {
        if let Some(rec) = parse_record(raw) {
            if rec.slot == slot && rec.fw_version == fw_version {
                match rec.kind {
                    KIND_ATTEMPT => self.attempts = self.attempts.saturating_add(1),
                    KIND_CONFIRM => self.confirmed = true,
                    _ => {}
                }
            }
        }
    }
}

/// Index of the next quad-word to program, given a reader over the page.
///
/// The log is append-only, so the free space is the suffix after the LAST
/// non-erased quad-word; a torn record in the middle is skipped, never reused
/// (a quad-word cannot be programmed twice). `None` when the page is full.
pub fn next_free<F: FnMut(usize) -> [u8; RECORD_LEN]>(mut read: F) -> Option<usize> {
    let mut i = LOG_CAPACITY;
    while i > 0 {
        if !is_erased(&read(i - 1)) {
            return if i < LOG_CAPACITY { Some(i) } else { None };
        }
        i -= 1;
    }
    Some(0)
}

/// Should the running secure world log a boot attempt / a confirmation for
/// itself? Only while its own manifest is `TRIED` and nothing has confirmed
/// it yet; a factory-flashed (`COMMITTED`) image never writes the log.
#[must_use]
pub fn needs_settling(own_try_once: u8, tally: Tally) -> bool {
    own_try_once == TRY_ONCE_TRIED && !tally.confirmed
}

// ---------------------------------------------------------------------------
// Slot choice (FSBL)
// ---------------------------------------------------------------------------

/// A slot that passed every FSBL check (signature, images, vector table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub fw_version: u32,
    pub try_once: u8,
    pub tally: Tally,
}

impl Candidate {
    /// Flashed at the factory, or confirmed by a successful unlock.
    #[must_use]
    pub fn settled(&self) -> bool {
        self.try_once == TRY_ONCE_COMMITTED || self.tally.confirmed
    }

    /// May the FSBL boot this slot in preference to an older one?
    #[must_use]
    pub fn bootable_as_newer(&self) -> bool {
        self.settled()
            || (self.try_once == TRY_ONCE_TRIED && self.tally.attempts < MAX_UNCONFIRMED_BOOTS)
    }
}

/// Pick the slot to boot. `None` when neither slot is a candidate.
///
/// * One candidate: boot it, whatever its state — there is nothing to fall
///   back to.
/// * Two: boot the higher version unless it is unconfirmed and out of
///   attempts (or carries a torn/unknown `try_once`), then boot the other.
/// * Equal versions (not produced by the updater, which requires a strictly
///   newer release): prefer a settled slot, then slot A.
#[must_use]
pub fn choose(a: Option<Candidate>, b: Option<Candidate>) -> Option<u8> {
    match (a, b) {
        (None, None) => None,
        (Some(_), None) => Some(SLOT_A),
        (None, Some(_)) => Some(SLOT_B),
        (Some(a), Some(b)) => {
            if a.fw_version == b.fw_version {
                return if b.settled() && !a.settled() {
                    Some(SLOT_B)
                } else {
                    Some(SLOT_A)
                };
            }
            let (newer, newer_slot) = if a.fw_version > b.fw_version {
                (a, SLOT_A)
            } else {
                (b, SLOT_B)
            };
            if newer.bootable_as_newer() {
                Some(newer_slot)
            } else {
                Some(other(newer_slot))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET_DEVICE_INFO trailer (non-secure world → host updater)
// ---------------------------------------------------------------------------

/// Appended after the 40-byte GET_DEVICE_INFO body by dev-unit images only.
/// Parsers that read the documented 40 bytes ignore it.
///
/// `"DU" | layout(1) | running slot(1) | fw_version u32 BE`.
/// Reported by the non-secure world from its own link address and build
/// stamp: a hint that lets the updater pick the right slot variant, never a
/// security input (the secure world re-checks everything at COMMIT).
pub const DEVICE_INFO_TRAILER_MAGIC: [u8; 2] = *b"DU";
pub const DEVICE_INFO_TRAILER_LAYOUT: u8 = 1;
pub const DEVICE_INFO_TRAILER_LEN: usize = 8;

/// Build the trailer.
#[must_use]
pub const fn device_info_trailer(slot: u8, fw_version: u32) -> [u8; DEVICE_INFO_TRAILER_LEN] {
    let v = fw_version.to_be_bytes();
    [
        DEVICE_INFO_TRAILER_MAGIC[0],
        DEVICE_INFO_TRAILER_MAGIC[1],
        DEVICE_INFO_TRAILER_LAYOUT,
        slot,
        v[0],
        v[1],
        v[2],
        v[3],
    ]
}

/// Parse a decimal `u32` at compile time (build stamps come in as strings).
/// Returns 0 for anything that is not a plain decimal number in range.
#[must_use]
pub const fn parse_u32_decimal(s: &str) -> u32 {
    let b = s.as_bytes();
    if b.is_empty() {
        return 0;
    }
    let mut v: u64 = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < b'0' || c > b'9' {
            return 0;
        }
        v = v * 10 + (c - b'0') as u64;
        if v > u32::MAX as u64 {
            return 0;
        }
        i += 1;
    }
    v as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TRY_ONCE_COMMITTING;

    fn cand(v: u32, try_once: u8, attempts: u32, confirmed: bool) -> Candidate {
        Candidate { fw_version: v, try_once, tally: Tally { attempts, confirmed } }
    }

    #[test]
    fn layout_constants_are_the_documented_map() {
        assert_eq!(SECURE_SLOT_CAPACITY, 655_360);
        assert_eq!(NS_SLOT_CAPACITY, 196_608);
        assert_eq!(SLOT_A_SECURE_ADDR + SECURE_SLOT_CAPACITY, 0x0C0A_E000);
        // Slot A stays clear of the per-device pages (bank-1 page 123).
        assert!(SLOT_A_SECURE_ADDR + SECURE_SLOT_CAPACITY <= 0x0C0F_6000);
        assert_eq!(SLOT_B_SECURE_ADDR + SECURE_SLOT_CAPACITY, 0x0C20_0000);
        assert_eq!(SLOT_A_NS_ADDR + NS_SLOT_CAPACITY, SLOT_B_NS_ADDR);
        assert_eq!(SLOT_B_NS_ADDR + NS_SLOT_CAPACITY, 0x0816_0000);
        assert_eq!((SECWM2_PSTRT, SECWM2_PEND), (48, 127));
        assert_eq!(secure_base(SLOT_A), SLOT_A_SECURE_ADDR);
        assert_eq!(secure_base(SLOT_B), SLOT_B_SECURE_ADDR);
        assert_eq!(ns_base(SLOT_A), SLOT_A_NS_ADDR);
        assert_eq!(ns_base(SLOT_B), SLOT_B_NS_ADDR);
        assert_eq!(manifest_addr(SLOT_A), MANIFEST_A_ADDR);
        assert_eq!(manifest_addr(SLOT_B), MANIFEST_B_ADDR);
        assert_eq!(other(SLOT_A), SLOT_B);
        assert_eq!(other(SLOT_B), SLOT_A);
        assert_eq!(LOG_CAPACITY, 512);
    }

    #[test]
    fn vectors_bind_an_image_to_its_slot() {
        let len = 500_000;
        // A slot-A image: SP at the top of secure SRAM1, reset inside slot A.
        let (sp, reset) = (SECURE_SRAM_END, SLOT_A_SECURE_ADDR + 0x801);
        assert!(vectors_in_slot(sp, reset, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        // The same image written into slot B points back into slot A: refused.
        assert!(!vectors_in_slot(sp, reset, SLOT_B_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        // A monolithic image (linked at the boot base) fits neither slot.
        let mono = 0x0C00_0801;
        assert!(!vectors_in_slot(sp, mono, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        // Thumb bit missing, reset at the base, reset past the end.
        assert!(!vectors_in_slot(sp, SLOT_A_SECURE_ADDR + 0x800, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        assert!(!vectors_in_slot(sp, SLOT_A_SECURE_ADDR | 1, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        assert!(!vectors_in_slot(sp, (SLOT_A_SECURE_ADDR + len) | 1, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        // Stack outside secure SRAM (e.g. a non-secure image), or misaligned.
        assert!(!vectors_in_slot(NS_SRAM_END, reset, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        assert!(!vectors_in_slot(SECURE_SRAM_BASE, reset, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        assert!(!vectors_in_slot(SECURE_SRAM_END - 4, reset, SLOT_A_SECURE_ADDR, len, SECURE_SRAM_BASE, SECURE_SRAM_END));
        // Non-secure slot B image.
        assert!(vectors_in_slot(NS_SRAM_END, SLOT_B_NS_ADDR + 0x1201, SLOT_B_NS_ADDR, 98_548, NS_SRAM_BASE, NS_SRAM_END));
        assert!(!vectors_in_slot(NS_SRAM_END, SLOT_B_NS_ADDR + 0x1201, SLOT_A_NS_ADDR, 98_548, NS_SRAM_BASE, NS_SRAM_END));
        // Overflowing base + len.
        assert!(!vectors_in_slot(sp, 0xFFFF_FF01, 0xFFFF_0000, 0x10_0000, SECURE_SRAM_BASE, SECURE_SRAM_END));
    }

    #[test]
    fn records_round_trip_and_reject_damage() {
        let r = encode_record(KIND_CONFIRM, SLOT_B, 0x1A0A_1501);
        assert_eq!(
            parse_record(&r),
            Some(Record { kind: KIND_CONFIRM, slot: SLOT_B, fw_version: 0x1A0A_1501 })
        );
        assert_eq!(parse_record(&[0xFF; 16]), None);
        assert!(is_erased(&[0xFF; 16]));
        assert!(!is_erased(&r));
        for i in 0..RECORD_LEN {
            let mut bad = r;
            bad[i] ^= 0x01;
            assert_eq!(parse_record(&bad), None, "flip in byte {i} must be rejected");
        }
        // A torn program that left some bytes erased.
        let mut torn = r;
        torn[8..].fill(0xFF);
        assert_eq!(parse_record(&torn), None);
        // Unknown kind / slot with a valid CRC.
        let mut odd = encode_record(KIND_ATTEMPT, SLOT_A, 7);
        odd[4] = 0x03;
        let crc = crate::crc32_ieee(&odd[..12]);
        odd[12..].copy_from_slice(&crc.to_be_bytes());
        assert_eq!(parse_record(&odd), None);
    }

    #[test]
    fn tally_counts_only_its_own_slot_and_version() {
        let log = [
            encode_record(KIND_CONFIRM, SLOT_A, 1),
            encode_record(KIND_ATTEMPT, SLOT_B, 2),
            encode_record(KIND_ATTEMPT, SLOT_B, 2),
            encode_record(KIND_ATTEMPT, SLOT_B, 3),
            encode_record(KIND_ATTEMPT, SLOT_A, 2),
            [0x00; 16],
            [0xFF; 16],
        ];
        let tally = |slot, v| {
            let mut t = Tally::default();
            for r in &log {
                t.observe(r, slot, v);
            }
            t
        };
        assert_eq!(tally(SLOT_B, 2), Tally { attempts: 2, confirmed: false });
        assert_eq!(tally(SLOT_A, 1), Tally { attempts: 0, confirmed: true });
        assert_eq!(tally(SLOT_B, 3), Tally { attempts: 1, confirmed: false });
        assert_eq!(tally(SLOT_B, 1), Tally::default());
    }

    #[test]
    fn next_free_appends_after_the_last_used_quadword() {
        let mut page = [[0xFFu8; 16]; LOG_CAPACITY];
        assert_eq!(next_free(|i| page[i]), Some(0));
        page[0] = encode_record(KIND_CONFIRM, SLOT_A, 1);
        assert_eq!(next_free(|i| page[i]), Some(1));
        // A torn quad-word is skipped, never reused.
        page[1] = [0x12; 16];
        assert_eq!(next_free(|i| page[i]), Some(2));
        // An erased hole before the last record is not reused either.
        page[5] = encode_record(KIND_ATTEMPT, SLOT_B, 2);
        assert_eq!(next_free(|i| page[i]), Some(6));
        page[LOG_CAPACITY - 1] = encode_record(KIND_ATTEMPT, SLOT_B, 2);
        assert_eq!(next_free(|i| page[i]), None);
    }

    #[test]
    fn settling_is_only_for_unconfirmed_tried_images() {
        let fresh = Tally::default();
        let confirmed = Tally { attempts: 1, confirmed: true };
        assert!(needs_settling(TRY_ONCE_TRIED, fresh));
        assert!(needs_settling(TRY_ONCE_TRIED, Tally { attempts: 5, confirmed: false }));
        assert!(!needs_settling(TRY_ONCE_TRIED, confirmed));
        assert!(!needs_settling(TRY_ONCE_COMMITTED, fresh));
    }

    #[test]
    fn choose_single_candidate_always_boots_it() {
        let exhausted = cand(9, TRY_ONCE_TRIED, 99, false);
        assert_eq!(choose(Some(exhausted), None), Some(SLOT_A));
        assert_eq!(choose(None, Some(exhausted)), Some(SLOT_B));
        assert_eq!(choose(None, None), None);
    }

    #[test]
    fn choose_new_release_gets_its_boots_then_rolls_back() {
        let old = cand(1, TRY_ONCE_COMMITTED, 0, false);
        for attempts in 0..MAX_UNCONFIRMED_BOOTS {
            let new = cand(2, TRY_ONCE_TRIED, attempts, false);
            assert_eq!(choose(Some(old), Some(new)), Some(SLOT_B), "attempt {attempts}");
            assert_eq!(choose(Some(new), Some(old)), Some(SLOT_A), "attempt {attempts} mirrored");
        }
        let failed = cand(2, TRY_ONCE_TRIED, MAX_UNCONFIRMED_BOOTS, false);
        assert_eq!(choose(Some(old), Some(failed)), Some(SLOT_A));
        assert_eq!(choose(Some(failed), Some(old)), Some(SLOT_B));
    }

    #[test]
    fn choose_confirmed_release_stays_booted() {
        let old = cand(1, TRY_ONCE_TRIED, 0, true);
        let new = cand(2, TRY_ONCE_TRIED, 7, true);
        assert_eq!(choose(Some(old), Some(new)), Some(SLOT_B));
        let factory = cand(2, TRY_ONCE_COMMITTED, 0, false);
        assert_eq!(choose(Some(old), Some(factory)), Some(SLOT_B));
    }

    #[test]
    fn choose_torn_try_once_falls_back() {
        let old = cand(1, TRY_ONCE_COMMITTED, 0, false);
        let torn = cand(2, TRY_ONCE_COMMITTING, 0, false);
        assert_eq!(choose(Some(old), Some(torn)), Some(SLOT_A));
        let garbage = cand(2, 0x37, 0, false);
        assert_eq!(choose(Some(garbage), Some(old)), Some(SLOT_B));
    }

    #[test]
    fn choose_equal_versions_prefers_settled_then_a() {
        let settled = cand(4, TRY_ONCE_COMMITTED, 0, false);
        let tried = cand(4, TRY_ONCE_TRIED, 0, false);
        assert_eq!(choose(Some(tried), Some(settled)), Some(SLOT_B));
        assert_eq!(choose(Some(settled), Some(tried)), Some(SLOT_A));
        assert_eq!(choose(Some(settled), Some(settled)), Some(SLOT_A));
        assert_eq!(choose(Some(tried), Some(tried)), Some(SLOT_A));
    }

    #[test]
    fn device_info_trailer_layout() {
        assert_eq!(
            device_info_trailer(SLOT_B, 0x1A0A_1501),
            [b'D', b'U', 1, 1, 0x1A, 0x0A, 0x15, 0x01]
        );
    }

    #[test]
    fn parse_u32_decimal_accepts_only_plain_decimals() {
        assert_eq!(parse_u32_decimal("436868353"), 436_868_353);
        assert_eq!(parse_u32_decimal("0"), 0);
        assert_eq!(parse_u32_decimal("4294967295"), u32::MAX);
        assert_eq!(parse_u32_decimal("4294967296"), 0);
        assert_eq!(parse_u32_decimal(""), 0);
        assert_eq!(parse_u32_decimal("12a"), 0);
        assert_eq!(parse_u32_decimal("-1"), 0);
    }
}
