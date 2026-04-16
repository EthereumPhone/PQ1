//! JARDÍN slot-state persistence in secure flash (per-chain log-structured).
//!
//! Two 8-KB pages at the top of secure flash form a **log** of up to 128
//! slot-state records (64 per page, 128 B each). Each record is keyed by
//! `(chain_id, slot_index)` and carries a globally-monotonic `seq`.
//!
//! ## Why per-chain
//!
//! JARDÍN FORS+C security collapses sharply under `(slot, q)` reuse:
//! 128-bit at q=1, ~105-bit at q=2 with random messages, much worse with
//! adversarial choice. A single record that tracks only the "most-recent"
//! chain causes q-reuse the moment the user signs on chain A, then B,
//! then returns to A — because the A record has been overwritten, the
//! state machine restarts at q=1 for A.
//!
//! Keeping latest state **per chain** is therefore a correctness
//! requirement, not an optimisation.
//!
//! ## Layout
//!
//! Each record is 128 B. Layout:
//!
//! ```text
//!   off  len  field
//!   ---  ---  -----------------------------------------
//!     0    4  magic              = 0x4A41_5244 ("JARD")
//!     4    4  version            = 2  (log-structured v2)
//!     8    8  seq                (u64 LE, global monotonic)
//!    16    8  chain_id           (u64 LE)
//!    24    4  slot_index         (u32 LE)
//!    28    4  next_q             (u32 LE, next unused FORS+C leaf)
//!    32    4  flags              (bit 0: slot_registered on chain_id)
//!    36    4  reserved
//!    40   32  h_r                (keccak256(r), the on-chain slotKey)
//!    72   16  sub_pk_seed        (16 B, N-masked pkSeed of the slot)
//!    88   16  sub_pk_root        (16 B, N-masked pkRoot of the slot)
//!   104   16  integrity          (first 16 B of keccak256(bytes[0..104]))
//!   120    7  reserved
//!   127    1  valid_marker       (0x00 = populated, 0xFF = blank)
//! ```
//!
//! The integrity tag is 16 B (widened from 4 B in v1) so that fault-
//! injection with a collision probability beyond 2^-128 would be needed
//! to forge a valid record. `valid_marker` at the final byte remains the
//! torn-write defence: the last QW (offset 112..128) is programmed
//! atomically; torn earlier writes leave the marker at 0xFF (blank).
//!
//! ## Write algorithm
//!
//! Appending a record:
//!
//!   1. Scan both pages; find `max_seq` and the first blank slot.
//!   2. If a blank slot exists: assign `seq = max_seq + 1`, program it.
//!   3. Otherwise compact: collect latest-per-chain (including the new
//!      state) in SRAM, erase one page, re-program the compacted set
//!      with fresh seqs, erase the other page. The re-seq'd records
//!      always have higher seqs than any stale records on the other
//!      page, so torn-compaction recovery is deterministic.
//!
//! Reads scan both pages and return the max-seq record for the given
//! chain_id.
//!
//! ## Wear
//!
//! At best ~64 × 2 pages = 128 records per erase cycle. With 2 × 10 K
//! endurance = 20 K erases, worst-case ≈ 1.3 M signs of headroom before
//! wearout — plenty for the lifetime of the device.

use zeroize::Zeroize;

/// Magic word identifying a JARDÍN slot-state record ("JARD" little-endian).
pub const MAGIC: u32 = 0x4A41_5244;

/// Current on-disk layout version (v2: per-chain log).
pub const VERSION: u32 = 2;

/// Record size in bytes = 8 flash quad-words.
pub const RECORD_LEN: usize = 128;

/// Page size on STM32U585 (2 KB flash page = 128 QW; we reserve 8 KB).
pub const PAGE_LEN: usize = 8 * 1024;

/// Records that fit in one page.
pub const RECORDS_PER_PAGE: usize = PAGE_LEN / RECORD_LEN;

/// Total records across both log pages.
pub const TOTAL_RECORDS: usize = RECORDS_PER_PAGE * 2;

/// Compaction buffer: maximum number of unique chain_ids we can retain
/// across a single compaction. Each chain consumes one record slot, so
/// this also bounds the post-compaction residency of page A.
pub const MAX_UNIQUE_CHAINS: usize = 32;

// Byte offsets within a record.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_SEQ: usize = 8;
const OFF_CHAIN_ID: usize = 16;
const OFF_SLOT_INDEX: usize = 24;
const OFF_NEXT_Q: usize = 28;
const OFF_FLAGS: usize = 32;
const OFF_H_R: usize = 40;
const OFF_SUB_PK_SEED: usize = 72;
const OFF_SUB_PK_ROOT: usize = 88;
const OFF_INTEGRITY: usize = 104;
const OFF_VALID_MARKER: usize = 127;

const INTEGRITY_COVERED_LEN: usize = OFF_INTEGRITY;
const INTEGRITY_LEN: usize = 16;
const VALID_MARKER: u8 = 0x00;

/// Flags bit positions.
pub const FLAG_SLOT_REGISTERED: u32 = 1 << 0;

/// In-memory representation of one slot-state record.
///
/// `seq` is managed by this module — callers should not set it; the
/// module assigns `max_seq + 1` on every write.
#[derive(Clone, Zeroize)]
pub struct SlotState {
    pub seq: u64,
    pub chain_id: u64,
    pub slot_index: u32,
    pub next_q: u32,
    pub flags: u32,
    pub h_r: [u8; 32],
    pub sub_pk_seed: [u8; 16],
    pub sub_pk_root: [u8; 16],
}

impl SlotState {
    /// Whether the slot is registered on the stored `chain_id`.
    pub fn is_registered(&self) -> bool {
        self.flags & FLAG_SLOT_REGISTERED != 0
    }

    fn serialize_into(&self, buf: &mut [u8; RECORD_LEN]) {
        for b in buf.iter_mut() {
            *b = 0xFF;
        }
        buf[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC.to_le_bytes());
        buf[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&VERSION.to_le_bytes());
        buf[OFF_SEQ..OFF_SEQ + 8].copy_from_slice(&self.seq.to_le_bytes());
        buf[OFF_CHAIN_ID..OFF_CHAIN_ID + 8].copy_from_slice(&self.chain_id.to_le_bytes());
        buf[OFF_SLOT_INDEX..OFF_SLOT_INDEX + 4].copy_from_slice(&self.slot_index.to_le_bytes());
        buf[OFF_NEXT_Q..OFF_NEXT_Q + 4].copy_from_slice(&self.next_q.to_le_bytes());
        buf[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&self.flags.to_le_bytes());
        buf[OFF_H_R..OFF_H_R + 32].copy_from_slice(&self.h_r);
        buf[OFF_SUB_PK_SEED..OFF_SUB_PK_SEED + 16].copy_from_slice(&self.sub_pk_seed);
        buf[OFF_SUB_PK_ROOT..OFF_SUB_PK_ROOT + 16].copy_from_slice(&self.sub_pk_root);

        let integrity = integrity_tag(&buf[..INTEGRITY_COVERED_LEN]);
        buf[OFF_INTEGRITY..OFF_INTEGRITY + INTEGRITY_LEN].copy_from_slice(&integrity);
        buf[OFF_VALID_MARKER] = VALID_MARKER;
    }

    fn deserialize(buf: &[u8; RECORD_LEN]) -> Option<Self> {
        if buf[OFF_VALID_MARKER] != VALID_MARKER {
            return None;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != MAGIC {
            return None;
        }
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != VERSION {
            return None;
        }
        let computed = integrity_tag(&buf[..INTEGRITY_COVERED_LEN]);
        if !ct_eq(&computed, &buf[OFF_INTEGRITY..OFF_INTEGRITY + INTEGRITY_LEN]) {
            return None;
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&buf[OFF_SEQ..OFF_SEQ + 8]);
        let mut chain_bytes = [0u8; 8];
        chain_bytes.copy_from_slice(&buf[OFF_CHAIN_ID..OFF_CHAIN_ID + 8]);
        let mut h_r = [0u8; 32];
        h_r.copy_from_slice(&buf[OFF_H_R..OFF_H_R + 32]);
        let mut sub_pk_seed = [0u8; 16];
        sub_pk_seed.copy_from_slice(&buf[OFF_SUB_PK_SEED..OFF_SUB_PK_SEED + 16]);
        let mut sub_pk_root = [0u8; 16];
        sub_pk_root.copy_from_slice(&buf[OFF_SUB_PK_ROOT..OFF_SUB_PK_ROOT + 16]);

        Some(Self {
            seq: u64::from_le_bytes(seq_bytes),
            chain_id: u64::from_le_bytes(chain_bytes),
            slot_index: u32::from_le_bytes([
                buf[OFF_SLOT_INDEX],
                buf[OFF_SLOT_INDEX + 1],
                buf[OFF_SLOT_INDEX + 2],
                buf[OFF_SLOT_INDEX + 3],
            ]),
            next_q: u32::from_le_bytes([
                buf[OFF_NEXT_Q],
                buf[OFF_NEXT_Q + 1],
                buf[OFF_NEXT_Q + 2],
                buf[OFF_NEXT_Q + 3],
            ]),
            flags: u32::from_le_bytes([
                buf[OFF_FLAGS],
                buf[OFF_FLAGS + 1],
                buf[OFF_FLAGS + 2],
                buf[OFF_FLAGS + 3],
            ]),
            h_r,
            sub_pk_seed,
            sub_pk_root,
        })
    }
}

/// First 16 bytes of keccak256 over the record prefix.
fn integrity_tag(prefix: &[u8]) -> [u8; INTEGRITY_LEN] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(prefix);
    let digest = h.finalize();
    let mut out = [0u8; INTEGRITY_LEN];
    out.copy_from_slice(&digest[..INTEGRITY_LEN]);
    out
}

/// Constant-time slice equality. Used to gate integrity acceptance so a
/// side-channel can't discriminate near-matches from mismatches.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d: u8 = 0;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

/// Persistence error. `sr` captures the raw FLASH_SECSR bits so a
/// caller can log which bit fired (WRPERR / PGSERR / SIZERR / etc.).
#[derive(Clone, Copy, Debug)]
pub enum FlashError {
    /// Flash controller reported an error during page erase.
    EraseHardware { sr: u32, page: u32 },
    /// Flash controller reported an error during quadword program.
    ProgramHardware { sr: u32, addr: u32 },
    /// Read-back after program did not match the intended bytes.
    VerifyFailed {
        addr: u32,
        byte_idx: usize,
        expected: u8,
        actual: u8,
    },
}

/// Identifier for the two log pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    A,
    B,
}

// ---------------------------------------------------------------------------
// Backend: real flash on STM32U585, RAM-mirrored on QEMU.
// ---------------------------------------------------------------------------

#[cfg(feature = "stm32u585")]
mod backend {
    //! STM32U585 backend. Two 8-KB pages at the top of secure flash
    //! bank 1 hold the log (pages 123 + 124). Programming is quad-word
    //! aligned; each record spans 8 QWs.

    use super::{FlashError, Page, RECORDS_PER_PAGE, RECORD_LEN};

    const PAGE_A_ADDR: u32 = 0x0C0F_8000;
    const PAGE_A_PAGE_NUM: u32 = 124;
    const PAGE_B_ADDR: u32 = 0x0C0F_6000;
    const PAGE_B_PAGE_NUM: u32 = 123;

    fn addr_of(page: Page) -> u32 {
        match page {
            Page::A => PAGE_A_ADDR,
            Page::B => PAGE_B_ADDR,
        }
    }

    fn page_num(page: Page) -> u32 {
        match page {
            Page::A => PAGE_A_PAGE_NUM,
            Page::B => PAGE_B_PAGE_NUM,
        }
    }

    fn slot_addr(page: Page, slot: usize) -> u32 {
        addr_of(page) + (slot as u32) * (RECORD_LEN as u32)
    }

    /// Read one slot of the log into `buf`.
    pub unsafe fn read_slot(page: Page, slot: usize, buf: &mut [u8; RECORD_LEN]) {
        debug_assert!(slot < RECORDS_PER_PAGE);
        let src = slot_addr(page, slot) as *const u8;
        for i in 0..RECORD_LEN {
            buf[i] = core::ptr::read_volatile(src.add(i));
        }
    }

    /// Program one slot. Assumes the slot is blank (all 0xFF). Programs
    /// 8 QWs in order; the final QW (which carries the valid_marker) is
    /// written last so torn writes leave the slot detected as blank.
    pub unsafe fn write_slot(
        page: Page,
        slot: usize,
        buf: &[u8; RECORD_LEN],
    ) -> Result<(), FlashError> {
        debug_assert!(slot < RECORDS_PER_PAGE);
        let base = slot_addr(page, slot);
        cortex_m::interrupt::free(|_| {
            let mut qw = [0u8; 16];
            for i in 0..(RECORD_LEN / 16) {
                qw.copy_from_slice(&buf[i * 16..(i + 1) * 16]);
                program_qw(base + (i as u32) * 16, &qw)?;
            }
            Ok(())
        })
    }

    /// Erase an entire log page. Sets all bytes to 0xFF.
    pub unsafe fn erase_page(page: Page) -> Result<(), FlashError> {
        cortex_m::interrupt::free(|_| erase_page_num(page_num(page)))
    }

    // Direct flash-controller interaction.
    const FLASH: u32 = 0x5002_2000;
    const FLASH_SECKEYR: *mut u32 = (FLASH + 0x0C) as *mut u32;
    const FLASH_SECSR: *mut u32 = (FLASH + 0x24) as *mut u32;
    const FLASH_SECCR: *mut u32 = (FLASH + 0x2C) as *mut u32;
    const KEY1: u32 = 0x4567_0123;
    const KEY2: u32 = 0xCDEF_89AB;
    const PG: u32 = 1 << 0;
    const PER: u32 = 1 << 1;
    const PNB_SHIFT: u32 = 3;
    const STRT: u32 = 1 << 16;
    const LOCK: u32 = 1 << 31;
    const BSY: u32 = 1 << 16;
    const ERR_MASK: u32 = 0xFA;

    // ICACHE registers (secure alias). After every flash write the data
    // cache must be invalidated or read-backs return stale bytes.
    const ICACHE: u32 = 0x5003_0400;
    const ICACHE_CR: *mut u32 = ICACHE as *mut u32;
    const ICACHE_SR: *const u32 = (ICACHE + 0x04) as *const u32;
    const ICACHE_FCR: *mut u32 = (ICACHE + 0x0C) as *mut u32;
    const CACHEINV: u32 = 1 << 1;
    const BUSYF: u32 = 1 << 0;
    const BSYENDF: u32 = 1 << 1;

    unsafe fn invalidate_icache() {
        let cr = core::ptr::read_volatile(ICACHE_CR);
        core::ptr::write_volatile(ICACHE_CR, cr | CACHEINV);
        // Data-synchronisation barrier so the CACHEINV write is visible
        // to the cache controller before we poll BUSYF.
        cortex_m::asm::dsb();
        let mut guard = 0u32;
        while core::ptr::read_volatile(ICACHE_SR) & BUSYF != 0 {
            cortex_m::asm::nop();
            guard = guard.wrapping_add(1);
            if guard > 1_000_000 {
                break;
            }
        }
        core::ptr::write_volatile(ICACHE_FCR, BSYENDF);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }

    unsafe fn wait_bsy() {
        while core::ptr::read_volatile(FLASH_SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
    }

    unsafe fn clear_errors() {
        let sr = core::ptr::read_volatile(FLASH_SECSR);
        if sr & ERR_MASK != 0 {
            core::ptr::write_volatile(FLASH_SECSR, sr & ERR_MASK);
        }
    }

    unsafe fn unlock() {
        core::ptr::write_volatile(FLASH_SECKEYR, KEY1);
        core::ptr::write_volatile(FLASH_SECKEYR, KEY2);
    }

    unsafe fn lock() {
        let cr = core::ptr::read_volatile(FLASH_SECCR);
        core::ptr::write_volatile(FLASH_SECCR, cr | LOCK);
    }

    unsafe fn erase_page_num(page_num: u32) -> Result<(), FlashError> {
        wait_bsy();
        clear_errors();
        unlock();
        let cr = PER | (page_num << PNB_SHIFT);
        core::ptr::write_volatile(FLASH_SECCR, cr);
        core::ptr::write_volatile(FLASH_SECCR, cr | STRT);
        wait_bsy();
        let sr = core::ptr::read_volatile(FLASH_SECSR);
        core::ptr::write_volatile(FLASH_SECCR, 0);
        lock();
        invalidate_icache();
        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(FlashError::EraseHardware { sr, page: page_num })
        } else {
            Ok(())
        }
    }

    unsafe fn program_qw(addr: u32, qw: &[u8; 16]) -> Result<(), FlashError> {
        wait_bsy();
        clear_errors();
        unlock();
        core::ptr::write_volatile(FLASH_SECCR, PG);
        let dst = addr as *mut u32;
        for i in 0..4 {
            let word = u32::from_le_bytes([
                qw[i * 4],
                qw[i * 4 + 1],
                qw[i * 4 + 2],
                qw[i * 4 + 3],
            ]);
            core::ptr::write_volatile(dst.add(i), word);
        }
        wait_bsy();
        let sr = core::ptr::read_volatile(FLASH_SECSR);
        core::ptr::write_volatile(FLASH_SECCR, 0);
        lock();
        invalidate_icache();
        if sr & ERR_MASK != 0 {
            clear_errors();
            return Err(FlashError::ProgramHardware { sr, addr });
        }
        // Read-back compare.
        let src = addr as *const u8;
        for i in 0..16 {
            let actual = core::ptr::read_volatile(src.add(i));
            if actual != qw[i] {
                return Err(FlashError::VerifyFailed {
                    addr,
                    byte_idx: i,
                    expected: qw[i],
                    actual,
                });
            }
        }
        Ok(())
    }
}

#[cfg(not(feature = "stm32u585"))]
mod backend {
    //! QEMU / host backend: two static-RAM buffers that mimic the flash
    //! layout. Not power-persistent; enough to exercise the read/write
    //! state machine in e2e tests.

    use super::{FlashError, Page, PAGE_LEN, RECORDS_PER_PAGE, RECORD_LEN};

    static mut PAGE_A: [u8; PAGE_LEN] = [0xFF; PAGE_LEN];
    static mut PAGE_B: [u8; PAGE_LEN] = [0xFF; PAGE_LEN];

    fn slot_offset(slot: usize) -> usize {
        slot * RECORD_LEN
    }

    pub unsafe fn read_slot(page: Page, slot: usize, buf: &mut [u8; RECORD_LEN]) {
        debug_assert!(slot < RECORDS_PER_PAGE);
        let off = slot_offset(slot);
        let src: &[u8; PAGE_LEN] = match page {
            Page::A => &*core::ptr::addr_of!(PAGE_A),
            Page::B => &*core::ptr::addr_of!(PAGE_B),
        };
        buf.copy_from_slice(&src[off..off + RECORD_LEN]);
    }

    pub unsafe fn write_slot(
        page: Page,
        slot: usize,
        buf: &[u8; RECORD_LEN],
    ) -> Result<(), FlashError> {
        debug_assert!(slot < RECORDS_PER_PAGE);
        let off = slot_offset(slot);
        let dst: &mut [u8; PAGE_LEN] = match page {
            Page::A => &mut *core::ptr::addr_of_mut!(PAGE_A),
            Page::B => &mut *core::ptr::addr_of_mut!(PAGE_B),
        };
        // Mimic NOR-flash one-way bit transitions: the slot must be blank
        // (all 0xFF) before programming — catches bugs where callers
        // forget to erase before re-program.
        for i in 0..RECORD_LEN {
            if dst[off + i] != 0xFF {
                return Err(FlashError::ProgramHardware {
                    sr: 0,
                    addr: off as u32,
                });
            }
        }
        dst[off..off + RECORD_LEN].copy_from_slice(buf);
        Ok(())
    }

    pub unsafe fn erase_page(page: Page) -> Result<(), FlashError> {
        let dst: &mut [u8; PAGE_LEN] = match page {
            Page::A => &mut *core::ptr::addr_of_mut!(PAGE_A),
            Page::B => &mut *core::ptr::addr_of_mut!(PAGE_B),
        };
        for b in dst.iter_mut() {
            *b = 0xFF;
        }
        Ok(())
    }

    /// Test-only helper to reset the simulated flash.
    #[cfg(test)]
    pub unsafe fn reset_all() {
        let _ = erase_page(Page::A);
        let _ = erase_page(Page::B);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read the latest-committed slot state for `chain_id`, or `None` if
/// this chain has no record.
pub fn read_latest_for(chain_id: u64) -> Option<SlotState> {
    let mut best: Option<SlotState> = None;
    scan_all(|rec| {
        if rec.chain_id == chain_id {
            let take = match &best {
                Some(cur) => rec.seq > cur.seq,
                None => true,
            };
            if take {
                best = Some(rec);
            }
        }
    });
    best
}

/// Read the globally-most-recent slot state across all chains.
///
/// Kept for diagnostics and legacy test code. For sign-time decisions
/// use `read_latest_for(chain_id)`.
pub fn read_latest() -> Option<SlotState> {
    let mut best: Option<SlotState> = None;
    scan_all(|rec| {
        let take = match &best {
            Some(cur) => rec.seq > cur.seq,
            None => true,
        };
        if take {
            best = Some(rec);
        }
    });
    best
}

/// Commit a new slot state. The module assigns `seq = max_seq + 1` and
/// appends to the log. When the log is full, the function compacts in
/// place before appending.
pub fn write(state: &SlotState) -> Result<(), FlashError> {
    // Scan both pages: find max_seq and first blank slot.
    let mut max_seq: u64 = 0;
    let mut first_blank: Option<(Page, usize)> = None;
    let mut buf = [0u8; RECORD_LEN];

    for &page in &[Page::A, Page::B] {
        for slot in 0..RECORDS_PER_PAGE {
            unsafe {
                backend::read_slot(page, slot, &mut buf);
            }
            if let Some(rec) = SlotState::deserialize(&buf) {
                if rec.seq > max_seq {
                    max_seq = rec.seq;
                }
            } else if is_slot_blank(&buf) && first_blank.is_none() {
                first_blank = Some((page, slot));
            }
        }
    }

    let mut to_write = state.clone();
    to_write.seq = max_seq.wrapping_add(1);
    let mut ser = [0xFFu8; RECORD_LEN];
    to_write.serialize_into(&mut ser);

    let result = if let Some((page, slot)) = first_blank {
        unsafe { backend::write_slot(page, slot, &ser) }
    } else {
        let r = compact_and_write(state, max_seq);
        to_write.zeroize();
        ser.zeroize();
        return r;
    };

    to_write.zeroize();
    ser.zeroize();
    result
}

/// Whether a raw 128-byte slot buffer is in the all-0xFF erased state.
fn is_slot_blank(buf: &[u8; RECORD_LEN]) -> bool {
    for &b in buf.iter() {
        if b != 0xFF {
            return false;
        }
    }
    true
}

/// Compact the log: collect latest-per-chain (including the new state),
/// write the compacted set to the emptier page, then erase the other.
fn compact_and_write(new_state: &SlotState, max_seq: u64) -> Result<(), FlashError> {
    // Per-page population counts help pick the target (we erase the page
    // with more populated slots first — it's more in need of compaction).
    let mut count_a: usize = 0;
    let mut count_b: usize = 0;
    {
        let mut buf = [0u8; RECORD_LEN];
        for slot in 0..RECORDS_PER_PAGE {
            unsafe {
                backend::read_slot(Page::A, slot, &mut buf);
            }
            if SlotState::deserialize(&buf).is_some() {
                count_a += 1;
            }
            unsafe {
                backend::read_slot(Page::B, slot, &mut buf);
            }
            if SlotState::deserialize(&buf).is_some() {
                count_b += 1;
            }
        }
    }

    // Target = page whose contents we will replace with the compacted set.
    // Pick the page that currently holds MORE records; that page is more
    // "in need" of compaction. Ties break to A.
    let target = if count_b > count_a { Page::B } else { Page::A };
    let other = if target == Page::A { Page::B } else { Page::A };

    // Build latest-per-chain map in SRAM. `new_state`'s chain must be
    // represented by `new_state` itself (overrides any stored record).
    let mut latest: [Option<SlotState>; MAX_UNIQUE_CHAINS] = Default::default();
    let mut n_chains: usize = 0;

    scan_all(|rec| {
        if rec.chain_id == new_state.chain_id {
            return;
        }
        for i in 0..n_chains {
            if let Some(ref cur) = latest[i] {
                if cur.chain_id == rec.chain_id {
                    if rec.seq > cur.seq {
                        latest[i] = Some(rec);
                    }
                    return;
                }
            }
        }
        if n_chains < MAX_UNIQUE_CHAINS {
            latest[n_chains] = Some(rec);
            n_chains += 1;
        }
        // else: silent drop — the map is full. The caller's new_state
        // still gets written below. Realistically unreachable for
        // sensible chain counts (ERC-4337 networks fit under 32).
    });

    // Prepend-ish: insert new_state at position n_chains (still unique).
    if n_chains < MAX_UNIQUE_CHAINS {
        latest[n_chains] = Some(new_state.clone());
        n_chains += 1;
    } else {
        // No room for new_state in the compaction buffer — fail rather
        // than silently drop. This is effectively impossible in
        // practice; bumping MAX_UNIQUE_CHAINS fixes it if it ever hits.
        return Err(FlashError::ProgramHardware { sr: 0, addr: 0 });
    }

    // Assign fresh monotonically-increasing seqs. The re-seqed records
    // dominate any stale records still on the other page, so reads
    // during the window between step 4 and step 5 pick the right state.
    let mut next_seq = max_seq.wrapping_add(1);
    let mut buf = [0xFFu8; RECORD_LEN];

    // Erase target.
    let erase_res = unsafe { backend::erase_page(target) };
    if erase_res.is_err() {
        zeroize_latest(&mut latest);
        return erase_res;
    }

    // Write the compacted set.
    for i in 0..n_chains {
        if let Some(ref mut rec) = latest[i] {
            rec.seq = next_seq;
            next_seq = next_seq.wrapping_add(1);
            rec.serialize_into(&mut buf);
            let w = unsafe { backend::write_slot(target, i, &buf) };
            if let Err(e) = w {
                buf.zeroize();
                zeroize_latest(&mut latest);
                return Err(e);
            }
        }
    }
    buf.zeroize();

    // Erase the other page — cleans up stale records. Not load-bearing
    // for correctness (readers already ignore stale records because
    // max-seq wins), but reclaims space for future appends.
    let erase_other = unsafe { backend::erase_page(other) };
    zeroize_latest(&mut latest);
    erase_other
}

fn zeroize_latest(latest: &mut [Option<SlotState>; MAX_UNIQUE_CHAINS]) {
    for slot in latest.iter_mut() {
        if let Some(ref mut r) = slot {
            r.zeroize();
        }
        *slot = None;
    }
}

/// Visit every valid record in the log.
fn scan_all(mut visit: impl FnMut(SlotState)) {
    let mut buf = [0u8; RECORD_LEN];
    for &page in &[Page::A, Page::B] {
        for slot in 0..RECORDS_PER_PAGE {
            unsafe {
                backend::read_slot(page, slot, &mut buf);
            }
            if let Some(rec) = SlotState::deserialize(&buf) {
                visit(rec);
            }
        }
    }
    buf.zeroize();
}

// ---------------------------------------------------------------------------
// Tests (host-only).
// ---------------------------------------------------------------------------

#[cfg(all(test, not(feature = "stm32u585")))]
mod tests {
    use super::*;

    fn sample(chain_id: u64, next_q: u32) -> SlotState {
        SlotState {
            seq: 0,
            chain_id,
            slot_index: 0,
            next_q,
            flags: FLAG_SLOT_REGISTERED,
            h_r: [0x11; 32],
            sub_pk_seed: [0x22; 16],
            sub_pk_root: [0x33; 16],
        }
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let mut s = sample(1, 7);
        s.seq = 42;
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        let r = SlotState::deserialize(&buf).expect("valid record");
        assert_eq!(r.seq, 42);
        assert_eq!(r.chain_id, 1);
        assert_eq!(r.next_q, 7);
    }

    #[test]
    fn blank_buffer_rejects() {
        let buf = [0xFFu8; RECORD_LEN];
        assert!(SlotState::deserialize(&buf).is_none());
    }

    #[test]
    fn corrupted_integrity_rejects() {
        let s = sample(1, 5);
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        buf[OFF_CHAIN_ID] ^= 0xA5;
        assert!(SlotState::deserialize(&buf).is_none());
    }

    use std::sync::Mutex;
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static M: Mutex<()> = Mutex::new(());
        let g = M.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            backend::reset_all();
        }
        g
    }

    #[test]
    fn empty_on_fresh_device() {
        let _g = lock();
        assert!(read_latest_for(1).is_none());
        assert!(read_latest().is_none());
    }

    #[test]
    fn write_then_read() {
        let _g = lock();
        write(&sample(1, 1)).expect("write");
        let got = read_latest_for(1).expect("present");
        assert_eq!(got.next_q, 1);
        assert_eq!(got.chain_id, 1);
    }

    #[test]
    fn per_chain_isolation_survives_interleave() {
        // The regression test for CRIT-1: alternating writes on two
        // chains must not erase either chain's state.
        let _g = lock();
        for q in 1..=10u32 {
            write(&sample(1, q)).unwrap(); // chain 1: q=1..10
            write(&sample(2, q)).unwrap(); // chain 2: q=1..10
        }
        let a = read_latest_for(1).unwrap();
        let b = read_latest_for(2).unwrap();
        assert_eq!(a.next_q, 10);
        assert_eq!(b.next_q, 10);
    }

    #[test]
    fn other_chain_does_not_see_this_chains_state() {
        let _g = lock();
        write(&sample(1, 50)).unwrap();
        assert!(read_latest_for(2).is_none());
    }

    #[test]
    fn compaction_preserves_latest_per_chain() {
        let _g = lock();
        // Fill the log past both pages (128 slots).
        // 3 chains cycling, next_q climbing.
        for i in 0..130u32 {
            let chain = ((i % 3) as u64) + 1;
            write(&sample(chain, i + 1)).unwrap();
        }
        for c in 1..=3u64 {
            let s = read_latest_for(c).expect("chain present after compaction");
            // After 130 interleaved writes the last next_q for each chain
            // is the last cycle hit.
            assert!(s.next_q >= 128);
        }
    }

    #[test]
    fn compaction_triggers_after_total_records() {
        let _g = lock();
        // Write TOTAL_RECORDS+1 records for distinct chains (up to
        // MAX_UNIQUE_CHAINS-1) then keep adding to chain 1. Compaction
        // must eventually run and preserve both.
        for i in 0..(MAX_UNIQUE_CHAINS - 1) as u64 {
            write(&sample(i + 10, 1)).unwrap();
        }
        // Now hammer chain 1.
        for q in 1..=120u32 {
            write(&sample(1, q)).unwrap();
        }
        let s = read_latest_for(1).unwrap();
        assert_eq!(s.next_q, 120);
        // Every other chain's state must still be present.
        for i in 0..(MAX_UNIQUE_CHAINS - 1) as u64 {
            let r = read_latest_for(i + 10).unwrap();
            assert_eq!(r.next_q, 1);
        }
    }
}
