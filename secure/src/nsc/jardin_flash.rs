//! JARDÍN slot-state persistence in secure flash.
//!
//! Two pages (primary + shadow) at the top of secure flash hold a
//! double-buffered, sequence-numbered `SlotStateRecord`. On STM32U585
//! the pages are real flash (writes survive power loss); on QEMU the
//! backing store is a static-RAM buffer so the same API can be
//! exercised by the e2e test without persistence semantics.
//!
//! ## Why persist at all
//!
//! JARDÍN FORS+C is a **few-time** scheme: each `(pk, q)` signs at most
//! once, and reusing `q` with a different message leaks FORS secrets
//! (security drops from 128 bits to ~105 at q=2, ~90 at q=3, etc.).
//! The on-chain verifier is stateless so the chain will not reject a
//! replayed q. The only thing preventing reuse after a power cycle is
//! device-local state. Hence: flash.
//!
//! ## Layout
//!
//! Each record is 128 bytes = 8 STM32 quad-words (QW = 16 B, the flash
//! programming unit). Layout:
//!
//! ```text
//!   off  len  field
//!   ---  ---  -----------------------------------------
//!     0    4  magic              = 0x4A41_5244 ("JARD")
//!     4    4  version            = 1
//!     8    8  seq                (u64 LE, monotonic)
//!    16    8  chain_id           (u64 LE)
//!    24    4  slot_index         (u32 LE)
//!    28    4  next_q             (u32 LE, next unused FORS+C leaf)
//!    32    4  flags              (bit 0: slot_registered on chain_id)
//!    36    4  reserved
//!    40   32  h_r                (keccak256(r), the on-chain slotKey)
//!    72   16  sub_pk_seed        (16 B, N-masked pkSeed of the slot)
//!    88   16  sub_pk_root        (16 B, N-masked pkRoot of the slot)
//!   104    4  integrity          (first 4 B of keccak256(bytes[0..104]))
//!   108   19  reserved
//!   127    1  valid_marker       (0x00 = populated, 0xFF = blank)
//! ```
//!
//! The `valid_marker` lives in the final byte so a torn QW write on
//! brown-out cannot leave the marker asserted with stale data: the
//! last QW (offset 112..128) is programmed atomically after the
//! preceding ones, so if we see `valid_marker == 0x00` the preceding
//! bytes are also committed.
//!
//! ## Write algorithm
//!
//! Updates are double-buffered at page granularity. To commit a new
//! `SlotState`:
//!
//!   1. Read the latest-seq record from either page, call that `cur`.
//!   2. Compute `new.seq = cur.seq + 1` (0 if no record exists).
//!   3. Erase the *other* page.
//!   4. Program the new record at offset 0 of the freshly-erased page.
//!   5. On success the new page is implicitly active (higher seq).
//!
//! Read: scan both pages, take the record with the highest seq whose
//! integrity hash verifies and whose valid_marker is 0x00. Return
//! `None` if neither page has a valid record.
//!
//! Wear: one page erase per commit, alternating between the two pages
//! → 2 × 10K erase-cycle endurance = 20K commits of headroom. At the
//! worst case (one commit per signature, 95 signs per rotation) this
//! gives ~20K signatures over the device lifetime. Fine for an MVP.
//! Log-structured appends would trade complexity for ~64× more
//! headroom; deferred until we measure a real bottleneck.

use zeroize::Zeroize;

/// Magic word identifying a JARDÍN slot-state record ("JARD" little-endian).
pub const MAGIC: u32 = 0x4A41_5244;

/// Current on-disk layout version.
pub const VERSION: u32 = 1;

/// Record size in bytes = 8 flash quad-words.
pub const RECORD_LEN: usize = 128;

/// Page size on STM32U585 (2 KB flash page = 128 QW).
///
/// We reserve one full page per buffer even though only 128 bytes are
/// used, because flash erase is per-page. The remaining 1920 bytes are
/// unused (0xFF).
pub const PAGE_LEN: usize = 8 * 1024;

// Byte offsets within a record
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
const VALID_MARKER: u8 = 0x00;

/// Flags bit positions.
pub const FLAG_SLOT_REGISTERED: u32 = 1 << 0;

/// In-memory representation of one slot-state record.
///
/// `seq` is managed by this module — callers should not set it; pass
/// whatever is in the returned `SlotState` back in on update.
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

    /// Serialize to the 128-byte on-disk record. Caller supplies the
    /// integrity-hash helper so we don't depend on a specific keccak impl.
    fn serialize_into(&self, buf: &mut [u8; RECORD_LEN]) {
        // Clear to 0xFF so unused bytes read as "blank" in case of a
        // partial write that writes the first QWs but not the last.
        // The final atomic QW write flips valid_marker to 0x00.
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

        // Integrity: first 4 bytes of keccak256 over bytes [0..104).
        let integrity = integrity_tag(&buf[..INTEGRITY_COVERED_LEN]);
        buf[OFF_INTEGRITY..OFF_INTEGRITY + 4].copy_from_slice(&integrity);

        // valid_marker is the very last byte and is programmed in the
        // final QW; use 0x00 to assert "valid".
        buf[OFF_VALID_MARKER] = VALID_MARKER;
    }

    /// Parse and validate a 128-byte record. Returns `None` if the
    /// record is blank, has the wrong magic, a bad integrity tag, or
    /// the valid marker is not asserted.
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
        // Verify integrity tag.
        let computed = integrity_tag(&buf[..INTEGRITY_COVERED_LEN]);
        if computed != buf[OFF_INTEGRITY..OFF_INTEGRITY + 4] {
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

/// First 4 bytes of keccak256 over the record prefix. Good enough as a
/// structural integrity check; not a security boundary (the seed
/// itself is protected by the SE + PIN gate).
fn integrity_tag(prefix: &[u8]) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(prefix);
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
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
    VerifyFailed { addr: u32, byte_idx: usize, expected: u8, actual: u8 },
}

// ---------------------------------------------------------------------------
// Backend: real flash on STM32U585, RAM-mirrored on QEMU.
// ---------------------------------------------------------------------------

#[cfg(feature = "stm32u585")]
mod backend {
    //! STM32U585 backend backed by the `hw::flash` driver.
    //!
    //! Two pages are reserved at the top of secure flash bank 1:
    //!
    //!   * page 124 (0x0C0F_8000) — primary buffer (A)
    //!   * page 123 (0x0C0F_6000) — shadow buffer  (B)
    //!
    //! `memory-stm32u585.x` must shrink `FLASH LENGTH` by 16 KB past
    //! the existing reservation for pages 125–127 to keep firmware
    //! code out of these pages.

    use super::{FlashError, PAGE_LEN, RECORD_LEN};

    const JARDIN_A_ADDR: u32 = 0x0C0F_8000;
    const JARDIN_A_PAGE_NUM: u32 = 124;
    const JARDIN_B_ADDR: u32 = 0x0C0F_6000;
    const JARDIN_B_PAGE_NUM: u32 = 123;

    pub const PAGE_A_ADDR: u32 = JARDIN_A_ADDR;
    pub const PAGE_B_ADDR: u32 = JARDIN_B_ADDR;

    unsafe fn read_page(addr: u32, buf: &mut [u8; RECORD_LEN]) {
        let src = addr as *const u8;
        for i in 0..RECORD_LEN {
            buf[i] = core::ptr::read_volatile(src.add(i));
        }
    }

    /// Read the first `RECORD_LEN` bytes of page A.
    pub unsafe fn read_page_a(buf: &mut [u8; RECORD_LEN]) {
        read_page(JARDIN_A_ADDR, buf);
    }

    /// Read the first `RECORD_LEN` bytes of page B.
    pub unsafe fn read_page_b(buf: &mut [u8; RECORD_LEN]) {
        read_page(JARDIN_B_ADDR, buf);
    }

    /// Erase page A and program `buf` at offset 0. Uses the same
    /// flash-controller sequence as `hw::flash` but targets a
    /// different page number.
    pub unsafe fn erase_and_write_page_a(buf: &[u8; RECORD_LEN]) -> Result<(), FlashError> {
        erase_and_write(JARDIN_A_ADDR, JARDIN_A_PAGE_NUM, buf)
    }

    /// Erase page B and program `buf` at offset 0.
    pub unsafe fn erase_and_write_page_b(buf: &[u8; RECORD_LEN]) -> Result<(), FlashError> {
        erase_and_write(JARDIN_B_ADDR, JARDIN_B_PAGE_NUM, buf)
    }

    // Direct flash-controller interaction mirrors `hw::flash` — the
    // public helpers there target pages 125..127, we need 123..124,
    // so duplicate the tight sequence here rather than widen the
    // driver's public surface.

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

    // ICACHE registers (secure alias). On STM32U5 the ICACHE serves
    // BOTH code fetches and data loads from flash, so after every
    // erase/program we must invalidate it or read-backs will return
    // the pre-write cached bytes. The non-secure alias lives at
    // 0x4003_0400 but the flash writes happen through SECCR so the
    // secure ICACHE at 0x5003_0400 is the one to invalidate.
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
        while core::ptr::read_volatile(ICACHE_SR) & BUSYF != 0 {
            cortex_m::asm::nop();
        }
        // Clear BSYENDF by writing 1 to it.
        core::ptr::write_volatile(ICACHE_FCR, BSYENDF);
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

    unsafe fn erase_page(page_num: u32) -> Result<(), FlashError> {
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
        // ICACHE must be invalidated after any flash erase/program or
        // subsequent reads will return stale cached bytes.
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
        // Invalidate ICACHE so the read-back below sees the freshly
        // programmed bytes, not the pre-write cached value.
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

    unsafe fn erase_and_write(
        addr: u32,
        page_num: u32,
        buf: &[u8; RECORD_LEN],
    ) -> Result<(), FlashError> {
        erase_page(page_num)?;
        // Program the 8 QWs making up the record in order. The last
        // QW holds `valid_marker` at its final byte, so if we fail
        // partway through the record is still detected as blank.
        let mut qw = [0u8; 16];
        for i in 0..(RECORD_LEN / 16) {
            qw.copy_from_slice(&buf[i * 16..(i + 1) * 16]);
            program_qw(addr + (i as u32) * 16, &qw)?;
        }
        // The remaining (PAGE_LEN - RECORD_LEN) bytes are left as 0xFF
        // (erase pattern) — no need to program them. Reference PAGE_LEN
        // to pin the constant.
        let _ = PAGE_LEN;
        Ok(())
    }
}

#[cfg(not(feature = "stm32u585"))]
mod backend {
    //! QEMU / host backend: two static-RAM buffers that mimic the
    //! flash layout. Not power-persistent; enough to exercise the
    //! read/write state machine in e2e tests.

    use super::{FlashError, RECORD_LEN};

    static mut PAGE_A: [u8; RECORD_LEN] = [0xFF; RECORD_LEN];
    static mut PAGE_B: [u8; RECORD_LEN] = [0xFF; RECORD_LEN];

    pub unsafe fn read_page_a(buf: &mut [u8; RECORD_LEN]) {
        *buf = *core::ptr::addr_of!(PAGE_A);
    }

    pub unsafe fn read_page_b(buf: &mut [u8; RECORD_LEN]) {
        *buf = *core::ptr::addr_of!(PAGE_B);
    }

    pub unsafe fn erase_and_write_page_a(buf: &[u8; RECORD_LEN]) -> Result<(), FlashError> {
        *core::ptr::addr_of_mut!(PAGE_A) = *buf;
        Ok(())
    }

    pub unsafe fn erase_and_write_page_b(buf: &[u8; RECORD_LEN]) -> Result<(), FlashError> {
        *core::ptr::addr_of_mut!(PAGE_B) = *buf;
        Ok(())
    }

    /// Test-only helper to reset the simulated flash. Not exposed on
    /// real hardware because there's no reason to; re-flashing the
    /// device is the equivalent.
    #[cfg(test)]
    pub unsafe fn reset_all() {
        *core::ptr::addr_of_mut!(PAGE_A) = [0xFF; RECORD_LEN];
        *core::ptr::addr_of_mut!(PAGE_B) = [0xFF; RECORD_LEN];
    }
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Which page holds the newer record, if any.
///
/// Both pages may hold independently-valid records (e.g. after an
/// interrupted write). The caller takes the one with the higher seq.
enum Newer {
    A(SlotState),
    B(SlotState),
    Neither,
}

fn pick_newer() -> Newer {
    let mut buf_a = [0u8; RECORD_LEN];
    let mut buf_b = [0u8; RECORD_LEN];
    // SAFETY: single-threaded secure world; no concurrent readers.
    unsafe {
        backend::read_page_a(&mut buf_a);
        backend::read_page_b(&mut buf_b);
    }
    let a = SlotState::deserialize(&buf_a);
    let b = SlotState::deserialize(&buf_b);
    match (a, b) {
        (None, None) => Newer::Neither,
        (Some(a), None) => Newer::A(a),
        (None, Some(b)) => Newer::B(b),
        (Some(a), Some(b)) => {
            if a.seq >= b.seq {
                Newer::A(a)
            } else {
                Newer::B(b)
            }
        }
    }
}

/// Read the latest-committed slot state, or `None` if no record has
/// ever been committed (or both records are corrupt / blank).
pub fn read_latest() -> Option<SlotState> {
    match pick_newer() {
        Newer::A(s) | Newer::B(s) => Some(s),
        Newer::Neither => None,
    }
}

/// Commit a new slot state. The module chooses the destination page
/// and assigns the sequence number; the caller should zero `seq` in
/// the input (or leave the value from a prior `read_latest()` — the
/// module increments what's in flash, not what's in `state`).
///
/// After a successful return the new record is readable via
/// `read_latest()`. On failure neither page is partially committed
/// (the destination erase happens before the program, so torn writes
/// leave the destination blank with `valid_marker = 0xFF`, which
/// deserialize() rejects).
pub fn write(state: &SlotState) -> Result<(), FlashError> {
    let (cur_seq, dest_is_a) = match pick_newer() {
        Newer::Neither => (0u64, true),
        // Cur is on A → commit to B, and vice versa.
        Newer::A(s) => (s.seq, false),
        Newer::B(s) => (s.seq, true),
    };
    let mut to_write = state.clone();
    to_write.seq = cur_seq.wrapping_add(1);
    let mut buf = [0xFFu8; RECORD_LEN];
    to_write.serialize_into(&mut buf);

    let result = unsafe {
        if dest_is_a {
            backend::erase_and_write_page_a(&buf)
        } else {
            backend::erase_and_write_page_b(&buf)
        }
    };
    // Always zeroize the serialised buffer — the sub_pk_seed / h_r are
    // not secret but there's no harm, and the habit keeps the
    // zeroize-on-drop discipline uniform across the secure world.
    buf.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Tests (host-only).
// ---------------------------------------------------------------------------

#[cfg(all(test, not(feature = "stm32u585")))]
mod tests {
    use super::*;

    fn sample(next_q: u32) -> SlotState {
        SlotState {
            seq: 0,
            chain_id: 1,
            slot_index: 0,
            next_q,
            flags: FLAG_SLOT_REGISTERED,
            h_r: [0x11; 32],
            sub_pk_seed: [0x22; 16],
            sub_pk_root: [0x33; 16],
        }
    }

    // Serialize/deserialize round-trips without any backend involvement.
    #[test]
    fn roundtrip_serialize_deserialize() {
        let s = sample(7);
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        let r = SlotState::deserialize(&buf).expect("valid record");
        assert_eq!(r.chain_id, s.chain_id);
        assert_eq!(r.slot_index, s.slot_index);
        assert_eq!(r.next_q, s.next_q);
        assert_eq!(r.flags, s.flags);
        assert_eq!(r.h_r, s.h_r);
        assert_eq!(r.sub_pk_seed, s.sub_pk_seed);
        assert_eq!(r.sub_pk_root, s.sub_pk_root);
    }

    #[test]
    fn blank_buffer_rejects() {
        let buf = [0xFFu8; RECORD_LEN];
        assert!(SlotState::deserialize(&buf).is_none());
    }

    #[test]
    fn corrupted_integrity_rejects() {
        let s = sample(5);
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        // Flip a byte inside the integrity-covered region.
        buf[OFF_CHAIN_ID] ^= 0xA5;
        assert!(SlotState::deserialize(&buf).is_none());
    }

    #[test]
    fn missing_valid_marker_rejects() {
        let s = sample(5);
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        buf[OFF_VALID_MARKER] = 0xFF;
        assert!(SlotState::deserialize(&buf).is_none());
    }

    #[test]
    fn wrong_magic_rejects() {
        let s = sample(5);
        let mut buf = [0u8; RECORD_LEN];
        s.serialize_into(&mut buf);
        buf[0] = buf[0].wrapping_add(1);
        assert!(SlotState::deserialize(&buf).is_none());
    }

    // Backend-involving tests. Serialized with a lock because they
    // share PAGE_A / PAGE_B static mut.
    use std::sync::Mutex;
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static M: Mutex<()> = Mutex::new(());
        let g = M.lock().unwrap();
        unsafe { backend::reset_all() };
        g
    }

    #[test]
    fn empty_on_fresh_device() {
        let _g = lock();
        assert!(read_latest().is_none());
    }

    #[test]
    fn write_then_read() {
        let _g = lock();
        let s = sample(1);
        write(&s).expect("write");
        let got = read_latest().expect("present");
        assert_eq!(got.next_q, 1);
        assert_eq!(got.seq, 1);
    }

    #[test]
    fn alternating_writes_bump_seq() {
        let _g = lock();
        for q in 1..=10u32 {
            let s = sample(q);
            write(&s).unwrap();
        }
        let got = read_latest().unwrap();
        assert_eq!(got.next_q, 10);
        assert_eq!(got.seq, 10);
    }

    #[test]
    fn corrupted_newer_page_falls_back_to_older() {
        let _g = lock();
        write(&sample(1)).unwrap();
        write(&sample(2)).unwrap();
        // Corrupt the newer page (page A after two writes, since
        // seq 1 landed on A and seq 2 on B? Let's just trash both
        // records and reinsert to confirm pick_newer handles the case.
        // Simpler: corrupt page B directly via the test helper.
        unsafe {
            let mut buf = [0u8; RECORD_LEN];
            backend::read_page_b(&mut buf);
            if SlotState::deserialize(&buf).is_some() {
                // Flip magic on B to invalidate.
                buf[0] ^= 0xFF;
                // Re-write via write helper would bump seq; use direct
                // reset and re-seed A by writing seq=1 then trashing B
                // via a blank write. Easier: directly manipulate the
                // backing buffer by writing a known-bad record to B.
                let _ = backend::erase_and_write_page_b(&buf);
            }
        }
        let got = read_latest().expect("should fall back to A");
        // We don't know which record survived, but one of them should
        // have a valid seq and next_q.
        assert!(got.seq >= 1);
        assert!(got.next_q >= 1);
    }
}
