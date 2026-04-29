//! Feature-agnostic facade over per-slot off-chain sig counter storage.
//!
//! On real STM32U585 hardware (`stm32u585` or `pka-accel` feature
//! present, where `crate::hw::flash` is available) every call routes
//! into the flash-backed log-structured store on bank-1 page 123 — the
//! durable, power-loss-tolerant implementation. On QEMU and other host
//! / non-flash builds the calls go to a SRAM-backed mock that lives in
//! a single static, zeroised on power cycle. The mock has the same
//! externally visible semantics (monotonic counters, slot registration,
//! gap enforcement) so the gateway commands and tests do not need to
//! know which backend is active.
//!
//! Why a facade and not a direct cfg-flag inside `hw::flash`? The `hw`
//! module itself is feature-gated (`#[cfg(any(stm32u585, pka-accel))]`),
//! so `crate::hw::flash` simply does not exist on a default QEMU build.
//! Touching `crate::hw::*` directly from `crate::nsc::cmd_sign_*` would
//! force every QEMU build to also enable an unrelated hardware
//! feature. Routing through this thin shim keeps the gateway path
//! buildable on every config the project supports.

/// Compute the 8-byte flash key for a `(account_index, chain_id, slot_index)`
/// tuple.
pub fn slot_key_compute(account_index: u8, chain_id: u64, slot_index: u32) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([account_index]);
    h.update(chain_id.to_be_bytes());
    h.update(slot_index.to_be_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

#[cfg(any(feature = "stm32u585", feature = "pka-accel"))]
mod backend {
    pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
        crate::hw::flash::offchain_count_read(slot_key)
    }
    pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
        crate::hw::flash::last_userop_count_read(slot_key)
    }
    pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
        crate::hw::flash::offchain_count_is_registered(slot_key)
    }
    pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
        crate::hw::flash::offchain_count_register_slot(slot_key)
    }
    pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        crate::hw::flash::offchain_count_bump(slot_key, new_count)
    }
    pub unsafe fn offchain_count_promote_to(
        slot_key: &[u8; 8],
        target: u64,
    ) -> Result<(), ()> {
        crate::hw::flash::offchain_count_promote_to(slot_key, target)
    }
    pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
        crate::hw::flash::last_userop_count_set(slot_key, count)
    }
}

#[cfg(not(any(feature = "stm32u585", feature = "pka-accel")))]
mod backend {
    //! SRAM-backed mock used by QEMU. Storage is a fixed-size table of
    //! `(slot_key, offchain, last_userop, registered)` records. Lost on
    //! power cycle, which exactly mirrors the seed-restore semantics —
    //! a fresh-from-seed firmware has no flash record of any slot, so
    //! `is_registered` returns false until the first `register_slot`
    //! call. Tests that want to simulate a recovery just call
    //! `crate::offchain_state::reset_for_test()`.

    const MAX_SLOTS: usize = 128;

    #[derive(Clone, Copy)]
    struct Entry {
        slot_key: [u8; 8],
        offchain: u64,
        last_userop: u64,
        registered: bool,
        used: bool,
    }

    static mut TABLE: [Entry; MAX_SLOTS] = [Entry {
        slot_key: [0u8; 8],
        offchain: 0,
        last_userop: 0,
        registered: false,
        used: false,
    }; MAX_SLOTS];

    unsafe fn find(slot_key: &[u8; 8]) -> Option<usize> {
        let table = &*core::ptr::addr_of!(TABLE);
        for (i, e) in table.iter().enumerate() {
            if e.used && &e.slot_key == slot_key {
                return Some(i);
            }
        }
        None
    }

    unsafe fn allocate(slot_key: &[u8; 8]) -> Option<usize> {
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        for (i, e) in table.iter_mut().enumerate() {
            if !e.used {
                e.slot_key = *slot_key;
                e.offchain = 0;
                e.last_userop = 0;
                e.registered = false;
                e.used = true;
                return Some(i);
            }
        }
        None
    }

    pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].offchain,
            None => 0,
        }
    }

    pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].last_userop,
            None => 0,
        }
    }

    pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
        match find(slot_key) {
            Some(i) => (*core::ptr::addr_of!(TABLE))[i].registered,
            None => false,
        }
    }

    pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        (*core::ptr::addr_of_mut!(TABLE))[idx].registered = true;
        Ok(())
    }

    pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        if new_count <= table[idx].offchain {
            return Err(());
        }
        table[idx].offchain = new_count;
        Ok(())
    }

    /// Mirror of `flash::offchain_count_promote_to` — set the per-slot
    /// off-chain counter to at least `target`. Idempotent.
    pub unsafe fn offchain_count_promote_to(
        slot_key: &[u8; 8],
        target: u64,
    ) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        if target > table[idx].offchain {
            table[idx].offchain = target;
        }
        Ok(())
    }

    pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
        let idx = match find(slot_key) {
            Some(i) => i,
            None => allocate(slot_key).ok_or(())?,
        };
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        // Tolerant of `count < last_userop`: no-op rather than error,
        // mirroring the flash-backed semantics so a stale caller
        // cannot brick the slot.
        if count > table[idx].last_userop {
            table[idx].last_userop = count;
        }
        Ok(())
    }

    /// Test-only: clear the SRAM mock to simulate a power cycle / seed
    /// restoration. Never compiled into a real firmware — guarded by
    /// `e2e-test`.
    #[cfg(feature = "e2e-test")]
    pub unsafe fn reset_for_test() {
        let table = &mut *core::ptr::addr_of_mut!(TABLE);
        for e in table.iter_mut() {
            *e = Entry {
                slot_key: [0u8; 8],
                offchain: 0,
                last_userop: 0,
                registered: false,
                used: false,
            };
        }
    }
}

pub use backend::*;
