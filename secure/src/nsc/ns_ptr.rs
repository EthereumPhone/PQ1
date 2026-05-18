//! Typestate wrapper for non-secure pointers.
//!
//! Phase 10 PR B of the modularity refactor.
//!
//! Every gateway command receives raw `u32` pointers from non-secure
//! world. Today's call sites validate them via free functions
//! ([`super::ptr_validate::validate_ns_read_ptr`] /
//! [`super::ptr_validate::validate_ns_write_ptr`]) that return `bool`;
//! a forgotten check or a dereference *before* the check are silent
//! footguns the type system can't catch.
//!
//! `NsPtr<T>` makes "validated" a type, not a discipline. The lifecycle
//! is:
//!
//! ```text
//!     NsPtr<T>           // raw u32 + phantom T, NOT yet validated
//!         │ validate_read(len)? / validate_write(len)?
//!         ▼
//!     ReadPtr<T> | WritePtr<T>   // proven NS, only thing with `as_slice` /
//!                                // `as_mut_slice` accessors
//! ```
//!
//! Forgetting to call one of `validate_*` becomes a type error: there
//! is no way to obtain a `ReadPtr<T>` / `WritePtr<T>` without going
//! through the validation step.
//!
//! ## Adoption
//!
//! Migration of every `cmd_*.rs` to thread `NsPtr<T>` end-to-end is
//! sequenced under Phase 7 of the modularity refactor (per
//! `docs/handoff-modularity-refactor.md` §4.6 PR B). Until that lands,
//! new code SHOULD use these types; existing call sites can adopt them
//! incrementally without breaking the legacy `validate_ns_*_ptr(u32,
//! usize)` API.

#![allow(dead_code)]

use core::marker::PhantomData;
use sphincs_tz_shared::NscStatus;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};

/// A raw NS-side pointer that has been *not yet* validated. The
/// `T` parameter records the eventual referent type the caller will
/// produce after `validate_read` / `validate_write` succeeds.
#[derive(Copy, Clone)]
pub struct NsPtr<T> {
    pub(crate) addr: u32,
    _phantom: PhantomData<T>,
}

impl<T> NsPtr<T> {
    /// Wrap a raw `u32` from a gateway argument. `addr == 0` is
    /// allowed at construction; validation refuses it.
    #[inline]
    pub const fn new(addr: u32) -> Self {
        Self {
            addr,
            _phantom: PhantomData,
        }
    }

    #[inline]
    pub fn raw(&self) -> u32 {
        self.addr
    }

    /// Verify that `addr..addr+len` is a fully-NS readable range and
    /// return a `ReadPtr<T>` proof. On failure, returns
    /// [`NscStatus::InvalidPointer`].
    ///
    /// F-8 hardening (TrustZone-boundary FI): the underlying predicate
    /// `validate_ns_read_ptr` is called TWICE through
    /// `fi::check_true_into_sentinel`, with `wait_random()` between, and
    /// each sentinel verdict is checked independently before constructing
    /// the `ReadPtr<T>`. A single fault that flips one verdict still leaves
    /// the second to reject the bad pointer — two coordinated faults
    /// required to bypass. See `tools/sca/README.md` §F-8 for the sweep
    /// evidence this defends against.
    #[inline]
    pub fn validate_read(self, len: usize) -> Result<ReadPtr<T>, NscStatus> {
        // First sentinel-encoded validation.
        let v1 = crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(self.addr, len));
        if v1 != crate::fi::OK_SENTINEL {
            return Err(NscStatus::InvalidPointer);
        }
        crate::fi::wait_random();
        // Second, independent sentinel-encoded validation.
        let v2 = crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(self.addr, len));
        if v2 != crate::fi::OK_SENTINEL {
            return Err(NscStatus::InvalidPointer);
        }
        Ok(ReadPtr {
            addr: self.addr,
            len,
            _phantom: PhantomData,
        })
    }

    /// Verify that `addr..addr+len` is a fully-NS writable range and
    /// return a `WritePtr<T>` proof. On failure, returns
    /// [`NscStatus::InvalidPointer`].
    ///
    /// F-8 hardening — identical pattern to `validate_read`.
    #[inline]
    pub fn validate_write(self, len: usize) -> Result<WritePtr<T>, NscStatus> {
        let v1 = crate::fi::check_true_into_sentinel(|| validate_ns_write_ptr(self.addr, len));
        if v1 != crate::fi::OK_SENTINEL {
            return Err(NscStatus::InvalidPointer);
        }
        crate::fi::wait_random();
        let v2 = crate::fi::check_true_into_sentinel(|| validate_ns_write_ptr(self.addr, len));
        if v2 != crate::fi::OK_SENTINEL {
            return Err(NscStatus::InvalidPointer);
        }
        Ok(WritePtr {
            addr: self.addr,
            len,
            _phantom: PhantomData,
        })
    }
}

/// A pointer whose target range has been proven NS-readable. The only
/// way to construct one is via [`NsPtr::validate_read`] — so a value
/// of this type is proof, not just intent, that the validation gate
/// has fired.
pub struct ReadPtr<T> {
    addr: u32,
    len: usize,
    _phantom: PhantomData<T>,
}

impl<T> ReadPtr<T> {
    #[inline]
    pub fn raw(&self) -> u32 {
        self.addr
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read the entire validated range into `dst`. `dst.len()` MUST
    /// equal `self.len()`. Reads are `core::ptr::read_volatile` so the
    /// compiler can't elide them as redundant — the TOCTOU snapshot
    /// pattern in `cmd_sign_userop` depends on this guarantee.
    pub fn read_into_slice(&self, dst: &mut [u8]) {
        assert_eq!(dst.len(), self.len);
        // SAFETY: category 2 — NS pointer deref. `ReadPtr<T>` was
        // constructed by `NsPtr::validate_read`, whose F-8-hardened
        // two-pass `validate_ns_read_ptr` proved the entire
        // `[self.addr, self.addr + self.len)` range is fully
        // NS-classified (constant window + ARMv8-M `tt`) and does
        // not overlap the shared mailbox. The SAU classification
        // cannot change underfoot for the duration of this call
        // because the secure world holds the gateway lock (non-
        // reentrant dispatcher) and NS cannot reprogram the SAU.
        // `read_volatile` byte-by-byte realises the TOCTOU snapshot
        // — the compiler is forbidden from eliding or batching the
        // reads, so a hostile NS cannot present different bytes to
        // the validator vs. the consumer.
        unsafe {
            let src = self.addr as *const u8;
            for i in 0..self.len {
                dst[i] = core::ptr::read_volatile(src.add(i));
            }
        }
    }

    /// View the validated range as a `&[u8]`. Caller must ensure the
    /// NS region is not concurrently mutated for the lifetime of the
    /// returned reference (today the gateway is single-threaded so
    /// this is trivially true; the snapshot pattern in
    /// `cmd_sign_userop` makes the explicit copy anyway).
    ///
    /// # Safety
    /// The borrow checker cannot see writes from the NS world; the
    /// caller is responsible for the no-concurrent-mutation invariant.
    #[inline]
    pub unsafe fn as_slice<'a>(&self) -> &'a [u8] {
        // SAFETY: category 2 — NS pointer deref backed by the typestate
        // proof. `ReadPtr<T>` can only be obtained via `NsPtr::validate_read`
        // (private constructor), which calls
        // `validate_ns_read_ptr(addr, len)` TWICE with `wait_random()`
        // between, gated by hamming-distant sentinels. That predicate
        // proved the entire `[addr, addr+len)` range is fully
        // NS-classified by the SAU (constant-window check + ARMv8-M
        // `tt` per-block) and doesn't overlap the shared mailbox.
        // The caller of `as_slice` carries the additional contract,
        // documented in `# Safety` above, that NS will not mutate the
        // range for the returned lifetime — single-threaded gateway
        // makes this trivially true for the duration of one handler.
        unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.len) }
    }
}

/// A pointer whose target range has been proven NS-writable. Symmetric
/// to [`ReadPtr<T>`] but with an additional `write_from_slice` helper.
pub struct WritePtr<T> {
    addr: u32,
    len: usize,
    _phantom: PhantomData<T>,
}

impl<T> WritePtr<T> {
    #[inline]
    pub fn raw(&self) -> u32 {
        self.addr
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Volatile-write the supplied slice into the validated NS range.
    /// `src.len()` MUST equal `self.len()`.
    pub fn write_from_slice(&self, src: &[u8]) {
        assert_eq!(src.len(), self.len);
        // SAFETY: category 2 — NS pointer deref. `WritePtr<T>` was
        // constructed by `NsPtr::validate_write`, whose F-8-hardened
        // two-pass `validate_ns_write_ptr` proved the entire
        // `[self.addr, self.addr + self.len)` range is fully
        // NS-classified, NS-writable (NS-SRAM, not NS-flash), and
        // does not overlap the shared mailbox. `write_volatile` per
        // byte forces the compiler to emit one store per source byte
        // — NS observers cannot see torn / partial words mid-copy.
        unsafe {
            let dst = self.addr as *mut u8;
            for (i, &b) in src.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), b);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
    use sphincs_tz_shared::{
        NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, SHARED_MAILBOX_BASE,
        SHARED_MAILBOX_END,
    };

    // ----------------------------------------------------------------
    // NsPtr / ReadPtr / WritePtr typestate — positive coverage
    // ----------------------------------------------------------------

    /// `NsPtr::new` does not validate by itself.
    #[test]
    fn positive_ns_ptr_new_is_no_op() {
        let p: NsPtr<u8> = NsPtr::new(0xDEAD_BEEF);
        assert_eq!(p.raw(), 0xDEAD_BEEF);
    }

    /// `NsPtr::new(0)` returns a struct (does not panic). Validation
    /// rejects it; construction alone must remain pure.
    #[test]
    fn positive_ns_ptr_new_accepts_zero_addr() {
        let p: NsPtr<u8> = NsPtr::new(0);
        assert_eq!(p.raw(), 0);
    }

    /// A clean NS-SRAM read pointer survives validation and exposes
    /// the address + length unchanged.
    #[test]
    fn positive_validate_read_ns_sram_passthrough() {
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE);
        let rp = p.validate_read(64).expect("legit NS-SRAM read must validate");
        assert_eq!(rp.raw(), NS_SRAM_BASE);
        assert_eq!(rp.len(), 64);
        assert!(!rp.is_empty());
    }

    /// A clean NS-flash read pointer is accepted (NS flash is read-only
    /// but still NS-readable, used for static payloads like an unsigned
    /// tx blob).
    #[test]
    fn positive_validate_read_ns_flash_is_accepted() {
        let p: NsPtr<u8> = NsPtr::new(NS_FLASH_BASE);
        let rp = p.validate_read(8).expect("NS flash must be readable");
        assert_eq!(rp.raw(), NS_FLASH_BASE);
        assert_eq!(rp.len(), 8);
    }

    /// A clean NS-SRAM write pointer survives validation.
    #[test]
    fn positive_validate_write_ns_sram_passthrough() {
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE);
        let wp = p.validate_write(64).expect("legit NS-SRAM write must validate");
        assert_eq!(wp.raw(), NS_SRAM_BASE);
        assert_eq!(wp.len(), 64);
        assert!(!wp.is_empty());
    }

    /// Validating right up to the boundary (`end == NS_SRAM_END`)
    /// must be accepted — the bound check is `end <= NS_SRAM_END`.
    #[test]
    fn positive_validate_read_inclusive_upper_boundary() {
        let ptr = NS_SRAM_END - 8;
        let p: NsPtr<u8> = NsPtr::new(ptr);
        assert!(p.validate_read(8).is_ok(), "end==NS_SRAM_END must be accepted");
    }

    /// `is_empty` follows length semantics.
    #[test]
    fn positive_zero_length_read_inside_region_is_accepted() {
        // Zero-length, base inside the region — the bound check
        // `end <= NS_SRAM_END` and `ptr >= NS_SRAM_BASE` both hold,
        // and a zero-length range cannot overlap the mailbox.
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE);
        let rp = p.validate_read(0).expect("zero-length at base must validate");
        assert!(rp.is_empty());
        assert_eq!(rp.len(), 0);
    }

    /// Address exactly past the mailbox is accepted — the overlap
    /// predicate is strictly `ptr < SHARED_MAILBOX_END`, so a pointer
    /// at SHARED_MAILBOX_END passes through.
    #[test]
    fn positive_address_exactly_past_mailbox_is_accepted() {
        let p: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_END);
        assert!(
            p.validate_read(4).is_ok(),
            "SHARED_MAILBOX_END boundary is not an overlap by the < check"
        );
    }

    // ----------------------------------------------------------------
    // NsPtr / ReadPtr / WritePtr typestate — negative coverage
    // ----------------------------------------------------------------

    /// `validate_read` / `validate_write` reject zero pointers (mirrors
    /// the legacy free-function behaviour).
    ///
    /// Assumption attacked: production handlers MUST refuse a NS arg
    /// of 0 (the canonical "uninitialised pointer" attacker payload).
    #[test]
    fn negative_validate_rejects_null() {
        let p: NsPtr<u8> = NsPtr::new(0);
        assert_eq!(p.validate_read(8).map(|_| ()), Err(NscStatus::InvalidPointer));
        let q: NsPtr<u8> = NsPtr::new(0);
        assert_eq!(q.validate_write(8).map(|_| ()), Err(NscStatus::InvalidPointer));
    }

    /// Assumption: a NS pointer whose range overflows `u32::MAX` MUST
    /// be rejected. Without the `checked_add` in the validator a
    /// hostile NS could wrap around and end up "validating" a range
    /// that aliases the very low SRAM region (or secure world on
    /// targets without the SAU check).
    #[test]
    fn negative_validate_rejects_arithmetic_overflow() {
        let p: NsPtr<u8> = NsPtr::new(0xFFFF_FFF0);
        assert_eq!(
            p.validate_read(0x20).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "ptr + len overflow MUST be rejected (would alias low memory after wrap)"
        );
        let q: NsPtr<u8> = NsPtr::new(0xFFFF_FFF0);
        assert_eq!(
            q.validate_write(0x20).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "ptr + len overflow MUST be rejected on the write path too"
        );
    }

    /// Assumption: NS flash MUST be refused on the write path — flash
    /// is read-only NS memory; admitting it would let NS trick the
    /// secure world into trying a flash word-write through an MMIO
    /// path that the production secure-flash driver does not gate
    /// against.
    #[test]
    fn negative_validate_write_rejects_ns_flash() {
        let p: NsPtr<u8> = NsPtr::new(NS_FLASH_BASE);
        assert_eq!(
            p.validate_write(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "NS flash is read-only — validate_write MUST refuse it"
        );
    }

    /// Assumption: a pointer one byte below `NS_SRAM_BASE` is NOT
    /// inside any NS region and MUST be refused.
    #[test]
    fn negative_validate_rejects_just_below_ns_sram_base() {
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE - 1);
        assert_eq!(
            p.validate_read(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
        let q: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE - 1);
        assert_eq!(
            q.validate_write(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
    }

    /// Assumption: a range that runs past `NS_SRAM_END` MUST be
    /// refused even if it starts inside NS SRAM (cross-region access).
    #[test]
    fn negative_validate_rejects_range_running_past_ns_sram_end() {
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_END - 4);
        assert_eq!(
            p.validate_read(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "range that crosses end-of-region boundary MUST be refused"
        );
    }

    /// Assumption: a pointer exactly at `NS_SRAM_END` (i.e. one byte
    /// past the last valid byte) cannot validate any nonzero range.
    #[test]
    fn negative_validate_rejects_addr_at_ns_sram_end_with_nonzero_len() {
        let p: NsPtr<u8> = NsPtr::new(NS_SRAM_END);
        assert_eq!(
            p.validate_read(1).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
    }

    /// Assumption: every byte of the shared-memory mailbox is OFF-
    /// LIMITS to gateway-supplied NS pointers. Otherwise a hostile NS
    /// could ask the secure world to overwrite the very mailbox word
    /// it is dispatching on, racing the validator (TOCTOU on the
    /// command itself).
    #[test]
    fn negative_validate_read_rejects_mailbox_base_overlap() {
        let p: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_BASE);
        assert_eq!(
            p.validate_read(4).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "mailbox-base address MUST be refused (CMD slot overwrite)"
        );
    }

    /// Assumption: a range that straddles the mailbox start is just
    /// as dangerous as a range that lands on the mailbox proper.
    #[test]
    fn negative_validate_read_rejects_mailbox_straddle() {
        let p: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_BASE - 4);
        assert_eq!(
            p.validate_read(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
            "straddling SHARED_MAILBOX_BASE MUST be refused"
        );
    }

    /// Assumption: the mailbox is also off-limits on the write path
    /// (the more dangerous one — an actual store could land on
    /// CMD/ARG0/RESULT).
    #[test]
    fn negative_validate_write_rejects_mailbox_overlap() {
        let p: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_BASE);
        assert_eq!(
            p.validate_write(4).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
        let q: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_BASE - 4);
        assert_eq!(
            q.validate_write(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
    }

    /// Assumption: the mailbox-overlap window is exactly
    /// `[BASE, END)`. The last byte of the mailbox (END-1) MUST be
    /// rejected.
    #[test]
    fn negative_validate_read_rejects_mailbox_last_byte() {
        let p: NsPtr<u8> = NsPtr::new(SHARED_MAILBOX_END - 1);
        assert_eq!(
            p.validate_read(1).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
    }

    /// Assumption: a NS pointer that lands in an unmapped gap
    /// between known NS regions (i.e. above NS flash but below NS
    /// SRAM on the QEMU layout) MUST be refused — the validator
    /// must not accidentally accept any non-region address.
    #[test]
    fn negative_validate_read_rejects_unmapped_gap() {
        // Pick something between the QEMU NS_FLASH_END (0x0040_0000)
        // and NS_SRAM_BASE (0x2802_0000) — e.g. 0x1000_0000.
        let gap_addr: u32 = 0x1000_0000;
        assert!(gap_addr > NS_FLASH_END);
        assert!(gap_addr < NS_SRAM_BASE);
        let p: NsPtr<u8> = NsPtr::new(gap_addr);
        assert_eq!(
            p.validate_read(8).map(|_| ()),
            Err(NscStatus::InvalidPointer),
        );
    }

    /// Assumption: returned error is exactly `InvalidPointer`, not
    /// `InternalError` or another bucket — the companion app routes
    /// off this enum variant.
    #[test]
    fn negative_validate_error_variant_is_invalid_pointer() {
        let p: NsPtr<u8> = NsPtr::new(0);
        let e = match p.validate_read(8) {
            Ok(_) => panic!("validate_read(NULL) must fail"),
            Err(e) => e,
        };
        assert_eq!(e as u32, NscStatus::InvalidPointer as u32);
        assert_eq!(NscStatus::InvalidPointer as u32, 4,
            "NscStatus::InvalidPointer wire value MUST stay 4 (companion ABI)");
    }

    // ----------------------------------------------------------------
    // Raw validate_ns_read_ptr / validate_ns_write_ptr — exhaustive
    // coverage of the underlying predicate (re-used by the typestate
    // wrapper).
    // ----------------------------------------------------------------

    #[test]
    fn positive_raw_validate_read_accepts_ns_sram_and_flash() {
        assert!(validate_ns_read_ptr(NS_SRAM_BASE, 8));
        assert!(validate_ns_read_ptr(NS_FLASH_BASE, 8));
        assert!(validate_ns_read_ptr(NS_FLASH_END - 8, 8));
    }

    #[test]
    fn positive_raw_validate_write_accepts_ns_sram_only() {
        assert!(validate_ns_write_ptr(NS_SRAM_BASE, 8));
        assert!(!validate_ns_write_ptr(NS_FLASH_BASE, 8),
            "flash MUST NOT be writable");
    }

    #[test]
    fn negative_raw_validate_zero_len_at_zero_ptr_still_refused() {
        // The ptr==0 short-circuit fires regardless of len.
        assert!(!validate_ns_read_ptr(0, 0));
        assert!(!validate_ns_write_ptr(0, 0));
    }

    /// Assumption: passing a `usize` length larger than `u32::MAX`
    /// must NOT be quietly accepted via truncation. If the validator
    /// accepts it, the caller (which speaks `usize`) believes a
    /// multi-gigabyte range is NS-valid even though the firmware
    /// only checked the truncated low 32 bits.
    ///
    /// On 32-bit ARM targets (the production target) `usize == u32`
    /// so this is not reachable in practice — but a host build is
    /// 64-bit and the trunc-cast is a real footgun.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn negative_raw_validate_rejects_oversized_usize_len() {
        // 0x1_0000_0000 truncates to 0 — would otherwise look like a
        // zero-length range starting in NS SRAM and pass.
        let huge: usize = (u32::MAX as usize) + 1;
        let truncated_accepts = validate_ns_read_ptr(NS_SRAM_BASE, huge);
        assert!(
            !truncated_accepts,
            "validator MUST refuse usize > u32::MAX rather than truncate; \
             current behaviour silently truncates the length on 64-bit hosts \
             (irrelevant on 32-bit ARM target_usize but a documented gap)"
        );
    }
}
