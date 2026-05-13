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
        // SAFETY: `validate_read` proved `self.addr..self.addr+self.len`
        // is fully NS-classified at the time of validation. Volatile
        // reads must come from a non-secure region — the SAU
        // classification holds across this call because the secure
        // world holds the gateway lock.
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
        // SAFETY: validated range, see contract above.
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
        // SAFETY: `validate_write` proved `self.addr..self.addr+self.len`
        // is fully NS-classified and not aliasing the shared mailbox.
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

    /// `NsPtr::new` does not validate by itself.
    #[test]
    fn ns_ptr_new_is_no_op() {
        let p: NsPtr<u8> = NsPtr::new(0xDEAD_BEEF);
        assert_eq!(p.raw(), 0xDEAD_BEEF);
    }

    /// `validate_read` / `validate_write` reject zero pointers (mirrors
    /// the legacy free-function behaviour).
    #[test]
    fn validate_rejects_null() {
        let p: NsPtr<u8> = NsPtr::new(0);
        assert_eq!(p.validate_read(8).map(|_| ()), Err(NscStatus::InvalidPointer));
        let q: NsPtr<u8> = NsPtr::new(0);
        assert_eq!(q.validate_write(8).map(|_| ()), Err(NscStatus::InvalidPointer));
    }
}
