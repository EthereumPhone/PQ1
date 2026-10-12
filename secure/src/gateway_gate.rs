//! One-at-a-time gate for the non-secure → secure gateway (#846).
//!
//! # Why this exists
//!
//! A gateway handler runs in secure *thread* mode on behalf of the
//! non-secure (NS) caller. Thread mode can be preempted by any exception,
//! and the NS world owns banked exceptions of its own (`SysTick_NS`,
//! `PendSV_NS`) that `AIRCR.PRIS` only de-prioritises against secure
//! *exceptions*, not against secure thread mode. An NS exception handler
//! can therefore run while a handler is parked in a confirm dialog and
//! call a second gateway entry. Before this gate nothing refused that
//! second call, and the handlers share `static mut` state
//! (`SIGN_SNAP_BUF`, `SLOT_CACHE`, the SE driver, `FW_UPDATE`): a nested
//! sign call could replace the calldata of the outer one after the user
//! had confirmed it.
//!
//! The gate makes "at most one gateway call in flight" a checked property
//! instead of an assumption: every `cmse-nonsecure-entry` function takes
//! the token as its first statement and returns a refusal when it is
//! already held. The stock NS image installs no exception handlers and
//! calls the gateway from its poll loop only, so it never sees a refusal.
//!
//! # What it is not
//!
//! * Not the idle-wipe guard. `nsc::HandlerGuard` / `HANDLER_DEPTH` keep
//!   their own meaning (a *long-running* handler holds stack copies of
//!   secrets, so SysTick must not wipe under it). Widening that guard to
//!   every gateway call would let NS starve the idle wipe by hammering a
//!   cheap entry.
//! * Not fault-injection proof on its own. One skipped branch here lets a
//!   nested call through, which is why the single-sign handler also binds
//!   the calldata it signs to the calldata it showed. That backstop covers
//!   the calldata only: under `ui-px` the pixel screen transcript shares
//!   `SIGN_SNAP_BUF` and nothing but this gate protects it.
//! * Not exclusion between a gateway call and SECURE exceptions. SysTick's
//!   idle wipe and the PendSV re-unlock dialog can still interleave with a
//!   short handler that holds no `HandlerGuard` (#152).
//!
//! Lives outside `nsc/` (which is `#[cfg(not(test))]`) so the unit tests
//! below actually run on the host.

use core::sync::atomic::{AtomicU32, Ordering};

/// Codeword for "no gateway call in flight". Any other value, including
/// the all-zero pattern of uninitialised or wiped RAM, reads as held, so
/// a corrupted gate refuses every call instead of admitting two.
pub(crate) const GATE_FREE: u32 = 0x3C5A_96A5;
/// Codeword for "a gateway call is in flight" (bitwise complement of
/// [`GATE_FREE`], Hamming distance 32).
pub(crate) const GATE_HELD: u32 = !GATE_FREE;

/// The gate itself. One static instance lives in `nsc`.
pub(crate) struct GatewayGate(AtomicU32);

/// Proof that the holder is the only gateway call in flight. Dropping it
/// reopens the gate, so every return path of an entry function releases.
#[must_use = "the gate reopens as soon as the token is dropped"]
pub(crate) struct GateToken<'a>(&'a GatewayGate);

impl GatewayGate {
    pub(crate) const fn new() -> Self {
        Self(AtomicU32::new(GATE_FREE))
    }

    /// Take the gate if it is free. A single atomic compare-and-swap, so
    /// two entries racing each other cannot both succeed.
    #[inline]
    pub(crate) fn try_enter(&self) -> Option<GateToken<'_>> {
        match self
            .0
            .compare_exchange(GATE_FREE, GATE_HELD, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => Some(GateToken(self)),
            Err(_) => None,
        }
    }
}

impl Drop for GateToken<'_> {
    #[inline]
    fn drop(&mut self) {
        self.0 .0.store(GATE_FREE, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_entry_is_admitted() {
        let gate = GatewayGate::new();
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn nested_entry_is_refused_while_the_token_lives() {
        let gate = GatewayGate::new();
        let outer = gate.try_enter();
        assert!(outer.is_some());
        // The nested call: refused, and it must not disturb the outer hold.
        assert!(gate.try_enter().is_none());
        assert!(gate.try_enter().is_none());
        assert_eq!(gate.0.load(Ordering::SeqCst), GATE_HELD);
        drop(outer);
    }

    #[test]
    fn refused_entry_does_not_release_the_outer_hold() {
        let gate = GatewayGate::new();
        let outer = gate.try_enter().expect("free gate admits");
        {
            // A refused entry yields no token, so nothing is dropped here
            // that could reopen the gate under the outer call.
            let nested = gate.try_enter();
            assert!(nested.is_none());
        }
        assert!(gate.try_enter().is_none(), "outer hold survived the refused entry");
        drop(outer);
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn gate_reopens_on_drop_and_on_early_return() {
        fn handler(gate: &GatewayGate, bail: bool) -> u32 {
            let Some(_token) = gate.try_enter() else { return 99 };
            if bail {
                return 1;
            }
            0
        }
        let gate = GatewayGate::new();
        assert_eq!(handler(&gate, true), 1);
        assert_eq!(handler(&gate, false), 0);
        assert_eq!(handler(&gate, true), 1);
        assert_eq!(gate.0.load(Ordering::SeqCst), GATE_FREE);
    }

    #[test]
    fn a_corrupted_gate_refuses_instead_of_admitting() {
        for bad in [0u32, 1, 0xFFFF_FFFF, GATE_FREE ^ 1, GATE_HELD ^ 0x8000_0000] {
            let gate = GatewayGate(AtomicU32::new(bad));
            assert!(gate.try_enter().is_none(), "state {bad:#010x} must read as held");
        }
    }

    #[test]
    fn codewords_are_complements() {
        assert_eq!(GATE_FREE ^ GATE_HELD, u32::MAX);
        assert_ne!(GATE_FREE, 0);
        assert_ne!(GATE_HELD, 0);
    }
}
