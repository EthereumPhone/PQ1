//! Pure, Kani-verifiable model of the **off-chain per-slot counter policy** —
//! the gate + state machine that `secure/src/nsc/cmd_sign_offchain.rs`,
//! `cmd_sign_userop_batch.rs`, and the page-123 store
//! (`secure/src/offchain_state.rs`) enforce on the shared SPHINCS+ few-time
//! budget.
//!
//! # Why this module exists
//!
//! Invariants #7 (per-chain caps monotonic, unresettable) and #9 (off-chain
//! sig counter + combined cap) are enforced by *arithmetic gates* scattered
//! across the sign gateway, and the durable counter store is a `static mut`
//! log inside `secure/` — neither reachable by `cargo kani` (the firmware
//! crate is `#![no_std]` + hardware-featured and is not a Kani target). The
//! bounded-verification plan
//! (`docs/firmware-bounded-verification-sota-2026-06.md`, line 81 + 215) files
//! *this exact move*: **extract the pure gate seam and Kani it** for
//! fail-closed monotonicity / overflow-freedom. This module is that seam,
//! plus a small owned `SlotLedger` / `OffchainLedger` model so the properties
//! can be proven over **sequences** of adversarially-ordered operations — the
//! reorder / replay / limit-slice discipline that catches the interactions a
//! per-transition test misses (`docs/archive/work-todo-retired-2026-07-19.md` §12e; the methodology is
//! ported from the Strix `business_logic.md` + `race_conditions.md` operator
//! set — model invariants, then attack by sequencing).
//!
//! # The two bricks this defends (both are *sequence* properties)
//!
//! * **Distinct-slot exhaustion** — spray ≥512 distinct `(account,chain,slot)`
//!   tuples via `CMD_OFFCHAIN_SYNC` → the page can no longer compact → every
//!   sign path wedges. Defended by [`may_create_distinct_slot`] /
//!   [`MAX_DISTINCT_SLOTS`]. (`VULN-offchain-sync-page123-exhaustion-brick.md`.)
//! * **Value inflation** — a companion-supplied `target_count ≥ MAX_SLOT_USES`
//!   promoted into the monotonic counter → the combined cap refuses every
//!   future signature. Defended by [`clamp_offchain_count`] /
//!   [`OFFCHAIN_COUNT_CEILING`]. (`VULN-offchain-sync-value-inflation-slot-brick.md`.)
//!
//! # Fidelity chain (read before trusting a green run)
//!
//! `Kani proof → this model`. The model is bound to the shipped code by:
//!   1. the sign gateway (`cmd_sign_offchain`) calling [`check_offchain_gate`]
//!      **in place** (the `decode_flags` precedent — the FI double-read /
//!      `wait_random` / re-check stays in the gateway, the arithmetic is this
//!      kernel), so the primary gate *is* this function;
//!   2. a differential host test
//!      (`secure/src/offchain_ledger_differential_pure_tests.rs`) that drives
//!      identical op-sequences through the real `offchain_state` mock backend
//!      and [`OffchainLedger`] and asserts equal counters.
//!
//! **Out of scope** (stated on purpose — an unstated boundary is a coverage
//! gap): this proves the counter **policy** (gap / combined-cap / ceiling /
//! distinct-slot / monotonicity) over adversarial op-orderings. It does **not**
//! reach the flash **crash-atomicity** of the log-structured page-123 store
//! (torn-compaction rollback lives below this seam in
//! `hw::flash::compact_page`; that HIGH is covered by the `fault_sweep_*.py`
//! single-fault sweeps, not here), nor the `mock == flash-policy` equivalence,
//! which the two backends assert by shared helpers + comments, not proof.

use pqsigner_proto::{MAX_OFFCHAIN_GAP, MAX_SLOT_USES};

/// Hard ceiling on any per-slot off-chain counter a durable write may store —
/// the value-inflation brick defence. `MAX_SLOT_USES - 1` is exactly right: a
/// truthful on-chain `offchainSigCount` can never exceed it (the on-chain
/// combined cap is strict, `< MAX_SLOT_USES`), so the clamp only ever clips a
/// value the chain itself would reject, and always leaves the slot with ≥1
/// usable signature. Mirrors `secure/src/offchain_state.rs::OFFCHAIN_COUNT_CEILING`.
pub const OFFCHAIN_COUNT_CEILING: u64 = MAX_SLOT_USES - 1;

/// Device-lifetime budget on the number of **distinct** slot keys the journal
/// will ever create — the distinct-slot exhaustion brick defence. `128 * 3 QW
/// = 384 ≤ 512` page capacity and `128 ≤ 256` projection-table size, so
/// compaction is un-wedgeable by construction. Mirrors
/// `secure/src/offchain_state.rs::MAX_DISTINCT_SLOTS`.
pub const MAX_DISTINCT_SLOTS: usize = 128;

/// Clamp a companion-/snapshot-supplied off-chain counter to
/// [`OFFCHAIN_COUNT_CEILING`]. Single source of truth for the value-inflation
/// brick defence. Mirrors `offchain_state.rs::clamp_offchain_count`.
#[inline]
#[must_use]
pub const fn clamp_offchain_count(count: u64) -> u64 {
    if count > OFFCHAIN_COUNT_CEILING {
        OFFCHAIN_COUNT_CEILING
    } else {
        count
    }
}

/// May a durable write that would create a **new** distinct slot proceed?
/// `already_present` ⇒ always `true` (an update to a known slot never grows the
/// distinct-slot set). Otherwise allowed only while
/// `distinct_live < MAX_DISTINCT_SLOTS`. Mirrors
/// `offchain_state.rs::may_create_distinct_slot`.
#[inline]
#[must_use]
pub fn may_create_distinct_slot(distinct_live: usize, already_present: bool) -> bool {
    already_present || distinct_live < MAX_DISTINCT_SLOTS
}

/// Outcome of the off-chain sign gate. `Accept { new_count }` carries the
/// counter value the sign path durably stores into the off-chain counter
/// (`executeWithOffchainCount` / `offchain_count` bump); the two rejects map
/// 1:1 to `NscStatus::OffchainGapExceeded` / `OffchainCapExceeded` in the
/// gateway (the gateway owns the status codes; this kernel stays dep-light).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateOutcome {
    /// Sign permitted; store `new_count` as the new off-chain counter.
    Accept {
        /// `max(offchain, last_userop) + 1` — the repair branch folded in.
        new_count: u64,
    },
    /// `local_offchain - last_userop >= MAX_OFFCHAIN_GAP`: publish a UserOp first.
    RejectGap,
    /// Combined few-time budget would be exceeded (or `+1` overflowed u64).
    RejectCap,
}

/// The pure off-chain sign gate — the arithmetic seam extracted verbatim from
/// `secure/src/nsc/cmd_sign_offchain.rs:303-345`, so a green Kani run and the
/// shipped decision are the same code.
///
/// Faithful transcription of, in order:
/// 1. **repair** (`:303-311`) — promote `local_offchain` up to `last_userop`
///    (`effective = max(offchain, last_userop)`);
/// 2. **gap gate** (`:330-334`) — reject when `effective - last_userop >= MAX_OFFCHAIN_GAP`;
/// 3. **new_count** (`:335-338`) — `effective.checked_add(1)`, overflow ⇒ `RejectCap`;
/// 4. **combined cap** (`:342-345`) — reject when
///    `userop_sigs.saturating_add(new_count) > MAX_SLOT_USES`.
///
/// (The gateway's F-10 double-read + `wait_random` + belt-and-braces re-check
/// wrap this call and stay in the gateway; they are FI hardening around the
/// same arithmetic, not part of the policy.)
#[must_use]
pub fn check_offchain_gate(offchain: u64, last_userop: u64, userop_sigs: u64) -> GateOutcome {
    // 1. repair branch (cmd_sign_offchain.rs:303-311)
    let effective = if last_userop > offchain {
        last_userop
    } else {
        offchain
    };
    // 2. gap gate (`:330`). effective >= last_userop, so this never underflows;
    //    saturating_sub mirrors the shipped form exactly.
    let gap = effective.saturating_sub(last_userop);
    if gap >= MAX_OFFCHAIN_GAP {
        return GateOutcome::RejectGap;
    }
    // 3. new_count (`:335`)
    let new_count = match effective.checked_add(1) {
        Some(v) => v,
        None => return GateOutcome::RejectCap,
    };
    // 4. combined cap (`:342`)
    if userop_sigs.saturating_add(new_count) > MAX_SLOT_USES {
        return GateOutcome::RejectCap;
    }
    GateOutcome::Accept { new_count }
}

/// The Type-2 UserOp / batch combined-cap gate — the arithmetic seam from
/// `cmd_sign_userop_batch.rs:1037` (`userop_sigs + offchain >= MAX_SLOT_USES`
/// ⇒ reject). A UserOp/batch produces exactly one Type-2 slot-key signature,
/// consuming one unit of the shared budget. Returns `true` when the sign may
/// proceed. Equivalent to the off-chain gate's cap arm: both enforce
/// `userop_sigs + offchain < MAX_SLOT_USES` on the pre-state.
#[inline]
#[must_use]
pub fn userop_cap_ok(offchain: u64, userop_sigs: u64) -> bool {
    userop_sigs.saturating_add(offchain) < MAX_SLOT_USES
}

/// Effective off-chain high-water mark used by every Type-2 UserOp gate.
///
/// `CMD_OFFCHAIN_SYNC` can raise `last_userop` above the locally materialised
/// `offchain` counter.  The sign handlers promote `offchain` to this floor
/// before release, so the cap decision MUST use the same repaired value.  A
/// gate over bare `offchain` would admit one signature and only then discover
/// that `userop_sigs + max(offchain, last_userop)` was already exhausted.
#[inline]
#[must_use]
pub const fn effective_offchain_count(offchain: u64, last_userop: u64) -> u64 {
    if last_userop > offchain {
        last_userop
    } else {
        offchain
    }
}

/// Type-2 UserOp / batch cap gate after folding in a synced high-water floor.
#[inline]
#[must_use]
pub fn userop_cap_ok_with_floor(offchain: u64, last_userop: u64, userop_sigs: u64) -> bool {
    userop_cap_ok(effective_offchain_count(offchain, last_userop), userop_sigs)
}

/// A floor-raising `CMD_OFFCHAIN_SYNC` that skips more than this many
/// signatures past the device's own count gets the loud warning page.
///
/// An honest sync mirrors the on-chain `offchainSigCount` after a restore or
/// when the same seed is used on a second device, which is normally a small
/// number of message signatures. A large jump is what the slot-exhaustion
/// attack (sweep 2026-10-13 finding #2) needs.
pub const SYNC_WARN_JUMP: u64 = 1_000;

/// A sync that would leave fewer than this many signatures on the slot gets
/// the loud warning page.
pub const SYNC_WARN_LEFT: u64 = 1_000;

/// Signatures (of either kind) the slot still allows after a sync to
/// `target`, as the device sees it:
/// `MAX_SLOT_USES - (userop_sigs + max(offchain, last_userop, clamp(target)))`,
/// saturating at 0. This is exactly the headroom the Type-2 and off-chain
/// gates will compute on the next sign.
#[inline]
#[must_use]
pub const fn sync_left_after(offchain: u64, last_userop: u64, userop_sigs: u64, target: u64) -> u64 {
    let eff = effective_offchain_count(
        effective_offchain_count(offchain, last_userop),
        clamp_offchain_count(target),
    );
    MAX_SLOT_USES.saturating_sub(userop_sigs.saturating_add(eff))
}

/// How far a sync raises the device's effective off-chain count
/// (`clamp(target) - max(offchain, last_userop)`, saturating at 0).
#[inline]
#[must_use]
pub const fn sync_jump(offchain: u64, last_userop: u64, target: u64) -> u64 {
    clamp_offchain_count(target).saturating_sub(effective_offchain_count(offchain, last_userop))
}

/// What the device does with a `CMD_OFFCHAIN_SYNC` request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncVerdict {
    /// The write would leave the slot with no signatures at all: the device
    /// could never sign with it again, so the request has no honest use.
    /// Refused without a dialog and without a write.
    Refuse,
    /// Allowed only after the loud warning page: the jump exceeds
    /// [`SYNC_WARN_JUMP`] or fewer than [`SYNC_WARN_LEFT`] signatures remain.
    Warn,
    /// Ordinary plain-language confirmation.
    Plain,
}

/// The sync policy (owner decision 2026-10-13: refuse + warn). Pure and
/// total; the handler evaluates it twice through the FI sentinel.
#[inline]
#[must_use]
pub const fn sync_verdict(offchain: u64, last_userop: u64, userop_sigs: u64, target: u64) -> SyncVerdict {
    let left = sync_left_after(offchain, last_userop, userop_sigs, target);
    if left == 0 {
        SyncVerdict::Refuse
    } else if sync_jump(offchain, last_userop, target) > SYNC_WARN_JUMP || left < SYNC_WARN_LEFT {
        SyncVerdict::Warn
    } else {
        SyncVerdict::Plain
    }
}

/// One slot's durable counters — a pure mirror of the
/// `offchain_state` backend's per-entry state (`offchain`, `last_userop`,
/// `userop_sigs`, existence==`registered`). The `apply_*` methods reproduce
/// the backend's transition semantics so a sequence of them models a real
/// adversarial op-ordering.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SlotLedger {
    /// Monotonic off-chain sig counter (`offchain_count`).
    pub offchain: u64,
    /// Monotonic floor mirrored from the on-chain `offchainSigCount`
    /// (`last_userop_count`) — a UserOp publishes it, closing the gap.
    pub last_userop: u64,
    /// Monotonic tally of Type-2 UserOp signatures produced for the slot.
    pub userop_sigs: u64,
    /// Journal entry exists (== `is_registered` in the backend).
    pub registered: bool,
}

impl SlotLedger {
    /// Apply one **off-chain sign** (`CMD_SIGN_OFFCHAIN`): run the gate; on
    /// accept, durably store `new_count` into `offchain`. Net effect on accept
    /// is `offchain' = max(offchain, last_userop) + 1` — the repair promotion
    /// **and** the `+1` bump, *not* a bare `offchain + 1` (see gate doc).
    /// A value-write registers the slot (backend allocates on first write).
    pub fn apply_sign_offchain(&mut self) -> GateOutcome {
        let outcome = check_offchain_gate(self.offchain, self.last_userop, self.userop_sigs);
        if let GateOutcome::Accept { new_count } = outcome {
            self.offchain = new_count;
            self.registered = true;
        }
        outcome
    }

    /// Apply `CMD_OFFCHAIN_SYNC`: raise the `last_userop` floor to a
    /// companion-supplied `target`, **clamped** to the ceiling and **tolerant**
    /// of a stale (`< current`) value (no-op, never an error — a stale caller
    /// must not be able to brick the slot). Mirrors
    /// `offchain_state::last_userop_count_set`.
    pub fn apply_offchain_sync(&mut self, target: u64) {
        let clamped = clamp_offchain_count(target);
        if clamped > self.last_userop {
            self.last_userop = clamped;
        }
        self.registered = true;
    }

    /// Apply one **Type-2 UserOp / batch sign**: cap-gated by
    /// [`userop_cap_ok_with_floor`]; on accept first repair `offchain` to the
    /// synced `last_userop` floor, then bump `userop_sigs` and advance
    /// `last_userop` to that effective count. Returns whether the sign
    /// proceeded.
    pub fn apply_sign_userop(&mut self) -> bool {
        let effective = effective_offchain_count(self.offchain, self.last_userop);
        if !userop_cap_ok(effective, self.userop_sigs) {
            return false;
        }
        self.offchain = effective;
        // Monotonic: userop_sigs strictly increases; guarded against u64
        // overflow (unreachable under the cap, but fail-closed anyway).
        self.userop_sigs = self.userop_sigs.saturating_add(1);
        self.last_userop = effective;
        self.registered = true;
        true
    }

    /// Is this slot exhausted (no further signature of either kind possible
    /// within the combined few-time budget)? Used by the no-brick harnesses.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        !userop_cap_ok_with_floor(self.offchain, self.last_userop, self.userop_sigs)
    }
}

/// A tiny fixed-capacity journal used to prove **slot isolation** (invariant
/// #8 — an op on one `(account,chain,slot)` key never perturbs another) and
/// the distinct-slot **allocation** policy over a sequence. Deliberately small
/// (`CAP`) so the Kani harnesses stay tractable; the numeric budget it enforces
/// is [`MAX_DISTINCT_SLOTS`] via [`may_create_distinct_slot`].
#[derive(Clone, Copy)]
pub struct OffchainLedger<const CAP: usize> {
    keys: [u64; CAP],
    slots: [SlotLedger; CAP],
    used: [bool; CAP],
}

impl<const CAP: usize> Default for OffchainLedger<CAP> {
    fn default() -> Self {
        Self {
            keys: [0; CAP],
            slots: [SlotLedger {
                offchain: 0,
                last_userop: 0,
                userop_sigs: 0,
                registered: false,
            }; CAP],
            used: [false; CAP],
        }
    }
}

impl<const CAP: usize> OffchainLedger<CAP> {
    /// Number of distinct live slots.
    #[must_use]
    pub fn distinct_live(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < CAP {
            if self.used[i] {
                n += 1;
            }
            i += 1;
        }
        n
    }

    fn find(&self, key: u64) -> Option<usize> {
        let mut i = 0;
        while i < CAP {
            if self.used[i] && self.keys[i] == key {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Locate `key`, allocating a fresh entry if absent **and** the
    /// distinct-slot cap permits it ([`may_create_distinct_slot`]). Returns
    /// `None` when a new slot is refused (graceful — no existing entry is
    /// touched, so an at-cap spray can never wedge a live slot) or the table is
    /// physically full. This is the chokepoint every durable writer funnels
    /// through in the flash backend.
    fn find_or_alloc(&mut self, key: u64) -> Option<usize> {
        if let Some(i) = self.find(key) {
            return Some(i);
        }
        if !may_create_distinct_slot(self.distinct_live(), false) {
            return None;
        }
        let mut i = 0;
        while i < CAP {
            if !self.used[i] {
                self.used[i] = true;
                self.keys[i] = key;
                self.slots[i] = SlotLedger::default();
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Read a slot's counters (absent ⇒ all-zero, matching the backend).
    #[must_use]
    pub fn get(&self, key: u64) -> SlotLedger {
        match self.find(key) {
            Some(i) => self.slots[i],
            None => SlotLedger::default(),
        }
    }

    /// Off-chain sign addressed to `key`. `Err(())` when a *new* slot is
    /// refused by the distinct-slot cap (graceful brick-avoidance); else the
    /// [`GateOutcome`].
    pub fn sign_offchain(&mut self, key: u64) -> Result<GateOutcome, ()> {
        let i = self.find_or_alloc(key).ok_or(())?;
        Ok(self.slots[i].apply_sign_offchain())
    }

    /// `CMD_OFFCHAIN_SYNC` addressed to `key`. `Err(())` iff a new slot is
    /// refused by the distinct-slot cap.
    pub fn offchain_sync(&mut self, key: u64, target: u64) -> Result<(), ()> {
        let i = self.find_or_alloc(key).ok_or(())?;
        self.slots[i].apply_offchain_sync(target);
        Ok(())
    }

    /// Type-2 UserOp/batch sign addressed to `key`.
    pub fn sign_userop(&mut self, key: u64) -> Result<bool, ()> {
        let i = self.find_or_alloc(key).ok_or(())?;
        Ok(self.slots[i].apply_sign_userop())
    }
}

// ───────────────────────────── host unit tests ─────────────────────────────
// Kani `#[kani::proof]` harnesses do NOT execute under `cargo test`; these host
// tests drive the concrete transitions so a `cargo test -p pqsigner-aa` run
// exercises the model (the "roundtrip/Kani never render → always add a host
// test" lesson, work-todo §12e / memory).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_refuses_a_target_that_exhausts_a_used_slot() {
        // Sweep 2026-10-13 finding #2, device view: 1 Type-2 already signed,
        // companion asks for the clamp ceiling. The write would leave 0.
        assert_eq!(sync_left_after(0, 0, 1, OFFCHAIN_COUNT_CEILING), 0);
        assert_eq!(sync_verdict(0, 0, 1, OFFCHAIN_COUNT_CEILING), SyncVerdict::Refuse);
        assert_eq!(sync_verdict(0, 0, 1, u64::MAX), SyncVerdict::Refuse);
        // One below: one signature left -> allowed, but only with the warning.
        assert_eq!(sync_left_after(0, 0, 1, OFFCHAIN_COUNT_CEILING - 1), 1);
        assert_eq!(sync_verdict(0, 0, 1, OFFCHAIN_COUNT_CEILING - 1), SyncVerdict::Warn);
    }

    #[test]
    fn sync_warns_on_a_big_jump_even_with_plenty_left() {
        // Restored device (all zero) asked to jump 1_001: plenty left, but
        // a jump that large is the attack shape on a used on-chain slot.
        assert_eq!(sync_verdict(0, 0, 0, SYNC_WARN_JUMP + 1), SyncVerdict::Warn);
        assert_eq!(sync_verdict(0, 0, 0, SYNC_WARN_JUMP), SyncVerdict::Plain);
        // The jump is measured from the effective count, not the bare floor.
        assert_eq!(sync_jump(500, 0, 1_400), 900);
        assert_eq!(sync_verdict(500, 0, 0, 1_400), SyncVerdict::Plain);
    }

    #[test]
    fn sync_warns_when_little_is_left() {
        let used = MAX_SLOT_USES - SYNC_WARN_LEFT - 10;
        // Small jump, but the slot is nearly spent.
        assert_eq!(sync_verdict(0, 0, used, 20), SyncVerdict::Warn);
        assert_eq!(sync_verdict(0, 0, used, 10), SyncVerdict::Plain);
    }

    #[test]
    fn honest_restore_sync_is_plain() {
        assert_eq!(sync_verdict(0, 0, 0, 40), SyncVerdict::Plain);
        assert_eq!(sync_left_after(0, 0, 0, 40), MAX_SLOT_USES - 40);
        // A stale (lower) target changes nothing and is plain.
        assert_eq!(sync_jump(0, 40, 12), 0);
        assert_eq!(sync_verdict(0, 40, 3, 12), SyncVerdict::Plain);
        assert_eq!(sync_left_after(0, 40, 3, 12), MAX_SLOT_USES - 43);
    }

    #[test]
    fn gate_repair_folds_max_plus_one() {
        // last_userop > offchain: repair promotes to last_userop, then +1.
        match check_offchain_gate(5, 40, 0) {
            GateOutcome::Accept { new_count } => assert_eq!(new_count, 41),
            o => panic!("expected accept, got {o:?}"),
        }
    }

    #[test]
    fn gate_rejects_at_gap_boundary() {
        // gap == 100 (== MAX_OFFCHAIN_GAP) must reject; gap == 99 must accept.
        assert_eq!(check_offchain_gate(100, 0, 0), GateOutcome::RejectGap);
        assert!(matches!(
            check_offchain_gate(99, 0, 0),
            GateOutcome::Accept { new_count: 100 }
        ));
    }

    #[test]
    fn gate_rejects_at_combined_cap() {
        // userop_sigs + new_count > MAX_SLOT_USES rejects.
        // offchain = MAX_SLOT_USES-1 → new_count = MAX_SLOT_USES; userop_sigs=1 → 1+MAX > MAX → reject.
        assert_eq!(
            check_offchain_gate(MAX_SLOT_USES - 1, MAX_SLOT_USES - 1, 1),
            GateOutcome::RejectCap
        );
        // last legitimate sign: userop_sigs=0, offchain=MAX-1 → new_count=MAX, 0+MAX<=MAX → accept.
        assert!(matches!(
            check_offchain_gate(MAX_SLOT_USES - 1, MAX_SLOT_USES - 1, 0),
            GateOutcome::Accept {
                new_count
            } if new_count == MAX_SLOT_USES
        ));
    }

    #[test]
    fn clamp_and_ceiling() {
        assert_eq!(clamp_offchain_count(u64::MAX), OFFCHAIN_COUNT_CEILING);
        assert_eq!(clamp_offchain_count(7), 7);
        assert_eq!(OFFCHAIN_COUNT_CEILING, MAX_SLOT_USES - 1);
    }

    #[test]
    fn distinct_slot_cap_graceful() {
        assert!(may_create_distinct_slot(MAX_DISTINCT_SLOTS - 1, false));
        assert!(!may_create_distinct_slot(MAX_DISTINCT_SLOTS, false));
        // an existing slot is always writable even at cap → never wedged.
        assert!(may_create_distinct_slot(MAX_DISTINCT_SLOTS, true));
        assert!(may_create_distinct_slot(usize::MAX, true));
    }

    #[test]
    fn sync_alone_cannot_brick_fresh_slot() {
        // The page-123 value-inflation VULN: sync a wild target, slot stays signable.
        let mut s = SlotLedger::default();
        s.apply_offchain_sync(u64::MAX);
        assert!(s.last_userop <= OFFCHAIN_COUNT_CEILING);
        assert!(
            matches!(s.apply_sign_offchain(), GateOutcome::Accept { .. }),
            "a synced-but-fresh slot must still admit a signature"
        );
    }

    #[test]
    fn two_offchain_signs_respect_combined_cap() {
        // near the cap: two signs in a row must not slice past MAX_SLOT_USES.
        let mut s = SlotLedger {
            offchain: MAX_SLOT_USES - 2,
            last_userop: MAX_SLOT_USES - 2,
            userop_sigs: 1,
            registered: true,
        };
        // 1 + (MAX-1) = MAX <= MAX → accept (new_count = MAX-1).
        assert!(matches!(s.apply_sign_offchain(), GateOutcome::Accept { .. }));
        assert!(s.userop_sigs.saturating_add(s.offchain) <= MAX_SLOT_USES);
        // now 1 + MAX-1... next new_count = MAX → 1+MAX > MAX → reject.
        assert_eq!(s.apply_sign_offchain(), GateOutcome::RejectCap);
    }

    #[test]
    fn userop_advances_last_userop_and_closes_gap() {
        let mut s = SlotLedger {
            offchain: 50,
            last_userop: 0,
            userop_sigs: 0,
            registered: true,
        };
        assert!(s.apply_sign_userop());
        assert_eq!(s.userop_sigs, 1);
        assert_eq!(s.last_userop, 50, "UserOp publishes the offchain floor");
        assert_eq!(s.offchain.saturating_sub(s.last_userop), 0, "gap closed");
    }

    #[test]
    fn synced_floor_is_included_in_userop_cap() {
        // Regression: the old Type-2 gate checked `userop_sigs + offchain`
        // before promoting `offchain` to a higher synced floor.  With one
        // prior Type-2 signature and a floor at MAX-1, that admitted another
        // signature and left the durable combined tally at MAX+1.
        let mut s = SlotLedger {
            offchain: 0,
            last_userop: 0,
            userop_sigs: 1,
            registered: true,
        };
        s.apply_offchain_sync(MAX_SLOT_USES - 1);

        assert!(
            !s.apply_sign_userop(),
            "effective combined cap is exhausted"
        );
        assert_eq!(s.offchain, 0, "a rejected sign must not promote state");
        assert_eq!(s.userop_sigs, 1, "a rejected sign must not consume a sig");
        assert!(s.is_exhausted());
    }

    #[test]
    fn synced_floor_boundary_allows_exactly_cap() {
        let mut s = SlotLedger {
            offchain: 0,
            last_userop: MAX_SLOT_USES - 2,
            userop_sigs: 1,
            registered: true,
        };

        assert!(s.apply_sign_userop());
        assert_eq!(s.offchain, MAX_SLOT_USES - 2);
        assert_eq!(s.last_userop, MAX_SLOT_USES - 2);
        assert_eq!(s.userop_sigs.saturating_add(s.offchain), MAX_SLOT_USES);
        assert!(
            s.is_exhausted(),
            "the exact-cap post-state must refuse next"
        );
    }

    #[test]
    fn ledger_slot_isolation() {
        let mut l: OffchainLedger<4> = OffchainLedger::default();
        let _ = l.sign_offchain(0xAAAA).unwrap();
        let before = l.get(0xBBBB);
        let _ = l.sign_offchain(0xAAAA).unwrap();
        assert_eq!(l.get(0xBBBB), before, "op on key A must not touch key B");
        assert_eq!(before, SlotLedger::default());
    }

    #[test]
    fn ledger_distinct_cap_refuses_new_but_keeps_existing() {
        // CAP=2 table: fill both, a third distinct key is refused, the two
        // live slots keep signing (graceful, no wedge).
        let mut l: OffchainLedger<2> = OffchainLedger::default();
        assert!(l.sign_offchain(1).is_ok());
        assert!(l.sign_offchain(2).is_ok());
        assert_eq!(l.sign_offchain(3), Err(()), "new slot refused at cap");
        assert!(l.sign_offchain(1).is_ok(), "existing slot still signs");
        assert!(l.sign_offchain(2).is_ok(), "existing slot still signs");
    }
}

// ─────────────────────────── Kani proof harnesses ──────────────────────────
// Run: `cargo kani -p pqsigner-aa` (wired into `make kani`). Anti-vacuity
// mutations for these harnesses live in `scripts/kani_mutations.json`
// (`offchain_gate_*`) and are checked by `make verify-kani-mutation`.
#[cfg(kani)]
mod verification {
    use super::*;

    /// **Sync policy soundness** (sweep 2026-10-13 finding #2). Over all
    /// symbolic device states and companion targets:
    /// * `Refuse` exactly when the write would leave the slot 0 signatures;
    /// * every sync the policy admits leaves the slot signable — the
    ///   Type-2 cap gate over the post-sync state accepts — for ANY prior
    ///   `userop_sigs` (this lifts `offchain_sync_never_bricks`' fresh-slot
    ///   assumption for every sync the handler will actually write);
    /// * `Plain` is only ever returned for a small jump with plenty left.
    #[kani::proof]
    fn sync_verdict_is_sound() {
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        let userop_sigs: u64 = kani::any();
        let target: u64 = kani::any();
        kani::assume(offchain <= OFFCHAIN_COUNT_CEILING);
        kani::assume(last_userop <= OFFCHAIN_COUNT_CEILING);
        kani::assume(userop_sigs <= MAX_SLOT_USES);
        let left = sync_left_after(offchain, last_userop, userop_sigs, target);
        let verdict = sync_verdict(offchain, last_userop, userop_sigs, target);
        assert_eq!(verdict == SyncVerdict::Refuse, left == 0);
        if verdict != SyncVerdict::Refuse {
            let mut s = SlotLedger { offchain, last_userop, userop_sigs, registered: true };
            s.apply_offchain_sync(target);
            assert!(userop_cap_ok_with_floor(s.offchain, s.last_userop, s.userop_sigs));
        }
        if verdict == SyncVerdict::Plain {
            assert!(sync_jump(offchain, last_userop, target) <= SYNC_WARN_JUMP);
            assert!(left >= SYNC_WARN_LEFT);
        }
    }

    /// **Single-gate soundness** (the doc baseline, `firmware-bounded-
    /// verification-sota-2026-06.md:81`). Over ALL symbolic `(offchain,
    /// last_userop, userop_sigs)`, an `Accept` implies every guarantee the
    /// caller relies on: the returned `new_count` is `max(offchain,
    /// last_userop) + 1`, the post-state gap is `<= MAX_OFFCHAIN_GAP`, and the
    /// combined budget is respected (`userop_sigs + new_count <= MAX_SLOT_USES`,
    /// hence `<= MAX_SLOT_USES` for `new_count` alone). No unwind: straight-line.
    #[kani::proof]
    fn offchain_gate_accept_is_sound() {
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        let userop_sigs: u64 = kani::any();
        if let GateOutcome::Accept { new_count } =
            check_offchain_gate(offchain, last_userop, userop_sigs)
        {
            let effective = if last_userop > offchain {
                last_userop
            } else {
                offchain
            };
            // new_count is exactly the repaired-then-bumped counter.
            assert!(new_count == effective + 1);
            // post-state gap (offchain' - last_userop) never exceeds the cap.
            assert!(new_count - last_userop <= MAX_OFFCHAIN_GAP);
            // combined few-time budget respected.
            assert!(userop_sigs.saturating_add(new_count) <= MAX_SLOT_USES);
            assert!(new_count <= MAX_SLOT_USES);
        }
    }

    /// **Accept/reject control** (non-vacuity partner of the above): the gate's
    /// verdict is *exactly* the conjunction of the two policy predicates — a
    /// reject is never spurious and an accept is never mis-granted. Forecloses
    /// a gate that accepts-everything (would be caught here, not by the accept
    /// harness which is vacuously true if nothing is ever accepted).
    #[kani::proof]
    fn offchain_gate_verdict_is_exact() {
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        let userop_sigs: u64 = kani::any();
        let effective = if last_userop > offchain {
            last_userop
        } else {
            offchain
        };
        let gap = effective.saturating_sub(last_userop);
        let overflow = effective == u64::MAX;
        let cap_ok = !overflow && userop_sigs.saturating_add(effective + 1) <= MAX_SLOT_USES;
        let expect_accept = gap < MAX_OFFCHAIN_GAP && !overflow && cap_ok;
        match check_offchain_gate(offchain, last_userop, userop_sigs) {
            GateOutcome::Accept { .. } => assert!(expect_accept),
            GateOutcome::RejectGap => assert!(gap >= MAX_OFFCHAIN_GAP),
            GateOutcome::RejectCap => {
                // reached only when the gap gate passed: gap < cap AND (overflow OR cap exceeded)
                assert!(gap < MAX_OFFCHAIN_GAP);
                assert!(overflow || !cap_ok);
            }
        }
    }

    /// **Value-inflation brick is unreachable** (`VULN-…value-inflation…`). A
    /// `CMD_OFFCHAIN_SYNC` with an *arbitrary* companion target, applied to a
    /// slot whose Type-2 tally leaves any headroom, always leaves the slot
    /// signable — the clamp guarantees `offchain`/`last_userop <= ceiling`, so
    /// the combined cap keeps ≥1 signature available. Proves the sync primitive
    /// alone can never durably brick a slot.
    #[kani::proof]
    fn offchain_sync_never_bricks() {
        let target: u64 = kani::any();
        let offchain: u64 = kani::any();
        kani::assume(offchain <= OFFCHAIN_COUNT_CEILING);
        // Fresh-slot model: the slot has produced NO Type-2 UserOp signature
        // (`userop_sigs == 0`) — the exact page-123 value-inflation attack setup
        // (a companion sprays `CMD_OFFCHAIN_SYNC` on slots the user never
        // rotated). The clamp's promise, verbatim from `offchain_state.rs`, is
        // "a clamped counter always leaves the slot with at least one usable
        // signature; reaching the cap requires a real, user-confirmed
        // signature". With `userop_sigs > 0` the combined cap *may* legitimately
        // reject — but only because real UserOp sigs already spent the budget,
        // which a bare sync cannot cause (sync never bumps `userop_sigs`).
        let mut s = SlotLedger {
            offchain,
            last_userop: 0,
            userop_sigs: 0,
            registered: true,
        };
        s.apply_offchain_sync(target);
        // (1) direct anti-value-inflation: sync clamps, never storing above the
        //     ceiling — the counter can never be inflated to the exhausted state.
        assert!(s.last_userop <= OFFCHAIN_COUNT_CEILING);
        // (2) fresh-slot no-brick: the combined cap never rejects a slot with no
        //     UserOp sigs after a sync. A gap-reject IS allowed here — it is
        //     recoverable by publishing a UserOp; only a CAP-reject would be the
        //     permanent brick the VULN describes.
        assert!(!matches!(
            check_offchain_gate(s.offchain, s.last_userop, s.userop_sigs),
            GateOutcome::RejectCap
        ));
    }

    /// **Two-step off-chain slicing cannot beat the combined cap.** From a
    /// symbolic state windowed just below the budget, two consecutive off-chain
    /// signs (the limit-slicing shape) never leave `userop_sigs + offchain`
    /// above `MAX_SLOT_USES` after any accept — the state update re-establishes
    /// the invariant the next gate depends on.
    #[kani::proof]
    fn offchain_two_step_cap_slice() {
        // window straddling the cap boundary (Strix limit-slicing near the edge).
        let userop_sigs: u64 = kani::any();
        let offchain: u64 = kani::any();
        kani::assume(userop_sigs <= 4);
        kani::assume(offchain >= MAX_SLOT_USES - 4 && offchain <= MAX_SLOT_USES);
        let mut s = SlotLedger {
            offchain,
            last_userop: offchain, // gap already closed → isolate the cap axis
            userop_sigs,
            registered: true,
        };
        if let GateOutcome::Accept { .. } = s.apply_sign_offchain() {
            assert!(s.userop_sigs.saturating_add(s.offchain) <= MAX_SLOT_USES);
        }
        if let GateOutcome::Accept { .. } = s.apply_sign_offchain() {
            assert!(s.userop_sigs.saturating_add(s.offchain) <= MAX_SLOT_USES);
        }
    }

    /// **Two-step off-chain slicing cannot beat the gap cap.** From a symbolic
    /// state windowed just below `MAX_OFFCHAIN_GAP`, two consecutive off-chain
    /// signs never leave the gap above `MAX_OFFCHAIN_GAP` after any accept.
    #[kani::proof]
    fn offchain_two_step_gap_slice() {
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        kani::assume(last_userop <= 8);
        // window straddling the gap boundary.
        kani::assume(offchain >= last_userop);
        kani::assume(offchain - last_userop <= MAX_OFFCHAIN_GAP + 2);
        kani::assume(offchain <= OFFCHAIN_COUNT_CEILING);
        let mut s = SlotLedger {
            offchain,
            last_userop,
            userop_sigs: 0,
            registered: true,
        };
        if let GateOutcome::Accept { .. } = s.apply_sign_offchain() {
            assert!(s.offchain.saturating_sub(s.last_userop) <= MAX_OFFCHAIN_GAP);
        }
        if let GateOutcome::Accept { .. } = s.apply_sign_offchain() {
            assert!(s.offchain.saturating_sub(s.last_userop) <= MAX_OFFCHAIN_GAP);
        }
    }

    /// **SYNC → Type-2 cap ordering.** For an arbitrary prior Type-2 tally and
    /// companion sync target, an accepted UserOp first folds in the synced
    /// floor and its post-state never exceeds the combined signature budget.
    /// This is the interleave the old bare-`offchain` gate missed.
    #[kani::proof]
    fn sync_then_userop_uses_effective_floor() {
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        let userop_sigs: u64 = kani::any();
        let target: u64 = kani::any();
        kani::assume(offchain <= MAX_SLOT_USES);
        kani::assume(last_userop <= OFFCHAIN_COUNT_CEILING);
        kani::assume(userop_sigs <= MAX_SLOT_USES);

        let mut s = SlotLedger {
            offchain,
            last_userop,
            userop_sigs,
            registered: true,
        };
        s.apply_offchain_sync(target);
        if s.apply_sign_userop() {
            assert!(s.offchain >= s.last_userop);
            assert!(s.userop_sigs.saturating_add(s.offchain) <= MAX_SLOT_USES);
        }
    }

    /// **Per-slot monotonicity** (invariant #7): no single op — sign / sync /
    /// userop — ever *decreases* any of the three counters, from any symbolic
    /// pre-state in the reachable envelope. Covers the whole op alphabet via a
    /// symbolic selector. Monotonicity is the load-bearing anti-replay property
    /// (a decrement would let a capped slot re-issue few-time signatures).
    ///
    /// Note: this deliberately does NOT assert a per-counter `<= ceiling` bound.
    /// The `OFFCHAIN_COUNT_CEILING` clamp binds only the *companion-supplied*
    /// writes (sync / promote); a *legitimate* off-chain sign bumps `offchain`
    /// to `new_count`, which reaches `MAX_SLOT_USES` on the final usable sign
    /// (when `userop_sigs == 0`). The real per-op bound is the combined cap,
    /// proven by `offchain_two_step_cap_slice`; the ceiling clamp is proven by
    /// `offchain_sync_never_bricks`.
    #[kani::proof]
    fn single_op_monotonic() {
        let op: u8 = kani::any();
        kani::assume(op < 3);
        let offchain: u64 = kani::any();
        let last_userop: u64 = kani::any();
        let userop_sigs: u64 = kani::any();
        // reachable envelope: no counter has run past the few-time budget.
        kani::assume(offchain <= MAX_SLOT_USES);
        kani::assume(last_userop <= MAX_SLOT_USES);
        kani::assume(userop_sigs <= MAX_SLOT_USES);
        let mut s = SlotLedger {
            offchain,
            last_userop,
            userop_sigs,
            registered: true,
        };
        let before = s;
        let target: u64 = kani::any();
        match op {
            0 => {
                let _ = s.apply_sign_offchain();
            }
            1 => s.apply_offchain_sync(target),
            _ => {
                let _ = s.apply_sign_userop();
            }
        }
        assert!(s.offchain >= before.offchain);
        assert!(s.last_userop >= before.last_userop);
        assert!(s.userop_sigs >= before.userop_sigs);
    }

    /// **Distinct-slot exhaustion is graceful** (`VULN-…page123-exhaustion…`,
    /// the found HIGH). Over a symbolic distinct-live count and presence bit,
    /// the allocation policy refuses a *new* slot exactly at the cap yet always
    /// admits an *existing* slot — so a spray of distinct keys caps out
    /// gracefully (creation returns "refused") and can never wedge a live slot.
    #[kani::proof]
    fn distinct_slot_policy_graceful() {
        let distinct_live: usize = kani::any();
        // an existing slot is ALWAYS writable — the anti-wedge guarantee.
        assert!(may_create_distinct_slot(distinct_live, true));
        // a new slot is admitted iff strictly under the cap.
        assert!(may_create_distinct_slot(distinct_live, false) == (distinct_live < MAX_DISTINCT_SLOTS));
    }

    /// **Ledger-level slot isolation** (invariant #8) + graceful cap over a
    /// tiny journal. Two distinct symbolic keys; an op addressed to `k0` leaves
    /// `k1`'s counters untouched, and once both entries are live a third
    /// distinct key is refused (not wedging the two live slots).
    #[kani::proof]
    #[kani::unwind(3)] // CAP + 1 for the table scans
    fn ledger_isolation_and_graceful_cap() {
        let k0: u64 = kani::any();
        let k1: u64 = kani::any();
        kani::assume(k0 != k1);
        let mut l: OffchainLedger<2> = OffchainLedger::default();
        // register both distinct slots.
        assert!(l.sign_offchain(k0).is_ok());
        assert!(l.sign_offchain(k1).is_ok());
        let k1_before = l.get(k1);
        // another op on k0 must not perturb k1.
        let _ = l.sign_offchain(k0);
        assert!(l.get(k1) == k1_before);
        // a third distinct key is refused gracefully; both live slots survive.
        let k2: u64 = kani::any();
        kani::assume(k2 != k0 && k2 != k1);
        assert!(l.sign_offchain(k2) == Err(()));
        assert!(l.get(k0).registered && l.get(k1).registered);
    }
}
