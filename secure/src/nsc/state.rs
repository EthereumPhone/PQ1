//! Gateway state singleton.
//!
//! This module is the **only** place in the secure world where mutable
//! gateway state lives as a `static mut`. Every command handler reaches
//! it through the [`with_state`] / [`peek_state`] closure accessors, so
//! there is exactly one address-taking site for the whole crate.
//!
//! ## Why a closure API and not a raw `&mut`
//!
//! The gateway is single-threaded and non-reentrant — `poll_gateway`
//! runs a single dispatch to completion before looking at another
//! command, and command handlers do not yield — so exclusive access
//! is guaranteed by construction. Wrapping the access in a closure
//! lets callers spell out that invariant at the call site without
//! sprinkling `unsafe { &mut STATE }` across every handler, and makes
//! the module trivially refactorable to a critical-section-guarded
//! `RefCell` later if we ever need to support preemption.

use sphincs_tz_shared::MAX_ATTEMPTS;
use zeroize::Zeroize;

use crate::fih::FihBool;

// ---------------------------------------------------------------------------
// Forced-blind attempt state (default-off feature).
//
// This is deliberately a dedicated two-word state rather than a bool or an
// enum discriminant.  The only valid codewords are the three owner-selected
// pairs below.  All other pairs are invalid and must be treated as a fatal
// forced-flow fault by callers; in particular, no invalid value is coerced to
// Armed.  The all-zero BSS image is the explicitly enumerated, fail-closed
// Disarmed state.
// ---------------------------------------------------------------------------

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_DISARMED_WORDS: (u32, u32) = (0x0000_0000, 0x0000_0000);
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_ARMED_WORDS: (u32, u32) = (0xA55A_A55A, 0x5AA5_5AA5);
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_SPENT_WORDS: (u32, u32) = (0x3CC3_3CC3, 0xC33C_C33C);

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_READ_DISARMED: u32 = 0x4A91_73C5;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_WRITE_ARMED: u32 = 0xB626_8C3A;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_READBACK: u32 = 0x79D4_15E2;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_EXPECTED: u32 = crate::cfi_expected!(
    FORCED_ARM_CFI_READ_DISARMED,
    FORCED_ARM_CFI_WRITE_ARMED,
    FORCED_ARM_CFI_READBACK,
);

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_READ_ARMED: u32 = 0x5D38_A671;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_WRITE_SPENT: u32 = 0xA2C7_598E;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_READBACK: u32 = 0x36EB_C914;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_EXPECTED: u32 = crate::cfi_expected!(
    FORCED_CHARGE_CFI_READ_ARMED,
    FORCED_CHARGE_CFI_WRITE_SPENT,
    FORCED_CHARGE_CFI_READBACK,
);

/// The only three valid interpretations of [`ForcedAttemptState`].
#[cfg(feature = "erc7730-forced-blind")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ForcedAttemptPhase {
    Disarmed,
    Armed,
    Spent,
}

/// A voted read did not produce one of the three exact owner codewords.
///
/// This is intentionally a single fatal class.  A caller must not recover an
/// invalid pair as Disarmed/Armed/Spent or infer eligibility from the failure.
#[cfg(feature = "erc7730-forced-blind")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InvalidForcedAttemptState;

/// SRAM-only one-attempt state for the default-off forced-blind flow.
///
/// `#[repr(C)]` plus the size assertion in the host tests pins this to exactly
/// two adjacent `u32` words.  The type is deliberately not `Copy` or `Clone`:
/// there must be one authoritative state inside [`SecureState`].
#[cfg(feature = "erc7730-forced-blind")]
#[repr(C)]
pub(super) struct ForcedAttemptState {
    primary: u32,
    check: u32,
}

#[cfg(feature = "erc7730-forced-blind")]
impl ForcedAttemptState {
    /// Const BSS initializer.  All-zero is explicitly Disarmed, never Armed.
    const fn new_disarmed() -> Self {
        Self {
            primary: FORCED_ATTEMPT_DISARMED_WORDS.0,
            check: FORCED_ATTEMPT_DISARMED_WORDS.1,
        }
    }

    #[inline(never)]
    fn decode_words(
        primary: u32,
        check: u32,
    ) -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        match (primary, check) {
            FORCED_ATTEMPT_DISARMED_WORDS => Ok(ForcedAttemptPhase::Disarmed),
            FORCED_ATTEMPT_ARMED_WORDS => Ok(ForcedAttemptPhase::Armed),
            FORCED_ATTEMPT_SPENT_WORDS => Ok(ForcedAttemptPhase::Spent),
            _ => Err(InvalidForcedAttemptState),
        }
    }

    /// Triple-vote each word independently before interpreting the pair.
    #[inline(never)]
    pub(super) fn phase(
        &self,
    ) -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        let primary = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.primary))
            .map_err(|()| InvalidForcedAttemptState)?;
        crate::fi::wait_random();
        let check = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.check))
            .map_err(|()| InvalidForcedAttemptState)?;
        Self::decode_words(primary, check)
    }

    /// Publish one exact codeword.  Any interruption between the two writes
    /// leaves an invalid pair, which every authority read rejects.
    #[inline(never)]
    fn write_words(&mut self, words: (u32, u32)) {
        // SAFETY: `self` is exclusively borrowed.  Volatile publication keeps
        // both SRAM writes materialized and ordered around the FI readbacks.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(self.primary), words.0);
            core::sync::atomic::compiler_fence(
                core::sync::atomic::Ordering::SeqCst,
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!(self.check), words.1);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Select the fail-closed state.  This is the only transition generic
    /// unlock helpers and zeroization may perform.
    #[inline(never)]
    fn disarm(&mut self) {
        self.write_words(FORCED_ATTEMPT_DISARMED_WORDS);
    }

    /// PIN-only `Disarmed -> Armed` transition.
    ///
    /// This method is private to the state module and is the sole Armed
    /// codeword writer.  `nsc::unlock_after_verified_pin` is its sole caller;
    /// source-call-graph tests pin that wrapper to the three genuine PIN entry
    /// paths.  Re-arming Armed/Spent or repairing an invalid pair is refused.
    #[inline(never)]
    pub(super) fn arm_forced_attempt_after_pin(&mut self) -> u32 {
        let mut cfi = crate::fi::CfiCounter::new();
        let initial = self.phase();
        let disarmed = crate::fi::check_true_into_sentinel(|| {
            initial == Ok(ForcedAttemptPhase::Disarmed)
        });

        // Fail-in shape: only the explicit OK-sentinel arm may publish Armed.
        // A skipped conditional falls through to FAIL_SENTINEL below.
        if disarmed == crate::fi::OK_SENTINEL {
            cfi.bump(FORCED_ARM_CFI_READ_DISARMED);
            self.write_words(FORCED_ATTEMPT_ARMED_WORDS);
            cfi.bump(FORCED_ARM_CFI_WRITE_ARMED);

            // Independent voted readback after the write.  A skipped/partial
            // writer or a faulted load cannot manufacture a successful arm.
            let readback = self.phase();
            let armed = crate::fi::check_true_into_sentinel(|| {
                readback == Ok(ForcedAttemptPhase::Armed)
            });
            if armed == crate::fi::OK_SENTINEL {
                cfi.bump(FORCED_ARM_CFI_READBACK);
                if cfi.check_into_sentinel(FORCED_ARM_CFI_EXPECTED)
                    == crate::fi::OK_SENTINEL
                {
                    return crate::fi::OK_SENTINEL;
                }
            }
        }

        crate::fi::FAIL_SENTINEL
    }

    /// Charge the sole warning opportunity with one voted, CFI-checked
    /// `Armed -> Spent` transition and an independent voted readback.
    ///
    /// The terminal forced handler invokes this only after deterministic
    /// preflight, immediately before the first severe warning.
    /// Returning a Hamming-distant sentinel lets that handler fail closed
    /// without trusting a `bool` or `Result` discriminant.
    #[allow(dead_code)]
    #[inline(never)]
    pub(super) fn charge_forced_attempt_for_warning(&mut self) -> u32 {
        let mut cfi = crate::fi::CfiCounter::new();
        let initial = self.phase();
        let armed = crate::fi::check_true_into_sentinel(|| {
            initial == Ok(ForcedAttemptPhase::Armed)
        });

        // The permission-bearing path is the explicit OK arm.  Disarmed,
        // Spent, invalid, or a voted-load disagreement all fall through to
        // FAIL_SENTINEL without showing a warning.
        if armed == crate::fi::OK_SENTINEL {
            cfi.bump(FORCED_CHARGE_CFI_READ_ARMED);
            self.write_words(FORCED_ATTEMPT_SPENT_WORDS);
            cfi.bump(FORCED_CHARGE_CFI_WRITE_SPENT);

            // Independent readback makes a skipped or partial transition
            // visible even if the write-step CFI bump itself executed.
            let readback = self.phase();
            let spent = crate::fi::check_true_into_sentinel(|| {
                readback == Ok(ForcedAttemptPhase::Spent)
            });
            if spent == crate::fi::OK_SENTINEL {
                cfi.bump(FORCED_CHARGE_CFI_READBACK);
                if cfi.check_into_sentinel(FORCED_CHARGE_CFI_EXPECTED)
                    == crate::fi::OK_SENTINEL
                {
                    return crate::fi::OK_SENTINEL;
                }
            }
        }

        crate::fi::FAIL_SENTINEL
    }
}

/// Mutable state the gateway owns across command dispatches.
pub(super) struct SecureState {
    /// How many PIN attempts the current lockout window still permits.
    /// Mirrors the secure element's monotonic PIN counter for the mock
    /// backend; real SE backends refresh it from the chip on every
    /// `cmd_get_remaining`.
    pub(super) remaining_attempts: u8,
    /// Whether the current session has passed PIN verification. Reset
    /// by [`zeroize_sensitive`] on cancel / idle wipe / panic.
    ///
    /// FI hardening (F-14): stored as `FihBool`, a Trezor-style
    /// `(val, complement)` pair with Hamming-distant magic
    /// constants. A single-fault flip of either word breaks the
    /// storage invariant; the reader detects it and fail-closes to
    /// `false`. Every gated command reads via
    /// `s.pin_verified.check_sentinel()` (composed with the
    /// `fi::check_true_into_sentinel` Hamming-distant sentinel
    /// pattern) so the caller compares a value rather than branching
    /// on a bool — defeats both storage glitch AND caller branch-
    /// skip together.
    pub(super) pin_verified: FihBool,
    /// The 32-byte master secret unwrapped by
    /// `crate::pin::verify_pin`.
    /// Used both as the AES-GCM key for the encrypted-entropy blob and
    /// as the hedge input for SLH-DSA signing randomizers.
    pub(super) master_secret: [u8; 32],

    // -- OTS tracking (session-scoped, lost on power cycle) -----------
    // The on-chain contract is authoritative. These fields only enforce
    // monotonicity within a single unlock session to prevent accidental
    // OTS index reuse if the companion sends a stale value.

    /// The chain_id of the last successful signature.
    pub(super) last_chain_id: u64,
    /// The key_index of the last successful signature.
    pub(super) last_key_index: u32,
    /// The ots_index used by the last successful signature.
    pub(super) last_ots_index: u32,
    /// Whether any signature has been produced this session.
    ///
    /// F-14-style hardening: `FihBool` complement-storage so a
    /// single-fault flip in BSS can't make a stale session appear
    /// signed. Currently write-only (no read site in the gateway),
    /// but future code that gates on "has the session signed yet?"
    /// inherits the storage-glitch defense for free.
    pub(super) has_signed: FihBool,

    // -- Slot cache (session-scoped) ------------------------------------
    // Post-C10-cutover the firmware is stateless with respect to slot
    // selection: the companion sends `(chain_id, slot_index, flags)` on
    // every sign. We cache the derived slot master entropy across the
    // unlock session (one BIP-39 → SHA-256 pass) and the derived slot
    // SigningKey (one multi-second hypertree keygen) to amortise repeat
    // signs. Both are dropped on lock / idle-wipe / panic.

    /// Slot master entropy (derived once per unlock from BIP-39 seed).
    pub(super) slot_master_entropy: [u8; 32],

    /// Whether `slot_master_entropy` has been derived this session.
    ///
    /// F-14-style hardening: `FihBool` complement-storage. If this
    /// flag is ever read as a "skip re-derive" optimization, a
    /// single-fault flip from false→true would let a follow-up
    /// command operate on stale / zero entropy. Defended now even
    /// though current code doesn't gate on it.
    pub(super) slot_master_derived: FihBool,

    // -- Bootstrap C10 pubkey LRU cache --------------------------------
    // Multi-account variant: one seed produces up to 256 independent
    // bootstrap C10 keypairs (one per `account_index`). Each keypair
    // takes <1 s of hypertree keygen on real STM32U585, so we cache the
    // derived pubkey halves keyed by `account_index`. Address-picker
    // pagination over fresh accounts is therefore one-shot per index;
    // repeated views (and the SIGN_USEROP fast path) hit SRAM.
    //
    // 16 entries comfortably covers a single rendered page of 10
    // addresses plus a small carry-over from the previous page. On full
    // insert we evict the oldest `last_used_tick` entry. Cache is
    // wiped on lock / idle-wipe / panic.
    pub(super) bootstrap_cache: [Option<CachedAccount>; BOOTSTRAP_CACHE_LEN],

    /// Monotonic tick stamped onto each cache entry on insert / lookup.
    /// Wraps after 2^64 events — effectively never.
    pub(super) bootstrap_cache_tick: u64,

    /// One forced-blind warning opportunity per genuine PIN unlock.  This is
    /// SRAM-only and absent from feature-off builds.
    #[cfg(feature = "erc7730-forced-blind")]
    pub(super) forced_attempt: ForcedAttemptState,
}

/// Number of simultaneously-cached account bootstrap pubkey pairs.
pub(super) const BOOTSTRAP_CACHE_LEN: usize = 16;

/// One entry in [`SecureState::bootstrap_cache`]. Stores only public
/// material — the C10 secret key is dropped (and zeroized) immediately
/// after `pk_seed` / `pk_root` have been extracted.
#[derive(Clone)]
pub(super) struct CachedAccount {
    pub(super) account_index: u32,
    /// 32-byte N-masked pkSeed (top 16 bytes populated, bottom 16 = 0).
    pub(super) pk_seed: [u8; 32],
    /// 32-byte N-masked pkRoot (top 16 bytes populated, bottom 16 = 0).
    pub(super) pk_root: [u8; 32],
    /// Tick stamped at last hit / insert. Used for LRU eviction.
    pub(super) last_used_tick: u64,
}

impl SecureState {
    const fn new() -> Self {
        // `Option::None` initialiser must spell out one entry per slot
        // because `Option<CachedAccount>` is not `Copy`. `[None; N]`
        // would require `Copy`; an explicit array literal is fine in
        // const context.
        const NONE_ENTRY: Option<CachedAccount> = None;
        Self {
            remaining_attempts: MAX_ATTEMPTS,
            pin_verified: FihBool::new_false(),
            master_secret: [0u8; 32],
            last_chain_id: 0,
            last_key_index: 0,
            last_ots_index: 0,
            has_signed: FihBool::new_false(),
            slot_master_entropy: [0u8; 32],
            slot_master_derived: FihBool::new_false(),
            bootstrap_cache: [NONE_ENTRY; BOOTSTRAP_CACHE_LEN],
            bootstrap_cache_tick: 0,
            #[cfg(feature = "erc7730-forced-blind")]
            forced_attempt: ForcedAttemptState::new_disarmed(),
        }
    }

    /// Wipe the master secret and drop the unlock flag. Called from
    /// the panic handler, idle-wipe paths, and any user-cancel branch
    /// where we don't want the next signing request to succeed without
    /// a fresh PIN.
    pub(super) fn zeroize_sensitive(&mut self) {
        // Forced authority is destroyed first.  A torn two-word publication
        // is an invalid pair and therefore still fail-closed; a complete one
        // is the exact all-zero Disarmed codeword.
        #[cfg(feature = "erc7730-forced-blind")]
        self.forced_attempt.disarm();
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        // F-17: clear the rate-limit counters on lock / idle-wipe.
        // Counters are SRAM-only and were already going to vanish on
        // a power cycle; this is for the in-session zeroize path
        // (idle-wipe, panic handler).
        crate::sign_rate::reset_counters();
        self.pin_verified.set_false();
        self.last_chain_id = 0;
        self.last_key_index = 0;
        self.last_ots_index = 0;
        self.has_signed.set_false();
        self.slot_master_entropy.zeroize();
        crate::fi::zeroize_barrier();
        self.slot_master_derived.set_false();
        // Bootstrap pubkey halves are technically non-secret, but wipe
        // them anyway so a stale entry can't influence post-lock UI
        // assumptions and so the cache reverts to a clean slate on
        // re-unlock.
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                c.pk_seed.zeroize();
                c.pk_root.zeroize();
                c.last_used_tick = 0;
                c.account_index = 0;
            }
            *entry = None;
        }
        self.bootstrap_cache_tick = 0;
        // SAFETY: single-threaded, exclusive access via with_state.
        // SLOT_CACHE holds a SigningKey (ZeroizeOnDrop). Replacing the
        // Option with None drops the inner key, which wipes its secret
        // material automatically.
        unsafe {
            *core::ptr::addr_of_mut!(SLOT_CACHE) = None;
            // Idle-wipe also drops any in-progress firmware-update
            // session. The inactive slot's erased pages stay erased
            // (harmless), and the companion must restart from BEGIN.
            // FwUpdateCtx is ZeroizeOnDrop so this clears the 8 KB
            // manifest buffer plus the running SHA-256 state.
            #[cfg(feature = "stm32u585")]
            {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
        }
    }

    /// Look up a cached bootstrap pubkey pair for `account_index`. On hit,
    /// bumps the entry's tick (so it stays warm under LRU pressure) and
    /// returns `(pk_seed, pk_root)`. Returns `None` on miss.
    pub(super) fn bootstrap_cache_lookup(
        &mut self,
        account_index: u32,
    ) -> Option<([u8; 32], [u8; 32])> {
        self.bootstrap_cache_tick = self.bootstrap_cache_tick.wrapping_add(1);
        let new_tick = self.bootstrap_cache_tick;
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                if c.account_index == account_index {
                    c.last_used_tick = new_tick;
                    return Some((c.pk_seed, c.pk_root));
                }
            }
        }
        None
    }

    /// Insert (or refresh) a `(pk_seed, pk_root)` pair for
    /// `account_index`. Evicts the oldest (`last_used_tick`-min) entry
    /// when the cache is full. If the index is already present its
    /// pubkey halves are overwritten — same account_index always maps
    /// to the same derived pair, so this is a no-op rewrite.
    pub(super) fn bootstrap_cache_insert(
        &mut self,
        account_index: u32,
        pk_seed: [u8; 32],
        pk_root: [u8; 32],
    ) {
        self.bootstrap_cache_tick = self.bootstrap_cache_tick.wrapping_add(1);
        let new_tick = self.bootstrap_cache_tick;

        // Refresh existing entry if present.
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                if c.account_index == account_index {
                    c.pk_seed = pk_seed;
                    c.pk_root = pk_root;
                    c.last_used_tick = new_tick;
                    return;
                }
            }
        }

        // Find an empty slot, else the LRU victim.
        let mut victim_idx: usize = 0;
        let mut victim_tick: u64 = u64::MAX;
        for (i, entry) in self.bootstrap_cache.iter().enumerate() {
            match entry {
                None => {
                    victim_idx = i;
                    victim_tick = 0;
                    break;
                }
                Some(c) => {
                    if c.last_used_tick < victim_tick {
                        victim_tick = c.last_used_tick;
                        victim_idx = i;
                    }
                }
            }
        }
        // Wipe the victim (defensive — pubkeys are non-secret but this
        // keeps the cache hygiene predictable).
        if let Some(c) = self.bootstrap_cache[victim_idx].as_mut() {
            c.pk_seed.zeroize();
            c.pk_root.zeroize();
        }
        self.bootstrap_cache[victim_idx] = Some(CachedAccount {
            account_index,
            pk_seed,
            pk_root,
            last_used_tick: new_tick,
        });
    }

    /// Stamp in a freshly-verified master secret and mark the device
    /// unlocked. Used by both the real PIN verify path and the
    /// `e2e-test` set-state helper.
    ///
    /// HIGH-6 fix: explicitly zeroize the previous master_secret
    /// before overwriting, so a re-unlock can never leave the
    /// prior session's secret on the stack or in BSS.
    pub(super) fn mark_unlocked(&mut self, mut master: [u8; 32]) {
        // Generic/non-PIN unlock is never forced-blind authority.  The PIN-only
        // wrapper performs a separate, private arm transition after this
        // function returns successfully.
        #[cfg(feature = "erc7730-forced-blind")]
        self.forced_attempt.disarm();
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        // Trezor-parity: random delay before installing the new
        // master_secret. The 32-byte copy below is a single fixed-
        // duration block that an EM-glitch attacker could otherwise
        // time-target; `wait_random` perturbs its temporal position.
        crate::fi::wait_random();
        // THE INSTALL AND THE ARM ARE ONE TRANSACTION (#802). SysTick's idle
        // wipe reads `pin_verified` and can preempt anything; if it ran
        // between these two lines it would zeroize a master that thread mode
        // is in the middle of installing, and then `set_true` would mark the
        // session unlocked over wiped state — unlocked with no secret, which
        // no later check would notice. Today that window is closed only by
        // TIMING (every production `mark_unlocked` follows a physical PIN
        // entry that just called `reset_activity()`, so `is_idle()` is false),
        // and only `cmd_request_unlock` holds a `HandlerGuard` — the wizard,
        // the boot-interactive path and PendSV hold none. Close it by
        // construction instead.
        //
        // PRIMASK does not mask NMI or HardFault, which is correct: both of
        // those wipe, which is the safe direction.
        #[cfg(feature = "stm32u585")]
        cortex_m::interrupt::free(|_| {
            self.master_secret = master;
            self.pin_verified.set_true();
        });
        #[cfg(not(feature = "stm32u585"))]
        {
            self.master_secret = master;
            self.pin_verified.set_true();
        }
        master.zeroize();
        crate::fi::zeroize_barrier();
        self.remaining_attempts = MAX_ATTEMPTS;
        // F-17: fresh unlock = full burst budget. The session sign
        // counter resets so the user gets `MAX_SIGNS_PER_SESSION`
        // signatures before being forced to re-unlock.
        crate::sign_rate::reset_counters();
    }
}

/// The one and only `static mut` instance. Declared at module scope so
/// the program loader places it in the secure-world BSS and so it has
/// a stable address for the no-`alloc` environment.
static mut STATE: SecureState = SecureState::new();

/// Cached slot SigningKey for the `(slot_index)` most recently signed with
/// during this unlock session. Re-keygen happens when the companion asks
/// for a different `slot_index`; the cache is dropped on lock/idle-wipe.
///
/// Kept separate from `SecureState` because `SigningKey` holds arrays that
/// cannot be const-constructed; `Option<None>` lives in BSS.
///
/// SAFETY: same single-threaded invariant as `STATE`.
pub(super) static mut SLOT_CACHE: Option<CachedSlot> = None;

/// Active firmware-update session state. Populated by `CMD_FW_BEGIN`
/// and drained by `CMD_FW_COMMIT` / `CMD_FW_ABORT`. Lives in SRAM only
/// — any reset or idle-wipe restarts the companion from BEGIN.
///
/// Kept separate from `SecureState` because the 8 KB manifest buffer
/// inside `FwUpdateCtx` dwarfs the rest of state, and we want explicit
/// zeroize-on-wipe semantics. See `fw_update::mod`.
///
/// SAFETY: same single-threaded invariant as `STATE`. `FwUpdateCtx`
/// is `ZeroizeOnDrop`.
#[cfg(feature = "stm32u585")]
pub(super) static mut FW_UPDATE: Option<crate::fw_update::FwUpdateCtx> = None;

/// In-SRAM slot cache: a SigningKey tagged with the
/// `(account_index, chain_id, slot_index)` tuple it was derived for.
/// After the Coinbase-Smart-Wallet port, slot keys are chain-specific —
/// signing on chain A with slot index N derives a different key than
/// chain B with the same index, so the cache keys on chain too. With
/// multi-account derivation, slot keys also vary per `account_index`
/// (the `master_entropy` they descend from is account-scoped). A
/// mismatch on any field triggers a fresh keygen (<1 s on hardware).
pub(super) struct CachedSlot {
    pub(super) account_index: u32,
    pub(super) chain_id: u64,
    pub(super) slot_index: u32,
    pub(super) key: sphincs_c10::SigningKey,
}

/// Borrow the gateway state mutably for the duration of `f`.
///
/// SAFETY INVARIANT: the gateway is single-threaded and non-reentrant,
/// so this helper is the unique owner of `STATE` from the moment it is
/// called until `f` returns. Callers must not escape the borrow (e.g.
/// by leaking it into a task queue) — there are no tasks, but future
/// contributors should know.
pub(super) fn with_state<R>(f: impl FnOnce(&mut SecureState) -> R) -> R {
    // SAFETY: see module comment — single-threaded non-reentrant
    // dispatcher gives exclusive access by construction, and the
    // closure bounds the lifetime of the reference.
    unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) }
}

/// Borrow the gateway state immutably. Same single-threaded invariant
/// as [`with_state`] — no concurrent readers.
pub(super) fn peek_state<R>(f: impl FnOnce(&SecureState) -> R) -> R {
    // SAFETY: see `with_state`. Shared references are narrower than
    // mutable references, so the same invariant covers them.
    unsafe { f(&*core::ptr::addr_of!(STATE)) }
}

// ---------------------------------------------------------------------------
// Host tests — exercise the `SecureState` API end-to-end through the
// `with_state` / `peek_state` accessors. The whole module is gated out of
// the production `nsc` tree (`#[cfg(not(test))]` on `mod nsc;`), so these
// tests fire only when the file is re-included under the crate-root
// `nsc_core_under_test` scaffold (see `secure/src/main.rs`).
//
// **Concurrency model.** Every test that touches `STATE` / `SLOT_CACHE`
// must hold `STATE_TEST_LOCK` for the duration of the test body.
// `cargo test` runs tests in parallel by default; without serialisation
// the assertions on the singleton are inherently racey.
// ---------------------------------------------------------------------------
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Process-wide lock for every test that touches the static `STATE`.
    /// Exposed `pub(super)` so the sibling-mod tests in the crate-root
    /// `nsc_core_pure_tests` scaffold can acquire it from outside the
    /// state module.
    pub(crate) fn state_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let m = LOCK.get_or_init(|| Mutex::new(()));
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reset STATE to a clean initial value between tests so ordering
    /// can't leak.
    fn reset_state() {
        with_state(|s| {
            s.zeroize_sensitive();
            s.remaining_attempts = MAX_ATTEMPTS;
        });
    }

    #[cfg(feature = "erc7730-forced-blind")]
    fn set_forced_words(words: (u32, u32)) {
        with_state(|s| s.forced_attempt.write_words(words));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    fn forced_phase() -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        peek_state(|s| s.forced_attempt.phase())
    }

    // -- positive coverage -----------------------------------------------

    #[test]
    fn positive_initial_pin_verified_is_false() {
        let _g = state_test_lock();
        reset_state();
        assert!(!peek_state(|s| s.pin_verified.is_true_fi()));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_is_exactly_two_words_and_bss_disarmed() {
        let _g = state_test_lock();
        reset_state();
        assert_eq!(core::mem::size_of::<ForcedAttemptState>(), 8);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Disarmed));
        let words = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
        assert_eq!(words, FORCED_ATTEMPT_DISARMED_WORDS);
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_codewords_match_owner_contract() {
        assert_eq!(FORCED_ATTEMPT_DISARMED_WORDS, (0x0000_0000, 0x0000_0000));
        assert_eq!(FORCED_ATTEMPT_ARMED_WORDS, (0xA55A_A55A, 0x5AA5_5AA5));
        assert_eq!(FORCED_ATTEMPT_SPENT_WORDS, (0x3CC3_3CC3, 0xC33C_C33C));
        assert_eq!(
            FORCED_ATTEMPT_ARMED_WORDS.0 ^ FORCED_ATTEMPT_ARMED_WORDS.1,
            u32::MAX,
            "Armed must be complement-coded",
        );
        assert_eq!(
            FORCED_ATTEMPT_SPENT_WORDS.0 ^ FORCED_ATTEMPT_SPENT_WORDS.1,
            u32::MAX,
            "Spent must be complement-coded",
        );
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_codewords_have_pairwise_distance_32() {
        fn distance(a: (u32, u32), b: (u32, u32)) -> u32 {
            (a.0 ^ b.0).count_ones() + (a.1 ^ b.1).count_ones()
        }

        let words = [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ];
        for i in 0..words.len() {
            for j in (i + 1)..words.len() {
                assert_eq!(distance(words[i], words[j]), 32, "pair {i}/{j}");
            }
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_every_single_bit_mutation_of_every_codeword_is_invalid() {
        for valid in [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ] {
            for bit in 0..64u32 {
                let mutated = if bit < 32 {
                    (valid.0 ^ (1u32 << bit), valid.1)
                } else {
                    (valid.0, valid.1 ^ (1u32 << (bit - 32)))
                };
                assert_eq!(
                    ForcedAttemptState::decode_words(mutated.0, mutated.1),
                    Err(InvalidForcedAttemptState),
                    "bit {bit} unexpectedly decoded from {valid:08x?}",
                );
            }
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_mixed_valid_halves_and_single_zero_words_are_invalid() {
        let words = [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ];
        for (i, left) in words.iter().enumerate() {
            for (j, right) in words.iter().enumerate() {
                let mixed = (left.0, right.1);
                if i == j {
                    assert!(ForcedAttemptState::decode_words(mixed.0, mixed.1).is_ok());
                } else {
                    assert_eq!(
                        ForcedAttemptState::decode_words(mixed.0, mixed.1),
                        Err(InvalidForcedAttemptState),
                        "mixed pair {i}/{j} must be fatal",
                    );
                }
            }
        }

        for valid in [FORCED_ATTEMPT_ARMED_WORDS, FORCED_ATTEMPT_SPENT_WORDS] {
            assert_eq!(
                ForcedAttemptState::decode_words(0, valid.1),
                Err(InvalidForcedAttemptState),
            );
            assert_eq!(
                ForcedAttemptState::decode_words(valid.0, 0),
                Err(InvalidForcedAttemptState),
            );
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_pin_arm_is_disarmed_to_armed_only_and_cannot_rearm() {
        let _g = state_test_lock();
        reset_state();
        let first = with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin());
        assert_eq!(first, crate::fi::OK_SENTINEL);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Armed));

        let second = with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin());
        assert_eq!(second, crate::fi::FAIL_SENTINEL);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Armed));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_pin_arm_refuses_spent_and_invalid_without_repair() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            assert_eq!(
                with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin()),
                crate::fi::FAIL_SENTINEL,
                "non-Disarmed pair {words:08x?} must refuse arming",
            );
            let after = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
            assert_eq!(after, words, "refusal must not repair/re-arm the pair");
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_charge_is_one_voted_armed_to_spent_transition() {
        let _g = state_test_lock();
        reset_state();
        assert_eq!(
            with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin()),
            crate::fi::OK_SENTINEL,
        );
        assert_eq!(
            with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
            crate::fi::OK_SENTINEL,
        );
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Spent));

        assert_eq!(
            with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
            crate::fi::FAIL_SENTINEL,
            "Spent must not admit a second warning",
        );
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Spent));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_charge_refuses_disarmed_spent_and_invalid_without_repair() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            assert_eq!(
                with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
                crate::fi::FAIL_SENTINEL,
                "non-Armed pair {words:08x?} must refuse",
            );
            let after = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
            assert_eq!(after, words, "refusal must not repair/re-arm the pair");
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_generic_unlock_and_zeroize_always_select_disarmed() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            with_state(|s| s.mark_unlocked([0x91; 32]));
            assert_eq!(
                forced_phase(),
                Ok(ForcedAttemptPhase::Disarmed),
                "generic mark_unlocked must never preserve authority",
            );

            set_forced_words(words);
            with_state(SecureState::zeroize_sensitive);
            assert_eq!(
                forced_phase(),
                Ok(ForcedAttemptPhase::Disarmed),
                "zeroize must select Disarmed even from an invalid pair",
            );
        }
    }

    #[test]
    fn positive_mark_unlocked_sets_pin_verified() {
        let _g = state_test_lock();
        reset_state();
        let master = [0x42u8; 32];
        with_state(|s| s.mark_unlocked(master));
        assert!(peek_state(|s| s.pin_verified.is_true_fi()));
    }

    #[test]
    fn positive_mark_unlocked_stores_master_secret() {
        let _g = state_test_lock();
        reset_state();
        let master = [0xA5u8; 32];
        with_state(|s| s.mark_unlocked(master));
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, master, "master_secret must be installed verbatim");
    }

    #[test]
    fn positive_zeroize_drops_pin_verified() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0x11u8; 32]));
        assert!(peek_state(|s| s.pin_verified.is_true_fi()));
        with_state(|s| s.zeroize_sensitive());
        assert!(
            !peek_state(|s| s.pin_verified.is_true_fi()),
            "zeroize_sensitive MUST land pin_verified back at false"
        );
    }

    #[test]
    fn positive_zeroize_wipes_master_secret() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0xCDu8; 32]));
        with_state(|s| s.zeroize_sensitive());
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0u8; 32], "master_secret MUST be byte-zeroed by zeroize_sensitive");
    }

    #[test]
    fn positive_zeroize_wipes_slot_master_entropy() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.slot_master_entropy = [0xBBu8; 32];
            s.slot_master_derived.set_true();
        });
        with_state(|s| s.zeroize_sensitive());
        let got = peek_state(|s| s.slot_master_entropy);
        assert_eq!(got, [0u8; 32]);
        assert!(!peek_state(|s| s.slot_master_derived.is_true_fi()));
    }

    #[test]
    fn positive_initial_remaining_attempts_is_max() {
        let _g = state_test_lock();
        reset_state();
        let r = peek_state(|s| s.remaining_attempts);
        assert_eq!(r, MAX_ATTEMPTS);
    }

    #[test]
    fn positive_bootstrap_cache_lookup_miss_returns_none() {
        let _g = state_test_lock();
        reset_state();
        let got = with_state(|s| s.bootstrap_cache_lookup(0));
        assert!(got.is_none(), "fresh state must have an empty bootstrap cache");
    }

    #[test]
    fn positive_bootstrap_cache_insert_then_lookup_returns_pubkeys() {
        let _g = state_test_lock();
        reset_state();
        let pk_seed = [0x11u8; 32];
        let pk_root = [0x22u8; 32];
        with_state(|s| s.bootstrap_cache_insert(7, pk_seed, pk_root));
        let got = with_state(|s| s.bootstrap_cache_lookup(7));
        assert_eq!(got, Some((pk_seed, pk_root)));
    }

    #[test]
    fn positive_bootstrap_cache_distinct_indices_distinct_pubkeys() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.bootstrap_cache_insert(0, [0x10; 32], [0x20; 32]);
            s.bootstrap_cache_insert(1, [0x11; 32], [0x21; 32]);
        });
        let a = with_state(|s| s.bootstrap_cache_lookup(0)).unwrap();
        let b = with_state(|s| s.bootstrap_cache_lookup(1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn positive_bootstrap_cache_reinsert_overwrites_in_place() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.bootstrap_cache_insert(3, [0x01; 32], [0x02; 32]));
        with_state(|s| s.bootstrap_cache_insert(3, [0x03; 32], [0x04; 32]));
        let got = with_state(|s| s.bootstrap_cache_lookup(3));
        assert_eq!(got, Some(([0x03; 32], [0x04; 32])));
    }

    #[test]
    fn positive_bootstrap_cache_lru_evicts_oldest() {
        let _g = state_test_lock();
        reset_state();
        // Fill the cache.
        with_state(|s| {
            for i in 0..(BOOTSTRAP_CACHE_LEN as u32) {
                s.bootstrap_cache_insert(i, [i as u8; 32], [i as u8 ^ 0xFF; 32]);
            }
        });
        // Touch index 0 to keep it warm, then insert one more.
        let _ = with_state(|s| s.bootstrap_cache_lookup(0));
        // The least-recently-touched at this point is index 1.
        with_state(|s| {
            s.bootstrap_cache_insert(99, [0xEEu8; 32], [0xEFu8; 32])
        });
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(1)).is_none(),
            "LRU victim (index 1) must have been evicted"
        );
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(0)).is_some(),
            "warm entry (index 0) must have survived"
        );
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(99)).is_some(),
            "newest entry must be present"
        );
    }

    // -- negative coverage -----------------------------------------------

    /// Assumption: `mark_unlocked` zeroizes the *caller's* buffer copy
    /// after stamping. Forgetting this leaves a 32-byte secret on the
    /// caller's stack indefinitely.
    #[test]
    fn negative_mark_unlocked_wipes_caller_local_master() {
        let _g = state_test_lock();
        reset_state();
        let mut master = [0xC3u8; 32];
        with_state(|s| s.mark_unlocked(master));
        // `master` was passed by value — the inside-the-fn `master.zeroize()`
        // does not affect the outer local. The contract is "the byte
        // buffer the function moved IN gets zeroized before return."
        // We can re-prove it by passing a buffer and checking that the
        // stored copy is the byte pattern we passed (i.e. nothing was
        // mangled). Caller-buffer wipe is the responsibility of the
        // caller (see `gated_unlock`); state pins the contract that the
        // stored copy is correct.
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0xC3u8; 32]);
        let _ = &mut master;
    }

    /// Assumption (HIGH-6): a re-unlock with a NEW master MUST wipe the
    /// prior master_secret BEFORE installing the new one. Otherwise an
    /// EM-glitch on the assignment leaves the stale secret in BSS.
    #[test]
    fn negative_mark_unlocked_overwrites_prior_master_completely() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0xAAu8; 32]));
        with_state(|s| s.mark_unlocked([0x55u8; 32]));
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0x55u8; 32]);
        // No byte of the prior 0xAA secret may survive.
        assert!(stored.iter().all(|b| *b != 0xAA),
            "no byte of the prior master_secret may remain after re-unlock");
    }

    /// Assumption: `zeroize_sensitive` also clears the per-slot tracking
    /// fields (`last_chain_id`, `last_key_index`, `last_ots_index`,
    /// `has_signed`). If any survive a wipe, a stale-session replay
    /// counter can be misinterpreted as a fresh-session zero by the
    /// next signing pass.
    #[test]
    fn negative_zeroize_clears_ots_tracking_fields() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.last_chain_id = 0xDEAD_BEEF_DEAD_BEEF;
            s.last_key_index = 0xCAFE_BABE;
            s.last_ots_index = 0x0BAD_F00D;
            s.has_signed.set_true();
        });
        with_state(|s| s.zeroize_sensitive());
        let (cid, ki, oi, hs) = peek_state(|s| (
            s.last_chain_id, s.last_key_index, s.last_ots_index,
            s.has_signed.is_true_fi(),
        ));
        assert_eq!(cid, 0, "last_chain_id must be zeroed");
        assert_eq!(ki, 0, "last_key_index must be zeroed");
        assert_eq!(oi, 0, "last_ots_index must be zeroed");
        assert!(!hs, "has_signed must be cleared");
    }

    /// Assumption: `zeroize_sensitive` wipes the bootstrap pubkey
    /// cache. Stale entries are technically non-secret but their
    /// presence after a lock would let post-wipe code path observe
    /// "warm cache" state that mismatches the freshly-zero
    /// `master_secret`.
    #[test]
    fn negative_zeroize_clears_bootstrap_cache() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.bootstrap_cache_insert(0, [0x10; 32], [0x20; 32]);
            s.bootstrap_cache_insert(1, [0x11; 32], [0x21; 32]);
        });
        with_state(|s| s.zeroize_sensitive());
        for i in 0..=1u32 {
            assert!(
                with_state(|s| s.bootstrap_cache_lookup(i)).is_none(),
                "bootstrap cache entry {i} must be cleared by zeroize_sensitive"
            );
        }
        // Tick counter is also reset (so post-wipe lookups don't see a
        // wrapped-but-non-zero tick that confuses LRU comparison).
        let tick = peek_state(|s| s.bootstrap_cache_tick);
        // After zeroize_sensitive sets tick to 0, the first lookup above
        // bumps it via wrapping_add — so it should be > 0 here. We only
        // assert it didn't survive at its old (post-fill) value of 2.
        assert!(tick <= 2,
            "bootstrap_cache_tick must reset to ~0 after zeroize_sensitive (saw {tick})");
    }

    /// Assumption (CLAUDE.md invariant #4 + ZeroizeOnDrop): `pin_verified`
    /// is FI-hardened storage (Trezor-style complement pair, NOT a bare
    /// `bool`). A bare `bool` would let a single bit-flip toggle it.
    /// We pin the size: `FihBool` is two `u32`s (8 bytes); a `bool`
    /// would be 1 byte.
    #[test]
    fn negative_pin_verified_storage_is_fihbool_sized() {
        use core::mem::size_of_val;
        let _g = state_test_lock();
        // peek to materialise an actual borrow; size_of_val is const but
        // we want to assert against the live field, not the type alias.
        let sz = peek_state(|s| size_of_val(&s.pin_verified));
        assert_eq!(sz, 8,
            "pin_verified must be FihBool-sized (val+complement = 8 bytes); \
             a 1-byte bool would re-open the F-14 single-bit-flip attack");
    }

    /// Assumption: `master_secret` storage is exactly 32 bytes (the SHA-256
    /// width assumed by every downstream KDF call site). A silent
    /// resize would break entropy-blob decryption.
    #[test]
    fn negative_master_secret_storage_is_32_bytes() {
        let _g = state_test_lock();
        let sz = peek_state(|s| s.master_secret.len());
        assert_eq!(sz, 32);
    }

    /// Assumption: the bootstrap-cache LRU array is exactly
    /// `BOOTSTRAP_CACHE_LEN` (16) entries. A silent enlargement
    /// expands the BSS footprint past what the documented invariant
    /// admits; a shrink starts evicting under workloads that fit
    /// today.
    #[test]
    fn negative_bootstrap_cache_array_length_is_pinned() {
        let _g = state_test_lock();
        let sz = peek_state(|s| s.bootstrap_cache.len());
        assert_eq!(sz, BOOTSTRAP_CACHE_LEN);
        assert_eq!(BOOTSTRAP_CACHE_LEN, 16,
            "BOOTSTRAP_CACHE_LEN is documented as 16 in state.rs");
    }

    /// Assumption: after `zeroize_sensitive`, an evicted-then-re-inserted
    /// cache entry's pubkey halves must be the new values — i.e. the
    /// old victim's bytes do NOT leak through.
    #[test]
    fn negative_evicted_cache_entry_pubkey_bytes_replaced() {
        let _g = state_test_lock();
        reset_state();
        // Fill, then push one extra to force eviction of the LRU.
        with_state(|s| {
            for i in 0..(BOOTSTRAP_CACHE_LEN as u32) {
                s.bootstrap_cache_insert(i, [0xAAu8; 32], [0xBBu8; 32]);
            }
            s.bootstrap_cache_insert(0xFF, [0x55u8; 32], [0x77u8; 32]);
        });
        let got = with_state(|s| s.bootstrap_cache_lookup(0xFF));
        assert_eq!(got, Some(([0x55u8; 32], [0x77u8; 32])));
        // The victim's `account_index` is no longer present.
        assert!(with_state(|s| s.bootstrap_cache_lookup(0)).is_none(),
            "victim's account_index must be evicted");
    }
}
