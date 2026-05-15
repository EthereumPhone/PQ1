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

/// Mutable state the gateway owns across command dispatches.
pub(super) struct SecureState {
    /// How many PIN attempts the current lockout window still permits.
    /// Mirrors the secure element's monotonic PIN counter for the mock
    /// backend; for the real TROPIC01 backend the value is refreshed
    /// from the chip on every `cmd_get_remaining`.
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
    /// `crate::pin::verify_pin` (or the TROPIC01 MAC-and-Destroy flow).
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
    pub(super) has_signed: bool,

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
    pub(super) slot_master_derived: bool,

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
            has_signed: false,
            slot_master_entropy: [0u8; 32],
            slot_master_derived: false,
            bootstrap_cache: [NONE_ENTRY; BOOTSTRAP_CACHE_LEN],
            bootstrap_cache_tick: 0,
        }
    }

    /// Wipe the master secret and drop the unlock flag. Called from
    /// the panic handler, idle-wipe paths, and any user-cancel branch
    /// where we don't want the next signing request to succeed without
    /// a fresh PIN.
    pub(super) fn zeroize_sensitive(&mut self) {
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        self.pin_verified.set_false();
        self.last_chain_id = 0;
        self.last_key_index = 0;
        self.last_ots_index = 0;
        self.has_signed = false;
        self.slot_master_entropy.zeroize();
        crate::fi::zeroize_barrier();
        self.slot_master_derived = false;
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
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        self.master_secret = master;
        master.zeroize();
        self.pin_verified.set_true();
        self.remaining_attempts = MAX_ATTEMPTS;
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
