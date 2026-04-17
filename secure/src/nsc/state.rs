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

/// Mutable state the gateway owns across command dispatches.
pub(super) struct SecureState {
    /// How many PIN attempts the current lockout window still permits.
    /// Mirrors the secure element's monotonic PIN counter for the mock
    /// backend; for the real TROPIC01 backend the value is refreshed
    /// from the chip on every `cmd_get_remaining`.
    pub(super) remaining_attempts: u8,
    /// Whether the current session has passed PIN verification. Reset
    /// by [`zeroize_sensitive`] on cancel / idle wipe / panic.
    pub(super) pin_verified: bool,
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

    // -- JARDÍN slot cache (session-scoped) -----------------------------
    // Post-C10-cutover the firmware is stateless with respect to slot
    // selection: the companion sends `(chain_id, slot_index, flags)` on
    // every sign. We cache the derived JARDÍN master entropy across the
    // unlock session (one BIP-39 → SHA-256 pass) and the derived slot
    // SigningKey (one multi-second hypertree keygen) to amortise repeat
    // signs. Both are dropped on lock / idle-wipe / panic.

    /// JARDÍN master entropy (derived once per unlock from BIP-39 seed).
    pub(super) jardin_master_entropy: [u8; 32],

    /// Whether `jardin_master_entropy` has been derived this session.
    pub(super) jardin_master_derived: bool,
}

impl SecureState {
    const fn new() -> Self {
        Self {
            remaining_attempts: MAX_ATTEMPTS,
            pin_verified: false,
            master_secret: [0u8; 32],
            last_chain_id: 0,
            last_key_index: 0,
            last_ots_index: 0,
            has_signed: false,
            jardin_master_entropy: [0u8; 32],
            jardin_master_derived: false,
        }
    }

    /// Wipe the master secret and drop the unlock flag. Called from
    /// the panic handler, idle-wipe paths, and any user-cancel branch
    /// where we don't want the next signing request to succeed without
    /// a fresh PIN.
    pub(super) fn zeroize_sensitive(&mut self) {
        self.master_secret.zeroize();
        self.pin_verified = false;
        self.last_chain_id = 0;
        self.last_key_index = 0;
        self.last_ots_index = 0;
        self.has_signed = false;
        self.jardin_master_entropy.zeroize();
        self.jardin_master_derived = false;
        // SAFETY: single-threaded, exclusive access via with_state.
        // JARDIN_SLOT holds a SigningKey (ZeroizeOnDrop). Replacing the
        // Option with None drops the inner key, which wipes its secret
        // material automatically.
        unsafe {
            *core::ptr::addr_of_mut!(JARDIN_SLOT) = None;
        }
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
        self.master_secret = master;
        master.zeroize();
        self.pin_verified = true;
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
pub(super) static mut JARDIN_SLOT: Option<CachedSlot> = None;

/// In-SRAM slot cache: a SigningKey tagged with the `slot_index` it was
/// derived for. Chain id is not part of the cache key because slot
/// derivation is chain-agnostic — on-chain separation is enforced by the
/// per-wallet `slots[slotKey]` mapping instead.
pub(super) struct CachedSlot {
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
