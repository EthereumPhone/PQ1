//! CMD_GET_WALLET_ADDRESS — compute the CREATE2-predicted wallet address
//! for a given `account_index` from the firmware-embedded factory +
//! proxy-init-code-hash constants and the bootstrap C10 pubkey.
//!
//! This lets the companion discover the sender address WITHOUT having
//! to do a full sign first just to extract `masterPkSeed` / `masterPkRoot`
//! from an emitted initCode. The numbers baked into the firmware
//! (`PQ_SMART_WALLET_FACTORY`, `PROXY_INIT_CODE_HASH`) are CREATE2-stable
//! across chains, so one formula covers every deploy target.
//!
//! Formula (mirrors `PQSmartWalletFactory.getAddress`):
//!   salt    = sha256(masterPkSeed(32) || masterPkRoot(32))
//!   initHash = PROXY_INIT_CODE_HASH
//!   address = keccak256(0xff || factory || salt || initHash)[12..]
//!
//! Requires an unlocked device. First call for a given `account_index`
//! triggers bootstrap C10 keygen (<1 s on hardware) and caches the
//! resulting pubkey halves in `SecureState::bootstrap_cache` (LRU,
//! capacity `BOOTSTRAP_CACHE_LEN`); subsequent calls reuse the cache
//! and return in <1 ms.
//!
//! `account_index` MUST be in `0..=MAX_ACCOUNT_INDEX` (8 bits). Account
//! 0 reproduces the legacy single-account derivation byte-for-byte so
//! pre-multi-account seeds keep their existing on-chain address.
//!
//! `arg2` is the companion's opt-in show-on-device flag (#472, Trezor
//! receive-address parity):
//!   * `0` — legacy behaviour: derive and return the address with no
//!     trusted-UI round-trip;
//!   * `1` — after derivation and BEFORE anything is written to the NS
//!     buffer, show the full EIP-55 address (bound to `account_index`)
//!     on the trusted OLED and require a physical confirm. Cancel /
//!     idle-wipe fail closed: no NS-buffer write, `UserRejected` /
//!     `IdleWipe` status;
//!   * `>1` — wire-format error (`InvalidPointer`).

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sphincs_tz_shared::{
    NscStatus, MAX_ACCOUNT_INDEX, PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::ptr_validate::validate_ns_write_ptr;
use super::GatewayArgs;

/// Output length: a 20-byte Ethereum address.
const ADDR_LEN: usize = 20;

/// CFI step committed only inside the non-inlined sender-binding helper.
const CFI_STEP_SENDER_BIND_DONE: u32 = 0x6B_4D_A2_17;
/// Expected caller-side CFI total after the binding helper completed.
pub(super) const SENDER_BIND_CFI_EXPECTED: u32 =
    crate::cfi_expected!(CFI_STEP_SENDER_BIND_DONE);

/// Return the bootstrap public-key halves for an account, deriving and caching
/// them on a miss.
///
/// # Safety
/// On a cache miss this accesses the process-wide secure-element singleton.
/// Callers must hold the non-reentrant NSC handler guard.
unsafe fn bootstrap_public_key_for_account(
    account_index: u32,
    progress_title: &'static str,
) -> Result<([u8; 32], [u8; 32]), NscStatus> {
    if account_index > MAX_ACCOUNT_INDEX {
        return Err(NscStatus::InvalidPointer);
    }

    let cached = super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
    Ok(match cached {
        Some(pair) => pair,
        None => {
            let master_secret: Zeroizing<[u8; 32]> =
                Zeroizing::new(super::state::peek_state(|s| s.master_secret));
            let mut entropy_blob = Zeroizing::new([0u8; 64]);
            let entropy_blob_len = {
                use crate::secure_element::WalletStore;
                // SAFETY: the caller holds HandlerGuard; gateway dispatch is
                // single-threaded and non-reentrant.
                let se = unsafe { &mut *core::ptr::addr_of_mut!(crate::SE) };
                se.read_entropy_blob(&mut *entropy_blob)
                    .map_err(|_| NscStatus::InternalError)?
            };
            let entropy = Zeroizing::new(
                crate::crypto::decrypt_entropy_blob(
                    &entropy_blob[..entropy_blob_len],
                    &*master_secret,
                )
                .map_err(|_| NscStatus::CryptoError)?,
            );

            crate::ui::show_progress(progress_title, 0);
            let (c10_sk, pk_seed_32, pk_root_32) =
                crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                    &*entropy,
                    account_index,
                    |p| crate::ui::show_progress(progress_title, p),
                );
            drop(c10_sk); // ZeroizeOnDrop wipes the bootstrap secret key.
            super::state::with_state(|s| {
                s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
            });
            (pk_seed_32, pk_root_32)
        }
    })
}

/// Derive the mnemonic-bound CREATE2 wallet address for `account_index`.
///
/// Signing gateways call this before confirmation so the untrusted companion
/// cannot pair an account-derived signing key with an arbitrary `sender`.
/// This is the canonical address computation shared with the AA crate and
/// `CMD_GET_WALLET_ADDRESS`; sender binding additionally recomputes it through
/// the structurally independent implementation below.
///
/// # Safety
/// On a cache miss this accesses the process-wide secure-element singleton.
/// Callers must hold the non-reentrant NSC handler guard.
pub(super) unsafe fn wallet_address_for_account(
    account_index: u32,
    progress_title: &'static str,
) -> Result<[u8; ADDR_LEN], NscStatus> {
    // SAFETY: forwarded from this function's contract.
    let (pk_seed, pk_root) = unsafe {
        bootstrap_public_key_for_account(account_index, progress_title)?
    };

    Ok(crate::aa::eip1271::proxy_address(&pk_seed, &pk_root))
}

/// Independent CREATE2 computation used only as the FI cross-check.
///
/// The canonical implementation in `pqsigner-aa` concatenates the two public
/// key halves into one 64-byte SHA input and feeds the complete 85-byte
/// CREATE2 preimage to Keccak in one update. This implementation deliberately
/// uses separate SHA updates, fills the CREATE2 preimage in a different order,
/// and feeds Keccak in three chunks. Keeping it non-inlined and separated by a
/// randomized gap prevents the sender-binding check from degenerating into two
/// calls to one shared computation (or two reads of one cached address).
#[inline(never)]
fn proxy_address_cross_check(
    pk_seed: &[u8; 32],
    pk_root: &[u8; 32],
) -> [u8; ADDR_LEN] {
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(core::hint::black_box(&pk_seed[..]));
        h.update(core::hint::black_box(&pk_root[..]));
        h.finalize().into()
    };

    let mut preimage = [0u8; 85];
    // Reverse write order relative to the canonical helper.
    preimage[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    preimage[21..53].copy_from_slice(&salt);
    preimage[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    preimage[0] = 0xff;

    let digest: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(core::hint::black_box(&preimage[..21]));
        h.update(core::hint::black_box(&preimage[21..53]));
        h.update(core::hint::black_box(&preimage[53..]));
        h.finalize().into()
    };
    let mut address = [0u8; ADDR_LEN];
    address.copy_from_slice(&digest[12..]);
    address
}

/// Re-read the account-bound public key and compute its address via the
/// independent CREATE2 implementation above.
///
/// # Safety
/// Same as [`wallet_address_for_account`].
#[inline(never)]
unsafe fn wallet_address_for_account_cross_check(
    account_index: u32,
    progress_title: &'static str,
) -> Result<[u8; ADDR_LEN], NscStatus> {
    // SAFETY: forwarded from this function's contract.
    let (pk_seed, pk_root) = unsafe {
        bootstrap_public_key_for_account(account_index, progress_title)?
    };
    Ok(proxy_address_cross_check(&pk_seed, &pk_root))
}

/// Result of binding a companion-supplied UserOp sender to a deterministic
/// wallet address.
///
/// `sender` is always initialized independently of the companion field. On a
/// derivation failure it is all-zero; after the first successful derivation it
/// is the mnemonic-derived address. Callers consume this field before checking
/// `verdict`, so an instruction skip at the reject branch can never expose the
/// companion address to a signed hash.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct SenderBinding {
    pub(super) sender: [u8; ADDR_LEN],
    pub(super) verdict: u32,
    pub(super) error: NscStatus,
}

impl SenderBinding {
    /// Materialized by each caller before the non-inlined binding call.
    /// A skipped `bl bind_userop_sender` therefore leaves an unusable zero
    /// sender and a Hamming-distant failure verdict, never stale sret bytes.
    pub(super) const fn fail_closed() -> Self {
        Self {
            sender: [0u8; ADDR_LEN],
            verdict: crate::fi::FAIL_SENTINEL,
            error: NscStatus::InternalError,
        }
    }
}

/// Bind a companion-supplied UserOp sender to this seed's deterministic
/// wallet for `account_index`.
///
/// The address is derived through two structurally independent CREATE2
/// computations with a randomized gap and both results are compared to the
/// companion field under the FI sentinel gate. On success the trusted, derived
/// address is published into the caller-owned `output` slot.
/// Signing handlers must discard the companion field and use only that slot
/// for display bindings and UserOp hashes. Consequently, even a fault that
/// skips the caller's reject branch cannot turn the device into a signer for
/// an arbitrary account.
///
/// # Safety
/// Same as [`wallet_address_for_account`]: the caller must hold the
/// non-reentrant NSC handler guard. For FI fail-closure it must also pass a
/// freshly initialized [`crate::fi::CfiCounter`] and volatile-materialize
/// `SenderBinding::fail_closed()` into `output` before this call.
#[inline(never)]
pub(super) unsafe fn bind_userop_sender(
    account_index: u32,
    companion_sender: &[u8; ADDR_LEN],
    output: &mut SenderBinding,
    cfi: &mut crate::fi::CfiCounter,
) {
    // Compute into a local fail-closed value and use one common epilogue. The
    // CFI bump must be reached on every ordinary success/failure return, and
    // must remain absent if the entire `bl bind_userop_sender` is skipped.
    let mut binding = SenderBinding::fail_closed();
    // SAFETY: forwarded from this function's contract.
    match unsafe { wallet_address_for_account(account_index, "Wallet check") } {
        Err(error) => binding.error = error,
        Ok(expected_a) => {
            // Only a mnemonic-derived address can ever be published.
            binding.sender = expected_a;
            let match_a = expected_a.ct_eq(companion_sender).unwrap_u8();

            // Recompute through the independently structured CREATE2 path
            // rather than calling the canonical helper twice. The cached
            // public key avoids a second C10 keygen.
            crate::fi::wait_random();
            // SAFETY: forwarded from this function's contract.
            match unsafe {
                wallet_address_for_account_cross_check(account_index, "Wallet check")
            } {
                Err(error) => binding.error = error,
                Ok(expected_b) => {
                    let match_b = expected_b.ct_eq(companion_sender).unwrap_u8();
                    let derivations_agree = expected_a.ct_eq(&expected_b).unwrap_u8();
                    binding.verdict = crate::fi::check_true_into_sentinel(|| {
                        core::hint::black_box(match_a) == 1
                            && core::hint::black_box(match_b) == 1
                            && core::hint::black_box(derivations_agree) == 1
                    });
                    binding.error = if derivations_agree == 1 {
                        NscStatus::InvalidPointer
                    } else {
                        NscStatus::InternalError
                    };
                }
            }
        }
    }

    // Publish sender/status first, verify the sender stores by two volatile
    // readbacks, and publish the verdict LAST. This matters on Thumb where an
    // aggregate 20-byte store lowers to several instructions: skipping one
    // word store must not leave a stale address paired with an OK verdict.
    // SAFETY: `output` is a unique, valid mutable reference.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(output.sender), binding.sender);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(output.error), binding.error);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    // SAFETY: the fields were initialized by the caller and written above;
    // volatile reads deliberately verify the materialized output slot.
    let sender_readback_a = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(output.sender))
    };
    crate::fi::wait_random();
    // SAFETY: same as the first readback.
    let sender_readback_b = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(output.sender))
    };
    let binding_was_ok = binding.verdict == crate::fi::OK_SENTINEL;
    let readback_a_ok = sender_readback_a.ct_eq(&binding.sender).unwrap_u8();
    let readback_b_ok = sender_readback_b.ct_eq(&binding.sender).unwrap_u8();
    let published_verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(binding_was_ok)
            && core::hint::black_box(readback_a_ok) == 1
            && core::hint::black_box(readback_b_ok) == 1
    });

    // The caller preinitialized this field to FAIL. Publishing OK last means
    // a skipped verdict store remains fail-closed.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `output` remains uniquely borrowed for this call.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(output.verdict),
            published_verdict,
        );
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(CFI_STEP_SENDER_BIND_DONE);
}

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// deref happens only after `validate_ns_write_ptr`; `static mut SE`
/// access uses the single-threaded dispatcher invariant.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // HIGH-7 guard (audit gateway-parsing 20260623, LOW-1): the cache-miss
    // path derives the bootstrap C10 keypair (~1 s keygen) while holding
    // stack-local `master_secret` / `entropy` copies AND while borrowing the
    // `STATE` singleton (pin-verified peek, `bootstrap_cache_insert`).
    // Without this guard `handler_is_busy()` reads false for that whole
    // window, so the SysTick idle-wipe (`zeroize_sensitive_state` ->
    // `with_state`, the idle-wipe branch in `main::SysTick`) can take
    // `&mut STATE` concurrently with this handler's borrow — an aliasing /
    // data race on the secret-bearing singleton. Every other keygen/sign
    // handler already holds this guard; match them so the wipe defers until
    // this handler returns.
    let _busy = super::HandlerGuard::enter();

    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    let out_ptr = args.arg0 as *mut u8;
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS write
    // pointer (bare `if !validate` is single-fault FAIL-OUT → OOB write).
    let write_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg0, ADDR_LEN)
    });
    if write_ptr_ok != crate::fi::OK_SENTINEL {
        return NscStatus::InvalidPointer as u32;
    }

    // arg1 carries the account_index (0..=255). Anything above the mask
    // is a wire-format error — the companion is supposed to mask before
    // sending. Refuse rather than silently truncating, so a stale
    // companion paying no attention to the new field doesn't quietly
    // alias account 256 onto account 0.
    let account_index = args.arg1;
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    // arg2 carries the show-on-device flag (#472). Anything above 1 is a
    // wire-format error — refuse rather than silently treating it as 0,
    // so a companion bug can never suppress the user verification it
    // asked about.
    let show = args.arg2;
    if show > 1 {
        return NscStatus::InvalidPointer as u32;
    }

    let was_cached =
        super::state::with_state(|s| s.bootstrap_cache_lookup(account_index)).is_some();
    // SAFETY: `run` holds `HandlerGuard`, satisfying the helper contract.
    let address = match unsafe { wallet_address_for_account(account_index, "Wallet addr") } {
        Ok(address) => address,
        Err(status) => return status as u32,
    };

    // Opt-in trusted-display verification (#472): the derived address is
    // shown and confirmed BEFORE any NS-bound write, so a cancelled
    // prompt leaves the companion with no address bytes at all (fail
    // closed). The page binds the exact account being answered; the
    // confirm idiom mirrors `cmd_offchain_sync` (affirmative-sentinel
    // gate, cancel → UserRejected, idle-wipe → zeroize + IdleWipe).
    if show == 1 {
        use crate::ui::confirm::{confirm_checked, ConfirmResult};
        let page = match crate::tx::display::build_wallet_address_page(account_index, &address)
        {
            Some(page) => page,
            None => return NscStatus::InternalError as u32,
        };
        // Port step 4: the same page facts on the design's screens (the
        // address whole on the docked grid); the page dialog only when the
        // pixel path cannot run.
        #[cfg(feature = "ui-px")]
        let px = super::px_confirm_plain(|t| crate::ui::px::status_map::wallet_address_screens(account_index, &page, t)).ok();
        #[cfg(not(feature = "ui-px"))]
        let px: Option<(ConfirmResult, u32)> = None;
        let (cr, cr_verdict) = match px {
            Some(out) => out,
            None => confirm_checked(core::slice::from_ref(&page)),
        };
        match cr {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail
        // closed — a faulted confirm can never masquerade as consent.
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }

    // Write the mnemonic-bound CREATE2 address to the validated NS buffer.
    for i in 0..ADDR_LEN {
        core::ptr::write_volatile(out_ptr.add(i), address[i]);
    }

    if !was_cached {
        crate::ui::show_status("PQSigner OS", "Ready");
    }

    NscStatus::Ok as u32
}
