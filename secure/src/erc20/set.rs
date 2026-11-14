//! Several Merkle-proven ERC-20 bundles per request (`CAP_ERC20_BUNDLE_SET`),
//! verified against the firmware-pinned [`crate::db_roots::ERC20_DB_ROOT`],
//! plus the fault-injection A/B proof the sign handlers run on the built set.
pub use pqsigner_tx::erc20::set::{
    parse_erc20_set_envelope, DupPolicy, Erc20Scope, Erc20Set, Erc20SetError,
    InsertOutcome,
};

use crate::db_roots::ERC20_DB_ROOT;

/// Build a request's set from the primary slot and the envelope.
pub fn build_erc20_set<'a>(
    slot0: &'a [u8],
    env: &'a [u8],
    chain_id: u64,
    policy: DupPolicy,
) -> Result<Erc20Set<'a>, Erc20SetError> {
    pqsigner_tx::erc20::set::build_erc20_set(slot0, env, chain_id, &ERC20_DB_ROOT, policy)
}

/// Verify one bundle into `set` (batch: one call per trailer record).
pub fn insert_verified<'a>(
    set: &mut Erc20Set<'a>,
    bundle: &'a [u8],
    chain_id: u64,
    policy: DupPolicy,
) -> Result<(), Erc20SetError> {
    pqsigner_tx::erc20::set::insert_verified(set, bundle, chain_id, &ERC20_DB_ROOT, policy)
}

/// Fault-injection A/B proof of a built set: rebuild it from the same
/// snapshot bytes after a random delay and compare entry-for-entry,
/// including the borrowed slices' addresses. Writes `OK_SENTINEL` to
/// `verdict_out` only on an exact match; the caller fail-initialises the
/// slot and reads it twice around another random delay.
#[inline(never)]
pub fn prove_erc20_set(
    slot0: &[u8],
    env: &[u8],
    chain_id: u64,
    policy: DupPolicy,
    built: &Erc20Set<'_>,
    verdict_out: &mut u32,
) {
    crate::fi::wait_random();
    let rebuilt = build_erc20_set(
        core::hint::black_box(slot0),
        core::hint::black_box(env),
        core::hint::black_box(chain_id),
        policy,
    );
    let same = matches!(&rebuilt, Ok(r) if r.same_entries(built));
    let verdict = crate::fi::check_true_into_sentinel(|| core::hint::black_box(same));
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: unique caller-owned slot, fail-initialised by the caller.
    unsafe { core::ptr::write_volatile(verdict_out, verdict) };
}

/// Run [`prove_erc20_set`] with the double-read verdict protocol and
/// return `true` only when both reads carry `OK_SENTINEL`.
#[inline(never)]
pub fn erc20_set_proven(
    slot0: &[u8],
    env: &[u8],
    chain_id: u64,
    policy: DupPolicy,
    built: &Erc20Set<'_>,
) -> bool {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique live local; volatile so a skipped proof leaves FAIL.
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    prove_erc20_set(slot0, env, chain_id, policy, built, &mut verdict);
    // SAFETY: same live local.
    let a = unsafe { core::ptr::read_volatile(&verdict) };
    crate::fi::wait_random();
    // SAFETY: second independent read after a random delay.
    let b = unsafe { core::ptr::read_volatile(&verdict) };
    crate::fi::scrub_sentinel_register();
    a == crate::fi::OK_SENTINEL && b == crate::fi::OK_SENTINEL
}

/// Batch variant of [`erc20_set_proven`]: rebuild the batch-wide set from
/// the ERC-20 trailer records (`bundles`, in record order) under
/// [`DupPolicy::CoalesceIdentical`] after a random delay, and compare it with
/// the one the routing loop built. Double-read verdict as above.
#[inline(never)]
pub fn erc20_batch_set_proven<'a>(
    bundles: impl Iterator<Item = &'a [u8]>,
    chain_id: u64,
    built: &Erc20Set<'_>,
) -> bool {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique live local; volatile so a skipped proof leaves FAIL.
    unsafe { core::ptr::write_volatile(&mut verdict, crate::fi::FAIL_SENTINEL) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    crate::fi::wait_random();
    let mut rebuilt = Erc20Set::new();
    let mut ok = true;
    for b in bundles {
        if insert_verified(
            &mut rebuilt,
            core::hint::black_box(b),
            core::hint::black_box(chain_id),
            DupPolicy::CoalesceIdentical,
        )
        .is_err()
        {
            ok = false;
        }
    }
    let same = ok && rebuilt.same_entries(built);
    let v = crate::fi::check_true_into_sentinel(|| core::hint::black_box(same));
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: same live local.
    unsafe { core::ptr::write_volatile(&mut verdict, v) };
    // SAFETY: same live local, read twice around a random delay.
    let a = unsafe { core::ptr::read_volatile(&verdict) };
    crate::fi::wait_random();
    // SAFETY: as above.
    let b = unsafe { core::ptr::read_volatile(&verdict) };
    crate::fi::scrub_sentinel_register();
    a == crate::fi::OK_SENTINEL && b == crate::fi::OK_SENTINEL
}
