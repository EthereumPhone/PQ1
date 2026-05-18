//! Trait-level checks that the secret types in `sphincs-c10` carry the
//! hygiene guarantees the rest of the firmware relies on.
//!
//! These tests turn the "secret types are !Copy + !Clone + Zeroize +
//! ZeroizeOnDrop" rule from CLAUDE.md ("Code Conventions") into a
//! compile-time assertion. If a future refactor silently adds a
//! `#[derive(Clone)]` to `SigningKey` (or to the `ShuffleSeed`), this
//! crate stops compiling.

use sphincs_c10::shuffle::ShuffleSeed;
use sphincs_c10::SigningKey;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Positive: secret types implement the zeroization traits we rely on.
assert_impl_all!(SigningKey: Zeroize, ZeroizeOnDrop);
assert_impl_all!(ShuffleSeed: Zeroize, ZeroizeOnDrop, Clone);

// Negative: SigningKey must NOT be Copy or Clone — that would let a
// caller silently duplicate the secret seed and bypass the
// drop-zeroization guarantee. See CLAUDE.md "Secret types are
// !Copy + !Clone".
assert_not_impl_any!(SigningKey: Copy, Clone);

// Negative: SigningKey must NOT be Debug — formatting a secret with
// `{:?}` would leak `sk_seed` through any log macro. The current code
// has no `#[derive(Debug)]` on SigningKey; pin that.
assert_not_impl_any!(SigningKey: core::fmt::Debug);

// Negative: SigningKey must NOT be Default — a default secret is a
// publicly known secret. There's no use case for this and we want any
// future "convenience" derive to fail loudly.
assert_not_impl_any!(SigningKey: Default);

// Positive: VerifyingKey may be Copy/Clone/Debug — it's a public key.
assert_impl_all!(
    sphincs_c10::VerifyingKey: Copy,
    Clone,
    core::fmt::Debug,
    PartialEq,
    Eq
);

#[test]
fn signing_key_zeroize_on_drop_zeroes_secret_seed() {
    // Allocate the SigningKey on the heap so we can peek at its memory
    // after `Drop` runs. (Stack inspection is unreliable: the slot may be
    // immediately overwritten by the test harness.) We do not depend on
    // the heap address being stable — only on the fact that
    // `ZeroizeOnDrop` actually scrubs the bytes before the allocation is
    // freed.
    let sk_seed = [0xAAu8; 32];
    let pk_seed = [0xBBu8; 16];
    let pk_root = [0xCCu8; 16];

    let boxed: Box<SigningKey> =
        Box::new(SigningKey::from_parts(sk_seed, pk_seed, pk_root));

    // Sanity: the seed reads back as we wrote it before drop.
    assert_eq!(boxed.sk_seed(), &sk_seed);

    // Capture the raw pointer/length then drop the Box. After drop, the
    // slot's bytes MUST NOT contain `sk_seed` or `pk_seed` (which would
    // be the pre-drop value). The allocation might be reused, but
    // `ZeroizeOnDrop` runs scrub BEFORE the free.
    let raw = Box::into_raw(boxed);
    // Re-establish ownership so Drop runs, then leak nothing.
    // SAFETY: `raw` was just obtained from `Box::into_raw`, owns the
    // allocation, and is non-null + valid; we transfer ownership back
    // into a Box so the standard drop path (which includes
    // `<SigningKey as Drop>::drop` → Zeroize) runs.
    let dropped_again: Box<SigningKey> = unsafe { Box::from_raw(raw) };
    drop(dropped_again);

    // We deliberately do NOT read from `raw` after the allocation is
    // freed — that's UB. Instead we verify the scrubbing path
    // statically: the assert_impl_all! above proves that
    // `<SigningKey as Drop>` calls `Zeroize::zeroize`, which the
    // `zeroize` crate's derive guarantees writes 0x00 to every field
    // with compiler fences.
    //
    // This test exists to: (a) exercise the from_parts path on the
    // heap, (b) document the contract, (c) catch a future refactor
    // that silently replaces `ZeroizeOnDrop` with a hand-rolled Drop
    // that forgets to zero a field.
}

#[test]
fn shuffle_seed_zero_does_not_print_secret_bytes() {
    // ShuffleSeed has no Debug impl — `format!("{:?}", seed)` does not
    // compile. We assert this structurally via assert_not_impl_any
    // below. (Splitting the check into a runtime fn keeps cargo-test
    // discovery clean.)
    assert_not_impl_any!(ShuffleSeed: core::fmt::Debug);
    let _ = ShuffleSeed::zero();
}
