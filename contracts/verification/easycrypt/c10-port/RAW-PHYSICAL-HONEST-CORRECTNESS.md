# Honest serialized correctness in the shared-oracle prefix game

`HonestBytePhysical.physical_honest_byte_error_concrete` applies the existing
whole-context secret-prefix theorem to actual key generation, signing,
serialization, parsing and verification. The physical game samples one
uniform 256-bit secret and uses a single shared memoized hash table for
public hashes and secret-prefixed private derivations.

The error event is a returned signature whose encoding is not exactly 4008
valid bytes or whose parsed signature fails verification against the earlier
root. Optional signing failure is explicitly outside that event.

The independent-table game has error probability zero by exact equivalence
to the checked fresh byte-signing harness. The existing same-client prefix
hop then bounds the physical game's error by

`30520798 * (1/2)^256`.

The checked public-query allowance is `3 * signing_budget + 520798`, with the
actual deployed model's `signing_budget = 10000000`. It includes key generation,
the message grind, both layer count searches, signing components and the
verification call. Cached public calls remain charged; no fresh-sampling
assumption is substituted for them.

This is an honest-correctness error bound in a classical random-oracle model.
It is not a forgery bound, a claim of guaranteed signing success, Rust
extraction, concrete SHA-256 security, QROM or production authority.
Adaptive opening coverage, component forgery reduction and the numerical
end-to-end unforgeability result remain open under #100/#295. The combined
owner-triggered playbook pass #509 remains deferred.
