# Returned-coordinate forgery partition

This extends the [adaptive response ledger](RAW-ADAPTIVE-EXPOSURES.md) in the
manual classical ideal-oracle model. The original signer, byte client, observer,
oracle calls, counters, failure behavior and game are unchanged.

`ExposureWidths.ec` proves that every successful response in the existing log
has the actual signature widths, through subsequent adaptive calls and final
verification. `ForsRootDeterminism.ec` proves uniqueness of complete FORS roots
at fixed coordinates in the same public/private tables. It needs no collision
exclusion: this is determinism of the retained reference construction.

`ExposurePrivate.ec` combines each logged response's retained forest reference
with the previous reverse-recovery theorem. Outside the explicit public-node
collision event, an ordinary returned value equals the private-table value at
its exact hypertree/tree/leaf coordinate. The thirteenth value is the complete
tree-12 root, not an ordinary secret at index zero. Widths are used explicitly,
including when changing the default value of an in-range list lookup.

`ExposureCoverage.ec` defines coverage over **all** responses. Each of the
twelve ordinary target coordinates must have been selected by some logged
response at the same hypertree index. Different trees may use different prior
responses. Repeats preserve the predicate; the empty log covers nothing. When
the forged forest has private openings and all coordinates are covered, all
twelve supplied values equal corresponding logged outputs, and its special
root equals a logged special root. Otherwise, the proof identifies an ordinary
coordinate absent from every returned response, together with the supplied
value's exact private-table witness. This is absence from returned coordinates,
not secrecy: public queries, intermediate values, other coordinates or guesses
may still disclose the value.

`ExposureComponents.ec` identifies the component messages of every logged
response using its retained construction references and actual layer signature.
A missing lower-root reference yields a top WOTS message unequal to every
returned top message at that address. A missing forest-root reference similarly
yields a new bottom WOTS message. These results do not exclude previously
disclosed WOTS chain values or prove that either case is hard.

`ExposurePartition.ec` and `ExposurePartitionGame.ec` refine the existing
successful new-message extraction into four residual cases:

1. A top WOTS opening on a new component message.
2. Linked layer openings with a new bottom WOTS component message.
3. Linked private FORS openings with an unreturned ordinary coordinate.
4. Linked private FORS openings covered by accumulated responses, with exact
   returned-value agreement including the special root.

The theorem preserves the original message-freshness guard, public seed/root
binding and signing cap. A separate lemma proves that the forged message's
H_msg input differs from every logged response's H_msg input, using signature
widths. It does **not** assert freshness against prior public queries.

`ExposurePartitionHop.ec::byte_exposure_partition_hop` carries this partition
into the existing real-to-independent probability hop via the exact passive
observer projection. The residual still includes successful forgery `res` and
the public collision/zero exclusions. The collision, zero-node and secret-prefix
charges are unchanged. None of the four residual cases receives a numerical
charge here; the result is not a nontrivial closed EUF bound.

All new modules are replay targets under both proof drivers. Enrollment retains
the old theorem statements and assumption census and introduces no project
axiom, admit or clone assumption. Controls include exact consumers, empty/repeat
and ordinary/special boundaries, a conditional mixed-coverage consumer, scope
probes and deliberately mismatched theorem applications. The mixed consumer
is not a constructed concrete counterexample. Rejected applications do not
prove altered statements false or premises necessary. Scope probes remain
name-level checks rather than full soundness or nonvacuity proofs.

General information-exposure accounting, reverse-chain/private-guess and
encoding/ITSR probability charges, and the final numerical bound remain open
under #100/#295. Rust extraction, concrete SHA-256, QROM and production assurance
remain separate. The combined owner-triggered playbook pass stays deferred
under #509.
