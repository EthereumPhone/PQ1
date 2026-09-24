# Actual key generation, signing and verification

`ActualSignerCorrect.total_actual_signer_correct` proves honest total
correctness for the actual structured C10 procedures over the same memoized
independent oracle. The harness calls `RawKeygen.root(seed,1,0)`, then
`RawSigner.sign` with that padded root, then the actual `RawSigner.verify`
when signing returns a signature. Every returned signature verifies against
the earlier key-generation root. If signing returns `None`, the harness
records verification as false without a verification call.

The probability-one statement includes termination. It does not assert
that grinding or the bounded WOTS count search always succeeds, and it
introduces no nonzero-node or artificial success premise.

## The checked connection

The forest opening contains all twelve ordinary paths, the special
thirteenth root-as-secret leaf hash and the exact compression entry.
Both layer openings contain actual WOTS and Merkle paths. Earlier entries
persist as the real procedures extend the public and private memo tables.

The eighteen-bit hypertree index follows the actual two divisions by 512.
After the second layer the tree coordinate is zero. A proof observer adds
only a list of intermediate roots to the actual finish loop; equivalence
preserves its optional signature and all oracle effects. The resulting
trace connects the forest root, both layer messages/signatures and the
separately generated top root.

The existing accepted-grind observation identifies the signature's actual
randomizer and retained accepting H_msg digest. The verifier repeats that
entry, the forest recovery and both layer recoveries, reaching the same
padded root. No fresh-sampling or independent-cached-output assumption is
substituted for the retained histories.

## Boundary

This is honest correctness of the structured manual model. The
[byte-signature result](RAW-BYTE-SIGNER-CORRECTNESS.md) separately proves
serialization/parsing correctness for the generated signatures. The physical
prefix-oracle transfer and Rust extraction remain separate boundaries.

It is not an unforgeability theorem. Accumulated adaptive opening coverage,
component forgery reduction, bad-event probability charges and a meaningful
numerical end-to-end bound remain open under #100/#295. No concrete SHA-256,
QROM, hardware or production claim follows. The combined owner-triggered
playbook pass #509 remains deferred.
