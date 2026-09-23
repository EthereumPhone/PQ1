# Raw authentication-path correspondence

These classical ideal-oracle results extend the
[complete-session history model](COMPLETE-SESSION-HISTORY.md) on the
verifier side of the remaining component reduction.

## Actual recovery and retained state

RawPathReplay proves that the actual nine-level RawMerkle.recover records
its authentication path in Independent.rawhistory. Its returned root equals
bottom-up evaluation of that path using the retained entries in the final
table. RawForsPathReplay proves the corresponding result for the initial
FORS secret-to-leaf hash and eleven authentication levels.

PathReplay and PathOracle prove persistence under memoized table extension.
RecoveryHistory instantiates the public-hash-only interfaces with the actual
Merkle and FORS recovery procedures. A previously recorded reference path
and its root remain valid through a new recovery call.

These are statements about the actual memoized intermediate-game oracle.
They do not replace it with a stateless function or assume new independence
for cached inputs.

## Concrete comparison against a recorded reference

RawPathComparison.merkle_recover_leaf_or_collision proves that a recovery
which returns a recorded reference root either starts from that reference
leaf or produces a recorded node-hash collision. The collision has two
distinct raw inputs at the same height and parent index.

RawForsComparison.fors_recover_secret_or_collision includes the first leaf
hash: returning the reference root implies the reference secret, a recorded
leaf-hash collision, or a recorded path-hash collision.

The premises are explicit: the reference hash/path entries must already
exist, the reference root must be their computed value, authentication-path
lengths must be nine or eleven as appropriate, and the compared leaves,
secrets and sibling nodes must have the stated 16-byte widths.

The width condition matters for raw-input separation. A checked countermodel
shows that differently split variable-length child values can produce the
same padded concatenation. This is outside the required node widths.

The node-collision events concern the 16-byte node projection, not equality
of complete 256-bit digests. No probability bound for these events is supplied
by this milestone.

## Boundary

The reference-path premises are not discharged by these results. A complete
component reduction still needs to connect the actual stack-based honest
tree construction to those reference witnesses, handle WOTS recovery and the
special omitted-path FORS tree, and compose the components with accumulated
adaptive opening coverage.

Zero nodes are allowed by the path lemmas. The actual WOTS invalid-sum
sentinel therefore remains part of the later WOTS/component obligation.
No nonzero-leaf premise is introduced to exclude it.

The independent-table intermediate game remains the scope of these recorded
history predicates. The existing whole-game prefix hop does not make them
literal physical-Rust invariants. The work remains manual-model verification;
no Rust extraction, concrete SHA-256, QROM, numerical end-to-end EUF or
production claim follows.

## Controls

Positive controls prove that two actual Merkle recovery calls, or two actual
FORS recovery calls, return the same root from the same inputs. A third checks
the width counterexample. Four negative controls remove reference history,
the FORS leaf entry, width equality or module privacy. Four scope probes cover
the new headline environments.

The remaining component and accumulated-opening work stays tracked under
#100/#295. Owner-triggered combined playbook pass #509 remains deferred.
