# Actual raw tree construction and reference paths

These classical ideal-oracle proofs supply the recorded reference witnesses
required by the [raw recovery comparison](RAW-PATH-CORRESPONDENCE.md).

## Actual construction, array capture and returned roots

The proof observers copy the actual RawMerkle.build and RawFors.tree
procedures and add a private node catalog. Checked equivalences preserve
the returned values and every oracle effect. A separate equivalence shows
that authentication bookkeeping preserves RawKeygen.root and its oracle
state for any target index.

The catalog is populated by the actual leaf results and parent-hash calls.
Binary-carry stack invariants prove that it contains exactly the completed
nodes, that stack values refer to those nodes, and that the final singleton
stack contains the catalog root. Recorded parent hashes therefore describe
the root actually returned by the builder.

The Merkle kept flags and FORS parity/range branches are checked as written.
For each valid target, the actual returned authentication array contains
the recorded sibling at every level. Width proofs cover all catalog nodes
and returned path elements. No opaque tree-correctness premise or separate
hash oracle is substituted for this construction.

## Complete reference witnesses

TotalBuilderReference proves, with probability one, that actual
independent-oracle construction supplies a 16-byte reference leaf, the
nine-level Merkle or eleven-level FORS authentication path, retained public
hash entries, and their bottom-up equality to the actual returned root.

ForsBuilderSecret additionally supplies a 16-byte reference secret and
its retained initial FORS leaf-hash entry. The value at every FORS catalog
leaf was produced by an actual initial leaf-hash call. This fills the leaf
entry premise as well as the path premise of the FORS recovery comparison.

BuilderTotality instantiates termination for the actual independent-oracle
builders and recovery procedures. The probability-one statements therefore
include termination, rather than relying only on partial correctness.

## Actual construction followed by recovery

MerkleBuilderComparison and ForsBuilderComparison execute the actual
builder and then actual recovery on a supplied candidate. They preserve
the constructed reference witness through recovery. A matching root implies
the same reference leaf/secret or an explicit retained collision event.
The collisions concern 16-byte node outputs from distinct raw inputs.

The comparisons retain the candidate length and width requirements.
They are component statements, not a complete adaptive signing game.
They provide no numerical probability charge for the collision events.

## Actual FORS signing

The private-provenance relation additionally links each FORS leaf to the
digest retained under its actual private derivation key. A previously
returned derivation persists through tree construction. The reference
secret therefore equals the secret returned by the actual signing procedure.

ForsSignRecord proves that the actual signature contains that retained
initial leaf entry and authentication path. ForsSignCorrect proves, with
probability one, that signing followed by recovery returns the tree root
computed during that signing call. Its proof observer retains the internal
root while preserving the real signature, recovery result and oracle effects.
This does not identify an independently generated external root without the
later composition proof.

## Boundary

The WOTS leaf/signature relation, the special FORS tree with an omitted
path, full component composition and accumulated adaptive opening coverage
remain open. No numerical end-to-end forgery bound is established.

The results allow zero nodes and retain the WOTS invalid-sum sentinel in the
later component obligation. No project axiom, admit or clone assumption is
added. The independent-table intermediate game is the scope of the recorded
history predicates; the whole-game secret-prefix hop does not transfer them
literally to physical Rust. This remains manual-model verification, without
Rust extraction, a concrete SHA-256 theorem, QROM or production authority.

The remaining work stays under #100/#295. The combined owner-triggered
playbook pass #509 remains deferred.
