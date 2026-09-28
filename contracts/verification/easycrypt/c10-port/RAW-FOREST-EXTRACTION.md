# Actual FORS extraction in the C10 byte game

`ByteGameForestExtraction.byte_game_forest_extraction` strengthens the
[subtree bridge](RAW-SUBTREE-EXTRACTION.md) in the same initialized
`IndependentGame(ByteContext(A))`. Outside the existing public-node collision
and zero-node events, successful new-message verification yields one of three
explicit cases:

- a top WOTS opening whose message lacks a matching recorded lower-subtree root;
- linked WOTS openings in both layers, whose lower message is the actual
  recovered forest, but that forest lacks a complete recorded construction
  reference; or
- those linked openings with a complete forest reference, identifying the
  twelve supplied ordinary FORS secrets with actual private derivations at
  the digest-selected coordinates and the thirteenth supplied component with
  a completely recorded tree-12 root.

The thirteenth component is a root-as-secret, not a thirteenth private leaf.
The actual special hash and forest compression are included in the comparison.
The accepted message-hash entry, original public seed/root, exact signature
widths, full-u32 WOTS verification counts and final new-message guard remain
bound. No new oracle queries or replacement attacker are used.

## Actual computation and construction references

`ForestRecoveryRecord.raw_forest_recovery_recorded` follows the twelve actual
authentication paths, the special last hash and compression.
`VerifierForestRecords.verifier_records_forest` retains the exact recovered
forest as the message consumed by the lower WOTS layer, and that layer's result
as the message consumed by the top layer.

`ForsRootWitness.fors_root_reference_at` selects a reference opening at any
valid later index from a complete recorded catalog and actual private-leaf
origins. `ForsRecordExtraction.recorded_fors_extracts` compares the supplied
path and leaf hash with that reference. `ForestRecordExtraction.recorded_forest_extracts`
then compares the full fixed-width compression and the special last hash.
Public-node collision exclusion is load-bearing for those comparisons.
Reference selection is logical selection from existing histories.

`ForestRootRecording.raw_forest_sign_root` establishes complete references
from actual shuffled forest signing, including the special last tree.
`HonestForestMessages.full_sign_forest_entry` connects successful calls of the
actual adaptive signing interface to the forest reference, returned secrets
and authentication paths, and the first layer's signed message, tied to the
returned signature and accepted message hash. Signing failure remains explicit.
`ForestReferenceHistory.full_client_forest_preserved` preserves each such
complete reference through later permitted hash/sign calls, including failures;
`public_verifier_forest_preserved` covers subsequent verification. These are
per-reference persistence results, not accumulated exposure accounting.

## Probability and remaining boundary

`ByteForestOpeningHop.byte_forest_opening_hop` refines the existing probability
residual with these cases in the same initialized byte game. The successful
forgery event `res` remains explicit. The public collision, public zero and
secret-prefix charges are unchanged. None of the three cases receives a new
numerical charge here, so this milestone supplies no smaller numerical bound.

Missing a complete root witness does not imply that every relevant private
leaf or chain value was previously unexposed. Conversely, the linked private
openings may also occur for honest signatures or reused values. Distinguishing
new component messages from prior adaptive exposures, accumulated opening
coverage, private preimage/guess and encoding-event charges, and a nontrivial
composed numerical forgery bound remain open under #100/#295.

The eighteen modules add no project axiom, admit or clone assumption and change
no runtime behavior, parameter or byte format. This remains a manual classical
ideal-oracle model. Rust extraction, concrete SHA-256, QROM and production
assurance are separate; #509 stays deferred.

The 34 added controls comprise thirteen positives, eleven scope probes and ten
rejected theorem applications (nine statement mismatches and one unfinished
width obligation). One positive proves an encoding
counterexample: two distinct lists of thirteen rows have the same forest
compression input when individual row widths are unrestricted. It establishes
that row count alone does not make this encoding injective. The special-root
positive checks the distinct tree-12 semantics. Rejected applications
show only their declared diagnostics, not falsity or premise necessity; the
positives are not complete-game nonvacuity evidence.

The later [adaptive response ledger](RAW-ADAPTIVE-EXPOSURES.md) accumulates
these references for every successful returned output, with exact original-game
projection, list multiplicity and cap accounting. It does not close general
information exposure or assign private/encoding probability charges.
