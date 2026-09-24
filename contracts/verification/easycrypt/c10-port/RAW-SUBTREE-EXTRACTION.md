# Linked subtree extraction in the actual C10 byte game

`ByteGameSubtreeExtraction.byte_game_subtree_extraction` strengthens the
[top-layer bridge](RAW-BYTE-TOP-EXTRACTION.md) in the same initialized
`IndependentGame(ByteContext(A))`. Outside the existing public-node collision
and zero-node events, successful new-message verification yields either:

- a top WOTS opening whose message lacks a matching recorded lower-subtree
  root at its digest-derived tree index; or
- linked openings for both WOTS layers, with the lower subtree's recorded
  root equal to the message of the top opening.

Both openings use the supplied signature components and their full-u32
verification counts. The message-hash entry, accepted digest, original public
seed/root, signature widths and final new-message guard remain bound. The
lower WOTS message is still an existential forest value; this result does not
yet extract the FORS leaves or authenticate that value against a recorded FORS
forest.

## Actual computation and references

`LayerRecoveryRecord.raw_layer_recovery_recorded` records the actual WOTS
recovery and authentication-path result. `VerifierLayerRecords.verifier_records_layers`
connects those records across both iterations of the existing verifier.
`LayerRecordExtraction.recorded_layer_extracts` derives a WOTS opening from
such a record and a complete root witness in the retained history. References
are selected logically from existing tables; no reference-building queries or
replacement attacker are introduced.

`LayerReturnedRoot.raw_layer_returns_recorded_root` proves that a successful
actual layer-signing call returns its completely recorded builder root.
`HonestSubtreeMessages.full_sign_subtree_entry` connects successful calls of
the actual adaptive signing interface to a lower-root reference and the top
layer's signed message, tied to the returned signature and its recorded
message hash. The existing `RootSessionHistory.full_client_root_preserved`
theorem preserves each such root through later permitted hash/sign calls,
including failures. This is per-reference persistence, not a completed
accounting theorem for accumulated signature exposures.

`SubtreeOpeningCases.recorded_verifier_subtree_cases` supplies the conditional
descent: if the top message has a recorded matching lower root, the lower
recovery yields its WOTS opening; otherwise the missing-root case remains
explicit. Missing a complete root witness is not a proof that every relevant
secret or chain value was previously unexposed.

## Probability and remaining boundary

`ByteSubtreeOpeningHop.byte_subtree_opening_hop` refines the existing residual
with these cases. All terms still use the same initialized byte game and
client. The successful-forgery event `res` stays explicit, and the public
collision, public zero and secret-prefix charges are unchanged. Neither new
case receives a numerical charge here; this milestone alone supplies no
smaller numerical forgery bound. Honest signatures also have linked openings.

Still open under #100/#295: FORS extraction; distinguishing new component
messages from previously signed or otherwise exposed values; adaptive
accumulated-opening coverage; private preimage/guess and encoding-event
charges; and a nontrivial composed numerical bound. The ten modules add no
project axiom, admit or clone assumption and change no runtime behavior,
parameter or byte format. This remains a manual classical ideal-oracle model;
Rust extraction, concrete SHA-256, QROM and production assurance are separate.
#509 stays deferred.

The 21 added controls comprise seven positives, six scope probes and eight
rejected exact theorem applications. The additional positive checks persistence
of a recorded root under history extension. Rejected exact applications show
only their declared diagnostics, not falsity or premise necessity; the
positives are not complete-game nonvacuity evidence.
