# Reverse WOTS recovery at deployed C10 geometry

`RawWotsExtraction.raw_wots_extracts_opening` connects an actual WOTS recovery
to its retained reference key. If recovery returns that key, then the final
public history contains a public-node collision, contains a zero node, or
the supplied signature opens the reference chains at the accepted message
digits. The two bad events are the events already charged in
[the byte-game bound](RAW-ZERO-NODE-CHARGE.md).

The proof records the actual counter query, all 43 recovery suffixes and the
key-compression query. Equal compression outputs identify equal compression
inputs outside the charged collision event. The 32-byte padded rows identify
each endpoint. Reverse comparison of recorded chains then identifies every
signature node, including digit 7, whose recovery suffix is empty. The proof
uses the existing memoized public/private tables; it adds no project axiom,
admit or clone assumption.

`VerifierWotsOpening.wots_verifier_opening` deliberately has the full wire
counter range, `0 <= count < 2^32`. The existing signing witness instead has
`count < 10000000`. The verifier does not enforce that signing-search limit. `VerifierWotsReplay.raw_wots_recovers_verifier_opening` supplies the
forward replay implication for the new predicate. Neither direction claims
that a bounded signing search must succeed.

`LayerWotsExtraction.raw_layer_extracts_wots_opening` composes actual WOTS
and Merkle recovery. Its explicit premises include a retained reference WOTS
key and a recorded nine-node reference path at the same address, plus the
supplied signature's exact widths. Matching the reference tree root implies
the same two bad events or a verifier opening of that reference WOTS key.
Both the reference and recovery trace survive subsequent public queries.

`WotsKeyExtraction.total_actual_wots_key_extraction` obtains the key from
actual `RawKeygen.leaf`; `LayerBuildExtraction.total_actual_layer_builder_extraction`
obtains the reference key and path from actual `RawMerkle.build`. Their
probability-one statements include termination of these concrete procedures.
These comparison harnesses create their references before recovery. They
are not the complete adaptive byte-session forgery game.

The thirteen added modules are direct and interactive proof targets in the
split closure, with statement/operator pins and source bindings. The 22 added
controls comprise five positive checks, eight scope probes and nine exact
statement mismatches. The positive checks include explicit unequal inputs
with equal retained outputs, unequal rows with equal flattenings, and a wire
counter outside the signing search range. These small examples establish
only their stated properties. A negative `exact` diagnostic does not prove
the altered theorem false or establish that every premise is necessary.

The [byte-game bridge](RAW-BYTE-TOP-EXTRACTION.md) now connects arbitrary
successful complete verification to a top-layer reference opening from the
earlier key-generation history. Lower-layer/FORS extraction, accumulated
adaptive opening coverage, and private preimage/guess and encoding-event
charges remain open in the initialized game. This result does not bound those events,
finish the WOTS/FORS forgery reduction, or close the numerical EUF bound.
Issues #100 and #295 remain open. The model is classical and manually written;
Rust extraction, concrete SHA-256 and QROM remain separate boundaries.
