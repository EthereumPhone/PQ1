# Remaining cryptographic and implementation limits

Research checkpoint: 2026-10-26, following the initialized classical byte-game
bound in [RAW-NUMERICAL-EUF.md](RAW-NUMERICAL-EUF.md). This page separates
possible next proofs from assumptions that cannot be removed by changing a
status label. Remaining research is tracked under PQ1 #100; #295 is closed.

## Separate PMF stateful-client stopping boundary

The separate [Lean probability project](../../probability/README.md#stateful-byte-clients-without-a-fixed-stopping-bound)
now covers directly defined stateful PMF byte clients without a uniform bound
on attempted interactions. The client may sample fresh randomness after replies
and take internal steps. Exact finite-cutoff compilation preserves the byte
result, admitted caps, persistent ledger and full memo table; public-key family
sampling composes actual key generation. The independently defined initialized
execution uses that same hidden prefix, public key and cache throughout.

Completed masses have a proved monotone limit. Under almost-sure termination
of that execution, the limit has mass one and defines its terminal PMF without
rescaling. The existing finite forgery and signing-availability bounds imply
the same capped terminal bounds; they are not extra hypotheses. Their real
forms, `2^-38` availability endpoint and `2^-50`/`2^-34` forgery examples retain
the existing admitted caps and worst-case grinder charges. A whole-game
geometric witness terminates almost surely while retaining positive pending
mass at every finite cutoff; an always-running kernel has zero terminal mass.

This removes the fixed stopping bound for the specified classical PMF client
interface. Earlier finite-client results remain unchanged. Representation of
arbitrary effectful Rust/EasyCrypt clients, execution equality across those
tools, concrete SHA correspondence, ideal-oracle hardness, QROM, entropy and
physical evidence remain separate boundaries. This extension changes no native
EasyCrypt source or environment assumption, and does not improve the existing
conservative forgery charges. Full replay and review remain separate evidence
requirements.

## Functional bounded-search backend interpretation

The paired representation now supplies `wots_first_slot` and `fors_first_slot`:
zero means exhaustion, and a positive value is the first accepted index plus
one. Both definitions come from the existing integer/list expression tree.
The only new primitive is signed integer subtraction; count subtraction stays
saturated, and every earlier generated definition is unchanged.

[`C10FunctionalSearch.lean`](../../extracted/Extracted/C10FunctionalSearch.lean)
connects the actual extracted `wots.find_count` and `fors.grind_r` results to
these selectors at the ten-million-trial cap. It preserves the returned WOTS
count, digest and digits, the FORS randomizer and digest in both OptRand modes,
and the exact assertion-failure result on exhaustion. Generic first-hit laws
establish the earliest hit and exhaustion without a success-existence premise
or concrete evaluation of ten million SHA computations. The 21 new Lean
headlines use only kernel axioms.

[`C10FunctionalSearch.ec`](cdrafts-split/C10FunctionalSearch.ec) connects the
original native `RawWots.count` and `RoleGrind.run` callers to the same selectors
through their paired callers. `C10FixedBackend` is a separate deterministic,
memoizing interpretation. Its complete prior history must agree with the fixed
function; it is retained through every call. The proofs give the exact queried
prefix and final history, one hash call per WOTS attempt, and two per FORS
attempt, including full exhaustion. The native correspondence also requires
256-bit backend outputs. Empty consistent history and a fixed-width function
are proved witnesses, so these premises do not assume the desired outcome.
The six new modules contain 46 lemmas and introduce no project axiom or admit.

This closes a functional bounded-search component under the disclosed backend
interpretation. It does **not** identify the executable Lean SHA model with
RustCrypto, STM32 SHA, or EasyCrypt's sampled `Shared` oracle. The generated
printers and cross-tool interpretation remain TCB, and the full Rust/EasyCrypt
keygen/sign/verify/session relation remains open. In particular, the ideal-oracle
availability and forgery bounds below do not transfer to this fixed backend.
Full replay, source identities and review are separate landing evidence; the
[control owner](CONTROL-EVIDENCE.md#functional-bounded-search-controls) states
the exact mutation coverage and its limits.

## Functional WOTS values under the fixed backend

The shared representation now also defines secret derivation, ordered chain
evaluation, all 43 key-generation endpoints and their compression, signature
values, and recovery including its sixteen-zero-byte rejection result. Its
typed extension permits only a pure bytes-to-bytes function parameter and
application, plus explicit count/integer conversions. Integer-to-count clamps
negative values to zero in both printers; earlier definitions retain their
bytes. Pure function applications do not themselves model oracle calls.

[`C10FunctionalWots.lean`](../../extracted/Extracted/C10FunctionalWots.lean),
[`C10FunctionalWotsSign.lean`](../../extracted/Extracted/C10FunctionalWotsSign.lean)
and [`C10FunctionalWotsRecover.lean`](../../extracted/Extracted/C10FunctionalWotsRecover.lean)
connect the actual extracted secret, chain, compression, keygen, shuffled-sign
and recovery procedures to those expressions. The 21 new audited headlines
have kernel-only axiom closures. Signing retains both the first accepted
counter and exact assertion failure at exhaustion. Recovery retains the full
u32 counter domain and the target-205 rejection branch; chain correspondence
covers every non-overflowing u32 window, including zero steps.

Seven native modules, from [`C10FunctionalWotsValue`](cdrafts-split/C10FunctionalWotsValue.ec)
through [`C10FunctionalWotsSign`](cdrafts-split/C10FunctionalWotsSign.ec),
prove the corresponding actual `RawKeygen.leaf`, `RawWots.sign`,
`RawWotsFill.sign` and `RawWots.recover` results under `FixedPrefix`.
Their 59 lemmas introduce no project axiom or admit. They retain arbitrary
backend-consistent prior history, frame the key and function, and specify the
ordered final history and exact query cost. Key generation takes 345 calls;
signing includes the bounded search, optional four-call shuffle and visited
secret/chain computations. Permuted writes give the same positional signature.
Recovery includes its digest, accepted suffix chains and compression, or just
the rejected digest call. Termination is proved without eventual acceptance.

This closes the selected functional WOTS component under the disclosed
backend interpretation. The next component is the FORS/Merkle recovery
bridge below; construction, forest/layer composition and complete functional
signer/verifier values are covered below. Initialized sessions remain open.
The paired printers, function
interpretation, concrete RustCrypto/STM32 correspondence, sampled-oracle
transfer and QROM/physical assumptions remain explicit limits. The ideal-model
probability bounds do not transfer through a deterministic interpretation.
[Control coverage](CONTROL-EVIDENCE.md#functional-wots-value-controls), full
replay, source identities and review are separate evidence requirements.

## Functional FORS and Merkle recovery values

Seven appended shared operators define FORS private derivation and leaf
hashing, pair hashing, an ordered authentication-path step/fold, and the
eleven-level FORS and nine-level XMSS recovery values. They use the existing
typed expression constructors and deterministic backend interpretation;
earlier generated definitions are preserved.

[`C10FunctionalTrees.lean`](../../extracted/Extracted/C10FunctionalTrees.lean)
connects the actual extracted `fors_secret`, `reconstruct_fors_root` and
`verify_auth_path` results to those values. Its 15 named theorems have
kernel-only axiom closures. Every u32 target/index is included, even outside
the corresponding tree's leaf range. FORS retains full u32 hypertree/tree
fields, and XMSS retains full u32 layer and u64 tree fields. The proofs preserve
parent division, sibling ordering, height, domain/keypair fields, padding and
sixteen-byte truncation.

[`C10FunctionalTreeValue`](cdrafts-split/C10FunctionalTreeValue.ec),
[`C10FunctionalMerkle`](cdrafts-split/C10FunctionalMerkle.ec) and
[`C10FunctionalForsRecovery`](cdrafts-split/C10FunctionalForsRecovery.ec)
add 18 lemmas without new project axioms or admits. The actual `RawFors.recover`
and `RawMerkle.recover` contracts preserve arbitrary backend-consistent
prehistory, frame the key and function, and give the ordered resulting history
and exactly 12 or 9 calls, respectively. FORS includes the initial secret-to-leaf
hash; XMSS begins with the supplied leaf. Losslessness is separate from result
equality. The private-derivation lemma also connects `FixedPrefix.derive` to
the shared FORS secret value.

This closes recovery computations under the disclosed interpretation. Root and
authentication-path construction, forest/layer composition and complete
functional signer/verifier values are covered below. Initialized sessions remain
open. Paired-printer and
backend interpretation, concrete RustCrypto/STM32 correspondence, sampled-oracle
security transfer and QROM/physical boundaries remain open. No ideal-model
probability bound transfers from these deterministic functional equalities.
[Controls](CONTROL-EVIDENCE.md#functional-tree-value-controls), full replay,
source identity and review remain separate requirements.

## Functional FORS and XMSS construction values

Twelve appended shared operators specify finite tree levels, roots and sibling
paths, then instantiate the FORS leaves and 512 WOTS public-key leaves. The
existing expression constructors are unchanged, and all fifty earlier generated
definitions are preserved. These expressions specify values; they do not impose
a new oracle execution order.

[`C10FunctionalBuilders.lean`](../../extracted/Extracted/C10FunctionalBuilders.lean)
connects the actual extracted FORS root/sign and XMSS root/authentication builders
to those shared values. Four new proof modules contribute 41 kernel-only
headlines, including the generic recurrences and the actual out-of-tree branches.
The top-level results cover every u32 target, not only valid leaves: FORS keeps
eleven zero authentication nodes outside 2,048 leaves, while XMSS keeps nine
outside 512 leaves. FORS still derives the requested target's secret, and XMSS
still returns the independently constructed root. Full u32 FORS fields and
u32/u64 XMSS layer/tree fields are retained. This is the existing callback-free,
release extraction boundary.

Eleven native modules culminate in
[`C10FunctionalBuildContracts`](cdrafts-split/C10FunctionalBuildContracts.ec),
with 128 new lemmas and no new project axiom or admit. The actual Raw and
CommonInput callers agree on return values and their complete backend state.
FORS root/tree construction makes exactly 6,143 calls, FORS signing 6,144,
and XMSS root/build construction 177,151. Losslessness is proved separately
for both caller forms.

The history contract is exact for every input key: construction queries map to
the supplied function's digest, and every other entry equals the initial map.
It retains arbitrary consistent prehistory, handles repeated queries, and frames
the key and function. FORS signing also retains its initial target-secret query,
including an out-of-tree target. This is an exact final-map contract, not an
ordered transcript; actual Raw/CommonInput execution equivalence and call
counts are separate statements. It assumes neither an empty initial history
nor a desired return value.

[Controls](CONTROL-EVIDENCE.md#functional-construction-controls) exercise both
printers and unchanged consumers. Forest/layer composition is covered below.
Complete signer/verifier/session composition, paired-printer and backend interpretation, concrete RustCrypto or
STM32 behavior, progress callbacks, sampled-oracle transfer, and QROM/physical
assumptions remain outside this result. The component does not transfer the
ideal-model probability bound. Full replay, source identity and review remain
separate requirements.

## Functional forest and layer caller values

Ten appended expressions reuse the existing typed constructors; all 62 earlier
expression trees are preserved. They compose twelve ordinary FORS paths, the
separate root-as-secret slot 12 and forest compression, plus the bounded WOTS
selector and the layer signature/recovery values. The zero selector still
means exhaustion, and a positive selector is the first accepted counter plus
one. The signature expression is consumed only for the actual accepted counter;
it does not assume that a successful search exists.

[`C10FunctionalForest.lean`](../../extracted/Extracted/C10FunctionalForest.lean),
[`C10FunctionalForestRecover.lean`](../../extracted/Extracted/C10FunctionalForestRecover.lean)
and [`C10FunctionalLayer.lean`](../../extracted/Extracted/C10FunctionalLayer.lean)
contribute 18 kernel-only headlines. The factored extracted forest-signing
phase and its actual compression call consume the shared secrets, paths and
result; the factored verifier forest block consumes the shared recovery value
for arbitrary u32 indices. The actual hypertree signing-loop body retains its
serialized continuation, recovered root, accepted count or exact assertion
failure. Forest signing uses the existing first-twelve-index bound below 2048;
the complete digest caller must discharge that premise when composed. Layer
signing uses the actual two-layer/9-bit leaf domain, while recovery retains
full u32 counters and coordinates.

Nine native modules culminate in
[`C10FunctionalForestSign`](cdrafts-split/C10FunctionalForestSign.ec),
[`C10FunctionalForestRecover`](cdrafts-split/C10FunctionalForestRecover.ec),
[`C10FunctionalLayerSign`](cdrafts-split/C10FunctionalLayerSign.ec) and
[`C10FunctionalLayerRecover`](cdrafts-split/C10FunctionalLayerRecover.ec).
Their 60 lemmas add no project axiom or admit. Raw/CommonInput callers agree on
results and complete backend state. Forest signing takes 80,017 calls plus its
explicit zero/nonzero-seed derivation and permutation costs; recovery takes
146. Layer signing includes the 177,151-call builder, derivation, bounded search
and, on success, recovery. Exhaustion retains construction and search effects:
10,177,151 calls plus zero or one derivation call. Recovery preserves the
WOTS zero-node rejection continuation through all nine XMSS levels. Separate
losslessness results require no eventual-success premise.

Every state contract allows arbitrary backend-consistent prior history and
frames the key/function. Construction and shuffled forest phases specify final
maps pointwise, retaining untouched keys; subsequent queries are explicit
remember operations. Intermediate maps are existentially quantified outputs
constrained by these exact pointwise relations, not assumed desired maps or
ordered transcript claims. The separate Raw/CommonInput equivalences retain
the actual execution state.

[Controls](CONTROL-EVIDENCE.md#functional-forest-and-layer-caller-controls),
full cold replay, exact source identities and the combined review remain
separate requirements. The complete verifier component is described below.
Complete release signing is described below. Initialized session composition remains next, including
the secure wrapper's two signing calls and verification cost.
Paired-printer and backend interpretation, concrete RustCrypto/STM32 behavior,
callback non-interference, sampled-oracle security transfer and QROM/physical
assumptions remain explicit limits. These deterministic equalities do not
transfer the ideal-model probability bound or grant production authority.

## Functional complete verifier values

Six appended expressions in the existing typed representation compose the
message digest, its FORS indices, forest recovery and both hypertree layers.
All 72 earlier definitions and the expression language are preserved. The
Boolean endpoint adapters check the shared forced-zero field and compare the
padded recovered root with the supplied root. They retain the raw verifier's
WOTS zero-node continuation through all nine XMSS levels.

[`C10FunctionalVerifier.lean`](../../extracted/Extracted/C10FunctionalVerifier.lean)
connects the actual `hypertree.verify` entry point to these values and the
existing shared decoder for every represented 4,008-byte signature. Its
`decoded_verifier_result` has no valid-signature, digest-acceptance, WOTS-success
or desired-result premise. It includes actual seed/root/randomizer/message
padding, the forced-zero refusal, all forest fields, both decoded layers and
the final comparison. The digest-index bounds are derived from the actual
digest. Nine headlines are enrolled in the exact kernel-only closure gate.

[`C10FunctionalVerifierValue`](cdrafts-split/C10FunctionalVerifierValue.ec),
[`C10FunctionalVerifierState`](cdrafts-split/C10FunctionalVerifierState.ec) and
[`C10FunctionalVerifier`](cdrafts-split/C10FunctionalVerifier.ec) add fourteen
lemmas. The actual native Raw/CommonInput verifier results and full backend
state agree. Structured Raw verification retains its existing two-u32-counter
condition; the 4,008-byte decoded endpoint discharges it. The common caller
contract admits arbitrary backend-consistent prehistory, including repeated
queries, and preserves the key and function. Its exact final history and call
count include the message query and, on digest acceptance, all forest and layer
effects. Refusal takes one call; the other branch takes 147 plus the two exact
layer recovery costs. Separate losslessness proofs assume no acceptance.

This closes the complete fixed-backend verifier component under the existing
printer and primitive interpretations. It does not identify either backend with
concrete RustCrypto/STM32 execution or a sampled oracle, nor transfer the
ideal-model probability bound. Complete release signing is covered below; initialized cross-language
session interpretation, callbacks and physical/QROM assumptions remain open.
The fixed-backend initialized-session and wrapper composition is described below.
The [control owner](CONTROL-EVIDENCE.md#functional-complete-verifier-controls)
records the ten typed mutations and the strengthened supplementary layer
examples from #1043. Full replay, exact source identities, required review and
actual CI remain separate landing evidence.

## Functional complete release-signer values

Seven appended definitions in the existing typed representation specify the
randomizer, message digest, bounded nonce schedule and selector, node and layer
encoding, and complete signature encoding. All 78 earlier definitions and the
expression language are preserved. The explicit Result/option adapters retain
exhaustion; they do not assume a successful search or a valid generated key.

[`C10FunctionalSigner.lean`](../../extracted/Extracted/C10FunctionalSigner.lean)
connects the actual extracted `release_sign_inner` caller to the shared nonce,
forest and two-layer values. The header retains both OptRand encodings and the
first accepted nonce at the ten-million-trial cap. Digest-derived coordinates,
the special thirteenth FORS secret, both layer searches, sequential messages and
positional serialization are composed from their existing component proofs.
`extracted_signer_bytes` gives the exact returned 4,008-byte array, including
every byte of both u32 counters. Failure remains the same Result, with no
success or final-root-equality premise. This is the release caller: it does not
invent the checked configuration's final debug root guard. Five new Lean
modules enroll 38 kernel-only theorem closures.

[`C10FunctionalSignerBytes`](cdrafts-split/C10FunctionalSignerBytes.ec) reaches
the actual native `RawSigner(FixedPrefix).sign` and common-input caller. Eight
new modules contain 36 lemmas. Their contracts retain the function and key,
arbitrary backend-consistent prehistory, the exact resulting history relation
and call count. Nonce exhaustion retains its executed query prefix; either
layer's exhaustion retains all construction and search work already performed.
The full caller obtains the digest width from the header. Successful signature
width and complete byte encoding follow from actual calls, without adding
successful signing as an entry premise. Losslessness remains separate from
value equality.

This closes the complete release-signer value/encoding component under the
existing paired-printer and primitive interpretations. It does not identify
the supplied Lean backend with RustCrypto, STM32 SHA or EasyCrypt's sampled
oracle. The next section composes initialized native sessions and the wrapper's
two signing calls and verification accounting. Callback non-interference,
whole effectful Rust/session interpretation and physical/QROM assumptions remain
open. No sampled-oracle probability bound transfers through
these deterministic equalities. The [control owner](CONTROL-EVIDENCE.md#functional-complete-signer-controls)
records the typed value, composition and native-effect mutations. Full cold
replay, exact identities, required review and actual CI remain separate landing
evidence; these statements confer no production authority.

## Functional initialized sessions and wrapper composition

The fixed-backend value relation now includes actual key preparation and the
native adaptive byte session (2026-10-25). It uses the existing 85 shared
definitions without extending the expression language. The backend function
and secret are explicit experiment inputs; this is separate from the sampled
oracle experiments and their security bounds.

[`C10FunctionalKeygen.lean`](../../extracted/Extracted/C10FunctionalKeygen.lean)
connects the actual public-key-root computation to the shared Merkle value at
layer one, tree zero, with the actual padded public seed. Its
`initialized_release_bytes` then composes actual key generation with the full
release signer and shared byte encoding. Every bounded signing failure remains
in the Result; no successful-signing premise is added. This theorem covers a
keygen/sign call sequence, not an extracted arbitrary Rust client.

[`C10FunctionalKeygen`](cdrafts-split/C10FunctionalKeygen.ec) preserves the
native preparation's arbitrary-public-input totalization, auxiliary random and
message outputs, key and function. It admits any backend-consistent prehistory
and accounts for all 177,151 hash/derive calls. This total differs from the
155,135 public-query charge: the remaining 22,016 calls derive WOTS secrets.
[`C10FunctionalCalls`](cdrafts-split/C10FunctionalCalls.ec) retains the existing
signer/verifier result, history and exact executed-prefix cost contracts as
unary and total-probability statements for caller composition.

[`C10FunctionalSession`](cdrafts-split/C10FunctionalSession.ec) and
[`C10FunctionalInitialization`](cdrafts-split/C10FunctionalInitialization.ec)
relate the actual native `ByteContext` to a value model whose adapter directly
uses the shared signature encoder and decoder. They preserve the same adaptive
client's observations and state, all `FullSession` fields, request admission,
raw/signing caps, absorbing signing failure, returned-message ledger and final
fresh-message verification. Successful signature widths are proved from the
actual calls; the decoded counter bounds follow from the admitted wire width.
Initialization establishes history consistency without an entry history or
success premise. The initialized success-probability equality compares these
two fixed-backend experiments only. It is not a transfer from the sampled-oracle
EUF experiment. Separate losslessness statements retain the ordinary
lossless-client obligation.

The value model does not execute oracle queries. Its backend history and call
counter are therefore not equated to the native execution. The relation retains
native history consistency and the key/function frame; the separate unary
contracts retain the native effects and exact costs. The request counters and
message ledger are equated in full.

[`C10FunctionalWrapper.lean`](../../extracted/Extracted/C10FunctionalWrapper.lean)
composes the existing source-lifted sequential wrapper with the same actual
release signer and raw verifier endpoints. A normal release has the exact
shared signature bytes, both actual signing calls using the same OptRand,
successful raw verification, and exactly two sign events and one verify event,
including an arbitrary prior trace. Normal refusals retain the existing
at-most-two-sign/one-verify bound. Dependency failure or divergence is not
relabelled as a normal refusal with final effects. The two new Lean modules add
four kernel-only headline closures.

[`C10FunctionalWrapper`](cdrafts-split/C10FunctionalWrapper.ec) separately
proves the native wrapper's value, exact history relation and call cost through
readiness refusal, signing exhaustion, both signing calls, internal verification
and the final guard. Both signing calls consume the retained backend state;
verification is charged even when the final guard refuses release. The wrapper
has no absorbing session-failure latch. Its environmental booleans do not prove
the rate, entropy, sentinel or physical dependency implementations.

[`C10FunctionalWrapperSession`](cdrafts-split/C10FunctionalWrapperSession.ec)
composes the existing initialized adaptive `WrapperContext` with that value
model. It preserves admission, caps, request counters, returned-message ledger
and final fresh-message verification. Every admitted attempt is charged,
including readiness refusals, and later attempts remain possible. It does not
import the library game's absorbing failure latch. Initialization, equality of
success probabilities and losslessness have the same fixed-backend and client
boundaries as the byte-session statements above.

This closes the named deterministic composition slices under the existing
paired-printer, primitive and wrapper source-lifting interpretations. It does
not prove a single cross-kernel theorem for an arbitrary effectful Rust client
or identify the fixed backend with a sampled oracle. Callback non-interference,
concrete backend execution, entropy freshness, physical erasure/fault resistance
and QROM remain open. The [control owner](CONTROL-EVIDENCE.md#functional-session-and-wrapper-controls)
describes the typed mutations. Full replay, exact identities, required review
and actual CI remain separate landing evidence; no production authority follows.

## Quantitative loss

**Addressed-node continuation (2026-10-26):**
[`AddressedNumericalBound`](cdrafts-split/AddressedNumericalBound.ec) replaces
the node term in the same initialized ordinary byte-game bound by the smaller
of the previous node charge and `R*(R+1)/2^128`, with
`R=qr+2*qs+771`. Actual keygen/signing canonicity, exact-key memo accounting,
the two exceptional FORS-address calls per admitted signing attempt, and the
unchanged final verifier derive this budget. No desired freshness, budget or
success premise is imposed; failure and cached/prepopulated histories remain.
The private observer preserves oracle outputs and proves complete collision
coverage before applying the conditional fundamental lemma. Its only added
state exclusion is private observer access. All latest FORS/WOTS candidate
charges and other non-node terms remain unchanged. At `qr=qs=65536`, the
complete expression improves from about `2^-59.28` to `2^-60.55`; see
[the exact formula and scope](RAW-NUMERICAL-EUF.md#addressed-node-continuation).
This closes the equal-address node-budget obligation, not concrete SHA-256,
QROM, Rust/cross-kernel correspondence, hardware, or tighter FORS/WOTS research.
**Paired/wrapper continuation (2026-10-27):** the same addressed-node charge
now transfers through the exact initialized probability equalities to
`PairedByteContext` and `PairedKeygenByteContext`. The distinct wrapper game has
its own proved nonordinary-key budget `qr+775*qs+771`: two actual signing calls
at most two keys each, the conservative 771-call internal verifier, and the
final verifier. Refusals, retries, withheld outputs, caps and persistent oracle
histories remain. Its successful-output partition and generic observer bound
yield `min(Q*(Q-1)/(2*2^128), Rwrapper*(Rwrapper+1)/2^128)`. All existing wrapper
non-node charges remain, with proved comparison to the retained complete bound.
See [paired endpoints](RAW-NUMERICAL-EUF.md#transfer-to-paired-signing-and-verification)
and [wrapper formula](RAW-WRAPPER-EUF.md#addressed-node-continuation).
This closes these endpoint-specific node transfers, not the remaining wrapper
non-node tightenings or the backend, cross-language and physical boundaries.

**Wrapper non-node continuation (2026-10-28):**
[`WrapperRefinedNumericalBound`](cdrafts-split/WrapperRefinedNumericalBound.ec)
now transfers accepted WOTS encoding collisions, exact Stirling coverage and
ordinary FORS fixed-candidate accounting to the actual retry/withholding wrapper.
It proves the transformed session budget, retains both fixed guesses and all
twelve final slots, and combines the events for the same initialized adversary.
Both complete charges are proved no larger than the preceding addressed-node
bound for every nonnegative cap. This closes those three named wrapper transfers;
the concrete-backend, arbitrary Rust-client, cross-kernel and physical boundaries
remain. See the [formula and exact illustrative arithmetic](RAW-WRAPPER-EUF.md#non-node-continuation).

**Native total signing availability (2026-10-21):**
[`ByteTotalAvailability.byte_total_initialized_availability`](cdrafts-split/ByteTotalAvailability.ec)
bounds the original initialized byte game's `FullSession.failed` event, including
both R and WOTS-count exhaustion. For the nonnegative raw/sign caps `qr, qs`,
the bound is `byte_r_availability_charge qr qs + 2^256 * (1-pW)^10,000,000`,
where `pW` is the exact deployed acceptance mass in
[`WotsAcceptanceMass`](cdrafts-split/WotsAcceptanceMass.ec).
[`TotalAvailabilityExamples.byte_total_deployed_availability`](cdrafts-split/TotalAvailabilityExamples.ec)
specializes this to at most `2^-38` for `qr=2^32`, `qs=2^20` and both
ten-million-trial grinders. Native real arithmetic bounds the R term by
`2^-39` and the WOTS term by `2^-64`; no Lean theorem is imported.

The WOTS proof uses a completion potential over distinct actual count inputs.
Previously cached accepts or rejects keep their observed contribution, so no
adversary-supplied freshness premise is needed. The finite union covers the
actual serialized layer/tree/keypair/message fields at a fixed public seed;
the count inputs use the original 32-byte big-endian counter. Actual
count, WOTS, layer, finisher and persistent-session procedures establish the
failure witness through key generation and final verification. The WOTS cache
event is bounded directly under the physical shared oracle. Only the returned
R-observer event uses the existing prefix comparison.

The nine modules add 86 lemmas, including duplicate-input, zero-trial,
prefilled-table, lossless forced-exhaustion, refusal and no-request witnesses.
The 81 generated controls cover 19 typed procedure changes, thirteen contract
changes and nine equivalent variants; nine scope probes are additional.
Their precise proof-sensitivity boundary is recorded in
[CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md#native-total-signing-availability-controls).
This closes native ideal-oracle total signing availability for lossless native
byte clients under the stated state exclusions and initial cap identities.
It does not strengthen the forgery bound or establish concrete SHA-256/Rust,
cross-kernel, QROM, physical-fault or deployed availability claims.

**Native EasyCrypt R availability (2026-10-21):**
[`ByteRAvailability.byte_r_initialized_exhaustion`](cdrafts-split/ByteRAvailability.ec)
now bounds actual nonce exhaustion through the complete initialized C10 game.
The private observer calls the original R grinder and WOTS/FORS finisher;
exact erasure preserves the original byte game's forgery result, session state
and oracle state. Recorded, classified histories derive either a fresh R context
or a retained successful trace, including histories after complete signing.
Actual key generation establishes this invariant; admission, caps, failed calls,
the successful-message ledger and final verification remain in the experiment.

For nonnegative raw/sign caps `qr, qs`, let `m=10,000,000`,
`H=155135+qr+qs*(3*m+364892)` and `p=1-1/2048`. The native endpoint is
`qs*(p^m + (m*H+m*(m-1)/2)/2^128) + (H+771)/2^256`.
Only the returned R-exhaustion Boolean crosses the existing physical-prefix
comparison. The theorem quantifies over native lossless byte adversaries under
the existing oracle-state exclusions; it assumes no caller-supplied freshness
and imports no Lean theorem. This is an explicit formula, not a new certified
numerical specialization or a concrete hash/firmware security rating.

The eleven modules add 53 lemmas. Boundary witnesses cover empty history,
initialization, malformed/capped/failed-session refusal and admitted exhaustion.
A lossless constant test oracle witnesses actual exhaustion; it is not claimed
to be a reachable initialized random-oracle history. The 62 generated controls
include 17 typed procedural changes, seven changed contracts and seven
equivalent variants, with unchanged consuming proofs. Contract rejection shows
proof sensitivity rather than falsity of every altered statement.
This establishes the native complete-signer R-context component used in the
total availability result above. The separate finite PMF result below covers
the corresponding larger event independently; no cross-kernel or backend
correspondence follows from either result.

**Current separate Lean frontier (2026-10-20):** the
[six-case composition](../../probability/README.md#six-case-initialized-forgery-bound)
now proves the finite initialized structured `Pr[forge] <= epsilon`, including
real-valued conversion and the final Boolean shared-oracle transfer. All six
alternatives remain charged; cache-visible events are not transferred. At
ten-million-trial grinders and 65,536 signing requests, the kernel checks bounds
below `2^-50` for `2^20` raw queries and `2^-34` for `2^24`. At `2^32` raw
queries the coverage union exceeds one and the capped bound is exactly one.
These conservative ideal-model figures add no concrete implementation margin.
The [exact PMF codec and finite byte-game extension](../../probability/README.md#exact-byte-codec-and-finite-byte-game)
now proves two-way roundtrips for all well-formed structured signatures and all
4,008-byte vectors, with full big-endian u32 counters and wrong-length refusal.
Its independently defined adaptive byte session preserves result, ledger,
caps and full cache through actual keygen and final verification. Exact
initialized Boolean equality carries the same capped bound without an added
loss or premise. Finite structured signing availability is now composed below.
Unbounded-adversary representation, concrete backend/Rust/EasyCrypt and
physical/QROM boundaries remain open.

The [context-aware adaptive R-grinding component](../../probability/README.md#context-aware-adaptive-r-grinding)
now removes the caller-supplied freshness premise for a bounded initialized
R/H_msg session. Actual private-cache provenance establishes freshness for a
new valid context; an old successful context replays its cached result.
The direct interpreter and compiler preserve the ordered ledger, caps, failure
flag and full cache, including malformed refusal and public queries after
failure. The shared returned-failure bound is
`qs*((1-1/2048)^m + collisionPairs(qr+qs*m,m)/2^128) + (qr+qs*m)/2^256`,
capped at one. At ten-million trials, `2^32` raw queries and `2^20` searches,
the kernel proves it at most `2^-40`. This is a separate ideal-model
availability bound, not a full C10 signing result or a stronger forgery bound.
The [complete-C10 R observer](../../probability/README.md#r-exhaustion-in-the-complete-c10-game)
now composes the other keygen/sign private callers with this provenance
invariant. Concrete WOTS/FORS tail separation and zero selected-call budgets
derive the keygen history and preserve successful R replay through complete
signing. Independent observer/compiler refinement erases to the original
session and final verified game, retaining result, ledger, caps and cache.
Its initialized shared returned-event bound is
`qs*((1-1/2048)^m + collisionPairs(H,m)/2^128) + (H+361)/2^256`,
where `H=155135+qr+qs*(m+2*n+364290)`, capped at one. Finiteness precedes real
conversion; a kernel example gives `2^-39` at `m=n=10,000,000`,
`qr=2^32`, `qs=2^20`. The observer distinguishes R exhaustion from subsequent
WOTS-count failure. **The R private-caller provenance obligation is closed.**
The [complete structured signing-availability bound](../../probability/README.md#complete-structured-signing-availability)
now adds WOTS-count failure. A fixed-schedule completion potential handles
arbitrary adaptive queries and cached replies from an empty physical oracle.
The actual serialized WOTS layer/tree/keypair/message fields have `2^256`
possible contexts at a fixed public seed. Their finite union gives
`2^256*(1-22169393903687611906220091621190388/8^43)^n`, at most `2^-64`
at ten million trials, without a caller-supplied freshness premise. Actual
WOTS/layer/signer/session traces show that a failed signing ledger implies R
exhaustion or a fully rejected WOTS schedule in the final cache. Actual keygen
and final verification preserve this result. The WOTS event is bounded directly
in the physical oracle; only the returned R event uses prefix transfer.
The combined returned-ledger bound is `min(1,c10RCharge+WotsDomainCharge)`;
at both ten-million grinder limits, `qr=2^32`, `qs=2^20`, it is at most `2^-38`.
This closes finite initialized structured-model signing availability, including
adaptive public prefill and repeated requests. Refusal remains distinct from
admitted exhaustion; existing forgery bounds remain unchanged. No concrete
backend, unbounded-adversary, cross-kernel, physical or QROM claim follows.
The [byte-model signing-availability extension](../../probability/README.md#byte-model-signing-availability)
now transports that same bound to the independently observed byte session.
Full result/ledger/cap/cache refinement preserves actual keygen and final
verification. The initialized law allows any joint public-seed/finite-byte-client
PMF independent of the uniform hidden prefix, with exact failed-event equality
and no serialization loss. Its real/capped endpoint is the same `2^-38` at
these quotas; malformed/capped refusal remains distinct from admitted failure.
This closes finite byte-model signing availability, without changing the
concrete correspondence, unbounded-adversary or physical boundaries above.
No EasyCrypt theorem is imported into Lean.

The [separate mathlib PMF project](../../probability/README.md) proves bounded
independent sampling, including exact first-hit, returned-event and exhaustion
probabilities. It now derives the C10 WOTS/FORS projection PMFs from a full
uniform 256-bit digest, proves the 32-byte big-endian bijection and exact
quotient/remainder formulas, and transfers the bounded search through those
projections without losing counters or failure. The persistent memo-table
model now proves result-distribution equivalence for distinct keys absent from
the initial history. Serialized 32-byte WOTS counter schedules establish local
distinctness, not absence from arbitrary earlier queries. A separate actual
collision detector for independent uniform keys proves the prior-history plus
birthday bound. The online random-key memoized loop is now proved equal to
pre-sampling its key schedule, retaining the returned result and final table.
The derived collision charge bounds differences in result-event probabilities
from independent reply sampling. The high-128-bit randomizer projection and
injective padded H_msg input instantiate this result, including conditional
FORS exhaustion at the signing cap. A shared-table two-query interpreter now
proves the independent-R comparison under distinct initially absent R inputs
and exact domain separation: deterministic/hedged R inputs occupy 103/119 bytes,
while H_msg inputs occupy 160 bytes. Its selected R, full digest, counter and
observed table are retained; only an explicit later projection forgets R for
the digest-result event bound. The empty-cache exhaustion bound follows at the
ten-million cap. Global initial R-input freshness remains open. The finite structured
forgery-game bound and Boolean shared-oracle transfer are now composed below;
concrete signer-session correspondence remains open. Neither
nonce uniqueness nor a secret prefix proves absence from arbitrary prior
queries or earlier signing calls.
A bounded adaptive oracle interpreter additionally proves the final-table
collision component: reply-dependent query inputs, cached replies, early
returns and initial client randomness are retained. Observer erasure is exact,
and a support invariant connects its persistent flag to distinct-input
projected collisions. Uniform fresh projections yield the history-plus-birthday
charge; an empty table and the proved full-digest/high-128-bit law give
`n.choose 2 / 2^128`. This is a bound for the actual adaptive PMF interpreter,
not yet a translation of the complete C10 signer/adversary session or a full
forgery theorem. Nonempty history requires coverage and initial collision
freedom, and all counts remain worst-case query budgets.
A further first-call result now discharges the prior-history R-input freshness
premise for an adaptive public-query prelude started from an empty table. The
secret is sampled uniformly before that prelude, and proved late-sampling
equality gives the actual prefix-hit charge `q/2^256`. Trace erasure and cache
origins connect this event to the exact first 32 bytes of each R-input. The
actual two-phase shared-table experiment differs from its independent-R
comparison by at most that charge, for events on the public result and returned
counter/digest. The composed first-FORS-grinder exhaustion bound is
`(1-1/2048)^n + (n*q+n.choose 2)/2^128 + q/2^256`, including the ten-million cap.
Both counts are worst-case budgets. Public client state and request parameters
must be independent of the secret. This does not cover secret-dependent keygen,
earlier signing responses, later continuations or repeated signing. Selected R
and final cache are marginalized by the final event comparison. Signer-session
and forgery composition remain open; a leaked-secret counterexample has certain
success with one query.
Cached and prefilled-key examples show why local counter uniqueness alone
cannot establish independent fresh sampling.
The private-prefix interface component now also has a separate PMF proof for
interleaved public and private calls. The same indexed adaptive client runs
against one shared memo table or separate public/private memo entries, with
actual cached replies in both. Stopped-execution equality is derived from a
proved cache relation and injectivity away from public prefix hits; its actual
abort mass is connected to the full query trace. Delayed sampling and a
structural public-call budget give a two-sided returned-value event error at
most `q/2^256` for the concrete 32-byte secret prefix. Earlier private replies
may influence later queries; private calls do not consume the public charge.
Zero public budget gives exact returned-value distribution equality. Both
experiments start empty and the client never receives the uniform secret or
the private table. The result does not translate the complete C10 signer/client,
prove repeated-grinder freshness, or supply the full PMF forgery theorem.
Repeated private inputs remain cached, so this comparison must not be read as
a fresh-R sampler. Independent finite examples exhibit a real/ideal gap and
show why secret leakage, noninjective private encoding and a prefilled
physical table invalidate the relevant premises.
The existing two-query FORS grinder now has a proved full-state compilation
into the interleaved client. Its secret-independent R-tail schedule, H_msg
inputs, selected R, full digest, counter, failure and cache are retained.
An actual adaptive prelude, that `sharedRandomizerSearch`, and a bounded
continuation compare with the separate-cache execution with two-sided event
error `(q_before+n+q_after)/2^256`, including the ten-million-trial
specialization. Internal H_msg calls count toward this public-query budget.
The continuation can depend on the returned R/digest or failure and keeps the
updated table; no intermediate freshness or success premise is added. The
uniform hidden secret and empty global initial cache remain explicit.
This closes the grinder's application to the private-prefix interface and
its bounded-continuation restriction. It does not make repeated private inputs
fresh or transfer the earlier independent-R exhaustion bound to arbitrary
repeated calls. The manual structured C10 clients are now composed below;
finite adaptive session/PMF forgery composition is now proved below; concrete backend correspondence remains open.
The accepted WOTS encoding collision component now also has a separate PMF
proof over the actual adaptive memoized interpreter. Its acceptance-filtered
observer preserves the full cache and result, and its derived history bound is
`(n*h + n.choose 2*p)/M`. The existing full-digest projection and sum-205
predicate give `n.choose 2*p/2^129` from an empty cache, with the exact
`p = Nat.card AcceptedWots/8^43`. Rejected duplicates and cached calls do not
count as new accepted collisions. Initial accepted-history coverage and
collision freedom remain explicit for nonempty tables; neither independent
query keys nor successful grinding is assumed. This retires the unported
accepted-encoding charge, not the full PMF successful-output partition or
forgery composition. Its numerical acceptance enumeration is now independently
kernel-proved in Lean: `Nat.card AcceptedWots` is exactly
`22169393903687611906220091621190388`. A finite-word bijection derives the
recurrence, a checked vector algorithm computes it, and the kernel evaluates
the finite computation. Exact PMF acceptance, first-hit, exhaustion and
accepted-collision substitutions retain their existing premises. The
EasyCrypt count is not imported as a premise or a cross-kernel certificate.
The public zero-sentinel component now also has a separate PMF proof over the
actual adaptive interpreter. Direct induction on the final cache gives
`n*acceptMass` for a target predicate fixed before execution, assuming the
initial cache contains no target hit. Existing hits persist even at zero
budget. Uniform projected replies give `n*targets.card/M` for a fixed finite
set. The concrete first sixteen big-endian digest bytes equal the high-128-bit
projection, so an all-zero node has fresh mass `1/2^128` and final-cache charge
`n/2^128`. Its union with public collisions on the same program and cache has
charge `(n.choose 2+n)/2^128`. This uses all program queries. Neither target
postselection nor independent query keys is assumed. This retires the unported
zero-sentinel component, not the remaining successful-output partition,
reverse-chain/FORS continuations or full PMF forgery composition.
The fixed node-domain selector and selected-budget probability component are
now separately proved in the PMF project. A structural budget `q` counts every
selected call, including cached calls, while all excluded replies remain in
the full cache and may influence future keys. Observer erasure preserves actual
output/cache; selected initial-history coverage and collision freedom are
explicit. The resulting selected collision charge is `(q*h+q.choose 2)/M`.
The exact byte selector excludes160-byte keys and zero-kind128-byte keys,
retaining other arbitrary raw inputs. From an empty cache the combined charge
is `(q.choose 2+n)/2^128`: the zero term still uses the full total index `n`.
The actual physical R/H_msg grinder proves at most one selected and two raw
calls per trial, yielding `(trials.choose 2+2*trials)/2^128`; this needs no
freshness or successful-grinding premise. The complete EasyCrypt C10 node-cost
formula remains unported. The separate Lean structured game has its own proved
budgets and final bound below; concrete implementation correspondence remains
open. The R query is retained in this physical one-cache program;
the separate-private-cache experiment is not silently substituted.
The ordinary WOTS count and chain components now have separate PMF client
compilations. Exact address/count/chain bytes, counters, early success, failure,
reply-dependent next inputs and the entire memo table are retained. Count
search has zero selected-node cost but keeps its full raw-query zero charge;
its independent-sampling/exhaustion laws still require initial schedule
freshness. A chain split at a base-eight digit preserves execution through
position seven, with exact selected-call trace length. This closes the
count/chain component translation. Public WOTS recovery now also composes all
43 ordered chains with the actual acceptance test, kind-1 compression and zero
fallback. Full result/cache equality holds for arbitrary initial history.
Acceptance derives exactly 96 remaining steps, giving at most 98 raw/97 selected
queries and an empty-cache collision-or-oracle-zero charge of 4754/2^128.
Invalid returned zero is not identified with an oracle-zero event. This closes
the manually transcribed public recovery component. The PMF WOTS leaf and
shuffled signer now also compile with full result/cache equality: exact tagged
private derivations, four ordered shuffle blocks, little-endian multiply-high
permutation, positional writes and bounded count exhaustion. Actual sum-205
acceptance and the proved 43-position permutation derive `n+252` total,
`n+209` public and 252 selected signing calls; the leaf derives 345 total and
302 public calls. The signing node-event bound is `(n+31878)/2^128` from an empty
cache. Private-prefix event transfer is `(n+209)/2^256` for signing and
`302/2^256` for the leaf, retaining empty tables and a uniform hidden secret
independent of the client inputs. Cached private repeats are not fresh draws.
The PMF Merkle subtree root, authentication builder and nine-step recovery
now also compile with full result/cache equality, including actual stack
merges, keep/kept updates, sibling ordering and list defaults. The 512-leaf
schedule derives 511 merges and 177151 total/155135 public tree calls; all
executed authentication heights are below 9. Root/build prefix transfer has
error 155135/2^256 under the same independent hidden-secret/empty-table premises.
Their conservative empty-cache node-event charge is 15691326976/2^128; recovery's
is 45/2^128. The PMF FORS tree/sign/recovery and shuffled forest clients now
also compile with full result/cache equality. Actual 2048-leaf/2047-merge
geometry, matching-slot authentication overwrites, eleven recovery levels,
full-digest sub-seed derivation and the twelve-position shuffle are retained.
The forest actually recovers each signed tree and stores by natural index.
Its thirteenth transmitted secret is the tree root; a separate leaf hash fills
the last ordered compression slot. Tree/sign costs are 6143/6144 total and
4095 public calls; forest signing uses at most 80022 total/53386 public calls,
and recovery uses 146. Prefix comparison has error 53386/2^256 for forest
signing under the same independent-secret/empty-table premises. Conservative
empty-cache node-event charges are 3201800253/2^128 for signing and 10731/2^128
for recovery. Cached calls are counted, not assumed fresh.
The manual structured C10 keygen/sign/verify clients now also compile with
full result/cache equality. Layer signing executes the builder, exact seven-byte
shuffle label, WOTS signing and actual reconstruction; two-layer composition
passes the reconstructed node and full cache onward. Natural counters retain
all 32 encoding bytes; successful counters are proved below their u32 cap.
Signing runs the actual R/H_msg search before forest and both layers. Verification
recomputes H_msg, enforces the forced-zero field, retains recovery defaults and
compares the whole padded root. Keygen uses the public digest's high half and
the layer-1/tree-0 root. Signing budgets are `2*m+2*n+435044` total,
`m+2*n+364290` public and `m+435042` selected calls; verification has 361 total
and 358 selected calls. Prefix error retains the independent uniform secret and
empty tables, while empty-cache node charges retain the full raw zero term.
Successful signature sizes, cached success/failure, full-table failure equations,
literal bytes and ordered two-layer traces are checked.
The finite adaptive structured session now composes those clients with actual
cap admission, persistent signing failure, successful-message ledger and final
fresh-message/shape checks. Keygen, adaptive calls and final verification retain
one full cache. For raw/sign caps `qr,qs`, initialized costs are
`qr+qs*(2*m+2*n+435044)+177512` total,
`qr+qs*(m+2*n+364290)+155496` public and
`qr+qs*(m+435042)+177509` selected physical calls, independent of refused-attempt
fuel. R inputs remain selected. The empty-cache physical node charge is
`(choose(selected,2)+total)/2^128`; with an independent uniform hidden secret,
initialized shared/independent returned-event error is at most `public/2^256`.
The component real-valued forgery-transfer theorem retains the independent
game's probability as a term; the combined bound below now charges it. This closes finite structured session
composition and cost; honest structured correctness is now proved below.
It does not close the 4008-byte PMF codec,
arbitrary lossless/unbounded-adversary representation or repeated-grinder
freshness. The supported forgery alternatives and finite bound are now composed below. The `none` exhaustion model does not prove runtime panic/retry,
callback or erasure semantics. Passive observations now retain actual successful
request/signature exposures and admitted client hash inputs, with exact
session/game result-and-cache erasure. Lookup-only replay in the actual final
cache supports joint keygen, exposure, ledger/cap, freshness and verifier
witnesses, including ordered layers and rejected WOTS zero branches.
Initialized returned-Boolean erasure inherits the existing transfer; it does
not compare cache-visible events. This supplies a dependency for the six-case
cryptographic alternatives and finite numerical bound now composed below.
Actual indexed tree builders now supply recorded Merkle/FORS root certificates
in the PMF model. Every valid coordinate chosen later has a derived reference
leaf and path; actual recovery at that coordinate binds to the actual WOTS leaf
or private FORS value unless the selected public cache contains a node collision.
Missing sibling defaults remain explicit. Winning initialized independent-game
outputs yield selected-node collision, public zero, or a joint top-tree opening
that retains H_msg, forest/layer recovery, actual keygen leaf, accepted WOTS count
and root equality in one final cache. Zero exclusion is necessary to derive
count acceptance. This structural opening is not itself a new-message WOTS
attack or a probability bound. Actual keygen fill and ordered WOTS recovery now
derive all 43 chain references. Fixed-width compression and same-coordinate
chain binding extend the top opening to every submitted signature value's
private-seeded prefix, retaining the collision and zero alternatives. Successful
session exposures have joint randomizer, forest and ordered layer witnesses with
their actual accepted counts and prefixes in that same final cache. Comparing
accepted words at a common address gives equal words/values or an earlier
position with a suffix to the signed value. This closes chain-opening extraction;
it does not establish that the earlier value is undisclosed or that equal words
mean equal messages. The complete repeated-address minimum is now derived below. The structural FORS descent, adaptive coverage and WOTS opening charges are
derived below; the complete six-case finite bound is now composed below. Forward correctness is now derived for the
actual returned Merkle/FORS authentication arrays at every valid target, using
certified stored siblings and the same cache; concrete merge alignment, bounds
and kept-flag initialization are discharged. Recovery preserves the actual WOTS
leaf or FORS private value and extends to later caches without a collision
exclusion. Actual FORS signing's returned secret/path recovers its own builder
root. The whole structured C10 honest-signature obligation is now closed under
the actual keygen result: every successful bounded signature verifies in its
resulting cache and every consistent later cache. The proof derives accepted
WOTS count lookups and recovery of the private-seeded prefixes, the actual
layer/builder root, shuffled positional forest records, special final-leaf
compression and both returned layers. Functional node uniqueness identifies
the top root with actual key generation; no desired root/path equality,
freshness, hash injectivity or collision exclusion is assumed.
The composed keygen/sign/verify PMF retains bounded failure as `none` and has
zero mass at `some false`. This is honest correctness, not guaranteed signing
success or a forgery bound. Eleven finite examples include asymmetric component
executions and counterexamples for wrong supplied roots and overwritten caches;
the inhabited whole-signature example uses a populated constant cache, not an
empty-cache success-probability argument. The structural FORS descent, adaptive coverage and WOTS opening charges are
derived below; the final six-case finite forgery bound is now composed below. The structured theorem
does not close the byte codec or concrete/hash/Rust/cross-kernel boundaries.
The repeated-address minimum component is now structurally derived from actual
signing: functional tree/forest root uniqueness, bounded count replay and the
actual 18-bit hypertree coordinates establish stable messages and accepted words
at each logical WOTS address. A complete chronological two-layer history is
constructed from all successful observed exposures, retaining duplicate calls
and the signing cap. Address filtering preserves every matching occurrence.
The actual winning top-chain opening either repeats a prior word and every
returned prefix value, or contains a coordinate below the exact minimum of all
prior returned positions at that address (endpoint seven for an empty history),
with an actual private-seeded prefix and suffix to every matching prior value.
All original collision/public-zero alternatives and actual opening witnesses
remain. No stable-word or completeness premise is assumed. The mixed accepted-word
counterexample shows why uniformity must be derived: an arbitrary minimum need
not have sum 205. This closes positional comparison only; it does not prove
secrecy, absence from raw queries or a private-opening probability charge.
The structural FORS descent, adaptive coverage and WOTS opening charges are
derived below; the complete six-case finite PMF bound is now composed below. No byte-codec, concrete hash,
Rust, cross-kernel, unbounded-adversary or repeated-freshness claim follows.
The repeated upper-word branch now descends into the actual lower tree. Actual
selected count lookups either expose two distinct public inputs with the same
accepted word or bind the submitted lower root to a prior actual signing root.
The prior lower builder supplies its complete certificate, including a reference
for a different submitted leaf. Reverse binding derives the submitted lower WOTS
leaf, accepted count and all private-seeded prefixes. The complete lower history
then gives either a repeated lower word and all returned values, or a position
below every prior returned position with actual suffix replay to every matching
value. Both logical lower coordinates, duplicate history and the signing cap
remain linked to the actual observed/initialized winning experiment. Original
node-collision/public-zero, top-earlier and accepted-word-collision alternatives
remain. This closes lower-layer structural descent only: the repeated lower-word
branch descends into FORS below, and no private-opening probability charge or
final six-case PMF bound follows. Seven finite examples and 32 complete-consuming-
proof controls cover these boundaries without weakening prior evidence.
The repeated lower-word branch now descends into actual FORS executions. Actual
count lookups retain accepted-word collisions or bind the forest public key;
both lower coordinates identify the complete hypertree address. Actual ordered
recovery and shuffled signing records supply all twelve ordinary tree
certificates, ordered thirteen-root compression, and the separate transmitted
last root/leaf hash. Selected-node collision exclusion binds the ordered roots
and derives every submitted ordinary private value from its real tree
certificate. The special thirteenth value remains a built root, not an ordinary
private-leaf exposure. Complete duplicate-preserving signing history then yields
coverage at every ordinary hypertree/tree/leaf coordinate, with equality to an
actual returned signing secret, or an unmatched coordinate with its actual
private lookup. Coverage can mix different prior signatures. Unmatched in signing
history does not establish absence from raw queries, secrecy, or a probability
charge. The actual observed/support/initialized winning endpoints retain the
complete history, cap, prior upper/lower occurrences and all collision/zero and
earlier-chain alternatives. Eight finite boundary examples and 45 complete-proof
controls accompany this structural descent. The adaptive coverage charge is
derived below, together with WOTS opening charges and the six-case PMF composition.
The codec, unbounded-adversary, repeated-freshness and implementation limits remain.
The fixed-sample quantitative dependency is now derived separately in Lean.
A full 256-bit equivalence retains 95 high bits, 18 hypertree bits, the actual
11-bit guard and twelve ordinary 11-bit indices. The uniform accepted-digest
PMF equals conditioning on that guard; joint address/opening-set masses and
bounded independent search retain the exact success/failure factor. Assigning
all twelve ordinary coordinates to `j` independent accepted witnesses gives
exact mass `2^-(132+18*j)`, including a full hypertree match for every group.
The target is fixed or independently sampled. Selecting a target and witnesses
from a larger independent accepted pool preserves this mass only with distinct
positions fixed before sampling. Eleven fixed-sample examples distinguish
reused positions,
rejected guards, changed addresses, unused high bits and unused-group address
costs; the empty example now consumes the general product law.
The separate Lean continuation now derives canonical coverage encodings and
their exact Stirling cardinality, ordered distinct witness positions excluding
the target with count `(n-1)_j`, and equivalence with ordinary-coordinate pool
coverage. Appending samples preserves the event. Composing these facts with
the existing fixed-assignment law proves the union upper bound
`sum(j=1..12) n*(n-1)_j*S(12,j)/2^(132+18*j)` without replacing its coefficient
by a looser count. A generic fresh-sampling completion argument transfers it to
randomized finitely bounded adaptive accepted-sampler programs under an observed
sample-length cap; the program work bound may exceed that cap. The list sampler
is proved equal to the accepted function-space PMF, and both extended-real and
real-valued bounds retain finiteness. Overlapping events are bounded by a union;
no equality of union probability and charge is asserted.
The next continuation derives the actual memoized H_msg transfer. It splits a
fresh full digest by the real acceptance guard and uses a completion potential
over the existing query interpreter. A passive observer records only fresh
accepted 160-byte public queries; cache hits retain their stored replies and add
no sample. Exact erasure preserves result and full cache, and empty-cache origins
identify every selected accepted final lookup with a pool entry. Reply-dependent
call budgets, result-width invariants and actual keygen/sign/verify control flow
derive the fresh accepted pool cap `qr + qs + 1`, independently of total work.
The actual observed session/driver/game compiler preserves queries, exposures,
refusals, failed-signing ledgers and final tables. Actual successful forgery
coverage maps through its valid complete signing history to distinct target and
witness pool positions, retaining all twelve ordinary coordinates and the full
hypertree address. Coordinates may use different prior signatures. Thus
`c10_observed_forest_coverage_bound` bounds `ObservedForestCoverage` in the
independently initialized observed PMF by the exact existing Stirling charge at
`qr + qs + 1`; its real-valued form is also derived. This proves that branch's
upper bound without declaring cache hits independent or assuming the cap.
The ordinary FORS and WOTS opening charges are derived next; six-case PMF composition is now proved below. Existing unbounded-adversary, codec, repeated-grinder freshness and
implementation limits remain. No EasyCrypt theorem is imported into Lean.
This continuation adds 107 theorem closures, nine boundary examples and 58
complete-proof controls including eleven equivalent forms. All 1760 preceding
statements, 1128 fixture objects and prior proof-module bytes are preserved.
The next continuation derives the ordinary FORS private-opening charge in the
actual initialized observed PMF game. A selected full private digest is sampled
early with exact removal of an unused cache entry. A shared-cache commitment
interface retains public queries before and after commitments, repeated calls,
adaptive full-digest reveals and execution after reveal. Only its unopened-result
view is redacted; no independence premise is attached to the actual transcript.
Full-cache refinement factors the selected leaf through actual keygen, forest,
WOTS layers, signing, observed sessions and verification. Failed requests retain
the cache without disclosing the deferred forest node. Successful exposures
supply the disclosure invariant against their complete final-cache history.
The existing unmatched ordinary opening event maps to the selected unreturned
event and its finite union over all 18-bit addresses, 12 trees and 2048 leaves.
Both extended-real and real-valued versions give
`6442450944 * min((177526+qr+qs*408408)/2^128,
(177524+qr+qs*(sessionSignCost cfg+1))/2^128)`.
Zero/all-FF candidates are charged once each; malformed raw inputs and all 12
final slots remain. The second charge protects the zero-signature boundary.
This event needs no accepted-forgery guard, so it also covers the narrower
unmatched branch; the complete history and actual cached opening remain required.
The 235 new closures, 23 boundary examples and 97 full-consuming controls retain
all 1867 previous statements, 1186 fixtures and 52 manual source bindings.
The subsequent WOTS continuation proves both earlier-than-all-exposures
branches in the original initialized observed independent PMF game. Exact
adaptive prefix precomputation restores every unused cache entry to its
baseline. Typed deferred chains retain all 43 coordinates, both layers and
cuts zero through six; position seven remains public. Full-cache refinements
cover actual keygen, builders, signer, sessions and final verification. Complete
successful-history provenance justifies legitimate releases at or before the
cut, including known earlier nodes. Failed and absorbed requests retain their
actual behavior. Passive raw/verifier probes erase exactly to the original
game; incoming reads are charged to preceding-cut openings, rather than
silently excluded. All staged freshness, disclosure and budget premises are
discharged for the actual game. The seven-cut recurrence weights sum to 28;
the finite union over 11294208 chains and initialized averaging give
`316237824*(155867+2*qr+qs*364076)/2^128` for `ObservedWotsOpening` and both existing
earlier-exposure branches. A kernel example proves this charge is below
`2^-64` at `qr=2^32, qs=65536`; it is not a full signer security margin.
The batch adds 299 closures in 57 modules, 34 boundary examples and 93 controls,
retaining all 2102 prior statements, 1283 fixtures and 52 manual bindings.
That preceding inventory had 2401 theorem closures and 1376 typed cases.
The six-case composition adds 48 closures in eight modules and 31 typed controls,
preserving every prior statement, fixture and non-umbrella proof module. The
six-case inventory was 2449 closures and 1407 typed cases. The byte-codec/session
extension adds 101 closures in thirteen modules and 64 controls, preserving all
preceding statements, fixtures, proof-module bytes and 52 bindings. The
repeated-R session adds 100 closures in seventeen modules and 64 controls,
retaining that preceding inventory of 2550 closures and 1471 typed cases.
The complete-C10 R observer adds 102 closures in sixteen modules and 64 controls,
preserving all 2650 preceding statements, 1535 fixtures, prior non-umbrella
proof-module bytes and 52 bindings.
The signing-availability extension adds 72 closures in fifteen modules and
56 typed controls (46 negative, ten equivalent), preserving all preceding
statements, fixture objects and manual bindings. That inventory had
2824 closures and 1655 typed cases. The byte-availability extension adds 28
closures in five modules and 40 controls (34 negative, six equivalent),
preserving every preceding statement, fixture and manual binding. That
inventory had 2852 closures and 1695 typed cases. The stateful-client extension
adds 71 closures in seventeen modules and 59 controls (49 negative, ten
equivalent), preserving that entire preceding inventory and all 52 bindings.
The current inventory is 2923 closures and 1754 typed cases. The combined forgery bound
retains all six events, uses exact tagged-cache erasure for collision/zero
charges, and transfers only the final Boolean with the public-prefix charge. These separate Lean
results import no EasyCrypt theorem and establish no concrete hash, Rust
execution, cross-kernel, QROM or hardware correspondence. Cache-visible events
have no shared/independent transfer. The initialized forgery transfer concerns
the final Boolean; the R-session availability result transfers its returned
failure flag.
All 52 manual source bindings are checked for
declared and push/PR trigger coverage, retaining the future-drift check #961.
No EasyCrypt theorem is imported into Lean; source pins on the manually
transcribed formulas do not prove extraction or cross-kernel correspondence.
The main `lean/` project remains mathlib-free.

The exact-witness continuation counts reverse restricted-growth assignments
and ordered distinct witness positions excluding the target. Its enrolled
coefficient is `n * (n-1)_j * S(12,j)`: the finite enumerators, falling factorial,
Stirling recurrence and preservation of the coverage event are proved in
EasyCrypt. The same adaptive-prefix argument and initialized byte games apply,
with unchanged premises. At `qr = qs = 65536` the coverage charge is about
`2^-98.14`, down from the earlier canonical `2^-93.29` (originally `2^-82.60`).
This closes the previously listed exact-enumeration obligation. It does not
make the union of overlapping coverage events an exact probability.
The accepted-encoding continuation also closes the overbroad WOTS encoding
event: actual opening and output-partition proofs require collisions only
between encodings that pass the sum-205 predicate. Its exact fresh-digest
acceptance mass is proved from the existing digit enumeration, and an adaptive
prefix argument transfers the smaller charge through the memoized oracle.
At these caps the encoding charge is about 30,698 times smaller and that
continuation improved the complete bound from about `2^-46.70` to `2^-47.28`.
The subsequent public-node domain proof removes the WOTS-count and H_msg
search calls from the node birthday budget, using actual widths and address
kinds rather than assuming all 128-byte inputs have the same role. Both
collision inputs in the successful-output partition are proved to belong to
the retained domain. The filtered memo oracle preserves adaptive state and
cached replies; the budget includes failed signing and arbitrary raw calls.
This reduces the complete bound to about `2^-54.39`. See the numerical owner
for the exact formula. These are upper probability bounds, not attack costs
or a deployed security rating.

The ordinary FORS continuation now counts repeated grinder candidates once:
the WOTS counter block yields a zero-valued candidate and H_msg an all-`FF`
candidate. Both guesses remain charged, together with every other query
candidate and the twelve final slots. The actual transformed target session
proves the remaining budget through key generation, signing failures and
verification. Existing adaptive hiding and private-table transfers reach the
same actual output; no query history is removed. Taking the minimum with the
previous FORS charge preserves every cap configuration. This improves the
complete bound to about `2^-57.45` without changing its model or premises.

The WOTS reverse-chain continuation also charges these same two fixed guesses
once, retaining all eight hidden digests and all 86 final output nodes. Its
filtered budget is proved in the actual opening-redacted chain session, with
unchanged cache, history and opening behavior. Existing programmed/fresh/
selected/coordinate transfers reach the same accepted output event. The
minimum with the old charge preserves every cap configuration. This brings
the complete bound to about `2^-59.28`; at that checkpoint the public-node
birthday charge dominated, followed by ordinary FORS openings. It closes this fixed-grinder
candidate obligation, not every possible WOTS or FORS reduction.

Finer ordinary FORS and WOTS target/candidate reductions remain possible.
The addressed-node continuation above closes the equal-address budget step.
Finer component charges and a tail charge for a smaller effective
hash budget remain possible. Substituting average grinding work for the
proved worst-case budget is invalid. The high-128-bit node projection and
low-129-bit encoding projection remain different, and their charges are
reduced by separate proofs.

The [formally verified SPHINCS+ reduction](https://eprint.iacr.org/2024/910)
provides a modular approach to tighter component reductions. Its construction
and premises must still be instantiated for C10's checksum-free encoding,
finite grinder, root-as-secret FORS case and shared byte oracle. Its title does
not establish those correspondences.

## Concrete SHA-256

There are two different obligations here. **Functional correctness** means the
chosen backend computes the specified SHA-256 digest. **Cryptographic security**
means the relevant keyed/tweaked uses resist suitably bounded adversaries.
Neither follows from the other.

The current EasyCrypt result samples an ideal full-digest oracle. It does not
prove that SHA-256 behaves that way. In particular, the model permits arbitrary
local computation and charges explicit oracle calls; instantiating a public
algorithm requires accounting for adversaries that compute it locally. A
meaningful concrete theorem needs a computational resource model and explicit
primitive security assumptions, or separate C10 reductions to precisely stated
hash properties. A premise saying the concrete game already has the desired
success bound would only restate the goal.

The [random-oracle methodology paper](https://arxiv.org/abs/cs/0010019) shows why
an ideal-oracle proof alone is not a generic security guarantee for concrete
hash instantiations. This does not show C10 insecure; it explains why the
instantiation step remains an obligation.

The repository's extracted hash wrappers call manually supplied
`hash.sha256_bytes` and streaming `hash.sha256_parts` definitions in `Extracted/Hash/FunsExternal.lean`. These wrappers
use executable `sha256_pure`; it does not mechanically extract RustCrypto's
SHA-256 implementation or the STM32 hardware driver. CAVP/test-vector agreement
and absence of project axioms do not close either backend correspondence.

**Portable word-compression correspondence (2026-10-26).**
`Extracted/Sha256Portable/Compression.lean` now proves
`Sha256Portable.compression_spec`: for every eight-word initial state and
sixteen-word block, the extracted RustCrypto portable
`sha256_digest_block_u32` succeeds and returns the unchanged vendored
`SphincsCVerify.Spec.Sha256Impl.compress` result. This includes modular
arithmetic, all 64 rounds, the rolling schedule, all round constants, input
word order, and all eight feed-forward additions. Its six audited headline
closures contain only `propext`, `Classical.choice`, and `Quot.sound`;
there is no hash-security or backend-correctness axiom in these results.

The proof input is the original word function from **C10's selected `sha2
0.10.9`**, not a replacement compression implementation. The proof-only module
root in `tools/sha256-portable-model/` reaches byte-identical `soft.rs` and
`consts.rs` copied with their licenses from the Cargo-checksummed crate.
`scripts/check_sha256_portable_source.py` checks the consumer's dependency
selection, package checksum, harness, and source bytes;
`make extract-sha256-portable` additionally authenticates the cached archive,
requires Charon's `has_errors=false`, and compares the complete Aeneas output
inventory and committed normalized files. Only the generated import path is
normalized. This retains the Charon/Aeneas translation and compiler trust
boundary; it does not prove the extractor itself correct.

The default extracted build and axiom census include the new compression proof.
`verify-extract-differential` executes 112 cases in the original Rust word
function, extracted Lean, and vendored specification, covering every input
word position, high bits, modular overflow, and deterministic mixed inputs.
It also rejects a change to each of the eight output words for every case.
Typed semantic controls check round and schedule rotations, constants, word
order, omitted rounds, and feed-forward. The additional local command
`python3 scripts/test_sha256_portable_controls.py --source-controls` makes
those changes in Rust, re-extracts them, and requires successful definition
typechecking before accepting a proof rejection or counterexample. Resource failures
and malformed fixtures do not count as successful negative controls. Round
rotations, schedule rotations, and constants break unchanged universal proofs;
word order, omitted rounds, and feed-forward have kernel-checked concrete
counterexamples to the same compression equality. The corresponding unchanged
concrete instance also passes. The counterexamples avoid treating elaborator
resource failures as evidence of inequivalence.

**Remaining backend boundary.** The word theorem does not connect the existing
`sha256_bytes`/`sha256_parts` postulates to an entire Rust `Digest` execution.
Byte decoding, the block loop, streaming updates, padding and length encoding,
dispatch, unsafe conversions, accelerated backends, and the STM32 driver
remain outside this proof. Direct extraction of the pinned full API still
encounters generic-array/trait translation errors; extracting the portable
byte-loop root encounters an Aeneas borrow-join failure. The successful word
extraction does not waive those failures. No concrete SHA-256 security,
random-oracle instantiation, QROM, physical, or side-channel guarantee follows
from this functional compression result.

## Quantum oracle access

`ByteClientOracle.hash` accepts one classical byte list and returns one digest.
The memo table and accepted-sample proofs observe those calls. They do not
represent a superposition query or justify observing a quantum query without
disturbing the adversary. Replacing `q` by `q^2`, or halving a quoted bit count,
is not a proof transfer.

The [SPHINCS+C paper, Appendix E](https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/sphincs-plus-c-pqc2022.pdf)
analyzes a quantum-accessible tweakable hash with classical challenge queries
and a reprogramming argument. That is relevant research, but its interfaces,
public-parameter timing, grinding and challenge restrictions need an exact
mapping to C10. No such QROM mapping is enrolled here.

A concrete next milestone is a quantum game specification with classical
signing, explicit quantum hash-query accounting, finite grinding failure and
one proved reprogramming/search hop. [qRHL-tool](https://dominique-unruh.github.io/qrhl-tool/)
provides a quantum relational logic and an Isabelle-backed implementation;
its existence does not supply a C10 proof. This is a separate proof-development
track, not an EasyCrypt checker option.

## Rust correspondence

Existing Aeneas extractions and Lean refinements cover useful components,
including address construction, FORS index extraction, WOTS digits, Merkle
recovery, WOTS recovery and several hash-input wrappers. The extraction
registry binds selected source and generated files, with separate generator
replay. These results should be reused, not described as if no extraction
existed.

The digest-field version bridge now closes the HT/FORS decoder portion of
[#288](https://github.com/EthereumPhone/PQ1/issues/288):
[`ForsSpecBridge.lean`](../../extracted/Extracted/ForsSpecBridge.lean) proves
the extracted Rust decoder results equal the verifier's vendored
`Util/Bits.lean` definitions for every 32-byte digest. It covers the 18-bit
HT field and all thirteen 11-bit FORS fields, including the last field,
without assuming that its forced-zero test succeeds. The byte conversion
preserves order and values; the four audited bridge results use only Lean's
kernel axioms. The exact copied definitions and their parameters are checked
by the vendored-fidelity gate. Rust-executed differential vectors complement
that theorem but do not prove the Aeneas translation sound. This is a bridge
to the verifier's Lean specification, not yet to the EasyCrypt game and not
a proof that every signer/recovery call uses the decoded position correctly.

The H_msg input-construction component is now proved in
[`HMsgSpecBridge.lean`](../../extracted/Extracted/HMsgSpecBridge.lean): for every
four 32-byte inputs, the extracted Rust caller returns the full digest of
`seed || root || R || message || FF[32]`, equal to the fidelity-checked
verifier H_msg definition after the byte conversion. The implementation streams
five slices through `sha256_parts`, avoiding a 160-byte concatenation buffer.
The supplied Lean backend hashes the concatenation; equivalence of that backend
to RustCrypto or STM32 remains open. The two new results have kernel-only
closures and join the default extracted gate. Seven copied declarations have
semantic drift and deletion controls, and six input-construction mutations
must fail the universal proof. A 132-case Rust/extracted/verifier corpus checks
every input-byte position; changes in either half of the output are rejected.
The default differential gate, including CI, executes both the software-backed
Rust H_msg and the hardware adapter with host hooks, requiring their outputs to
match the committed corpus without rewriting it. The hooks also check all five
update calls and their bytes; they do not exercise the peripheral. `GEN=1`
regenerates the corpus before these checks.

The WOTS digest/digit components are now joined in
[`WotsSpecBridge.lean`](../../extracted/Extracted/WotsSpecBridge.lean).
For every three input words and every `u32` count, the extracted hash caller
agrees with the verifier's `wotsDigest`, including its 28 zero padding bytes,
big-endian counter and full digest. This covers counts outside the signer's
10-million-trial range too. For every digest, all 43 extracted digits, their
complete array and their sum equal the verifier's bit-loop definitions; no
accepted-sum premise is imposed. Four added results have kernel-only closures.
The default gate executes 140 Rust hash cases and 262 Rust digit cases, checks
both extracted and verifier outputs, and rejects altered expectations and
malformed inputs. Seven copied definitions have fidelity drift/deletion
controls; ten semantic changes must break the universal bridge proofs.
These results do not establish the Rust grinder's stopping/failure behavior
or that every recovery/signing caller consumes these components correctly.

The bounded WOTS search is now covered separately by
[`FindCountSpec.lean`](../../extracted/Extracted/FindCountSpec.lean).
The actual Rust `find_count` body is extracted with an explicit counter and
indexed sum; its sum loop is definitionally the already-proved verifier loop.
For every input, the unconditional theorem gives exactly two outcomes: the
first count in `0..10_000_000` with digit sum 205, together with its complete
digest and all 43 digits, or failure because every count in that interval is
rejected. Charon reconstructs the terminal Rust panic as `assertionFailure`;
the proof excludes a successful value and divergence on that path. Separate
first-success and exhaustion results complete the three new kernel-only
headlines. No success-probability or independent-trials premise is added.

The default differential gate executes the actual Rust search against an
independent real-SHA reference, plus hardware-adapter host hooks forcing first,
progress-boundary, last-permitted and full-exhaustion cases. Controlled outputs
with sums 204 and 206 must be rejected; a success must return all of the actual
count, digest and digits. The controlled cases also run under `lean_extract`.
Eight altered executable definitions must typecheck and then fail the unchanged
proofs. Fresh generator replay checks the complete new extraction and the
affected older modules. The release ARM crate has unchanged section sizes and
all 26 frame annotations; this is not a final firmware or whole-program stack
bound. The supplied SHA backend and erased progress callbacks remain explicit
boundaries: arbitrary production callbacks are not proved to return or to
preserve behavior, and the host hooks do not exercise STM32 silicon.

The actual FORS `grind_r` search is now covered by
[`GrindRSpec.lean`](../../extracted/Extracted/GrindRSpec.lean). For both `None`
and `Some(opt_rand)`, its extracted body constructs exactly
`sk_seed || "R_grind" || [opt_rand] || message || zero[28] || nonce_be32`,
truncates SHA-256 to the first 16 bytes, and computes the full H_msg digest
using the padded public seed, root and randomizer. The acceptance test is
exactly digest bits 132 through 142 being zero. Three kernel-only headlines
prove the first accepted nonce in `0..10_000_000`, failure after every nonce
in that interval rejects, and an unconditional disjunction of those outcomes.
The terminal Rust panic again maps to `assertionFailure` in the extraction.
The default gate now checks 82 headline closures with the unchanged
27 environment axioms.

The source uses the existing streaming SHA boundary and an explicit counter;
the deterministic path still omits the OptRand update entirely. Default
controls execute independent real-SHA reference searches and controlled
hardware-adapter hooks in normal and `lean_extract` configurations. They
check every update's bytes and length, ascending nonces, first success,
byte-carry boundaries, the last permitted nonce, exhaustion and complete
returned values in both randomness modes. Twelve typed changes to executable
definitions must break the unchanged proofs. Generator replay covers both
the new search and the existing FORS decoder. ARM crate code is six bytes
smaller with unchanged data sections and all 26 frame annotations; this is
not final firmware or whole-program stack evidence. SHA backend correctness,
cryptographic hardness and caller-provided randomness freshness remain open;
these functional results assume neither independent trials nor eventual
success. They do not establish the EasyCrypt random-oracle game relation.

The WOTS recovery caller is now connected to the verifier specification in
[`WotsRecoveryBridge.lean`](../../extracted/Extracted/WotsRecoveryBridge.lean).
The actual extracted chain walk agrees whenever `start + steps ≤ u32::MAX`,
including zero steps. Endpoint compression preserves each padded node
and its position for all lists of at most 43 nodes. For every seed, position,
16-byte message, 43-node signature and full `u32` counter, the extracted
`pk_from_sig` result equals the verifier's recovered node, with `none` mapped
to Rust's zero sentinel. A separate audited equation preserves the exact
sum-205 branch: an accepted zero-valued hash remains `some zero`, whereas a
rejected sum produces `none`. No converse from a zero Rust result to rejection
is assumed. This is a component value/outcome relation, not a proof that the
full Rust verifier handles that sentinel identically to the on-chain verifier.

Four added headline results are kernel-only, bringing the default extracted
closure audit to 86 with the same 27 environment axioms. Fifteen additional
copied verifier declarations are checked for semantic drift and deletion.
The default differential gate executes the production Rust module files in a
host test crate, under normal and extraction configurations, against an
independent preimage/chain reference and committed Lean vectors. The 20
recovery cases include accepted and rejected messages at counter boundaries
through `u32::MAX`; 40 chain cases include carry and zero-step boundaries,
and four compression cases include empty and full lists. Both extracted and
verifier computations must agree, including the explicit rejection outcome.
Fourteen well-typed changes to chain order, compression and recovery semantics
must break the unchanged universal proofs. No production Rust, hash backend,
cryptographic assumption or EasyCrypt game is changed by this bridge.

The XMSS authentication-path component is connected in
[`MerkleRecoveryBridge.lean`](../../extracted/Extracted/MerkleRecoveryBridge.lean).
The actual extracted pair hash preserves all four 32-byte preimage segments.
For every seed, layer, tree, leaf, full `u32` index and nine-node path, the
extracted recovery agrees with the verifier's nine-level computation. This
preserves sibling order, parity selection, successive parent indices, height
fields and the tree address domain. Out-of-range leaf indices are included as
computations; agreement does not assert membership in a 512-leaf subtree.

The two additional kernel-only headlines bring the default closure audit to
88 with the same 27 environment axioms. Five copied declarations have fidelity
and deletion controls. The default execution corpus covers all 512 nine-bit
branch patterns, 16 full-width boundary cases and six pair-hash cases, under
both normal and extraction Rust configurations and both Lean computations.
Fifteen well-typed semantic mutations must break the unchanged proofs.
Fresh Merkle extraction also checks the complete generated interface; its old
external-template pin was corrected only for an eight-line source-comment
shift, with the declaration unchanged. This component retains the supplied
SHA backend boundary and does not prove tree construction, membership
soundness or the complete verifier/session relation.

The FORS single-tree component is connected in
[`ForsRecoveryBridge.lean`](../../extracted/Extracted/ForsRecoveryBridge.lean).
The actual private `reconstruct_fors_root` helper is newly extracted without
changing production Rust. It hashes the secret with the leaf address, then
folds all eleven siblings. The functional result and verifier correspondence
cover every represented seed, `u32` hypertree position, tree and leaf index,
secret and eleven-node path. Position widening, the FORS address domain,
initial leaf index, sibling order and parent/height fields are preserved.
As with XMSS, out-of-range indices remain computation claims.

Two more kernel-only headlines bring the default closure audit to 90, with
unchanged environment assumptions. Three copied definitions have fidelity and
deletion controls. A test-only crate embeds the complete production helper
module unchanged and appends a child test, giving private-function access
without a production API or source change. Both Rust configurations and both
Lean computations agree on all 2,048 branch patterns and 16 full-width cases.
The gate rejects 4,128 changed outputs and seven malformed inputs, plus 23
well-typed semantic mutations: nine in the Rust-derived functions and fourteen
in verifier recovery/address definitions. Fresh generation checks the complete
new extraction interface. Full thirteen-root/forced-zero composition, tree
construction, membership, backend correctness and signer/session refinement
remain open.

The FORS forest stage now adds
[`ForsPkSpec.lean`](../../extracted/Extracted/ForsPkSpec.lean),
[`ForsForestSpec.lean`](../../extracted/Extracted/ForsForestSpec.lean) and
[`ForsRejectSpec.lean`](../../extracted/Extracted/ForsRejectSpec.lean).
The actual `compute_fors_pk` and complete `hypertree::verify` bodies are
freshly extracted, with existing proved dependency implementations and no
new opaque assumptions. The compression theorem preserves all thirteen
roots in order, their padding, domain 4 and the full `u32` position. The
actual verifier's twelve-root loop agrees pointwise with the verifier's
single-tree computation for every represented input and preserves slot 12.
The whole Rust verifier is proved to return false whenever its actual
H_msg digest's final FORS field is nonzero, including the signature's first
sixteen bytes as the randomizer. This is a refusal theorem; it makes no
claim about the accepting branch.

Four additional kernel-only headlines bring the default closure audit to
94; the environment inventory remains 27 axioms. Complete-output generation
checks both new extraction interfaces. Three copied definitions have edit
and deletion controls. Normal and `lean_extract` Rust, extracted execution
and verifier computations agree on 32 forest/compression cases and 16 actual
whole-verifier refusals. The cases include full-width positions/indices and
distinct secrets/paths for each tree. The gate also rejects 480 changed
outputs, 16 changed digest fields, ten malformed inputs and 18 well-typed
semantic mutations (fourteen Rust-derived and four verifier/address), with
five positive proof baselines. Production Rust is unchanged.

The FORS prefix continuation (2026-10-09) closes that forest/caller gap.
[`ForsParseSpec.lean`](../../extracted/Extracted/ForsParseSpec.lean) proves the
actual signature parsers read all thirteen secrets from bytes 16–223 and all
12×11 authentication nodes from bytes 224–2335, retaining exact order and
ending at offset 2,336. The special last leaf uses tree 12, height/index zero,
the decoded HT position and secret 12. It fills root slot 12 before compression.
[`ForsPrefixSpec.lean`](../../extracted/Extracted/ForsPrefixSpec.lean) composes
those calls with the faithful complete `Fors.reconstructForsPk` definition.
[`ForsVerifierPrefix.lean`](../../extracted/Extracted/ForsVerifierPrefix.lean)
then proves the **actual full verifier** equals its unchanged WOTS/XMSS
continuation with that public key on every signature whose final FORS digest
field is zero. The theorem preserves the continuation's `Result`, including
failure/divergence; it neither assumes totality nor proves acceptance of the
remaining layers. The earlier nonzero-field refusal theorem covers the other
branch. No production Rust behavior changes.

Four new kernel-only headlines bring the default audit to 98; the environment
inventory stays at 27 axioms. Both copied complete-FORS declarations have
semantic-edit and deletion fidelity controls. The execution corpus runs the
whole production verifier in normal and `lean_extract` configurations, its
extracted counterpart, the exact prefix/continuation split and the faithful
FORS computation on 22 cases: four accepting KAT signatures, two negative KATs,
and sixteen synthetic signatures that pass the forced-zero check. It checks
all parsed bytes and offsets and rejects 132 value mutations, 44 incorrect
output widths and seven malformed inputs. Five positive proof baselines accompany
23 well-typed semantic controls
for parser sources/destinations/offsets, the actual last-leaf/compression/handoff
calls and verifier-side reconstruction. These controls supplement universal
proofs; the corpus alone is not a full verifier refinement.

The WOTS/XMSS continuation (2026-10-09) closes its computation and totality
obligations. [`HypertreeParseSpec.lean`](../../extracted/Extracted/HypertreeParseSpec.lean)
proves both actual layer parsers and all four big-endian counter bytes. Each
layer consumes 43 chain nodes, four counter bytes and nine siblings, exactly
836 bytes. [`HypertreeLayerSpec.lean`](../../extracted/Extracted/HypertreeLayerSpec.lean)
proves the actual body preserves the layer/tree/leaf addresses, shifts the tree
index by nine bits and hands the recovered node to the next layer.
[`HypertreeContinuationSpec.lean`](../../extracted/Extracted/HypertreeContinuationSpec.lean)
proves the actual two-iteration loop terminates, finishes at offset 4,008 and
returns the final root comparison. These results cover every represented
32-bit index, every 4,008-byte signature and every full-width wire counter.

The executable specification deliberately preserves Rust's invalid-WOTS
zero-node fallback and subsequent XMSS computation. It does not identify a
zero node with rejection. [`HypertreeStrictSpec.lean`](../../extracted/Extracted/HypertreeStrictSpec.lean)
separately proves that **when** the faithful strict `verifyHypertree` returns
`some expected`, the actual continuation returns exactly the comparison of
`expected` with the public root. Its `none` branch is not claimed equivalent
to the Rust continuation. No production behavior changes, added assumptions
or unconditional strict-acceptance equivalence are hidden in this relation.

Eight kernel-only headlines brought that batch to **106**; the exact
environment inventory remains **27** axioms. Four copied hypertree declarations
have semantic-edit and deletion fidelity controls. Fifty execution vectors
cover the actual parsers, extracted continuation, raw computation model and
strict specification. Forty-two also execute the unchanged whole production
verifier (the prior 22 cases plus ten counter boundaries in each layer); eight
additional cases cover index boundaries through `u32::MAX`. Both normal and
`lean_extract` Rust configurations check the same vectors. Successful strict
reconstruction and rejection at either WOTS layer are exercised. Controls
reject 350 altered values, 50 wrong output widths and eight malformed inputs.
Six positive proof baselines accompany 29 compiling semantic mutations across
the parsers, counter order/high byte, addresses, node/index handoffs, loop entry,
terminal comparison and strict reconstruction. The earlier prefix receipt now
separates value changes from output-width rejection (#815).

The complete signature-deserializer relation is now proved (2026-10-09).
[`SignatureDecodeSpec.lean`](../../extracted/Extracted/SignatureDecodeSpec.lean)
proves that the faithful byte decoder returns exactly the actual parser's
randomizer, all FORS secrets and siblings, both WOTS signatures and full counters,
and both XMSS paths. The sixteen-byte load proof includes the final node at
byte 3,992, whose thirty-two-byte intermediate load extends past the signature.
No padding/default branch replaces an in-range signature byte.

[`WholeVerifierSpec.lean`](../../extracted/Extracted/WholeVerifierSpec.lean)
composes the existing actual-verifier proofs into an **unconditional** totality
and computation theorem for every represented seed, root, message and 4,008-byte
signature. Its raw model preserves the actual invalid-WOTS zero-node fallback.
The faithful strict byte entry point is separately bound to its complete decoder,
H_msg construction and parsed fields. **Strict byte-verifier acceptance implies
Rust acceptance**; this is the completeness direction, not the security-soundness
converse. When strict reconstruction returns a root, the complete Boolean
result agrees, including a final root mismatch. A nonzero final FORS field
forces both verifiers to refuse. Rust acceptance implying strict acceptance
remains open because of the deliberate rejection/zero-node distinction.

Eight additional kernel-only headlines brought that batch to **114**, with
the same exact **27** environment axioms. Sixteen copied top-verifier/decoder
and byte-load declarations have semantic-edit and deletion fidelity controls.
Forty-eight vectors execute the unchanged whole production Rust verifier and an
independent SHA-byte oracle in normal and `lean_extract` configurations: all
twelve published KATs, sixteen synthetic forced-zero signatures and twenty
counter-boundary cases. The extracted Lean check executes the complete decoder,
actual verifier, raw model and faithful strict byte verifier on those inputs,
with 288 altered-value, 48 output-width and seven malformed-input controls.
Six positive proof baselines accompany 21 compiling semantic mutations covering
byte loads, full counters, parser offsets, header binding and verifier decisions.
The control scripts and original signature specification are enrolled in the
per-push/per-PR workflow paths, with path-deletion regression controls (#817).

Tree construction/membership, concrete hash backends, randomness and full
signer/session refinement remain open. EasyCrypt proof inputs and numerical
bounds are unchanged.

WOTS public-key generation (2026-10-09) now has an actual extraction and
unconditional correspondence theorem. `WotsSecretSpec` proves the exact 80-byte
secret preimage: 32-byte secret seed, `"wots"`, four-byte layer, full 64-bit tree
right-aligned in a 32-byte word, four-byte keypair and four-byte chain index,
followed by 16-byte truncation. `WotsSecretBridge` connects it to the faithful
`wotsSecret`. `WotsKeygenSpec` proves termination and all 43 positional chain
endpoints, each starting at zero and advancing seven steps, followed by ordered
compression in the WOTS-public-key address domain. `WotsKeygenBridge` composes
these with the faithful `Wots.keygenPk` for every input seed and address.

The only production change routes `hash::wots_secret` through the existing
`sha256_parts` helper. Its six updates preserve order and lengths
`[32,4,4,32,4,4]`; the supplied SHA backend model is unchanged. This small refactor
avoids an unsupported generic-Digest extraction path in the pinned translator.
Normal, `lean_extract`, software and host hardware-adapter builds compare all
195 secret cases against independent preimage assembly. The adapter cases check
the exact six update segments, without claiming peripheral correctness. Another
195 normal/extraction Rust cases compare actual `keygen_pk` to an independent
address/secret/chain/compression oracle. Both Lean execution suites compare the
actual extraction, pure result and faithful reference, each with 390 changed
output-byte and 195 output-width controls, plus six/seven malformed-input cases.

Six additional kernel-only headlines bring the audit to **120**, with the same
**27** environment axioms. Both new extractions and all six existing targets
sharing `hash.rs` have complete-output regeneration checks; the registry has
24 entries, 23 fresh and the unchanged, explicitly waived tx-merkle entry.
Four new copied definitions have semantic-edit and deletion fidelity controls.
Seven positive proof baselines accompany 28 typed semantic mutation controls.
The new controls and KAT JSON input are enrolled in the shared push/PR paths;
removing any new path from either event fails a regression control (#819).

Release `thumbv8m.main-none-eabi`, `hw-sha256` crate comparison measures 44 fewer
code bytes, unchanged rodata/data/bss, and an eight-byte compiler-frame increase
in `wots::keygen_pk` and `hypertree::sign_inner`. This is a bounded crate/frame
delta, not a whole-program worst-case-stack or silicon receipt. The manual
Rust/EasyCrypt source binding and split identity are deliberately updated;
the EasyCrypt proof sources, assumption census and numerical bounds are unchanged.
Tree construction/membership, shuffled signing, concrete hash backends,
randomness and full signer/session refinement remain open. FORS secret generation
is covered by the next result below.

FORS secret generation (2026-10-09) closes the reference mismatch in #820.
`Spec.forsSecret` and all reference signer/round-trip callers now include the
hypertree position, matching the existing Rust preimage:
`sk_seed[32] || "fors"[4] || BE32(ht_idx) || BE32(tree_idx) || BE32(leaf_idx)`.
The reference signer and its honest round-trip theorem rebuild with this field.
This correction does not establish refinement of the actual Rust signer.

`ForsSecretSpec.fors_secret_spec` proves the actual extracted helper returns the
first 16 bytes of the existing supplied SHA backend on exactly those 48 bytes;
`ForsSecretBridge.firmware_fors_secret_matches_vendored` composes that result with
the faithfully copied corrected helper for every seed and all three full-width
32-bit fields. Rust uses the existing ordered SHA helper for the same five
updates. Concrete software/peripheral hash correctness remains outside the proof.

Three new kernel-only headlines bring the extracted closure audit to **123**,
with the same exact **27** environment axioms. The new extraction and all eight
existing targets pinning the changed Rust file regenerate completely. The
registry contains 25 entries: 24 fresh and the unchanged tracked `tx-merkle`
waiver. Both copied FORS declarations have mutation and deletion fidelity controls.

An independent 48-byte oracle checks 131 Rust cases covering every seed byte,
every bit of hypertree/tree/leaf indices, zero, maximum and mixed fields. The
same corpus runs in normal/extraction software and host hardware-adapter builds;
the latter checks all five update segments `[32,4,4,4,4]`, without exercising a
peripheral. Extracted/pure/reference executions match it. Controls reject 262
altered output values, 131 wrong widths and five malformed inputs. Two fresh
positive proof baselines pass; 13 independently compiling semantic mutations of
the actual and reference helper fail their unchanged consuming proofs.

The release ARM crate comparison measured 120 additional code bytes, unchanged
static data and an eight-byte smaller `sign_inner` compiler frame. These are
crate/frame measurements, not a whole-program stack or silicon claim. The Rust
source binding changes, so this batch requires a new complete EasyCrypt replay;
its proof definitions, axioms, numerical bounds and cryptographic assumptions
are unchanged. FORS tree construction/membership, shuffled signing, randomness,
concrete hash backends and full signer/session refinement remain open.

FORS tree construction (2026-10-09) closes the root-building helper and the
reference final-slot mismatch in #823. `ForsRootSpec.fors_compute_root_spec`
proves termination, stack/index safety, all leaf derivations, ordered pair
hashes and the exact height-11 result of the actual extracted
`compute_fors_root`, for every pair of 32-byte seeds and all full-width
hypertree/tree indices. A finite schedule certificate checks all 2,048 leaf
positions and 12 possible heights using Lean's kernel (`decide +kernel`);
it contains only indices/heights. The loop invariant separately proves every
stack value equals the corresponding recursive hash node. No output-equality
premise, native-code proof axiom or new hash/tree assumption is introduced.

`ForsRootBridge.firmware_fors_root_matches_vendored` composes this with the
faithfully copied recursive `forsMtNode`. The new reference
`Signer.forsSigningValue` emits ordinary secrets in the first twelve slots and
the complete root in slot twelve, matching Rust's existing construction.
`firmware_fors_final_slot_matches_vendored` proves that root agrees with this
final-slot helper. The reference honest-signature round-trip theorem still
holds; that theorem alone would also have accepted the old leaf-secret rule,
so it was not evidence of generation correspondence.

Five new kernel-only headlines bring the extracted closure audit to **128**,
with the same exact **27** environment axioms. The complete root extraction is
registered and regenerates, giving 26 entries: 25 fresh and the unchanged
tracked `tx-merkle` waiver. Both copied definitions have semantic-edit and
declaration-deletion fidelity controls. Three fresh proof baselines and 19
independently compiling mutations cover leaf count/start, secret inputs,
address fields, carry condition, parent height/index, child order, stack
writes, returned root and the reference tree/final-slot rules.

The independent recursive Rust byte oracle checks 21 roots against the actual
stack implementation in normal and extraction builds, including zero, maximum,
mixed/full-width addresses, the final-slot tree and seed-byte changes. The
actual extraction, pure tree and faithful reference execute against that corpus;
42 altered values, 21 wrong widths and six malformed inputs are rejected.
Every root differs from the old leaf-zero-secret rule. Two actual signing
cases independently decode the digest position, check the forced-zero gate and
compare the emitted final slot with the recursive root before verifying the
signature. These are executable caller checks, not a proof of `sign_inner`.

Production Rust is unchanged in this batch. The completed 1,998-check EasyCrypt
replay for proof identity `27015a144ca3e10d6a96b4375c3e29e8` is reusable after exact
proof-input and manual source-binding comparisons; no new numerical or
cryptographic claim follows from reuse. FORS authentication-path generation,
hypertree key-generation trees, shuffled signing, randomness, concrete hash
backends and the complete Rust/EasyCrypt signer/session relation remain open.

FORS authentication-path generation (2026-10-09) now closes the actual
`sign_fors_tree` helper. `ForsAuthSpec.fors_sign_tree_spec` proves totality,
the exact derived secret and each of the eleven canonical sibling nodes for
all pairs of 32-byte seeds, all full-width hypertree/tree indices and every
leaf below 2,048. The valid-leaf bound is explicit; this theorem does not
advertise a membership claim for arbitrary 32-bit out-of-range leaves.

The proof reuses the root frontier/value invariant and tracks every path slot
whose parent merge has completed. The actual shifts, XOR sibling selection,
left/right comparisons, array writes and ordered hashes preserve that
invariant; completion establishes every slot. Two finite geometry certificates
use `decide +kernel` over leaf/height and traversal/height indices only. They
contain no hash values and add no native-code assumption.
`ForsAuthBridge.firmware_fors_auth_matches_vendored` relates the actual helper
to the faithfully copied `sibIdx`/`forsMtAuthPath` definitions consumed by the
reference signer, plus the existing faithful secret derivation. This proves
the generated subtree values directly; it does not assume the desired path.

Five added headlines bring the closure audit to **133**, retaining the exact
**27** environment axioms. Complete authentication-path extraction is registered
and regenerates: 27 entries, 26 fresh and the unchanged `tx-merkle` waiver.
The two copied definitions have semantic-edit and deletion fidelity controls.
Two positive proof baselines and 24 typed semantic controls cover traversal,
secret/address binding, merge geometry and ordering, sibling selection,
capture/update/return behavior and the copied path rules. Each changed body
must compile before its unchanged consuming proof is required to reject it;
name/parse errors, timeouts and exhausted proof resources do not count.

An independently assembled recursive Rust byte oracle checks 23 boundary cases
and all 2,048 leaves of one additional tree, including all 22,528 siblings and
secret values. Own-node substitutions discriminate from the expected siblings.
Both normal and extraction builds select both Rust tests. The actual Lean
extraction, pure recursive nodes and faithful reference execute on the 23-case
corpus. Controls reject 552 altered values, 46 wrong path lengths, 276 wrong
widths and eight malformed input shapes/ranges. All new scripts and the Rust
oracle are enrolled in default gates and blocking push/PR path coverage.

Production Rust and EasyCrypt proof inputs are unchanged. The completed
1,998-check replay remains reusable only after exact input/source-binding
comparison. This component theorem does not yet compose actual signer control
flow, serialization, the twelve-tree forest or recovery into a whole-signer
result. Hypertree key-generation trees, shuffled signing, randomness, concrete
hash backends and the complete Rust/EasyCrypt signer/session relation remain
open. No new cryptographic probability or hardware claim follows.

FORS signing/recovery composition (2026-10-09) now connects the actual
per-tree helpers. `ForsRoundtripSpec.fors_auth_recovery_root` proves that
folding the generated secret and eleven canonical siblings reaches the
height-11 root. Its intermediate invariant tracks the exact ancestor node,
index and ordered children at every level. It uses the existing kernel-checked
sibling geometry and adds no hash-collision or desired-root assumption.
`firmware_fors_sign_recover_root` composes the total extracted signing,
recovery and root-construction results: for every pair of seeds, full-width
hypertree/tree index and leaf below 2,048, recovery of the generated secret
and path equals the actual constructed root. A second actual-call headline
relates the recovered value to the faithful reference tree. The only input
precondition is the explicit valid-leaf bound.

Three added headlines bring the audit to **136**, with the same **27**
environment axioms. The independent Rust recursive oracle now supplies roots
for all 23 authentication-path cases; the Lean corpus compares actual signing,
recovery and construction against those roots. It retains the prior value,
shape and malformed-input controls and adds 46 altered-root controls, 552
executed altered-secret/path recoveries and 23 wrong-leaf recoveries. These
concrete unequal-output checks are corpus evidence, not a universal
collision-freedom theorem. A test child of the unchanged private Rust module
also checks all 2,048 leaves, 22,528 changed siblings and six full-width
positions, in both normal and extraction configurations. Seven typed fold
mutations exercise parity, child order, missing sibling, parent height/index,
next index and discarded merge; normal proof-error termination is required,
and resource or malformed-definition failures do not count.

Production Rust and extraction registration are unchanged. No new EasyCrypt
proof input or source binding is introduced. This result closes per-tree
membership and the signing/recovery connection; the actual shuffled forest
loop, serialization, special final-slot composition, hypertree key-generation
trees and complete Rust/EasyCrypt signer/session relation remain separate.
Concrete backends, randomness, resources and hardware remain outside this
component result.

XMSS key-generation tree construction (2026-10-09) is now connected in
`XmssRootSpec` and `XmssRootBridge`. The actual iterative `compute_subtree_root`
processes all 512 WOTS public keys, preserves the exact stack frontier and
ordered parent hashes, and returns the recursive height-nine root. The proof
covers every seed, full-width 32-bit layer and 64-bit tree, and all byte-valued
progress ranges. The actual `compute_pk_root` wrapper pads its sixteen-byte
public seed and selects layer one, tree zero; its output equals the faithful
recursive reference over the already-proved WOTS key-generation function.
No desired-root premise or new hash assumption is introduced.

Six additional kernel-only headlines bring the default audit to **142**, with
the same **27** environment axioms. A finite index/height schedule certificate
is checked by the kernel; symbolic hash values remain in the structural proof.
The new extraction is regenerated completely, including Types and external
interfaces; this checkpoint brought the registry to 28 entries, 27 fresh and the unchanged,
explicitly waived tx-merkle entry. Existing WOTS/hash bodies and the identical
progress-sink definition are reused, without new opaque assumptions.

Eight normal and extraction Rust cases compare actual roots with an independent
recursive byte oracle, including full-width addresses, zero/max seeds and
progress-range boundaries. The normal configuration also checks all 32 progress
reports per subtree and the public progress wrapper's root. Both actual entries
(public root and a full-width subtree) execute in Lean against those Rust roots
and the faithful recursive reference. The public-root case also executes the
internal pure tree; the full-width case's duplicate pure evaluation is allocated
to the actual authentication builder below, keeping six full-tree evaluations
across the two corpora. Universal pure-tree correspondence covers both cases.
Four changed values, two
wrong output widths and eleven malformed test inputs are rejected. These
bounded examples complement the universal proofs. Two positive proof baselines
and 23 compiling semantic mutations exercise leaf counts, seeds and addresses,
merge order, parent fields, stack slots and the public-root wrapper. The copied
recursive tree definition has strict semantic-drift and deletion controls;
resource/abnormal exits do not count as valid mutation rejection. All new gates
and script paths are enrolled in blocking push/PR coverage.

Production Rust and EasyCrypt proof inputs are unchanged. As elsewhere, formal
totality applies to the callback-free `lean_extract` shape; arbitrary callback
execution and its effects are outside that theorem. The normal/extraction
corpus is empirical correspondence evidence, not a universal callback proof.
The actual shuffled forest/signer loop, serialization and special final-slot
composition remain open, along with concrete backends, randomness and the
complete Rust/EasyCrypt signer/session relation. No hardware or shipment claim
follows from this component result.

XMSS authentication-path generation and membership (2026-10-09) are now
connected in `XmssAuthSpec`, `XmssAuthBridge` and `XmssAuthRecovery`. For every
seed, full-width layer/tree address, byte-valued progress range and target leaf
below 512, the actual `build_subtree_with_auth` returns the reference height-nine
root and all nine siblings from the faithful `mtAuthPath`. The carry invariant
tracks each capture flag in both directions and binds every captured value;
all flags are ready before the final copy loop, making its panic unreachable
on this domain. No desired-path or desired-root premise is imposed.

The actual builder, WOTS public-key leaf, authentication recovery and independent
root builder compose into a membership theorem. Seven added headlines bring
the default audit to **149**, with the same **27** environment axioms. Three
new headlines are kernel-only; the four consuming the actual builder also
reference the existing Aeneas `core.fmt.Formatter : Type` axiom through the
debug-panic formatting branch. That branch is proved unreachable for valid
leaves, but the syntactic type dependency is explicitly pinned in their exact
closures. This is not a proof of Rust formatting or panic-message behavior;
the environment inventory is unchanged. The regenerated extraction, normalized Types and imported external
interfaces are enrolled together: 29 registry entries, 28 fresh and the existing
tx-merkle waiver. The shared Rust-file metadata and checker-owned binding cover
the new entry too. Production Rust and EasyCrypt proof inputs are unchanged.

Twenty normal and extraction Rust cases compare the path, root and WOTS leaf
with an independent recursive SHA byte oracle, including leaf boundaries and
full-width addresses. Normal execution checks every progress transcript.
The Rust corpus also executes 180 altered-sibling, 20 altered-leaf and 20
wrong-index recoveries. One full-width extracted path build runs in Lean,
checking all nine siblings, the root, WOTS leaf and recovered root against
the independent corpus. It rejects 22 altered values, 16 malformed output
shapes and ten malformed inputs; 21 executed changed-value/wrong-index
recoveries must return a different root. These unequal-output examples are
empirical controls, not a universal collision-freedom theorem.

Three positive proof baselines and 36 typed semantic mutations cover leaf
generation, capture flags and indices, child order, copy-loop behavior, copied
path shape and recovery folding. Each mutated definition must compile before
its unchanged consuming proof fails. Resource, malformed-definition and
abnormal exits do not count. The copied path declaration has semantic-drift
and deletion controls; the default gate and blocking push/PR paths run all
new checks. The callback-free extraction boundary remains explicit. This does
not itself prove WOTS signature construction (now covered below), the shuffled
forest/signer loop, serialized signature production or the full Rust/EasyCrypt
signer/session relation.

Shuffled WOTS signature construction (2026-10-09) is now connected in
`ShuffleSpec`, `WotsSignSpec`, `WotsSignRecovery` and `WotsSignBridge`.
For every seed and prefix length at most 64, the actual Fisher–Yates function
terminates, preserves exactly the prefix permutation and leaves its tail zero.
The signer theorem consumes that result directly. For every input, the actual
`sign_with_shuffle` either returns the first accepted count below its ten-million
bound with all 43 chains in their specified positions, or fails with every
candidate rejected. Successful signatures recover the public key computed by
actual `keygen_pk` and agree position by position with the faithful reference
secret, digest, address and chain definitions. Any two shuffle seeds give the
same result, including bounded failure. Neither a desired permutation nor a
desired signature is a premise of these headlines.

Seven added kernel-only headlines bring the default audit to **156**:
143 kernel-only, four retaining the existing opaque `Formatter` type, four
SHA-256, one SHA-256/HMAC and four Keccak closures. The environment still has
**27** axioms. The registry now contains **31** entries: 30 fresh and the existing
tx-merkle waiver. Exact generation covers both new modules, normalized Types
and imported external interfaces. No axiom or native proof tactic was added.

The private Rust shuffle SHA-block computation was factored without changing
its RustCrypto backend, domain prefix, seed/counter encoding or caller
zeroization. Its extraction boundary uses the existing executable SHA-256
model; zeroization follows the existing total/discarded-result model. These
are explicit backend and physical-erasure limits. Before/after Rust outputs
agree on 2,535 seed/length cases in each normal/extraction mode. A separate
72-case Rust/Lean corpus checks exact SHA-derived order and zero tails; the
permutation theorem alone deliberately makes no exact-order or randomness
claim. The signer corpus checks 24 signatures across six full-width address
and first-count cases, both zero and seven digits, and 258 altered-chain
recoveries. Three cases run the actual extracted signer, recovery and keygen
in Lean, including alternative shuffle seeds and malformed inputs.
Two positive proof baselines and 20 typed semantic changes exercise shuffle
initialization, reduction, swaps, signer addressing, count, chain, iteration
and positional output. Each changed definition must compile before its
unchanged consuming proof fails; resource or abnormal failures do not count.
All new checks are part of the ordinary extraction/differential gates.

A required host-emulator tail check also has explicit evidence limits: it uses
a gate mirror, fixed keys/randomness and one message, not a production image
or silicon. Every changed literal-success output must now undergo actual
unfaulted verification; baseline failure, verifier errors and ambiguous key
artifacts cannot become successful rejection evidence. Crashes, hangs and
noncanonical returns remain separately reported. This is sampled integration
evidence, not full-body fault resistance, DPA resistance or shipment authority.

The callback-free extraction boundary remains. This closes the WOTS signing
component. The shuffled FORS forest is covered below; the whole hypertree signer and
session relation, backend correctness, entropy freshness and physical leakage remain open.

Shuffled FORS forest construction (2026-10-10) now covers the actual
`sign_inner_loop0` extracted from the unchanged `hypertree.rs`. For every seed,
full-width hypertree index and twelve valid leaf indices, the loop fills all
natural positions despite shuffled scheduling. The complete forest phase
computes the special tree-12 root, transmits that root, and hashes it once at
the correct address for the thirteenth compression slot. The final digest
index is not read by this phase. The resulting thirteen secrets and twelve
paths agree with the faithful reference, recover the same public key through
the actual verifier forest, and do not depend on the shuffle seed.

`SignForestFactor` proves exact equality between the actual caller and its
header, forest phase and unchanged suffix. `firmware_sign_fors_prefix` then
replaces the forest with its specified values unconditionally: no successful
search or desired-output premise is assumed, and failures/divergence remain
in the header and suffix. This does not prove whole-signer success or the
serialization/hypertree suffix. Six additional headlines bring the default
audit to **162**: 148 kernel-only, five with the existing opaque `Formatter`
type, four SHA-256, one SHA-256/HMAC and four Keccak closures. The environment
remains at **27** axioms. The registry contains **32** entries: 31 fresh plus
the existing tx-merkle waiver. Generated panic-string size witnesses are
explicit kernel proofs; Aeneas's default native witness is not admitted.

The explicit `ShuffleSeed.derive` boundary models the existing zero-seed fast
path and exact SHA-256 domain/seed/label bytes. Its backend correspondence is
empirical; the forest theorem requires only its totality and the proved
permutation property. Fifteen independent derivation cases cover zero and
nonzero seeds, empty/FORS/binary labels and a 256-byte label. In both normal
and extraction configurations, six actual whole Rust signatures over two
messages and three shuffle seeds agree byte for byte. Every transmitted
secret and sibling agrees with an independently assembled, recursively
hashed oracle. A separate full-width component case exercises leaf endpoints
and an unrestricted final index. Two Lean cases execute the actual forest,
recovery and compression; all 290 one-byte changes to transmitted secrets or
siblings yield different recovered keys. Malformed input shapes and altered
expected outputs are rejected. Three positive proof baselines and fifteen
typed semantic changes cover positional writes, iteration, final-slot
construction and the actual caller connection. Each changed definition must
compile before a normal proof error counts as rejection. These checks and
exact extraction regeneration are enrolled in the ordinary gates.

Production Rust is unchanged by this batch. Callback, concrete hash backend,
erasure, entropy and physical leakage limits remain. The forest component
adds no full signer/session, cryptographic reduction or shipment claim.

Signature serialization (2026-10-10) now has universal byte-level contracts
for the actual extracted sixteen-byte writer and all secret, FORS-path,
WOTS-chain and XMSS-path loops. Each contract specifies both the bytes written
and preservation outside the destination range. The thirteen secrets and
twelve eleven-node paths occupy bytes 16 through 2,335, preserving the nonce
and remaining suffix. The existing decoders recover every supplied field.
An unconditional equality replaces that forest serialization in the actual
signer suffix while preserving all later failures and divergence.

Each 836-byte layer consists of 43 sixteen-byte chains, all four big-endian
counter bytes and nine sixteen-byte siblings. For every in-range starting
offset, the extracted loops and literal counter-write fragment terminate with
that exact layout and offset. The computed subtree height is proved to be nine.
At each of the two wire positions, decoding recovers the original chains,
full-width counter and path. A kernel equality factors that serializer from
the actual layer body without changing its cryptographic calls or Result
behavior. These serialization contracts are composed with the cryptographic
components in the two-layer result below. The nonce-generation/header bridge
and complete session relation remain separate work.

The thirteen serialization headlines are included in the default audit total
reported below. The environment remains
at 27 axioms and the extraction registry is unchanged. The caller equality
uses a continuation argument to keep kernel checking small; no kernel check,
axiom audit or mutation acceptance condition is bypassed.

Eight independent concatenation cases execute the unchanged inline production
fragments in both Rust configurations and the extracted Lean writers. They
cover unaligned starts, both layer positions, the final buffer boundary and
counters from zero through 0xffffffff, including upper-byte changes. Every
output byte is compared, including the unchanged frame. Malformed corpus
inputs, changed expected bytes and a one-byte-overrun write must be rejected.
Nine positive proof baselines and twelve independently typechecked semantic
mutations check ranges, order, iteration counts, field selection and both
caller connections. Resource failures do not count as semantic rejections.
These checks run in the ordinary differential gate. Production Rust and
extraction artifacts are unchanged; backend, callback, erasure, entropy,
physical leakage, full signer/session and research-reduction limits remain.

Actual two-layer signing (2026-10-10) now has an unconditional Result equality
from the extracted signer loop to two pure layer operations. Each operation
uses the first accepted bounded WOTS count, the canonical positional chains
and nine independently specified XMSS siblings. The equality preserves bounded
search failure; it does not assume that either grinder succeeds. It retains
the full input index and the actual layer/tree/leaf arithmetic, writes at
2,336 and 3,172, and finishes at byte 4,008. On success the nonce/FORS prefix is
unchanged and the returned node is the top tree root; for an 18-bit input index
that tree is zero. A further unconditional equality connects forest
serialization, FORS compression, both actual layers and the existing final
root check to the real post-FORS caller. Matching the computed root passes
that check. The whole-signer extension below composes the nonce/header and
earlier FORS caller with this result.

This two-layer batch added nine audited headlines, bringing its total to **184**:
161 kernel-only, fourteen retaining the existing opaque Formatter type, four
SHA-256, one SHA-256/HMAC and four Keccak closures. The environment remains
at 27 axioms. No production Rust, extraction artifact or registry changes are
needed for this composition.

Three full-byte cases compare the unchanged production two-layer fragment with
an independent recursive byte/preimage oracle in normal and extraction Rust,
covering the maximum 18-bit and full-u32 indices and 0xfffffffe, first accepted counts, top
roots and shuffle independence. The extracted Lean loop executes the full-u32
case with distinct lower/upper leaves (510/511) and compares every signature
byte, root, offset and count, with eighteen
altered-output, four output-shape and eight malformed-input controls. The
fixtures deterministically select counts below 64 to keep routine execution
bounded; the universal proof retains the production ten-million-count limit
and failure behavior. Five positive proof baselines and fourteen separately
typechecked semantic mutations test crypto selection, byte offsets, actual
body/loop arithmetic and the final caller check. Resource and syntax failures
are not accepted as semantic rejections. These checks are enrolled in the
ordinary differential gate. Callback, backend, entropy, erasure, physical and
complete Rust/EasyCrypt session boundaries remain unchanged.

Actual nonce/header and whole signing (2026-10-10) now have an unconditional
functional Result relation from the extracted `sign_inner` entry point to a pure
composition. The nonce model selects the first accepted count below ten million,
in both OptRand modes, and retains the extracted assertion failure on exhaustion.
The actual header writes exactly the 16 nonce bytes into a zeroed 4,008-byte
buffer, pads the public seed, extracts all thirteen 11-bit FORS fields and the
18-bit hypertree field, and establishes the final FORS field is zero on success.
The composition connects that header to the canonical forest, its serialization,
FORS compression, both first-count signer layers and the unchanged final root
check. It does not assume grinder success or bypass a root mismatch. Shuffle
seed changes preserve the complete returned Result. A successful whole signature
retains the first accepted nonce bytes and its supplied public root equals the
independently constructed layer-one, tree-zero key-generation root.

**Build-profile boundary:** the final offset and root checks are Rust
`debug_assert_eq!` sites retained by the extraction and omitted by the normal
release profile. Consequently root-mismatch failure and the whole-success
root conjunct are facts about that extracted model; they do not establish
those behaviors for release Rust. The runtime corpora execute the header and
two-layer fragments before these final checks. Release caller/verification
correspondence remains a separate obligation. The bounded nonce-exhaustion
`panic!` is not a debug assertion.

Twelve additional audited headlines bring the current default total to **196**:
169 kernel-only, eighteen with the existing opaque Formatter type, four SHA-256,
one SHA-256/HMAC and four Keccak closures. The 27-axiom environment is unchanged.
Two header fixtures use independent Rust nonce-preimage and digest-window
oracles, with first counts zero and seven and both OptRand modes. Normal and
extraction Rust execute the unchanged production header fragment; Lean executes
the actual extracted header and grinder. Every output byte, digest, padded seed,
index and offset is checked, with 34 altered-output, eight expected-shape and
sixteen malformed-input controls. Four positive proof baselines and twelve
separately typechecked mutations check nonce inputs, exhaustion, digest windows,
header writes and whole-signer composition. Syntax/resource failures never count
as semantic rejection. The header checks and mixed-leaf two-layer case run in
the ordinary differential gate. Production Rust and extraction artifacts remain
unchanged. This closes the functional nonce/header and whole-signer composition
slice, not the cross-language EasyCrypt simulation or session relation; backend,
callback, entropy, erasure, physical and cryptographic reduction limits remain.

Release-configured signer caller (2026-10-10): `extract-sign-release` now
independently generates `sign_inner` with debug assertions disabled and overflow
checks enabled. All four debug checks disappear, including the forced-zero and
post-forest offset checks. Regeneration compares every shared caller helper
byte for byte before deduplication and checks the complete raw/generated output.
The three changed caller/loop bodies are retained with identifier renaming only.
`firmware_sign_release_pure` proves an unconditional Result relation through the
same canonical nonce, forest and two-layer computation without a final root guard.
`firmware_sign_checked_release_relation` gives the exact all-input relation:
the checked caller applies its final root guard to the release caller's result.
`firmware_sign_release_valid_key` proves equality when the root belongs to this
key, and `firmware_keygen_sign_release` discharges that condition using the actual
extracted key-root computation. Shuffle independence and bounded nonce exhaustion
also hold for the release-configured caller. No successful signing premise is
needed for these Result equalities.

This is a **caller configuration refinement under shared component models**.
The extraction's opaque dependencies still use the existing checked helper and
hash models; it does not prove all release-compiled dependencies, machine code,
or the secure wrapper's double-compute/compare/verify/CFI release effect. In
particular, no matching-root consequence is asserted for arbitrary release
caller inputs. Host software tests execute both OptRand modes in four shapes
(debug assertions on/off, normal/`lean_extract`), compare every signature byte,
and distinguish the exact checked root-mismatch panic from unchecked output
that the verifier rejects. Typed proof controls retain independent positive
baselines and reject changed inputs, omitted layers and altered returned bytes;
resource or syntax errors do not count as semantic rejection. These run in the
ordinary differential gate. Fourteen new audited headlines bring the total to
**210**: 170 kernel-only, 31 with the existing opaque Formatter type, four SHA-256,
one SHA-256/HMAC and four Keccak closures; the 27-axiom environment is unchanged.
Production Rust is unchanged. This retires the caller's debug-assertion mismatch
as an unmodeled step, not the remaining runtime or cross-language session limits.

Release component configuration (2026-10-10): all 20 registered C10 component
extraction recipes now explicitly set `debug-assertions=off` and
`overflow-checks=on`. The checked signer caller remains explicitly assertion-on
for its comparison theorem; the independently generated release caller remains
off. Fresh generation changes six bodies: digest-bit extraction, FORS roots,
XMSS roots, XMSS authentication capture/copy, shuffle, and the complete verifier.
The other fourteen complete raw module sets are identical to their previous
pinned output. The existing functional statements are re-proved against the
release bodies. Tree frontier and path-capture invariants establish the required
bounds and values without runtime debug assertions. Loop outputs that existed
only for assertions are no longer exposed; exact layout remains in the loop
invariants and parser specifications. The top-level signer and verifier claims
retain their previous inputs, failure behavior and scope.

This supersedes the helper assertion-profile limitation above for the registered
C10 components. It is not a proof of RustCrypto, hardware SHA, compiler lowering,
physical erasure, progress callbacks or the modeled shuffle sub-seed backend.
The obsolete flag-only authentication-path control is retired: release output
does not expose those flags, so breaking a flag invariant alone is not an
observable-output mutation. The remaining 36 authentication controls retain
typed semantic rejection. All 24 enrolled proof-control suites use the strict
result classifier and reject killed or resource-failed proof runs instead of
counting them as evidence. H_msg mutations separately type-check their changed
definitions before running the unchanged proof.

The total audited headline count remains **210**; removing the formatting path
removes the opaque Formatter dependency from 31 closures, leaving **201
kernel-only**, four SHA-256, one SHA-256/HMAC and four Keccak closures. The exact
27-axiom environment is unchanged. Typed tree/path/verifier mutation controls now
exercise the release bodies, including path copying without its removed debug
guard. The extraction freshness gate rejects missing, reversed or conflicting
profile flags and incompatible Cargo release overrides. Root Cargo profile and
lockfile changes trigger the blocking extraction/profile checks. No production
Rust or byte format changes in this batch.

Sequential secure-wrapper model (2026-10-11): `extract-secure-wrapper` extracts
the ordinary public signing entry and shared inner function from an exact
production-cfg slice of `secure/src/crypto.rs`. A counted source adapter threads
an explicit `Effects` argument through backend calls and replaces progress
function pointers with Unit. Its generated Rust module is committed verbatim,
checked against fresh adapter output, and materialized as a normal source module
before Charon/Aeneas; import and source-provenance normalization changes no Lean
body. Complete raw output, source dependencies, generated declarations and
external-interface types are pinned and replayed.

Ten new kernel-only headlines raise the audit to **220** (211 kernel-only and
nine existing hash-boundary closures), with the same 27-axiom environment.
`wrapper_success_requires_rate` proves the accepted charge and exact wrapping
read-back. `wrapper_entry_success_certificate` proves two equal signing results
from the same key/message/OptRand, verification of the returned bytes, the
matching final CFI sum and the final wipe/barrier; it also retains actual backend
Result equalities for composition. `wrapper_inner_cleanup` covers every normal
return after valid rate evidence; `wrapper_inner_refusal` classifies its final
trace as early rate refusal, entropy cleanup, or a bad comparison/sentinel/CFI
guard immediately followed by relock, wipe and barrier. These trace predicates
are suffix guarantees, not a physical trace or an entropy-distribution theorem.
A failed or divergent modeled dependency is not converted to Rust's recoverable
Err. `wrapper_firmware_release` instantiates the signing and verification oracles
with the existing extracted functions and proves release bytes agree with the
pure release signer and pass the faithful raw verifier.

The literal source and lifted source execute against scripted dependencies in
three host build configurations: debug, release, and release with the forced
feature enabled. Each compares 8,192 guard combinations, all 4,008 mismatch
positions and 32 sparse-entropy cases, including call arguments and wiped-buffer
contents. The forced feature build provides compilation coverage; it does not
exercise or prove forced-rate receipt validation. Twelve typed Lean mutations
and five compiled Rust controls check that changes to gate, message, randomizer,
release, relock and cleanup behavior are rejected; resource failures never count
as semantic rejection.

The new theorem remains about the sequential source-lifted model. The lifting
pass, SigningKey-to-field interpretation, hardware/dependency interpretations
and callback non-interference are translation/model trust boundaries; source
pins and finite examples do not prove their all-input correspondence. Entropy
freshness, physical erasure, timing, hardware FI and LLVM/assembly remain outside
the certificate. The verifier composition intentionally preserves Rust's
zero-node continuation and does not assert raw-acceptance implies strict byte
verification. No production source or signature format changes in this batch.

Wrapper source refresh (2026-10-22): the current firmware adds a UI guard around
the three strong draws and polls between them. The counted adapter interprets
the guard and polls as Unit under the same explicit callback non-interference
boundary as progress callbacks. Fresh extraction changes only generated source
locations; the Lean declaration bodies and types remain byte-identical. The
literal-source host corpus retains these calls and independently observes guard
entry/exit and poll positions, checks that each strong draw is guarded and each
signing call is outside the guard, and covers cleanup on early returns. Three
compiled source mutations disable entry, suppress polls, or postpone explicit
guard exit; each fails its named lifecycle oracle. This brings the Rust source
controls to nine. These finite scripted observations do not verify the real UI
guard, display/interrupt state, timing, or callback non-interference; those remain
dependency-interpretation limits, not newly proved firmware properties.

Paired representation endpoints (2026-10-11):
`cdrafts-split/C10RepresentationBridge.ec` and
`extracted/Extracted/C10RepresentationBridge.lean` prove their actual digest
readers and signature-parser values against common integer/list normal forms.
`tools/c10_representation.py` emits both definitions from one closed typed
expression tree; a byte-for-byte fidelity check runs in the Lean fidelity gate,
the EasyCrypt pin gate and the full-replay launcher. Words use signed mathematical
integers; offsets/counts use nonnegative integers (Lean `Nat`, EasyCrypt `int`
restricted to that domain). The Lean byte-domain lemmas discharge EasyCrypt's
0..255 premises. The generated tuple represents an ordered collection of fields,
with each language's own product/list encoding.

The endpoints cover all 32-byte digests and all 4,008-byte signatures, including
both full-width unsigned wire counters and the final node at offset 3992.
No accepted-digest or valid-signature premise hides rejected inputs. Nine new
Lean headlines are kernel-only, taking the audited total to **229** (220
kernel-only and nine existing hash-boundary closures); the 27-axiom environment
is unchanged. The EasyCrypt side retains its existing imported logical/model
foundation and adds no project axiom or admit. Ten typed arithmetic/layout
changes per language must break the unchanged endpoint proofs; changed
definitions first typecheck; timeouts, resource failures and unfinished runs
never count as semantic rejection. Static controls also enforce generated-file fidelity and
exact enrollment of the EasyCrypt controls. Each new EasyCrypt dependency and
proof enters the existing complete direct/CLI replay and statement/taint census.

This retires manual byte-order, digest-field and wire-decoder ambiguity **under
the disclosed common representation interpretation**. The generator and the
cross-tool interpretation of integer arithmetic, lists and tuples remain TCB.
These are two independently checked endpoint proofs, not a cross-kernel proof
exporter, an automatic Aeneas-to-EasyCrypt translator, or a whole-game theorem.
Hash-input/primitive and caller relations, bounded-search/error behavior across
languages, oracle histories and arbitrary adaptive sessions remain open. The
secure wrapper's two signing calls and internal verification also need their own
cost accounting; the single-library-sign session budget cannot be attached to
the wrapper unchanged. Concrete SHA, QROM and physical claims are unaffected.

Paired hash-preimage endpoints (2026-10-12): `C10HashInputBridge.lean` and
`C10HashInputBridge.ec` extend the same small generated representation to
H_msg, one-node, pair and ordered multi-node hashing, WOTS digest inputs and
randomizer derivation. They prove equality of the **preimage bytes**, without
assuming hash injectivity or inferring inputs from equal digests. The Lean
side composes the actual extracted hash adapters and bounded grinder-body
theorem with these forms. Multi-node execution retains the source's at-most-43
bound; its preimage identity holds for arbitrary node lists. R derivation
retains both OptRand modes. Counter encoding covers every u32, and the
EasyCrypt raw WOTS caller's 32-byte slot equals 28 zero bytes followed by the
same four big-endian bytes. Signing's ten-million-step bound is not substituted
for the verifier's full wire-counter domain.

Fifteen additional kernel-only headlines bring the default audit to **244**
(235 kernel-only, nine with the existing hash assumptions); the elaborated
axiom environment is unchanged. Twenty-one typed layout mutations now test
the combined representation endpoints in each language, including field order,
domain suffix/tag, node padding/order, counter endian/stride and optional
randomness. Changed definitions must typecheck and unchanged endpoint proofs
must reject normally; timeouts and resource failures are not semantic controls.
The 43 EasyCrypt fixtures, new root and its scope probe enter the complete
replay and exact inventories. The local Lean dependency closure of the new
endpoint joins source binding. The generated definitions, primitive list/integer
interpretation, extraction and supplied SHA models remain explicit boundaries.

That batch closes the concatenation/padding/counter-layout components; the
address/private-input endpoints below extend them.
It also does not identify concrete SHA results with ideal-oracle samples,
prove stateful histories or arbitrary clients, or account for the secure
wrapper's two signing calls and internal verification. No cryptographic bound,
production Rust, signature format or hardware claim changes.

Paired address/private-input endpoints (2026-10-12):
`C10AddressInputBridge.lean` and `C10AddressInputBridge.ec` extend the same
common expression tree without adding expression-language features. The
actual extracted address constructor and chain-index setter agree with the
common layouts for every u32/u64 field. The chain-position update used by
the existing hash-chain model has the corresponding byte equality. In
EasyCrypt, both window updates equal rebuilding the existing `address`
with the updated field, connecting them to the model's field-based callers. These
results preserve the address type and final hash-address field, not only
the smaller index ranges used by honest C10 callers.

The actual extracted WOTS and FORS secret helpers consume the common
preimages. WOTS retains all 80 bytes: the secret seed, `wots` tag, u32 layer,
24 zero bytes plus the complete u64 tree, u32 keypair and u32 chain. FORS
retains all 48 bytes, including the `fors` tag and full u32 hypertree, tree
and leaf positions. EasyCrypt's existing address, tagged WOTS tail and
tagged FORS tail equal those same forms under the full machine-field
bounds. The keyed-oracle tag is connected as an input expression; this is
not a proof relating the keyed and physical hash oracles.

Twelve additional kernel-only headlines bring the default audit to **256**
(247 kernel-only and the existing nine hash-assumption headlines). The
27-axiom environment is unchanged. Thirty-two typed layout mutations now
exercise the combined endpoints in both languages; the eleven additions
cover u64 width/high bits, address type/tail, chain-update windows, both
private tags, WOTS tree padding/keypair order and FORS hypertree binding.
All changed definitions typecheck before unchanged endpoint proofs must
reject normally. The 65 EasyCrypt fixtures and new root/scope probe are
enrolled in the complete gate. Source pins include the new proof's local
Lean dependency closure. These controls check proof sensitivity, not a
logical-falsity theorem for each mutation.

This closes the listed address and private-derivation input components.
Cross-tool integer/list interpretation, generation, extraction and supplied
hash models remain TCB. Composition into the actual EasyCrypt callers,
bounded-search/error behavior, shuffle derivation and callback effects,
stateful oracle/session histories, and secure-wrapper query costs remain
open. No production Rust, hash assumption, signature format or hardware
claim changes.

EasyCrypt caller-input composition (2026-10-13): `C10CallerInputBridge.ec`
connects the actual `RawWots.count`, `RawWots.chain`, `RawWots.recover` and
`RoleGrind.run` procedures to views that consume the existing generated common
preimages. Four relational theorems preserve both the returned value and the
entire global state of the same arbitrary oracle module. They require no
fresh table, successful search, accepted digest or hash-output equality premise.
Thus cached calls and oracle effects are retained as well as results.

WOTS counting retains the exact ten-million-attempt search and `None` on
exhaustion. Recovery permits every u32 wire counter, including those outside
the signing search, and preserves its zero-node result on a rejected sum.
Its ordered chain results feed the common multi-node preimage. Address fields
retain their full u32/u64 ranges. The chain theorem requires a nonnegative
starting position and an exclusive stop at most `2^32`; it also covers
zero-iteration calls. Nonce grinding retains both randomizer modes, the
R-then-H_msg call order, first-success stopping and bounded exhaustion.

Ten typed procedural mutations check the search bound, returned count, chain
position/result, full counter, rejection sentinel, node order, caller randomness,
acceptance test and exhaustion result. The changed definitions must compile
before their unchanged caller proofs reject. Solver/resource failures do not
count; the focused audit checks the intended theorem. The new procedures,
ten lemmas and four headlines enter the exact source, statement, module-body,
scope and full-replay inventories. The Lean headline and axiom inventories are
unchanged; the already paired Lean endpoints remain their source-side evidence.

This closes these four EasyCrypt callers' common-input composition component.
The common views still call the same EasyCrypt oracle: they do not identify
its sampled results with the supplied Lean SHA model or physical SHA-256.
Remaining key-generation/signing callers, shuffle derivation, cross-language
control-flow/error relations, callbacks, full stateful sessions and secure-wrapper
query-cost composition remain open. No production source or hash assumption
changes, and no whole-session or hardware claim, follow from this batch.

WOTS private caller composition (2026-10-14): `C10PrivateCallerBridge.ec`
connects the actual `RawKeygen(PreparationView(O)).leaf` and
`RawWots(PreparationView(O)).sign` procedures to the existing common private,
count, chain and multi-node inputs. The same arbitrary `PrefixOracle` runs on
both sides; the returned value and its entire global state agree. All u32/u64
address fields remain available. There is no fresh-history, successful-count,
desired-output or oracle-losslessness premise.

The leaf retains 43 private derivations, seven public steps per chain, ordered
padded endpoints and the type-1 compression address. Signing retains `None` on
count exhaustion, then the paired shuffle procedure proved below, private derivations
in its visit order, each accepted digit's chain length, writes at the shuffled
signature index, and the returned count. A partial-correctness shuffle lemma
proves index bounds for both its zero-seed identity and nonzero-seed branches
without asserting uniformity or termination of an arbitrary oracle.

Eleven typed procedural mutations exercise private keypair/tree/index binding,
chain stops, compression order/type, shuffle inputs, signature positions,
exhaustion and the returned count. Each changed definition compiles, and the
unchanged proof rejects at the intended theorem without syntax/resource credit.
Nine lemmas and two additional headlines enter the complete proof, statement,
module-body, scope, source-binding and replay inventories. Lean headlines and
the cryptographic axiom inventory are unchanged.

This closes common-input composition for these two EasyCrypt callers. The
paired-shuffle extension below composes the exact order relation into signing.
At this stage, remaining FORS/tree/forest/layer/signer callers,
cross-language control-flow/error and session relations, hash/backend/callback
interpretations and secure-wrapper query costs remain open. No production
source, signature format, concrete-SHA or hardware claim changes.

FORS and Merkle caller composition (2026-10-14): `C10TreeCallerBridge.ec`
connects the actual `RawFors.tree`, `root`, `sign` and `recover`,
`RawKeygen.root`, and `RawMerkle.build` and `recover` procedures through
`PreparationView(O)` to common-input views. Seven relational theorems preserve
the returned value and the complete state of the same arbitrary `PrefixOracle`.
The private FORS tag is supplied once, and public leaf and ordered-pair calls
use the existing generated preimages. Merkle construction consumes the already
checked common WOTS leaf view.

The treehash loops retain every leaf derivation, carry, ordered child pair and
authentication-path update. The increasing-stack and mass invariants establish
height and parent-address bounds inside the loops; these are proved facts,
not new caller premises. Layer/tree fields retain their full u32/u64 ranges;
FORS hypertree/tree identifiers retain the full u32 range. Builder targets are
unrestricted integers. Signing/recovery indices retain the full u32 range,
including values outside the honest tree's leaf range. Recovery retains
parity-dependent sibling order, all nine or eleven levels and the existing
out-of-range path defaults, without a well-formed-path premise.

Sixteen typed procedural mutations exercise FORS private/leaf address binding,
child order, path placement, root/secret/path results, full-width recovery
targets, loop lengths, Merkle leaf arguments and parent indices. Each changed
definition must compile before its unchanged intended proof rejects; a solver
or resource failure is not semantic evidence. The source, thirteen lemmas,
two common modules, seven headlines, scope probe and all control fixtures enter
the exact inventories. Production Rust, Lean headlines and cryptographic axioms
are unchanged.

This closes the listed EasyCrypt callers' common-input composition component.
It does not identify the shared oracle with the Lean hash interpretation or
physical SHA-256, nor prove a cross-kernel or stateful session relation.
Forest/layer/signer outer composition, paired shuffle derivation, cross-language
control-flow/errors, hash/backend/callback interpretations and secure-wrapper
query costs remain open. No fresh-history, successful-output or oracle-losslessness
premise, and no whole-scheme cryptographic or hardware claim, is introduced.

Forest/layer/signer caller composition (2026-10-14):
`C10OuterCallerBridge.ec` composes the actual `RawForest.one`, `sign` and
`recover`, `RawLayer.sign` and `recover`, and `RawSigner.finish`, `sign` and
`verify` with the existing common-input component views. A ninth relation
specializes verification to every signature produced by decoding a 4,008-byte
input. Returned values and the complete state of the same arbitrary
`PrefixOracle` agree, including failed searches and rejected signatures.

The forest retains shuffled secret/path placement, the thirteenth
root-as-secret, its distinct leaf address and ordered root compression.
Layers retain construction before WOTS search, paired shuffle
derivation with the same layer label, count exhaustion and recovery of the returned signature. Local
partial-correctness lemmas derive successful signing counters' bounds without
assuming oracle losslessness. The signer retains the two 9-bit coordinate
updates, early layer failure, both randomizer modes, H_msg root binding,
digest rejection, path defaults and final root comparison.

Structured verification requires only the u32 range of the two counters it
actually consumes. The real decoder establishes that premise for every
4,008-byte input; neither valid authentication paths nor an accepted signature
is assumed. Forest and layer interfaces retain their full u32/u64 field ranges,
and forest-index bounds also cover short digests. Twenty-nine typed mutations
exercise these distinctions: changed definitions compile, then the unchanged
intended proof rejects promptly without syntax or resource-failure credit.
The seventeen lemmas, three common modules, nine headlines, source bindings,
scope probe and generated controls enter the exact certificate inventories.

This closes the listed EasyCrypt outer callers' common-input composition.
These caller proofs now compose the component relation below, replacing the
shared shuffle calls with paired derivation and permutation expressions.
Cross-language control-flow/error and session relations, hash/backend/callback
interpretation and secure-wrapper query costs remain open. The shared oracle
is not identified with Lean's hash interpretation or physical SHA-256. No
cryptographic axiom, production source, wire format or hardware claim changes.

Paired shuffle component correspondence (2026-10-14):
`C10ShuffleBridge.lean` proves the actual extracted zero detection, block copy,
four-block stream and descending swap loops. For every 32-byte seed and length
from 0 through 64, the complete extracted function successfully returns the
paired expression's exact prefix order and a zero unused tail. This strengthens
the existing permutation theorem: visiting the same indices in a different
order does not satisfy the new result. All nineteen theorem closures are
kernel-only. Separate input theorems retain arbitrary label bytes and every
u32 block counter.

`C10ShuffleBridge.ec` relates `RawShuffle.derive` and `permutation` to
`PairedShuffle`, preserving returned values and the complete state of the same
arbitrary `PreparationOracle`. The nontrivial path retains exactly four ordered
block queries; zero seeds and lengths 0/1 retain their fast paths. The relation
needs neither a fresh oracle history nor oracle losslessness. The descending
loop is related to the same generated pure order expression used by Lean.

The shared generator adds only saturated count subtraction, division by a
positive constant, list indexing with a default and list update. Its printers
and the interpretation of nonnegative counts and byte lists remain TCB.
Thirty independent fixtures exercise order, labels, full-width counters,
index/update behavior and multiply-high reduction in both languages; twelve
orders also match the existing actual-Rust/independent-Rust corpus. Eighteen
EasyCrypt and fifteen Lean typed mutations exercise the consuming proofs,
including five mutations to the actual extracted loops. Definition checks
precede proof rejection; abnormal/resource exits receive no rejection credit.

This closes the bounded shuffle component's exact-order gap. The subsequent
derivation refinement below replaces the supplied `ShuffleSeed.derive` body
with extraction. The SHA backend models remain explicit boundaries. These
results do not identify EasyCrypt's arbitrary oracle with Lean's concrete SHA
interpretation, prove physical erasure or side-channel behavior, or supply the
complete signer/session relation. No new cryptographic axiom is introduced.

Paired shuffle caller composition (2026-10-14): the WOTS fill, forest sign and
layer sign comparison procedures now call `PairedShuffle`. The new
`caller_shuffle_paired` relation combines exact raw/paired result and complete
oracle-state equality with the raw shuffle's permutation proof, for lengths
0 through 64. The actual callers discharge this bound at 43 and 12; the existing
index-bound proofs therefore apply to the paired order without assuming it.
Forest derivation retains the four-byte `fors` label and passes the resulting
subseed to its permutation. Layer derivation retains `layer_label layer` and
passes its result to WOTS signing. Both derivation calls consume
`shuffle_derive_common`, including the zero-seed branch.

Existing WOTS, forest, layer, signer and decoded-verification equivalences
retain their statements and propagate this composition through results, errors
and arbitrary prior oracle state. Four additional typed procedural mutations
change the forest label, permutation seed/size, and layer seed; the existing
WOTS shuffle and layer-label mutations remain enrolled. Positive definitions
must compile and each unchanged proof must reject at its intended theorem.
These are proof-sensitivity controls, not proofs that every mutation is false.
The source/module/statement pins bind the selected paired procedures.

This closes the EasyCrypt callers' use of the paired shuffle component. It
adds no oracle losslessness, fresh-history, successful-search or desired-result
premise. The subsequent derivation and label refinement below connects the
actual extracted formatter to the paired labels. The paired printers, backend
interpretation and complete cross-language/session relation retain the
boundaries stated above.

Extracted shuffle derivation and caller labels (2026-10-14): the Rust
`ShuffleSeed.derive` zero comparison, early return and nonzero input construction
are now extracted by a separate pinned Charon/Aeneas target. The kernel theorem
`shuffle_derive_exact` proves the exact result for every 32-byte seed and arbitrary
label slice. The zero branch performs no hash call. The nonzero branch supplies
the literal domain tag, seed and label in order to a private software-SHA helper.
That helper retains the existing `sha2` backend, including when `hw-sha256` is
enabled; its supplied ordered-concatenation/SHA interpretation remains a backend
boundary. This is not verification of the SHA library or the compiler.

The paired expression adds the four-byte forest label and the seven-byte layer
label, including its trailing zero. Lean proves the actual extracted formatter
equals the paired expression for every u32 layer: zero selects `wots-0\0`;
every nonzero value selects `wots-1\0`. Existing forest/layer factor proofs and
signer proofs consume these results. EasyCrypt proves its raw labels equal the
same paired expressions and uses them in the comparison callers, preserving
the previous result/error and full arbitrary-oracle-state relations.

Five new kernel-only headline closures cover derivation and labels. Eight typed
mutations of the actual extracted derivation must fail at its exact-result
theorem; five additional paired-label mutations exercise both Lean and EasyCrypt
endpoints. The independent fixture corpus now has 36 cases, including zero,
nonzero and maximum-u32 layers (and a negative mathematical integer on the
EasyCrypt/common-expression side). Each changed definition must typecheck before
its unchanged proof is rejected. The generator's typed zero-test constructor,
paired printers and cross-tool interpretation remain disclosed TCB. Extraction
regeneration, source/statement/module pins and the existing full signer evidence
cover the changed dependencies; none supplies a complete cross-language session
relation or closes the cryptographic, erasure or side-channel assumptions.

Secure-wrapper integration with the current firmware (2026-10-14): the later
FI-delay change adds a final `delay_source_failed` check before release. The
source adapter and freshly generated wrapper now include that branch. The
success certificates require a false status and include its observed event
before OptRand cleanup. The refusal theorem distinguishes unavailable delay
status (wipe and barrier, without relock in that suffix) from confirmed
comparison/sentinel/CFI faults (relock, wipe and barrier). The all-return cleanup
property and actual signer/verifier composition remain in place.

The host corpus now compares 16,384 guard combinations in each of its three
production-cfg builds, plus the existing mismatch-position and sparse-entropy
cases. Six compiled source controls and sixteen typed Lean controls include
changes to the final guard, observation, cleanup and relock classification.
The backend supplies the observed delay-status boolean explicitly; neither the
pool implementation nor its TRNG, interrupt, timing or physical FI behavior is
proved by this sequential wrapper model. No production guard is removed or
weakened to restore extraction freshness.

The outstanding bridge is a compositional relation between the current Rust
keygen/sign/verify implementation and the EasyCrypt byte game. It must cover
the remaining fixed-width operations, primitive/caller computations, bounded
search, all error returns, caller-supplied randomness, hash backends and session
semantics. The paired representation endpoints above are one component; their
interpretation TCB does not disappear when composing the rest. Source hashes and differential examples detect drift but do not
prove that relation for all inputs. No automatic Aeneas-to-EasyCrypt bridge is
part of the current certificate.

The [Aeneas cryptographic verification guide](https://github.com/AeneasVerif/aeneas/blob/main/documentation/crypto-verification.md)
and [SymCrypt technical report](https://arxiv.org/abs/2609.15648) support a
staged approach: extracted code, mathematical specifications and proved
refinements between them. The digest-field, H_msg input-construction and WOTS digest/digit components
are now bridged to the verifier specification. Bounded WOTS and FORS searches
have functional success/failure proofs; their connection to the EasyCrypt
games and the complete signer/session relation remain open. An opaque hash definition remains an explicit
backend boundary even when the surrounding refinement is axiom-free.

Replay optimization #789 and the combined owner-triggered assurance pass #509
remain separate deferred work. None of the research above grants shipment or
hardware authority.

Secure-wrapper query accounting (2026-10-14): the extracted
`SecureWrapperCost.lean` now proves that every **normal return**, including
refusals, preserves the cost of the incoming event trace and adds at most two
signing calls and one verification call. A successful return adds exactly those
three calls. The weights are arbitrary natural numbers; separate instantiations
bound the signing and verification counts. These are kernel-checked facts about
the sequential lifted wrapper and its recorded effects, with no new project
axiom. Aeneas failure/divergence carries no final `Effects` value, so this does
**not** bound physical prefixes of aborted executions. RNG, delay, callbacks and
other events are uncharged by this particular accounting and need their own
backend/resource arguments.

`RawWrapper` explicitly schedules two `RawSigner.sign` calls and, after equal
successful results, one `RawSigner.verify` call over the same persistent oracle.
`RawWrapperCost` proves bounds of `2*(4*signing_budget+435646)+771` physical-model
queries and `2*(3*signing_budget+364892)+771` public-model queries, preserving
arbitrary prior counts. Here “physical” names the existing `Physical` oracle
model; it does not measure firmware instructions or hardware time. Caller-chosen
readiness and final-guard booleans overapproximate environment outcomes.
`WrapperSessionCost` composes these bounds for an adaptive client, charging every
admitted attempt even when it refuses. Later attempts remain permitted. Key
generation and a final candidate verification are charged separately: the total
is at most `177151+qr+qs*wrapper_physical_budget+771`, or
`155135+qr+qs*wrapper_public_budget+771` in the public-query model, for nonnegative
raw-query and attempt caps `qr,qs`.

This closes the separate **call-accounting and abstract query-budget** component
of the wrapper-cost gap recorded above. The Lean per-call weights are not an
instantiation of a proved backend-cost relation to EasyCrypt. The subsequent
[initialized byte-wrapper security proof](RAW-WRAPPER-EUF.md) now supplies a
classical ideal-oracle cryptographic reduction for this adaptive context,
retaining charged refusals, retries and freshness over externally released
signatures only. Its independent and physical ideal-model bounds compose
wrapper-specific WOTS, ordinary FORS, coverage and public-event charges; they
do not reuse the absorbing library theorem by renaming its game. The complete
cross-language signer/session relation, physical abort prefixes, concrete hash,
RNG/delay/callback interpretations, QROM assumptions and hardware claims remain
open. Typed mutations check sensitivity to missing/extra calls, a reset prior
trace/count, omitted verification or second-sign charges, uncharged refusals and
removed caps. EasyCrypt budget controls change both the definition and its
derived identity, so rejection reaches a consuming cost inequality. A tuple
assignment preserves the reset control's instruction layout. Paired variants
that preserve history or increase either budget must pass. An actual third-sign
mutation derives its extra charge from the callee contract and fails a numerical
budget obligation, without relying on an instruction-layout error or a solver
timeout. An intended proof rejection is sensitivity evidence, not a proof that
every mutated specification is logically false. No production code changes or
new signing authority are part of this result.

Paired search acceptance (2026-10-15): `C10AcceptanceBridge` now connects the
exact acceptance computations to the shared representation. WOTS sums all 43
base-8 digits from one digest and compares with 205; FORS tests exactly the
11-bit window beginning at bit 132 for zero. The existing typed expression
language generates both endpoints without new primitives. EasyCrypt proves
equivalence with `RawWots.count_accepts` and `C10RawGrind.accept_digest` on
32-byte inputs whose elements are in `[0,256)`. Lean discharges that byte domain
through the existing fixed-byte-array representation and proves both branches
of the actual extracted trial bodies. Its complete bounded-search theorems
retain the first accepted counter, returned digest/digits or randomizer, and
exhaustion as `.fail .assertionFailure`, including both optional-randomizer
modes. No successful-search premise is added.

This closes the **exact acceptance-computation component** of bounded-search
correspondence. It does not relate the Rust supplied pure SHA function to an
EasyCrypt oracle, its history or its distribution. The EasyCrypt procedural
searches still use their existing bit-valued predicates; the new endpoint
equalities provide their interpretation on well-formed byte digests. No
cross-kernel search/session theorem, callback behavior, physical abort-prefix
bound or probability transfer follows. The paired printers and their primitive
interpretation remain disclosed TCB. Seven new Lean headline closures are
kernel-only; no project axiom is added. Five typed changes exercise an omitted
last WOTS digit, a nonzero initial sum, an altered target and shifted/narrowed
FORS windows. Each unchanged endpoint proof must reject at its intended
theorem; unchanged and value-preserving fixtures must pass. These are
sensitivity controls, not proofs that every mutated proposition is false.

Paired acceptance in search procedures (2026-10-15): `C10SearchAcceptance`
now composes those endpoint equalities into WOTS count search, WOTS recovery
and FORS nonce grinding. The comparison procedures consume `wots_sum`,
`wots_target` and `fors_zero_field` on the bytes of the current oracle digest.
Their equivalences reach the original `RawWots`, `RoleGrind` and
`StatefulGrind` procedures through the existing common-input refinements.
They preserve the exact result, including bounded exhaustion and the recovery
zero sentinel, and the complete shared history and call/draw counters. The
role-based comparisons also preserve the physical-model secret key. Existing
address/counter bounds remain explicit for the raw WOTS input refinements.

The history premise is `valid_history`, which permits arbitrary prior entries
and repeated inputs but requires every recorded digest to have 256 bits. The
initialization theorem establishes it, and the proved shared-oracle coupling
preserves it on every hash call. Conversion then yields exactly 32 valid bytes,
with a proved bit/byte round trip. This premise is necessary: an arbitrary
abstract oracle may return malformed lengths, so these new equivalences are
not stated for every possible oracle implementation. No empty-history,
successful-search, independent-trial or desired-result premise is added.

This closes the **EasyCrypt procedural use of the paired acceptance component**;
it does not establish a cross-kernel search or whole signer/session theorem.
The supplied pure Rust/Lean SHA backend is still not identified with the
stateful EasyCrypt oracle or its distribution. Paired-printer interpretation,
callbacks, physical abort prefixes, cryptographic assumptions and shipment
remain outside this result. Typed procedural changes exercise the acceptance
target, search budget, returned counter, rejection sentinel, wrong digest,
inverted FORS test and exhaustion result. Their definitions must compile before
the unchanged consuming proof rejects; baseline and value-preserving variants
must pass. No production behavior or project axiom changes.

Paired acceptance through complete EasyCrypt callers (2026-10-15):
`C10PairedSigner` composes the paired WOTS count/recovery and FORS nonce
acceptance procedures through WOTS signing, both hypertree layers and the
complete `RawSigner` signing and verification callers. The comparison verifier
also consumes the paired FORS zero-field predicate on its current message
digest. The refinements preserve exact results, all bounded failure branches,
the WOTS recovery zero sentinel, and the complete `Physical` oracle state:
shared history, call/draw counters and secret key. No successful-signing or
fresh-history premise is imposed. The existing `valid_history` invariant allows
arbitrary valid prior entries and repeated inputs; new helper contracts show
that shuffle, private derivation, trees and the forest preserve it throughout.

The structured verification endpoint retains the existing two-u32-counter
condition. The decoded endpoint discharges it for any 4,008-element byte
representation using the established decoder theorem. These are EasyCrypt
procedure equivalences under the existing oracle model, not new totality or
cryptographic probability claims. The original results and their existing
termination evidence are unchanged. The paired comparison procedures continue
to use the existing bit-valued chain digits and digest coordinates; pairing the
acceptance predicate does not identify every internal computation with the
shared integer/list representation.

This closes the **whole EasyCrypt caller composition of paired acceptance**.
It does not connect pure Rust/Lean SHA to the stateful oracle or its distribution,
or establish the complete cross-language signer/session relation. Paired-printer
interpretation, callbacks, physical abort prefixes, cryptographic assumptions
and shipment remain open. Thirty-one lemmas add no project axiom or production
change. Nine typed caller mutations exercise the returned WOTS counter, accepted
digest, exhaustion, layer counter/path, layer order, nonce root input and verifier
acceptance/root comparison. Each definition-only fixture compiles before its
unchanged consuming proof rejects; baseline and value-preserving fixtures pass.
These controls establish proof sensitivity, not falsity of every mutant theorem.

Paired digest computations through complete EasyCrypt callers (2026-10-15):
`C10DigestCallers` connects the WOTS signing and recovery chain lengths, FORS
leaf indices, and hypertree digest field to the existing shared integer/list
definitions. Its comparison procedures consume `wots_field`, `fors_field` and
`ht_field` on the bytes of the actual digest. The forest's shuffled visit order,
the two nine-bit layer-coordinate splits, and all hash preimages remain exact.
The refinements reach `RawSigner.sign`, structured verification and the decoded
4,008-element representation, preserving results, exhaustion, the WOTS recovery
zero sentinel, and the complete `Physical` state and query order.

The proof obtains 256-bit digests from the actual hash and bounded-search
contracts under the existing `valid_history` invariant. It proves the shuffled
WOTS and FORS index bounds from the permutation result. The new standalone
`finish` equivalence explicitly requires a 256-bit supplied digest; the actual
signer discharges this from nonce grinding, without assuming search success.
The top-level sign and verify statements add no new premise to the previous
paired-acceptance endpoints. Existing theorems, including the older arbitrary-
digest finish endpoint, remain unchanged.

This closes the **EasyCrypt callers' use of paired digest fields and chain
lengths**. It does not identify the pure Rust/Lean SHA backend with the stateful
oracle or prove a complete cross-language session relation. The paired printers
and primitive interpretation remain TCB; callbacks, physical abort prefixes,
probability transfer, cryptographic assumptions and shipment remain outside
this result. Twenty-five lemmas introduce no project axiom or production change.
Nine typed mutations change digit selection or its digest, FORS selection or its
digest, either hypertree field, the layer-coordinate divisor, and WOTS exhaustion.
Each definition-only fixture compiles before the unchanged proof rejects at its
intended theorem; unchanged and value-preserving fixtures pass. The field
equalities use direct proof steps so these controls do not rely on an SMT budget
failure. These remain proof-sensitivity controls, not proofs of mutant falsity.

Paired computations through the adaptive byte session (2026-10-16):
`C10PairedSession` lifts the paired signing and verification procedures through
the original session's raw/sign admission checks, configured caps, absorbing
signing failure, byte conversion and returned-message ledger. The comparison
uses the same session state. Its driver retains the exact final message,
4,008-byte signature validation, decoding and new-message check. The relational
results preserve the returned result, client globals, complete session state,
oracle history, query/draw counters and physical-model secret key.

`C10PairedInitialization` proves that actual key preparation preserves the
valid-history invariant and discharges it from the existing oracle
initialization. The initialized experiment therefore needs no caller-supplied
history-validity or successful-search premise. Its success probability equals
that of the original byte game. `C10PairedSessionBound` transfers the existing
WOTS-candidate numerical bound with exactly the original configured caps,
client losslessness and private-state exclusions. It does not reduce that
bound or introduce a new cryptographic assumption.

This closes the **EasyCrypt adaptive-session composition of paired signing and
verification computations**. The comparison retains the existing key-generation
procedure and the existing absorbing-failure session contract; it is not the
separate secure-wrapper session, whose refused attempts may be followed by
further calls. The pure Rust/Lean SHA backend is still not identified with the
stateful oracle or its distribution. A complete cross-language session relation,
paired-printer interpretation, callbacks, physical abort prefixes, concrete hash
assumptions and QROM remain open. Twelve lemmas and three comparison modules add
no project axiom or production change. Typed procedural and contract controls
are described in [CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md).

Paired key preparation through initialization (2026-10-16):
`C10PairedKeygen` composes the existing private-leaf and root refinements into
key preparation. Its comparison calls `CommonInputMerkle.root` at layer 1,
tree 0, with the exact public-seed padding, root padding and auxiliary returned
values. The generic helper excludes an oracle that writes `KeygenInputs`;
the concrete `Physical` oracle already satisfies this framing condition.
The existing totalization for arbitrary public-seed bit lists is retained.
No 256-bit public-seed premise or successful-keygen premise is introduced.

`PairedKeygenByteContext` combines this preparation with the paired byte driver.
The procedural and initialized relations preserve results, complete session
state, the physical-model key, shared history and query/draw counters. Actual
initialization discharges valid history. Its success probability equals the
original byte game's, and `C10PairedKeygenBound` transfers the same numerical
bound with exactly its existing caps, losslessness and private-state exclusions.
Seven lemmas and two comparison modules add no operation or project axiom.

This closes the **EasyCrypt composition of paired key preparation with the
paired signing/verification session**. It does not remove the paired-printer
or primitive-interpretation TCB, identify the pure Rust/Lean backend with the
stateful oracle, or prove the complete cross-language session relation. The
absorbing-failure game, separate secure-wrapper experiment, physical effects,
concrete hash assumptions, QROM and separate #295 probability-monad scope keep
their existing boundaries.
