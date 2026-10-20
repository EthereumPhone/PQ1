# C10 probability project

This is the separate mathlib project requested by
[PQ1 #295](https://github.com/EthereumPhone/PQ1/issues/295). It proves bounded
independent sampling and derives the C10 projection PMFs from a uniform full
256-bit digest, within this Lean project. It also proves an event-probability comparison between online memoized search
and independent sampling, using a derived history-plus-birthday charge. The
randomizer instance includes its high-128-bit projection and padded H_msg bytes.
A two-query shared-table grinder now derives that independent-R comparison
under explicit initial R-input freshness and proved domain separation. A bounded
adaptive oracle interpreter now also derives the birthday charge for actual
distinct-input collisions in its final memo table. A first shared-table grinder
after an adaptive public-query prelude now has a derived secret-prefix error
and composed exhaustion bound, with secret-independent public inputs. A further
private-prefix interface theorem compares full interleaved public/private
executions through one shared memo table and separate memo tables, including
queries chosen from earlier private replies.
The actual two-query FORS grinder now has an exact client compilation and a
prefix-error comparison with bounded adaptive work before and after the call.
**The finite initialized forgery bound now also covers the separately defined
byte game below, through an exact 4,008-byte codec and full-session refinement.
Concrete signer-session correspondence remains open.** The existing
`lean/` project stays mathlib-free and is not imported here.

The [finite adaptive R-grinding session](#context-aware-adaptive-r-grinding)
now derives freshness or successful replay from actual execution history and
bounds first exhaustion, including the shared secret-prefix transfer. Its
initialized endpoint has no caller-supplied freshness premise. The
[complete C10 R-exhaustion observer](#r-exhaustion-in-the-complete-c10-game)
now composes the other private callers and actual keygen. The
[complete signing-availability bound](#complete-structured-signing-availability)
below adds WOTS-count exhaustion with arbitrary adaptive cache prefill, then
charges the actual failed signing ledger in the initialized structured game. The
[byte-model availability extension](#byte-model-signing-availability) carries
the same bound through the direct byte session and joint public initialization.

## What is checked

`grind p accept start n` draws from the PMF `p`, stops at the first accepted
sample and returns its counter and value. It returns `none` after `n` rejected
draws. The recursion retains zero budget, counters starting at `start`, and
the last admissible trial; no success premise is required.

Write `a = Pr[p accepts]`, and let `E` be a predicate fixed before these draws.
The kernel checks:

* `Pr[none] = (1-a)^n`.
* An accepted value `x` at first-hit index `i` has mass
  `(1-a)^(i-start) * p(x)` when `start <= i < start+n`, and zero otherwise.
* If `a > 0`, the **unconditioned** probability of returning a value in `E` is
  `(1-(1-a)^n) * Pr[p accepts and E] / a`. In particular it is at most the
  conditional one-draw probability. Failure contributes zero to this event.
* Every returned value is accepted and its counter lies within the budget.
  Always-reject and always-accept distributions, and zero budget, are checked.

The positive-acceptance premise is needed only to express the ratio. The PMF
and the exact first-hit/failure laws also cover acceptance probability zero.
The real-valued laws are derived from normalized probability masses, including
the required finiteness checks before conversion from `ENNReal`.

`Projections.lean` instantiates the deployed acceptance alphabets and cap:

| Projection | Acceptance | Exact one-draw mass |
|---|---|---|
| 43 uniform base-eight digits | digit sum is 205 | `Nat.card AcceptedWots / 8^43` |
| Uniform eleven-bit field | field equals zero | `1/2048` |

Both searches use 10,000,000 trials. `WotsCount.lean` now proves
`Nat.card AcceptedWots = 22169393903687611906220091621190388` in Lean.
`WordCount.lean` derives the exact recurrence by a first-digit/tail bijection;
integer target sums preserve negative residuals. `CountVector.lean` proves
that a descending-target vector computes that cardinality, including its
zero-word basis and default-zero entries. The Lean kernel evaluates all 43
steps at base eight and target 205; no native evaluator or asserted numerical
count is trusted. The existing concrete accepted and rejected words remain.

`WotsExact.lean` substitutes this count into the projection and full-digest
acceptance, first-hit and exhaustion laws, and the actual adaptive accepted
collision bound. Full digest atoms retain denominator `2^256`; projected
word atoms retain `8^43`. `CountExamples.lean` independently enumerates small
finite word spaces and checks zero/empty/negative and maximum-sum boundaries.
EasyCrypt's separate count is documented in
[RAW-NUMERICAL-EUF.md](../easycrypt/c10-port/RAW-NUMERICAL-EUF.md#accepted-wots-encoding-collisions).
Its theorem is not imported into Lean.

`ForsCoordinates.lean` now retains all 256 bits in one mixed-radix
bijection: 95 unused high bits, the full 18-bit hypertree address, the separate
11-bit acceptance guard, and twelve ordinary 11-bit indices. `ForsAccepted.lean`
derives the uniform accepted full-digest PMF and proves it equals conditioning
`digestDraw` on the actual guard. Its atoms have mass `2^-245`; the joint
hypertree/ordinary coordinate PMF is uniform. Fixed opening sets have exact
mass `product(card(opened_i)) / (2^18 * 2048^12)`. Bounded independent search
multiplies that conditional mass by `1-(1-1/2048)^budget`, retaining exhaustion.

`ForsAssignment.lean` and `ForsWitnessMass.lean` assign all twelve ordinary
coordinates to `j` independent accepted witnesses. Every witness must match
the target's complete hypertree address, including groups assigned no ordinary
coordinate. The resulting exact mass is `2^-(132+18*j)`. The target may be fixed
or sampled independently. `ForsSelectedWitness.lean` derives the same law for
a target and witnesses selected at distinct positions in a larger independent
accepted pool. Positions and assignments are fixed before sampling; value-dependent
selection, cached replies and adaptive histories gain no independence claim.
Eleven finite examples cover empty samples, zero search budget, one/two witnesses,
a nonmonotone distinct selection, reused positions, guard rejection, changed
hypertree address, retained unused high bits and the address cost of unused
witness groups. The empty example consumes the general product law. Reusing the
target position has mass one, demonstrating why injectivity is load-bearing.

`SamplePrefix.lean` proves a generic completion bound for fresh-sampling
programs. The client may stop based on earlier replies; its initial random
choice is independent of future samples. For any extension-closed event, the
probability of that event together with an observed sample-length cap is at
most its probability in a fixed pool of that size. The finite program work
bound may exceed the observed cap. `ForsSamplePrefix.lean` connects the list
sampler to the existing uniform accepted function-space PMF.

`GrowthWords.lean` derives the cardinality of reverse restricted-growth
encodings from their recursive construction: `S(k,j)`, the Stirling number of
the second kind. Every label is used, and `GrowthFactorization.lean` factors
any coordinate-to-witness map through one such encoding and an injective tuple.
`ForsWitnessPositions.lean` derives the exact `(n-1)_j` count of ordered
witness positions excluding the target. `ForsPoolCoverage.lean` proves that
ordinary-coordinate coverage is equivalent to this canonical witness union
and is preserved when more samples are appended. Every witness retains the
complete hypertree address; coordinates may use different witnesses.

`ForsCoverageBound.lean` composes these counts with the fixed-witness mass:

```
Pr[coverage in n independent accepted samples]
  <= sum(j=1..12) n * (n-1)_j * S(12,j) / 2^(132+18*j).
```

The same charge bounds `observed length <= n AND coverage` for every finite
adaptive accepted-sampling program, including a PMF over such programs.
Both extended-nonnegative-real and real-valued bounds are proved. This is a
union upper bound; overlapping witnesses do not make it an exact probability.
Nineteen new boundary theorems cover empty/singleton pools, mixed witnesses,
exact Stirling/falling-factorial counts, unused-group address costs, adaptive
stopping, the observed cap, and the failure of extension closure for exact-length
events.

The actual memoized transfer is now derived in `ForsSplit.lean`,
`SampleCompletion.lean` and the `HmsgPool*` modules. A fresh full digest is split
by its actual acceptance guard into normalized accepted and rejected laws.
Completion induction over the existing `QueryProgram` interpreter bounds the
fresh accepted pool while preserving cache hits, unselected queries and rejected
replies. `hmsg_pool_program_erases` recovers the exact result and full cache for
arbitrary initial tables. The observer records only fresh selected accepted
keys; their final-cache origins and uniqueness are proved. Completeness requires
initial absence, and the initialized application starts with an empty cache.

`ReplyBudget.lean` counts accepted calls even when a call hits the cache, so it
bounds the smaller pool of fresh entries. `QueryExclusion.lean` retains result
widths through loops and trees. `HmsgWots.lean`, `HmsgTrees.lean`,
`HmsgForest.lean` and `HmsgSigner.lean` derive separation of private queries and
public inputs whose lengths differ from 160 bytes. Actual key generation adds
no H_msg calls; signing adds at most one accepted H_msg call, including grinder
exhaustion, and final verification adds at most one. This derives the pool cap
`qr + qs + 1` from the actual structured session, independently of total work.

`ObservedProgram.lean` compiles the existing observed session/driver/game with
exact evaluation equalities. It preserves refusals, failed-signing ledgers,
forwarded raw queries, duplicate signing histories and final tables.
`HmsgSession.lean` proves exact erasure to the independently initialized game.
`HmsgCacheCoverage.lean` maps selected accepted final-cache keys into pool
positions; witness keys differ from the target, while coordinates may share a
witness or use different prior signatures. `ObservedCoverage.lean` connects the
actual successful forgery and valid complete-history FORS records to that event.
Fresh-message admission separates its H_msg key from each prior signing key.
Thus `c10_observed_forest_coverage_bound` and its real-valued version prove

```
Pr[ObservedForestCoverage in c10ObservedInitializedIndependent cfg sampler qr qs]
  <= forsCoverageCharge (qr + qs + 1).
```

All twelve ordinary coordinates and complete hypertree addresses remain in the
event. This is the FORS coverage branch's upper bound, not a full forgery bound.
Nine kernel-checked examples cover accepted/rejected/unselected entries,
159/160/161-byte and private query domains, repeated cached/fresh calls, charged
cache hits, refusal and admitted exhaustion. The ordinary FORS private-opening
charge and both WOTS earlier-opening charges are derived below. The six-case composition is proved below.

`OpeningProgram.lean` gives a selected node an explicit commitment interface:
public calls and commitments share one cache, while an adaptive reveal returns
the full private digest and keeps executing. Only the unopened-result view is
redacted. `CommitmentGuess.lean`, `OpeningGuess.lean` and `CandidateBudget.lean`
derive its candidate bound without assuming that the real transcript is
independent of the node. Zero and all-FF candidates are charged once each;
every other decodable raw input is charged, including malformed padding and
cached or repeated calls. Twelve final ordinary slots are retained, with default
zero values and duplicates.

`MemoPresample.lean` preserves the actual result and full cache when sampling
one initially absent private digest early: an unused entry is removed again.
`SelectedOpeningEvent.lean` observes that an actual cached opening must have
queried that target, so restoration preserves its full table on the event.
The selected private digest is uniform over all 256 bits; only its high 128-bit
node is used by commitments. Proved coordinate injectivity and domain separation
retain all 18 hypertree bits, twelve ordinary trees and all 2048 leaves.

The `Fors*Opening`, `Forest*Opening`, `C10*Opening` and `ObservedOpening*`
modules factor that selected leaf through the existing actual keygen, forest,
WOTS layers, signer, session and final verifier. Full-cache refinement retains
all other private calls, raw queries, refusals, failed requests and successful
exposures. Internal forest use does not reveal the selected node; a successful
signature containing its placeholder does. A failed WOTS phase does not reveal
it. The disclosure proof uses the actual complete signing history and final
cache, rather than a presumed hidden-history invariant.

`ObservedForestOpening.lean` maps the existing `ForestHistoryUnmatched` branch
with a valid complete signing history into this selected unreturned event and
takes the proved finite coordinate union. Its theorem
`c10_observed_forest_opening_bound_real` gives

```
Pr[ObservedForestOpening cfg in c10ObservedInitializedIndependent cfg sampler qr qs]
 <= 6442450944 * min((177526 + qr + qs * 408408) / 2^128,
                    (177524 + qr + qs * (sessionSignCost cfg + 1)) / 2^128).
```

The first term uses the derived variable-candidate budget plus two fixed values
and twelve final slots. It is independent of the R/WOTS grinding limits. The
second retains the conservative total-work charge, which is smaller at zero
signing budget. The additional one per signature is the observer's possible
reveal step. `ObservedForestOpening` deliberately requires no accepted-forgery
or final-H_msg guard, so its bound also covers the narrower unmatched branch
that supplies those guards. It still requires the actual complete signing
history and a cached ordinary private opening. The union factor is
`2^18 * 12 * 2048 = 6442450944`; this is a conservative upper bound, not an exact
probability or a tight 128-bit security claim.

This retires the separate PMF ordinary FORS opening charge. The WOTS
continuation below supplies the other opening charge. The six-case composition is proved below. No EasyCrypt execution, concrete SHA/Rust
correspondence, QROM or physical claim is added.

### WOTS earlier-than-all-exposures opening charge

`AdaptivePresample.lean` proves exact precomputation of an arbitrary adaptive
prefix: restore every entry the later client never queried to its original
baseline. The law preserves the full result, query trace and cache, including
pre-existing entries and duplicate queries. `WotsCutPrefix.lean` instantiates
this with the actual predecessor prefix. Its next input is fresh in that
precomputation; freshness is not assumed of the later adversary execution.

A typed deferred node identifies one actual address, one of 43 chains and one
cut in 0 through 6. The incoming key is private at cut zero and public at higher
cuts. Its outgoing commitment uses the next position, with proved input
separation. The actual leaf, 512-leaf builder, signer, both layers and keygen
retain all other calls and the entire cache. Position seven is a public endpoint.
Recovery uses proved cached replay of the actual generated signature and path.

`WotsC10Provenance.lean`, `WotsRecordProvenance.lean` and the disclosure modules
connect deferred metadata to every valid record in the actual complete signing
history. A legitimate release requires complete C10 success at the selected
address and a digit at or before the cut, including a known earlier node.
Exhausted, refused and incomplete requests do not create successful exposures;
their accumulated caches and ledger effects are retained.

`C10Probes.lean` records only admitted raw adversary inputs and final-verifier
queries. Its erasure is exactly the original observed game, including the full
cache. Honest secret-bearing inputs are not included as guessed candidates.
The proved bound is `qr + 361` probes, plus the two actual forged coordinates.
A public read of the incoming key reveals the selected full digest and contains
the preceding node. `WotsCutRecurrence.lean` explicitly charges that event to the
preceding cut, retaining its prefix replay and absence of a legitimate release.
The cut-zero incoming key cannot be read by the public probe interface.

`ObservedWotsBound.lean` sums the recurrence weights `1+...+7 = 28` over
`(512*512+512)*43 = 11294208` chains and averages over the initialized sampler.
`ObservedWotsExposure.lean` maps both existing complete-history earlier-exposure
branches into this event. The real-valued endpoint is

```
Pr[ObservedWotsEarlierExposure cfg in c10ObservedInitializedIndependent cfg sampler qr qs]
 <= 316237824 * (155867 + 2*qr + qs*364076) / 2^128.
```

The same bound holds for the broader original-game `ObservedWotsOpening` event.
It needs no accepted-forgery guard. The final endpoints have no assumed
freshness, transcript independence, session budget or disclosure implication:
those obligations are proved from the actual programs and complete history.
A kernel arithmetic example gives a charge below `2^-64` at `qr = 2^32` and
`qs = 65536`. This is a conservative branch bound, not a tight 128-bit margin
or a full forgery theorem. The six-case probability composition is proved next. The concrete-backend,
unbounded-adversary, repeated-grinder freshness, QROM and physical limits remain.
The separate PMF codec is closed in the byte-game extension below. These cache-visible events
are not transferred to the physical shared oracle; only the existing Boolean
result transfer has that interface.

## Six-case initialized forgery bound

`ObservedForgeCases.lean` now maps every supported accepted forgery in the
original initialized independent game into six alternatives: selected public
node collision, public zero, accepted WOTS-word collision, earlier WOTS
exposure, unmatched ordinary FORS opening, or FORS coverage. These events may
overlap. No disjointness or hidden-history independence is assumed.

`TaggedCacheCharges.lean` and `ObservedCacheCharges.lean` derive the first
three charges in that same tagged cache. The node selector reuses the existing
syntactic budget by mapping query labels only; it does not equate independent
and physical caches. Exact observed-game erasure preserves the full cache.
`ForgeBound.lean` then combines those charges with the existing opening and
coverage bounds. All statements quantify over arbitrary PMFs of finite
adaptive clients, with empty initial caches, actual keygen, signing failures,
caps, complete successful histories and final verification retained.

For raw-query cap `qr`, signing cap `qs`, and grinder limits `r` and `w`, write

```
N = qr + qs*(2*r + 2*w + 435044) + 177512
S = qr + qs*(r + 435042) + 177509
P = qr + qs*(r + 2*w + 364290) + 155496
A = 22169393903687611906220091621190388
```

The independent charge is

```
choose(S,2)/2^128 + N/2^128 + choose(N,2)*A/8^86
+ ordinaryWotsOpeningCharge(qr,qs)
+ ordinaryForsOpeningCharge(cfg,qr,qs)
+ forsCoverageCharge(qr+qs+1).
```

`SharedForgeBound.lean` transfers only the final Boolean event with the existing
`P/2^256` secret-prefix charge. The main endpoints are
`c10_shared_forge_bound_real` and `c10_shared_forge_bound_real_capped`:
`Pr[forge] <= min(1, independent charge + P/2^256)`. The observed shared game
has the same bound through exact Boolean erasure. No cache-visible event
transfer is needed. `ForgeArithmetic.lean` proves the expanded real formula,
including the FORS opening minimum and every Stirling/falling-factorial term.

At `r=w=10000000` and `qs=65536`, `ForgeNumeric.lean` checks:

| Raw-query cap | Bound for the actual initialized shared model |
|---|---|
| `2^20` | strictly below `2^-50` |
| `2^24` | strictly below `2^-34` |
| `2^32` | capped bound is `1`; the coverage charge alone exceeds `1` |

The first two examples consume the general shared-game theorem. The third
is a proved limitation of this conservative union bound, not a forgery attack
or a claim that the actual success probability is one. These figures are
budget-specific ideal-model upper bounds, not concrete wallet security levels.
The node budget still charges worst-case grinder work; the coverage pool cap
charges every admitted raw query as potentially accepted. Tightening either
requires further proofs and is outside this composition.

This closes the finite structured PMF successful-output composition and its
quantitative bound under #295. The byte-game extension below closes the PMF
codec boundary. Representation of arbitrary unbounded/lossless adversaries,
repeated-grinder freshness, concrete SHA/Rust
and EasyCrypt execution correspondence, cross-kernel transfer, QROM and physical
claims remain outside this result. The existing qualitative crypto assumptions
and the separate mathlib-free `lean/` project are unchanged.

## Exact byte codec and finite byte game

The separate PMF model now has an exact 4,008-byte signature codec and an
independently defined finite adaptive byte session. `ByteCodec.lean` and
`ByteCodecBlocks.lean` compose fixed-width node and big-endian u32 bijections;
`SignatureFields.lean` relates their fixed-size fields to the existing
structured well-formedness predicate. `SignatureCodec.lean` proves both
roundtrips: every well-formed structured signature survives encode/decode, and
every 4,008-byte vector survives decode/encode. Zero and maximum counters and
all node values remain representable. Decoding establishes shape, not
cryptographic acceptance. Other byte lengths return `none`.

`SignatureLayout.lean` proves the positional formulas, with zero-based indices:

| Field | Offset | Width |
|---|---|---|
| R | `0` | `16` |
| Secret `i < 13` | `16 + 16*i` | `16` |
| FORS path node `t < 12, h < 11` | `224 + 176*t + 16*h` | `16` |
| Layer `l < 2` | `2336 + 836*l` | `836` |
| WOTS node `c < 43` in layer `l` | `2336 + 836*l + 16*c` | `16` |
| Big-endian u32 counter in layer `l` | `3024 + 836*l` | `4` |
| XMSS path node `h < 9` in layer `l` | `3028 + 836*l + 16*h` | `16` |

The thirteen secrets are contiguous, followed by the twelve FORS paths.
Boundary consumers check both counter byte orders with distinct values,
last fields, all-FF input, maximum u32, and 4,007/4,009-byte refusal.

`C10ByteClient` receives optional byte signatures and can choose every later
request from earlier replies. `ByteSession.lean` defines its PMF execution
directly, then proves equality to the translated structured execution while
preserving the complete session result, ledger, remaining caps and oracle
cache. Refusal, admitted exhaustion, persistent failure, duplicate successful
messages, capped defaults and repeated cached reads retain the existing rules.
No new success, freshness or independence premise is added.

`ByteDriver.lean` checks failure, message width, signature length and new-message
admission before final verification. Malformed byte signatures translate to a
provably malformed structured value only inside the correspondence proof;
the direct byte semantics refuse them. `ByteGame.lean` executes actual keygen,
passes its seed/root and complete cache to the client, and proves full-game
refinement and the existing query budgets. Its initialized shared and
independent final Boolean PMFs equal the corresponding structured PMFs.

`ByteForgeBound.lean` consequently proves
`Pr[byte forge] <= min(1, sharedForgeCharge cfg qr qs)`, including real-valued
forms. Serialization adds no loss. `ByteGameExamples.lean` applies the existing
numeric bounds below `2^-50` and `2^-34` to arbitrary PMFs of finite byte clients.
The constant-cache acceptance witness is inhabited functional evidence, not an
initialized random-oracle history. The conservative bound at `2^32` raw queries
remains uninformative.

This closes the separate PMF byte-codec and finite byte-session boundary.
It does not establish concrete SHA, Rust or EasyCrypt execution equivalence,
cross-kernel transfer, representation of all lossless/unbounded adversaries,
repeated-grinder freshness, QROM or physical security. The existing manual
source pins, including `RawSignature.ec`, remain drift checks only.

## Context-aware adaptive R grinding

`RContext.lean` proves injectivity of the actual private R tail across request
contexts and counters. Admission requires a 32-byte message and optional
randomness of length zero or sixteen. The u32 nonce retains the existing
32-byte big-endian derivation encoding. A malformed-width counterexample
demonstrates why the message-width check is necessary.

`RContextHistory.lean` derives private-cache provenance from supported public
queries and actual memoized R/H_msg searches. `RContextReplay.lean` derives
successful replay witnesses from execution and preserves them under memo
extension. Thus an unseen valid context has fresh private inputs; an old
successful context returns its cached counter, R and digest without resampling.
`RPublicHistory.lean` bounds the public cache from actual query traces.

`RSessionProgram.lean` separately defines a direct PMF interpreter and a
query-program compiler, then proves equality of their complete outputs,
ordered successful-context lists, remaining caps and memo tables. Clients may
choose later public queries and searches from earlier replies. Refused calls
spend no cap; admitted searches spend one even on exhaustion. The first
exhaustion persistently refuses later searches while raw queries remain
available. Duplicate successful contexts remain in the chronological list.
Zero-trial searches and zero call caps are covered without a positivity premise.

For `m` trials, admitted raw/search caps `qr, qs`, and
`H = qr + qs*m`, the initialized independent session satisfies

```text
Pr[first exhaustion] <= qs * ((1 - 1/2048)^m
                              + collisionPairs(H,m) / 2^128)
collisionPairs(H,m) = m*H + m*(m-1)/2
```

`RSessionInvariant.lean` and `RSessionExhaustion.lean` discharge the history,
freshness and successful-replay invariants from the empty initial state.
The theorem permits arbitrary PMFs of finite adaptive clients. The bound
counts admitted calls rather than attempted-interaction fuel.

`RSessionTransfer.lean` refines the direct shared experiment through the
existing one-secret private-prefix interface. It adds `H/2^256` to the
returned-failure event and caps the result at one. The returned event includes
the session failure flag; no cache-visible event is transferred. Session
parameters and client randomness are independent of the sampled private-prefix
secret. `RSessionReal.lean` establishes finiteness before real conversion.
`RSessionNumeric.lean` proves a conservative bound of `2^-40` for ten-million-trial
searches at caps `qr = 2^32` and `qs = 2^20`, using a block bound on the
geometric tail instead of expanding the large exponent.

This closes the repeated-context freshness premise for this bounded R/H_msg
session. Its provenance is composed with the complete signer below. No
concrete SHA/Rust/EasyCrypt execution, cross-kernel, unbounded-adversary, QROM
or physical claim follows. The existing forgery bounds are unchanged.

## R exhaustion in the complete C10 game

`RForeignBudget.lean` selects private tails of the valid R widths, 71 or 87
bytes. Actual WOTS and FORS private tails have lengths 48 and 16; shuffle and
recovery queries use the public interface. A zero selected-call budget preserves
every selected cache entry exactly, including absence. `RForeignComposition`,
`RForeignWots`, `RForeignTree`, `RForeignFors` and `RForeignSign` compose this
property through the existing chain, stack-tree, forest, layer and complete
post-R signer programs. No original query program or budget is changed.

`C10RInvariant.lean` derives the empty R-context history from actual keygen.
An admitted search adds its real context; a successful search supplies a replay
witness that survives all later private and public calls. Public-history
coverage follows from the executed query budgets. These premises are discharged
at the initialized endpoint, including repeated contexts.

`C10RSign`, `C10RSession` and `C10RGame` define independent direct interpreters
and query-program compilers for an auxiliary R-failure observation. Their
refinements retain the original client replies, signed-message ledger,
remaining caps, final verification decision and complete cache. Erasing the
observation yields the original C10 session/game exactly. R exhaustion sets
the flag; later WOTS-count exhaustion does not. Either failure retains the
original persistent signing refusal, while raw queries remain available.
The flag is exposed only in the returned observer result.

For R/WOTS trial limits `m,n`, admitted raw/sign caps `qr,qs`, define

```text
S = m + 2*n + 364290
H = 155135 + qr + qs*S
Q = H + 361
Pr[an admitted R search exhausts] <=
  min(1, qs*((1-1/2048)^m + collisionPairs(H,m)/2^128) + Q/2^256)
```

`C10RExhaustion.lean` bounds first R exhaustion in the complete adaptive session.
`C10RGame.lean` composes actual keygen and final verification.
`C10RTransfer.lean` transfers this returned event through the uniform
secret-prefix interface, including randomized finite adversaries that receive
the actual generated public key. Configuration, public seed and adversary
randomness are independent of the sampled hidden prefix. No cache-visible
event is transferred.

`C10RReal.lean` proves finiteness before real conversion. `C10RNumeric.lean`
checks a conservative `2^-39` bound at `m=n=10,000,000`, `qr=2^32`, `qs=2^20`;
the larger history includes all full-signing public calls. Direct witnesses
distinguish zero-R exhaustion from later WOTS failure, repeated cached
signatures, malformed/capped refusal and public queries after failure.
An initialized zero-R-trial experiment has failure flag true with probability
one, without a prefilled-cache premise.

The other-private-caller provenance obligation is closed for this R event.
The complete signing-availability result below adds the WOTS-count component.
These remain ideal-model results with the correspondence boundaries below.

## Complete structured signing availability

`RejectCompletion.lean` bounds complete rejection of a fixed finite set of
oracle keys under any finite adaptive memoized query program started empty.
Its potential assigns an absent key the fresh rejection mass, a cached
rejection one, and a cached acceptance zero. A fresh query preserves the
expected product; cache hits reuse their stored values. Thus complete rejection
of `n` distinct keys has probability at most `r^n`, even when an adversary
queries them out of order or interleaves unrelated work. An arbitrary prefilled
table instead retains its explicit completion potential; repeated keys do not
increase the exponent.

`WotsCountDomain.lean` covers the actual serialized WOTS count stems at a fixed
public seed. The variable fields are the four-byte layer, eight-byte tree,
four-byte keypair and sixteen-byte message: exactly 256 bits. Kind, chain,
position, hash-address and padding bytes retain their actual zero values.
The finite cover includes all serialized field values, without assuming a
logical-address restriction or fresh message. A union over its `2^256`
contexts bounds the event that any complete count schedule is cached rejected:

```text
rW = 1 - 22169393903687611906220091621190388 / 8^43
Pr[any fully rejected WOTS count schedule] <= 2^256 * rW^n.
```

This bound is deliberately independent of the finite query cap. It applies to
the physical shared oracle directly, including public prefill, arbitrary
private inputs, adaptive context selection and repeated requests. It is a
cache-event bound, not an assertion that each search samples independently.
At `n=10,000,000`, `WotsDomainNumeric.lean` proves it at most `2^-64`:
the actual acceptance mass exceeds `1/30720`, and 320 conservative blocks
absorb the finite-context union.

`WotsFailure.lean` and `C10WotsFailure.lean` show that actual count exhaustion
leaves every scheduled key rejected. Failure provenance composes through
WOTS signing, both layers and the forest prework. `C10FailureSession.lean`
then proves that an initially healthy session's failed ledger implies either
the existing R observer flag or such a WOTS cache witness. Malformed requests
and exhausted interaction caps refuse without setting that ledger; later raw
queries preserve the witness. `C10FailureGame.lean` composes actual keygen and
final verification, and proves that the ledger observation agrees exactly with
the original session after erasing the R observer.

`C10Availability.lean` uses that same initialized physical shared game and
returns `c10SigningFailure`, the actual session ledger's failed bit. Its bound
for arbitrary PMFs of finite adaptive adversaries is

```text
Pr[an admitted signing request fails] <=
  min(1, c10RCharge(cfg, qr, qs) + 2^256 * rW^cfg.wTrials).
```

The R component retains its uniform hidden-prefix assumptions and actual
keygen/signing/verification public-call charge. The WOTS cache event is bounded
directly and is never transferred using the returned-event prefix theorem.
Finiteness precedes real conversion. At both grinder limits of ten million,
`qr=2^32` and `qs=2^20`, the kernel proves the combined bound at most `2^-38`.

This closes finite initialized **structured-model signing availability** under
#100. It does not change the existing forgery bounds or establish concrete
SHA/Rust/EasyCrypt execution, cross-kernel correspondence, arbitrary unbounded
adversary representation, QROM or physical security. The exact byte-session
refinement remains a separate existing result; this endpoint is stated for
the structured game.

## Byte-model signing availability

`ByteObservedDriver.lean` independently observes the existing byte session and
final verifier, retaining the actual session result, ordered ledger, remaining
caps, verification Boolean and full final cache. Its erasure is exactly the
original byte driver. Translation of the returned byte forgery and session
result agrees with the structured R observer after forgetting only its
auxiliary R-exhaustion flag. `ByteObservedGame.lean` composes actual key generation
and preserves both the final verification law and the failed-ledger event.

`ByteAvailability.lean` initializes an empty physical oracle with a uniform
hidden prefix. It permits any joint PMF of public seed and finite adaptive byte
adversary, independent of that hidden prefix; the seed and adversary need not
be independent of each other. The observation erases exactly to the previously
defined initialized byte game. Its actual signing-failure law equals the
structured returned-ledger law, so serialization adds no charge or premise:

```text
Pr[an admitted byte-session signing request fails] <=
  min(1, c10RCharge(cfg, qr, qs) + wotsDomainCharge(cfg.wTrials)).
```

The ENNReal and finite real bounds use the unchanged structured charge.
`ByteAvailabilityReal.lean` proves at most `2^-38` for both ten-million-trial
grinders, `qr=2^32` and `qs=2^20`. Nine direct witnesses distinguish admitted
R/WOTS exhaustion, malformed and cap refusal, healthy completion and cached
signing success. Constant prefilled caches in the witnesses are functional
examples, not asserted reachable initialized histories.

This closes finite initialized **byte-model signing availability**. The event
is the session's persistent failed ledger, not every refused request and not
forgery success. No cache-visible event is transferred between oracle models.
Existing forgery bounds and concrete SHA/Rust/EasyCrypt, cross-kernel,
unbounded-adversary, QROM and physical boundaries remain unchanged.

## Independence and correspondence boundary

`Digest.lean` proves an explicit bijection between 32 big-endian bytes and
`Fin (2^256)`, with round trips and both byte/integer formulas. Under the
uniform PMF on that full type, the quotient/remainder maps produce exactly
`wotsDraw` and `forsDraw`: digit `i` is `(d / 2^(3*i)) % 8`, and the FORS
acceptance field is `(d / 2^132) % 2048`. The decomposition retains all unused
bits when proving the bijection; no projection-uniformity premise is assumed.
Pointwise witnesses cover byte order, WOTS bit128 versus bit129, and FORS
bits131/132/142/143. Uniformity alone would not distinguish those positions.

`DigestGrind.lean` proves that projection commutes with bounded first-accepted
sampling, retaining the counter and `none`. It derives the raw-digest failure
and first-hit laws. An individual full returned digest has atom mass
`1/2^256`; an individual WOTS projection has mass `1/8^43`. These outcomes are
not conflated.

`Memo.lean` models actual lookup and update: a present key returns its stored
value without sampling, while an absent key draws and stores a reply. Existing
entries survive both queries and the complete bounded search. The search keeps
the final table even on exhaustion. Its returned-result distribution equals
`grind` when the schedule has no duplicate keys **and every key is absent from
the initial history**. Empty history witnesses this premise; uniqueness alone
does not imply it. This theorem concerns the result marginal, not equality of
a stateful distribution with a stateless one.

`Counter.lean` instantiates the schedule with a fixed input stem followed by a
full 32-byte big-endian counter block. It proves that the first 28 bytes are
zero for a `u32`, proves key injectivity and bounded-schedule distinctness, and
checks that the 10,000,000-trial cap fits. The WOTS digest projection and
exhaustion laws then transfer under the explicit initial-history premise.
Arbitrary earlier queries or an earlier signing call can invalidate it.

`KeyCollision.lean` samples independent uniform keys, stops on a hit against
its growing finite seen set, and returns a collision flag. For `n` trials,
`h` existing keys and a nonempty key space of size `M`, the actual flag's
probability is at most `(n*h + n*(n-1)/2)/M`. Both the history and pair terms
are derived; the bound also has a real-valued form and a `2^128` key-space
instantiation. It is an upper bound (possibly above one), not an equality or
a claim that the concrete keyed-R stream meets this experiment.

`Schedules.lean` and `RandomGrind.lean` prove that drawing keys online and stopping
at the first accepted memoized reply has the same distribution as drawing a
complete independent key schedule first, then running `memoGrind`. This equality
preserves both the returned result and final table; unused scheduled keys are
not queried after success.

`Transfer.lean` proves a two-sided event bound for that online program. For any
fixed result event, its probability differs from independent reply sampling by
at most `(n*h + n*(n-1)/2)/M`. Equality on collision-free schedules follows from
the earlier freshness theorem. The initial history covers every cached key in
the injectively encoded source alphabet; its exact finite preimage supplies a
witness for any starting table. The bound compares result marginals, not final
table events.

`Randomizer.lean` derives the uniform high 128 bits from the full digest and
proves that their big-endian encoding is exactly its first 16 bytes. The H_msg
key is `seed || root || R[16] || zero[16] || message || FF[32]`, with proved
injectivity in R and length 160 for 32-byte seed, root and message. For independent
R draws and memoized full-digest replies, FORS exhaustion differs from
`(1 - 1/2048)^n` by at most the history-plus-birthday charge over `2^128`. With an
empty initial table, the upper bound is that exhaustion term plus
`n.choose 2 / 2^128`, also specialized to the 10,000,000-trial cap. This is still
an independent-R comparison experiment. The shared-table refinement below
identifies its relation to the manually transcribed R-derivation procedure;
global session freshness remains open.

`LabelledGrind.lean` retains the chosen randomizer label, full reply, counter
and table in the independent-key loop. `forgetLabel` is an explicit projection
to the earlier digest-only result, and it preserves exhaustion probability.
`MemoView.lean` proves that observing a table with a designated domain erased
commutes with queries outside that domain. This erasure is an observation of
the final state, not a change to the executed oracle.

`DerivedGrind.lean` executes two queries through the same table per attempt:
the first reply determines the randomizer and hence the second key. If the
first-query inputs are distinct and initially absent, and their domain is
disjoint from the second-query keys, its distribution equals the labelled
independent-key comparison after erasing the first-query domain in the
observed table. The theorem retains the selected label, full reply, counter
and failure. A prefilled first-query input gives a checked counterexample to
using that comparison without freshness. A cached rejected second reply still
forces failure. Immediate-success postconditions independently check the
updated table for scheduled, online and two-query searches.

`SharedRandomizer.lean` instantiates this with
`secret[32] || R_grind[7] || optional_random[0 or 16] || message[32] || nonce[32]`.
The tag bytes, field order and full big-endian nonce block are explicit. The
103/119-byte input widths separate these queries from 160-byte H_msg inputs;
the existing bounded counter schedule supplies nonce distinctness. Distinct
nonzero field witnesses check deterministic and hedged R layouts and the
H_msg layout. The shared experiment returns R as its proved 128-bit value,
whose 16-byte serialization is already a bijection.

Under the explicit premise that every scheduled R input is initially absent,
the shared experiment inherits the digest-result event and FORS exhaustion
bounds, with arbitrary initial H_msg history retained. Empty history discharges
the R-input premise and gives `(1-1/2048)^n + n.choose 2 / 2^128`, including the
ten-million cap. No theorem says that secret keys or nonce distinctness alone
exclude earlier queries to these inputs. Adaptive prior-query guessing,
repeated signing calls and complete signer-session transfer remain open.

`QueryProgram.lean` represents a finite oracle client whose next input may
be chosen from earlier replies. Its index bounds the number of queries on
every continuation, including early returns and the last permitted query.
`evalProgram` uses the existing memoized oracle and returns both the client's
value and the final table. A PMF over such programs supplies client randomness;
continuations receive replies rather than the oracle's private table. This
represents bounded adaptive clients, not a translation of the complete signer.

`CollisionObserver.lean` adds a finite set of projected replies and a persistent
collision flag. Only fresh queries insert a projection or set the flag;
cached repeats retain the previous reply and observer state. Erasing these
observers gives exactly the original program's returned-result and final-table
distribution. A proved support invariant connects the flag to actual final-table
collisions between distinct inputs, including different full replies with the
same projection.

`AdaptiveCollision.lean` derives a history-plus-birthday bound for every such
adaptive program and every initial randomized choice of program. If the
initial table has no projected collision, a set of `h` projections covers all
its entries, and each fresh reply has a uniform projection in a space of size
`M`, the probability of a distinct-input projected collision in the final table
is at most `(n*h + n.choose 2)/M`. Query inputs need not be independent or
uniform. Cached queries do not resample, and the budget is worst-case query
count rather than expected work. The real-valued bound is derived from PMF
probabilities with explicit finiteness checks. The already-proved full-digest
high-128-bit law gives `n.choose 2 / 2^128` from an empty table.

`AdaptiveExamples.lean` independently checks the boundary: repeated lookup of
one input has collision probability zero; two fresh Boolean inputs have
collision probability `1/2`; one prior entry and a fresh query also give `1/2`.
A reply-dependent query has observer-flag probability `1/4`. An already
colliding table has collision probability one even with zero new queries, so
initial collision freedom cannot silently be omitted. The client, observer
and final-table event are separate definitions connected by proved laws.

`AcceptedObserver.lean` and `AcceptedCollision.lean` tighten the collision
component to equal **accepted** projections at distinct inputs. The real cache
still stores every fresh reply; only accepted projections enter the observed
set and can set its persistent flag. Erasure preserves the complete result and
cache. If `h` projections cover the initially accepted entries and that cache
has no accepted collision, the actual adaptive event probability is at most
`(n*h + n.choose 2*p)/M`, where `p` is the fresh-reply acceptance probability.
The proof derives the factor `p` from expected accepted-history growth. Query
keys may depend on replies, cached calls do not resample, and early returns and
randomized clients are retained. Both extended-nonnegative and real bounds are
proved; the initial-validity guard is explicit.

`AcceptedWots.lean` instantiates this result with the existing full-digest
projection to 43 base-eight digits and the sum-205 test. From an empty cache,
the accepted-encoding charge is `n.choose 2*p/2^129`, with the exact
`p = Nat.card AcceptedWots / 8^43`. `WotsCount.lean` and `WotsExact.lean`
now supply its kernel-checked numerator and numeric substitution. This
introduces no freshness or successful-grinding premise and does not supply the full forgery
game or its successful-output partition.

`AcceptedExamples.lean` independently computes actual finite distributions.
Two fresh Boolean inputs have accepted-collision mass `1/4` when only `true`
is accepted, versus `1/2` when every reply is accepted. Cached repeats and
rejected duplicates contribute zero. Adaptive inputs and rejection-based early
return are checked, including the unqueried second key. One accepted history
entry and a fresh query have collision mass `1/2`; an already accepted-colliding
cache has mass one with zero new queries. These examples also check flag
persistence and that rejected fresh replies remain stored.

`TargetEvent.lean` derives a direct final-cache target-hit bound from the
unchanged adaptive interpreter: at most `n * acceptMass p target`, provided the
initial cache has no hit. The predicate is fixed before execution. Query keys,
early returns and client randomness may depend on replies; cached calls do
not draw again. Existing target hits persist, including with zero new queries.
`TargetSet.lean` specializes uniform projected replies to a fixed finite set,
with bound `n * targets.card / M`. This does not apply to targets chosen after
seeing the replies.

`NodeZero.lean` defines a node as the actual first sixteen big-endian digest
bytes and proves that its all-zero predicate is the high-128-bit projection's
zero value. Its fresh mass is `1/2^128`, yielding an actual final-cache zero-node
bound `n/2^128` from an empty cache. A nonzero full digest can still have a zero
node. `NodeCharges.lean` unions that event with the existing public collision
event on the same program and cache, giving `(n.choose 2+n)/2^128`. This counts
all queries in the program; the narrower EasyCrypt node-producing-domain
budget is not imported or assumed here.

`SelectedBudget.lean`, `SelectedObserver.lean` and `SelectedCollision.lean`
now derive a tighter collision charge for a fixed input selector. A structural
budget `q` counts selected calls on every continuation, including cache hits;
the actual query trace satisfies that budget. All queries still execute against
the full memo table, and excluded replies can choose future selected inputs.
Erasing the observer preserves the complete returned result and cache. If the
initial selected cache is collision-free and covered by `h` seen projections,
the actual final selected-cache collision probability is at most
`(q*h+q.choose 2)/M`. Randomized clients and real-valued bounds are included.

`NodeDomain.lean` transcribes the exact EasyCrypt selector: exclude all160-byte
inputs and128-byte inputs whose bytes44–47 are zero; retain everything else,
including malformed raw inputs. H_msg and padded WOTS-count inputs are
excluded under their width/tag premises. Chain/compression widths and
nonzero-kind pair inputs remain selected. `DomainNodeCharges.lean` gives
`(q.choose 2+n)/2^128` from an empty cache, where **zero nodes are still charged
to the full raw-query index `n`**. The selected event and zero event share the
same actual execution and final full cache.

`DomainGrind.lean` derives this budget for the existing physical R/H_msg
grinder: at most one selected and two total calls per trial. The H_msg call is
excluded; R inputs remain selected by this conservative raw-domain selector.
The actual `sharedRandomizerSearch` charge is therefore
`(trials.choose 2+2*trials)/2^128`, without a freshness or successful-return
premise. This does not yet port the complete EasyCrypt C10 node-cost formula
or its successful-output/forgery partition.

`DomainExamples.lean` computes actual finite events independently of the
bound. An excluded first reply chooses whether later selected calls repeat,
giving collision mass `1/4`; a randomized optional execution gives `1/8`.
Nonempty selected history gives `1/2`, while a preexisting selected collision
has mass one at zero queries. Cache retention, cached replies, repeated-call
budgeting, every adaptive branch, exact kind-byte boundaries and malformed
widths are checked. A zero value at an excluded input still makes the combined
event bad.

`TargetExamples.lean` checks actual finite cache-event probabilities: two fresh
Boolean keys hit `true` with probability `3/4`, a repeated key with `1/2`, a
reply-dependent repeat with `1/2`, early return with `3/4`, and a randomized
optional query with `1/4`. Safe cached replies, rejecting/accepting predicates,
initial hits at zero budget and empty/full target sets are checked separately.
Concrete caches distinguish a zero node without collision from a collision
without a zero node, so neither side of the union is dispensable.

These adaptive results supply a random-oracle collision component. They do not
instantiate a complete C10 signer/adversary program, prove global R-input
freshness or supply the remaining full forgery bound. No theorem replaces
worst-case hash budgets with expected grinding work.

`QueryTrace.lean` records every public query of the actual adaptive interpreter,
including cached repeats. Erasing the trace preserves the returned value and
memo table. A support proof bounds its length by the program index and shows
that every entry in a table started empty originated in a recorded query.
This supplies the finite history bound used by the subsequent grinder.

`PrefixGuess.lean` samples a uniform secret before the public prelude, then
proves that sampling it afterwards gives the same joint distribution. The
client, its initial randomization, the initial table and public reply law do
not receive that secret. Each queried input decodes to at most one candidate,
so the probability that the trace names the secret is at most `q/|Secret|`.
The bound is derived from the actual trace; its probability is not a premise.

`SecretPrefix.lean` decodes the first 32 big-endian bytes, rejecting shorter
inputs. It proves the exact secret prefix of every transcribed `R_grind`
input, including the existing tag, optional randomness and nonce placement.
For the uniform 256-bit secret, the prelude hit charge is `q/2^256`. On a
non-hit execution from an empty cache, every scheduled R-input is absent.
This discharges the earlier initial-freshness premise for this public-prelude
experiment; it does not establish freshness across earlier signing calls.

`PreludeTransfer.lean` executes a first shared-table grinder after that
prelude. Its request may depend on the public result, with the existing
message/seed/root widths and zero-or-16-byte optional randomness. For every
event on the returned public value and grinding counter/digest, the absolute
probability difference from the independent-R memoized comparison is at most
`q/2^256`. Both executions preserve cache behavior internally; this final
observation marginalizes the selected R and final table. It is not a relation
for an arbitrary continuation after that signing call.

`PreludeBound.lean` proves that the prelude's H_msg history has at most `q`
entries, rather than assuming a cache-size bound. It combines the derived
prefix charge with the existing history/birthday and finite-search results:

```
Pr[first shared-table FORS grinder exhausts after n trials]
  <= (1 - 1/2048)^n + (n*q + n.choose 2)/2^128 + q/2^256.
```

The theorem includes the ten-million-trial specialization. Here `q` bounds
all prelude queries and `n` bounds actual grinding attempts; both are
worst-case counts. The secret is uniform and independent of the public
prelude and request parameters. Secret-dependent key generation, earlier
signing responses and repeated signing are not covered by this first-grinder
theorem. The interleaved interface result below does not itself prove repeated
grinder freshness or instantiate the complete signer-session/forgery game.

`PreludeExamples.lean` independently checks fixed and repeated Boolean guesses
(probability `1/2`), an adaptive guess (`3/4`), and a client explicitly given
the secret (one-query hit probability one). The latter uses a different
interface and shows why uniformity alone is insufficient. A prefilled-cache
example also shows that an empty trace cannot establish freshness unless the
initial cache condition is respected.

`QueryMap.lean` relabels inputs of the existing adaptive interpreter, preserving
its reply-dependent continuations and total-call index. Public and private calls
are represented by different sum constructors. `PublicBudget` is a structural
condition on every continuation; a support proof bounds the number of public
calls in the actual trace. Every program also satisfies its total-call index as
a conservative public budget. Private calls consume that total index but do not
consume the separate public-call charge.

`StoppedProgram.lean` defines an auxiliary execution that stops before a
designated bad query. It proves both that its retained-event probability is
below the full execution's and that the full execution is bounded by the
retained event plus the actual stopped mass. Its stopped mass equals the bad
event on the full query trace. `MemoRelabel.lean` proves equality of stopped
executions from a cache correspondence and key injectivity away from bad
queries, then derives the two-sided event comparison for the full executions.
The shared and independent experiments themselves never use the stopped
interpreter.

`PrivateQueries.lean` collects prefix candidates only from public queries.
The ideal oracle uses one sum-key memo table, which gives separate public and
private caches. Repeated private tails return their stored reply. The hidden
uniform secret is sampled before the client, but the program, its initial
randomness and the ideal oracle do not receive it. Public queries may depend
on earlier private replies. Delayed sampling and the proved public trace bound
give an actual prefix-hit probability at most `q/cardSecret`.

`PrivateTransfer.lean` executes the same bounded client against a shared table
where private keys are secret-prefixed, and against the independent sum-key
table. Prefix decoding and private-tail injectivity discharge the correspondence
away from a public prefix hit. For every event on the returned client value,
the probability difference is at most `q/cardSecret`, in both `ENNReal` and
real-valued forms. Zero public budget gives exact returned-value distribution
equality. Both experiments start with empty tables. Their final private tables
are not public observations; a finite adaptive continuation can instead be
included in the client and its returned value.

`PrivateSecret.lean` instantiates the interface with the exact 32-byte
big-endian secret followed by an arbitrary byte tail, a uniform full-digest
reply law, and error `q/2^256`. It proves private-tail injectivity and the exact
connection to the existing `R_grind` preimage. The generic theorem's encoding
conditions are discharged for these concrete formulas.

`PrivateExamples.lean` computes a nonzero comparison gap independently: a
private call followed by a fixed public guess, or the reverse call order, gives
equality of the two replies with probability `3/4` in the shared experiment and
`1/2` in the separate-cache experiment. Repeated private calls return the same
reply with probability one. An adaptive public guess after a private reply has
prefix-hit probability `1/2` in the Boolean instance. Giving the client a
three-valued secret makes the `1/3` charge invalid; a noninjective private
encoding also creates a gap with zero public calls. A prefilled physical table
fails the required empty-start cache relation, and short byte inputs do not
name a complete secret prefix.

This closes the interleaved private-prefix interface component. It does not
translate C10 key generation, signing and verification into one PMF client or
prove the full forgery bound. In particular, separate private caching is not
fresh resampling: a repeated R-input still returns its earlier reply. The
first-grinder exhaustion theorem keeps its existing premises. Direct secret
leakage, correlated initial state, concrete SHA and quantum queries remain
outside these results.

`ProgramComposition.lean` composes bounded clients using their actual return
values and persistent cache. Index padding preserves execution and does not
issue queries. The composition theorem preserves the complete state, and the
public-budget theorem adds worst-case public calls across both stages.

`GrindProgram.lean` compiles `derivedMemoGrind` into that client language. Its
full-state equality holds for arbitrary starting tables, including cached
replies, without a successful-search or freshness premise. Each attempt makes
the actual first query, derives the second input from its reply, and tests the
second reply. Success retains the selected label, full reply and counter;
failure advances the counter and retains the updated table. No later input is
queried after acceptance. The total index is twice the number of permitted
attempts, and the private/public instance has at most one public call per
attempt.

`GrindInterface.lean` proves that prefixing its secret-independent tail schedule
produces exactly the existing R-input schedule, including `R_grind`, optional
randomness, message and the full counter block. Its concrete client has total
index `2*n` and public budget `n`. Mapping private calls through the hidden
secret gives exactly `sharedRandomizerSearch`, including its returned R,
digest, counter, failure and full memo table. Running the client with sum keys
gives the separately cached private/public comparison. These equalities do not
assume fresh R inputs or discard the final state.

`GrindSession.lean` defines the actual three-stage executions separately: an
adaptive prelude, the existing grinder, and a bounded continuation. It proves
their equivalence to composed clients and obtains

```
|Pr[shared execution returns E] - Pr[separate-cache execution returns E]|
  <= (q_before + n + q_after) / 2^256.
```

Both directions are proved over `ENNReal`, followed by the real-valued bound
and the ten-million-trial specialization. Requests may depend on earlier
private replies; the continuation receives the actual selected R and digest,
counter or failure, and runs against the actual updated cache. The public
budget includes the grinder's H_msg queries. Both global caches start empty,
and neither the client, request function nor continuation directly receives
the uniform secret. Intermediate tables need not be empty or fresh. A finite
continuation can include further compiled calls, but private repeats remain
cached; no repeated-call independent-sampling or exhaustion bound follows.

`GrindClientExamples.lean` independently evaluates cache reuse across composed
clients, a reply-dependent continuation with mass `1/4`, immediate success,
cached first and second replies, counter advancement, zero-budget failure and
two repeated private grinder calls. The repeated calls agree with probability
one, illustrating why the ideal private table must not be read as fresh R
sampling. This closes the actual grinder's application to the prefix-interface
theorem, including later bounded work. Complete C10 keygen/sign/verify client
translation, full PMF forgery composition and concrete backend correspondence
remain open. The earlier independent-R exhaustion theorem keeps its premises.

`CountProgram.lean` now compiles the one-query `memoGrind` search into the
same bounded client language. The equality retains the complete cache, selected
counter and full digest, early success and exhaustion, including cached replies.
`SelectedComposition.lean` adds selected-budget composition without dropping
excluded calls. `AddressBytes.lean` gives the exact big-endian 32-byte C10
address layout; its natural-number fields are truncated to their byte widths,
and correspondence to Rust uses the existing u32/u64 argument domains.

`WotsProgram.lean` instantiates the actual WOTS count input:
`seed[32] || address[32] || message[16] || zero[16] || counter[32]`.
The counter schedule stays within its 32-bit range. At most `n` raw calls and
zero selected-node calls follow from the actual program, with no freshness or
success premise. Its final-cache node-collision-or-zero charge is therefore
`n/2^128` from an empty table: excluded queries still contribute to the zero
term. Existing independent-sampling projection and exact ten-million-trial
exhaustion laws transfer only when every scheduled key is absent initially.
Exhaustion is represented by `none`; this is not a proof of Rust panic handling
or the secure wrapper's retry behavior.

`ChainProgram.lean` and `WotsChain.lean` model the reply-dependent chain loop.
Each 96-byte query includes the current chain position and the previous node;
the next node is exactly the first sixteen big-endian digest bytes. Splitting
at an intermediate position preserves the complete execution and shared cache.
For any base-eight WOTS digit, running from zero to that digit and continuing
to seven equals the full chain execution, including cached replies. The
selected trace has exactly `stop-start` calls for an ordinary 32-byte seed;
zero or reversed natural ranges retain the initial value and table. These are
count/chain components; their composition into public recovery is described
below. The complete WOTS leaf and shuffled signer are described after recovery.
`WotsProgramExamples.lean` checks finite adaptive/cached executions and exact
byte vectors independently of the compiler-equality proofs.

`ChainCollection.lean` executes an ordered finite collection of chains through
one shared cache and compiles it with the exact sum of step counts as its raw
index. `WotsRemaining.lean` instantiates all 43 signature positions in order.
It proves `sum(7-digit) + sum(digit) = 301`; the actual sum-205 acceptance test
therefore gives exactly 96 remaining steps. This is a derived cost, with no
independent-chain or freshness premise. `WotsCompression.lean` preserves the
kind-1 address and concatenates every 16-byte node with its sixteen zero padding
bytes, in order. Its input is exactly 1,440 bytes for a 32-byte seed and 43 nodes;
the returned node is the high 128 bits of the full cached digest.

`WotsRecovery.lean` combines the count query, actual acceptance test, all chains
and compression. Its compiler equality preserves both the result and full memo
table for arbitrary initial history. Rejection returns zero after the one count
query; it does not query a zero node. The complete client has at most 98 raw
calls and 97 selected-node calls, since the count key is excluded. From an empty
cache, its selected collision-or-raw-zero event has probability at most
`(97.choose 2 + 98)/2^128 = 4754/2^128`, also in real-valued form. This event is
about oracle replies, not the invalid-return sentinel. `WotsRecoveryExamples.lean`
checks finite ordered/cache executions, exact compression bytes, accepted-word
arithmetic, and a complete recovery with every query already cached.

`StateFold.lean` compiles stateful indexed folds while threading the full cache.
`WotsPrivate.lean` retains the actual private input: a 32-byte secret prefix,
the literal `wots` tag, four-byte layer, 32-byte tree field, four-byte keypair
and four-byte chain index. Private and public calls have separate labels in the
interface client; physical interpretation sends both through one raw memo table.
The direct loop writes each result at its chain index. `WotsLeaf.lean` composes
43 private derivations, seven public steps each and ordered compression, deriving
345 total and 302 public calls. Its physical compiler equation preserves the
complete result and table for arbitrary initial history.

`WotsShuffle.lean` executes four ordered full-digest block queries, then the
actual little-endian 16-bit multiply-high Fisher-Yates computation. It proves
index bounds, sufficient stream bytes, and preservation of all 43 positions.
The zero seed returns the identity with no query. No uniform-permutation or
physical side-channel claim is made. `WotsSigning.lean` composes bounded count
search, this shuffle and the private chain fill, retaining exhaustion, the
selected counter and every positional signature write. Its direct procedure
has no extra acceptance guard: a support theorem proves the count procedure
only returns accepted digests and discharges the compiler's unreachable branch.
Actual sum-205 acceptance and the proved permutation give 205 chain calls,
43 private calls and at most four shuffle calls. Thus the whole signer has at
most `n+252` total and `n+209` public calls for an `n`-trial count limit.

`WotsSigningCharges.lean` proves the full physical relabelling and derives at
most 252 selected calls for normal seed/message widths. From an empty cache,
the selected collision-or-raw-zero charge is `(n+31878)/2^128`; count calls
remain in the zero term. The separate private-prefix comparison has event
error at most `(n+209)/2^256` for signing and `302/2^256` for the leaf, with an
initially uniform hidden secret, secret-independent client inputs and empty
tables. Repeated private inputs remain cached. `WotsSignerExamples.lean` checks
byte layouts, a separately computed patterned permutation, all four ordered
shuffle calls, positional writes, cached complete signing and exhaustion.

`TreeShape.lean`, `TreeMerge.lean` and `TreeRun.lean` compile the actual
leaf-by-leaf list-stack treehash procedure. The pure schedule proves that 512
leaves leave one height-9 root and execute 511 merges; costs are derived from
those transitions. `Subtree.lean` composes the WOTS leaves and ordered kind-2
pair inputs into the full subtree root, with 177151 total and 155135 public
calls. Compiler equalities preserve the complete result and arbitrary initial
memo table, including cached calls and adaptive replies.

`MerkleBuild.lean` retains the actual keep/kept state, sibling parity, pre-hash
left/right choice and per-height list writes. `TreeAccess.lean` proves that all
executed merge heights are below 9 and that the returned path has nine entries.
`MerkleRecover.lean` retains all nine directional calls, parent/index updates,
child order and default siblings; its array reads are in range for a nine-entry
path. These are manual procedure/compiler and cost theorems, not a new universal
build/recover correctness theorem or an all-input Rust extraction theorem.

`MerkleCharges.lean` gives subtree root/build prefix-event error 155135/2^256,
with a uniform hidden secret independent of the client and empty initial tables.
The empty-cache selected collision-or-raw-zero charge is 15691326976/2^128,
conservatively counting all 177151 calls in the selected budget. The recovery
charge is 45/2^128. `MerkleExamples.lean` checks independent address/child bytes,
authentication writes/defaults, exact query traces and cache retention;
`TreeCached.lean` proves an inhabited complete cached subtree execution.

`ForsInputs.lean` and `ForsShape.lean` retain the private `fors` tag and
coordinates, kind-3 leaf/pair addresses and kind-4 ordered compression. The
executed stack schedule proves 2048 leaves, 2047 merges and eleven valid
authentication slots. `ForsTree.lean` retains matching-slot overwrites (FORS
has no Merkle kept flags), the target secret query before tree construction,
and all cache updates. The tree uses 6143 total/4095 public calls, signing uses
6144 total/4095 public calls, and `ForsRecover.lean` executes a leaf hash followed
by eleven directional sibling calls. Full result/cache compiler equations hold
for arbitrary initial history.

`ShuffleDerive.lean` models the literal sub-seed domain, complete label and
full 256-bit reply. `ForestShuffle.lean` executes the FORS sub-seed query and
four ordered full-digest blocks, then the actual twelve-position Fisher-Yates
permutation. Both zero-seed branches skip their queries. The permutation and
read bounds are proved; uniform permutation and physical protection are not
claimed. `ForestOne.lean` signs each tree and then actually recovers its root.
`ForestFill.lean` visits those twelve trees in the computed order and writes
secrets, paths and roots at natural tree positions.

`ForestSign.lean` builds the thirteenth tree root, transmits that root as the
last secret, and separately hashes it as a leaf for the final compression slot.
The ordered thirteen-root compression supplies the returned public key. All
stages share the cache. Worst-case cost, including cached calls and all shuffle
branches, is 80022 total/53386 public calls. `ForestRecover.lean` executes twelve
ascending recoveries, the last zero-index leaf and compression: 146 calls.
The forced-zero digest check belongs to the outer verifier. `ForestAccess.lean`
proves the returned array lengths and relevant read bounds. `ForsExamples.lean`
checks literal bytes, digest fields, authentication overwrites, patterned shuffle,
query order and distinct transmitted-root/leaf/compression roles.
`ForestCached.lean` supplies inhabited complete cached executions.

`ForestCharges.lean` derives physical full-cache compiler equalities. Prefix
event error is 4095/2^256 for tree/signing and 53386/2^256 for forest signing,
with an independent uniform hidden secret and empty initial tables. Conservative
empty-cache collision-or-oracle-zero charges count every raw call as selected:
18871296/2^128 for a tree, 18877440/2^128 for tree signing, 3201800253/2^128
for forest signing and 10731/2^128 for recovery. These bounds are not forgery
bounds and do not turn cached repeats into independent samples.

This closes the named manual WOTS, Merkle and FORS/forest compiler/cost clients.
The complete structured C10 clients now compose these components as described
below. No new universal tree/forest build/recover correctness theorem is claimed.

## Complete structured C10 clients

`LayerInputs.lean` retains the seven-byte `wots-0\0`/`wots-1\0` labels,
the 18-bit field starting at bit 143, and the actual leaf/parent coordinates.
Recovery encodes natural counters in all 32 bytes; it does not wrap them to
u32. `RecoveryRelabel.lean` and `WotsRecoveryUnder.lean` preserve public recovery
under a surrounding input map and agree with the existing recovery on u32 counts.
`LayerRecover.lean` still executes the nine-node path after WOTS returns zero.
`LayerSign.lean` builds the subtree, derives its full-digest shuffle sub-seed,
signs, and actually reconstructs the root. The builder's root is unused.

`HypertreeSign.lean`, `HypertreeRecover.lean` and `C10Finish.lean` execute both
layers in order, carrying reconstructed nodes, signatures and the full cache.
`RandomizerUnder.lean` and `C10Sign.lean` prepend the actual two-query R/H_msg
search. `C10Verify.lean` recomputes H_msg, enforces the last-FORS-field-zero
condition, recovers the forest and both layers, and compares the whole padded
32-byte root. Missing-layer defaults remain explicit. `C10Keygen.lean` takes
the public digest's high half, pads it, and builds layer 1/tree 0.

The compiler equations hold for arbitrary initial cache. Structural budgets
count every call, including cache hits and prework before exhaustion. Let `m`
be the R trial cap and `n` the WOTS count cap, each at most `2^32`:

| Client | Total calls | Public calls | Selected node calls |
| --- | ---: | ---: | ---: |
| Layer signing | `n+177511` | `n+155452` | `177510` |
| Finish after R | `2*n+435044` | `2*n+364290` | `435042` |
| Complete signing | `2*m+2*n+435044` | `m+2*n+364290` | `m+435042` |
| Verification | `361` | `361` | `358` |
| Key generation | `177151` | `155135` | `177151` (conservative) |

`C10Charges.lean` proves the physical shared-cache equations. Prefix event
error is the public budget divided by `2^256`, under independent uniform hidden
secret and empty-table premises. From an empty physical cache, signing's
collision-or-oracle-zero charge is
`((m+435042).choose 2 + 2*m+2*n+435044)/2^128`; verification's is
`64264/2^128`. Selected-call exclusions require the proved seed/root/message
widths; the zero term retains the total budget. These are not forgery bounds.

`LayerAccess.lean` and `C10Access.lean` prove successful counter and signature
shape bounds from the executed clients: 13 secrets, 12 eleven-node paths and
two layers with u32 counts and nine-node paths. `C10Flow.lean` retains the
actual resulting tables in first/second-layer failure equations and shows that
zero WOTS budget still performs forest/build/sub-seed prework. `C10Cached.lean`
and `C10Examples.lean` supply complete cached signing success/failure, verification,
literal bytes, field placement, root-padding refusal and ordered two-layer traces.
Populated constant-cache witnesses are not fresh-oracle or honest-correctness claims.

This is a manually transcribed structured-signature model. The exact byte codec,
finite session, honest structured-signature correctness, successful-output
partition and finite forgery PMF bound are now composed in this project.
Repeated-grinder freshness and concrete backend execution remain open.
Rust panic/retry/callback/erasure behavior, natural-number address truncation,
cross-language correspondence and physical execution retain their existing boundaries.

The adaptive structured session now compiles through these clients.
`SessionTypes.lean` represents finite reply-dependent hash/sign interactions,
with attempted-interaction fuel distinct from admitted-call caps. `SessionProgram.lean`
proves full result/cache equality between the compiler and direct PMF session.
A raw-cap refusal returns the zero digest; signing checks the failure flag,
message32, random0or16, shuffle32 and remaining signing cap. Refusal changes
neither cap nor cache. Every admitted signing call spends one cap, including
exhaustion; only successful signatures append the message, and failure prevents
later signing while leaving raw hash calls available. `SessionState.lean` proves
monotone caps, persistent failure, ledger-prefix preservation and message widths.

`SessionDriver.lean` checks nonfailure, message width, structured signature shape
and absence from the successful-message ledger before final verification.
`SessionGame.lean` initializes keygen and passes the resulting public seed/root
and full cache to the adaptive client. Its compiler-only public-key width guard
is proved redundant on actual keygen support. All requested raw hashes,
signatures and final verification retain the same oracle history.

For nonnegative raw/sign caps `qr,qs`, define the complete initialized budgets:

- `T = qr + qs*(2*m+2*n+435044) + 177512` total calls;
- `P = qr + qs*(m+2*n+364290) + 155496` public calls;
- `N = qr + qs*(m+435042) + 177509` selected physical-node calls.

These bounds do not grow with refused attempts. Private R inputs remain in `N`.
`SessionCharges.lean` gives the empty-cache physical node-event charge
`(choose(N,2)+T)/2^128`. For any independent public-seed/adversary sampler, a
uniform hidden secret and initially empty tables, the real-valued returned-event
error between the actual initialized shared game and the independent-interface
game is at most `P/2^256`. The forgery-transfer inequality keeps the independent
game's forgery probability on its right-hand side; it does not bound that
residual event. `SessionBranches.lean` characterizes successful driver support,
and `SessionExamples.lean` checks refused calls, repeated cache reads, admitted
exhaustion, duplicate successful messages, replay rejection and a populated-cache
initialized success. These are finite structured clients, not a representation
theorem for every lossless or unbounded EasyCrypt adversary. The exact byte-codec extension is proved above. The supported successful-output alternatives
and final finite-model forgery bound are composed above.

The passive observed interpreter in `ObservedSession.lean` now retains each
successful request/signature exposure and each admitted client hash input in
chronological order, including duplicates. Refused requests are absent; an
exhausted signing call spends its cap without creating an exposure. Exact
erasure preserves the original session result and complete cache.
`ObservedAccounting.lean` identifies the message ledger with the exposure
messages and proves query/cap accounting.

`QueryReplay.lean` derives lookup-only replay from actual execution support
and preserves it under later cache extensions. `ObservedGame.lean` and
`ObservedOutput.lean` use that result to retain actual keygen, successful
signing exposures, forwarded query replies and the final forgery in one final
cache. Accepted outputs satisfy the actual admission/freshness checks and
provide H_msg, FORS and ordered two-layer root-reconstruction witnesses.
`RecoveryWitness.lean` preserves the rejected WOTS count/zero-sentinel branch;
root equality does not establish acceptance of every WOTS count.

`ObservedInitialized.lean` proves exact returned-Boolean erasure for both
initialized games and inherits their existing `P/2^256` transfer. It does not
compare cache-visible events across the two oracle interfaces. The six-case alternatives and finite numerical bound are composed above.
Finite examples check refusal, order, repeated cached queries, exhaustion,
duplicate signatures, replay rejection and populated-cache success; that last
witness supplies no empty-cache success probability.

`TreeReplay.lean` and `TreeCertificate.lean` now derive recorded tree
certificates from the actual indexed builder loops. `TreeRootCertificate.lean`
instantiates all 512 Merkle leaves and 2,048 FORS leaves. Each certificate
retains actual leaf replay and ordered parent lookups in one cache, and survives
later cache extensions. `TreeReference.lean` derives a reference leaf and path
for every valid coordinate chosen after construction; it does not assume a
reference oracle or correctness of the builder's returned authentication array.

`PathRecovery.lean` connects those paths to actual recovery, retaining missing
sibling zero defaults and ignoring surplus siblings exactly as the programs do.
`NodeInputBinding.lean` proves fixed-width child-input injectivity at a common
coordinate. `NodePathBinding.lean` and `BuilderRecoveryBinding.lean` therefore
bind recovery to an actual WOTS leaf or private FORS derivation, or an explicit
selected-node collision. Global injectivity of truncated addresses is not used.

`TopTreeOpening.lean` applies this to actual winning initialized independent-game
outputs: selected-node collision, public zero, or a jointly linked top-tree
opening. H_msg, forest and lower-layer recovery, top WOTS recovery, the actual
keygen leaf, count digest and padded root remain in the same final cache.
Count acceptance is derived only after excluding the public-zero case. This
opening is not yet a new-message WOTS attack. The 21 tree-binding finite
examples cover populated tree execution, all four toy reference positions,
defaults, and counterexamples when coordinate, length, collision or zero
conditions are omitted. They supply no empty-cache success probability.

`ChainReplay.lean`, `WotsInputBinding.lean` and `WotsChainBinding.lean`
split actual lookup chains and bind their starting values at the same coordinate
under the selected-public-node collision exclusion. `WotsFillReplay.lean` and
`WotsRecoveryReplay.lean` extract all 43 private-seeded keygen references and
ordered recovery endpoints. `WotsLeafBinding.lean` binds the ordered, fixed-width
compression inputs: accepted recovery of the actual keygen leaf fixes each
submitted signature value to its private-seeded prefix in the same cache.
`TopChainOpening.lean` carries these prefixes into the joint winning-output
witness, retaining the selected-node-collision and public-zero alternatives.

The signing replay modules derive actual randomizer, forest and ordered
two-layer witnesses, including the accepted count and chain values, from
successful signing. `ObservedChains.lean` puts every successful session exposure
and the winning top-chain alternatives in one final cache. This does not assume
universal honest-signature correctness or equate a builder root with a recovered
root. `WotsPrefixComparison.lean` and `LayerPrefixComparison.lean` compare accepted
sum-205 words at a common address: equal words give equal prefix values; otherwise
some recovered position is earlier, with an actual suffix to the signed value.
An earlier position is not necessarily undisclosed, and equal words need not
mean equal messages or full digests. The complete repeated-address minimum is derived below. FORS
descent is derived below and adaptive coverage above. WOTS opening charges are derived above;
the complete six-case finite-model forgery bound is composed above.

The 21 additional finite examples in `ChainBindingExamples.lean` and
`WotsOpeningExamples.lean` cover split chains, binding failures without the
coordinate/length/collision conditions, ordered input sensitivity, accepted-word
comparisons and actual cached signing. Populated caches witness satisfiability,
not empty-cache success probability. Truncated addresses are not claimed to be
globally injective.

`ReturnedAuth.lean` and `ReturnedAuthRecovery.lean` now establish forward
correctness for the actual arrays returned by the 512-leaf Merkle and 2048-leaf
FORS builders, at every valid selected target. The loop invariant certifies each
stored sibling against the same memo table. Kernel-checked schedules supply
merge alignment and array bounds; Merkle's kept-flag invariant follows from its
actual all-false initialization. Functional cache consistency identifies the
stored siblings with the tree nodes, without a collision exclusion or an assumed
reference path. Recovery retains the actual WOTS leaf replay or FORS private
value/public leaf lookup, and remains valid under cache extension.
`ReturnedForsSigning.lean` binds recovery to the secret and authentication array
actually returned by FORS signing and to that execution's builder root. This
component supplies the whole structured-signer result below; it is not a
forgery-probability bound.
The ten `AuthPathExamples.lean` witnesses use an asymmetric four-leaf cache;
they cover all positions, order, false initialization of kept flags, short
arrays, invalid targets and unaligned merges. Forty additional typed cases
exercise the stored-node certificates, collector writes and kept-flag links.

`C10Honest.lean` now proves universal honest correctness for the actual
structured keygen/sign/verify clients. Every successful bounded signature
under an actually generated key verifies in its resulting cache, and in any
later cache that preserves its recorded replies. The keygen premise is consumed:
the top layer's reconstructed root is proved equal to the independently
constructed layer-one/tree-zero root, rather than assumed equal.

`CountReplay.lean`, `WotsHonest.lean` and `WotsHonestSign.lean` derive the
accepted full-width count lookup and recover each actual private-seeded prefix
to the generated WOTS leaf. `LayerHonest.lean` composes the actual returned
authentication path and uses functional tree-node uniqueness to identify the
builder root. `ForestRecords.lean` preserves all twelve positional records
through the computed shuffle; `ForestHonest.lean` connects them to ordered
recovery, the special final root-as-secret, its separate leaf hash and all
thirteen compression positions. `RandomizerReplay.lean` retains the actual
R/H_msg lookup and accepted digest. `HypertreeHonest.lean` composes the two
returned layers and their actual top keygen root. None of these forward
correctness results requires fresh queries, hash injectivity or collision
exclusion.

`HonestProbability.lean` composes actual keygen, signing and verification in a
single PMF experiment. Its result law keeps `none` for bounded signing failure
and returns `some true` for every successful signature; the rejection outcome
`some false` has mass zero. This proves neither guaranteed signing success nor
unforgeability. The generic input map covers both the independent public/private
interface and the physical shared-input interpretation under the same memoized
ideal digest model. `HonestExamples.lean` supplies eleven finite witnesses:
asymmetric chains, retry/query selection, positional forest writes and last-slot
compression, an inhabited actual keygen/sign/verify execution, and rejection
counterexamples for an arbitrary supplied root and an overwritten cache. The
whole-signature witness uses a populated constant cache and gives no empty-cache
success probability. The structured result does not include the 4,008-byte
codec or establish Rust, EasyCrypt, backend or cross-kernel equivalence.

`RootStability.lean`, `ForestStability.lean` and `WotsStability.lean` derive
functional root and signing-result uniqueness in one memo table, including
different selected paths and shuffles. `C10AddressStability.lean` and
`C10RecordStability.lean` use the actual 18-bit hypertree coordinates to prove
that successful C10 signatures at a repeated logical WOTS address have the
same signed message, accepted count digest and returned word. This uses actual
replay; stable messages or words are not additional assumptions.

`C10SigningRecord.lean` retains the actual request/signature replay, R/H_msg,
forest, both layer signatures, accepted count lookups and all private-seeded
prefixes. `C10ExposureHistory.lean` derives a complete chronological record
list from every successful observed exposure, including duplicate calls, and
proves its length is bounded by the signing allowance. `C10ExposureMinimum.lean`
filters all occurrences by the full logical lower or upper address. Its
accepted-word uniformity follows from the actual records.

`ExposureMinimum.lean` takes the coordinatewise minimum of all returned words,
using endpoint seven for an empty history. `TopChainRecord.lean` preserves every
witness of the existing top-chain opening in both directions.
`TopExposureOpening.lean` connects that actual winning opening to the complete
history: either it repeats a prior word and all returned prefix values, or a
coordinate lies strictly below the exact minimum of every prior returned
position at that address. The latter retains the actual private-seeded prefix
and an actual chain suffix to every matching prior value. Initialized independent
winning-game endpoints retain the original collision and public-zero alternatives.
An earlier position is not a secrecy claim, absence from raw queries, or a
private-opening probability charge; equal words do not imply equal full digests.
The repeated upper-word branch is descended into the lower tree below. The repeated lower-word branch descends into FORS below; adaptive coverage is derived above.
WOTS opening charges are derived above; the six-case PMF bound is composed above.

The fifteen finite examples in `ExposureExamples.lean` and
`ExposureHistoryExamples.lean` include three nonconstant accepted sum-205 words:
their mixed minimum has sum 203, and a third accepted word is distinct from both
without falling below that minimum. This demonstrates why actual same-address
uniformity is necessary. Synthetic records test logical coordinates, order and
duplicates; separate actual cached executions establish duplicate histories and
the failure of cache consistency after an overwrite. These populated-cache
witnesses make no initialized empty-cache probability claim.


`CountMessageBinding.lean` binds fixed-address serialized count inputs to their
16-byte node messages. It does not infer message equality from equal accepted
words: distinct actual inputs with the same accepted word give an explicit
`AcceptedWotsCollision`, equivalent to failure of the existing acceptance-filtered
collision-free predicate on the public input cache. No global input-map or
full-digest injectivity is assumed, and arbitrary natural counts retain the
32-byte serialization boundary.

`RepeatedUpperBinding.lean` retrieves the prior signature's actual successful
count lookup. A repeated upper word therefore yields either that collision or
equality with the prior signature's lower root. Its upper-address equality
identifies the entire lower tree, even when the submitted lower leaf differs
from the prior selected leaf. `LowerChainOpening.lean` derives the certificate
from the prior actual lower builder, uses reverse Merkle binding to obtain the
submitted actual WOTS leaf, excludes rejected-count zero only in the retained
nonzero branch, and derives all 43 private-seeded prefixes.

`LowerExposureOpening.lean` compares that lower opening with the complete lower
history, preserving both tree and leaf coordinates, duplicates, the empty-history
endpoint seven, and actual suffix replay to every matching prior value.
`LowerDescent.lean` composes the result for actual observed and independently
initialized winning sessions. It retains the complete signing history and cap,
the actual top opening, the prior upper-word/signature occurrence and equal
lower root, plus the lower opening and comparison. The top-earlier, selected-node
collision, public-zero and accepted-word-collision alternatives remain explicit.
A lower earlier position still makes no secrecy or private-opening probability
claim. The repeated lower-word branch descends into FORS below; adaptive coverage is derived above.
WOTS opening charging is derived above; the six-case PMF bound is composed above.

The seven kernel-checked examples in `LowerDescentExamples.lean` exercise distinct
node messages, actual accepted collisions, harmless repeated use of one input,
natural-count serialization wrap, different lower leaves within the same upper
address, different lower trees sharing a leaf coordinate, and an unseen lower
address. Populated caches and synthetic coordinate records are labelled as such;
these examples do not claim initialized-game probability or valid synthetic
signing executions.


`RepeatedLowerBinding.lean` retrieves the actual lower count lookups. Equal
accepted words retain the distinct-input collision alternative before binding
the forest public key. Both lower coordinates identify the complete hypertree
index, linking the prior actual forest signing program to the candidate address.

`ForestRecoveryRecord.lean` and `ForestSigningRecord.lean` derive ordered recovery
and shuffled signing records from the actual programs. They retain all twelve
ordinary slots, the thirteen-position compression, the special last transmitted
root, its separate leaf hash, and certificates for every actually built tree.
`ForestCompressionBinding.lean` binds the ordered root vectors under the existing
selected-node collision exclusion, then binds the special last root. It assumes
neither global query-map injectivity nor equality of full output digests.
`ForestPrivateOpening.lean` derives all twelve submitted private-value lookups
from those certificates and actual recovery paths, including defaulted fields.
The thirteenth transmitted value remains a built root, not a thirteenth ordinary
private-leaf exposure.

`ForestHistoryOpening.lean` compares the ordinary coordinates with the complete
successful-signing list. Either each tree's hypertree/leaf coordinate matches an
actual earlier occurrence and its returned secret, or some coordinate is absent
from every signing record at that hypertree index while retaining its actual
private lookup. Different trees may match different prior signatures; coverage
does not imply one repeated full digest. Duplicate occurrences stay in the list.
Unmatched in signing history does not mean absent from the raw-query transcript,
undisclosed, fresh, or probabilistically bounded.

`ForestDescent.lean` and `ObservedForestDescent.lean` compose these results for
actual observed, supported, and independently initialized winning sessions.
They retain the complete history and cap, actual top/lower openings, prior
upper/lower occurrences, both earlier-chain alternatives, and all original
node-collision/public-zero/accepted-word-collision alternatives. This closes the
structural repeated-lower-word FORS descent. The adaptive coverage charge is
derived above, together with WOTS opening charges; six-case PMF composition is proved above.

The eight kernel-checked examples in `ForestDescentExamples.lean` cover empty and
duplicate histories, coverage mixed across distinct prior digests, the need for
the complete hypertree coordinate, compression order, the separate last-root
position, actual recovery of missing arrays using defaults, and compatibility of
an unmatched history coordinate with a populated private cache. Synthetic
coordinate records are not claimed to be valid signatures or winning games.


These programs and integer formulas are manually transcribed from the existing
EasyCrypt and Rust source specifications and bound to them by hashes. Those
pins detect drift; they do not prove extraction, cross-kernel correspondence,
or global session freshness. No theorem equates concrete SHA-256 with this
ideal sampler.

`Boundaries.cached` draws once and reuses that reply. With a fair Boolean reply
and two attempts, failure has probability `1/2`; two independent attempts fail
with probability `1/4`. The strict inequality is kernel-checked. `memoGrind` now reproduces
the same `1/2` failure from actual persistent-table lookup, and a prefilled
rejected key forces failure even on a one-key distinct schedule. A repeated
memoized query therefore cannot be treated as a fresh draw without a further
argument. The actual EasyCrypt game retains its memo table and separate
revisit/transfer proofs.

There is no full C10 EUF-CMA theorem in this project, no substitution of expected
grinding work for the worst-case budget, and no claim about concrete SHA-256,
QROM, caller entropy, physical execution or shipment. The existing qualitative
crypto assumptions are not imported. The current initialized EasyCrypt bound
and remaining implementation limits retain their owners in
[RAW-NUMERICAL-EUF.md](../easycrypt/c10-port/RAW-NUMERICAL-EUF.md) and
[RESEARCH-LIMITS.md](../easycrypt/c10-port/RESEARCH-LIMITS.md).

## Replay and enforcement

The project pins Lean `v4.30.0-rc2` and mathlib commit
`5450b53e5ddc75d46418fabb605edbf36bd0beb6`, with all transitive revisions in
`lake-manifest.json`. Dependency caches are a tool-trust boundary, as are the
Lean kernel, frontend and pinned mathlib. The existing main proof project is
neither upgraded nor made dependent on this project.

From this directory, fetch the relevant prebuilt dependencies once:

```sh
lake exe cache get Mathlib.Probability.ProbabilityMassFunction.Constructions Mathlib.Probability.Distributions.Uniform Mathlib.Tactic Mathlib.Algebra.BigOperators.Fin Mathlib.Logic.Equiv.Fin.Basic Mathlib.Data.List.OfFn Mathlib.Data.Nat.Choose.Basic
```

From the repository root, run:

```sh
make -C contracts/verification verify-probability
```

The gate rebuilds every project module, checks all 2852 theorem closures against
the standard logical axioms (`propext`, `Classical.choice`, `Quot.sound`), and
requires the complete source, statement and query inventories. It rejects
proof escape constructs and verifies the projection-source bindings. An actual
compiler-produced added-assumption canary must be rejected by the closure
checker; missing closure records must also fail.

**Throughput work (#1000, 2026-10-20).** The cold command above still performs
every check. Local parallelism is configurable:

```sh
/usr/bin/python3 -E -S contracts/verification/scripts/check_probability.py --workers 8
PROBABILITY_WORKERS=12 make -C contracts/verification verify-probability
/usr/bin/python3 -E -S contracts/verification/scripts/test_probability_execution.py
```

`auto` selects at most twelve workers, limited by CPU affinity/cgroup quota
and available host/cgroup memory after a 2 GiB reserve and a 2 GiB admission
allowance per worker. Explicit counts must be within 1–32 and that admission
budget. This is a scheduling allowance, not a new compiler memory limit.
The Lean invocation, per-control 90-second timeout and consuming-theorem
judging rules are unchanged. Each compiler has its own fixture and log;
imported project/dependency libraries have no concurrent writer.

Cold CI uses eight deterministic control shards, selected from a four/eight-shard
comparison.
Every shard freshly rebuilds all project proofs, audits all closures and
runs both closure canaries before its assigned cases. All three stages of
a case stay together. The required aggregate runs its own fresh proof and
closure checks, then requires successful producers and an exact set of
shard receipts. It authenticates current source/statement/binding inputs,
generated fixtures, checking-policy bytes, actual Lean/Python and dependency
library bytes, project libraries, checkout identity, workflow identity,
run ID and run attempt. It rechecks raw closure/control logs and requires
each expected case/stage exactly once. Missing, failed, cancelled, duplicate,
unexpected, stale or mismatched evidence fails the gate.

Cold shard transport stays within the current workflow run and attempt; the
reviewed producer workflow and GitHub runner/artifact service remain trusted.
Sharding and receipt aggregation require that CI context; local runs use the
full gate. Retry the whole workflow, since receipts from an earlier attempt
cannot satisfy the current aggregate.
The #1000 batch added no cross-run reuse. The #1002 contract below owns that
separate boundary, coordinated with #789; push proof checks remain fresh.
The [portable benchmark receipt](https://github.com/EthereumPhone/PQ1/issues/1000#issuecomment-6294566604)
records frozen source identities, reproduction commands, hardware, wall time,
CPU/memory observations, failures and subsequent PR/push measurements. The
eight-worker local run took 24m42s versus 38m49s for the original four-worker
runner, with all checks retained. In the initial CI experiment, eight shards
completed their producer group in 24m20s versus 33m09s for four; total runner
time including aggregation was 153m42s versus 127m52s. Both aggregates waited
for the experiment's shared producer matrix, so its derived 34m27s standalone
eight-shard duration is an estimate, not an observed standalone workflow time.
The receipt distinguishes that experiment from the selected-only workflow.

**PR-to-master control reuse (#1002).** The [admission contract](CONTROL-REUSE.md)
requires a successful, unambiguous same-repository PR run for the landed target,
the same complete Git tree, all fifteen input/toolchain/policy identities and
complete original aggregate/shard evidence. It authenticates GitHub run, job,
checkout and artifact metadata, explicitly checks downloaded archives against
API-recorded uploader digests, and judges every raw control result again under
the original run context. The uploader, hosted runner and GitHub API remain
trusted. No original context is rewritten and no artifact code is executed.

All jobs fetch pinned dependencies without restoring Actions dependency caches.
The probe compares the fourteen identity fields that need no project build;
it cannot satisfy the verification gate. The final push job freshly rebuilds
and audits all proofs, bindings and both canaries before comparing the remaining
project-library identity. Its separate result links target and authenticated
origin. An ineligible/failed probe retains eight fresh shards. A later refusal
records its reason and runs all controls in the final process on the fresh
build; that route can take longer than sharding and has a 180-minute job budget.
Skipped or failed jobs cannot stand in for a successful required gate.

Set repository variable `PROBABILITY_FORCE_COLD=true` or run the workflow's
manual dispatch to force cold CI. The ordinary local command remains entirely
cold. Run the focused provenance/fallback regressions with
`/usr/bin/python3 -E -S contracts/verification/scripts/test_probability_reuse.py`.
[#1002](https://github.com/EthereumPhone/PQ1/issues/1002) owns actual measurements
and acceptance receipts. This does not separate or inherit Rust correspondence,
prove a new theorem, or weaken any control/census/closure requirement.

1695 typed cases run 5085 compiler jobs: each baseline and changed
definition must compile, 1485 changed behaviors must reject at the
consuming `checked` theorem, and 210 value-preserving changes must pass.
The byte-availability extension adds 28 closures in five modules and 40
controls (34 negative, six equivalent). All 2824 preceding statements, 1655
fixture objects, prior non-umbrella proof-module bytes and 52 bindings remain
unchanged. Consumers cover the failed bit, full returned observation, caps,
cache threading, key-generation initialization, public seed/adversary mapping,
hidden-prefix sampling and the exact initialized event law.
The complete signing-availability extension adds 72 closures in fifteen modules
and 56 controls (46 negative, ten equivalent), preserving all 2752 preceding
statements, 1599 fixture objects, non-umbrella proof-module bytes and 52 manual
bindings. Consumers cover completion factors, full rejected-key coverage,
serialized context fields/cardinality, empty-cache initialization, physical
shared-game identity, the actual failed ledger and both quantitative charges.
The complete-C10 R observer adds 102 closures in sixteen modules and 64 controls
(57 negative, seven equivalent), preserving all 2650 preceding statements,
1535 fixture objects, non-umbrella proof-module bytes and 52 manual bindings.
Consumers cover private-input separation, history/replay premises, independent
sign/session/game refinement, R-versus-WOTS failure, caps, caches, keygen,
final verification, initialized experiments and exact charged events.
The repeated-R session adds 100 closures in seventeen modules and 64 controls
(57 negative, seven equivalent). Consumers cover context encoding, private and
public history, successful replay, cap/refusal/failure behavior, full-cache
refinement, initialized experiments and the exhaustion/prefix charges.
All 2550 preceding statements, 1471 fixture objects, non-umbrella proof-module
bytes and 52 manual bindings are preserved. That batch raised the probability
CI timeout to 120 minutes after prior PR/push jobs took 86m52s/85m09s, leaving
its compiler limits, worker count, toolchain and checks unchanged. The later
#1000 throughput work is described above.
The byte-codec/session extension adds 101 closures in thirteen modules and
64 controls (58 negative, six equivalent). Complete consumers cover byte order,
full counters, malformed lengths, reply translation, all admission checks,
ledger/cap/cache preservation, keygen and initialized Boolean correspondence.
All 2449 preceding statements, 1407 fixture objects, non-umbrella proof-module
bytes and 52 manual bindings are preserved. Compiler resource policy is unchanged.
The six-case composition adds 48 theorem closures in eight modules and
31 controls (26 negative, five equivalent). Its complete consumers retain all
six charges, public/selected/total budgets, the accepted-word alphabet,
coverage's final query and signing/raw caps, and the Boolean prefix-transfer
charge. Examples cover overlapping events, every alternative, private-only
zero entries, a public zero without a collision, no-signature work, and the
informative and saturated numerical bounds. All 2401 preceding statements,
1376 fixture objects, non-umbrella proof-module bytes and 52 manual bindings
are preserved. The compiler heartbeat and memory policy is unchanged; numeric
examples locally permit exponentiation through 512 for the 2^348 denominator.
The 93 WOTS opening controls add 82 negatives and 11 equivalent forms. They
exercise baseline-cache restoration, query multiplicity/order, full-digest
probes, actual address/cut boundaries, endpoint exclusion, successful release
at or before the cut, session failures/ledger effects, original-game erasure,
provenance, complete histories, predecessor charging and the finite union.
Thirty-four boundary theorems include the last address/chain/cut, an earlier
known-node release, incomplete two-layer signing, duplicate exposures, absent
final layers and a concrete numerical charge. All 2102 preceding theorem
statements, 1283 fixture objects, prior proof-module bytes and 52 manual source
bindings are preserved. The batch adds 299 theorem closures in 57 modules;
toolchain and compiler resource policy are unchanged.
The 97 ordinary-opening controls add 80 negatives and 17 equivalent forms.
Their complete consumers cover cache threading, adaptive full-digest revelation,
unused-target restoration, candidate decoding and fixed charges, actual private
leaf/tree/signing and observed-session composition, final slots, target bounds,
full histories, and the uniformity, avoidance and domain-separation premises.
Twenty-three boundary theorems exercise these behaviors independently, including
the 3/4 shared-cache guessing example, zero signing budget and malformed padding.
All 1867 preceding theorem statements, 1186 fixture objects, prior proof-module
bytes and 52 source bindings are preserved. The batch adds 235 theorem closures
in 30 modules; no toolchain or compiler resource policy changes.
The 58 actual-pool controls add 47 negatives and eleven equivalent forms.
Complete consuming proofs check the acceptance mixture, selected fresh entries,
cache updates/reuse, completion potential, reply-dependent costs, input-domain
separation, result invariants, full observed histories, target distinction,
ordinary coordinates and complete hypertree addresses. They also check initial
freshness, the observed cap, width premises and the final verification allowance.
All 1760 preceding theorem statements, 1128 fixture objects, prior proof-module
bytes and 52 source bindings are preserved. No compiler limit or gate execution
policy is changed.
The 47 adaptive-coverage cases add 38 negatives and nine equivalent controls.
Complete consuming proofs exercise fresh-sample traces, observed caps, extension
closure, canonical counts, target exclusion, full-address and coordinate binding,
and every factor of the coverage charge. All 1705 preceding statements, 1081
fixture objects and 52 source bindings are preserved. The only prior proof-body
change routes the empty-sample example through its general product law; two
unused-group examples are additive. The probability CI timeout is 90 minutes
for the larger replay; its command, workers, compiler limits and checks are
unchanged.
The 45 FORS-descent cases add 38 negatives and seven equivalent controls. Full
consuming proof bodies check actual ordered recovery/signing records, private
opening coordinates and special last root, complete-history coverage/unmatched
lookups, actual repeated lower occurrences, and the composed endpoint's history
links. The previous 995 fixture objects, 1629 statements, old proof-module bytes
and all 52 source bindings remain unchanged. These are selected proof-sensitivity
checks, not proofs that every changed statement is false.
The 32 lower-descent cases add 27 negatives and five equivalent controls. They
exercise count-message binding, the distinct-input accepted-collision predicate,
actual lower builder/recovery/count/prefix witnesses, full lower-address and suffix
comparison, and the composed descent's prior occurrence/root/word/value links.
The unchanged complete consuming proofs reject the changed definitions; elementary
normalization allows equivalent message/list/conjunction forms to pass. These are
proof-sensitivity checks, not claims that every changed statement is false.
All previous 963 fixture objects, 1605 theorem statements, proof-module bytes and
52 source bindings are preserved.
The 46 repeated-exposure cases add 40 negatives and six mathematical equivalents.
They exercise minimum selection, empty-history endpoint, complete logical-address
filtering and occurrence order, history length, every retained top-opening
witness and the complete winning-exposure comparison proof. Full consuming proof
bodies or asymmetric kernel computations use the changed definitions; the
previous 917 fixture objects, 1545 theorem statements, old proof-module bytes and
52 source bindings are preserved.
The 47 honest-correctness cases add 40 semantic negatives and seven equivalent
controls. They cover actual forest positions, special final-leaf/compression
handling, selected randomizer replies/counters, ordered chains, H_msg/signature
inputs and the composed PMF's cache threading and failure outcome. The endpoint
controls re-run the complete honest-replay and distribution proof bodies against
the changed definitions, retaining actual keygen and successful signing. The
slot consumer derives actual forest recovery from the changed record predicate.
Value-preserving `b && true` and `root ++ []` controls pass with elementary
normalization in the same baseline/mutant proof, despite not being definitionally
equal to their variable inputs. These are sensitivity checks for the selected
consuming proofs, not proofs that every changed program falsifies the theorem.
The preceding 870 fixture objects, 1505 theorem statements, old proof-module
bytes and 52 source bindings are preserved.
The 40 returned-authentication cases add 36 semantic negatives and four
equivalent controls; the preceding 830 fixture objects, 1448 theorem statements,
old proof-module bytes and 52 source bindings are preserved.
The 47 WOTS chain-binding cases cover the joint top opening, actual layer/C10
signing witnesses, private routing, chain inputs and selected-node collision
conditions, including four equivalent controls. The three witness-predicate
consumers require the complete original claim from the changed predicate; a
deleted link must fail that consumer. These checks establish sensitivity of
the selected consumers, not logical falsity of every altered predicate.
All preceding 783 fixture objects, 1381 theorem statements, old proof-module
bytes and 52 source bindings remain unchanged.
The 58 tree-binding cases cover actual compiled merge/tree replay, certificate
provenance and coordinates, recovery correspondence, selected-node collision
premises and linked top-opening witnesses, including four equivalent controls.
The reference-deletion control consumes the opening to recover the same H_msg
digest, recovered WOTS leaf and keygen-reference leaf; deleting that conjunct
must reject this consumer, rather than merely break the opening's producer proof.
All preceding 725 fixture objects, 1305 theorem statements and proof-module
bytes remain unchanged.
The 56 observed-session cases cover passive logs, replay, cache/state erasure,
initialized experiments and verifier/WOTS witnesses, including four equivalent
controls. All preceding 669 fixture objects and 1224 theorem statements remain
unchanged.
The 60 adaptive-session cases add admission, cap, history, ledger, final-guard,
keygen composition and cost sensitivity, including four equivalent controls.
The 98 C10 client cases cover complete labels and natural count bytes,
coordinate shifts, recovery and signing history, returned fields, both layers,
R/H_msg composition, forced-zero and whole-root verification, and keygen's
public seed and root coordinates. All preceding 511 fixture objects and 1017
theorem statements are preserved; no previous proof-module bytes are changed.
The classifier rejects unresolved typeclass arguments as well as non-reducing
decisions and resource failures; none of these diagnostics counts as sensitivity.
The 71 FORS/forest cases cover private/public byte layouts, digest indices,
authentication overwrites, eleven-level recovery, full-digest sub-seed derivation,
twelve-position shuffle, all four blocks, positional writes, actual recovery,
last-root/leaf/compression roles and full-table propagation through the complete
sign/recover clients. Source-derived aliases isolate each changed direct
procedure from its unchanged compiler consumer. The 42 Merkle cases cover stack geometry/costs, pair bytes/order, authentication
selection/writes, full cache retention, leaf/query ordering and nine-step recovery. The signer controls cover private
bytes/routing, positional writes, shuffle inputs/order/multiply-high, all four
queries, zero-seed behavior, exhaustion and cache propagation. The recovery
controls include chain ordering and shared-cache retention, accepted-word work,
compression bytes, acceptance and both return branches. Cases also cover exhaustion,
acceptance, returned values and counters, retry bounds, the observed event,
WOTS length/radix/target, FORS width/zero test, both cap directions and cached
resampling, full-digest byte order, WOTS bit truncation/shift/digit order, FORS
field offset/width, mixed-radix orientation and result projection. New cases
cover cached resampling/history loss, missing insertion, changes to other keys,
search counter/acceptance, counter byte order/block width/schedule repetition,
and both collision-charge terms and seen-set insertion. Online controls cover
schedule length/independence, collision scanning, cache reuse across retries,
initial cached replies and counters. Randomizer controls cover high-half
selection, truncation, byte order, padding width/value, the domain suffix and
key injectivity; equivalent history and counter expressions must pass. Shared
search controls cover R/H_msg cache resets, missing stores, discarded successful
updates, continuing past success, returned label/reply/counter, acceptance and
retry-table propagation. Layout controls cover the R tag, optional randomness,
nonce placement, both R domains and three H_msg field-order swaps. The table
erasure and equivalent counter forms also have positive controls. Adaptive
controls cover initial-cache resets, discarded updates, resampled replies to
continuations, a fixed replacement for a reply-dependent key, observer stores
and history, cached resampling, lost flags, distinct-input identity, projection
semantics and the initial-validity guard. Equivalent budget, insertion and flag
forms must pass. The query budget is enforced by the indexed program type. Prelude
controls additionally cover trace origin/order, cache preservation, prefix
candidate collection and hit direction, full secret-byte order and width,
short-input refusal, request lengths and the actual shared/independent
comparison implementations. The comparison control proves its bridge helpers
locally inside the consuming theorem; imported original implementations cannot
mask a changed executed definition. Equivalent trace, set, prefix-guard and
request forms must pass. Interleaved controls cover input relabeling, public
budgets and traces, stopping/abort semantics, retained-event definitions,
cache preservation, continuation replies, cache correspondence, prefix
decoding, client/secret randomization and the concrete private-input layout.
The full event-bound consumer proves its composition helpers locally, so an
imported original implementation cannot mask these mutations. Equivalent
mapping, budget, guard, secret and prefix expressions must pass. Client/grinder
controls additionally cover altered continuation keys, first/second query
inputs, acceptance and stopping, selected R/reply/counter, exact R-tail and
H_msg fields, private/public cache routing, secret and client randomization,
and discarded state or results between actual session stages. The consuming
session-bound proof establishes its compiler and composition helpers locally.
Equivalent counter, association, continuation, secret and table expressions
must pass. Accepted-collision controls cover rejected-reply storage, cached
resampling, continuation reply/cache propagation, accepted-history insertion,
filtering, persistent flags, distinct-input/projection semantics, initial
validity, and the history, pair, acceptance and denominator terms in the charge.
Equivalent cache, set and arithmetic expressions must pass. Syntax
errors, resource limits and failures before the consumer
are not accepted as negative evidence. These are proof-sensitivity controls,
not a general proof that every changed proposition is false.

The 41 fixed-FORS-mass controls retain complete consuming proofs and cover
joint coordinates, the accepted distribution, full address and opening sets,
assignment routing, per-group probability factors, independent witness/target
sampling, distinct-position premises, the exact exponent and bounded-search
failure/acceptance factors. Seven equivalent forms must pass. All previous
1040 fixture objects and 1663 theorem statements remain unchanged.

The gate-enforcement reverse check derives source paths from every entry in
`claims.json.bindings` and requires their declared coverage; the forward check
then requires both push and pull-request triggers to cover them. Deleting each
binding from the declaration or either trigger is exercised by self-tests.
These path checks detect future source drift; hashes remain manual bindings,
not extraction evidence.

The dedicated `lean-probability.yml` workflow runs this gate on relevant pull
requests and master pushes. It is registered with the repository's enforcement
checker. Each local run retains its sources, logs and receipts under
`.lake/probability-evidence-*`. A green gate establishes only the statements
above; semantic review and the remaining game/backend obligations still matter.

Exact-count controls cover radix, length, target, negative-target clamping,
sum offset, convolution window, row tail, zero/omitted/duplicated steps,
basis length/value/order, representation direction/default and the decimal
result. Equivalent target, window, basis and result expressions must pass.

Target-event controls cover predicate inversion/vacuity, missing or inverted
cache lookup, weakened quantification, fixed-set membership, low-half or
repeated-byte nodes, byte order, whole-digest/any-byte/incorrect-value zero
tests, lost cache or target conditions and either omitted union event.
Equivalent predicate, set, index and zero-value expressions must pass.

Selected-domain controls cover cache filtering, full-view erasure, excluded
reply storage, seen-set and flag changes, cached resampling, budget consumption
and universal continuation guards. Byte controls distinguish both excluded
widths, the conjunction/disjunction, kind-field start/width/value and both
union events. Equivalent selector, budget, offset and zero expressions pass.
