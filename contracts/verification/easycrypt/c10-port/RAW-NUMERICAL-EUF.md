# Numerical EUF bound for the initialized byte game

`NumericalByteBound.physical_byte_euf_bound` gives an explicit upper bound on
successful new-message forgery in `RealGame(ByteContext(A)).run`. This is the
manually transcribed, classical ideal-oracle byte game, with actual key
generation, adaptive hash/sign calls, complete verification and the 4008-byte
signature codec. It is separate from the older conditional MM45 theorem family.

For nonnegative configured caps `qr` and `qs`, define

```
Q = full_public_budget(qr, qs)
  = 155135 + qr + qs * (3 * 10000000 + 364892) + 771
n = qr + qs + 1
C(n) = sum(j = 1..12, n^(j+1) * j^12 / 2^(132+18*j))

Pr[RealGame(ByteContext(A)).run : res]
 <= Q*(Q-1)/(2*2^128)                 public node collisions
  + Q/2^128                         zero-node sentinel
  + Q*(Q-1)/(2*2^129)                WOTS encoding collisions
  + 632475648*(Q+86)/2^128           WOTS reverse-chain cuts
  + 6442450944*(Q+12)/2^128          unreturned ordinary FORS openings
  + C(n)                            accumulated returned FORS coverage
  + Q/2^256                         shared/private-prefix game transfer
```

The client must terminate for lossless hash/sign oracles. The theorem's module
exclusions keep private oracle state and proof observers inaccessible. They are
not independence assumptions supplied by the client. There are no new project
axioms, admitted proofs or unresolved clone premises in this continuation.
`original_byte_euf_bound` proves the first six terms in the common initialized
`IndependentGame(ClientQueryContext(ByteLift(A)))` game. Exact projections and
the previously proved physical-to-independent hop give the seventh term.

## Accepted samples and adaptive coverage

`HmsgMemoOracle` refines the persistent oracle exactly. For a fresh 160-byte
public input, it samples the acceptance flag, then a digest from the appropriate
conditional distribution. Accepted digests enter a private iid sample pool.
Memoized repeats return the stored digest. `AcceptedDigestDistribution` proves
that this split has the original full-digest distribution.

`Hmsg*Count` proves width and count invariants through key generation, shuffles,
WOTS chains, FORS, Merkle construction, grinding, signing and verification.
Internal inputs other than H_msg have widths different from 160. One completed
signing grind adds at most one accepted H_msg call; a raw client call adds at
most one, as does final verification. The counter conservatively counts cached
accepted calls too. The number of fresh accepted samples is therefore at most
`qr + qs + 1`, without assuming fresh signing randomizers or distinct contexts.
Failures, malformed/refused requests and absorbing failed sessions are retained.

`HmsgPoolRecords` assigns each accepted H_msg table entry a matching pool index.
`CoveredOutputPool` binds the actual new-message output and every coordinate's
returned witness to these indices. New-message input distinctness makes the
target index different from all witness indices. Digest values themselves may
coincide. `CoverageWitnessCompression` retains at most twelve distinct witness
indices and an assignment of each of the twelve ordinary FORS coordinates to a
witness. The special thirteenth root-as-secret is handled by the earlier output
partition; it is not counted as an ordinary hidden coordinate.

For a fixed target and `j` distinct witnesses, a fixed assignment requires all
witnesses to share the target's 18-bit hypertree field and to match the assigned
11-bit FORS coordinates. `SelectedCoverageMass` proves exact mass
`2^(-132-18*j)`. The finite union uses at most `n` target choices, `n^j` witness
sequences and `j^12` assignments, yielding `C(n)`. This deliberately overcounts.

The coverage event persists when the pool grows. `AcceptedPrefixSampling`
uses a nonnegative completion-expectation invariant to dominate an arbitrary
adaptive prefix by a fixed iid pool of size `n`. Thus later signing responses,
repeated contexts and adaptive stopping are included; no final adaptive set is
substituted into a fixed-prior-set theorem. `OriginalCoverageBound` transfers
this charge back to the actual output event in the original byte game.

## Canonical-witness tightening

`CanonicalNumericalBound.physical_byte_canonical_euf_bound` proves the same
initialized byte-game bound with only the coverage term replaced by

```
A(j) = product(i = 0..11, min(j, 12-i)) = j! * j^(12-j), for 1 <= j <= 12
Ccanonical(n) = sum(j = 1..12, n^(j+1) * A(j) / 2^(132+18*j))
```

`CanonicalWitnessIndices` bounds the index of each coordinate's witness after
reversing last-occurrence deduplication. Its index is less than `12-i` and
less than the number of witnesses. `CanonicalPoolWitness` constructs that
representation; `CanonicalPoolEvent` proves it represents exactly the earlier
coverage event. `BoundedAssignmentWords` enumerates the separate coordinate
alphabets and proves their cardinality. The uniform assignment mass, adaptive
prefix domination and original-game projection are retained.

`canonical_physical_charge_tighter` proves that the resulting full bound is
no larger than the earlier bound for every nonnegative pair of caps. At the
example caps, coverage is approximately `8.2837816e-29` (`2^-93.29`), an
improvement by about 1,644 times. The overall probability upper bound remains
approximately `8.7695861e-15` (`2^-46.70`) because the other charges are unchanged.
The assignment enumeration still overcounts; this is not the exact occupancy
or Stirling-number formula.

## Exact witness enumeration

`StirlingNumericalBound.physical_byte_stirling_euf_bound` replaces only the
coverage term of the same initialized physical byte game by

```
(m)_j = product(i = 0..j-1, max(0, m-i))
S(0,j) = 1 if j=0, otherwise 0
S(k+1,j) = j*S(k,j) + S(k,j-1), for k >= 0
Cstirling(n) = sum(j = 1..12, n * (n-1)_j * S(12,j) / 2^(132+18*j))
```

`RestrictedGrowthWords` generates labels from right to left: reuse a label
below the suffix width or introduce the next label. It proves membership,
uniqueness, use of every label and the exact Stirling count.
`ReverseGrowthEncoding` proves that reverse last-occurrence normalization
produces such a word, reconstructs the original positions, and is included in
the earlier canonical assignment enumeration. `DistinctWitnessWords` removes
each selected position before the next selection and excludes the target. Its
enumerator has exactly `(n-1)_j` entries for a valid target, including empty
selection and insufficient-pool boundaries.

`StirlingPoolWitness` and `StirlingPoolEvent` prove that every covered coordinate
survives normalization and that the enumeration is exactly the existing pool
coverage event. `StirlingCoverageBound` reuses the fixed-assignment mass and
adaptive-prefix domination. `OriginalStirlingCoverage` transfers the result
through the same oracle projections to the initialized byte game.
`original_byte_stirling_euf_bound` and `physical_byte_stirling_euf_bound` retain
the existing client, module exclusions, losslessness premise, configured caps
and all other charges. Both new full charges are proved no larger than their
canonical predecessors for every nonnegative pair of caps. No new axiom,
freshness, independence or successful-search premise is introduced.

At `qr = qs = 65536`, the coverage charge is approximately `2.8623021e-30`
(`2^-98.14`), about 28.94 times smaller than the canonical charge. The relative
decrease in the full bound is only about `9.12e-15`; its displayed value remains
`2^-46.70`. These counts remove redundant enumeration, but the union still
overcounts overlapping events. They do not prove a tight forgery probability,
a concrete SHA-256 security level, or a quantum-oracle result. The separate
probability-monad requirement tracked by #295 remains open.

## Accepted WOTS encoding collisions

`AcceptedEncodingNumericalBound.physical_byte_accepted_encoding_euf_bound`
retains the Stirling coverage charge and replaces the WOTS encoding term by

```
p = count_ds(43, 8, 205) / 8^43
  = 22169393903687611906220091621190388 / 680564733841876926926749214863536422912
Caccepted(Q) = Q*(Q-1)/2 * p * 2^-129
```

`WotsAcceptanceMass` proves that the actual `RawWots.raw_digits` projection of
a fresh full digest is uniform over 43 base-eight digits. The existing
kernel-checked sum enumeration then gives exactly `p` for `count_accepts`, the
sum-205 predicate. A fixed encoding has mass `2^-129`; an independent pair with
equal accepted encodings has mass `p * 2^-129`. Acceptance is nonvacuous: `p > 0`.

`AcceptedEncodingPool` bounds collisions among the accepted words in an iid
full-digest list. `FullDigestPrefixSampling` proves completion domination for
arbitrary adaptive prefixes. `AcceptedEncodingMemo`, `AcceptedEncodingGame`
and `AcceptedEncodingCharge` relate that pool to the existing memoized oracle:
fresh inputs draw once, cached inputs retain their earlier replies. The actual
whole-run budget bounds the pool, without a freshness or successful-grind
premise and without substituting average work for worst-case work.

`AcceptedWotsCollision`, `AcceptedWotsCut`, `AcceptedActualWotsCut` and
`AcceptedEncodingCases` prove that the actual opening and output partition need
only exclude equal encodings whose digests both pass the acceptance test.
`ByteAcceptedEncodingCharge` transfers this event bound to the initialized
byte context. All other charges, configured caps, losslessness and existing
private-state exclusions are retained; the additional `FullDigestSamples`
exclusion hides only the new proof sampler. Both new full charges are proved
no larger than their Stirling predecessors for all nonnegative caps.

At `qr = qs = 65536`, `p` is approximately `3.2574997e-5`, reducing the encoding
charge from `2.9094038e-15` to `9.4773819e-20`, by about 30,698 times. The full
bound becomes approximately `5.8602770e-15` (`2^-47.28`), an improvement by
about 1.496 times. The unchanged public-node charge still dominates. Its
high-128-bit projection differs from the low-129-bit encoding projection;
equal encodings do not imply equal public nodes.

## Public-node domain accounting

`DomainNumericalBound.physical_byte_domain_node_euf_bound` retains the accepted
encoding and Stirling coverage charges and replaces only the public-node
birthday term by

```
N = node_public_budget(qr, qs) = 155135 + qr + qs * 364892 + 771
Cnode(N) = N*(N-1)/(2*2^128)
```

`NodeQueryDomain.node_query` conservatively excludes all 160-byte inputs and
128-byte inputs whose address-kind bytes at offsets 44–47 encode zero. It
retains every other arbitrary raw input, including inputs outside the actual
signer's shapes. Length alone cannot distinguish the 128-byte WOTS count input
from the 128-byte Merkle and FORS pairs: the latter use kinds two and three.
The proofs also retain the 96-byte chain, 480-byte forest compression and
1440-byte WOTS compression inputs. The actual initialized game establishes the
32-byte public seed and required element widths.

The `Domain*Extraction`, `DomainWotsOpening`, `DomainActualPartition` and
`DomainNodeCases` proofs restrict both sides of every relevant collision to
this domain, through actual recovery and the successful-output partition.
All other charged events are retained. The high-128-bit node projection is
still distinct from the low-129-bit WOTS encoding projection.

`Domain*Cost` counts selected calls through the actual key generation,
grinders, tree construction, reconstruction, signer, verifier and adaptive
session. Cached repeats count too, so this is an upper bound on fresh selected
draws. Only the proved non-domain WOTS-count and H_msg grinding calls are
removed from the budget; arbitrary client calls and conservative remaining
costs stay. Failed searches and absorbing sessions are covered. Partial
correctness supplies these budgets without a new losslessness premise, and
oracle initialization establishes the private-table validity used by the proof.

`DomainMemoOracle` keeps one raw memo table and the original private table.
A fresh selected key draws through the node sampler; a fresh excluded key
draws from the same full-digest distribution without entering that sampler.
Cached replies never resample. Exact relational refinement preserves both
tables, the call log, client globals and return value. `DomainCollisionBound`
then applies the existing adaptive birthday theorem with the selected-draw
budget. No fixed-history independence or average-grinding-work premise is
introduced. The additional `DomainMemo` exclusion hides only this proof oracle;
all prior game premises remain.

Both complete charges are proved no greater than their accepted-encoding
predecessors for nonnegative caps. At `qr = qs = 65536`, `N = 23913783554`,
compared with `Q = 1989993783554`. The node charge falls from `5.8188076e-15`
to `8.4028604e-19`, about 6,925 times smaller. The complete physical-game bound
becomes approximately `4.2309698e-17` (`2^-54.39`), about 138.51 times tighter.
At that stage the unreturned ordinary FORS opening charge dominates
(`3.7675879e-17`), followed by WOTS reverse-chain cuts (`3.6987594e-18`).
Both terms there use `Q`. These are upper probability bounds in the stated classical model,
not attack costs, lower bounds or a deployed security rating.

## Ordinary FORS candidate accounting

`ForsCandidateNumericalBound.physical_byte_fors_candidate_euf_bound` retains
all public-node, zero-node, accepted-encoding, WOTS, coverage and physical
transfer terms above, replacing only the ordinary FORS opening charge by

```
V = leaf_candidate_budget(qr, qs) = 155135 + qr + qs * 364892 + 771
Cfors = min(6442450944*(Q+12)/2^128, 6442450944*(V+14)/2^128)
```

The actual commitment hybrid examines a query's sixteen-byte suffix candidate.
WOTS grinder counter words contribute the same zero-valued candidate, and
H_msg contributes the same all-`FF` candidate. The covering list retains both
once, every other query candidate, and the twelve final output slots. It does
not remove any query or memo-table entry from the experiment. Arbitrary raw
inputs, malformed inputs, adaptive history and cached repeats remain covered.
The actual transformed target session proves the `V` budget, including key
generation, failed searches, all admitted attempts and final verification.
Its formula happens to equal the node-domain budget; the two measures and
their game instantiations have separate proofs.

The existing hybrid-to-independent, late-sampling, reveal-redaction and
private-table event transfers are reused without new premises or axioms.
The new bound reaches the same accepted-output event and coordinate union.
The minimum retains the prior charge where adding two fixed candidates would
otherwise be worse, including the zero-signing case. Both complete charges
are proved no greater than their public-node-domain predecessors.

At `qr = qs = 65536`, `V = 23913783554`; the ordinary FORS term falls by about
83.22 times to `4.5275157e-19`. The complete physical-game expression becomes
approximately `5.0865709e-18` (`2^-57.45`), about 8.32 times tighter than the
previous `4.2309698e-17`. At that stage, WOTS reverse-chain cuts dominate. These are
conservative classical ideal-oracle upper bounds, not attack costs or a
deployed security rating. Further candidate-specific reductions remain open.

## WOTS fixed-candidate accounting

`WotsCandidateNumericalBound.physical_byte_wots_candidate_euf_bound` replaces
only the WOTS reverse-chain term of the ordinary-FORS continuation by

```
Vchain = chain_candidate_budget(qr, qs) = 155135 + qr + qs * 364892 + 771
Cwots = min(632475648 * (Q + 86) / 2^128,
            632475648 * (Vchain + 2 + 86) / 2^128)
```

The same `leaf_suffix_candidate` appears in the chain hybrid's bad event.
`ChainCandidateMass` covers the original candidate list with its nonfixed
entries and the zero/all-`FF` values. Both fixed guesses remain charged even
when they equal hidden nodes. All eight iid hidden digests and all 86 WOTS
output slots remain covered. The original independent-vector experiment and
late-sampling argument are unchanged; this is a bound on the same event.

`ChainVariable*Cost` proves the filtered budget in the actual opening-redacted
chain backend, including cache hits, private derivations, key generation,
finite grinder failures, arbitrary admitted raw calls, absorbing sessions and
final verification. No oracle query or history entry is deleted. The numerical
formula agrees with the FORS and node budgets, but this game instantiation has
its own accounting proofs. `VisibleChainCandidateBudget` connects the actual
query suffixes and outputs to the filtered list.

The programmed, fresh, selected and finite-coordinate transfers retain the
existing opening flags, private-state exclusions, valid-cut requirements and
losslessness premise. `WotsCandidateCutBound` reaches the same successful
actual-output cut event. The complete independent and physical game bounds
retain every previous non-WOTS term. Taking the minimum with the old WOTS
charge makes both complete bounds no larger for every pair of caps, including
zero signing requests. There are no new axioms, modules or game assumptions.

At `qr = qs = 65536`, the WOTS term falls by about 83.22 times to
`4.4448045e-20`. The complete physical-game expression is approximately
`1.4322595e-18` (`2^-59.28`), about 3.55 times smaller than the previous
`5.0865709e-18`. The public-node charge now dominates, followed by ordinary
FORS openings. These are conservative upper probability bounds in the same
classical ideal-oracle model, not attack costs or deployed security ratings.

## Transfer to paired signing and verification

`C10PairedSessionBound.paired_byte_wots_candidate_euf_bound` gives the identical
WOTS-candidate upper bound for `RealGame(PairedByteContext(A)).run`. The paired
session calls the comparison signer and verifier whose input constructions,
shuffle, acceptance tests and digest fields are connected to the shared
representation. Session admission, caps, failure, returned-message tracking,
byte validation and final verification are preserved.

`C10PairedInitialization.paired_byte_success_probability` proves exact equality
of the two initialized success probabilities. The procedural relation preserves
the complete session and oracle state; key preparation preserves valid history,
and initialization establishes it. The bound retains the same configured caps,
losslessness and private-state exclusions. It supplies no tighter number and
no new backend or cross-language interpretation. The original key-generation
procedure and absorbing-failure contract remain; the secure-wrapper session is
a separate experiment. See [RESEARCH-LIMITS.md](RESEARCH-LIMITS.md).

## Composition, evidence and limits

`NumericalByteCases` proves that every successful output belongs to one of the
six charged cases. The composition uses those events in one initialized game;
it does not sum probabilities from incompatible transformed experiments.
The [WOTS](RAW-WOTS-CHARGE.md) and [FORS](RAW-SELECTIVE-HIDING.md) owners explain
the earlier hiding and finite-coordinate charges.

All new proof modules are direct and CLI replay targets with statement and
operation pins, source bindings, a declaration census and scope controls. Four
paired checks cover accepted cached-call accounting, distinct iid indices,
the single-witness assignment mass and the physical-transfer expression. Their
rejections have the limited meaning described in [CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md).
Successful local prototype compilation alone is not the full certificate;
landing requires the source-matched two-driver replay, cold full gate and
bounded review receipts.
The exact-enumeration continuation adds eight replay targets, 76 lemmas,
23 operation pins, eleven paired checks and eight scope probes. Its negative
controls distinguish checked finite counterexamples from sensitivity of the
event/game transfer proofs; see [CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md).
The accepted-encoding continuation adds twelve replay targets, 60 proved
statements, twelve operation pins, fourteen paired checks and twelve scope
probes. Three concrete modules and two module interfaces are census-pinned;
there are no new project axioms.
The public-node domain continuation adds 31 replay targets, 112 proved
statements, ten operation pins, three concrete module declarations,
23 paired controls and 31 scope probes. It adds no project axiom and changes
no existing theorem statement.
The ordinary FORS candidate continuation adds nineteen replay targets,
67 proved statements, seven operation pins, 23 paired controls and nineteen
scope probes. It adds no project axiom or new concrete module and preserves
the previous games and theorem statements.

The WOTS candidate continuation adds nineteen replay targets, 61 proved
statements, seven operation pins, 23 paired controls and nineteen scope probes.
It adds no project axiom or concrete module and preserves all previous games
and theorem statements.

The original bound is conservative. At `qr = qs = 65536`, exact rational evaluation gives
approximately `8.7695861e-15` overall (about `2^-46.70`), with coverage alone
approximately `1.3619301e-25` (about `2^-82.60`). The broad public-query budget
and birthday terms dominate. The continuations above give the improved bounds.
These are upper bounds on game probability, not
attack costs, lower bounds, or a claim of deployed 96-bit security. For large
caps the expression can exceed one and is then uninformative.

The accumulated-coverage and numerical-composition proof gaps in this manual
classical model are closed by these theorems. Tightening the charges, proving
concrete SHA-256 assumptions, QROM security, mechanically extracting the model
from Rust, and making a deployment security-level claim remain outside this
result. The earlier conditional MM45 capstone and its explicit residuals are
unchanged. See [RESEARCH-LIMITS.md](RESEARCH-LIMITS.md) for the specific remaining
quantitative, concrete-hash, quantum and Rust correspondence obligations.
Replay optimization #789 and the owner-triggered assurance pass #509 remain deferred.
