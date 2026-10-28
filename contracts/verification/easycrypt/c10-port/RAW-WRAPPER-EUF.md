# Initialized byte-wrapper security in the classical ideal-oracle model

`WrapperRefinedNumericalBound.wrapper_independent_byte_refined_euf_bound`
and `wrapper_physical_byte_refined_euf_bound` bound new-message forgery in the original
`IndependentGame(WrapperByteContext(A))` and
`RealGame(WrapperByteContext(A))`. Key preparation, adaptive requests, final
verification and the 4008-byte signature codec execute inside these games.
The structured implementation is the existing `RawWrapper` and `WrapperSession`.

Every admitted attempt consumes the signing cap, including refusals. A refused
attempt does not prevent a later attempt. Both internal signing calls, their
comparison and internal verification retain their actual conditional execution.
Only signatures released to the client enter the exposure and signed-message
logs. Readiness and final-guard booleans overapproximate environment outcomes;
the theorem assumes neither successful search nor release.

## Retained bound and hypotheses

For nonnegative configured raw-query and admitted-attempt caps `qr, qs`, define:

```
Q = 155135 + qr + qs * (2 * (3 * 10000000 + 364892) + 771) + 771
V = 155135 + qr + qs * 727934 + 771
n = qr + 3 * qs + 1
C(n) = sum(j = 1..12, n^(j+1) * j^12 / 2^(132+18*j))

Pr[RealGame(WrapperByteContext(A)).run : res]
 <= Q*(Q-1)/(2*2^128)            public node collisions
  + Q/2^128                    zero-node sentinel
  + Q*(Q-1)/(2*2^129)           WOTS encoding collisions
  + 632475648*(V+88)/2^128      WOTS reverse-chain cuts
  + 6442450944*(Q+12)/2^128     unreturned ordinary FORS openings
  + C(n)                       coverage by released ordinary FORS openings
  + Q/2^256                    private-prefix transfer
```

The independent-game bound omits the final term. `wrapper_query_byte_euf_bound`
first combines all six cases in a common initialized logged game. Exact passive
observer and byte-interface projections give the original-game statement; the
same-client physical-to-independent hop supplies the last term. “Physical” is
the name of an ideal oracle model, not a claim about hardware execution.

The client must terminate when supplied lossless hash/sign oracles. The stated
module exclusions prevent access to private oracle state, configuration and
proof observers. The hypotheses do not require fresh randomizers, successful
internal calls, distinct contexts or a final successful release. Existing ideal
distributions, encoding definitions and solver/kernel foundations remain the
trusted model boundary. This continuation introduces no project axioms or admits.

## Refusal and release accounting

The ordinary library security theorem cannot be substituted directly: its
session latches a signing failure, whereas this wrapper permits retries and can
withhold an internally completed signature. Treating that hidden signature as
an external exposure would change the claim.

The FORS and WOTS reductions therefore prove separate exact views of the
original wrapper. They retain both internal plans and their comparison, all
bounded searches, shuffles, tree construction and optional results. Private
signature positions are materialized only after the final release decision.
These transformations preserve both persistent oracle maps and the result.
Their observers account for openings solely through actual returned signatures,
without a failed-state escape or an unexplained observer reset.

For WOTS, retained lower-tree roots and first accepted counters connect the
materialized positions to the returned signature. Endpoint-only planning leaves
a proper selected cut unopened, including on refusal. Adaptive accounting,
losslessness, fresh-chain hiding, selected-coordinate sampling and a finite
union yield the WOTS charge. `V` charges both internal plans, both materialized
layers and every admitted attempt; 86 final candidate values and the existing
sampling terms give `V+88`.

For ordinary FORS, the analogous retained-tree plan preserves exact secret
addresses and opens only externally returned coordinates. The special
thirteenth root-as-secret is handled by the existing actual-output partition.
It is not counted as another hidden ordinary coordinate.

Accepted H_msg accounting allows two internal grinds and internal verification
per attempt, one final verification and admitted client hash calls. The
conservative coverage pool therefore uses `qr+3*qs+1`. The existing adaptive
prefix domination and coverage union apply after these wrapper-specific
obligations have been discharged. The retained formula above uses the original
conservative coverage coefficient; the non-node continuation below tightens it.

## Addressed-node continuation

The addressed-node bound uses the same initialized wrapper experiments and
replaces only the first term of the retained formula:

```
Rwrapper = qr + 775*qs + 771
Cnode = min(Q*(Q-1)/(2*2^128), Rwrapper*(Rwrapper+1)/2^128)
```

`AddressedWrapperMemoCalls` charges at most two nonordinary public memo keys
for each actual signing call and conservatively charges all 771 calls of the
internal verifier. Thus an admitted wrapper attempt costs at most `2+2+771=775`.
This is an upper bound, not an assertion that every attempt reaches that cost.
`AddressedWrapperMemoSession` derives the initialized adaptive budget, including
raw calls, retries after refusals, both signing passes, withheld results and the
final verifier's additional 771 calls. Key preparation establishes zero
nonordinary keys. Arbitrary earlier raw prepopulation and memo hits remain in
the actual persistent tables; no desired count or freshness premise is added.

`AddressedWrapperActualForest` and `AddressedWrapperActualPartition` derive the
equal-address collision alternative from actual successful wrapper outputs.
`AddressedWrapperBucketBudget` and `AddressedWrapperByteCollision` then compose
the generic address-bucket and private-observer proofs with the wrapper's own
initialized count. The same public seed and serialized address define a node
bucket; the private observer preserves samples, replies and histories.
The only additional module exclusion is private `AddressedAudit` state.

`AddressedWrapperNumericalBound` retains the zero-node, original WOTS encoding,
wrapper WOTS-candidate, ordinary FORS, released-coverage and private-prefix
terms exactly. It proves both complete charges are no greater than their
retained counterparts. The ordinary library's later non-node tightenings are
not automatically transferred to this distinct retry/withholding experiment.
No production or backend interpretation changes.

## Non-node continuation

The wrapper-specific continuation (2026-10-28) retains the addressed-node,
zero-node, WOTS reverse-chain and private-prefix terms. It replaces the encoding,
ordinary FORS and coverage terms in the same initialized experiments:

```
p = 22169393903687611906220091621190388 / 2^129
Vleaf = 155135 + qr + qs * (2 * 364892 + 771) + 771
Cencoding = Q*(Q-1)*p/(2*2^129)
Cfors = min(6442450944*(Q+12)/2^128,
            6442450944*(Vleaf+2+12)/2^128)
(m)_j = product(i = 0..j-1, max(0, m-i))
S(0,j) = 1 if j=0, otherwise 0
S(k+1,j) = j*S(k,j) + S(k,j-1)
Cstirling(n) = sum(j = 1..12, n*(n-1)_j*S(12,j)/2^(132+18*j))
```

`WrapperAcceptedEncodingCases` narrows the successful-output partition to two
accepted WOTS encodings while preserving the addressed-node case.
`WrapperAcceptedEncodingCharge` applies the exact sum-205 acceptance mass `p`
to the actual wrapper's public-query budget. Private `FullDigestSamples` state
is additionally excluded from the client; no success or independence premise
is added.

`WrapperLeafCandidateCost` and `WrapperLeafSessionCost` prove the variable
candidate budget for the actual transformed target session, including both
hidden signing plans, refused attempts, client calls, key preparation and final
verification. The existing original-to-transformed projection discharges
internal verification by memo/history equivalence; the new budget still
conservatively reserves 771 calls per admitted attempt. The two fixed suffix
guesses (zero and all-FF) and all twelve final candidate slots remain charged.
`WrapperSelectedLeafBound` and `WrapperLeafOpeningBound` transfer the hiding
bound back to actual unreturned ordinary FORS openings. The minimum preserves
the old charge even at zero signing attempts.

`WrapperStirlingCoverage` uses the already-proved adaptive wrapper pool bound
`n=qr+3*qs+1` and exact witness enumeration for the same coverage event. This
is still a union bound, not an exact forgery probability. None of these transfers
substitutes the ordinary library's absorbing-failure session.

`WrapperRefinedNumericalBound` combines these events for one common adversary
and proves that both complete charges are no greater than the addressed-node
continuation for every nonnegative pair of caps. All earlier theorems remain.

Exact rational evaluation with `python3 tools/wrapper_nonnode_examples.py`
gives these illustrative physical ideal-model charges. These decimal values
come from that arithmetic utility, not an additional native numerical proof:

| `qr` | `qs` | Previous addressed-node charge | New combined charge |
| ---: | ---: | ---: | ---: |
| 0 | 0 | 3.24190336e-24 | 3.24188551e-24 |
| 50,000 | 50,000 | 6.83171226e-15 | 9.79894104e-19 |
| 1,000,000 | 1,000 | 1.77928152e-14 | 1.53013562e-20 |

These are conservative upper bounds, not deployment policy, attack costs or
deployed security-bit estimates. They add no concrete backend or hardware claim.

## Numerical examples of the retained bound

The following are illustrative query budgets, not enforced deployment policy.
Exact rational evaluation of the retained formula gives the approximations;
`WrapperNumericalExamples` independently checks the stated strict upper bounds
using native EasyCrypt arithmetic.

| `qr` | `qs` | Physical ideal-model charge, approximately | Native upper bound |
| ---: | ---: | ---: | ---: |
| 0 | 0 | 3.24194e-24 | less than 2^-78 |
| 50,000 | 50,000 | 2.038e-14 | less than 2^-45 |
| 1,000,000 | 1,000 | 1.77982e-14 | less than 2^-45 |

These are conservative forgery-probability upper bounds, not attack costs or
deployed security-bit estimates. A loose upper bound is not an attack attaining
that probability.

## Validation and remaining boundary

The source modules, every statement and defined operator, dependency cone,
declaration census and forbidden-symbol scope probes are enrolled in the split
certificate. The complete pinned cold replay must check every direct/CLI target
and positive, typed, rejection and scope control. Focused development passes
alone do not satisfy that gate. The control family and raw-rejection audit
obligations are described in [CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md).

This closes the classical ideal-oracle wrapper-reduction component. It does not
prove a complete probabilistic simulation of arbitrary Rust clients, concrete
SHA-256 or PRF backends, entropy and callback implementations, physical abort
prefixes, fault behavior, QROM assumptions or hardware execution. The shared
functional/extracted correspondence results keep their existing interpretation
boundary. See [RESEARCH-LIMITS.md](RESEARCH-LIMITS.md#rust-correspondence).
The distinct ordinary library game and its tightenings remain owned by
[RAW-NUMERICAL-EUF.md](RAW-NUMERICAL-EUF.md).
