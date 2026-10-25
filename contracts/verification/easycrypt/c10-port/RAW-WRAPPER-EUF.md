# Initialized byte-wrapper security in the classical ideal-oracle model

`WrapperNumericalBound.wrapper_independent_byte_euf_bound` and
`wrapper_physical_byte_euf_bound` bound new-message forgery in the original
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

## Bound and hypotheses

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
obligations have been discharged. This bound retains the original conservative
coverage coefficient; it does not claim the later library-only tightenings.

## Numerical examples

The following are illustrative query budgets, not enforced deployment policy.
Exact rational evaluation of the displayed formula gives the approximations;
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
