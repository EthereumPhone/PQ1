# C10 probability project

This is the separate mathlib project requested by
[PQ1 #295](https://github.com/EthereumPhone/PQ1/issues/295). It proves bounded
independent sampling and derives the C10 projection PMFs from a uniform full
256-bit digest, within this Lean project. It also proves an event-probability comparison between online memoized search
and independent sampling, using a derived history-plus-birthday charge. The
randomizer instance includes its high-128-bit projection and padded H_msg bytes.
A two-query shared-table grinder now derives that independent-R comparison
under explicit initial R-input freshness and proved domain separation. **The probability-monad forgery-game theorem
and full signer-session transfer remain open.** The existing
`lean/` project stays mathlib-free and is not imported here.

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

Both searches use 10,000,000 trials. The WOTS numerator is a proved finite
cardinality, **not a Lean-checked evaluation of that integer**. A concrete
accepted word and a rejected word witness that the predicate is nontrivial.
EasyCrypt's separate evaluated count is documented in
[RAW-NUMERICAL-EUF.md](../easycrypt/c10-port/RAW-NUMERICAL-EUF.md#accepted-wots-encoding-collisions).
That proof is not automatically transferred to Lean.

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

The gate rebuilds every project module, checks all 186 theorem closures against
the standard logical axioms (`propext`, `Classical.choice`, `Quot.sound`), and
requires the complete source, statement and query inventories. It rejects
proof escape constructs and verifies the projection-source bindings. An actual
compiler-produced added-assumption canary must be rejected by the closure
checker; missing closure records must also fail.

87 typed cases run 261 compiler jobs: each baseline and changed
definition must compile, 77 changed behaviors must reject at the
consuming `checked` theorem, and ten value-preserving changes must pass. Cases cover exhaustion,
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
erasure and equivalent counter forms also have positive controls. Syntax
errors, resource limits and failures before the consumer
are not accepted as negative evidence. These are proof-sensitivity controls,
not a general proof that every changed proposition is false.

The dedicated `lean-probability.yml` workflow runs this gate on relevant pull
requests and master pushes. It is registered with the repository's enforcement
checker. Each local run retains its sources, logs and receipts under
`.lake/probability-evidence-*`. A green gate establishes only the statements
above; semantic review and the remaining game/backend obligations still matter.
