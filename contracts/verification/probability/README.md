# C10 probability project

This is the separate mathlib project requested by
[PQ1 #295](https://github.com/EthereumPhone/PQ1/issues/295). It proves bounded
independent sampling and derives the C10 projection PMFs from a uniform full
256-bit digest, within this Lean project. **The probability-monad forgery-game theorem
and the connection to the actual memoized grinder remain open.** The existing
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

The starting distribution is an explicit uniform independent-digest comparison
experiment. No theorem here identifies each actual stateful hash call with
that experiment. The integer formulas are manually transcribed from the
existing EasyCrypt and Rust source specifications and bound to them by hashes.
Those pins detect drift; they do not prove extraction, cross-kernel
correspondence or freshness.

`Boundaries.cached` draws once and reuses that reply. With a fair Boolean reply
and two attempts, failure has probability `1/2`; two independent attempts fail
with probability `1/4`. The strict inequality is kernel-checked. A repeated
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
lake exe cache get Mathlib.Probability.ProbabilityMassFunction.Constructions Mathlib.Probability.Distributions.Uniform Mathlib.Tactic Mathlib.Algebra.BigOperators.Fin Mathlib.Logic.Equiv.Fin.Basic
```

From the repository root, run:

```sh
make -C contracts/verification verify-probability
```

The gate rebuilds every project module, checks all 81 theorem closures against
the standard logical axioms (`propext`, `Classical.choice`, `Quot.sound`), and
requires the complete source, statement and query inventories. It rejects
proof escape constructs and verifies the projection-source bindings. An actual
compiler-produced added-assumption canary must be rejected by the closure
checker; missing closure records must also fail.

Twenty-nine typed cases run 87 compiler jobs: each baseline and changed
definition must compile, twenty-five changed behaviors must reject at the
consuming `checked` theorem, and four value-preserving changes must pass. Cases cover exhaustion,
acceptance, returned values and counters, retry bounds, the observed event,
WOTS length/radix/target, FORS width/zero test, both cap directions and cached
resampling, full-digest byte order, WOTS bit truncation/shift/digit order, FORS
field offset/width, mixed-radix orientation and result projection. Syntax
errors, resource limits and failures before the consumer
are not accepted as negative evidence. These are proof-sensitivity controls,
not a general proof that every changed proposition is false.

The dedicated `lean-probability.yml` workflow runs this gate on relevant pull
requests and master pushes. It is registered with the repository's enforcement
checker. Each local run retains its sources, logs and receipts under
`.lake/probability-evidence-*`. A green gate establishes only the statements
above; semantic review and the remaining game/backend obligations still matter.
