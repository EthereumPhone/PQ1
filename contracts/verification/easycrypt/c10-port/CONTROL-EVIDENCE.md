# What the control receipts establish

`cert-controls-split.tsv` checks each file's exit status and declared diagnostic.
A `MUST-FAIL` result shows that the specified proof attempt was rejected. It
does not, by itself, refute the attempted statement, prove a hypothesis
logically necessary, or prove a probability charge tight or indispensable.

In particular, EasyCrypt's `the given proof-term proves:` diagnostic is an
exact-statement mismatch. These controls check theorem application and that the
proof driver actually rejects the mismatched term. Statement hashes separately
check source drift. Neither check is a semantic counterexample to another claim.

## Probability-bound batch

The 38 controls added with the honest-error and public-node bounds consist of:

| Evidence class | Count | Meaning |
| --- | ---: | --- |
| Positive proof checks | 6 | The stated theorem application or concrete example checks successfully. |
| Scope rejections | 12 | The specified forbidden symbol is unavailable in that environment. |
| Exact-statement mismatches | 19 | The supplied theorem does not directly prove the altered goal. |
| Unfinished proof obligation | 1 | The specified attempt leaves an obligation; this alone is not a refutation. |

The positive checks have different scopes. `C10Q13ClientsPositive.ec` checks
concrete query-accounting and table examples. `C10Q15ZeroWitnessPositive.ec`
exhibits a supported digest whose node projection is zero. Other positives
exercise the stated bound applications; they are not all countermodel witnesses.

For example, let `B = 30520798 * (1/2)^256`. The checked honest-error theorem
states `Pr[error] <= B`. Its arithmetic consequence `Pr[error] <= B + 1` is
also true, but applying the original theorem with `exact` produces the same
mismatch diagnostic as an attempted stronger goal. Using the theorem followed
by arithmetic proves the weaker bound. A compiler reproduction of both attempts
is retained with the review receipt.

Consequently, `C10Q12DropsPrefixCharge.ec` does not prove that physical honest
error has positive probability, and the other dropped-charge/residual controls
do not establish that their terms are necessary. The proved upper bounds and
their explicit residual events remain the claims. No lower bound or optimality
claim follows from these rejection controls. Earlier shorthand calling the
whole collection "semantic controls" must be read with this distinction.

## WOTS continuation controls

The WOTS batch adds four paired positive/negative checks and one unavailable-
symbol scope probe per new module. The pairs check an internal request above
versus at the selected cut, 86 versus 12 output positions, the complete versus
bottom-only coordinate count, and 129 versus 128 encoding bits. The negative
attempts are graded on `[by]: cannot close goals`, with positive twins checked
separately. They do not establish that the factor eight or any union-bound
summand is tight. The complete two-driver proof replay is separate evidence.

## Accepted-pool and numerical composition controls

Four paired checks compare counting an accepted cached call with omitting it,
distinct iid sample indices with a repeated index, the exact single-witness
150-bit assignment mass with a claimed 151-bit mass, and the physical-transfer
expression with its prefix term omitted. Positive twins must compile; negative
attempts must produce their enrolled unfinished-obligation diagnostic. There is
also one unavailable-symbol scope probe per new module. These checks do not
prove the final upper bound tight or each summand necessary.

## Canonical witness counting controls

Three paired checks cover a reverse last-occurrence index bound (using
`[7;3;7]` and applying `reverse_undup_index`), the exact 2-witness assignment
count (2048 versus 1024), and the forced zero final assignment index. The last
pair changes only the final digit of `rcons (nseq 11 1) digit`; a separate
positive witness proves that the zero-final-digit word is canonical. Thus the
negative claim has a checked counterexample. Positive twins compile; negative
twins reach their enrolled proof-application or unfinished-obligation diagnostic
without relying on a failed SMT search. Each new module also has an unavailable-
symbol scope probe. These checks exercise the canonical counting machinery;
they do not establish optimality, remove the birthday charges, or certify a
concrete hash backend.

## Exact witness enumeration controls

Eleven positive/negative twins cover reverse last-occurrence labels, the exact
`S(12,2)=2047` count (the previous canonical enumeration had 2048 words), the
old-label factor in the Stirling recurrence, six distinct two-witness choices
from a three-position alphabet rather than nine with replacement, exclusion of
the target, insufficient pools, the one empty selection, all twelve coordinate
labels, preservation of the coverage event, and both initialized byte-game
transfers. The recurrence is evaluated on its small numeric rows; the control
does not materialize the full twelve-coordinate partition enumeration.

Each negative keeps its positive twin's proof and changes the claimed count,
word, event or charge. The checker must reject the final proof application in
`checked` with `the given proof-term proves:`. Parser errors, missing symbols,
unfinished earlier helper proofs and time/resource failures are not credited.
The finite-word/count twins provide checked counterexamples. The event and
game-transfer twins test proof sensitivity; they do not establish a lower bound
on forgery probability or the necessity of every summand. In particular, the
independent-game twin removes the coverage charge and the physical-game twin
removes the shared/private-prefix charge without supplying a new proof.

`tools/stirling_coverage_controls.py` generates the fixtures, which are checked
by the existing source-binding and exact control-enrollment gates. Each of the
eight new modules also has an unavailable-symbol scope probe. These controls
do not discharge the remaining collision-budget, concrete-hash, QROM or full
Rust/session obligations.

## Accepted WOTS encoding controls

Fourteen positive/negative twins cover the digit alphabet and atom mass, the
129-bit encoding width, actual sum-205 acceptance mass, both acceptance
predicates in the pair event, empty/singleton/repeated-accepted pools, the
adaptive prefix cap, the accepted table event, the successful-output guard,
the independent and physical game transfers, and comparison to the prior
charge. They exercise twelve new modules containing 60 proved statements.

Each negative retains its positive twin's proof and changes the claimed event,
mass or charge. Rejection must occur at the final proof application in
`checked`: `the given proof-term proves:`, except the empty-list false claim,
which simplifies and reports `[by]: cannot close goals`. Parser errors, missing
symbols, earlier helper failures and time/resource failures are not credited.
The finite digit/list cases have checked counterexamples; positivity of the
actual acceptance mass rules out an empty acceptance event. The adaptive,
event and game-transfer controls establish proof sensitivity, not lower
forgery probabilities or necessity of every charge. In particular, removing a
charge and reapplying the old theorem is not a proof that the smaller bound
is false.

`tools/accepted_encoding_controls.py` generates these fixtures and their exact
enrollment. Twelve unavailable-symbol probes check that the new modules do
not expose the tainted structural FORS theorem. The complete two-driver replay,
source bindings, operation/statement pins and declaration census remain
separate gates. These controls leave the public-node, concrete-hash, QROM and
full Rust/session obligations open.

## Public-node domain controls

Twenty-three positive/negative twins cover concrete 160-byte exclusions,
128-byte kind-zero counts and kind-two/three pairs, cached-repeat call counts,
excluded calls, seed/element widths, compression row counts, restricted WOTS
opening, fresh and excluded table insertion, zero-cost count loops, signer and
initialized-session budgets, adaptive budget premises, the restricted table
event, successful-output guard, both full-game charges and their comparison.
The finite input/count twins have explicit false paired claims. The transfer
and premise-removal twins test theorem sensitivity; they do not establish that
every smaller bound is false or that every charge is necessary.

Rejection must occur at the final application in `checked`, not in an earlier
helper, parser or import. The expected diagnostic is `the given proof-term
proves:`, except the removed count-seed-width premise (`[by]: cannot close
goals`) and the changed adaptive budget premise (`this proof-term proves:`).
The exact source line and theorem are checked in the focused receipt. Resource
and timeout failures are not credited. `tools/node_domain_controls.py` contains
literal reviewed claims and generates the fixtures and exact control rows;
it does not automatically adopt changed implementation statements.

Every new proof module is checked directly and through the CLI, source-bound,
statement/operation-pinned and declaration-censused. Thirty-one scope probes
also require the tainted structural FORS theorem to stay unavailable. The full
cold replay and bounded review remain separate requirements. Concrete hash,
quantum-oracle and full Rust/session correspondence obligations remain open.

## Ordinary FORS candidate controls

Twenty-three positive/negative twins cover retention of both fixed guesses,
their two-slot charge, repeated malformed and fixed queries, final candidate
retention, the maximum u32 counter, padding/counter bounds, the actual H_msg
suffix, the fixed-query guard, candidate mass, adaptive query budgets, hidden
and final-output charges, signer/verification work, raw and signing caps,
the accepted-output event, both complete games and comparison with the prior
bound. Seven finite pairs have explicit false alternatives. The remaining
pairs test theorem sensitivity; they do not establish that every smaller
bound is false or that each conservative summand is necessary.

Rejection must occur at the final proof application in `checked`. Expected
diagnostics are `the given proof-term proves:`, except the removed counter
width/range premises (`[by]: cannot close goals`) and changed adaptive budget
(`this proof-term proves:`). Earlier helper failures, missing imports, parser
errors and time/resource failures receive no credit. The focused audit binds
each accepted rejection to its exact source line, theorem and raw output.

`tools/leaf_candidate_controls.py` contains literal claims and generates the
paired fixtures and exact control rows without adopting changed statements
from implementation files. Nineteen scope probes keep the tainted structural
FORS result unavailable. Direct/CLI replay, exact statement/operation/source
inventories, the full cold gate and bounded review remain separate gates.
The classical ideal-oracle, concrete-hash, cross-language and quantum limits
remain explicit.

## WOTS fixed-candidate controls

Twenty-three positive/negative twins cover both fixed guesses, their two-slot
charge, repeated malformed and fixed candidates, final-output retention, the
eighth hidden value, vector multiplicity, adaptive budgets, valid cuts,
cached-value work, signer and final-verifier work, raw/sign caps, all 86 output
slots, seed binding, the finite coordinate universe, the accepted-output guard,
both complete game charges and comparison with the prior bound. Seven finite
pairs have explicit false alternatives; sixteen theorem-sensitivity pairs do
not assert that every smaller bound is false or every premise necessary.

Each rejection must occur at the final proof application in `checked`, with
`the given proof-term proves:`. Earlier type/import/helper failures and resource
failures receive no credit. `tools/chain_candidate_controls.py` stores literal
claims and generates the paired fixtures and exact enrollment. The focused
audit binds the rejection to its source line and raw output. Nineteen scope
probes retain the forbidden structural-FORS boundary. Direct and CLI checks,
statement/operation/source inventories, the full cold replay and bounded
review remain separate requirements.

## Paired adaptive byte-session controls

Twelve typed changes alter failed-session admission, the signing cap, message
width, attempt charge, exhaustion flag, returned-message ledger, signer message,
preservation of prior query cost, final failure/freshness/byte guards, and the
verified payload. Each definition-only copy must compile before the unchanged
session or driver proof rejects at its intended theorem. The original and a
value-preserving variant must pass. Eleven rejections use `[by]: cannot close
goals`; the changed payload rejects with `the given proof-term proves:` at the
direct decoder-theorem application, without relying on an SMT timeout.

Three further positive/negative contract pairs exercise equal initial caps,
the exact success event and the inherited numerical charge. Their rejection is
at the `checked` lemma's final application with `the given proof-term proves:`.
These are theorem-sensitivity checks, not proofs that every changed contract is
false or that the numerical bound is tight. Together there are 32 controls:
17 expected passes and 15 expected rejections. The generator is
`tools/c10_paired_session_controls.py`; the focused audit binds source bytes,
transitive proof dependencies, intended theorem/line and raw output.

All three new proof modules have direct/CLI checks, statement/source pins,
declaration census entries and forbidden-symbol scope probes. Full cold replay
and bounded review remain separate landing requirements. No control establishes
a Rust/oracle interpretation, a secure-wrapper security reduction or a concrete
hash/quantum claim.

## Paired key-preparation controls

Fifteen typed changes alter the public seed, seed/root padding, root-call seed,
layer/tree, auxiliary returned values, the byte driver's seed/root and caps,
preservation of prior query cost/history, and the returned boolean. Each
definition-only copy must compile before the unchanged preparation or context
proof rejects at its intended theorem with `[by]: cannot close goals`.
The original definitions and a value-preserving variant must pass. The final
preparation proof uses a direct application of the proved coordinate bounds;
these rejections do not depend on exhausting an SMT budget.

Four positive/negative contract pairs exercise equal initial caps, equal key
inputs, the exact success event and the inherited numerical charge. Rejection
must occur at the final application in `checked` with `the given proof-term
proves:`. These are proof-sensitivity checks, not proofs that every changed
contract is false. There are 40 controls: 21 expected passes and 19 intended
rejections, generated by `tools/c10_paired_keygen_controls.py`.

The focused audit authenticates each source, transitive dependency, intended
theorem/line and raw output. Both new modules have direct/CLI checks,
statement/source/module pins and forbidden-symbol scope probes. Full cold
replay and bounded review remain separate landing requirements. The controls
do not establish a concrete hash or cross-kernel/session interpretation.

## Native total signing-availability controls

Nineteen typed procedure changes exercise the memoized cache, bounded count
schedule, acceptance test, invented failure, node width, refusal behavior,
seed binding and persistent failure state through WOTS/layer/finisher/session,
driver and keygen context. Each changed definition must type-check alone.
Eight unchanged and eight equivalent procedures must pass the original
consuming proof. Count, finisher and session fixtures first prove relational
correspondence to their canonical procedure using deterministic tactics; the
original consuming proof follows. This makes their rejection independent of
inconclusive SMT attempts on changed invariants.

Thirteen contract pairs exercise distinct inputs, the actual prefilled table,
message width/byte range, context cardinality, counter wrap, the physical
charge, initial caps, the failure event and numerical budget/target. They must
reject at the `checked` proof application with `the given proof-term proves:`.
These and the procedure controls establish proof sensitivity, not that every
changed contract is false, every term is necessary, or the bound is tight.

The generator `tools/c10_total_availability_controls.py` enrolls 80 controls:
48 expected passes and 32 intended rejections. Diagnostics are pinned to the
intended `checked` lemma and authenticated against raw output and current
transitive inputs; parsing, typing and resource failures receive no credit.
Nine additional forbidden-symbol scope probes guard the new modules.
Direct/CLI checks, source/statement/operation inventories, full cold replay and
bounded review remain separate requirements. The constant rejecting test
oracle is a nonvacuity witness, not a concrete backend or a claim about a
reachable initialized random-oracle history.
