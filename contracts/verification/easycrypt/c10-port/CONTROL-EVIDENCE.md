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
