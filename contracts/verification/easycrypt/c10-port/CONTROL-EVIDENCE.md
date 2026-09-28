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
