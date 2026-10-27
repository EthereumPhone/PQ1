# What the control receipts establish

`cert-controls-split.tsv` checks each file's exit status and declared diagnostic.
A `MUST-FAIL` result shows that the specified proof attempt was rejected. It
does not, by itself, refute the attempted statement, prove a hypothesis
logically necessary, or prove a probability charge tight or indispensable.

In particular, EasyCrypt's `the given proof-term proves:` diagnostic is an
exact-statement mismatch. These controls check theorem application and that the
proof driver actually rejects the mismatched term. Statement hashes separately
check source drift. Neither check is a semantic counterexample to another claim.

## Addressed-node continuation

The addressed-node batch enrolls 45 generated fixtures and one unavailable-
symbol scope probe for each of its 61 new modules. The fixtures comprise:

| Evidence class | Count | Meaning |
| --- | ---: | --- |
| Finite positive/rejection pairs | 16 | Eight proved examples contradict their altered claims: the exceptional address, its two counted calls, distinct keys sharing a label, cached insertion, raw prepopulation, an actual collision, the first sample, and different address labels. |
| Contract positive/rejection pairs | 16 | Eight original theorem applications pass; seven altered applications mismatch the theorem and one leaves the seed-width obligation open. These are application checks, not counterexamples to all possible stronger theorems. |
| Typed program mutants and rejected comparisons | 8 | Each changed program typechecks before its comparison with the original is rejected: cached resampling, a replaced memo reply, and removed header/layer refusal guards. |
| Original program comparisons | 3 | The original audit oracle and signer sign/finish comparisons pass. |
| Preserving variants | 2 | Double-negating the audit fresh-key guard and parenthesizing the signer header guard preserve the checked comparisons. |

The contract pairs cover address equality, exceptional-call charging, partial
refusal, ordinary-input preservation, seed width, the actual byte-game count,
its collision-probability bound and physical transfer. Their rejection does not
prove a probability summand necessary or the new bound tight. Program comparisons
exercise the actual memoized draw/reply and refusal behavior; their declared
proof-obligation diagnostics must be reached after typing, without credit for
parser errors, resource failures or timeouts. Scope probes check symbol hiding,
not semantic soundness. The full isolated two-driver replay remains separate
evidence from these control classifications and development checks.

## Addressed paired/wrapper continuation

This batch adds 41 generated fixtures and nine unavailable-symbol scope probes:

| Evidence class | Count | Meaning |
| --- | ---: | --- |
| Contract positive/rejection pairs | 16 | Exact paired prefix charges, both signing passes, final verification, the raw cap, actual initialized experiment, collision charge and wrapper prefix transfer. |
| Charge positive/type/rejection triples | 15 | Local changes to each retained non-node independent-game term typecheck and fail direct application of the original complete theorem. |
| Original/equivalent program comparisons | 2 | The wrapper's original body and double-negated readiness guard preserve result and complete oracle state. |
| Typed program mutants/rejected comparisons | 4 | Omitting the second signing call or internal verifier typechecks but fails the unchanged comparison proof. |
| Arithmetic positive/rejection pairs | 4 | A concrete initialized budget and the retained-minimum inequality contradict their altered claims. |

Every rejection must occur at its named consumer after successful parsing and
typing; parser errors, resource failures and timeouts are not credited. The
program comparisons establish sensitivity of the checked relation, not universal
inequivalence. Contract and local-charge mismatches do not prove that 775 is
tight, that a probability term is indispensable, or that a stronger theorem is
false. The arithmetic examples do not establish attainability of the budget.
The full pinned two-driver replay and exact first-diagnostic audit remain
separate mandatory evidence.

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
Eight unchanged and nine equivalent procedures must pass the original
consuming proof. The refusal control sets the failure flag only in the outer
refusal branch; its matching self-assignment branch must pass both relational
correspondence and the consuming proof. The faulty branch must reject at an
incomplete `checked` proof, not a tactic-shape error. Count, finisher and
session fixtures first prove relational
correspondence to their canonical procedure using deterministic tactics; the
original consuming proof follows. This makes their rejection independent of
inconclusive SMT attempts on changed invariants.

Thirteen contract pairs exercise distinct inputs, the actual prefilled table,
message width/byte range, context cardinality, counter wrap, the physical
charge, initial caps, the failure event and numerical budget/target. They must
reject at the `checked` proof application with `the given proof-term proves:`.
These and the procedure controls establish proof sensitivity, not that every
changed contract is false, every term is necessary, or the bound is tight.

The generator `tools/c10_total_availability_controls.py` enrolls 81 controls:
49 expected passes and 32 intended rejections. Diagnostics are pinned to the
intended `checked` lemma and authenticated against raw output and current
transitive inputs; parsing, typing and resource failures receive no credit.
Nine additional forbidden-symbol scope probes guard the new modules.
Direct/CLI checks, source/statement/operation inventories, full cold replay and
bounded review remain separate requirements. The constant rejecting test
oracle is a nonvacuity witness, not a concrete backend or a claim about a
reachable initialized random-oracle history.

## Functional bounded-search controls

Seven shared-expression mutations change the first accepted slot, exhaustion,
the index increment, or signed subtraction. Each generated definition must
type-check in Lean and EasyCrypt before the unchanged paired selector law
rejects. The Lean fixture also contains the actual extracted WOTS/FORS result
theorems. The original and an arithmetic-equivalent edit pass the whole fixture.
The signed-subtraction mutation exposes the distinction between a negative
difference and zero; count subtraction retains its original saturated meaning.

Nine procedure mutations change the memoized backend's cost, returned value or
retained history, or the actual paired searches' cap, initial counter and
returned result. Each definition-only fixture must compile. A deterministic
`checked` comparison to the canonical procedure comes before the unchanged
functional consuming proofs. The unchanged and equivalent variants pass both
parts; the changed variants reject at an incomplete comparison proof. This
tests correspondence sensitivity. It does not independently establish that
every later invariant proof would reject every mutation. The comparison uses
no inconclusive SMT attempt as rejection evidence.

A separate exact-contract pair removes the requirement that prior cached
values agree with the fixed backend. The original contract passes; the altered
one rejects at the exact application of `fixed_hash`. Contract rejection shows
proof sensitivity, rather than proving every strengthened statement false.
The empty-history and fixed-width-function witnesses keep the original model's
premises nonvacuous.

`tools/c10_functional_search_controls.py` enrolls 43 EasyCrypt controls:
26 expected passes and 17 intended rejections. Six additional forbidden-symbol
scope probes cover the new modules. Parsing, typing, resource failures and
unmatched diagnostics receive no rejection credit. The Lean runner executes
two positive fixtures and seven typed intended-theorem rejections. Full native
direct/CLI replay, extraction gates, identities and bounded review remain
separate requirements. These controls add no concrete SHA security,
random-oracle transfer, or cross-kernel session claim.

## Functional WOTS value controls

Twelve shared-expression mutations change node width, backend input, secret
index, chain order or position, keygen chain count or length, compression
domain, signing digit, or recovery length, target or zero sentinel.
`tools/c10_functional_wots_controls.py` emits 27 native fixtures in the distinct
`scratch/c10_wots_value_*` family: original and equivalent positives, twelve
definition-only passes, twelve intended unchanged-consumer rejections, and
independent boundary examples. Seven forbidden-symbol scope probes cover the
new modules. Prior search and procedural caller/shuffle controls remain enrolled.

The positive fixtures contain all seven native modules; the Lean fixtures
contain all three new endpoint modules. Each changed definition must type-check
before its first consuming theorem rejects. The recorded consumer is a chain,
secret, node-list, compression or recovery law; later endpoint proofs are not
claimed to have run after an earlier rejection. Rejection demonstrates proof
sensitivity, not a proof of the mutated proposition's negation. Syntax, typing,
resource failure and inconclusive SMT output earn no rejection credit. Replacing
the node width 16 with `8+8` passes the entire fixture in each language.

`tools/c10_functional_wots_fixtures.py` checks both printers' pure application
and count/integer boundaries, including negative-to-zero conversion. Five
ordered-chain examples cover zero steps, multiple steps, a position-byte carry
and a high u32 position. Expected bytes come from a separate Python byte-array
loop, not evaluation of the shared expression tree. Lean checks these examples
with kernel `decide`; EasyCrypt proves the explicit finite folds. These finite
examples supplement the generic proofs and do not establish printer correctness
for all expressions or identify the supplied function with a sampled oracle.

## Functional tree value controls

`tools/c10_functional_tree_controls.py` covers fourteen changes to FORS secret
index, leaf domain, pair order, parent division, height, parity, sibling
selection, fold order, and FORS/XMSS domain, keypair and path length.
The `scratch/c10_tree_value_*` family contains original and equivalent
positives, fourteen definition-only passes and fourteen intended-consumer
rejections, plus independent examples. Three scope probes cover the new
modules. The previous FORS search module and its controls remain unchanged.

Each changed definition must typecheck before the first unchanged consuming
theorem rejects it. Both checkers record that consumer; later proofs after a
rejection earn no execution credit. Syntax/type errors, resource failures and
inconclusive SMT outcomes do not count. Replacing the height increment `1`
with `2-1` passes the whole fixture. This is sensitivity evidence, not a proof
that each mutated theorem's negation holds.

`tools/c10_functional_tree_fixtures.py` independently constructs concrete
addresses and ordered hash inputs with Python byte encodings. Seven pinned
complete-path checkpoint sequences cover even/odd traversal, full u32/u64
fields and an out-of-tree FORS index. Lean uses kernel `decide`; EasyCrypt
checks the corresponding finite computations, sharing proved byte-projection
lemmas to avoid repeatedly expanding the same lists. The toy function is
public arithmetic, not SHA. These examples supplement the generic endpoint
proofs and do not remove the paired-printer or backend interpretation boundary.

## Functional construction controls

`tools/c10_functional_build_controls.py` supplies sixteen typed changes covering
left/right child selection, node height/index, fold order, root depth, path
parity/defaults, FORS and XMSS leaf indices, root domains, authentication
keypairs, the returned FORS secret and the XMSS target. Every changed definition
must compile, then fail at its recorded first consuming proof. The unchanged
and arithmetic-equivalent `i + (2-1)` fixtures pass. The combined fixtures retain
the actual-caller consumers; later statements following a rejection earn no
execution credit. Ordinary proof rejection demonstrates sensitivity, not the
logical negation of each changed theorem. Syntax/type errors and resource
failures do not count. Eleven scope probes cover the new native modules.

`tools/c10_functional_build_fixtures.py` independently constructs every node of
four complete trees using Python byte encodings: 2,048 and 512 leaves with zero
and maximum-width FORS/XMSS address fields. It pins four roots and twenty paths,
covering first, odd, last, first-outside and maximum-u32 targets. The leaves are
explicit arithmetic vectors; these fixtures do not execute the actual FORS
secret or WOTS leaf backends. Their instantiations are covered by the separate
actual-caller proofs and typed controls. The public arithmetic hash observes
address bytes and ordered children. Lean and EasyCrypt prove whole-level
identities before checking the roots and paths, keeping the fixtures small
without replacing either proof checker with Python evaluation. The paired
printers and supplied-backend interpretation remain disclosed boundaries.

## Functional forest and layer caller controls

`tools/c10_functional_caller_controls.py` supplies twelve typed mutations:
forest final-tree selection, secret/path index, separate final leaf, compression
domain, recovery ordering, signing address, layer search bound, zero sentinel,
returned counter, authentication-path target and recovery position. The original 27
`scratch/c10_caller_value_*` fixtures include original and arithmetic-equivalent
positives, twelve definition-only passes, twelve intended-consumer rejections
and independent value examples. Nine scope probes cover the new native modules.
The native positive fixtures retain all nine modules; the Lean fixture retains
the three endpoint modules and the transitive caller proofs needed to avoid
importing a second copy of the shared definitions. Repeated backend reducibility
attributes are retained once, with other declarations unchanged.

Each changed definition must typecheck before its first unchanged consuming
theorem rejects. The Lean checker enforces that first error's theorem location;
the native full gate enforces its ordinary rejection diagnostic, with the
coordinator's raw-log audit checking the intended location. Persistent native
location enforcement remains the separate deferred #1034. Later proofs after a
rejection earn no execution credit. Syntax/type errors, timeouts, resource
failures and inconclusive outcomes do not count. Replacing compression domain
`4` with `2+2` passes the complete fixture. These controls demonstrate proof
sensitivity, not the logical negation of the changed theorem.

`tools/c10_functional_caller_fixtures.py` independently constructs two full
forest recoveries using Python byte encodings, pins all 26 positional roots and
the two compressed values, and checks them in both provers. They include zero
and maximum hypertree fields and first, odd, last, outside and maximum-u32 leaf
indices. The thirteenth secret gets its separate tree-12 leaf hash at index zero.
Four layer examples retain zero-node WOTS rejection and the nine-level XMSS
continuation at counters 0, 9,999,999, 10,000,000 and maximum u32, with full-width
coordinates and empty witness lists. These layer examples use a constant-zero
backend. They check reduction to zero and cannot themselves distinguish a wrong
position, path or address. Universal consuming-proof controls remain separate.

The #1043 correction adds six input-sensitive examples with non-empty chains
and paths, zero/odd/full-width coordinates and the same four counter boundaries.
An independent imperative byte encoder pins every complete WOTS query, its
digest and rejected digit sum, the zero sentinel, and all nine XMSS node values.
The arithmetic backend observes addresses and path nodes. It deliberately need
not distinguish every counter: the encoded query checks pin the counter bytes,
while rejected counters can legitimately produce the same final root.
Four additional well-typed changes shift the recovery position, change the tree
address, reverse the path or omit continuation. Both provers reject their first
`layer_zero_complete` equation; Lean computes a false proposition. Baseline and
an equivalent `kp+0` example pass. The nine new native fixtures comprise that
equivalent positive and four definition-only/rejection pairs. Earlier examples
remain enrolled. These finite checks supplement universal correspondence; they
do not establish accepted-WOTS behavior or sensitivity to every possible change.

The earlier WOTS and complete-tree fixtures remain enrolled. All fixture
backends are public arithmetic, not SHA. Lean uses kernel `decide` and native
EasyCrypt checks the finite folds; Python is not a substitute proof checker.

## Functional complete verifier controls

`tools/c10_functional_verifier_controls.py` supplies ten typed mutations covering
digest indices and root binding, the forest digest/address, first-layer position,
top-layer identifier, the second layer's input message, forest ordering, the
forced-zero decision, final-root comparison and selection of the second decoded
layer. The 22 native fixtures contain two positives and ten definition-only /
intended-consumer rejection pairs; three scope probes cover the new modules.
The unchanged complete-verifier proofs consume local copies of the six appended
expressions, with earlier component proofs imported unchanged. Decision mutations
change the final Boolean adapter before rechecking its unchanged consumer.

`scripts/test_c10_functional_verifier_controls.py` runs in the full extracted
differential gate. The Lean checker enforces normal semantic rejection at the
intended first theorem. Local irreducibility keeps complete recovery and decoded
layer arrays symbolic during unification; explicit proof rewrites still unfold
the required definitions. Thus a mismatched layer does not earn rejection credit
from eager expansion or a resource limit. The equivalent `2-1` layer identifier
passes. Native first-location checks are retained in the coordinator's raw audit;
persistent native enforcement remains #1034. These are proof-sensitivity tests,
not proofs that every changed universal statement is false. Full cold replay and
all inherited controls remain mandatory.

## Functional complete signer controls

`tools/c10_functional_signer_controls.py` changes the optional randomizer,
secret/message order, nonce, public-root binding, first trial, search budget,
exhaustion selector, node order, high counter bytes, forest-path order, second
layer fields and randomizer prefix. Each typed change rechecks the unchanged
header or byte-encoding consumer. `tools/c10_functional_signer_composition_controls.py`
adds five paired changes to the first coordinates, second layer identifier,
second input message, second-layer exhaustion and outer root input. Three
native-only changes cover the header's call cost and history retained through
nonce exhaustion and completion. These native state/cost obligations are not
claimed as Lean runtime-effect proofs.

The native family has six positive/preserving fixtures and twenty separately
typed rejection pairs, plus eight scope probes. The Lean suite runs six
positive/preserving fixtures and seventeen typed rejections at the intended
first theorem in `scripts/test_c10_functional_signer_controls.py`, wired into
the full extracted differential gate. Each compiler process has a 4 GiB memory
cap; resource errors cannot earn rejection credit. The preserving variants use
a constant budget expression, bound-variable renaming and beta-equivalent
index selection. Native rejection locations are checked in the coordinator's
raw audit; persistent enforcement remains #1034. These controls establish
sensitivity of the selected consuming proofs, not falsity of every changed
proposition or completeness against all specification errors. Full cold replay
and inherited controls remain mandatory.

## Functional session and wrapper controls

The initialized-session batch uses four positive/preserving Lean fixtures and
eight separately typechecked changes to theorem propositions. Each unchanged
proof must reject at the named consuming theorem. These cover the actual keygen
layer and seed padding, initialized signer message and returned bytes, wrapper
shared bytes and verifier result, and the two-sign/one-verify event counts.
The typed fixtures define propositions; they do not admit the altered claims.

The native fixtures include eight positive/preserving checks and seventeen
separately typechecked operator or module mutations. They cover keygen layer,
secret and padding; request caps, the absorbing failure latch, returned-message
ledger and final freshness check; initialized key assignment; shared byte
encoding and decoding; and wrapper final-guard, second-sign cost, verifier cost
and second-sign history composition. The adaptive wrapper context adds charged
readiness refusals, later attempts and final freshness controls. Operator
arguments have explicit types so
that removing an argument's only use still produces a well-typed change. A type
error is never credited as a proof rejection.

Seven additional scope probes check the existing forbidden-symbol boundary for
the seven native modules. The full gate must execute every registered target and
control. Focused calibration alone is not full replay evidence. Raw receipts
must distinguish ordinary proof rejection at the intended consumer from
syntax/type failures, timeouts, signals and resource errors. These checks do not
transfer sampled-oracle security bounds or validate physical wrapper effects.

## Initialized byte-wrapper security controls

`tools/c10_wrapper_security_controls.py` supplies 13 positive/preserving fixtures
and 12 separately typed rejection pairs. The procedural changes cover logging
an unreleased result, logging a capped hash request, selecting the wrong FORS
tree, reversing the FORS or WOTS release guard, changing final message width,
removing final signature framing and opening a WOTS position during internal
planning. The focused byte controls compare a copy of the actual byte driver
directly with its unchanged original, keeping the shared session and byte view.

The early WOTS-value mutant adds its existing call rule to the proof, so its
rejection reaches the unchanged logical unopened-cut postcondition. The saved
failed goal identifies a matching selected coordinate whose flag changes from
false to true. The FORS address and release-guard failed obligations are also
inspected separately; tactic diagnostics alone are not presented as general
counterexamples.

Four charge-contract changes omit half the admitted-attempt candidate budget,
the WOTS contribution, the ordinary FORS contribution or the private-prefix
hop. They retain a definition-only typecheck and compare the altered charge
with the original proved contract by exact proof-term matching. Their unchanged
positive counterparts pass. This checks charge/statement sensitivity without
crediting an SMT search timeout as rejection, and does not assert that every
undercharged proposition is logically false.

Ninety-nine scope probes cover the new proof modules. All 99 direct targets,
their CLI replays and the new controls join the complete inherited cold gate.
`WrapperNumericalExamples` checks three strict numerical upper bounds in native
arithmetic. The coordinator must audit every new rejection's raw diagnostic at
the intended first consumer recorded by `CONSUMERS`; persistent enforcement of
that location check remains deferred in #1034. Parsing/type errors, signals,
resource failures and timeouts earn no rejection credit. These checks do not
extend the theorem to concrete backends, arbitrary Rust clients or hardware.
