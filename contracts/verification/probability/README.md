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
**The probability-monad forgery-game theorem
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

This closes the named manually transcribed WOTS and Merkle subtree clients.
Full C10 FORS/hypertree composition, session cost, successful-output partition
and the forgery game remain open. Shuffle
sub-seed derivation belongs to those outer callers. Natural-number address
truncation, the manual correspondence boundary, Rust panic/callback/erasure
behavior and concrete backends remain explicit.

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

The gate rebuilds every project module, checks all 861 theorem closures against
the standard logical axioms (`propext`, `Classical.choice`, `Quot.sound`), and
requires the complete source, statement and query inventories. It rejects
proof escape constructs and verifies the projection-source bindings. An actual
compiler-produced added-assumption canary must be rejected by the closure
checker; missing closure records must also fail.

440 typed cases run 1320 compiler jobs: each baseline and changed
definition must compile, 381 changed behaviors must reject at the
consuming `checked` theorem, and fifty-nine value-preserving changes must pass.
The 42 Merkle cases cover stack geometry/costs, pair bytes/order, authentication
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
