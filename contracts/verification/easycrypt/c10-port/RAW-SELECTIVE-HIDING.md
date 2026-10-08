# Ordinary FORS private-opening charge

This extends the [private-guess boundary](RAW-PRIVATE-GUESS-BOUNDARY.md)
in the manual classical ideal-oracle model. The selective hiding experiment
is now connected to an unreturned ordinary private opening in the **actual
accepted output** of the original initialized byte game.

`OriginalForsOpeningBound.original_byte_fors_opening_bound` proves

```
Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run :
   res /\ actual_output_unreturned(..., ClientQueryLog.output)]
  <= 6442450944 * (full_public_budget(qr, qs) + 12) / 2^128

full_public_budget(qr, qs)
  = 155135 + qr + qs * (3 * signing_budget + 364892) + 771
```

Premises are nonnegative configured query/signing caps and client termination
for lossless byte hash/sign oracles. The theorem exposes no unproved query
budget or private-independence premise. Its finite-universe factor is
`2^18 * 12 * 2^11 = 6442450944`; this is a conservative union bound, not a tight
128-bit security claim. It charges this event only, not complete EUF success.
The special thirteenth tree is not an ordinary private-value candidate.

## Quantitative result and its premises

`TargetByteBound.byte_selective_private_guess_bound` proves

```
Pr[SelectivePrivateGuess(TargetByteCandidates(A)).run : res]
    <= (q + 12) / 2^128.
```

The private input is fixed before initialization. Its full digest is sampled
uniformly, and all other private inputs use a persistent independent table.
The same public oracle serves commitments and public hash calls. A byte client
still sees only the original hash/sign interface. A successful experiment
requires the structured byte-game verifier to accept, an ordinary output slot
to equal the selected private node, and the selected input never to have been
explicitly opened. The twelve slots include duplicates and arbitrary values.

The client must terminate for lossless byte hash/sign oracles. Termination of
the factored signer, verifier, key generation, and adapters is proved from that
client premise. The selective theorem's resource premise bounds **all public hash calls
in the transformed ideal game** by `q`, including non-encapsulated internal
hashes. It is not merely the byte client's raw-query cap. Initial-state versions
freeze the context's starting globals, so runtime caps need not be uniform over
unrelated configurations. `TargetAdapterCost.ec`, `TargetForsCost.ec`,
`TargetSignerCost.ec` and `TargetSessionCost.ec` discharge it for the transformed
byte consumer, including repeated calls, initialization and final verification.

## Why commitments do not reveal the node for free

`LeafCommitmentHybrid.ec` maintains a relation between the real public table
and separate public/commitment tables. A commitment to a prefix hashes
`prefix ++ pad key`. Its answer is memoized, including repeated commitments.
Ordinary hash queries preserve the relation until the sixteen-byte node slot
in their final padded block equals the hidden key. The slot test is conservative:
it includes malformed inputs and does not require the trailing padding to be
valid. Queries before and after commitment creation are both covered.

`LeafCommitmentBound.ec` removes the private hit observer, moves the independent
node draw after the context, and applies the finite-list mass bound. With `q`
public queries and `n` final candidates, the charge is `(q+n)/2^128`.
The commitment interface does not expose private derivation values: its
`derive(prefix)` method means a public commitment in this local experiment.

`LeafOpeningBound.ec` allows adaptive requests to reveal the selected key.
It proves an exact event equivalence to a redacted experiment that drops all
final candidates after a reveal. Its up-to-reveal invariant records that the
real side has also revealed the key; it therefore does not add the probability
of a legitimate reveal as a guessing charge. Opened runs cannot win the
unopened-value experiment.

`TargetOracleSplit.ec` connects this experiment to a selected FORS private
input. Internal leaf commitments use the selected value without marking it
opened. Explicit secret requests and direct private derivation of that input
mark it opened. Other private inputs remain memoized. Equality of encoded
inputs selects the target, avoiding an unproved coordinate-injectivity premise
inside the adapter. `ForsCoordinateUniverse.ec` proves coverage and the exact
size of the finite ordinary-coordinate universe used by the union bound.

## Connection already proved to the original program

`ClientOutputBinding.ec` relates the private output log to a reference driver
that returns the exact pair submitted to the original final verifier, including
rejected pairs. It also proves eligibility of the recorded output on success.
`ClientQueryReplay.ec` proves that two forwarded identical queries append twice
and consume two calls. The earlier reflexive coordinate identity has been
replaced by a consumer of this operational witness.

`LeafForestView.ec`, `LeafSignerView.ec`, and `LeafSessionView.ec` lift the exact
commitment/opening interface through the forest, signer, session and initialized
byte game, preserving results, original oracle state, and both private logs.
`TargetByteView.ec` projects the internal target interface back to that program
and proves at most twelve final candidates. The original signer is unchanged.

`PrivateTargetSampling.ec` proves that memoizing one private entry before an
adaptive context is equivalent to memoizing it afterwards, including complete
final table equality. `TargetTableProjection.ec` and `TargetTableGames.ec`
complete the event hop. An absent selected entry cannot satisfy the original
event; sampling it afterwards may add success, so this step is an inequality.
The context explicitly excludes both
the sampled table and target-sampling globals; the eager swap writes only the
excluded private table. This satisfies the disjointness condition missing from
older EasyCrypt eager automation (upstream #1097). The pinned checker and SMT
solvers remain trusted components; the scoped checker update/audit is tracked
in #100. No new project axiom, admit, or unresolved clone assumption is added.

## Original-game connection and remaining composition

`TargetSignerOpenings.ec` binds a newly observed opening to the successful
signature's actual H_msg digest. The session/exposure/client/context lemmas
prove that any such opening on a nonfailed accepted run is represented in the
persistent returned-response ledger. Failed signing is absorbing, and later
public hashes and successful requests preserve prior exposure entries.
Thus an unreturned ordinary encoded input is unopened on the winning event.
Non-aliasing or an absent response alone is never used as a hiding argument.

`OriginalCandidateBound.ec` supplies a pointwise charge in the unchanged
initialized byte candidate game. `OriginalCandidateUnion.ec` combines those
charges in that same game. `ActualForsOpening.ec` attaches the event to the
exact client output and its H_msg table entry; `OriginalForsOpeningBound.ec`
consumes the union for that accepted output.

The older `new_message_exposure_partition` and
`new_message_unaliased_partition` predicates contain existential signature
witnesses. Their whole existential events are **not** silently identified with
this actual-output event. The final common-game composition must carry the
actual-output witness through its extraction and partition steps.

WOTS reverse-chain/new-message charges, encoding/ITSR charges, that explicit
partition connection, and numerical same-game EUF composition remain under
#100/#295. Concrete SHA-256, QROM, extraction, #789 optimization and #509 combined
assurance remain separate.

## Controls and evidence scope

Exact consumers and positive witnesses cover opened-output rejection, empty
candidates, memoized commitment replay, internal leaves preserving the unopened
flag, explicit secrets setting it, output binding, and repeated client queries.
Registered rejected attempts remove the twelve final candidates, substitute
256-bit for 128-bit node guessing, accept an opened candidate, substitute the
output log, or drop the second query. Each rejection concerns that concrete
proof attempt; it is not a general claim that every premise is necessary.
The dropped-query control now uses a valid one-call proof script, with an
otherwise identical passing one-call witness. New controls also reject losing
a public adapter call, treating tree 12 as ordinary, treating an absent private
entry as selected, and clearing an already failed session.
Every new target is enrolled in both proof drivers, statement/definition pins,
source bindings and forbidden-theory scope probes. See
[control evidence](CONTROL-EVIDENCE.md) for the gate's evidence ceiling.

The [WOTS continuation](RAW-WOTS-CHARGE.md) supplies the exact-output partition,
reverse-chain and encoding charges. Accumulated returned FORS coverage/ITSR and
the final common-game numerical composition remain open.
