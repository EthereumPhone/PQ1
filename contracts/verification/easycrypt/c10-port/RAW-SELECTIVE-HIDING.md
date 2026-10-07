# Selective hiding of an ordinary FORS private value

This extends the [private-guess boundary](RAW-PRIVATE-GUESS-BOUNDARY.md)
in the manual classical ideal-oracle model. It proves a numerical bound for a
selected private-input experiment, including an actual byte-client consumer.
It does **not yet charge the unreturned-private-opening event in the original
initialized byte game**. The connecting obligations are listed below.

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
client premise. The remaining resource premise bounds **all public hash calls
in the transformed ideal game** by `q`, including non-encapsulated internal
hashes. It is not merely the byte client's raw-query cap. Initial-state versions
freeze the context's starting globals, so runtime caps need not be uniform over
unrelated configurations. This resource premise has not yet been discharged for
the complete byte consumer.

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
inside the adapter. The target's ordinary-tree bounds will be needed when the
final existential event is charged.

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
final table equality. This is a separate sampling lemma, not yet the complete
original-game/selective-game event hop. The context explicitly excludes both
the sampled table and target-sampling globals; the eager swap writes only the
excluded private table. This satisfies the disjointness condition missing from
older EasyCrypt eager automation (upstream #1097). The pinned checker and SMT
solvers remain trusted components; the scoped checker update/audit is tracked
in #100. No new project axiom, admit, or unresolved clone assumption is added.

## Remaining connection to the original forgery event

1. Complete the original initialized private-table to selective-table projection
   using the sampling lemma, with the exact observed output and event preserved.
2. Prove that a selected unreturned ordinary coordinate was not internally
   opened on a successful run, accounting for repeated responses and signing
   failures. Non-aliasing or an absent response alone is not this proof.
3. Discharge the transformed game's public-query budget. Internal selected leaf
   commitments are encapsulated; other honest hashes must remain accounted for.
4. Charge the final existential coordinate using a proved finite-coordinate
   union bound or adaptive selection reduction.

The WOTS reverse-chain/new-message charges, encoding/ITSR charges, and numerical
same-game EUF composition follow under #100/#295. Concrete SHA-256, QROM,
extraction, #789 optimization and #509 combined assurance remain separate.

## Controls and evidence scope

Exact consumers and positive witnesses cover opened-output rejection, empty
candidates, memoized commitment replay, internal leaves preserving the unopened
flag, explicit secrets setting it, output binding, and repeated client queries.
Registered rejected attempts remove the twelve final candidates, substitute
256-bit for 128-bit node guessing, accept an opened candidate, substitute the
output log, or drop the second query. Each rejection concerns that concrete
proof attempt; it is not a general claim that every premise is necessary.
Every new target is enrolled in both proof drivers, statement/definition pins,
source bindings and forbidden-theory scope probes. See
[control evidence](CONTROL-EVIDENCE.md) for the gate's evidence ceiling.
