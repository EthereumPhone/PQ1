# Boundary for ordinary FORS private-value guessing

This supplies prerequisites for the next hiding argument in the manual
classical ideal-oracle model. It extends the
[generated-node alias result](RAW-PRIVATE-VALUE-ALIASES.md), without adding
another probability charge to the byte-game forgery bound.

## Encoded private inputs

`ForsInputSeparation.ec` reuses the existing four-byte decoding theorem to
prove injectivity of `fors_tail` and `fors_private_key` when each integer is
in `[0, 2^32)`. Existing digest-coordinate bounds discharge these premises for
the actual eighteen-bit hypertree index and eleven-bit FORS leaf indices.
Tree indices 0 through 12 remain distinct. WOTS and R private inputs have
different tags. These statements concern input bytes, not independent outputs
or the secrecy of a value.

`ReturnedPrivateInputs.ec` proves that returned ordinary-coordinate coverage
equals coverage of its encoded private input. With the existing supported
response ledger, width, public-collision and private-alias exclusions, a value
at an unreturned ordinary coordinate cannot equal any explicitly logged
ordinary FORS private value, including one at another coordinate. This does
not cover all information an adversary can compute from signatures.

## Actual client queries and final output

`ClientQueryLog.ec` adds a private observer around the client-facing session.
It records precisely the raw inputs forwarded under the raw-query cap,
including repeats. Calls rejected because the cap is exhausted are not logged.
Signing calls preserve this list: internal signing hashes do not enter it.
The existing successful-response ledger is preserved.

`ClientQueryDriver.ec` records the client's final structured output before
verification. Its relational projection preserves the initialized exposure
game's result, client state, original oracle tables/query list, session state
and response ledger. The observer is inaccessible to both client and oracle.
The earlier byte-to-exposure projection connects this to the original byte
game. A proved session invariant bounds recorded inputs by the raw-query cap.

`ClientGuessCandidates.ec` forms a list consisting of the sixteen-byte slot
at offset 64 of each forwarded input and the twelve ordinary private-value
slots of the final output. A correctly framed FORS leaf query places its
secret in that exact input slot. Every ordinary final-output slot also appears
in the list, which has size at most `qr + 12`. This includes arbitrary,
malformed and repeated query inputs; no byte-validity or distinctness premise
is silently imposed on them.

The list is **not independent of actual private values merely because its size
is bounded**. The mass lemma for a fresh independent node draw is an auxiliary
distribution fact, not a probability bound for the actual signer. In
particular, the client may have learned values through signing responses.

## Commitment/opening interface

`ForsLeafView.ec` separates a FORS leaf's public commitment from an explicit
private-value opening. The concrete implementation uses the original private
derivation and public hash operations in the same order. Relational proofs
preserve the result and complete oracle state for tree construction, root
computation and signing. These equivalences hold for an arbitrary preparation
oracle, so they do not assume oracle freshness, independence or determinism.

This interface is a prerequisite for replacing one unrevealed leaf commitment
by a separately sampled value. That replacement and its common-game coupling
are not proved here. The original signing and verification modules are unchanged.

## Evidence and next obligation

Eight modules add 45 statements and three operator pins. Their definitions,
module bodies and interface signature enter the census. Existing statements
and project assumptions remain unchanged; there is no new axiom, admit or
clone assumption. Exact consumers check byte-game projection and the candidate
budget. Positive controls cover two forwarded queries at the same coordinate, the ordinary/special tree
boundary, candidate counts, and forwarded versus blocked queries.

Eight scope probes and three rejected attempts cover forbidden-theory scope,
dropping final-output candidates, logging blocked calls, and removing bounded
encoding premises. Rejection means the particular proof attempt fails, not
that every hypothesis is necessary; see [control evidence](CONTROL-EVIDENCE.md).

Next: prove a selective private-leaf hiding/lazy-sampling game hop, preserve
the actual public hash/sign view up to a recorded input hit, and discharge its
reveal and resource conditions. Only then can a fresh-node mass bound charge
the remaining adaptive private-value event. WOTS reverse-chain/new-message
bounds, encoding/ITSR and the composed numerical EUF bound follow under
#100/#295. Concrete SHA-256, QROM and Rust extraction remain separate; #789 and
#509 remain deferred.

The [selective-hiding continuation](RAW-SELECTIVE-HIDING.md) now supplies the
output/verified-pair relation, an operational repeated-query witness, full
interface lifting, and a numerical selective experiment. Its original-game
event connection and transformed resource premise remain explicit.
