# Complete-session history and repeat accounting

These classical ideal-oracle lemmas extend the
[quantitative foundations](QUANTITATIVE-FOUNDATIONS.md). They remove a manual
freshness premise for new messages and characterize repeated signing
contexts in the complete structured and byte-session models.

## History of a live session

FullMessageHistory and ByteHistory establish the actual session invariant:
all private R derivations belong to messages in FullSession.signed_messages
while FullSession.failed is false. The public table also retains a record
of every public input. Key generation, complete signing, adaptive interface
calls and final verification are covered.

RTailMessages then makes every unsigned 32-byte message fresh for the
entire bounded grind window, for any randomizer input. This conclusion
uses the existing fixed-width message contract and private module
restrictions. Failed signing is sticky; the statement does not assert the
live-session invariant after failure.

## Repeated contexts

GrindTrace records the rejected trials before the first acceptance.
GrindTraceRecorded proves that the actual memoized grinder produces such a
trace. Public and private table extensions preserve it. GrindTraceReplay
proves that a repeated context cannot produce a different accepted result
and has zero probability of grind exhaustion once this trace exists.

SignerTrace carries the trace through complete signature construction.
Successful repeats retain the emitted randomizer and the same accepted
digest. It does not assert byte-identical complete signatures for different
shuffle inputs, nor does it make an extraction claim.

ClassifiedSession proves a stronger invariant for each live complete game:
every 32-byte context is either unused over the whole grind window or has
a retained completed trace. No additional context list is exposed to the
client. The corresponding theorems cover IndependentGame(FullContext(A))
and IndependentGame(ByteContext(A)).

## Quantitative consequence and its limit

ClassifiedBound.session_novel_digest_bound proves

    Pr[session returns a signature whose retained digest satisfies p]
      <= accepted_probability(p) + revisit_charge(size(entry public queries)).

It requires a live classified session, the recorded public history, the
32-byte seed/root/message contracts, and the condition that p rejects the
retained output if the current context was already completed. The fresh
case uses the existing memoized signing bound. The repeated case contributes
zero to this event. The predicate is fixed at call entry and may depend on
that entry state.

All of these history invariants are statements about the independent-table
intermediate model. The existing whole-game secret-prefix hop does not
turn its private state into literal physical-Rust state.

This does not bound arbitrary eventual FORS opening sets, remove the
cached-query charge, or close the complete byte-game component reduction.
The accumulated-opening argument and quantitative EUF-CMA composition
remain open under #100/#295. No deployed 96-bit security, concrete SHA-256,
QROM or Rust-extraction claim follows.

## Controls

Positive controls replay the live byte-session invariant, repeat/fresh
separation and novel-event law. Negative controls require rejection after
dropping fail-stop handling, the private-state restriction, or the retained
output condition, and when a completed context is claimed fresh. Four
scope probes check the new headline environments.
