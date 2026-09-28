# Public projected-node collision charge

`PublicCollisionBound.public_node_birthday` bounds a collision between the
16-byte node projections at two distinct inputs in the actual independent
public memoized table. The game initializes both tables and the public query
log, executes an arbitrary restricted `PrefixContext`, and observes that
retained-table event.

For a nonnegative whole-run public-call allowance `q`, the bound is
`q * (q - 1) / 2 * (1/2)^128`. Its explicit Hoare premise covers every public
call made by the context and its components, including cache hits. Private
calls use their separate memoized table; they do not draw from or inspect the
public sampler's bookkeeping. Contexts cannot directly access either table,
the query log or the proof observer.

The proof supplies the distribution and reduction. The ideal 256-bit digest's
node projection has the same distribution as packing 128 uniform bits. Its
history mass is at most the history length times `(1/2)^128`. An adaptive
birthday proof then counts fresh public draws. An exact oracle refinement
records one node per fresh public input, preserves cache hits, and proves
that a retained-table collision implies a repeated recorded node. The draw
count is at most the actual public-call count. No termination premise is
needed for this upper bound on a subdistribution event.

The previously checked Merkle/FORS path-input collision and FORS leaf-input
collision predicates imply this charged table event. The byte-width and pair
injectivity requirements remain explicit where needed. This closes the generic
independent public-node collision charge; it does not prove that every forgery
produces one of those events or an exposed private opening.

The statement is about the classical independent-table manual model. It is
not a 256-bit collision bound, a concrete SHA-256 theorem, QROM, extraction,
or a numerical end-to-end unforgeability claim. Adaptive accumulated opening
coverage and component forgery reductions remain under #100/#295. The
owner-triggered combined playbook pass #509 remains deferred.

The [complete byte-game application](RAW-BYTE-PUBLIC-COLLISIONS.md) supplies
the actual session budget. The [zero-node companion](RAW-ZERO-NODE-CHARGE.md)
separately covers the possible invalid-sum WOTS sentinel match.
