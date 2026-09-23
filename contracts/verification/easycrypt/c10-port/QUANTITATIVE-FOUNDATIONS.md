# Quantitative C10 foundations

These classical ideal-oracle lemmas extend the
[shared byte-session model](SHARED-BYTE-SESSION.md). They bound particular
events in the actual memoized grinder and complete signer, and isolate an
exact-coordinate replay event in the adaptive byte game. They do not bound
the remaining independent-game forgery probability.

## Exact-coordinate replay

`ByteReplay.byte_coordinate_replay_hop` gives, with
`Q = full_public_budget qr qs`,

```text
Pr[real byte-game win]
  <= Pr[audited byte-game win and accepted-coordinate uniqueness]
     + Q(Q-1)/2 * 2^-161 + Q * 2^-256.
```

The original nonnegative caps, oracle-relative adversary termination and
module privacy restrictions remain premises. The same client is used in each
game. The private monitor does not cap the public oracle: it records only the
first Q calls, while normal memoized answers continue. A separate checked
cost theorem covers every public call in this experiment.

For valid accepted 256-bit digests, equal twelve FORS coordinates and equal
18-bit hypertree coordinates imply equal first 161 bits. The forced-zero
11-bit chunk occupies positions 132 through 142. Equal H_msg inputs with
equal randomizer widths imply equal messages. This prevents exact-coordinate
replay across different messages on the uniqueness event.

It does not prevent combining FORS openings from several signatures. The
residual audited forgery event explicitly includes that possibility.
The 161-bit projection is an H_msg coordinate fact, not a collision bound for
the 128-bit node/R suffix. `DigestWindow` separately proves fresh window laws.

## Accepted output of an actual signing call

`StreamAccepted.role_grind_accepted_bound` proves, for every fixed digest
predicate p,

```text
Pr[RoleGrind returns Some(r,d) with p(d)]
  <= Pr[fresh uniform d satisfies p, conditioned on acceptance]
     + revisit_charge q0.
```

The premises include the recorded entry history with q0 public calls, fresh
private derivation tails for this context, and 32-byte seed/root arguments.
The loop stops at its first accepted digest or the deployed 10-million-trial
limit. A cached public H_msg input is accounted for by the explicit revisit
event, not assigned a new independent digest.

`SignerReturned.signature_digest_bound` carries this bound through complete
signature construction. A private observation is equivalent to the actual
signer, preserving its returned signature and oracle state. The proof ties
the emitted randomizer to the retained accepted H_msg entry and proves that
the subsequent FORS/WOTS/Merkle work preserves that entry. Failed complete
signatures do not contribute to the success event.

This theorem observes the retained table entry at the model's emitted
randomizer followed by sixteen zero bytes. It is not an extra oracle call or
an adversary API exposing private state. Wire widths and the physical
byte-session connection retain the separate contracts documented in
`SHARED-BYTE-SESSION.md`.

Two corollaries are checked:

- A fixed 18-bit hypertree target has probability at most
  `2^-18 + revisit_charge q0`.
- For twelve opening lists fixed before the call, and a fixed hypertree
  target, the joint probability is at most
  `2^-18 * product_i(size(opened_i) * 2^-11) + revisit_charge q0`.
  The exact distributional statement uses the twelve list-membership
  probabilities; list sizes give a conservative bound even with duplicates.

The charge is the previously checked sum
`sum_{i=0}^{B-1}(q0+i)*2^-128`, where B is the signing limit.
The accepted-output bound does not substitute an expected number of trials
for this worst-case allowance.

## Adaptive boundary and controls

The opening lists and target above are fixed before that invocation. They
may depend on its entry state. They cannot be replaced by sets enlarged
after seeing this invocation's output or by the eventual sets after future
chosen signing requests without another argument.

The enrolled timing countermodel constructs each singleton opening directly
from the sampled digest. Coverage then always holds, so joint
acceptance/coverage has probability `2^-11`, rather than the
`2^-143` expression obtained by treating those singletons as fixed before
the draw. This is a counterexample to that independence shortcut, not a
deployed signing attack.

Positive controls replay the complete-signing and joint laws. Negative
controls require rejection when private-tail freshness, the revisit charge,
or the opening-set timing boundary is removed. Separate scope probes check
the four new headline environments.

## Remaining proof obligations

The complete adaptive byte game still needs a checked component reduction
and an accumulated-opening argument that handles future signing queries,
repeated contexts and their costs. These lemmas do not supply those missing
steps, a numerical end-to-end EUF-CMA bound, a 96-bit deployed security claim,
Rust extraction, a concrete SHA-256 theorem or QROM security.

The opened-position and component-reduction distinctions in
[the SPHINCS+C analysis, sections 4.1.1 and 5.2](https://eprint.iacr.org/2022/778.pdf)
guide the remaining work. Its public-counter construction must not be
silently substituted for this model's secret-derived R loop.
The research remains tracked in #100 and #295; #509 remains a deferred
owner-triggered combined playbook pass.
