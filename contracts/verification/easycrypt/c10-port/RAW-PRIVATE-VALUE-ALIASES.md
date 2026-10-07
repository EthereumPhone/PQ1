# Generated-node aliases for ordinary private FORS values

This extends the [returned-coordinate partition](RAW-FORGERY-PARTITION.md) in
the manual classical ideal-oracle model. It gives one exposure subcase a
numerical charge in the original initialized byte game. Direct adaptive guesses
and the other forgery cases remain explicit; this is not a closed EUF bound.

## The charged event

`JointNodeCollision.ec` defines `private_node_alias`: either two **distinct
private-table inputs** have equal projected 128-bit nodes, or a private-table
node equals a public-table node. Public and private tables are independent in
this game, so the cross-table case includes equal raw input bytes. A replay of
one private input is one retained draw, not a collision with itself.

The event includes all retained public/intermediate projected nodes and all
private inputs, including values that were never returned. It is a conservative
bad event, not a complete description of information available to the client.
In particular, absence of this event says nothing about private values appearing
in public query **inputs**, computations using known values, or successful
direct guesses. Nor does this result prove that two different coordinates have
different encoded private inputs.

`JointMemoOracle.ec` samples both kinds of fresh entries through the existing
`ProjectedSamples` sampler. It records their nodes in one private list and
counts every hash/derive call, including replays. Exact relational proofs
preserve the original independent oracle's answers, both tables, public query
list and client state. The client cannot access the observer's private state.
`PrivateAliasBound.ec` applies the existing adaptive projected-node birthday
lemma to that list. No conditional independence after observing signatures is
assumed. The generic theorem first has an explicit draw-budget event; the
state-bound theorem requires a proved call budget.

`JointCallCost.ec` proves that budget for the unchanged key generation, raw
hash/sign interface, byte client and final verification, all instantiated with
the independent instrumented oracle. The proof follows the existing physical
call-accounting proof bodies; it does not infer equal physical/independent
execution lengths. `BytePrivateAlias.ec` discharges the budget premise for the
actual `ByteContext`. With nonnegative raw/sign caps `qr, qs`, let

```
Q = full_physical_budget qr qs
  = 177151 + qr + qs * (4 * signing_budget + 435646) + 771
signing_budget = 10000000
```

Then `byte_private_node_alias` bounds the initialized independent byte game's
alias-event probability by `Q * (Q - 1) / 2 * 2^-128`. Despite the reused budget
name, the accounting here is proved for the independent game. Counting all
calls overestimates fresh draws; the birthday bound also charges public/public
pairs. These are deliberate overestimates, not tightness claims.

## Same-game forgery refinement

`ForsValueExposure.ec` partitions an unreturned ordinary opening into a value
that equals a node elsewhere in the tables, or a value without such an alias.
An aliased opening implies the charged event. Different ordinary leaves can
witness the two cases, so this existential partition is not claimed disjoint.
Outside the global alias event, every unreturned-opening witness is unaliased.
The twelve ordinary leaves and thirteenth root-as-secret remain separate.

`BytePrivateAliasHop.ec::byte_aliased_private_opening` gives the aliased ordinary
opening event the same numerical bound in the passive exposure game. The exact
observer projection preserves the original tables. `byte_private_alias_hop`
adds this charge to the existing real-to-independent hop and refines its
residual with `!private_node_alias` and `new_message_unaliased_partition`.
Successful forgery `res`, message freshness, root/seed binding, public collision
and zero exclusions, and all three previous charges are retained. The new top
WOTS, new bottom WOTS, unaliased private opening, and accumulated-returned-value
cases still need their remaining probability arguments.

## Evidence and limits

Nine new modules are direct and CLI replay targets. Their 70 statements and 11
operator definitions are pinned; two instrumented module bodies also enter the
declaration census. Existing statements and project assumptions are unchanged:
no new axiom, admit or clone assumption. `BytePrivateAliasConsumer.ec` consumes
the exact complete hop. `PrivateAliasControls.ec` proves single-input/replay,
cross-table equal-input, distinct-private-input, and public-node boundaries. It
also constructs an unaliased unreturned opening: no-alias is not impossibility
or secrecy. That algebraic witness is not a successful forgery experiment.

Nine scope probes check name-level isolation from the existing admitted theory.
The no-charge control deliberately mismatches an exact theorem application;
its rejection does not prove the removed charge necessary. The no-cross control
copies the defining module, drops its cross-table event, and checks rejection
of the existing proof. Neither rejection is a general soundness proof. See
[control evidence](CONTROL-EVIDENCE.md).

The next mathematical obligation is a hiding/lazy-sampling argument for direct
adaptive private-value guesses through the actual public hash/sign interface.
Uniform fresh draws alone do not justify that bound after observations. General
exposure accounting, WOTS reverse-chain bounds, encoding/ITSR, and the final
numerical EUF bound remain open under #100/#295. Rust extraction, concrete
SHA-256 and QROM remain separate. Optimization #789 and combined owner-triggered
assurance #509 remain deferred.
