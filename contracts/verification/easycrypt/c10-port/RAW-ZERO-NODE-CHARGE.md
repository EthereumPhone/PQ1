# The WOTS zero sentinel has an explicit probability charge

The actual WOTS recovery procedure returns sixteen zero bytes when its count
hash does not satisfy the target sum. A generated reference leaf can also be
zero. The model therefore must not assume that matching an earlier leaf proves
count acceptance merely because the reference was generated honestly.

`WotsZeroSentinel.invalid_sum_matches_only_zero` proves that an invalid-sum
recovery matching a retained reference leaf implies a recorded public zero-node
event. The proof uses the actual recovery behavior and reference compression
entry. No nonzero-node premise is introduced. A concrete valid 256-bit digest
with a zero node projection is exhibited by a positive control.

`PublicNodeZero.public_node_zero_at_state` charges this event by
`q * (1/2)^128` for a public-call-bounded context from empty tables. Fresh
public draws are recorded; cached calls remain in the query budget and do not
become fresh draws. Private calls remain in the separate private table.

For the complete actual byte-signing game, `BytePublicNodeBad` combines this
with the existing public-collision and same-secret prefix bounds. With
`Q = full_public_budget qr qs`, the residual successful-forgery event excludes
both public-node collisions and public zero nodes, and the added charges are

```
Q*(Q-1)/2 * (1/2)^128 + Q * (1/2)^128 + Q * (1/2)^256.
```

The residual probability is retained. This is not a completed WOTS/FORS
forgery extraction, adaptive accumulated-opening proof or numerical EUF bound.
It concerns the classical manually transcribed oracle model, not concrete
SHA-256, Rust extraction, QROM or production authority. #100/#295 stay open;
#509 remains an owner-triggered deferred playbook pass.
