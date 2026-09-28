# Public collision charge in the complete byte game

`BytePublicCollision.byte_public_collision_hop` applies the public-node
birthday theorem to the actual adaptive byte-signing experiment. For
`Q = full_public_budget qr qs`, it proves

```
Pr[physical byte-game win]
  <= Pr[independent byte-game win and no retained public-node collision]
     + Q*(Q-1)/2 * (1/2)^128 + Q * (1/2)^256.
```

The same client runs in both games. Its nonnegative public and signing caps,
initial cap bindings, oracle-relative termination and private-state restrictions
are explicit. Key generation, signing, cache hits and final verification all
contribute to Q. A state-indexed budget fixes the actual initial client state;
it does not assume a uniform resource bound over unrelated states.

The first probability on the right is deliberately retained. Its event still
requires an accepted new-message forgery in the real byte-facing model. This
result does not prove that event impossible, bound accumulated FORS openings,
extract a WOTS preimage, or give a closed numerical EUF advantage. The 128-bit
term is for node outputs; the 256-bit term is the existing secret-prefix hop.
They are not interchangeable with the separate 161-bit coordinate replay term.

This is a classical oracle-model reduction for manually transcribed code.
Concrete SHA-256 security, Rust extraction, QROM and production authority remain
outside it. #100/#295 retain the adaptive/component reduction obligations and
#509 remains a deferred combined playbook pass.

The [zero-node companion](RAW-ZERO-NODE-CHARGE.md) further excludes public
zero nodes from the residual, with its own explicit Q * (1/2)^128 charge.
