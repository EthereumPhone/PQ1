# Numerical EUF bound for the initialized byte game

`NumericalByteBound.physical_byte_euf_bound` gives an explicit upper bound on
successful new-message forgery in `RealGame(ByteContext(A)).run`. This is the
manually transcribed, classical ideal-oracle byte game, with actual key
generation, adaptive hash/sign calls, complete verification and the 4008-byte
signature codec. It is separate from the older conditional MM45 theorem family.

For nonnegative configured caps `qr` and `qs`, define

```
Q = full_public_budget(qr, qs)
  = 155135 + qr + qs * (3 * 10000000 + 364892) + 771
n = qr + qs + 1
C(n) = sum(j = 1..12, n^(j+1) * j^12 / 2^(132+18*j))

Pr[RealGame(ByteContext(A)).run : res]
 <= Q*(Q-1)/(2*2^128)                 public node collisions
  + Q/2^128                         zero-node sentinel
  + Q*(Q-1)/(2*2^129)                WOTS encoding collisions
  + 632475648*(Q+86)/2^128           WOTS reverse-chain cuts
  + 6442450944*(Q+12)/2^128          unreturned ordinary FORS openings
  + C(n)                            accumulated returned FORS coverage
  + Q/2^256                         shared/private-prefix game transfer
```

The client must terminate for lossless hash/sign oracles. The theorem's module
exclusions keep private oracle state and proof observers inaccessible. They are
not independence assumptions supplied by the client. There are no new project
axioms, admitted proofs or unresolved clone premises in this continuation.
`original_byte_euf_bound` proves the first six terms in the common initialized
`IndependentGame(ClientQueryContext(ByteLift(A)))` game. Exact projections and
the previously proved physical-to-independent hop give the seventh term.

## Accepted samples and adaptive coverage

`HmsgMemoOracle` refines the persistent oracle exactly. For a fresh 160-byte
public input, it samples the acceptance flag, then a digest from the appropriate
conditional distribution. Accepted digests enter a private iid sample pool.
Memoized repeats return the stored digest. `AcceptedDigestDistribution` proves
that this split has the original full-digest distribution.

`Hmsg*Count` proves width and count invariants through key generation, shuffles,
WOTS chains, FORS, Merkle construction, grinding, signing and verification.
Internal inputs other than H_msg have widths different from 160. One completed
signing grind adds at most one accepted H_msg call; a raw client call adds at
most one, as does final verification. The counter conservatively counts cached
accepted calls too. The number of fresh accepted samples is therefore at most
`qr + qs + 1`, without assuming fresh signing randomizers or distinct contexts.
Failures, malformed/refused requests and absorbing failed sessions are retained.

`HmsgPoolRecords` assigns each accepted H_msg table entry a matching pool index.
`CoveredOutputPool` binds the actual new-message output and every coordinate's
returned witness to these indices. New-message input distinctness makes the
target index different from all witness indices. Digest values themselves may
coincide. `CoverageWitnessCompression` retains at most twelve distinct witness
indices and an assignment of each of the twelve ordinary FORS coordinates to a
witness. The special thirteenth root-as-secret is handled by the earlier output
partition; it is not counted as an ordinary hidden coordinate.

For a fixed target and `j` distinct witnesses, a fixed assignment requires all
witnesses to share the target's 18-bit hypertree field and to match the assigned
11-bit FORS coordinates. `SelectedCoverageMass` proves exact mass
`2^(-132-18*j)`. The finite union uses at most `n` target choices, `n^j` witness
sequences and `j^12` assignments, yielding `C(n)`. This deliberately overcounts.

The coverage event persists when the pool grows. `AcceptedPrefixSampling`
uses a nonnegative completion-expectation invariant to dominate an arbitrary
adaptive prefix by a fixed iid pool of size `n`. Thus later signing responses,
repeated contexts and adaptive stopping are included; no final adaptive set is
substituted into a fixed-prior-set theorem. `OriginalCoverageBound` transfers
this charge back to the actual output event in the original byte game.

## Canonical-witness tightening

`CanonicalNumericalBound.physical_byte_canonical_euf_bound` proves the same
initialized byte-game bound with only the coverage term replaced by

```
A(j) = product(i = 0..11, min(j, 12-i)) = j! * j^(12-j), for 1 <= j <= 12
Ccanonical(n) = sum(j = 1..12, n^(j+1) * A(j) / 2^(132+18*j))
```

`CanonicalWitnessIndices` bounds the index of each coordinate's witness after
reversing last-occurrence deduplication. Its index is less than `12-i` and
less than the number of witnesses. `CanonicalPoolWitness` constructs that
representation; `CanonicalPoolEvent` proves it represents exactly the earlier
coverage event. `BoundedAssignmentWords` enumerates the separate coordinate
alphabets and proves their cardinality. The uniform assignment mass, adaptive
prefix domination and original-game projection are retained.

`canonical_physical_charge_tighter` proves that the resulting full bound is
no larger than the earlier bound for every nonnegative pair of caps. At the
example caps, coverage is approximately `8.2837816e-29` (`2^-93.29`), an
improvement by about 1,644 times. The overall probability upper bound remains
approximately `8.7695861e-15` (`2^-46.70`) because the other charges are unchanged.
The assignment enumeration still overcounts; this is not the exact occupancy
or Stirling-number formula.

## Composition, evidence and limits

`NumericalByteCases` proves that every successful output belongs to one of the
six charged cases. The composition uses those events in one initialized game;
it does not sum probabilities from incompatible transformed experiments.
The [WOTS](RAW-WOTS-CHARGE.md) and [FORS](RAW-SELECTIVE-HIDING.md) owners explain
the earlier hiding and finite-coordinate charges.

All new proof modules are direct and CLI replay targets with statement and
operation pins, source bindings, a declaration census and scope controls. Four
paired checks cover accepted cached-call accounting, distinct iid indices,
the single-witness assignment mass and the physical-transfer expression. Their
rejections have the limited meaning described in [CONTROL-EVIDENCE.md](CONTROL-EVIDENCE.md).
Successful local prototype compilation alone is not the full certificate;
landing requires the source-matched two-driver replay, cold full gate and
bounded review receipts.

The bound is conservative. At `qr = qs = 65536`, exact rational evaluation gives
approximately `8.7695861e-15` overall (about `2^-46.70`), with coverage alone
approximately `1.3619301e-25` (about `2^-82.60`). The broad public-query budget
and birthday terms dominate. These are upper bounds on game probability, not
attack costs, lower bounds, or a claim of deployed 96-bit security. For large
caps the expression can exceed one and is then uninformative.

The accumulated-coverage and numerical-composition proof gaps in this manual
classical model are closed by these theorems. Tightening the charges, proving
concrete SHA-256 assumptions, QROM security, mechanically extracting the model
from Rust, and making a deployment security-level claim remain outside this
result. The earlier conditional MM45 capstone and its explicit residuals are
unchanged. See [RESEARCH-LIMITS.md](RESEARCH-LIMITS.md) for the specific remaining
quantitative, concrete-hash, quantum and Rust correspondence obligations.
Replay optimization #789 and the owner-triggered assurance pass #509 remain deferred.
