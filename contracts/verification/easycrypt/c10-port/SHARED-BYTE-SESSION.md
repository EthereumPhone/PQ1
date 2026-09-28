# Costed shared-oracle byte session

This research milestone supplies a manually transcribed, adaptive C10 signing
experiment over one persistent classical raw-input oracle. It proves query
budgets, a byte/structured game equivalence, and a secret-prefix game hop.
**The independent-oracle forgery probability remains unbounded. This is not a
numerical EUF-CMA security theorem or a replacement for the existing conditional
SPHINCS+C reductions.** Issues #100 and #295 retain that frontier.

## Model and checked contracts

`RealGame(ByteContext(A))` samples one uniform 256-bit secret. Key generation,
FORS and WOTS private derivations, secret-prefixed R generation, H_msg, chain and
tree hashing, and shuffle hashing share the same raw oracle. Repeated inputs
reuse recorded answers. Counters charge physical calls, including cached ones;
fresh draws are separate. The adversary can query arbitrary public raw inputs
and adaptively request signatures up to explicit nonnegative caps `qr` and `qs`.
The public seed is supplied independently of the newly sampled secret.

`RawKeygen`, `RawFors`, `RawForest`, `RawWots`, `RawMerkle`, `RawLayer` and
`RawSigner` spell out the computation. They include the special final FORS tree,
43 checksum-free radix-8 chains, target sum 205, both hypertree layers, and the
actual shuffle labels and hashing. Search inspects counters 0 through 9,999,999;
verification accepts the full u32 counter field. `node` is totalized on arbitrary
oracle outputs and agrees with the deployed truncation on 256-bit outputs.

A signing exhaustion sets a sticky failure flag. Further signing requests return
no signature and make no oracle calls; the final forgery check rejects a failed
session. `FullFailure` proves these boundaries. `None` and dummy capped replies
are experiment devices, not a recoverable firmware panic interface. Only
successful signing requests enter the signed-message list. The final test
requires a new 32-byte message and a correctly sized byte signature.

`RawSignerWidths.physical_signature_bytes` proves successful signatures serialize
to 4008 bytes from a valid initial oracle history. `RawDecode` proves that every
4,008-byte input parses to the exact node/layer widths and u32 counter range;
parsing and re-encoding arbitrary valid byte values preserves every byte.
`ByteSession.byte_context_equiv` connects the byte-facing experiment to the
structured one, preserving the result and oracle/session state. This is an
EasyCrypt model equivalence, not Rust extraction.

Let `B = 10,000,000`. The checked worst-case budgets are:

| Operation | Physical oracle calls | Public calls in the prefix hybrid |
|---|---:|---:|
| Key generation |177151|155135|
| Complete signing attempt |4B+435646|3B+364892|
| Verification |771|771|
| Keygen, bounded adaptive session, final verification |177151+qr+qs(4B+435646)+771|155135+qr+qs(3B+364892)+771|

`FullPrefix` proves these session budgets from the actual modeled loops, rather
than assuming a reduction query budget. Let `qpub` be the last right-hand entry.
`ByteBound.byte_physical_to_independent` proves, for the same admissible client,

```
Pr[RealGame(ByteContext(A)) wins]
  <= Pr[IndependentGame(ByteContext(A)) wins] + qpub / 2^256.
```

The hop uses a fresh uniform secret and excludes adversarial access to private
oracle/session globals. It retains explicit oracle-relative termination and
cap premises. The independent game still keeps public and private histories
across the entire session. It separates secret-prefixed inputs from public
queries; it does not declare all algorithm roles mutually independent.

`SessionClosedForm.raw_session_exhaustion_explicit` separately bounds any R-grind
exhaustion in a keygen-plus-grinding session. With `q=155135+qr+qs*B`, its bound is

```
qs * ((1 - 2^-11)^B + (B*q + B*(B-1)/2)*2^-128) + q*2^-256.
```

That experiment exposes R grinding, not complete signatures. The cached-H_msg
term and adaptive/repeated-context accounting are explicit. This availability
result is not a forgery bound; it does not account for WOTS exhaustion as though
it were an independently fresh IID search.

## Correspondence evidence and remaining work

`tools/fullsign_model/check.py` compares an executable manual transcription with
the actual Rust crate on five deterministic public test keys: 20 complete
4008-byte signatures (absent/present OptRand, zero/nonzero shuffle seed), plus 160
altered signatures/messages. It compares every signature byte, verification
outcome and physical hash-call count. Software shuffle SHA calls are counted
separately from Rust's hardware-hook counter and included in the total. These
fixtures support manual correspondence; they prove neither extraction nor all
Rust executions. They also do not emulate hardware SHA or fault behavior.

The full split gate executes that comparison with locked Cargo dependencies,
then replays every proof target with both EasyCrypt drivers in the pinned cold
container. Statement/source identities, assumption census, semantic controls and
headline isolation are enrolled with the new files. No new project axiom,
admit or generic clone assumption was added. Individual focused replay is not
the full-gate receipt; the landing receipt records the exact reviewed snapshot.

Still open: connect this complete adaptive byte game to the appropriate C10
cryptographic reductions and bound the remaining independent-game forgery
probability with actual reduction costs. The legacy uncosted pure-function ITSR
countermodel still matters. No KDF-entropy, quantum-random-oracle or real-SHA-256
independence theorem is claimed, and these results do not establish deployed
96-bit security or production readiness.

Run the whole mandatory profile from the repository root:

```
make -C contracts/verification verify-easycrypt-split
```

For the correspondence fixture alone, choose a new output directory outside
the repository:

```
python3 -I contracts/verification/easycrypt/c10-port/tools/fullsign_model/check.py --out /tmp/pq-fullsign-evidence
```
