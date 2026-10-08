# Remaining cryptographic and implementation limits

Research checkpoint: 2026-10-08, following the initialized classical byte-game
bound in [RAW-NUMERICAL-EUF.md](RAW-NUMERICAL-EUF.md). This page separates
possible next proofs from assumptions that cannot be removed by changing a
status label. Work remains tracked under PQ1 #100 and #295.

## Quantitative loss

The canonical-witness continuation removes redundant assignment choices from
the adaptive FORS coverage union. At `qr = qs = 65536` its coverage charge is
about `2^-93.29`, down from `2^-82.60`. The complete bound remains about
`2^-46.70`: public-node and WOTS-encoding birthday terms dominate. These are
upper probability bounds, not attack costs or a deployed security rating.

Two distinct next obligations remain:

- Count only canonical surjections and distinct witness positions. A candidate
  sharper coefficient is `n * (n-1)_j * S(12,j)`, with a falling factorial and
  Stirling number of the second kind, instead of `n^(j+1) * j! * j^(12-j)`.
  This requires another event-preserving enumeration proof; it is not the
  enrolled bound.
- Replace the global all-pairs collision event with the target collisions
  actually sufficient for successful verification, or prove a tail charge for
  a smaller effective hash budget. Substituting average grinding work for the
  proved worst-case budget is invalid. Honest-but-private intermediate values,
  repeated calls, failed signing and adaptive oracle queries must be covered.

The [formally verified SPHINCS+ reduction](https://eprint.iacr.org/2024/910)
provides a modular approach to tighter component reductions. Its construction
and premises must still be instantiated for C10's checksum-free encoding,
finite grinder, root-as-secret FORS case and shared byte oracle. Its title does
not establish those correspondences.

## Concrete SHA-256

There are two different obligations here. **Functional correctness** means the
chosen backend computes the specified SHA-256 digest. **Cryptographic security**
means the relevant keyed/tweaked uses resist suitably bounded adversaries.
Neither follows from the other.

The current EasyCrypt result samples an ideal full-digest oracle. It does not
prove that SHA-256 behaves that way. In particular, the model permits arbitrary
local computation and charges explicit oracle calls; instantiating a public
algorithm requires accounting for adversaries that compute it locally. A
meaningful concrete theorem needs a computational resource model and explicit
primitive security assumptions, or separate C10 reductions to precisely stated
hash properties. A premise saying the concrete game already has the desired
success bound would only restate the goal.

The [random-oracle methodology paper](https://arxiv.org/abs/cs/0010019) shows why
an ideal-oracle proof alone is not a generic security guarantee for concrete
hash instantiations. This does not show C10 insecure; it explains why the
instantiation step remains an obligation.

The repository's extracted hash wrappers call manually supplied
`hash.sha256_bytes` and streaming `hash.sha256_parts` definitions in `Extracted/Hash/FunsExternal.lean`. These wrappers
use executable `sha256_pure`; it does not mechanically extract RustCrypto's
SHA-256 implementation or the STM32 hardware driver. CAVP/test-vector agreement
and absence of project axioms do not close either backend correspondence.

## Quantum oracle access

`ByteClientOracle.hash` accepts one classical byte list and returns one digest.
The memo table and accepted-sample proofs observe those calls. They do not
represent a superposition query or justify observing a quantum query without
disturbing the adversary. Replacing `q` by `q^2`, or halving a quoted bit count,
is not a proof transfer.

The [SPHINCS+C paper, Appendix E](https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/sphincs-plus-c-pqc2022.pdf)
analyzes a quantum-accessible tweakable hash with classical challenge queries
and a reprogramming argument. That is relevant research, but its interfaces,
public-parameter timing, grinding and challenge restrictions need an exact
mapping to C10. No such QROM mapping is enrolled here.

A concrete next milestone is a quantum game specification with classical
signing, explicit quantum hash-query accounting, finite grinding failure and
one proved reprogramming/search hop. [qRHL-tool](https://dominique-unruh.github.io/qrhl-tool/)
provides a quantum relational logic and an Isabelle-backed implementation;
its existence does not supply a C10 proof. This is a separate proof-development
track, not an EasyCrypt checker option.

## Rust correspondence

Existing Aeneas extractions and Lean refinements cover useful components,
including address construction, FORS index extraction, WOTS digits, Merkle
recovery, WOTS recovery and several hash-input wrappers. The extraction
registry binds selected source and generated files, with separate generator
replay. These results should be reused, not described as if no extraction
existed.

The digest-field version bridge now closes the HT/FORS decoder portion of
[#288](https://github.com/EthereumPhone/PQ1/issues/288):
[`ForsSpecBridge.lean`](../../extracted/Extracted/ForsSpecBridge.lean) proves
the extracted Rust decoder results equal the verifier's vendored
`Util/Bits.lean` definitions for every 32-byte digest. It covers the 18-bit
HT field and all thirteen 11-bit FORS fields, including the last field,
without assuming that its forced-zero test succeeds. The byte conversion
preserves order and values; the four audited bridge results use only Lean's
kernel axioms. The exact copied definitions and their parameters are checked
by the vendored-fidelity gate. Rust-executed differential vectors complement
that theorem but do not prove the Aeneas translation sound. This is a bridge
to the verifier's Lean specification, not yet to the EasyCrypt game and not
a proof that every signer/recovery call uses the decoded position correctly.

The H_msg input-construction component is now proved in
[`HMsgSpecBridge.lean`](../../extracted/Extracted/HMsgSpecBridge.lean): for every
four 32-byte inputs, the extracted Rust caller returns the full digest of
`seed || root || R || message || FF[32]`, equal to the fidelity-checked
verifier H_msg definition after the byte conversion. The implementation streams
five slices through `sha256_parts`, avoiding a 160-byte concatenation buffer.
The supplied Lean backend hashes the concatenation; equivalence of that backend
to RustCrypto or STM32 remains open. The two new results have kernel-only
closures and join the default extracted gate. Seven copied declarations have
semantic drift and deletion controls, and six input-construction mutations
must fail the universal proof. A 132-case Rust/extracted/verifier corpus checks
every input-byte position; changes in either half of the output are rejected.
The default differential gate, including CI, executes both the software-backed
Rust H_msg and the hardware adapter with host hooks, requiring their outputs to
match the committed corpus without rewriting it. The hooks also check all five
update calls and their bytes; they do not exercise the peripheral. `GEN=1`
regenerates the corpus before these checks.

The WOTS digest/digit components are now joined in
[`WotsSpecBridge.lean`](../../extracted/Extracted/WotsSpecBridge.lean).
For every three input words and every `u32` count, the extracted hash caller
agrees with the verifier's `wotsDigest`, including its 28 zero padding bytes,
big-endian counter and full digest. This covers counts outside the signer's
10-million-trial range too. For every digest, all 43 extracted digits, their
complete array and their sum equal the verifier's bit-loop definitions; no
accepted-sum premise is imposed. Four added results have kernel-only closures.
The default gate executes 140 Rust hash cases and 262 Rust digit cases, checks
both extracted and verifier outputs, and rejects altered expectations and
malformed inputs. Seven copied definitions have fidelity drift/deletion
controls; ten semantic changes must break the universal bridge proofs.
These results do not establish the Rust grinder's stopping/failure behavior
or that every recovery/signing caller consumes these components correctly.

The bounded WOTS search is now covered separately by
[`FindCountSpec.lean`](../../extracted/Extracted/FindCountSpec.lean).
The actual Rust `find_count` body is extracted with an explicit counter and
indexed sum; its sum loop is definitionally the already-proved verifier loop.
For every input, the unconditional theorem gives exactly two outcomes: the
first count in `0..10_000_000` with digit sum 205, together with its complete
digest and all 43 digits, or failure because every count in that interval is
rejected. Charon reconstructs the terminal Rust panic as `assertionFailure`;
the proof excludes a successful value and divergence on that path. Separate
first-success and exhaustion results complete the three new kernel-only
headlines. No success-probability or independent-trials premise is added.

The default differential gate executes the actual Rust search against an
independent real-SHA reference, plus hardware-adapter host hooks forcing first,
progress-boundary, last-permitted and full-exhaustion cases. Controlled outputs
with sums 204 and 206 must be rejected; a success must return all of the actual
count, digest and digits. The controlled cases also run under `lean_extract`.
Eight altered executable definitions must typecheck and then fail the unchanged
proofs. Fresh generator replay checks the complete new extraction and the
affected older modules. The release ARM crate has unchanged section sizes and
all 26 frame annotations; this is not a final firmware or whole-program stack
bound. The supplied SHA backend and erased progress callbacks remain explicit
boundaries: arbitrary production callbacks are not proved to return or to
preserve behavior, and the host hooks do not exercise STM32 silicon.

The actual FORS `grind_r` search is now covered by
[`GrindRSpec.lean`](../../extracted/Extracted/GrindRSpec.lean). For both `None`
and `Some(opt_rand)`, its extracted body constructs exactly
`sk_seed || "R_grind" || [opt_rand] || message || zero[28] || nonce_be32`,
truncates SHA-256 to the first 16 bytes, and computes the full H_msg digest
using the padded public seed, root and randomizer. The acceptance test is
exactly digest bits 132 through 142 being zero. Three kernel-only headlines
prove the first accepted nonce in `0..10_000_000`, failure after every nonce
in that interval rejects, and an unconditional disjunction of those outcomes.
The terminal Rust panic again maps to `assertionFailure` in the extraction.
The default gate now checks 82 headline closures with the unchanged
27 environment axioms.

The source uses the existing streaming SHA boundary and an explicit counter;
the deterministic path still omits the OptRand update entirely. Default
controls execute independent real-SHA reference searches and controlled
hardware-adapter hooks in normal and `lean_extract` configurations. They
check every update's bytes and length, ascending nonces, first success,
byte-carry boundaries, the last permitted nonce, exhaustion and complete
returned values in both randomness modes. Twelve typed changes to executable
definitions must break the unchanged proofs. Generator replay covers both
the new search and the existing FORS decoder. ARM crate code is six bytes
smaller with unchanged data sections and all 26 frame annotations; this is
not final firmware or whole-program stack evidence. SHA backend correctness,
cryptographic hardness and caller-provided randomness freshness remain open;
these functional results assume neither independent trials nor eventual
success. They do not establish the EasyCrypt random-oracle game relation.

The outstanding bridge is a compositional relation between the current Rust
keygen/sign/verify implementation and the EasyCrypt byte game. It must cover
fixed-width arithmetic, byte/bit order, the full wire counter, bounded search,
all error returns, caller-supplied randomness, hash backends and session
semantics. Source hashes and differential examples detect drift but do not
prove that relation for all inputs. No automatic Aeneas-to-EasyCrypt bridge is
part of the current certificate.

The [Aeneas cryptographic verification guide](https://github.com/AeneasVerif/aeneas/blob/main/documentation/crypto-verification.md)
and [SymCrypt technical report](https://arxiv.org/abs/2609.15648) support a
staged approach: extracted code, mathematical specifications and proved
refinements between them. The digest-field, H_msg input-construction and WOTS digest/digit components
are now bridged to the verifier specification. Bounded WOTS and FORS searches
have functional success/failure proofs; their connection to the EasyCrypt
games and the complete signer/session relation remain open. An opaque hash definition remains an explicit
backend boundary even when the surrounding refinement is axiom-free.

Replay optimization #789 and the combined owner-triggered assurance pass #509
remain separate deferred work. None of the research above grants shipment or
hardware authority.
