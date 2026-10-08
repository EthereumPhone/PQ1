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

The repository's extracted hash wrappers call a manually supplied
`hash.sha256_bytes` definition in `Extracted/Hash/FunsExternal.lean`. That wrapper
uses executable `sha256_pure`; it does not mechanically extract RustCrypto's
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
refinements between them. For this repository, the next bounded component is
H_msg input construction and digest-field decoding, followed by the bounded
signer/session relation. An opaque hash definition remains an explicit
backend boundary even when the surrounding refinement is axiom-free.

Replay optimization #789 and the combined owner-triggered assurance pass #509
remain separate deferred work. None of the research above grants shipment or
hardware authority.
