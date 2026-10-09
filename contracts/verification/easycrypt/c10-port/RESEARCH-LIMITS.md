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

The WOTS recovery caller is now connected to the verifier specification in
[`WotsRecoveryBridge.lean`](../../extracted/Extracted/WotsRecoveryBridge.lean).
The actual extracted chain walk agrees whenever `start + steps ≤ u32::MAX`,
including zero steps. Endpoint compression preserves each padded node
and its position for all lists of at most 43 nodes. For every seed, position,
16-byte message, 43-node signature and full `u32` counter, the extracted
`pk_from_sig` result equals the verifier's recovered node, with `none` mapped
to Rust's zero sentinel. A separate audited equation preserves the exact
sum-205 branch: an accepted zero-valued hash remains `some zero`, whereas a
rejected sum produces `none`. No converse from a zero Rust result to rejection
is assumed. This is a component value/outcome relation, not a proof that the
full Rust verifier handles that sentinel identically to the on-chain verifier.

Four added headline results are kernel-only, bringing the default extracted
closure audit to 86 with the same 27 environment axioms. Fifteen additional
copied verifier declarations are checked for semantic drift and deletion.
The default differential gate executes the production Rust module files in a
host test crate, under normal and extraction configurations, against an
independent preimage/chain reference and committed Lean vectors. The 20
recovery cases include accepted and rejected messages at counter boundaries
through `u32::MAX`; 40 chain cases include carry and zero-step boundaries,
and four compression cases include empty and full lists. Both extracted and
verifier computations must agree, including the explicit rejection outcome.
Fourteen well-typed changes to chain order, compression and recovery semantics
must break the unchanged universal proofs. No production Rust, hash backend,
cryptographic assumption or EasyCrypt game is changed by this bridge.

The XMSS authentication-path component is connected in
[`MerkleRecoveryBridge.lean`](../../extracted/Extracted/MerkleRecoveryBridge.lean).
The actual extracted pair hash preserves all four 32-byte preimage segments.
For every seed, layer, tree, leaf, full `u32` index and nine-node path, the
extracted recovery agrees with the verifier's nine-level computation. This
preserves sibling order, parity selection, successive parent indices, height
fields and the tree address domain. Out-of-range leaf indices are included as
computations; agreement does not assert membership in a 512-leaf subtree.

The two additional kernel-only headlines bring the default closure audit to
88 with the same 27 environment axioms. Five copied declarations have fidelity
and deletion controls. The default execution corpus covers all 512 nine-bit
branch patterns, 16 full-width boundary cases and six pair-hash cases, under
both normal and extraction Rust configurations and both Lean computations.
Fifteen well-typed semantic mutations must break the unchanged proofs.
Fresh Merkle extraction also checks the complete generated interface; its old
external-template pin was corrected only for an eight-line source-comment
shift, with the declaration unchanged. This component retains the supplied
SHA backend boundary and does not prove tree construction, membership
soundness or the complete verifier/session relation.

The FORS single-tree component is connected in
[`ForsRecoveryBridge.lean`](../../extracted/Extracted/ForsRecoveryBridge.lean).
The actual private `reconstruct_fors_root` helper is newly extracted without
changing production Rust. It hashes the secret with the leaf address, then
folds all eleven siblings. The functional result and verifier correspondence
cover every represented seed, `u32` hypertree position, tree and leaf index,
secret and eleven-node path. Position widening, the FORS address domain,
initial leaf index, sibling order and parent/height fields are preserved.
As with XMSS, out-of-range indices remain computation claims.

Two more kernel-only headlines bring the default closure audit to 90, with
unchanged environment assumptions. Three copied definitions have fidelity and
deletion controls. A test-only crate embeds the complete production helper
module unchanged and appends a child test, giving private-function access
without a production API or source change. Both Rust configurations and both
Lean computations agree on all 2,048 branch patterns and 16 full-width cases.
The gate rejects 4,128 changed outputs and seven malformed inputs, plus 23
well-typed semantic mutations: nine in the Rust-derived functions and fourteen
in verifier recovery/address definitions. Fresh generation checks the complete
new extraction interface. Full thirteen-root/forced-zero composition, tree
construction, membership, backend correctness and signer/session refinement
remain open.

The FORS forest stage now adds
[`ForsPkSpec.lean`](../../extracted/Extracted/ForsPkSpec.lean),
[`ForsForestSpec.lean`](../../extracted/Extracted/ForsForestSpec.lean) and
[`ForsRejectSpec.lean`](../../extracted/Extracted/ForsRejectSpec.lean).
The actual `compute_fors_pk` and complete `hypertree::verify` bodies are
freshly extracted, with existing proved dependency implementations and no
new opaque assumptions. The compression theorem preserves all thirteen
roots in order, their padding, domain 4 and the full `u32` position. The
actual verifier's twelve-root loop agrees pointwise with the verifier's
single-tree computation for every represented input and preserves slot 12.
The whole Rust verifier is proved to return false whenever its actual
H_msg digest's final FORS field is nonzero, including the signature's first
sixteen bytes as the randomizer. This is a refusal theorem; it makes no
claim about the accepting branch.

Four additional kernel-only headlines bring the default closure audit to
94; the environment inventory remains 27 axioms. Complete-output generation
checks both new extraction interfaces. Three copied definitions have edit
and deletion controls. Normal and `lean_extract` Rust, extracted execution
and verifier computations agree on 32 forest/compression cases and 16 actual
whole-verifier refusals. The cases include full-width positions/indices and
distinct secrets/paths for each tree. The gate also rejects 480 changed
outputs, 16 changed digest fields, ten malformed inputs and 18 well-typed
semantic mutations (fourteen Rust-derived and four verifier/address), with
five positive proof baselines. Production Rust is unchanged.

The FORS prefix continuation (2026-10-09) closes that forest/caller gap.
[`ForsParseSpec.lean`](../../extracted/Extracted/ForsParseSpec.lean) proves the
actual signature parsers read all thirteen secrets from bytes 16–223 and all
12×11 authentication nodes from bytes 224–2335, retaining exact order and
ending at offset 2,336. The special last leaf uses tree 12, height/index zero,
the decoded HT position and secret 12. It fills root slot 12 before compression.
[`ForsPrefixSpec.lean`](../../extracted/Extracted/ForsPrefixSpec.lean) composes
those calls with the faithful complete `Fors.reconstructForsPk` definition.
[`ForsVerifierPrefix.lean`](../../extracted/Extracted/ForsVerifierPrefix.lean)
then proves the **actual full verifier** equals its unchanged WOTS/XMSS
continuation with that public key on every signature whose final FORS digest
field is zero. The theorem preserves the continuation's `Result`, including
failure/divergence; it neither assumes totality nor proves acceptance of the
remaining layers. The earlier nonzero-field refusal theorem covers the other
branch. No production Rust behavior changes.

Four new kernel-only headlines bring the default audit to 98; the environment
inventory stays at 27 axioms. Both copied complete-FORS declarations have
semantic-edit and deletion fidelity controls. The execution corpus runs the
whole production verifier in normal and `lean_extract` configurations, its
extracted counterpart, the exact prefix/continuation split and the faithful
FORS computation on 22 cases: four accepting KAT signatures, two negative KATs,
and sixteen synthetic signatures that pass the forced-zero check. It checks
all parsed bytes and offsets and rejects 132 value mutations, 44 incorrect
output widths and seven malformed inputs. Five positive proof baselines accompany
23 well-typed semantic controls
for parser sources/destinations/offsets, the actual last-leaf/compression/handoff
calls and verifier-side reconstruction. These controls supplement universal
proofs; the corpus alone is not a full verifier refinement.

The WOTS/XMSS continuation (2026-10-09) closes its computation and totality
obligations. [`HypertreeParseSpec.lean`](../../extracted/Extracted/HypertreeParseSpec.lean)
proves both actual layer parsers and all four big-endian counter bytes. Each
layer consumes 43 chain nodes, four counter bytes and nine siblings, exactly
836 bytes. [`HypertreeLayerSpec.lean`](../../extracted/Extracted/HypertreeLayerSpec.lean)
proves the actual body preserves the layer/tree/leaf addresses, shifts the tree
index by nine bits and hands the recovered node to the next layer.
[`HypertreeContinuationSpec.lean`](../../extracted/Extracted/HypertreeContinuationSpec.lean)
proves the actual two-iteration loop terminates, finishes at offset 4,008 and
returns the final root comparison. These results cover every represented
32-bit index, every 4,008-byte signature and every full-width wire counter.

The executable specification deliberately preserves Rust's invalid-WOTS
zero-node fallback and subsequent XMSS computation. It does not identify a
zero node with rejection. [`HypertreeStrictSpec.lean`](../../extracted/Extracted/HypertreeStrictSpec.lean)
separately proves that **when** the faithful strict `verifyHypertree` returns
`some expected`, the actual continuation returns exactly the comparison of
`expected` with the public root. Its `none` branch is not claimed equivalent
to the Rust continuation. No production behavior changes, added assumptions
or unconditional strict-acceptance equivalence are hidden in this relation.

Eight kernel-only headlines brought that batch to **106**; the exact
environment inventory remains **27** axioms. Four copied hypertree declarations
have semantic-edit and deletion fidelity controls. Fifty execution vectors
cover the actual parsers, extracted continuation, raw computation model and
strict specification. Forty-two also execute the unchanged whole production
verifier (the prior 22 cases plus ten counter boundaries in each layer); eight
additional cases cover index boundaries through `u32::MAX`. Both normal and
`lean_extract` Rust configurations check the same vectors. Successful strict
reconstruction and rejection at either WOTS layer are exercised. Controls
reject 350 altered values, 50 wrong output widths and eight malformed inputs.
Six positive proof baselines accompany 29 compiling semantic mutations across
the parsers, counter order/high byte, addresses, node/index handoffs, loop entry,
terminal comparison and strict reconstruction. The earlier prefix receipt now
separates value changes from output-width rejection (#815).

The complete signature-deserializer relation is now proved (2026-10-09).
[`SignatureDecodeSpec.lean`](../../extracted/Extracted/SignatureDecodeSpec.lean)
proves that the faithful byte decoder returns exactly the actual parser's
randomizer, all FORS secrets and siblings, both WOTS signatures and full counters,
and both XMSS paths. The sixteen-byte load proof includes the final node at
byte 3,992, whose thirty-two-byte intermediate load extends past the signature.
No padding/default branch replaces an in-range signature byte.

[`WholeVerifierSpec.lean`](../../extracted/Extracted/WholeVerifierSpec.lean)
composes the existing actual-verifier proofs into an **unconditional** totality
and computation theorem for every represented seed, root, message and 4,008-byte
signature. Its raw model preserves the actual invalid-WOTS zero-node fallback.
The faithful strict byte entry point is separately bound to its complete decoder,
H_msg construction and parsed fields. **Strict byte-verifier acceptance implies
Rust acceptance**; this is the completeness direction, not the security-soundness
converse. When strict reconstruction returns a root, the complete Boolean
result agrees, including a final root mismatch. A nonzero final FORS field
forces both verifiers to refuse. Rust acceptance implying strict acceptance
remains open because of the deliberate rejection/zero-node distinction.

Eight additional kernel-only headlines brought that batch to **114**, with
the same exact **27** environment axioms. Sixteen copied top-verifier/decoder
and byte-load declarations have semantic-edit and deletion fidelity controls.
Forty-eight vectors execute the unchanged whole production Rust verifier and an
independent SHA-byte oracle in normal and `lean_extract` configurations: all
twelve published KATs, sixteen synthetic forced-zero signatures and twenty
counter-boundary cases. The extracted Lean check executes the complete decoder,
actual verifier, raw model and faithful strict byte verifier on those inputs,
with 288 altered-value, 48 output-width and seven malformed-input controls.
Six positive proof baselines accompany 21 compiling semantic mutations covering
byte loads, full counters, parser offsets, header binding and verifier decisions.
The control scripts and original signature specification are enrolled in the
per-push/per-PR workflow paths, with path-deletion regression controls (#817).

Tree construction/membership, concrete hash backends, randomness and full
signer/session refinement remain open. EasyCrypt proof inputs and numerical
bounds are unchanged.

WOTS public-key generation (2026-10-09) now has an actual extraction and
unconditional correspondence theorem. `WotsSecretSpec` proves the exact 80-byte
secret preimage: 32-byte secret seed, `"wots"`, four-byte layer, full 64-bit tree
right-aligned in a 32-byte word, four-byte keypair and four-byte chain index,
followed by 16-byte truncation. `WotsSecretBridge` connects it to the faithful
`wotsSecret`. `WotsKeygenSpec` proves termination and all 43 positional chain
endpoints, each starting at zero and advancing seven steps, followed by ordered
compression in the WOTS-public-key address domain. `WotsKeygenBridge` composes
these with the faithful `Wots.keygenPk` for every input seed and address.

The only production change routes `hash::wots_secret` through the existing
`sha256_parts` helper. Its six updates preserve order and lengths
`[32,4,4,32,4,4]`; the supplied SHA backend model is unchanged. This small refactor
avoids an unsupported generic-Digest extraction path in the pinned translator.
Normal, `lean_extract`, software and host hardware-adapter builds compare all
195 secret cases against independent preimage assembly. The adapter cases check
the exact six update segments, without claiming peripheral correctness. Another
195 normal/extraction Rust cases compare actual `keygen_pk` to an independent
address/secret/chain/compression oracle. Both Lean execution suites compare the
actual extraction, pure result and faithful reference, each with 390 changed
output-byte and 195 output-width controls, plus six/seven malformed-input cases.

Six additional kernel-only headlines bring the audit to **120**, with the same
**27** environment axioms. Both new extractions and all six existing targets
sharing `hash.rs` have complete-output regeneration checks; the registry has
24 entries, 23 fresh and the unchanged, explicitly waived tx-merkle entry.
Four new copied definitions have semantic-edit and deletion fidelity controls.
Seven positive proof baselines accompany 28 typed semantic mutation controls.
The new controls and KAT JSON input are enrolled in the shared push/PR paths;
removing any new path from either event fails a regression control (#819).

Release `thumbv8m.main-none-eabi`, `hw-sha256` crate comparison measures 44 fewer
code bytes, unchanged rodata/data/bss, and an eight-byte compiler-frame increase
in `wots::keygen_pk` and `hypertree::sign_inner`. This is a bounded crate/frame
delta, not a whole-program worst-case-stack or silicon receipt. The manual
Rust/EasyCrypt source binding and split identity are deliberately updated;
the EasyCrypt proof sources, assumption census and numerical bounds are unchanged.
Tree construction/membership, FORS secret generation (#820), shuffled signing,
concrete hash backends, randomness and full signer/session refinement remain open.

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
