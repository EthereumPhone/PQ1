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
Tree construction/membership, shuffled signing, concrete hash backends,
randomness and full signer/session refinement remain open. FORS secret generation
is covered by the next result below.

FORS secret generation (2026-10-09) closes the reference mismatch in #820.
`Spec.forsSecret` and all reference signer/round-trip callers now include the
hypertree position, matching the existing Rust preimage:
`sk_seed[32] || "fors"[4] || BE32(ht_idx) || BE32(tree_idx) || BE32(leaf_idx)`.
The reference signer and its honest round-trip theorem rebuild with this field.
This correction does not establish refinement of the actual Rust signer.

`ForsSecretSpec.fors_secret_spec` proves the actual extracted helper returns the
first 16 bytes of the existing supplied SHA backend on exactly those 48 bytes;
`ForsSecretBridge.firmware_fors_secret_matches_vendored` composes that result with
the faithfully copied corrected helper for every seed and all three full-width
32-bit fields. Rust uses the existing ordered SHA helper for the same five
updates. Concrete software/peripheral hash correctness remains outside the proof.

Three new kernel-only headlines bring the extracted closure audit to **123**,
with the same exact **27** environment axioms. The new extraction and all eight
existing targets pinning the changed Rust file regenerate completely. The
registry contains 25 entries: 24 fresh and the unchanged tracked `tx-merkle`
waiver. Both copied FORS declarations have mutation and deletion fidelity controls.

An independent 48-byte oracle checks 131 Rust cases covering every seed byte,
every bit of hypertree/tree/leaf indices, zero, maximum and mixed fields. The
same corpus runs in normal/extraction software and host hardware-adapter builds;
the latter checks all five update segments `[32,4,4,4,4]`, without exercising a
peripheral. Extracted/pure/reference executions match it. Controls reject 262
altered output values, 131 wrong widths and five malformed inputs. Two fresh
positive proof baselines pass; 13 independently compiling semantic mutations of
the actual and reference helper fail their unchanged consuming proofs.

The release ARM crate comparison measured 120 additional code bytes, unchanged
static data and an eight-byte smaller `sign_inner` compiler frame. These are
crate/frame measurements, not a whole-program stack or silicon claim. The Rust
source binding changes, so this batch requires a new complete EasyCrypt replay;
its proof definitions, axioms, numerical bounds and cryptographic assumptions
are unchanged. FORS tree construction/membership, shuffled signing, randomness,
concrete hash backends and full signer/session refinement remain open.

FORS tree construction (2026-10-09) closes the root-building helper and the
reference final-slot mismatch in #823. `ForsRootSpec.fors_compute_root_spec`
proves termination, stack/index safety, all leaf derivations, ordered pair
hashes and the exact height-11 result of the actual extracted
`compute_fors_root`, for every pair of 32-byte seeds and all full-width
hypertree/tree indices. A finite schedule certificate checks all 2,048 leaf
positions and 12 possible heights using Lean's kernel (`decide +kernel`);
it contains only indices/heights. The loop invariant separately proves every
stack value equals the corresponding recursive hash node. No output-equality
premise, native-code proof axiom or new hash/tree assumption is introduced.

`ForsRootBridge.firmware_fors_root_matches_vendored` composes this with the
faithfully copied recursive `forsMtNode`. The new reference
`Signer.forsSigningValue` emits ordinary secrets in the first twelve slots and
the complete root in slot twelve, matching Rust's existing construction.
`firmware_fors_final_slot_matches_vendored` proves that root agrees with this
final-slot helper. The reference honest-signature round-trip theorem still
holds; that theorem alone would also have accepted the old leaf-secret rule,
so it was not evidence of generation correspondence.

Five new kernel-only headlines bring the extracted closure audit to **128**,
with the same exact **27** environment axioms. The complete root extraction is
registered and regenerates, giving 26 entries: 25 fresh and the unchanged
tracked `tx-merkle` waiver. Both copied definitions have semantic-edit and
declaration-deletion fidelity controls. Three fresh proof baselines and 19
independently compiling mutations cover leaf count/start, secret inputs,
address fields, carry condition, parent height/index, child order, stack
writes, returned root and the reference tree/final-slot rules.

The independent recursive Rust byte oracle checks 21 roots against the actual
stack implementation in normal and extraction builds, including zero, maximum,
mixed/full-width addresses, the final-slot tree and seed-byte changes. The
actual extraction, pure tree and faithful reference execute against that corpus;
42 altered values, 21 wrong widths and six malformed inputs are rejected.
Every root differs from the old leaf-zero-secret rule. Two actual signing
cases independently decode the digest position, check the forced-zero gate and
compare the emitted final slot with the recursive root before verifying the
signature. These are executable caller checks, not a proof of `sign_inner`.

Production Rust is unchanged in this batch. The completed 1,998-check EasyCrypt
replay for proof identity `27015a144ca3e10d6a96b4375c3e29e8` is reusable after exact
proof-input and manual source-binding comparisons; no new numerical or
cryptographic claim follows from reuse. FORS authentication-path generation,
hypertree key-generation trees, shuffled signing, randomness, concrete hash
backends and the complete Rust/EasyCrypt signer/session relation remain open.

FORS authentication-path generation (2026-10-09) now closes the actual
`sign_fors_tree` helper. `ForsAuthSpec.fors_sign_tree_spec` proves totality,
the exact derived secret and each of the eleven canonical sibling nodes for
all pairs of 32-byte seeds, all full-width hypertree/tree indices and every
leaf below 2,048. The valid-leaf bound is explicit; this theorem does not
advertise a membership claim for arbitrary 32-bit out-of-range leaves.

The proof reuses the root frontier/value invariant and tracks every path slot
whose parent merge has completed. The actual shifts, XOR sibling selection,
left/right comparisons, array writes and ordered hashes preserve that
invariant; completion establishes every slot. Two finite geometry certificates
use `decide +kernel` over leaf/height and traversal/height indices only. They
contain no hash values and add no native-code assumption.
`ForsAuthBridge.firmware_fors_auth_matches_vendored` relates the actual helper
to the faithfully copied `sibIdx`/`forsMtAuthPath` definitions consumed by the
reference signer, plus the existing faithful secret derivation. This proves
the generated subtree values directly; it does not assume the desired path.

Five added headlines bring the closure audit to **133**, retaining the exact
**27** environment axioms. Complete authentication-path extraction is registered
and regenerates: 27 entries, 26 fresh and the unchanged `tx-merkle` waiver.
The two copied definitions have semantic-edit and deletion fidelity controls.
Two positive proof baselines and 24 typed semantic controls cover traversal,
secret/address binding, merge geometry and ordering, sibling selection,
capture/update/return behavior and the copied path rules. Each changed body
must compile before its unchanged consuming proof is required to reject it;
name/parse errors, timeouts and exhausted proof resources do not count.

An independently assembled recursive Rust byte oracle checks 23 boundary cases
and all 2,048 leaves of one additional tree, including all 22,528 siblings and
secret values. Own-node substitutions discriminate from the expected siblings.
Both normal and extraction builds select both Rust tests. The actual Lean
extraction, pure recursive nodes and faithful reference execute on the 23-case
corpus. Controls reject 552 altered values, 46 wrong path lengths, 276 wrong
widths and eight malformed input shapes/ranges. All new scripts and the Rust
oracle are enrolled in default gates and blocking push/PR path coverage.

Production Rust and EasyCrypt proof inputs are unchanged. The completed
1,998-check replay remains reusable only after exact input/source-binding
comparison. This component theorem does not yet compose actual signer control
flow, serialization, the twelve-tree forest or recovery into a whole-signer
result. Hypertree key-generation trees, shuffled signing, randomness, concrete
hash backends and the complete Rust/EasyCrypt signer/session relation remain
open. No new cryptographic probability or hardware claim follows.

FORS signing/recovery composition (2026-10-09) now connects the actual
per-tree helpers. `ForsRoundtripSpec.fors_auth_recovery_root` proves that
folding the generated secret and eleven canonical siblings reaches the
height-11 root. Its intermediate invariant tracks the exact ancestor node,
index and ordered children at every level. It uses the existing kernel-checked
sibling geometry and adds no hash-collision or desired-root assumption.
`firmware_fors_sign_recover_root` composes the total extracted signing,
recovery and root-construction results: for every pair of seeds, full-width
hypertree/tree index and leaf below 2,048, recovery of the generated secret
and path equals the actual constructed root. A second actual-call headline
relates the recovered value to the faithful reference tree. The only input
precondition is the explicit valid-leaf bound.

Three added headlines bring the audit to **136**, with the same **27**
environment axioms. The independent Rust recursive oracle now supplies roots
for all 23 authentication-path cases; the Lean corpus compares actual signing,
recovery and construction against those roots. It retains the prior value,
shape and malformed-input controls and adds 46 altered-root controls, 552
executed altered-secret/path recoveries and 23 wrong-leaf recoveries. These
concrete unequal-output checks are corpus evidence, not a universal
collision-freedom theorem. A test child of the unchanged private Rust module
also checks all 2,048 leaves, 22,528 changed siblings and six full-width
positions, in both normal and extraction configurations. Seven typed fold
mutations exercise parity, child order, missing sibling, parent height/index,
next index and discarded merge; normal proof-error termination is required,
and resource or malformed-definition failures do not count.

Production Rust and extraction registration are unchanged. No new EasyCrypt
proof input or source binding is introduced. This result closes per-tree
membership and the signing/recovery connection; the actual shuffled forest
loop, serialization, special final-slot composition, hypertree key-generation
trees and complete Rust/EasyCrypt signer/session relation remain separate.
Concrete backends, randomness, resources and hardware remain outside this
component result.

XMSS key-generation tree construction (2026-10-09) is now connected in
`XmssRootSpec` and `XmssRootBridge`. The actual iterative `compute_subtree_root`
processes all 512 WOTS public keys, preserves the exact stack frontier and
ordered parent hashes, and returns the recursive height-nine root. The proof
covers every seed, full-width 32-bit layer and 64-bit tree, and all byte-valued
progress ranges. The actual `compute_pk_root` wrapper pads its sixteen-byte
public seed and selects layer one, tree zero; its output equals the faithful
recursive reference over the already-proved WOTS key-generation function.
No desired-root premise or new hash assumption is introduced.

Six additional kernel-only headlines bring the default audit to **142**, with
the same **27** environment axioms. A finite index/height schedule certificate
is checked by the kernel; symbolic hash values remain in the structural proof.
The new extraction is regenerated completely, including Types and external
interfaces; this checkpoint brought the registry to 28 entries, 27 fresh and the unchanged,
explicitly waived tx-merkle entry. Existing WOTS/hash bodies and the identical
progress-sink definition are reused, without new opaque assumptions.

Eight normal and extraction Rust cases compare actual roots with an independent
recursive byte oracle, including full-width addresses, zero/max seeds and
progress-range boundaries. The normal configuration also checks all 32 progress
reports per subtree and the public progress wrapper's root. Both actual entries
(public root and a full-width subtree) execute in Lean against those Rust roots
and the faithful recursive reference. The public-root case also executes the
internal pure tree; the full-width case's duplicate pure evaluation is allocated
to the actual authentication builder below, keeping six full-tree evaluations
across the two corpora. Universal pure-tree correspondence covers both cases.
Four changed values, two
wrong output widths and eleven malformed test inputs are rejected. These
bounded examples complement the universal proofs. Two positive proof baselines
and 23 compiling semantic mutations exercise leaf counts, seeds and addresses,
merge order, parent fields, stack slots and the public-root wrapper. The copied
recursive tree definition has strict semantic-drift and deletion controls;
resource/abnormal exits do not count as valid mutation rejection. All new gates
and script paths are enrolled in blocking push/PR coverage.

Production Rust and EasyCrypt proof inputs are unchanged. As elsewhere, formal
totality applies to the callback-free `lean_extract` shape; arbitrary callback
execution and its effects are outside that theorem. The normal/extraction
corpus is empirical correspondence evidence, not a universal callback proof.
The actual shuffled forest/signer loop, serialization and special final-slot
composition remain open, along with concrete backends, randomness and the
complete Rust/EasyCrypt signer/session relation. No hardware or shipment claim
follows from this component result.

XMSS authentication-path generation and membership (2026-10-09) are now
connected in `XmssAuthSpec`, `XmssAuthBridge` and `XmssAuthRecovery`. For every
seed, full-width layer/tree address, byte-valued progress range and target leaf
below 512, the actual `build_subtree_with_auth` returns the reference height-nine
root and all nine siblings from the faithful `mtAuthPath`. The carry invariant
tracks each capture flag in both directions and binds every captured value;
all flags are ready before the final copy loop, making its panic unreachable
on this domain. No desired-path or desired-root premise is imposed.

The actual builder, WOTS public-key leaf, authentication recovery and independent
root builder compose into a membership theorem. Seven added headlines bring
the default audit to **149**, with the same **27** environment axioms. Three
new headlines are kernel-only; the four consuming the actual builder also
reference the existing Aeneas `core.fmt.Formatter : Type` axiom through the
debug-panic formatting branch. That branch is proved unreachable for valid
leaves, but the syntactic type dependency is explicitly pinned in their exact
closures. This is not a proof of Rust formatting or panic-message behavior;
the environment inventory is unchanged. The regenerated extraction, normalized Types and imported external
interfaces are enrolled together: 29 registry entries, 28 fresh and the existing
tx-merkle waiver. The shared Rust-file metadata and checker-owned binding cover
the new entry too. Production Rust and EasyCrypt proof inputs are unchanged.

Twenty normal and extraction Rust cases compare the path, root and WOTS leaf
with an independent recursive SHA byte oracle, including leaf boundaries and
full-width addresses. Normal execution checks every progress transcript.
The Rust corpus also executes 180 altered-sibling, 20 altered-leaf and 20
wrong-index recoveries. One full-width extracted path build runs in Lean,
checking all nine siblings, the root, WOTS leaf and recovered root against
the independent corpus. It rejects 22 altered values, 16 malformed output
shapes and ten malformed inputs; 21 executed changed-value/wrong-index
recoveries must return a different root. These unequal-output examples are
empirical controls, not a universal collision-freedom theorem.

Three positive proof baselines and 37 typed semantic mutations cover leaf
generation, capture flags and indices, child order, copy-loop behavior, copied
path shape and recovery folding. Each mutated definition must compile before
its unchanged consuming proof fails. Resource, malformed-definition and
abnormal exits do not count. The copied path declaration has semantic-drift
and deletion controls; the default gate and blocking push/PR paths run all
new checks. The callback-free extraction boundary remains explicit. This does
not itself prove WOTS signature construction (now covered below), the shuffled
forest/signer loop, serialized signature production or the full Rust/EasyCrypt
signer/session relation.

Shuffled WOTS signature construction (2026-10-09) is now connected in
`ShuffleSpec`, `WotsSignSpec`, `WotsSignRecovery` and `WotsSignBridge`.
For every seed and prefix length at most 64, the actual Fisher–Yates function
terminates, preserves exactly the prefix permutation and leaves its tail zero.
The signer theorem consumes that result directly. For every input, the actual
`sign_with_shuffle` either returns the first accepted count below its ten-million
bound with all 43 chains in their specified positions, or fails with every
candidate rejected. Successful signatures recover the public key computed by
actual `keygen_pk` and agree position by position with the faithful reference
secret, digest, address and chain definitions. Any two shuffle seeds give the
same result, including bounded failure. Neither a desired permutation nor a
desired signature is a premise of these headlines.

Seven added kernel-only headlines bring the default audit to **156**:
143 kernel-only, four retaining the existing opaque `Formatter` type, four
SHA-256, one SHA-256/HMAC and four Keccak closures. The environment still has
**27** axioms. The registry now contains **31** entries: 30 fresh and the existing
tx-merkle waiver. Exact generation covers both new modules, normalized Types
and imported external interfaces. No axiom or native proof tactic was added.

The private Rust shuffle SHA-block computation was factored without changing
its RustCrypto backend, domain prefix, seed/counter encoding or caller
zeroization. Its extraction boundary uses the existing executable SHA-256
model; zeroization follows the existing total/discarded-result model. These
are explicit backend and physical-erasure limits. Before/after Rust outputs
agree on 2,535 seed/length cases in each normal/extraction mode. A separate
72-case Rust/Lean corpus checks exact SHA-derived order and zero tails; the
permutation theorem alone deliberately makes no exact-order or randomness
claim. The signer corpus checks 24 signatures across six full-width address
and first-count cases, both zero and seven digits, and 258 altered-chain
recoveries. Three cases run the actual extracted signer, recovery and keygen
in Lean, including alternative shuffle seeds and malformed inputs.
Two positive proof baselines and 20 typed semantic changes exercise shuffle
initialization, reduction, swaps, signer addressing, count, chain, iteration
and positional output. Each changed definition must compile before its
unchanged consuming proof fails; resource or abnormal failures do not count.
All new checks are part of the ordinary extraction/differential gates.

A required host-emulator tail check also has explicit evidence limits: it uses
a gate mirror, fixed keys/randomness and one message, not a production image
or silicon. Every changed literal-success output must now undergo actual
unfaulted verification; baseline failure, verifier errors and ambiguous key
artifacts cannot become successful rejection evidence. Crashes, hangs and
noncanonical returns remain separately reported. This is sampled integration
evidence, not full-body fault resistance, DPA resistance or shipment authority.

The callback-free extraction boundary remains. This closes the WOTS signing
component. The shuffled FORS forest is covered below; the whole hypertree signer and
session relation, backend correctness, entropy freshness and physical leakage remain open.

Shuffled FORS forest construction (2026-10-10) now covers the actual
`sign_inner_loop0` extracted from the unchanged `hypertree.rs`. For every seed,
full-width hypertree index and twelve valid leaf indices, the loop fills all
natural positions despite shuffled scheduling. The complete forest phase
computes the special tree-12 root, transmits that root, and hashes it once at
the correct address for the thirteenth compression slot. The final digest
index is not read by this phase. The resulting thirteen secrets and twelve
paths agree with the faithful reference, recover the same public key through
the actual verifier forest, and do not depend on the shuffle seed.

`SignForestFactor` proves exact equality between the actual caller and its
header, forest phase and unchanged suffix. `firmware_sign_fors_prefix` then
replaces the forest with its specified values unconditionally: no successful
search or desired-output premise is assumed, and failures/divergence remain
in the header and suffix. This does not prove whole-signer success or the
serialization/hypertree suffix. Six additional headlines bring the default
audit to **162**: 148 kernel-only, five with the existing opaque `Formatter`
type, four SHA-256, one SHA-256/HMAC and four Keccak closures. The environment
remains at **27** axioms. The registry contains **32** entries: 31 fresh plus
the existing tx-merkle waiver. Generated panic-string size witnesses are
explicit kernel proofs; Aeneas's default native witness is not admitted.

The explicit `ShuffleSeed.derive` boundary models the existing zero-seed fast
path and exact SHA-256 domain/seed/label bytes. Its backend correspondence is
empirical; the forest theorem requires only its totality and the proved
permutation property. Fifteen independent derivation cases cover zero and
nonzero seeds, empty/FORS/binary labels and a 256-byte label. In both normal
and extraction configurations, six actual whole Rust signatures over two
messages and three shuffle seeds agree byte for byte. Every transmitted
secret and sibling agrees with an independently assembled, recursively
hashed oracle. A separate full-width component case exercises leaf endpoints
and an unrestricted final index. Two Lean cases execute the actual forest,
recovery and compression; all 290 one-byte changes to transmitted secrets or
siblings yield different recovered keys. Malformed input shapes and altered
expected outputs are rejected. Three positive proof baselines and fifteen
typed semantic changes cover positional writes, iteration, final-slot
construction and the actual caller connection. Each changed definition must
compile before a normal proof error counts as rejection. These checks and
exact extraction regeneration are enrolled in the ordinary gates.

Production Rust is unchanged by this batch. Callback, concrete hash backend,
erasure, entropy and physical leakage limits remain. The forest component
adds no full signer/session, cryptographic reduction or shipment claim.

Signature serialization (2026-10-10) now has universal byte-level contracts
for the actual extracted sixteen-byte writer and all secret, FORS-path,
WOTS-chain and XMSS-path loops. Each contract specifies both the bytes written
and preservation outside the destination range. The thirteen secrets and
twelve eleven-node paths occupy bytes 16 through 2,335, preserving the nonce
and remaining suffix. The existing decoders recover every supplied field.
An unconditional equality replaces that forest serialization in the actual
signer suffix while preserving all later failures and divergence.

Each 836-byte layer consists of 43 sixteen-byte chains, all four big-endian
counter bytes and nine sixteen-byte siblings. For every in-range starting
offset, the extracted loops and literal counter-write fragment terminate with
that exact layout and offset. The computed subtree height is proved to be nine.
At each of the two wire positions, decoding recovers the original chains,
full-width counter and path. A kernel equality factors that serializer from
the actual layer body without changing its cryptographic calls or Result
behavior. These serialization contracts are composed with the cryptographic
components in the two-layer result below. The nonce-generation/header bridge
and complete session relation remain separate work.

The thirteen serialization headlines are included in the default audit total
reported below. The environment remains
at 27 axioms and the extraction registry is unchanged. The caller equality
uses a continuation argument to keep kernel checking small; no kernel check,
axiom audit or mutation acceptance condition is bypassed.

Eight independent concatenation cases execute the unchanged inline production
fragments in both Rust configurations and the extracted Lean writers. They
cover unaligned starts, both layer positions, the final buffer boundary and
counters from zero through 0xffffffff, including upper-byte changes. Every
output byte is compared, including the unchanged frame. Malformed corpus
inputs, changed expected bytes and a one-byte-overrun write must be rejected.
Nine positive proof baselines and twelve independently typechecked semantic
mutations check ranges, order, iteration counts, field selection and both
caller connections. Resource failures do not count as semantic rejections.
These checks run in the ordinary differential gate. Production Rust and
extraction artifacts are unchanged; backend, callback, erasure, entropy,
physical leakage, full signer/session and research-reduction limits remain.

Actual two-layer signing (2026-10-10) now has an unconditional Result equality
from the extracted signer loop to two pure layer operations. Each operation
uses the first accepted bounded WOTS count, the canonical positional chains
and nine independently specified XMSS siblings. The equality preserves bounded
search failure; it does not assume that either grinder succeeds. It retains
the full input index and the actual layer/tree/leaf arithmetic, writes at
2,336 and 3,172, and finishes at byte 4,008. On success the nonce/FORS prefix is
unchanged and the returned node is the top tree root; for an 18-bit input index
that tree is zero. A further unconditional equality connects forest
serialization, FORS compression, both actual layers and the existing final
root check to the real post-FORS caller. Matching the computed root passes
that check. The whole-signer extension below composes the nonce/header and
earlier FORS caller with this result.

This two-layer batch added nine audited headlines, bringing its total to **184**:
161 kernel-only, fourteen retaining the existing opaque Formatter type, four
SHA-256, one SHA-256/HMAC and four Keccak closures. The environment remains
at 27 axioms. No production Rust, extraction artifact or registry changes are
needed for this composition.

Three full-byte cases compare the unchanged production two-layer fragment with
an independent recursive byte/preimage oracle in normal and extraction Rust,
covering the maximum 18-bit and full-u32 indices and 0xfffffffe, first accepted counts, top
roots and shuffle independence. The extracted Lean loop executes the full-u32
case with distinct lower/upper leaves (510/511) and compares every signature
byte, root, offset and count, with eighteen
altered-output, four output-shape and eight malformed-input controls. The
fixtures deterministically select counts below 64 to keep routine execution
bounded; the universal proof retains the production ten-million-count limit
and failure behavior. Five positive proof baselines and fourteen separately
typechecked semantic mutations test crypto selection, byte offsets, actual
body/loop arithmetic and the final caller check. Resource and syntax failures
are not accepted as semantic rejections. These checks are enrolled in the
ordinary differential gate. Callback, backend, entropy, erasure, physical and
complete Rust/EasyCrypt session boundaries remain unchanged.

Actual nonce/header and whole signing (2026-10-10) now have an unconditional
functional Result relation from the real `sign_inner` entry point to a pure
composition. The nonce model selects the first accepted count below ten million,
in both OptRand modes, and retains the extracted assertion failure on exhaustion.
The actual header writes exactly the 16 nonce bytes into a zeroed 4,008-byte
buffer, pads the public seed, extracts all thirteen 11-bit FORS fields and the
18-bit hypertree field, and establishes the final FORS field is zero on success.
The composition connects that header to the canonical forest, its serialization,
FORS compression, both first-count signer layers and the unchanged final root
check. It does not assume grinder success or bypass a root mismatch. Shuffle
seed changes preserve the complete returned Result. A successful whole signature
retains the first accepted nonce bytes and its supplied public root equals the
independently constructed layer-one, tree-zero key-generation root.

Twelve additional audited headlines bring the current default total to **196**:
169 kernel-only, eighteen with the existing opaque Formatter type, four SHA-256,
one SHA-256/HMAC and four Keccak closures. The 27-axiom environment is unchanged.
Two header fixtures use independent Rust nonce-preimage and digest-window
oracles, with first counts zero and seven and both OptRand modes. Normal and
extraction Rust execute the unchanged production header fragment; Lean executes
the actual extracted header and grinder. Every output byte, digest, padded seed,
index and offset is checked, with 34 altered-output, eight expected-shape and
sixteen malformed-input controls. Four positive proof baselines and twelve
separately typechecked mutations check nonce inputs, exhaustion, digest windows,
header writes and whole-signer composition. Syntax/resource failures never count
as semantic rejection. The header checks and mixed-leaf two-layer case run in
the ordinary differential gate. Production Rust and extraction artifacts remain
unchanged. This closes the functional nonce/header and whole-signer composition
slice, not the cross-language EasyCrypt simulation or session relation; backend,
callback, entropy, erasure, physical and cryptographic reduction limits remain.

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
