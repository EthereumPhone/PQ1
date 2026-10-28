# Original portable SHA-256 byte/block correspondence

This isolated Lean 4.35 profile proves the original selected `sha2 0.10.9`
`soft.rs::compress` body against the existing SHA-256 compression specification:

```lean
theorem Sha256Portable.Bytes.original_compress_spec
    (state : HashState) (blocks : Slice Block) :
    (do let st ← sha256_portable.soft.compress state blocks; ok (toWords st)) =
      ok (foldBlocks blocks.val (toWords state))
```

`HashState` is eight u32 words; `Block` is 64 bytes. `foldBlocks` applies the
unchanged specification's big-endian byte decoding and word compression in
input order. The theorem quantifies over every representable state and block
slice, including empty input, without a success or termination premise.
The inner-loop proof also covers arbitrary initial scratch words.

This is a **frozen, source-bound experimental extraction**, with the compiler
and library-model trust boundary below. It does not verify full `Digest`
streaming, padding, message-length encoding, dispatch, accelerated or STM32
backends, callbacks, or SHA-256's cryptographic security. Those remain tracked
in [#1067](https://github.com/EthereumPhone/PQ1/issues/1067) and
[#1070](https://github.com/EthereumPhone/PQ1/issues/1070). It does not replace
the existing Lean 4.30 extracted project or the EasyCrypt gate.

## Replay

Linux x86_64, Python 3.11+, git and `leanprover/lean4:v4.35.0` are required.
From this directory, with that toolchain on PATH:

```sh
python3 verify.py --source-only
python3 test_gate.py -v
python3 prepare.py /absolute/new/path/aeneas
python3 verify.py \
  --backend /absolute/new/path/aeneas/backends/lean \
  --lean "$(elan which lean)" \
  --output /absolute/new/path/replay
python3 test_proofs.py /absolute/new/path/replay
```

`prepare.py` checks out the exact Aeneas revision in `profile.json`, validates
all 275 backend sources, retrieves only the imported mathlib cache closure,
and builds the upstream Lean backend. The upstream manifest pins all nine
packages. It does not install the experimental extractor patch. A prepared
dependency directory can be reused: `verify.py` authenticates the backend
sources, package commits and clean tracked sources, Lean executable and
version, and records the actual compiled dependency artifacts. Compiled
dependencies, including the mathlib distribution cache, remain trusted inputs;
their receipt is not represented as a fresh kernel replay of those libraries.
`--backend-cache` can select a separate already-built backend cache, whose
artifact inventory is recorded with the same explicit trust boundary.

The replay requires a **new output directory outside the profile**, fixes
`LEAN_PATH`, and freshly compiles all 16 local modules in dependency order.
It checks all 98 named closures (12 model, 46 word, 40 byte/block theorems),
allowing only `propext`, `Classical.choice`, and `Quot.sound`. Missing or
duplicate results and unexpected axioms fail. `result.json` records identities,
commands, times, artifacts and closure results; `logs/` retains compiler output.
The GitHub workflow runs the same commands and retains these small receipts,
without uploading dependency caches or generated proof binaries.

`test_gate.py` checks frozen-source drift, Cargo selection, specification drift,
additional modules, structural/whole-input guard failures and missing/duplicate/
unapproved axiom results. `test_proofs.py` reruns the unchanged final proof as
a positive control and requires semantic proof rejection when its conclusion
skips the first block or reverses block order. Setup errors and timeouts do not
count as successful negative controls.

## Extraction and model boundary

`frozen/input.llbc` is the original complete successful Charon extraction
(`has_errors=false`). It embeds the original Rust sources. The normal replay
checks them byte-for-byte against the existing Cargo/vendor source gate, which
authenticates C10's dependency selection and the crate checksum. The LLBC also
contains its original absolute paths and extraction options; reserializing or
re-extracting it is **not** silently accepted as equivalent.

`profile_guard.py` binds the complete LLBC digest and the mapped declarations
and use sites in all transparent bodies: 16 functions and 14 mapped sites.
The final whole-input digest also binds Charon's shared type graph and foreign
signatures. This guard accepts exactly one snapshot; it is not a general type
resolver or an authorization to use this model for other iterator combinations.
`verify.py` makes the guard mandatory before replay. The complete raw generated
`Input/Types.lean` and `Input/Funs.lean` are pinned, with no handwritten body edits.

The source compiler is Aeneas `399081f237935f9aa805f2d4a51fd3784aea11a9`, with
its Charon pin `2ec7e964e1032c59220e726840a9ac7d7684be2f` and Rust commit
`923c95cdf5ba65cea505aa2ea829f578e1506ed8`. `frozen/compiler.patch` records
three borrow-processing corrections and the concrete mutable-Zip mappings.
The patched executable's SHA-256 is pinned in `profile.json`; it was used to
emit this snapshot, and is not installed by this profile.

The corrections use the actual visited abstraction depth, restrict the frozen
loan check to fixed abstractions, and allow an endable deepest sub-abstraction
with no remaining loans to end through the existing synthesis continuation.
The patch also maps this concrete `IterMut<u32>`/`ChunksExact<u8>` Zip to
`MutableZipModel.lean`. The model follows the pinned standard library's
`TrustedRandomAccess` branch: Zip keeps its own index/length and the backward
continuation writes the selected word back. The Lean model has proved
constructor, progress, update and frame facts. Its correspondence to Rust's
pointer/layout implementation is an **explicit TCB assumption**, as are
Charon/Aeneas translation and their other standard-library models. A clean
axiom census does not prove compiler or model soundness.

The original experiment additionally checked four upstream borrow fixtures
against both compiler variants (identical emissions), three universal input
preservation contracts, two invalid borrow programs rejected at their intended
source errors, a valid lifetime-loop control, three model mutations, and 16
profile-guard rejection cases. One upstream `verify::test` fixture needed
unsplit emission on both variants because split output placed its guard before
the definition; no source was edited to obtain the pass. These are bounded
regressions, not the whole upstream suite or a compiler-correctness proof.

The earlier evidence and artifact digests are recorded in
[#1067: model/extraction](https://github.com/EthereumPhone/PQ1/issues/1067#issuecomment-6473289052)
and [#1067: universal byte/block theorem](https://github.com/EthereumPhone/PQ1/issues/1067#issuecomment-6474598319).
`profile.json` pins the B1/B2/B3 receipt digests. These prior receipts support
the frozen extraction; the commands above replay its Lean proofs, not the
compiler regression campaign or a new Charon extraction.
