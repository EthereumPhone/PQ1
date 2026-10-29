# SHA-256 padding: frozen corrected-dependency experiment

This research profile preserves symbolic evidence for the original
`block-buffer 0.10.4` eager padding implementation, with a separately identified
correction to `generic-array 0.14.7` and an experimental Kani compiler. It is a
component of [#1067](https://github.com/EthereumPhone/PQ1/issues/1067).

For every 64-byte initial buffer, every valid position `0..63` and every supplied
`u64` bit length, the two positive harnesses check:

- one block for positions `0..55`, two for `56..63`;
- every emitted byte: unchanged prefix, `0x80`, zero fill and big-endian length;
- reset of the buffer position to zero.

The length is an arbitrary **supplied value**. No theorem here connects it to
the total number of bytes received by `Digest::update`. The independent byte
specification uses shifts, while the implementation uses `to_be_bytes`.
The unwind bound is 65; default, uninitialized-memory, valid-value and unwinding
checks remain enabled. All four relevant boundary/length covers are reached.
Each positive run reports 641 properties, including six covers; unreachable
properties remain explicit and are not described as successful safety checks.

The wrong-endian mutation fails only the unchanged first-block byte assertion.
The wrong-threshold mutation fails only the unchanged block-count assertion.
Its later position-55 cover is unsatisfiable because that assertion already
rejects the path; the positive baseline reaches position 55. Setup failure,
unsupported checks, a different failing assertion or timeout do not count as
successful negative controls.

## What changed, and what remains open

`frozen/lib.rs` is byte-identical to the accepted harness, retaining its original
line numbers. Its comment about an unmodified dependency refers to
**block-buffer**; **generic-array is modified**. The latter's `generate` writes
each element through a raw pointer before creating a reference, and advances
the initialized prefix after the write. `ArrayBuilder::drop` destroys only that
prefix through raw pointers. Public signatures and successful output order are
unchanged. `prepare.py` reconstructs the exact corrected file, including its
CRLF line endings. Other constructors and the public unsafe `iter_position`
method are outside this correction.

The original dependency forms a reference over uninitialized storage. The
retained Kani reference-formation check and experimental recursive Miri reject
that construction; default Miri does not. This is an explicit model/validity
boundary, not a settled claim about every interpretation of Rust. **This result
does not verify the original dependency pin.**

The compiler patch adds nested `MaybeUninit` storage classification, explicit
local/argument/return initialization-state transfers, ordinary addressed-return
read checking, and byte-copy shadow-state corrections. Unsupported layouts,
opaque closures, overlapping aggregate transfers, indirect/foreign endpoints
and cleanup unwinding retain refusals. Rust/compiler/model soundness and
general reference lifetime/alias semantics remain trusted boundaries.

The actual `sha256_bytes` / `sha256_parts` force-soft caller census was regenerated
on the pinned production sources: 44 emitted records, 40 in the root crate,
byte-identical to the preceding census, with no newly reached constructor.
Sixteen one-shot and 48 streaming cases match independently generated hashlib
vectors both natively and under experimental recursive Miri. These are finite
compatibility checks. They do not prove universal dependency equivalence,
panic/unwind equivalence, ARM dispatch or complete `Digest` execution.

Streaming updates, length accumulation, full caller composition, hardware and
accelerated backends, callbacks, cross-tool refinement and cryptographic
security remain open. This profile changes neither production Cargo dependencies
nor the default EasyCrypt, Aeneas, Lean or Kani installations.

## Check the preserved evidence

Python 3.12+, GNU patch and git are sufficient for input/evidence checks:

```sh
python3 verify.py
python3 test_gate.py -v
python3 prepare.py /absolute/new/path/padding-inputs
```

`verify.py` authenticates every frozen file, the production source pins and the
complete selected C10 lockfile closure. Unrelated lockfile packages do not
invalidate that binding, including dependency-name disambiguation caused by
adding another unselected package version. Edges use resolved package identities.
It rechecks the compressed original logs against
their execution receipts, compiler/harness identities, exact property census,
intended assertion locations, failure sets and covers. It **does not rerun a
solver**, authenticate a historical host or prove that the verifier is sound.
The CI workflow is explicitly an evidence/source check, not a new proof replay.
Recorded manifests, lockfiles, corrected dependency and mutant source identities
are also compared with the packaged inputs; updating a patch and its checksum
cannot reuse proof logs for the previous dependency. Every archived crate is
bound to the selected consumer checksum and each recorded registry lock entry.

Compiler consistency combines recorded evidence with explicit build trust.
The gate compares the 12 individually recorded changed compiler/library sources
and one unchanged upstream source with their source pins. It also checks the
complete 51-file changed-source inventory and patch against a retained
coordinator reconstruction receipt, and ties the recorded upstream build's
commit, tree and binaries to this profile. That reconstruction was performed
against the private checkout; CI checks its receipt, not a fresh patch application
or compiler rebuild. Two additional changed compiler sources were not separately
inventoried in the original per-run receipts. The linked C model and runtime
libraries likewise were not all inventoried by those per-run receipts; their
separate runtime and source comparisons remain recorded evidence, not a
retroactive execution inventory or a proof of source-to-binary correspondence.

`prepare.py` checks the four archived crate checksums, reconstructs the original
and corrected dependencies and both mutants, and emits isolated Cargo projects
with offline directory sources. The small archives include their original
licenses. Prepared input validation reconstructs the expected bytes again;
editing a generated `prepared.json` cannot bless changed source. It rejects
additional build scripts and source files. Targets and proof output belong in
separate directories.

## Fresh replay with the retained runtime

`frozen/kani.patch` applies to upstream Kani
`744b3e84d6eb68fd5456826997568666791bd355`. It contains the compiler, library and
test changes from private candidate `2a5a39e9c07e330b411e653331ef98582a729fcc`;
historical experiment documents are excluded. `frozen/kani-sources.json`
records the resulting changed-file hashes. The compiler uses
`nightly-2026-10-23-x86_64-unknown-linux-gnu`. To reconstruct source in a clean
disposable clone at that baseline:

```sh
git apply /absolute/path/to/sha256-padding/frozen/kani.patch
cargo build-dev --locked
```

This source recipe does not promise a byte-reproducible binary. The replay
entrypoint deliberately accepts only the **retained experimental binaries**,
runtime libraries, linked `kani_lib.c` model source and tools identified in
`frozen/kani-runtime.json` and
`frozen/external-runtime.json`. Those binaries are not distributed in this
directory. A newly rebuilt compiler requires its own evidence and reviewed
profile renewal; changing a binary checksum is not a successful replay.
The retained driver embeds an absolute Cargo path for metadata queries. Replay
therefore requires the original Rustup home recorded in the receipts and
`external-runtime.json`, and hashes the Cargo binary at that location. Copying
identical tools into a different Rustup home is refused; relocation requires a
rebuild and reviewed evidence renewal. The operating system, ordinary system
libraries, and host C preprocessor/headers used by `goto-cc` remain trusted
execution inputs.

With those retained tools available, set the paths below to their existing
locations and use a new output directory inside the allocation budget root:

```sh
python3 replay.py \
  --prepared "$PADDING_INPUTS" \
  --kani-root "$PADDING_KANI_TREE" \
  --rustup-home "$PADDING_RUSTUP_HOME" \
  --rustup "$PADDING_RUSTUP_BINARY" \
  --solver-bin "$PADDING_SOLVER_BIN" \
  --compat-libs "$PADDING_COMPAT_LIBS" \
  --case single-block \
  --output "$PADDING_BUDGET_ROOT/new-single-block-run" \
  --budget-root "$PADDING_BUDGET_ROOT"
```

Repeat for `two-blocks`, `wrong-endian` and `wrong-threshold`, each with a new
output directory. Independent cases may run concurrently; each has its own
working directory, Cargo home and target. Do not run the same case concurrently
against the same prepared directory because Kani writes a diagnostic graph in
its working directory. Prepared paths are canonicalized before containment and
ancestor Cargo-configuration checks and execution. Solver commands resolve
through a private directory of links to the authenticated executables; adjacent tools in a Rustup or Kani
directory cannot take precedence. Resolution and runtime identities are checked
before and after execution. `--check-only` validates source and runtime without
execution; `--codegen-only` exercises compilation without claiming a proof.
Each run has a 1,800-second active-time bound and a 6,144 MiB allocation cap over
the supplied budget root. Linux monotonic time excludes laptop suspension.
Raw output and terminal results survive failure. The negative cases require
exit 1 and their exact intended failed assertion; the script's own successful
exit means that acceptance predicate passed.

## Earlier compiler and consumer gates

The frozen receipts retain the current candidate's full pinned Linux CPROVER
regression stages, format/copyright/Clippy checks, 1,628 accepted regression
cases (including 22 expected failures in the separate fixme mode), 327 unit/doc
tests, 44 exact-read controls and 17 auxiliary/refusal controls. Source-declared
ignores remain explicit. This is not an all-platform, LLBC or general compiler
correctness claim. Full gate logs remain in the research archive; the small
aggregate receipt here preserves their identities, not their complete contents.

The caller refresh's three commands passed. Its original collector then compared
44 total records with a prior count of 40 root-crate records. The retained
consumer receipt documents that bookkeeping failure and its scoped completion
using exact census/output identity, without relabelling the failed collector
or rerunning the successful commands.

The original proof-run dependency inventory recorded generic-array's `src/lib.rs`.
The other package files were compared byte-for-byte with the reconstructed
archives during publication; that is a present-day correspondence check, not
a retroactive complete run-time inventory. Fresh replay checks every prepared
input before and after execution.

The original private implementation review and the broader gate milestone are
recorded on [#1067](https://github.com/EthereumPhone/PQ1/issues/1067).
Their recommendations apply to their named snapshots and stages. They do not
substitute for this profile's merge review or authorize production adoption.
