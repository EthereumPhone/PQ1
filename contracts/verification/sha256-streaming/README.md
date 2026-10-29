# Original initialized streaming-step component

This research profile preserves a bounded symbolic proof of the original
`block-buffer 0.10.4` eager `digest_blocks` method with original
`generic-array 0.14.7`. It advances the streaming component of
[#1067](https://github.com/EthereumPhone/PQ1/issues/1067); it does not close the
complete Rust `Digest` correspondence obligation.

For arbitrary initial buffer bytes, every initial position `0..63`, every input
length `0..192`, arbitrary input bytes and an arbitrary valid byte index, the
unchanged method satisfies:

- emitted bytes are the complete 64-byte blocks of the buffered prefix followed
  by the input, in exactly that order;
- the residual position and bytes are the remaining suffix;
- callbacks receive nonempty block slices, occur at most twice, and occur
  exactly when at least one complete block is available;
- the adjacent eight-byte prefix and suffix objects remain unchanged.

The single-byte observer is universally quantified over the concatenated
sequence. It checks the selected emitted byte exactly once, or the selected
residual byte. Empty input with an empty buffer remains a separate included
case. Length, position, callback-count and frame assertions are unconditional.
The callback observes the blocks; it does not compute or stub a hash result.

The entry object is fully initialized through `zeroed` followed by the public
`set` operation and a `Copy` of the initial byte array. The pinned private
representation contains a byte position, byte-array leaves and zero-sized
markers, so zero is a valid entry value independently of field offsets.
**This does not execute or prove the original default/generate constructor.**
It does not resolve the partially initialized reference boundary documented
in the [separate padding profile](../sha256-padding/README.md).

## Evidence and limits

The positive symbolic run has 866 properties: 850 successful checks, ten
unreachable checks and six generated covers. All 13 semantic assertions pass.
Five source cases are reachable: empty, buffered-empty, no compression, exact
fill and three blocks with a residual. Optimized MIR duplicates the
no-compression cover: one generated branch supplies literal `false`. Its
unsatisfiable result is recorded in `frozen/cover-audit.json`, bound to the
complete compressed MIR and an extracted function body. It is not counted as
a sixth source case or as successful coverage.

The wrong-remainder source mutation fails only `byte == expected`; the
lost-residual mutation fails only `residual == total % 64`. The latter also
makes the subsequent three-block/residual cover unsatisfiable. All other
semantic assertions pass, and neither control is credited for a setup,
unsupported-operation, memory-safety or timeout failure.

The unwind bound is 257. Default safety checks, uninitialized-memory checking,
valid-value checking and unwinding assertions remain enabled. No stubs or loop
contracts are used. Proof times were approximately six minutes per case.

The independent finite full-trace oracle compared 12,352 position/length cases
and 1,574,881 byte probes. Experimental recursive Miri checked 50 sparse cases
and 255 probes. Both native source mutants failed the indexed observer itself.
Their original sources, receipts and logs are retained; these finite checks
are complementary evidence, not the universal symbolic proof.

The compiler, model, source-to-binary build and host execution remain trusted.
The exact experimental Kani runtime and upstream regression receipts are shared
with [sha256-padding](../sha256-padding/README.md), whose model/refusal and
reconstruction limitations still apply. That shared runtime does **not** imply
that this profile uses the padding profile's corrected dependency: preparation
here uses the original archived generic-array bytes throughout.

Inputs longer than 192 bytes, unbounded update histories, accumulated bit length,
SHA computation, arbitrary callback behavior, full Rust alias/provenance
semantics, cross-tool refinement, dispatch and the complete `Digest` API remain
open. No cryptographic, hardware or side-channel security result follows.
Production dependencies and installed verification tools are unchanged.

## Check or reconstruct the evidence

From this directory, with Python 3.12+ and GNU patch:

```sh
python3 streaming.py
python3 test_streaming.py -v
python3 prepare_streaming.py /absolute/new/path/streaming-inputs
```

The first command checks frozen identities, the selected C10 source/dependency
binding, recorded commands/runtime inventories, raw logs, all property names,
semantic assertion locations, exact failures and coverage. CI runs these three
commands. **They do not execute a solver or authenticate the historical host.**
The gate tests reject missing or unreachable assertions, unintended failures,
false coverage, timeouts, changed tool inventories, source drift and forged
prepared inventories. Reconstructing the expected files independently prevents
editing `prepared.json` from blessing a changed dependency or new build script.

The source authentication receipt inventories the recorded source files, not
every historical Cargo-cache file. The original positive run reused its exact
code-generation target after checking source and runtime identities. Fresh
replay uses a new Cargo home and target with offline reconstructed inputs.
Reusing the recorded evidence does not convert it into a fresh compilation.

## Fresh replay

Use the retained binaries and paths described by the padding profile. No tool
is installed or substituted; a newly built or relocated runtime needs reviewed
evidence renewal. The original Rustup home is required by the driver's embedded
Cargo path. With those paths and a new output directory:

```sh
python3 replay_streaming.py \
  --prepared "$STREAMING_INPUTS" \
  --kani-root "$STREAMING_KANI_TREE" \
  --rustup-home "$STREAMING_RUSTUP_HOME" \
  --rustup "$STREAMING_RUSTUP_BINARY" \
  --solver-bin "$STREAMING_SOLVER_BIN" \
  --compat-libs "$STREAMING_COMPAT_LIBS" \
  --case positive \
  --output "$STREAMING_BUDGET_ROOT/new-positive-run" \
  --budget-root "$STREAMING_BUDGET_ROOT"
```

Cases are `positive`, `wrong-remainder` and `lost-residual`. `--check-only`
checks inputs/runtime without execution; `--codegen-only` compiles without a
solver verdict. Independent cases may run concurrently with separate outputs;
do not run the same prepared case concurrently because Kani writes a diagnostic
graph beside its inputs. The runner retains raw logs/results on failure and
accepts controls only at their intended assertion. Every run keeps the
1,800-second active-time bound, 6,144 MiB aggregate allocation cap and 16 MiB
per-file limit. Linux monotonic time excludes laptop suspension.
