# SHA-256 final-state output serialization

This research profile checks the actual `sha2 0.10.9`
`Sha256VarCore::finalize_variable_core` implementation with the corrected
`generic-array 0.14.7` dependency selected in
[issue #1097](https://github.com/EthereumPhone/PQ1/issues/1097).
The upstream method bodies are unchanged in the positive case. A proof-only
module appended to `core_api.rs` calls real padding, compression and output
serialization, then observes the resulting private state.

The theorem is a relation between the output and that actual final state.
It is not an independent functional SHA-256 specification. Production
dependencies are unchanged; the original-dependency criterion in
[#1067](https://github.com/EthereumPhone/PQ1/issues/1067) remains open.

## Statement and input domain

The positive harness quantifies over:

- all eight initial `u32` state words;
- all 64 initial buffer bytes and all 32 previous output bytes;
- buffer positions from 0 through 63;
- block counters from 0 through `2^55 - 1`; and
- the observed output-byte index from 0 through 31.

The position and counter bounds ensure that the final bit-length expression
fits in `u64`. They do not establish that the counter describes a particular
earlier input history. The initial state need not be reachable from SHA-256's
standard initialization vector, so the result also covers all states that are
reachable within the selected domain.

After actual finalization, the selected output byte equals the corresponding
big-endian byte of the actual final state word. The oracle uses scalar shifts
and a mask, independently of the implementation's `to_be_bytes` operation.
The block counter is preserved and the buffer position is zero. Quantifying
over the byte index checks every output position, including overwriting
arbitrary previous output bytes.

Four covers occur after all three assertions: positions 0, 55 and 56, and
the joint boundary of position 63, byte index 31 and counter `2^55 - 1`.
The checker requires each cover and its exact reachability probe to be reached.
In this `no_std` root, the ordinary Rust assertions lower to guarded
failure-path checks; they have no direct `KANI_CHECK_ID` reachability pair.
The post-assertion covers provide the stated non-vacuity witnesses.

## Complete results and controls

The positive result covers all **2,324 static properties** in 19 partitions,
plus the same successful dynamic unwinding assertion in every partition.
Every ordinary safety, validity, initialization, bounds and unsupported-operation
check must succeed. CBMC prints a reached cover or reachability probe as
`FAILURE`; the checker interprets those separately from ordinary assertions.
An overall exit code of 10 is therefore not itself a failing proof or a valid
negative control.

The source controls have the following scope:

| Case | Deliberate change | Required result |
| --- | --- | --- |
| `little-endian` | Serialize the SHA-256 words with `to_le_bytes` | All 2,324 static properties checked; only the output-byte assertion fails among ordinary properties |
| `omitted-word` | Write only the first seven state words | All 2,330 static properties checked, including six extra slice checks; only the output-byte assertion fails among ordinary properties |
| `unreachable` | Add `kani::assume(false)` before finalization | All 2,324 static properties reported, but the required final covers are unreachable and positive semantic acceptance is refused |

The first two are **finite causal controls**: zero initial state, buffer and
output, position and counter zero, and observed byte 31. This concrete input
is contained in the positive universal domain. Checks after their intended
failing assertion are unreachable and are retained explicitly. They are not
universal claims that every input detects either mutation.

The original positive query with a global unwind bound of 193 exhausted its
180-second allocation during padding-loop expansion. A separately selected
query bounded that loop at 65 while retaining 193 elsewhere and retaining
unwinding assertions. The first complete-census, unpartitioned byte-order
control also exhausted its 180-second allocation, during propositional
conversion. Its successful replacement reused the unchanged compiled program
and complete census with bounded partitions. Neither stopped attempt receives
proof or negative-control credit.

The first root collector used an older parser that refused CBMC's inline
source-file label. The retained raw log was rechecked with the already-reviewed
parser, which compares that label to the exact census filename. No solver
replay or result editing was needed. The historical refusal and later
completion are both retained.

## Source and tool boundary

The input recipe extracts the ten archived dependency packages, applies the
exact [generic-array correction](../sha256-padding/frozen/generic-array.patch),
and reconstructs all four cases. The generated root manifest selects the
portable `force-soft`, `no_std` source configuration. It is a minimal proof
manifest, not a claim that the complete upstream package manifest was built.
The source reconstruction was compared byte-for-byte with every recorded input
file, including the generated Cargo checksum files. The Cargo lockfile is
retained separately from the pre-build input inventory.

The selected private compiler/model/backend composition is the one accepted
in the [C3/C4 milestone](https://github.com/EthereumPhone/PQ1/issues/1097#issuecomment-6874194946).
These runs use the explicit **MiniSat2** backend profile. They do not inherit a
full-proof or timing claim for the Kani driver's default CaDiCaL solver.
All default, uninitialized-memory, valid-value and unwinding checks remain
enabled. There are no stubs, verified stubs, function contracts, loop contracts
or assumed compression results.

The retained runtime uses 13,015 selected read-only host files; this is not
complete host hermeticity. Source and runtime identities were checked before
and after execution. The independently supervised compiler/solver commands
have their own active-time, CPU, memory, output and storage bounds. Active-time
measurements use a monotonic clock that excludes laptop suspension. Recorded
command times do not include all surrounding preparation and validation work.

The archived receipts are evidence of the recorded runs, not cryptographic
authentication of a historical host or a proof of compiler/model soundness.
Compiler correctness, the Rust memory model and alias/provenance behavior
remain explicit trust boundaries.

## Check the recorded evidence

With Python 3.12+ and GNU patch, from this directory:

```sh
python3 -B check.py
python3 -B test_gate.py -v
```

The checker authenticates 442 compressed artifacts, reconstructs the source
inputs, checks the compilation and program-preparation chain, and parses every
original result row. It verifies the exact runtime identities recorded for each
stage, command flags, resource bounds, clean completion, census coverage,
reachability and control semantics. These commands need neither the private
compiler installation nor the original absolute paths. Those paths are keys
into the archive, not files read from the checking host.

The [CI job](../../../.github/workflows/sha256-output-evidence.yml) runs these
recorded-evidence checks and input reconstruction. It does **not** run a compiler
or solver. The rejection tests separately exercise archive integrity and
semantic validation, including mutated data after archive authentication.

## Reconstruct the inputs

With Python 3.12+ and GNU patch, from this directory:

```sh
python3 inputs.py /absolute/new/output-inputs --case positive
```

The other cases are `little-endian`, `omitted-word` and `unreachable`.
Preparation executes no compiler or solver. `inputs.check_prepared` independently
reconstructs the expected files; editing `prepared.json` cannot authorize
different source, configuration or extra files.

## Replay an archived solver program

`replay.py` reruns one case's archived prepared GOTO program using the retained
private runtime. This is a fresh **solver replay**, not fresh Rust translation.
The source-to-program compilation evidence remains the archived, checked
evidence. Full source compilation requires the selected private compiler/model
installation and its historical compilation/preparation recipes; the archive
includes those recipes and exact commands, but does not bootstrap a portable
compiler installation.

On the retained research host, use the exact accepted runtime namespace and a
new output directory under the research root. For example, from this directory:

```sh
research_dir=/home/nicola/.local/state/pqsigner-research/easycrypt-full-digest-20261028
runtime_dir="$research_dir/corrected-digest/circular-backend-cadical-v1/runtime-recovery-v1"
python3 -B "$runtime_dir/namespace_v4.py" /usr/bin/python3 -B \
  "$PWD/replay.py" "$research_dir/output-unreachable-replay" --case unreachable
```

The four case names are the same as for input reconstruction. Use distinct
output directories and run one case at a time. The runner checks the retained
runtime and read-only host mounts before work, reconstructs inputs in the new
directory, and authenticates source/runtime/program identities around each
solver command. It preserves all new logs and receipts and stops at the first
identity, resource, execution or semantic failure. It does not retry or replace
historical evidence. `assessment.json` appears only after complete acceptance
of that case's stated positive or negative semantics.

The root/whole-query cap is 180 active seconds; a partitioned tail has a separate
900-second cap. The supervisor enforces CPU limits, 16 GiB address space,
16 MiB per output file, a 4 GiB workspace-growth allowance, a 106 GiB aggregate
research allowance and a 10 GiB plus 32 MiB host-space floor. Preflight requires
32 GiB available memory. Preparation and runtime authentication have additional
cost outside the per-command caps. A time/resource stop gives no proof credit.

## Remaining correspondence

This component does not close `CtVariableCoreWrapper` or `CoreWrapper`
composition, accumulated Rust history and bit-length correspondence, general
streaming updates, unrestricted Digest callers, arbitrary closures, or
cross-tool refinement. It does not turn the final state into an independently
specified SHA-256 digest, prove cryptographic assumptions, cover accelerated
hardware backends, or authorize production dependency adoption or shipment.
Those boundaries remain tracked in #1097 and the parent research issue #100.
