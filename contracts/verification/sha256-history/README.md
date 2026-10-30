# SHA-256 streaming history and length model

This Std-only Lean component proves the mathematical composition needed by
PQ1 #1067: all finite input lengths and update histories, exact byte order,
complete-block counts, residual bytes, and checked 64-bit length arithmetic.
It is a **manual value-level transcription**, not extracted Rust. It closes
these mathematical obligations without claiming the remaining original
`Digest` implementation correspondence.

## Statements and entry conditions

`step` transcribes the Eager branches at block size 64. `split` separates a
complete-block prefix from the residual suffix. Both operate on lists of any
element type; instantiating with `UInt8` gives byte lists. The model records
emitted bytes, not compression state, pointer addresses or callback grouping.

- `step_conserves` proves exact byte conservation. With buffered length below
  64, `step_count_exact` and `step_residual_exact` give quotient and remainder.
- `run_conserves`, `run_count_exact`, `run_canonical_prefix` and
  `run_canonical_suffix` compose arbitrary finite histories from any valid
  initial state. Validity means the previously emitted length equals 64 times
  the block count and the buffered length is below 64.
- `run_segmentation` proves that any two segmentations of the same input bytes
  produce the same modeled state. Empty updates are included.
- `bitLength_value_exact` proves the exact value `8 * L` when `L < 2^61`.
  `history_bitLength` derives `L` from the complete history; it does not assume
  the desired output. `history_update_checked` and `history_prefix_bitLength`
  cover each intermediate update and history prefix under the final bound.
  `partial_counter_checked` covers a partial increment within one step; it
  does not establish Rust callback behavior.
- `last_representable_length` and `first_overflowing_length` check the exact
  `2^61 - 1` and `2^61` byte boundaries. The model returns `none` on overflow.
  This is not a claim about the panic/wrapping behavior of every Rust profile.

All 38 theorem declarations have pinned signatures and exact axiom closures.
The closures contain only `propext` and `Quot.sound`, or no axioms. The empty
initial state is proved valid; the concrete boundary examples and mutation
counterexamples are kernel-checked using `decide`.

## Source mapping and remaining trust boundary

`source/` preserves three unchanged Cargo-source files, with their upstream
MIT/Apache licenses. `profile.json` pins their bytes. These are historical
mapping inputs; the gate does not claim to authenticate the current production
dependency graph or prove the mapping itself.

| Source | Value-level interpretation |
|---|---|
| `block-buffer-0.10.4/src/sealed.rs:14–35` | Eager invariant, division into complete 64-byte blocks and suffix |
| `block-buffer-0.10.4/src/lib.rs:139–177` | Short-input append, fill existing partial block, process full input blocks, retain leftover |
| `sha2-0.10.9/src/core_api.rs:35–39` | Add the number of emitted blocks to the accumulated count |
| `sha2-0.10.9/src/core_api.rs:62–65` | Evaluate `8 * (position + 64 * block_count)` |

List operations abstract away the unsafe slice conversions, initialization,
aliasing and provenance rules. The model does not execute the original
constructor or verify arbitrary callbacks, compression-state evolution,
allocation/resource limits, padding byte emission, or the entire `Digest`
API. The independently checked [initialized streaming step](../sha256-streaming/README.md)
and [corrected-dependency padding](../sha256-padding/README.md) keep their own
bounds and TCB; these theorems do not automatically compose those source-level
results. Cross-tool refinement and all cryptographic/physical assumptions
remain open in [RESEARCH-LIMITS](../easycrypt/c10-port/RESEARCH-LIMITS.md).

The trusted Lean runtime includes the official 4.35.0 compiled Std/Init
libraries and native tactics. The gate checks the Linux Lean executable hash
and exact version; it is not a reproducible build or independent kernel audit
of that toolchain. No project model cache is imported: the component is freshly
compiled in an isolated output directory with an empty `LEAN_PATH`.

## Replay and semantic controls

From this directory, with the official Linux Lean 4.35.0 toolchain:

```sh
python3 verify.py --source-only
python3 test_gate.py -v
python3 verify.py --lean /absolute/path/to/lean --output /new/replay/directory
```

The source-only command authenticates inputs and enrollment; it is not a
proof replay. The complete replay compiles the baseline and a value-preserving
block-count change, then runs four semantic mutations: wrong remainder,
lost residual bytes, omitted filled block, and a bit-length scale of 7 instead
of 8. For each, the definitions must compile, an explicit counterexample must
be kernel-checked, and the unchanged consumer must reject at the intended
theorem. Timeout, syntax, missing-tool and resource failures are not accepted
as semantic rejection. Raw sources, logs, commands and result hashes are saved.
Each invocation has a 90-second active-time limit, a CPU limit and an output
limit. The initial complete replay took about six seconds on the research host.

The path-scoped `lean-sha256-history.yml` CI job runs the fresh replay and all
controls. Its evidence concerns this model only. The broader owner-triggered
FV assurance pass remains deferred under PQ1 #509.
