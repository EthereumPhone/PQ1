# C10 autoresearch — speed up PQ1's SPHINCS+C10 signing

Karpathy-style autoresearch loop (`ref/karpathy-program.md`), adapted to firmware.
One fixed evaluator, one change at a time, and only measured wins are kept.

## Branch and scope

- Branch `research/c10-autoresearch` in `~/repos/pq1-autoresearch-wt`, cut from master `0bf8153f2`.
- Local commits only. **Never push.** A "keep" is a measured win on this research branch, not something ready to land.
- Landing is a separate step that needs FV re-pins, FI/SCA review, from-flash confirmation and the owner's go.

## Frozen (do not edit during the loop; any edit means a new baseline)

- `inputs.rs`: the seeds, messages, opt_rand and shuffle seeds.
- `golden.bin`: pk_root, then sig(m0), then sig(m1), all from unmodified master.
- `harness/`: the startup code, the linker script, the clock raise to 160 MHz and the SWD runner.
- `bench/src/lib.rs` and `host/src/main.rs`. The one allowed host change: adding a software SHA-256 hook for a new driver entry point. Each such hook must be plain sha2 output.
- `evaluate.py` and `experiment.sh`.

## What you may edit

Everything that runs in the signer. Every edit must be output-identical.

- `sphincs-c10/src/**`.
- `hw/src/hash.rs`. It is shared with the FSBL, so put changes behind a secure-only feature, or note the FSBL impact.
- The bench's `[profile.release]` and its dependency feature lists in `bench/Cargo.toml`. These are codegen experiments.

## Metric

`./experiment.sh` runs two gates, then measures:

1. **Host gate.** The edited `sphincs-c10` is rebuilt with the `hw-sha256-oneshot` code path and checked against `golden.bin`, byte for byte.
2. **Kit gate.** The SRAM bench runs on the B-U585I-IOT02A kit (UID 0055002D). It must reach status DONE, pass both verifies, and produce pass A == pass B, with pk_root and both signatures byte-identical to golden.
3. **Cycles.** Measured on DWT. Noise at baseline was about 150 cycles in 1e9 over 3 runs.
   - `cached_sign` = 2 sign passes + 1 verify. This is the hashing work of the production FI chain for a cached Type-2 sign, and the **headline**.
   - `keygen` = the top-layer keygen. It runs on a first sign with a new slot.
   - `total` = keygen + 3 sign passes + 2 verifies. This is the **keep criterion**.

Keep rule:

- Keep when `total` drops by more than 2,000 cycles, `cached_sign` does not rise, and both gates pass.
- Weigh complexity as Karpathy does: tiny gains bought with ugly code are a discard, and equal speed with simpler code is a keep.

## Rules from the project (CLAUDE.md, invariants)

- Parameters, preimage layouts and wire formats are frozen. The WOTS+C and FORS+C grinds must find the same counters.
- The FI chain stays: two independent passes, a constant-time compare, and verify before release.
  - Ideas that reuse pass-A work in pass B, or cache state across signs, are **track B**. Measure them with a separate bench variant, and never auto-keep them.
- No secret-dependent branches or memory access patterns. No heap. Secure RAM is a budget.
- `hash.rs`, `wots.rs` and `hypertree.rs` are Lean-extracted and EasyCrypt line-cited. Edits there are allowed in the loop, but tag the row `[FV]`. Tag edits to the shared FSBL driver `[FSBL]`.
- Kit safety:
  - SRAM only: never flash, option bytes, OTP, backup registers, TAMP or GTZC.
  - Only volatile RCC/PWR/HASH writes, and every run ends with `reset run`.
  - Check the flash SHA-256 (f599a5dc…) and OPTR (0x9deff8aa) at session start and end.
- Keep the host quiet during kit runs. That means no fuzzers or mutation sweeps.

## Loop

1. Pick the top untried hypothesis from `ledger.md`, from Fable 5.2's ranked lists (`fable-hypotheses-*.md`) or from the profile.
2. Edit, then commit (`exp: <idea>`). Stage only `sphincs-c10/`, `hw/` and `bench/Cargo.toml` (`git add <paths>`, never `commit -a`): a `commit -a` swept harness edits into an experiment commit, and its revert removed them.
3. Run `./experiment.sh > out/exp.json`.
4. Append a row to `results.tsv` (untracked): commit, cached_sign, keygen, total, status (`keep`/`discard`/`crash`/`gate-fail`), description.
5. On a keep, leave the commit. Otherwise run `git reset --hard HEAD~1`.
6. Every ~8 experiments, or when the keep rate stalls, send `results.tsv` and the ledger back to Fable for re-ranking.
7. Do not stop to ask whether to continue. Report at milestones.

## Flash-only levers (cannot be measured on this kit)

These are logged in `ledger.md` as "needs flash-run board":

- ICACHE way mode (`rcc.rs` writes `ICACHE_CR = 1`, which clears WAYSEL and selects 1-way).
- FLASH_ACR prefetch and latency.
- Code placement in SRAM versus flash.
