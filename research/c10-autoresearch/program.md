# C10 autoresearch — speed up PQ1's SPHINCS+C10 signing

Karpathy-style autoresearch loop (the `program.md` of github.com/karpathy/autoresearch), adapted to firmware.
One fixed evaluator, one change at a time, and only measured wins are kept.

## Branch and scope

- Branch `research/c10-autoresearch` in its own worktree, cut from master `0bf8153f2`.
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

## Evaluators (current: v3b)

- `experiment_flash.sh` (**v3b, primary**): code in flash bank 1, 4 wait states, ICACHE 2-way. Pass `EXP_CFLAGS=` for the shipped 1-way setting.
- `experiment.sh` (v2): code on the SRAM1 C-bus alias. Fast and flash-free; within about 2% of v3.
- `experiment_b.sh`: track B, the top-layer cache (bench_b). Never auto-kept.
- `bench_diff`: kit differential, 32 cases against `out/diff-ref.txt` from pristine master, plus the search128 edge cases.
- PC differentials:
  - `target-diff/release/diff-ref N E` builds from pristine master.
  - `target/release/c10-ar-host diff N E` runs the fast path.
  - `target-b/release/c10-ar-host diff|controls` runs the cache path.

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
- Kit safety (updated 2026-11-12):
  - The owner allowed **flash writes** on the kit (bank 1 pages, via `harness/run_flash.sh`). Never write option bytes, OTP, RDP/TZEN, backup registers, TAMP or GTZC, and never do permanent provisioning. The secure elements are not connected.
  - Volatile RCC/PWR/HASH/FLASH_ACR/ICACHE writes are fine. Every run ends with `reset run`.
  - At session end, re-read the option registers 0x40022040..0x4002206C and compare with the values captured before the first flash: `9deff8aa 0800007f 0bf9007f 0c00007c ffffff80 7f807f80 ff80ffff ff80ffff ff80ffff 7f807f80 ff80ffff ff80ffff`.
  - After flash runs the kit boots the last bench image, not its original stub. The stub can be restored from the old dump (flash SHA f599a5dc…).
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
