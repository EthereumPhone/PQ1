TITLE: FI and wipe assurance does not test what the docs say: fi_target does not build, the C10 verify sweep never reaches the WOTS or root compares, delay-source fixes are stranded on a branch, and the wipe-recovery e2e cannot pass since S-6
LABELS: finding,priority:high,surface:sca-fi,surface:secure-element,surface:fv,source:frontier-research-2026-10
---
Four assurance gaps with no tracking issue. In each, a document or a closed issue says something is covered and the tree says otherwise.

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

## 1. The FI emulation harness for the `fi.rs` primitives does not compile

- `tools/sca/fi_target` fails with `error[E0425]: cannot find function byte_nonsecret in module crate::rng`. Its stub at `tools/sca/fi_target/src/main.rs:33-38` provides only `byte()`, while production `secure/src/fi.rs:58` calls `crate::rng::byte_nonsecret(...)`. I re-ran `cargo check --offline --target thumbv8m.main-none-eabi` on the master sources and got that error.
- `tools/sca/ns_ptr_target` and `tools/sca/fw_verify_target` carry the same `byte()`-only stub. They are unchanged since the research commit, where `ns_ptr_target` failed the same way (`fw_verify_target` was not compiled; its lockfile is stale).
- Broken since `29960ebe` (2026-07-01). The ELFs on the bench machine predate that. No workflow builds any `tools/sca` target.
- `tools/sca/c10_sign_target` **was fixed on master** by `ce717f31`: it now stubs `byte_nonsecret`, builds, and its header honestly says "Reduced mirror; production caller/CFI behavior is outside this target". It still calls plain `sk.sign` twice (`:97`, `:99`) where production calls `sign_with_shuffle` (`secure/src/crypto.rs:350`, `:358`), which is the gap #592 tracks.
- Consequence: every "FI-swept" statement about the `fi.rs` primitives is currently unreproducible.
- [ ] Fix the three stubs, and add a CI job that at least `cargo check`s every `tools/sca/*_target`.

## 2. The "clean" verdict for the C10 verifier covers almost none of the verifier

- `tools/sca/fault_sweep_c10v.py:51`: `SWEEP_CAP = 8_000` instructions per vector.
- `tools/sca/README.md:1843-1845` (and `:240-246`) says `wrong-message`, `wrong-root` and `mutated-R` "run the full verify (~7521 instr — H_msg, FORS recompute, hypertree, final root compare — all of it), so the sweep covers every instruction".
- That is not possible: by the same README the other three vectors take 1.2 to 1.8 million instructions. The three "full" vectors each change an input of the message hash, so they leave at the forced-zero check (`sphincs-c10/src/hypertree.rs:393`) immediately after it. About 7,500 instructions is three SHA-256 blocks.
- So no swept fault reaches a WOTS target-sum compare (`sphincs-c10/src/wots.rs:183`, a single bare compare) or the final root compare. A fault that skips the forced-zero return runs past the 25,000-instruction budget and is booked as a "hang", which the harness counts as not a forgery.
- This verifier is what the FSBL uses to admit firmware.
- [ ] Sweep the WOTS target-sum and root-compare regions explicitly, and correct the README.

## 3. Fixes that are not on master

- `secure/src/fi_delay_pool.rs` exists only on `perf/flash-opt-level-z` (commits `e23fc5cd`, `2d9304d6`, `dd901592`, `0a02fe54`, `7594e606`, `2363fb9d`). #832 was closed on 2026-10-09 as "Fixed and verified on silicon", but master's `secure/src/fi.rs:58` still has the last-good reuse arm. Landing that branch has no issue.
- The consumption-mask driver still carries its own inline PRNG (`secure/src/hw/consumption_mask.rs:138`, `:145`, `:195-219`), while the tested pure module `secure/src/consumption_mask_prng.rs` has no production caller and says so itself (`:22-28`). A host test pins the zero-seed rejection against the orphan module, not the driver (`secure/src/hw_platform_under_test/pure_tests.rs:1251-1254`). The refactor that fixes this exists in no commit on any branch.
- The `fi_min` fix and `scripts/check_fi_ir.sh` likewise exist in no commit (#777, #130).
- [ ] Land or explicitly drop each of these, and reopen or annotate #832.

## 4. The wipe-recovery e2e cannot pass on a current build, and the lockout-wipe FI suite does not run

- `make pin-gate-wipe-e2e` (`Makefile:3450-3460`) builds a non-locked image (`...e2e-test,otp-hardcoded-master-key...`). Its post-wipe re-provision (`secure/src/main.rs:3608`) hits the UserID guard that the S-6 change added (`secure/src/se050/mod.rs:1993-2000`, commit `3fe56460`, 2026-05-28).
- Its only recorded pass is commit `0969901c` (2026-04-22), and the "Passing" row at `docs/security/threat-model.md:571` is dated 2026-05-12. Both predate S-6. The test's own comments (`secure/src/main.rs:3432`, `:3438`) still describe the pre-S-6 behaviour. By source read the recovery step can no longer pass. I did not run it.
- The lockout-wipe FI suite's `mod` line was removed in `e537e7cf` (`secure/src/main.rs:415-425` says so), so it does not execute, and its test file is untracked.
- [ ] Re-run `pin-gate-wipe-e2e` on a current build, add a cold reboot to it, and record the result. Until then the threat-model row should not say "Passing".
- [ ] Put the wipe decision logic in a workspace crate so its tests actually run.

Evidence level: item 1 reproduced by build; items 2 to 4 by code and history read, re-checked independently at `c75b0d9c` (all confirmed; items 1 and 2 are worse than the report said, and item 4's second half had the wrong reason in the report, corrected here).

Related: #591, #592, #232, #211, #296, #832, #834, #835, #777, #130, #168, #200, #776.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M19 / M05 / M06 / M15 / M14, defect row D5, D7, D8, D9, B9).  The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
