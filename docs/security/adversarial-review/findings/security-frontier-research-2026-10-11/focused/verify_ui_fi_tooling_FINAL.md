RE-CHECK OF 13 DEFECT ROWS AT c75b0d9c (feat/pq1-board-target). Research only. Nothing in the repo was modified: `git status --short` shows 72 entries (28 M + 44 ??), identical to the first listing of the session. No issue was filed or commented on.

Two of my results are new defects that are not in the claim text, so they should not get lost inside the rows:
- **D6:** with the uncommitted `black_box` fix, `fi_min`'s "opposite-inequality recompute" is merged into the first `umin` on host and thumbv8m alike. A tripped guard returns the same first-computed value, so the fix does nothing against the stated single-glitch threat, and the gate would still pass.
- **D7:** no vector in the C10 verify sweep gets past the FORS+C forced-zero check. The WOTS target-sum compares and the final root compare are both unswept, although the README says the whole verify is covered.

Conventions and method:
- CONFIRMED means every sentence of the "Defect" cell holds at c75b0d9c; errors in the other cells are listed as corrections. PARTLY means a sentence of the Defect cell is false.
- Ship set is PROD_SHIP_FEATURES / RELEASE_FEATURES (`Makefile:2662`, `:2718`). It contains `ui-lcd` and `consumption-mask`. It does not contain `ui-px` or `debug-log`.
- Of the cited files only `secure/src/hw/consumption_mask.rs` and `pqsigner-fi/src/lib.rs` are modified in the working tree. Every other line number is the same at the commit and in the tree.
- Remote-tracking refs were not fetched. origin/master tip is 0feea78a (2026-10-11), 156 commits ahead of c75b0d9c. origin/perf/flash-opt-level-z tip is 73287916 (2026-10-09).
- What I ran:
  - `cargo check` of five `tools/sca` crates into a scratch target dir (`--locked --offline`, RUSTFLAGS unset).
  - An LLVM-IR and asm probe of `fi_min` on host and thumbv8m (pinned nightly-2026-04-06, opt-level s and z, LTO).
  - A host probe of `play_screen`'s loop control against the real `pqsigner-ui-px` crate.
  - `gh issue view` (read-only).

ROW A24: CONFIRMED
- Corrected citations at c75b0d9c: `secure/src/tx/display/erc20_unknown.rs:88-97` (the only part that ships); `secure/src/tx/display/dispatch.rs:1104-1145` (direct call with no bound metadata routes to `render_erc20_unknown_pages`); `pqsigner-erc7730/src/display/primitives.rs:1236-1241`; `tx/src/erc20/calldata.rs:33`, `:70` (selector 0x095ea7b3). `secure/src/tx/display/erc20_screens.rs:45` and `:190-194` are ui-px only, outside the ship set.
- Decisive code (`erc20_unknown.rs:90`, `:97`; `primitives.rs:1239`):
```
    } else if matches!(call, Erc20Call::Approve { .. }) && amount.is_zero() {
        write_line(&mut pages.buf[p][1], "Revoke approval");
    // token-id guess (the unknown-token path never calls this helper). The
```
- Wrong or imprecise:
  1. The shipping 16x4 path renders 8 pages for `approve(addr,0)` on an unknown contract. P0 is "! Unknown token" / "approve" / "(decimals = ?)" / "> next". P1 is "Contract:" plus the address. P2 is "Spender:" plus the address. P3 is "Amount (raw):" / "Revoke approval" / "> next". Then chain, two fee pages, and the nonce page with "L=Cancel" / "R=Confirm". The warning is on P0, not on the page that says "Revoke approval".
  2. The string "(RAW) approve" does not exist on that path. It is the ui-px AMOUNT screen (`erc20_screens.rs:190-194`), whose hero is "APPROVE UNKNOWN TOKEN?" and whose ending caption is "REVOKE SIGNED" (`:45`, applied to the unknown family at `:60-66`).
  3. "Not exercised … in a host test" is wrong. `secure/src/display_under_test/pure_tests.rs:834-856` (`positive_unknown_token_zero_approve_paints_revoke_framing`, compiled under `cfg(test)` via `main.rs:493-494`) asserts exactly this rendering as intended behaviour. What is untested is the ERC-721 reading.
  4. Precision on scope: a `(chain, target, selector)` known to the pinned ERC-7730 call set is refused or rendered by the 7730 path before this branch (`dispatch.rs:969-1053`). The legacy Safe-inner unknown path prints "Raw amount:" with no revoke wording (`safe_display.rs:1955-1975`). So the defect is: direct call, non-registry contract, tokenId 0. I did not check the px Safe path (`safe_screens.rs:428`); it is outside the ship set.
  5. The `primitives.rs` comment dismisses the ERC-721 reading only for the authenticated helper; the unknown path carries its own copy of the string. Introduced by f89094ac. #474 is CLOSED, #343 is OPEN.
- Strongest doubt: exploitation needs the wallet to own token id 0 of an NFT contract outside both databases, and I did not run it on a device.

ROW A25: CONFIRMED
- Corrected citations: `secure/src/ui/seed_wizard.rs:918-949` (letters at `:930-933`, flush at `:949`), `:624`, `:655` (not `:656`), `:824`; `secure/src/ui/lcd.rs:153-170` (lookup at `:166`); `secure/src/ui/secret_text.rs:84-94`; `secure/src/ui/pin_entry.rs:188-221` (digit at `:203-205`, flush at `:221`).
- Decisive code (`secret_text.rs:86`; `lcd.rs:165-166`; `pin_entry.rs:205`):
```
/// irrelevant. NEVER call this for secret rows; use [`secret_glyph_cols`].
                let ch = self.rows[r][c];
                let cols = public_glyph_cols(ch);
            b'0' + d
```
- Wrong or imprecise: nothing material.
  - Backend: this is the legacy 16x4 `ui-lcd` glyph blitter, which is the ship set. With `ui-px` absent, the early returns at `seed_wizard.rs:914-917` and `pin_entry.rs:181-187` are compiled out.
  - Path: the letter row and the PIN row go through `Display::flush` to `public_glyph_cols`, a direct `FONT_FLAT_5X8[(ch - FONT_FIRST_CHAR)]` index. The mnemonic pages and the candidate list on the same backend use `flush_with_secret_rows` and the 96-entry masked scan in `ct_glyph_col`.
  - Reachability: `main.rs:988` (`verify_mnemonic`), `:1000` (`enter_mnemonic`), `:927` / `:1675` / `:4163` / `:4553` and `nsc/cmd_request_unlock.rs:54` (PIN entry).
  - Addition: the restore path sends all 24 words' prefixes through the same row, not only the 3 check words, and every intermediate dial value is drawn too.
  - #784 (OPEN) is px-only, as the row says.
- Strongest doubt: the address channel has only an emulated trace behind it, and both paths put the same glyph pixels on SPI anyway.

ROW A26: CONFIRMED
- Corrected citations: `secure/src/ui/seed_wizard.rs:817`, `:896-897` (the reset is `:897`), `:963`, `:824`; contrast `secure/src/ui/pin_entry.rs:79-88`.
- Decisive code (`seed_wizard.rs:817`, `:897`, `:963`; `pin_entry.rs:85`):
```
    let mut buf = [b'a'; MAX_LETTERS];
                buf[len] = b'a';
    let mut cur = start;
            pin[i] = rand_bytes[i] % 10;
```
- Wrong or imprecise (precision only):
  - A repaint count gives the number of short presses but not their direction. Press count with button identity gives the letter exactly.
  - An SPI observer does not need to count at all; the letter's pixels are on the bus.
  - On the new-wallet path the observer learns 3 words but not their positions (the "Check word NN" index is only on the glass, picked at `:715`). The full seed is exposed only on the restore path (`:747-773`).
  - The same `buf` and `cur` feed the px path, so this is not backend-specific.
- Strongest doubt: none on the code; the observer model is the one F-20 already accepts as real for the PIN.

ROW B6: PARTLY
- Corrected citations: `secure/src/ui/px/status_map.rs:277-294` (digit at `:286`); `secure/src/ui/pin_entry.rs:181-186`; `secure/src/ui/px/screens.rs:127-129`; `secure/src/ui/px/lcd.rs:663`, `:664-671`, `:683-693`, `:47`, `:639`; `pqsigner-ui-px/src/rows.rs:75-90`; `pqsigner-ui-px/src/raster.rs:398` against `:404`; `pqsigner-ui-px/src/font.rs:72-77`, `:221`; `pqsigner-ui-px/src/scene.rs:245-258`, `:602-628`; `secure/src/hw/spi_hw.rs:214-221`.
- Decisive code (`status_map.rs:286`; `lcd.rs:663`; `raster.rs:398`, `:404`):
```
            glyphs[i] = b'0' + pin[i] % 10;
    let force = !secret.is_empty();
        Item::Text { ref run, color } => font.blit_run(run, color, s),
        Item::Secret { text, tier, x, y, color } => font.blit_secret_run(tier, text, x, y, color, s),
```
- Wrong or imprecise:
  - **Sentence 1 holds, but it is ui-px only, so not in the ship set.** `pin_row` puts the live digit in the record and `pin_entry` calls `show()`, which is `show_with(s, &[])`, so `force` is false. The digit is drawn by `Item::Text` through `Font::blit_run` and `Font::glyph` (a table index keyed on the character), not by `blit_secret_run`. A strip digest of those pixels is stored in `static mut SHOWN`. #784's "contrast `pin_row` … which masks with `b'*'`" is true only for digits already entered.
  - **Sentence 2 is refuted at this commit.** The screens that carry `secret` (`seed_page`, `candidate_list`) are `Kind::Words`. `layout_of` gives them no sweep, hint or band, and `Anim::new` starts every spring asleep, so `Anim::step` returns false on the first call and `play_screen` paints one forced frame per call. My host replication of the loop gives `frames_painted=1` for `seed_page`, `candidate_list`, `pin_row` and `letter_row`. Running to `PLAY_CAP_MS` is what the Hero chooser does (#783), and it carries no secret cells. A secret page is re-streamed once per button event.
  - **Sentence 3 is then moot.** As arithmetic, 121,552 B × 8 / 20 MHz = 48.6 ms is right at the default divider and halves under `ui-px-spi40`.
  - origin/master has a reworked presenter (`play_screen` at `lcd.rs:1139`, with a `plays_forever` branch); I did not re-probe it. `pin_row` there still emits the live digit through `show()`.
- Strongest doubt: the one-frame result is a host replication of the loop control, not a capture from the panel.

ROW B9: CONFIRMED
- Corrected citations at c75b0d9c: `secure/src/hw/consumption_mask.rs:138`, `:145`, `:195-207` (reseed), `:213-219` (inline xorshift); `secure/src/consumption_mask_prng.rs:22-43`; `secure/src/main.rs:187`; `secure/src/hw_platform_under_test/pure_tests.rs:1251-1254`.
- Decisive text (`consumption_mask_prng.rs:23-24`, `:27-28`):
```
// STATUS (2026-09-01): this module has NO production caller in the committed
// tree, so its tests below do NOT cover the PRNG the firmware actually runs.
// `hw/consumption_mask.rs` still carries its own inline `static mut PRNG_STATE`
// and a duplicate xorshift. The two implementations look equivalent, but the
```
- Wrong or imprecise: nothing found; the module documents its own orphan status.
  - At the commit, `git grep consumption_mask_prng` finds only the `mod` line and an `include_str!` in a test.
  - Addition: `pure_tests.rs:1251-1254` pins the zero-seed rejection against the orphan module's source text, not the driver's own check at `consumption_mask.rs:171-173`.
  - The uncommitted diff (41+/75-) deletes `PRNG_STATE`, `RESEED_TICKS` and the inline xorshift, and calls `consumption_mask_prng::seed` (tree `:159`) and `::advance` (tree `:181`). It does not touch the STATUS comment, which becomes false the day the diff lands.
  - No commit on any ref contains `consumption_mask_prng::advance`.
- Strongest doubt: none; an issue search for the module name returns nothing, consistent with "untracked".

ROW D5: CONFIRMED
- Corrected citations: `tools/sca/fi_target/src/main.rs:33-38`; `secure/src/fi.rs:58`; `tools/sca/c10_sign_target/src/main.rs:105`, `:107` (not `:97`, `:99`), plus `:33-38` and `:80`; `secure/src/crypto.rs:350`, `:358`; `sphincs-c10/src/lib.rs:170-171` against `:192-199`.
- Decisive output and code (`cargo check`; `fi.rs:58`; `c10_sign_target` `:105`; `crypto.rs:350`):
```
error[E0425]: cannot find function `byte_nonsecret` in module `crate::rng`
        let b = crate::rng::byte_nonsecret(FI_DELAY_LAST_GOOD.load(Ordering::Relaxed));
    let sig_a = sk.sign(msg, opt_rand);
    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, progress.0);
```
- Wrong or imprecise (the row understates the breakage):
  - Reproduced on the pinned nightly: `fi_target`, `c10_sign_target` and `ns_ptr_target` each fail with that single E0425. So the C10 sign target does not build either.
  - `fw_verify_target` has the same `byte()`-only stub (`main.rs:41-45`), but I could not compile it because its `Cargo.lock` is stale under `--locked`.
  - `scp03_target` builds because it stubs `byte_nonsecret` (`main.rs:62`). Precision: it sweeps SCP03 logic, so the last sentence of the row still holds for the fi.rs primitives' own sweep.
  - Broken since 29960ebe (2026-07-01). The local ELFs are older (`sca-fi-target` 2026-06-10, `sca-c10-sign-target` 2026-05-18). No workflow builds `tools/sca` targets.
  - The model gap is wider than `sign` against `sign_with_shuffle`. The harness still says "Bit-equivalent to `secure::crypto::c10_sign_verified_with_progress`" (`:80`), but it also lacks the 7-step `CfiCounter`, the rate limiter, the OptRand and shuffle-seed draws with their non-zero checks, and the relock on mismatch (`crypto.rs:153-162`, `:305-348`, `:373-440`).
- Strongest doubt: none on the build; I ran no sweep, so I cannot say what the last published results covered.

ROW D6: PARTLY
- Corrected citations at c75b0d9c: `Makefile:4431-4436` (not `:4480-4485`); `scripts/check_fi_ir.sh` is untracked (`git ls-files` 0 hits, `git log --all` none), relevant lines `:33-34`, `:100`, `:119`; `pqsigner-fi/src/lib.rs:236-249` at the commit has no `black_box`. The fix is the uncommitted +11 lines (tree `:248-250`).
- Decisive output (my probe of the working-tree fix, thumbv8m, opt-level s and z, LTO):
```
  %a.b.i = tail call i32 @llvm.umin.i32(i32 %a, i32 %b)
  %_5.i = icmp ugt i32 %_0.i.i, %a
  %_6.i = icmp ugt i32 %_0.i.i, %b
  %r.sroa.0.0.i = select i1 %or.cond.i, i32 %a.b.i, i32 %_0.i.i
```
- Wrong or imprecise:
  - **"The fix that thumbv8m folds away" is not what happens.** On thumbv8m both guard compares survive (2 `icmp ugt`, same as host), so the script would pass and the pass would be literally true.
  - **What is folded, on every target, is the recompute.** On a tripped guard the function returns the first min again (`movhi r1, r2`, where r2 is the first min). A skip of the single `movlo` in the min trips the guard and still returns the wrong, larger value.
  - So the blind spot is "counts compares, never checks that the recompute is independent". It is not host-specific; a host-only script could catch it.
  - #130's 2026-08-20 comment "guard + recompute now survive -O (IR shows both `icmp ugt` + select)" is wrong on the recompute half.
  - The Makefile target was committed in an unrelated commit (65968d7e, 2026-08-30) while the script, the fix and the `production-security.md` paragraph stayed uncommitted. On a clean checkout `make check-fi-ir` fails on a missing file and `fi_min` is the pre-fix body.
  - "52 days" is 2026-08-20 to 2026-10-11. #777 (OPEN) already tracks the phantom gate; #130 is OPEN.
- Strongest doubt: the probe is a standalone `#[inline(never)]` call site, not `fi_min` inlined into the USB and APDU call sites of a release ELF, which cannot be built under the S-2 fence.

ROW D7: CONFIRMED
- Corrected citations: `tools/sca/README.md:1840-1851`, `:1855`, and `:240-246`; `tools/sca/fault_sweep_c10v.py:50-51`, `:122`, `:159`, `:203-208`; `sphincs-c10/src/wots.rs:174-180` (compare at `:178`); `sphincs-c10/src/hypertree.rs:380-382`; `sphincs-c10/src/params.rs:43`; `fsbl/src/main.rs:343-345`.
- Decisive code (`fault_sweep_c10v.py:51`; `wots.rs:178-179`; `hypertree.rs:380`):
```
SWEEP_CAP    = 8_000       # max instructions to sweep per vector (covers the full ~7.5k of the normal ones)
    if sum != TARGET_SUM {
        return [0u8; N]; // Invalid: digit sum doesn't match
    if fors_indices[K - 1] != 0 {
```
- Wrong or imprecise (the row is understated):
  - The README says twice (`:1843-1845`, `:240-246`) that `wrong-message`, `wrong-root` and `mutated-R` "run the full verify (~7521 instr — H_msg, FORS recompute, hypertree, final root compare — all of it)". That is internally inconsistent: by the same README the other three vectors take 1.2 to 1.8 million instructions, and the harness needs a 3,000,000 budget for its baseline runs.
  - All three "full" vectors change an input of H_msg, so they leave at the forced-zero return right after it. About 7.5k instructions is three SHA-256 blocks.
  - So the sweep covers H_msg plus one early return on three vectors, and the first 8,000 instructions on the other three. No swept fault reaches a WOTS target-sum compare or the final root compare.
  - A fault that skips the forced-zero return runs past the 25,000-instruction budget and is booked as a "hang", which the harness counts as non-forge.
  - The harness's explanation of the long runs, "a malformed WOTS digit drives an unbounded chain" (`:203-208`), is also false: W is 8 and digits are masked to 3 bits, so every chain is at most 7 steps. 1.24 M is simply what a complete verify costs.
  - The FSBL precondition is right: `verify_signature` sits inside `check_true_into_sentinel`, which evaluates it twice.
- Strongest doubt: I did not re-derive the 2^56 grind estimate, and I did not run the emulator to trace the 7.5k-instruction exit.

ROW D8: CONFIRMED
- Corrected citations:
  - `secure/src/fi_delay_pool.rs` is absent at c75b0d9c and on origin/master, and present on origin/perf/flash-opt-level-z. The commits are e23fc5cd and 2d9304d6 (#832), dd901592 (#833), 0a02fe54 (#834), 7594e606 and 2363fb9d (#835). `git branch -r --contains` lists only that branch for each. The branch is 24 commits ahead of origin/master.
  - The `fi_min` diff and the `consumption_mask.rs` diff (41+/75-) exist in no commit on any ref (`git log --all -S` is empty for both).
- Decisive text (#832 closing comment, 2026-10-09; `origin/master:secure/src/fi.rs:58`):
```
## Fixed and verified on silicon  `fi_delay_pool` (2d9304d6, e23fc5cd, 79419a5b)
        let b = crate::rng::byte_nonsecret(FI_DELAY_LAST_GOOD.load(Ordering::Relaxed));
```
- Wrong or imprecise: nothing found. Additions: `scripts/check_fi_ir.sh` belongs in the same list (see D6). origin/master still has the last-good reuse arm and the inline mask PRNG (`consumption_mask.rs:138`). #832 was CLOSED as completed on 2026-10-09; #834 and #835 are OPEN.
- Strongest doubt: the remote-tracking refs were not fetched, so a merge after 2026-10-11 would not show here.

ROW E9: CONFIRMED
- Corrected citations: `secure/src/nsc/mod.rs:694-705` (sentence at `:698-700`) against `:713-725`; `secure/src/board/pq1.rs:301-318` (NC at `:309`); `secure/src/hw/consumption_mask.rs:16-17`, `:41-51`, `:231`, `:378-382` (commit numbering); `docs/security/red-teaming.md:306`, `:694`; `README.md:88`, `:261`, `:417`.
- Decisive text (`nsc/mod.rs:698-700` against `:722`):
```
// FORS leaf secrets. `consumption-mask` drives a TIM2-CH1 PWM on PA5 whose duty
// is re-randomised from the SysTick handler, so the signature stays
// uncorrelated across the whole signing window; without it the only sign-path
     establish, since neither board drives a load from the mask pin and its \
```
- Wrong or imprecise:
  - "On pq1" is too narrow: iota2's PA5 is unloaded as well (`pq1.rs:309-311`, `consumption_mask.rs:43-49`), so the comment is unsupported on both boards.
  - 10 kHz is the code's own figure (PSC 0, ARR 15,999, assuming a 160 MHz timer clock that I did not verify on pq1).
  - The cited README and red-teaming lines are stale pin text, not efficacy claims. They overlap E21, so file them once.
  - Two further stale statements sit in those lines. `red-teaming.md:694` says the duty PRNG is "seeded from `rng_strong`", while the driver deliberately uses the platform TRNG and forbids `rng_strong` there (`consumption_mask.rs:150-156`, `:188-190`). `README.md:88` says the hooks are "All feature-gated; CI keeps them out of production", while the mask is in PROD_REQUIRED.
  - #228 and #646 are OPEN.
- Strongest doubt: "electrical no-op" stays a physics argument; nobody has measured the pad.

ROW E12: CONFIRMED
- Corrected citations: `docs/security/threat-model.md:259`, `:263`; `secure/src/nsc/ns_ptr.rs:27-34`; `secure/src/nsc/mod.rs:2011`; for example `secure/src/nsc/cmd_sign_userop.rs:64`, `:147`, `:154`.
- Decisive text (`threat-model.md:263`; `ns_ptr.rs:29-31`):
```
`NsPtr<T>` typestate validates pointer ranges against NS regions only; failure returns `NscStatus::InvalidPtr` before any deref
//! Migration of every `cmd_*.rs` to thread `NsPtr<T>` end-to-end is
//! sequenced under Phase 7 of the modularity refactor (per
//! `docs/archive/handoff-modularity-refactor.md` §4.6 PR B). Until that lands,
```
- Wrong or imprecise:
  - Do not present "18" as an error. The ship set compiles exactly 18 CMSE entry points: 33 veneers in `nsc/mod.rs`, minus 13 prodtest, minus 2 e2e-test. That is 17 `CMD_*` handlers plus `nsc_register_heartbeat`. The sentence dates from 5bff4c5a (2026-06-18), so the match may be luck, but it is not wrong today.
  - The typestate half is exact. `NsPtr` has one production use (`mod.rs:2011`, the heartbeat veneer) and none in any `cmd_*.rs`. Twelve handler files call the bool functions `validate_ns_read_ptr` / `validate_ns_write_ptr` directly.
  - Pointers are still validated, so this is a wrong mechanism name, not a missing check. #84 is OPEN.
- Strongest doubt: none on the text; the severity is purely documentary.

ROW E21: CONFIRMED
- Corrected citations: `docs/hardware/evt-silicon-validation.md:757-765`, `:175`, `:908-923`; `docs/security/red-teaming.md:97-105`; `docs/hardware/hardware_requirements.md:119-122`; also `README.md:88` / `:261` / `:417` and `CLAUDE.md:221`, `:318`.
- Decisive text (`evt-silicon-validation.md:757`, `:759`, `:921-922`):
```
**A `mode-production` pq1 image is currently unsatisfiable, by construction.**
The consumption mask is TIM2_CH1 on **PA5** (`hw/consumption_mask.rs:113`), and
**SCA note:** the on-bench LA1010 is digital-only. On-silicon power/EM SCA (9.2/9.3)
needs a ChipWhisperer-Husky / ChipSHOUTER, which is **not yet on the bench**
```
- Wrong or imprecise: all four sub-claims hold.
  - The evt doc has no later UPDATE recording the TIM3_CH1/PA6 port; its only TIM3 mention is inside the stale paragraph, although `board/pq1.rs:314-318` moved the mask.
  - "§9" exists (line 908), but its items 9.1 to 9.6 never mention the mask. `consumption_mask.rs:47-49`, `pq1.rs:312-313`, the `nsc/mod.rs` fence text and CLAUDE.md all send the reader there for the open load measurement.
  - The bench disagreement is `evt-silicon-validation.md:921-923` against `red-teaming.md:97-105`, which assigns CPA/DPA to the MHO934 scope with a shunt or current probe and reserves ChipWhisperer for fault exploitation.
  - `hardware_requirements.md:119-122` is a different stale item: it lists the mask as "Optional / nice-to-have" on PA5, while the production fence makes it mandatory.
  - Line 175 is the pre-pq1 dev-board pin table, so it is historical, not wrong for iota2.
- Strongest doubt: `docs/tooling-and-systems.md`, the evt doc's source for "not yet on the bench", is modified and uncommitted in this tree; I did not reconcile it.

ROW E22: CONFIRMED
- Corrected citations: `docs/security/threat-model.md:321` (its only `wait_random` mention); `secure/src/fi.rs:76-95`; `pqsigner-fi/src/lib.rs:129`.
- Decisive text (`threat-model.md:321`; `fi.rs:86`, `:93`):
```
| Random-delay glitch sentinel (`wait_random` style) | T3 | Planned — Trezor `random_delays.c:186-202` pattern with the double-invariant `i + j == wait` under volatile pair |
pub fn wait_random() {
        pqsigner_fi::wait_random_loop(rng_byte);
```
- Wrong or imprecise: "231 call lines" counts comments. `git grep 'wait_random()' c75b0d9c -- 'secure/src/*.rs'` gives 272 lines. Removing 41 in test-scaffold files leaves 231. Of those, 19 are comment lines, 1 is the definition and 4 sit in inline `#[cfg(test)]` modules, leaving 207 code call lines in 40 files by my count. Say "over 200".
- Strongest doubt: none; e2e-test builds make it a no-op (`fi.rs:87-90`), which does not affect the ship set.

SUMMARY
Fully confirmed: 11 (A24, A25, A26, B9, D5, D7, D8, E9, E12, E21, E22), each with the corrections listed; D5 and D7 are worse than written.
Partly: 2 (B6: sentence 2 is refuted, one forced frame per call; D6: the compares survive on thumbv8m and it is the recompute that is merged). Refuted outright: 0.
Trusted least: B6, because the half that survives is ui-px only, outside the ship set, and my refutation of the other half rests on a host replication of the loop, not a panel capture.

A copy of this report is at `/tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/recheck-report-draft.txt` (earlier draft; this message supersedes it). The probe crates are in the same scratchpad under `fi-ir-probe/` and `anim-probe/`.