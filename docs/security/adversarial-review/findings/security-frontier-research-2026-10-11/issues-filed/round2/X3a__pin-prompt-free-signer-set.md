TITLE: Pin two gateway policy sets with source tests: the one handler that signs without a prompt (command 15) and the entries callable on a locked device
LABELS: enhancement,priority:low,surface:trustzone,surface:docs,source:frontier-research-2026-10
---
## Summary

**This issue does not reopen the owner's WON'T-FIX on `CMD_GET_INIT_CODE`.** That command (number 15) returns a fresh bootstrap-key signature behind the PIN gate and without an on-device prompt. The owner accepted that on 2026-06-30 and marked it "do not re-raise"; a 2026-07-10 update to the record quantified the risk and kept the disposition. No confirm, tally or deterministic signature is proposed here.

What the acceptance does not do is stop the exception from growing. It covers one handler. Nothing in the tree fails if a second handler, or a new branch inside an existing handler, starts returning key-derived output with no prompt. The same is true of a second policy set: which gateway entries may run on a locked device is decided handler by handler, with no reviewed list. This issue asks for two regression pins (host source-text tests with set equality) and one documentation line. Behaviour does not change.

## What the code does today

- `secure/src/nsc/cmd_get_init_code.rs:78`: the handler checks the `pin_verified` sentinel. `secure/src/nsc/cmd_get_init_code.rs:31`: its header states there is no confirmation. `secure/src/nsc/cmd_get_init_code.rs:266`: it calls `factory_calldata::build`, which signs with the bootstrap key at `secure/src/nsc/factory_calldata.rs:78`.
- Every signer call site under `secure/src/nsc` at master:
  - `secure/src/nsc/cmd_sign_userop.rs:2311`, `secure/src/nsc/cmd_sign_userop.rs:2437`, `secure/src/nsc/cmd_sign_userop.rs:2558` (three)
  - `secure/src/nsc/cmd_sign_userop_batch.rs:2444`, `secure/src/nsc/cmd_sign_userop_batch.rs:2535`, `secure/src/nsc/cmd_sign_userop_batch.rs:2651` (three)
  - `secure/src/nsc/cmd_sign_offchain.rs:1337`, `secure/src/nsc/cmd_sign_offchain.rs:1499` (two)
  - `secure/src/nsc/cmd_sign_userop_forced.rs:1387` (one)
  - `secure/src/nsc/cmd_get_init_code.rs:266` (one)
- Of those five files, only `cmd_get_init_code.rs` contains no confirm call (a text count gives 0, against 12, 8, 8 and 3 in the others). So the set of prompt-free signers is one file today. No test asserts it.
- One raw signer exists outside the gateway: `secure/src/fw_rollback_e2e.rs:80`, a development-key signer behind a test feature.
- On the real chip there is no central dispatcher to hang a policy on. `dispatch` is compiled only for the emulator (`secure/src/nsc/mod.rs:1833`); on hardware each command is its own gateway entry function.
- Which entries run on a locked device is not written down in one place. A text search gives only a rough picture: 12 of the 20 `cmd_*.rs` files return the not-unlocked status somewhere, and the other 8 are a mix. Some are meant to run locked (`secure/src/nsc/cmd_is_unlocked.rs:11` only reads the flag and returns 1 or 0; get-remaining, lock, the illegal-access status and the PIN-attempt log have no gate), one is the unlock command itself, one is test-only, and one (`cmd_sign_userop_forced.rs`) is not an entry at all but is reached from the single-sign handler after that handler's gate. There are 34 gateway entry functions in `secure/src/nsc/mod.rs`, and some (the watchdog heartbeat, the factory-test set) have no handler file. Existing tests check the gate for hand-maintained lists of files, for example `secure/src/nsc_batch_offchain_pure_tests.rs:687`. A new entry that is in none of those lists is checked by nothing.
- The right home for the new tests is a file the host build compiles: `secure/src/main.rs:361` mounts `nsc_small_cmds_pure_tests` under `cfg(test)`, the CI job that runs the secure crate's host tests picks it up, and it is not on the never-run allowlist. The gateway module itself is compiled out under test (`secure/src/main.rs:171`), so a test written inside a handler would never run.
- The per-command audit table has a column for the unlock gate and none for "prompts the user": `docs/audits/gateway-parsing-20260623-220401.md:140`.
- The acceptance record still quotes about 1.5 s per call and 60 to 80 signatures per unlock: `docs/VULN-getinitcode-bootstrap-fewtime-oracle.md:155`.

## What is already tracked elsewhere

- The finding itself is recorded and closed as accepted in `docs/VULN-getinitcode-bootstrap-fewtime-oracle.md:8`. It has no issue and needs none.
- #181 is the sibling: the counterfactual off-chain path also releases a bootstrap signature, but it prompts.
- #89 covers the few-time margin of the slot keys, a different key.
- #84 and #859 cover the pointer-validation shape of the handlers. #719 is the owner decision on whether the PIN-attempt log may be read on a locked device. #846 adds a refusal check at the top of every gateway entry and a source test over all entries.

So this issue is only about pinning the two sets and adding the prompt column.

## Proposed work

- [ ] **Prompt-free signer pin.** A host test that enumerates every file under `secure/src/nsc/` (read from the crate directory at test time; `include_str!` cannot glob), finds every signer call (`c10_sign_verified*`, `factory_calldata::build`, and raw `SigningKey` signing), and asserts that the set of files with a signer and no confirm call equals exactly `{cmd_get_init_code.rs}`. Allowlist `secure/src/fw_rollback_e2e.rs` by name.
- [ ] Pin the number of signer call sites per file (3, 3, 2, 1, 1 today). A file-level check alone passes a new silent branch added inside a handler that already prompts elsewhere; a changed count forces a review.
- [ ] Pin the three properties the acceptance rests on, for command 15: it checks the `pin_verified` sentinel, it never calls the idle-timer reset, and its signature goes through the rate-limited signer.
- [ ] **Locked-callable pin.** In the same test file, one table of the gateway entries that may run on a locked device, and an assertion that it equals the set found in the source. Enumerate the gateway entry functions in `secure/src/nsc/mod.rs`, not the handler files, and classify each one by whether its handler returns the not-unlocked status before doing any work. Do not classify by whether the word `pin_verified` appears: that would put the is-unlocked command on the wrong side. The row for the PIN-attempt log waits for #719. If #846 lands a common prologue for every entry, the same table can drive a runtime check there; that is optional and not needed for the pin.
- [ ] Negative controls: run the same classifier over a synthetic handler that signs without a confirm and require it to fail, and assert that every confirm token the classifier searches for still occurs in a real handler, so a rename cannot make the test pass by matching nothing.
- [ ] **Documentation.** Add a "prompts the user" column and an output-class column to the audit table, and add a dated, additive note to the acceptance record with the one fact that has moved since it was written: per-signature time on pq1 is now measured at about 6.4 to 7.2 s on the `test-key-speed` path, so the harvest per 120 s window is EXPECTED to be far below the recorded 60 to 80 (the research's estimate is 12 to 17; nobody has timed command 15 itself). The note must say that the disposition is unchanged.

## What it needs

Host tests and documentation only. No firmware behaviour change, no flash, no wire format.

## Limits

- The tests pin source text, not behaviour. They catch the cheap regressions (a new silent handler file, a new signer call site) and nothing subtler. Confirm-before-sign ordering stays with the existing per-handler tests.
- The "one file" claim rests on text counts per file, not on a call-graph analysis.
- The note to the acceptance record must be additive and dated, so it cannot be read as reopening the decision.
- Not checked by me: whether an in-flight handler guard can extend the idle window across calls, which matters before anyone writes that the 250-per-session cap is unreachable.

## Related

#181, #89, #719, #846, #859, #84. Precedent for auditing the no-prompt command set, as an analogy for the practice only: Ledger [LSB-025](https://donjon.ledger.com/lsb/025/) and [LSB-022](https://donjon.ledger.com/lsb/022/).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report items X3a, section 12, and the surviving part of USB-06, section 10). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
