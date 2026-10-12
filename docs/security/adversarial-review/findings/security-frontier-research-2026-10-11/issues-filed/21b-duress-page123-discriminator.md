TITLE: duress-pin: page-123 counters have no wallet discriminator, so OFFCHAIN_STATUS after a decoy unlock shows the real wallet's counts
LABELS: finding,priority:medium,surface:lifecycle,surface:offchain,source:frontier-research-2026-10
---
## Summary

The duress feature gives a coerced user a decoy wallet. The per-slot counters on flash page 123 are keyed by account, chain and slot only. Nothing separates the real wallet's counters from the decoy's. After a decoy unlock, `CMD_OFFCHAIN_STATUS` reports the real wallet's off-chain and UserOp counts, which tells a coercer that another wallet exists and has been used.

`duress-pin` is not in the shipping feature set (#636), so this is a prerequisite for enabling it, not a defect in a shipping image.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

- `secure/src/offchain_state.rs:23-33`: the key is derived from `account_index`, `chain_id` and `slot_index` (`:26-28`). No "duress" or "decoy" input appears in this file, in `secure/src/nsc/cmd_offchain_status.rs` (`:36`, `:75-79`) or in `secure/src/nsc/state.rs`.
- Gating feature: `duress-pin` in `secure/Cargo.toml` (`= ["dual-se", "optiga-hw-counter"]`). The page-123 code itself is not gated; the leak exists once a second wallet does.

## Two smaller duress items

- `secure/src/nsc/mod.rs:1567`: the wipe-on-duress path does `let _ = se.factory_reset_admin();`, discarding the result. On the USB arm the returned `PinLocked` then runs the normal lockout wipe, which does reset page 124. On the boot and idle arms page 124 stays charged; the comment at `:1542-1543` says that is intended. Re-check verdict: partly.
- The SE050 duress objects are missing from every wipe list while three comments say they are reclaimed. That is already #107.

## Severity and evidence level

- Severity: **medium** (a deniability failure; no key or fund compromise).
- Evidence: code read; re-checked independently. Whether decoy signing also writes the real wallet's counters was not traced (same key, so likely). No CI job compiles `duress-pin`.

## Fix directions

- [ ] Add a wallet discriminator to the page-123 key before `duress-pin` is enabled anywhere.
- [ ] Consume the duress wipe result.
- [ ] Add a CI job that at least compiles `duress-pin`.

## Related

#636 (parent), #107, #280, #370, #123.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item pin-04 / M14, defect row B3). Re-checked before filing by an independent read at `c75b0d9c` (page-123 claim confirmed; wipe-error claim partly). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
