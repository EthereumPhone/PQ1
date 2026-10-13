# VULN — CMD_OFFCHAIN_SYNC page-123 exhaustion → permanent, unrecoverable signing brick

**Severity:** HIGH (availability — software-triggerable, unrecoverable permanent brick, post-provisioning, no physical fault injection).
**Status:** FIXED 2026-06-30 (working tree). Two-layer fix — confirm-gate new-slot SYNC + structural distinct-slot cap; see [§ Fix applied](#fix-applied).
**Class:** Denial-of-service / device brick. **Not** theft — the seed (and therefore funds) remains recoverable on a *different* device; the affected device itself becomes permanent e-waste for all signing.
**Not a ship-blocker / not previously known:** distinct from the OPTIGA S-1/S-2/S-3 + SE S-7d ship-blockers, from F3 (physical torn-compaction), and from the FW-COMMIT OTP-before-manifest brick (fixed 2026-06-30). The handler's own "Security note" explicitly argues this primitive is harmless — it overlooks the durable-write side-effect.

## Summary

`CMD_OFFCHAIN_SYNC` (cmd 18, USB `INS_V2_OFFCHAIN_SYNC = 0x64`) lets the **untrusted** companion write a durable page-123 journal entry for a **companion-chosen, seed-independent** `(account_index, chain_id, slot_index)` tuple, with **no user confirmation, no rate limit, and no distinct-slot cap** — gated only on `pin_verified`. By spraying ≥512 distinct tuples (e.g. iterating `chain_id`), a malicious companion fills page 123 with >256 distinct live slot keys. The page then can never be compacted (compaction fail-closes on `overflow` *before* erasing) and never be bulk-erased (the self-heal refuses while live entries exist). Because **every** signing path writes page 123 *after* computing the signature and returns `InternalError` when that write fails, the device can no longer produce **any** UserOp / EIP-1271 / batch signature for **any** account/chain/slot. No in-firmware path erases page 123, and the slot keys are seed-independent, so the wedge survives a 10-wrong-PIN factory wipe, the dev `make wipe-for-wizard`, and a restore-from-seed. Only a full firmware re-flash (`make factory-reset`, i.e. physical JTAG/probe access) recovers — out of reach for an end user.

## Reachability (attacker = untrusted USB companion, device correctly locked + provisioned)

Precondition: the user has unlocked once with the correct PIN (normal operation; `pin_verified` set). The attacker is a malicious/compromised companion app or a malicious dapp driving a legitimate companion over USB.

1. `INS_V2_OFFCHAIN_SYNC` (0x64) routes to `cmd_offchain_sync::run` — `nonsecure/src/usb/commands.rs:240`, dispatched unconditionally in production at `secure/src/nsc/mod.rs:1211` / `:1681` (no feature gate).
2. `cmd_offchain_sync::run` (`secure/src/nsc/cmd_offchain_sync.rs:40`) checks only `pin_verified` (line 43) — **no `confirm()`, no rate limit, no distinct-slot cap** — then calls `last_userop_count_set(slot_key, target_count)` (line 87) with attacker-supplied `account_index ≤ 255`, full-`u64` `chain_id`, full-`u32` `slot_index`, arbitrary `target_count`.
3. `slot_key = sha256(account_index ‖ chain_id ‖ slot_index)[..8]` — `secure/src/offchain_state.rs:23` — is **attacker-chosen and seed-independent** (no `master_secret`/entropy input).
4. For a fresh tuple, `last_userop_count_set` (`secure/src/hw/flash.rs:1952`) reads `pre = 0`, neither no-op branch fires (`count < pre` false; `count == pre && registered` false because the slot is unregistered), so it calls `write_entry` → appends one `OFFCHAIN_TYPE_USEROP` quad-word. Holds for **any** `target_count` (including 0).
5. Page 123 capacity is `OFFCHAIN_CAPACITY = 512` quad-words (`flash.rs:1238`). 512 distinct-tuple syncs fill it with 512 distinct live slot keys.
6. The next `write_entry` (`flash.rs:1609`) finds no blank → `compact_page()` (`flash.rs:1503`). `scan_page_into_table` flags `overflow` when a 257th distinct slot key is seen (`flash.rs:1449`, `MAX_ACTIVE_SLOTS = 256`). `compact_page` returns `Err` **before** `erase_offchain_page()` (`flash.rs:1522-1524`), and the `?` aborts `write_entry`. The self-heal bulk erase is unreachable too — it is gated by `!offchain_page_has_live_entries()` (`flash.rs:1641`), and the page is full of live `USEROP` entries.
7. Page 123 is now **permanently un-writable**. Every signature path writes it *after* computing the sig and refuses to release the sig on failure:
   - `cmd_sign_userop.rs:1758` (`last_userop_count_set`) and `:1779` (`userop_sigs_bump`) → `InternalError` ("Sig commit FAIL").
   - `cmd_sign_offchain.rs` (count bump) and `cmd_sign_userop_batch.rs` likewise.
   → No UserOp, EIP-1271, or batch signature can ever be produced again, for any account/chain/slot.

## Unrecoverability

`erase_offchain_page` (`flash.rs:1369`) has exactly two callers, both unreachable in the wedged state: `compact_page` (refuses on `overflow` before erasing) and the `write_entry` self-heal (refuses while live entries exist). Beyond those:
- `trigger_lockout_wipe` (10-wrong-PIN factory reset, `cmd_request_unlock.rs:155`) wipes the SEs + page 124 + SRAM — **never page 123**.
- `make wipe-for-wizard` (`secure/src/main.rs:3099`) wipes OPTIGA/SE050 objects + page 124 + SRAM — its own doc comment lists what it touches; **page 123 is not in it**.
- First-boot wizard / provisioning never erase page 123.
- Slot keys are seed-independent (step 3), so **restore-from-seed on the same device leaves the page wedged**.

Only `make factory-reset` (mass-erase + re-flash, i.e. physical JTAG/probe access) clears it. An end user of the $149 consumer device has **no recovery path**.

## Why HIGH

Matches the rubric's HIGH definition: "an unrecoverable permanent brick triggerable post-provisioning." A single malicious-companion session (after one ordinary PIN unlock) — ~512 × 21-byte APDUs, well under a second over USB, **zero user confirmations** — permanently destroys all signing capability of a correctly-provisioned device. Funds stay seed-recoverable on another device, so it is availability, not theft → HIGH, not CRITICAL.

## Root cause

`CMD_OFFCHAIN_SYNC` is a confirm-free, untrusted-companion-driven primitive that can **create an unbounded number of distinct durable page-123 entries**. The fixed 512-entry page + the (correct, anti-rollback) HIGH-1 decision to *refuse* compaction on >256 distinct slots together turn "too many distinct slots" into a permanent, self-inflicted wedge, because no path ever reclaims the page. The handler's "Security note" reasons only about the *value* being set ("no stronger than the existing slot-rotation flow") and misses the durable-write side-effect for arbitrary fresh slot keys.

## Suggested fixes (design choice for the owner)

1. **Gate new-slot SYNC behind a trusted-display confirm.** When `!offchain_count_is_registered(slot_key)`, require an affirmative `confirm()` ("Sync chain N slot M?") before the durable write. Legitimate post-reflash sync is a rare, deliberate recovery action; a 512-distinct spray would need 512 confirms (infeasible). Matches the confirm-gating of every other state-creating path. (Lowest-risk; preserves the legit post-reflash use case.)
2. **Bound distinct page-123 slots and make overflow recoverable.** On `compact_page` overflow, evict the oldest surplus `USEROP`/`last_userop` entries instead of permanently refusing — those are backstopped by on-chain `_setOffchainSigCount` monotonicity + the `MAX_OFFCHAIN_GAP` gap (per the F3 comment), so bounded eviction does not enable the counter-rollback the HIGH-1 fix prevents for `userop_sigs`. Keep `userop_sigs` non-evictable; cap distinct slots well below 256.
3. **Refuse SYNC once page-123 distinct-slot occupancy crosses a safe threshold** (fail the SYNC, not the device), so a spray cannot reach the wedge state.

Recommended: (1) alone closes the reported attack with minimal blast radius; combine with (3) as defense in depth.

## Fix applied

Implemented 2026-06-30 (working tree) as two independent layers — suggested fix (1) **and** a structural form of (3). Eviction/erase (suggested fix (2)) was deliberately **not** taken: it would reset the non-evictable `userop_sigs` few-time-key tally and weaken HIGH-1/F3.

**Layer 1 — confirm-gate new-slot SYNC (stops the attack).** `cmd_offchain_sync::run` now requires a trusted-display `confirm()` before the durable write whenever the target slot is **not already registered** (`!offchain_count_is_registered`). Decline ⇒ refuse (`UserRejected`), no write. Re-syncs of an already-registered slot stay confirm-free (idempotent floor bumps). A 512-distinct spray would need 512 physical confirms. The consent gate sits *before* the durable write (the `cmd_sign_offchain` MEDIUM-3 "defer the durable write until after confirm" discipline). The confirm (originally a 2-page "SYNC COUNTER?"; since 2026-10-13 the 4–5-page plain-language "Update signature count?" dialog with a remaining-budget row and a `! CAREFUL` page, see the value-inflation VULN Layer C) is `secure/src/tx/display/offchain_sync.rs` (`build_offchain_sync_pages`). The handler's stale "Security note" was rewritten to record the durable-write side-effect.

**Layer 2 — structural distinct-slot cap (page provably un-wedgeable).** New `offchain_state::MAX_DISTINCT_SLOTS = 128` + pure policy `may_create_distinct_slot(distinct_live, already_present)`, enforced at the single durable-write chokepoint `hw::flash::write_entry` (new lightweight `distinct_slot_count_capped` scan, ~1 KB stack, runs only on the new-slot branch) and mirrored by the host/QEMU mock backend's table size (`MAX_SLOTS = MAX_DISTINCT_SLOTS`). A brand-new slot is refused once 128 distinct are live; updates to existing slots always succeed (the cap sits *above* `compact_page`, which bypasses `write_entry`). Because a slot occupies ≤3 QWs after compaction, `128 × 3 = 384 ≤ 512` and `128 ≤ 256` ⇒ **compaction can never fail** ⇒ no brick by construction, for any caller (not just SYNC). This is a device-lifetime budget on distinct `(account,chain,slot)` tuples ever used; at the cap, new-slot creation fails *gracefully* (existing slots keep signing). Structural max is 170 if more headroom is ever needed.

**Tests / verification.** Host suite green (2016 passed / 0 failed) including 5 new tests: exhaustive `may_create_distinct_slot` policy, structural const-proof (`MAX_DISTINCT_SLOTS*3 ≤ 512 ∧ ≤ 256 ∧ == 128`), mock-backend cap source pin, flash `write_entry` cap wiring pin, and the handler confirm-gate pin (incl. confirm-precedes-write ordering). `stm32u585` debug type-check clean (compiles the flash-side code, host-untested otherwise) and a release+link hardware build clean. Files: `secure/src/{offchain_state.rs, hw/flash.rs, nsc/cmd_offchain_sync.rs, tx/display/offchain_sync.rs, tx/display/mod.rs}` + tests in `secure/src/{secure_crypto_glue_under_test/pure_tests.rs, nsc_batch_offchain_pure_tests.rs}`.

## Discovery

Found in the 2026-06-30 ultracode CRITICAL/HIGH hunt (wave 2, `offchain-counter-store-desync` finder), independently CONFIRMED by two adversarial verification lenses (exploitability + novelty/severity) and then re-verified by hand against the source end-to-end (handler → slot_key → flash state machine → every sign path → all recovery paths).
