# VULN — CMD_OFFCHAIN_SYNC unbounded `target_count` → consent-free durable slot brick (value-inflation)

**Severity:** HIGH (availability — software-triggerable, durable/seed-survivable, no user consent, post-provisioning; escalates to a permanent full-device brick). A strict single-slot reading floors at MEDIUM; see [§ Severity](#severity).
**Status:** FIXED (found 2026-07-01, fixed 2026-07-01 — see [§ Fix applied](#fix-applied)).
**Class:** Denial-of-service / device brick. **Not** theft/forgery — the seed (and funds) stay recoverable on another device; the affected slot(s) become permanent e-waste for signing.
**Distinct from the fixed sibling:** [`docs/VULN-offchain-sync-page123-exhaustion-brick.md`](VULN-offchain-sync-page123-exhaustion-brick.md) (FIXED 2026-06-30) is the **distinct-slot SPRAY that wedges page-123 compaction**. This is a **different root cause in the same command**: the unbounded *value* written to `last_userop` is durably promoted into the monotonic `local_offchain` counter past `MAX_SLOT_USES`, tripping the combined-cap gate forever. Neither layer of the 2026-06-30 fix closes it — Layer 1's confirm-gate explicitly **exempts already-registered slots** ("idempotent floor bumps stay confirm-free"), and Layer 2's `MAX_DISTINCT_SLOTS = 128` is the *enabler* of the full-device escalation, not a mitigation.

## Summary

`CMD_OFFCHAIN_SYNC` (cmd 18, USB `INS_V2_OFFCHAIN_SYNC = 0x64`) lets the **untrusted** companion write a fully companion-controlled `u64 target_count` (offset 13, **no clamp** to `MAX_SLOT_USES`) into the durable per-slot `last_userop` counter. For a slot the wallet has **already registered** (i.e. any slot the user has ever used), the handler **skips the trusted-display confirm** and writes it silently. The next sign for that slot durably promotes `last_userop` into the monotonic `local_offchain` counter, pushing it past `MAX_SLOT_USES`; the combined-cap gate then refuses **every** future signature for that slot — permanently, across power cycles and restore-from-seed.

## Reachability (attacker = untrusted USB companion, device correctly locked + provisioned)

Precondition: one ordinary PIN unlock (normal operation; `pin_verified` set). Attacker is a malicious/compromised companion app or a malicious dapp driving a legitimate companion over USB (the documented threat model). No physical access, no fault injection, **no user confirmation**.

1. `INS_V2_OFFCHAIN_SYNC` (0x64) → `cmd_offchain_sync::run`, dispatched **unconditionally in production** at `secure/src/nsc/mod.rs:1211` (no feature gate).
2. `cmd_offchain_sync::run` gates only on `pin_verified`. The **confirm gate only fires for UNregistered slots** (`secure/src/nsc/cmd_offchain_sync.rs:107` — `if !offchain_count_is_registered(&slot_key) { confirm() }`). For a registered slot it falls straight through to the durable write.
3. `secure/src/nsc/cmd_offchain_sync.rs:132` — `last_userop_count_set(&slot_key, target_count)` with attacker-chosen `target_count`. **No upper clamp** anywhere: `hw::flash::last_userop_count_set` (`flash.rs:2021`) writes any `count >= pre` verbatim.
4. The FI double-read guard in the sign handlers only rejects the exact value `u64::MAX`; the attacker picks `target_count = MAX_SLOT_USES` (`= 65536`) — passes the `== u64::MAX` check, still ≥ the cap.

### The durable brick (any subsequent sign, itself confirm-free)

- `CMD_SIGN_OFFCHAIN` for that slot: §6 promote runs **before** the §7b/§9 user confirm — `secure/src/nsc/cmd_sign_offchain.rs:289-297`:
  ```
  if last_userop > local_offchain {
      offchain_count_promote_to(&slot_flash_key, last_userop)   // DURABLE flash write, line 290
      local_offchain = last_userop;                             // now = 65536
  }
  ```
  `offchain_count_promote_to` (`flash.rs:1988`) writes the value verbatim (no clamp). Then the cap check at `cmd_sign_offchain.rs:321-331` (`new_count = local_offchain + 1 = 65537 > MAX_SLOT_USES`) returns `OffchainCapExceeded` **before** reaching the confirm at §9. So the attacker triggers the durable brick itself with **zero user interaction**.
- `CMD_SIGN_USEROP` for that slot: same promote at `cmd_sign_userop.rs:1320-1337` (`new_offchain_count = local.max(last_userop)` → `offchain_count_promote_to`), durable; the combined-cap gate at `cmd_sign_userop.rs:1304` refuses thereafter.

Once `local_offchain >= MAX_SLOT_USES`, the combined-cap gate `userop_sigs.saturating_add(local_offchain) >= MAX_SLOT_USES` (`cmd_sign_userop.rs:1304`, `cmd_sign_offchain.rs:328`) permanently refuses. Counters are **monotonic with no reset path** (invariant #7), so the slot is dead forever.

## Unrecoverability

Same as the sibling brick: page-123 state is not wiped by the 10-wrong-PIN factory reset (`cmd_request_unlock.rs`), `make wipe-for-wizard`, or restore-from-seed (the `slot_key` is **seed-independent**: `sha256(account_index ‖ chain_id ‖ slot_index)[..8]`, `offchain_state.rs:23`). Only a full firmware re-flash (`make factory-reset`, i.e. physical JTAG/probe) clears it — out of reach for an end user of the $149 consumer device.

## Escalation to a permanent full-device brick

Recovery from a per-slot brick is a slot rotation (`FLAG_REGISTER_SLOT`, companion-selected `slot_index` — invariant #8). But:
- The attacker **re-bricks** each newly-registered slot with 2 confirm-free APDUs, faster than the user can rotate (1 confirmed Type-1 rotation).
- Every distinct `(account, chain, slot)` registration consumes one of the **device-lifetime** `MAX_DISTINCT_SLOTS = 128` budget (`offchain_state.rs:64`). Once 128 distinct slots have been registered-then-bricked, `may_create_distinct_slot` returns `false` and **no new slot can ever be registered** → total, seed-survivable brick of **all** signing.

The full-device brick requires ~128 user-consented registrations (each new-slot registration needs a confirm), so it is a slower burn than the sibling's single zero-confirm session — but the terminal state is identical (permanent full brick), and the per-slot damage along the way is durable and consent-free.

## Severity

- **Floor (strict single-slot reading): MEDIUM.** One bricked slot is recoverable by rotating `slot_index`.
- **Assessed: HIGH.** The brick is durable, seed-survivable, unrecoverable except by JTAG — the repo rubric's HIGH criterion, and exactly how the sibling page-123 brick is rated. Recovery is attacker-sabotageable (asymmetric: 2 confirm-free APDUs to brick vs 1 confirmed rotation to recover) and bounded by the 128-slot lifetime cap, converging on a permanent full-device brick. It defeats a fix that landed 2026-06-30 by refuting its stated "the *value* set here is harmless" safety rationale (`cmd_offchain_sync.rs:22-25`).

## Root cause

`CMD_OFFCHAIN_SYNC` treats a re-sync of an already-registered slot as an "idempotent floor bump" and skips consent, but the *value* is unbounded and is durably promoted into the monotonic `local_offchain` counter, which the combined-cap gate reads. A "floor bump" to `>= MAX_SLOT_USES` is not idempotent — it is an irreversible slot kill. The handler's security note reasons only about on-chain monotonicity of the value and misses the **firmware-side** combined-cap consequence.

## Suggested fixes (design choice for the owner)

1. **Clamp `target_count` to `<= MAX_SLOT_USES` at the source** (`cmd_offchain_sync.rs` before line 132) and clamp the promote target to `<= MAX_SLOT_USES` in the sign-path promotes (`cmd_sign_offchain.rs:290`, `cmd_sign_userop.rs`). A legitimate on-chain `offchainSigCount` can never exceed the cap, so the clamp never rejects a legitimate sync. (Lowest-risk; closes the reported attack.)
2. **Clamp inside the flash setters** `last_userop_count_set` / `offchain_count_promote_to` (`flash.rs:2021` / `:1988`) to `min(count, MAX_SLOT_USES)`, so every caller inherits the bound (defense in depth).
3. Optionally also confirm-gate a value-inflation sync (a `target_count` that raises `last_userop` by more than a small delta) on registered slots, mirroring the unregistered-slot gate.

Recommended: (1) + (2) — a pure clamp with no UX cost, since the on-chain floor a legitimate sync mirrors is itself always `<= MAX_SLOT_USES`.

> **Off-by-one note (corrected in the applied fix):** the clamp ceiling must be
> `MAX_SLOT_USES - 1`, **not** `MAX_SLOT_USES`. The combined-cap gate refuses at
> `>= MAX_SLOT_USES` (`cmd_sign_userop`) / promotes then refuses at
> `offchain + 1 > MAX_SLOT_USES` (`cmd_sign_offchain`), so a counter of exactly
> `MAX_SLOT_USES` still bricks. A truthful on-chain `offchainSigCount` is always
> `< MAX_SLOT_USES` (strict on-chain cap `slotUses + offchainSigCount < MAX_SLOT_USES`),
> so clamping to `MAX_SLOT_USES - 1` never clips an honest sync.

## Fix applied

Landed 2026-07-01 (working tree). Two defence-in-depth layers, mirroring the
sibling page-123 fix's "consent + structural cap" shape:

**Layer A — structural clamp (closes the permanent, cap-tripping brick).**
Single source of truth in `secure/src/offchain_state.rs`:

```rust
pub const OFFCHAIN_COUNT_CEILING: u64 = sphincs_tz_shared::MAX_SLOT_USES - 1;
pub const fn clamp_offchain_count(count: u64) -> u64 { /* min(count, ceiling) */ }
```

Every durable writer of the `offchain` / `last_userop` counters funnels through
`clamp_offchain_count`, so a single missed site cannot re-open the hole:
- source-side in `cmd_offchain_sync::run` (before the durable write);
- `hw::flash::last_userop_count_set` and `hw::flash::offchain_count_promote_to`
  (production, `stm32u585`);
- both mock-backend setters in `offchain_state.rs` (host/QEMU parity).

A clamped counter is always `< MAX_SLOT_USES`, so the combined-cap gate still
admits at least one signature — the permanent, consent-free, seed-survivable
brick is now **unreachable**. Reaching the cap requires a real, user-confirmed
signature (the legitimate exhausted state), never a bare sync APDU. The clamp is
a no-op for every honest sync (the mirrored on-chain floor is always in range).

**Layer B — consent gate on value inflation (closes the consent-free
near-exhaustion).** `cmd_offchain_sync::run` now requires a trusted-display
`confirm()` not only for a new slot but also whenever the sync would **raise** the
stored `last_userop` on an already-registered slot (`raises_floor = target_count >
last_userop_count_read(slot_key)`). A raise legitimately occurs only on genuine
recovery (post-reflash catch-up — itself a new slot — or a rare multi-device floor
advance), so honest users pay at most one confirm, while a hostile companion can
no longer silently burn a registered slot's few-time budget toward exhaustion (the
lever that would otherwise force the slot-rotation treadmill into the
`MAX_DISTINCT_SLOTS` full-device brick). Idempotent re-syncs (`target <= stored`)
stay confirm-free. The read is fail-safe: a glitch over-gates (an extra confirm),
never under-gates.

**Residual:** none on the availability axis for this vector. The permanent brick
is structurally unreachable (Layer A) and consent-free near-exhaustion is denied
(Layer B). A single confirmed inflation could still advance a registered slot's
floor, but that is user-consented and recoverable by slot rotation — the same
posture as any other confirmed slot use.

> **UPDATE 2026-10-13 — the residual above was wrong when written; corrected.**
> The 2026-10-13 security sweep (finding #2) showed two gaps:
>
> 1. **"Recoverable by slot rotation" was false.** Wire v2 returned the
>    bootstrap Type-1 signature over `addOwnerBytes(newOwnerBytes)` without the
>    64-byte `newOwnerBytes`, so a seedless companion could not rebuild the
>    signed UserOp (#353). A slot exhausted on-chain froze the wallet's funds
>    on that chain. Fixed by protocol **0x0203**: the Type-1 section is now
>    `new_owner_bytes(64) || wrapper(4128)`, copied out of the exact signed
>    calldata and FI-bound before release.
> 2. **The clamp did not stop a confirmed sync from exhausting a used slot.**
>    The ceiling is `MAX_SLOT_USES - 1` regardless of the slot's Type-2 tally,
>    and the device cannot see on-chain `slotUses`. A hostile companion could
>    pick `target = 65,535 - slotUses` so the owner's next ordinary Type-2 fills
>    the on-chain combined cap exactly, behind a screen that showed only bare
>    "Current / Target" numbers. Fixed by **Layer C** (owner decision: refuse +
>    warn): `pqsigner_aa::offchain_gate::sync_verdict` refuses a sync that would
>    leave the slot 0 signatures (no dialog, no write); a jump > 1,000 or
>    < 1,000 left adds a `! CAREFUL` page; and the dialog is reworded for users
>    ("Update signature count?", "On device / From app / Sigs left"). Kani
>    `sync_verdict_is_sound` proves that every sync the policy admits leaves
>    the slot signable for **any** prior Type-2 tally, which lifts the
>    `userop_sigs == 0` assumption of `offchain_sync_never_bricks`.
>
> **Residual now:** the device cannot see on-chain `slotUses`, so a restored
> device (tally 0) can still be steered to a confirmed sync that exhausts a
> heavily used slot *without* tripping the refusal; it trips the `! CAREFUL`
> page unless the jump is ≤ 1,000, i.e. unless the slot already had fewer than
> about 1,000 signatures left on-chain. Either way the slot is now recoverable:
> rotate to the next slot (one bootstrap use).

**Tests / build.** Regression coverage added:
- `secure/src/secure_crypto_glue_under_test/pure_tests.rs` — pure clamp
  boundaries (incl. the exact attack value `MAX_SLOT_USES` and `u64::MAX`), the
  `OFFCHAIN_COUNT_CEILING == MAX_SLOT_USES - 1` off-by-one pin, an end-to-end
  mock-backend reproduction (`sync(MAX_SLOT_USES)` → promote → slot stays
  signable), promote-over-cap clamp, and source-text pins that both flash setters
  + both mock setters + the helper/ceiling stay wired.
- `secure/src/nsc_batch_offchain_pure_tests.rs` — source-text pins that the
  handler clamps `target_count` before the durable write and confirm-gates a
  floor-raising sync.

`cargo test -p sphincs-tz-secure --tests --release` → 2044 passed / 0 failed.
`stm32u585` firmware image builds clean.
