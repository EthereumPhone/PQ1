# First-boot self-provisioning — device-side requirements

Status: normative requirements for the `rdp2-self-lock` flow (2026-07-21).
Companion to [`first-boot-provisioning.md`](first-boot-provisioning.md) (the
operator/field runbook, factory⇄device split, error codes, and silicon
runbook). This document states only **what the on-device flow must do** — it
grants no production authority; the handoff/receipt, authenticate-before-rotate,
recovery-adequacy, E140-ordering, and silicon gates tracked there remain OPEN.

Requirement keywords are RFC-2119 (**MUST / MUST NOT / SHOULD**).

---

> **UPDATE 2026-10-27: owner direction changes this split (design only, NOT implemented).**
> The factory raises the MCU to **RDP-1** and installs the **final** SE050/OPTIGA credentials, derived on-die from the per-die DHUK alone (no page-126 BHK, no page-127 salt).
> It then regresses RDP 1→0 (mass erase) and ships at RDP-0 with only a small prover in flash.
> The user verifies the device in the Vault app with a USB proof of secure erasure: fill all flash with random data, unplug and replug, read everything back.
> This reverses "no factory RDP burn of any level", "factory MUST NOT install a final credential", and the first-boot transport→final rotation.
> It also moves WRP staging from the factory to first boot.
> Until implemented, the text below still describes the current code.
> Design, prerequisites and the open RDP-1-in-transit caveat: [`user-device-verification.md` § USB path](../security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

## 0. Scope and division of labor

The device-side flow performs exactly **one MCU-irreversible action** (the
RDP-2 burn) and a set of **secret rotations** off the factory transport
keysets. Everything else — the entire option-byte profile *except RDP*
(TZEN, SECWM, SECBOOTADD0, **WRP1A over the FSBL pages**, BOR, OEM locks),
the OTP-master burn, and all SE-internal structure and irreversible locks —
is staged at the **factory** while the device is at RDP-0 and therefore
user-verifiable over SWD before first power.

Rationale (invariant #10): the user verifies *state*, not code promises. WRP
is reversible at RDP-0, so factory staging costs nothing; deferring the WRP
write into first boot would create a fault-injection / power-cut window in
which RDP-2 could burn with the FSBL unprotected — an unrecoverable forfeit
of the verify-once guarantee. The device therefore **verifies** the staged
lock and **only then** welds it shut.

## 1. Placement in the boot sequence

- **R1.1** The entire flow MUST run before the seed wizard, before the first
  PIN entry, and before any wallet secret exists on the device.
- **R1.2** Phase A MUST run at earliest secure boot, before SE traffic, USB
  bring-up, or any per-device flash write.
- **R1.3** The flow MUST be a no-op on every boot after completion: RDP
  already at Level 2 → skip Phase A; page-127 journal shows ALL_DONE → skip
  Phase B. (Idempotence is the resume mechanism, not an optimization.)

## 2. Phase A — verify the ship state, then self-lock (pre-lock, MCU point of no return)

- **R2.1 (verify, don't set).** Phase A MUST read back and verify the full
  published ship option-byte profile (`shared/src/lockdown.rs`
  `SHIP_PROFILE_U585`): TZEN=1, SECWM1/2, SECBOOTADD0, **WRP1A covering the
  FSBL pages**, OEM-locks state. The flow MUST NOT program WRP or any option
  byte other than RDP itself. A missing or wrong WRP1A is a hard fail, never
  something Phase A "fixes" — a unit that reaches the field unstaged is not a
  genuine ship unit.
  *(UPDATE 2026-10-27: under the owner direction above, R2.1 stops being verify-only for WRP1A, because WRP staging moves on-device before RDP-2. R2.3's transport-keyset role goes away.)*
- **R2.2 (blank per-device pages).** Pages 123–127 MUST be blank-checked
  before locking. A pre-planted page-127 journal would spoof "already done"
  and a pre-planted salt would make the final OPTIGA PBS predictable.
- **R2.3 (OTP master present).** The factory OTP-master burn MUST be
  confirmed present (it is the root of the transport keysets Phase B
  authenticates against). Absent → fail before the lock.
- **R2.4 (confirm gate — owner decision 2026-07-17, not yet implemented).**
  The RDP burn MUST NOT run automatically on first power. The trusted UI
  MUST display an explicit "Confirm to lock device — after that verification
  over SWD not possible anymore." prompt and wait for a deliberate on-device
  button sequence. Until confirmed the device MUST stay at RDP-0, touch no
  SE/USB/journal state, and re-enter the same prompt on every boot.
- **R2.5 (the burn).** Only after R2.1–R2.4 pass MAY the flow program
  RDP=0xCC and issue `OBL_LAUNCH` (which resets the MCU). If the launch
  fails to reset, the flow MUST park (never continue executing below RDP-2).
- **R2.6 (fail unlocked).** Every Phase-A fault MUST halt with the unit
  still at RDP-0 — returnable and reflashable. Phase A MUST NOT convert a
  bad flash, bad profile, or failed burn into an RDP-2 brick.
- **R2.7 (ordering, invariant #10).** R2.1 before R2.5 is the load-bearing
  order: WRP verified-set strictly before RDP-2. No refactor may reorder,
  weaken, or make conditional the WRP1A check on any path that can reach the
  RDP write.

## 3. Phase B — journaled secret rotation (post-lock, per-die DHUK now final)

All Phase-B steps MUST be recorded commit-LAST in the append-only page-127
journal and MUST be resumable across resets (§4). Order:

- **R3.1 BHK first-write.** Generate the BHK from the hardware TRNG, store
  DHUK-wrapped on page 126. The write MUST erase-and-reprovision
  (anti-pre-plant) and MUST be journal-gated so a torn write is retried, not
  trusted.
- **R3.2 SE050 SCP03 rotation.** Transport → final (BHK-rooted) via GP
  `PUT KEY`, key blocks wrapped under the transport DEK. Two-phase: the
  FINAL keyset MUST be confirmed live (successful re-establish) before the
  transport keyset is considered dead.
- **R3.3 SE050 admin credential re-key.** Transport → final (BHK-rooted),
  delete + recreate, same two-phase confirm discipline.
- **R3.4 OPTIGA PBS rotation.** Persist a fresh TRNG salt to the page-127
  journal **before** deriving or writing the final PBS (DHUK + salt), then
  rotate via shielded `SetData(E140)`, two-phase confirm. The salt record
  MUST be reserved in full (data QWs + completion markers) before the first
  program command; insufficient journal room fails closed with no write.
- **R3.5 Finalize.** Mark ALL_DONE, then continue into normal boot → seed
  wizard.
- **R3.6 (rotation only).** Phase B MUST NOT create SE objects/policies,
  ratchet any SE lifecycle state (LcsO, E140 metadata, F1D0), burn OTP, or
  touch any option byte. It rotates the pairing secrets it inherits —
  nothing else.

## 4. Power-loss and resume requirements

- **R4.1** Every step MUST be idempotent between completed flash quad-word
  programs; completion markers are written only after the step's effect is
  durable (commit-LAST).
- **R4.2** On a resume boot the flow MUST re-scan the journal, skip every
  completed step, and continue at the first incomplete one. Per-SE resume
  MUST probe the FINAL keyset first, then the TRANSPORT keyset; success on
  either determines where the step restarts.
- **R4.3** The recovery budget is finite (one 512-QW page). When the journal
  cannot hold a full pending record plus its completion markers, the flow
  MUST fail closed without writing.
- **R4.4** The UI MUST show "DO NOT POWER OFF" during Phase A's burn window
  and all of Phase B; a resume MUST display "RECOVERING / DO NOT POWER OFF",
  not an error.

## 5. Failure discipline

- **R5.1** Unrecoverable states fail **closed**, halting with a stable
  `EXXXX` code on the LCD (`first_boot/state.rs` `FirstBootError`; code
  table in [`first-boot-provisioning.md`](first-boot-provisioning.md)).
  Codes MUST remain stable across firmware versions.
- **R5.2** Class boundary: Phase-A faults (`0x080x`) halt **unlocked**;
  Phase-B faults (`0x081x`+) occur after the lock and route to RMA. No fault
  path may leave the device continuing into normal boot with a
  partially-rotated keyset.

## 6. Things the flow MUST NOT do (summary)

- Program or modify WRP or any option byte other than RDP (Phase A) — §2.1.
- Write anything into the FSBL flash range, ever (invariant #10).
- Burn RDP-2 before the WRP1A + blank-page + OTP-master + confirm-gate
  checks all pass — §2.7.
- Perform SE-internal irreversible provisioning (factory scope) — §3.6.
- Run under any dev/test feature: `rdp2-self-lock` is production-only,
  implies `bhk`, requires `dual-se`, and is compile-fenced against
  `debug-log` / `e2e-test` / `mock-se` (`nsc/mod.rs`; check with
  `make build-rdp2-self-lock`).
- Enter the seed wizard, accept a PIN, or expose USB before ALL_DONE.

## 7. Traceability

| Requirement | Code |
|---|---|
| R1.x boot wiring | `secure/src/main.rs` |
| R2.x Phase A | `secure/src/first_boot/mod.rs` `run_pre_lock_and_maybe_lock` |
| R2.1 profile comparators | `shared/src/lockdown.rs` |
| R2.5 RDP write path | `secure/src/hw/flash.rs` |
| R3.x state machine | `secure/src/first_boot/state.rs` |
| R4.x journal codec | `secure/src/first_boot/journal.rs` |
| R3.2–R3.4 SE rotations | `secure/src/se050/{mod,scp03}.rs`, `secure/src/optiga/mod.rs` |
| R2.3 OTP-master pre-lock | `run_pre_lock_and_maybe_lock` (`E0803`); Phase-B belt-and-braces keeps `E0811` |
| R2.4 confirm gate | **implemented 2026-07-21** — `state::build_lock_confirm_pages` + `confirm_checked` both-buttons chord + `rdp_burn_authorized`, gated before the burn in `run_pre_lock_and_maybe_lock` |

Gaps between this document and the code are defects in one or the other. As of
2026-07-21 the known device-side gaps (R2.3 mis-phasing, R2.4 confirm gate, the
collapsed `ObField` codes) are **closed**; what remains OPEN is not device-side
logic but the silicon/receipt/handoff/E140-ordering gates tracked in
[`first-boot-provisioning.md`](first-boot-provisioning.md) (incl. the
`OEM_LOCK_MASK_PINNED` fail-closed pin, `HW-ASSUME-PUTKEY-KCV-RESP`, and the
DEK-liveness `HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT` bench).

## 8. Factory input state — exactly what the factory must have done

The device-side flow assumes, and where possible verifies, the following
ship state. This list mirrors the canonical responsibility split in
[`first-boot-provisioning.md`](first-boot-provisioning.md#authoritative-factory--first-boot-responsibility-split)
(keep them in sync; the quarantined operator manual is
[`factory-provisioning.md`](factory-provisioning.md) — as of 2026-07-21
there is **no authorized factory ceremony**, so this section is required
*state*, not an operator instruction).

All factory steps run at **RDP-0** on the production line, under read-back
QA, before any secret exists on the MCU:

- **F1 Flash** the reproducible batch-uniform image: FSBL + secure + NS app
  into the A/B slots. Batch-uniform means byte-identical across every unit
  of a release — nothing per-device in flash.
- **F2 Option bytes** — the full ship profile (`lockdown.rs`
  `SHIP_PROFILE_U585`): TZEN=1, SECWM1/2, SECBOOTADD0, **WRP1A over the
  FSBL pages**, BOR_LEV, BOOT_LOCK/nBOOT, OEM-key finalization —
  **everything EXCEPT RDP, which stays 0**. There is no factory RDP burn of
  any level, on any path. (WRP is reversible at RDP-0, so this step is
  non-irreversible for the MCU; the user verifies it over SWD and Phase A
  re-verifies it as R2.1 before making it permanent.)
- **F3 OTP master** — burn the per-device OTP master from the factory TRNG
  (`otp::ensure_device_master`). Factory-side because the initial two-QW
  burn is not crash-retry-safe, and it is the root from which every
  transport keyset derives (HKDF; transport keys are
  public-by-assumption).
- **F4 SE050** — create the admin UserID + user-object OID
  structure/policies; rotate SCP03 from the AN12436 defaults to the
  per-device **transport** keyset (GP `PUT KEY` under `PLATFORM_DEK`);
  transport lock if applicable.
- **F5 OPTIGA** — write the **transport PBS** to E140 with metadata keeping
  the `Conf(E140)` arm so the PBS stays shield-rotatable (this is what
  makes R3.4 possible); F1D0 `Change=Auto(F1D0)` (S-1); close the candidate
  type-`0x11` Protected-Update anchor pool `{0xE0E8, 0xE0E9, 0xE0EF}`
  (SKU/revision inventory still to be pinned on silicon) and
  preserve/ratchet the device-certificate surfaces
  `{0xE0E0, 0xE0E1, 0xE0E2, 0xE0E3}` **without retyping them** (S-2 — *no
  ceremony is authorized*; this line previously named `0xE0E3` and
  `0xE0E4..0xE0E8`, which is wrong and not a harmless no-op — see the
  CORRECTION 2026-07-26 block in
  [`first-boot-provisioning.md`](first-boot-provisioning.md#authoritative-factory--first-boot-responsibility-split));
  provision the E120 LUC, bind F1D0 `Execute=LUC`, freeze the F1E1
  soft counter (S-3); **LcsO=Op ratchet** on the locked OIDs — the
  SE-internal point of no return stays on the factory line, never
  on-device.
- **F6** The #22 attestation/binding manifest burn (when it lands).
- **F7 Read-back QA** over SWD (connect-under-reset) against the
  reproducible build — encouraged, deliberately **not** load-bearing (the
  user's own verification is the load-bearing check).
- **F8 Ship at RDP-0** with SWD + NRST pads accessible. Pages 123–127
  blank. The only SE pairing material in existence is the public transport
  values.

*(UPDATE 2026-10-27: owner direction reverses the RDP and final-credential clauses below. See the note under §0.)*
Factory MUST NOT: program RDP to any level; perform the BHK write; install
any final (post-rotation) pairing credential; create or ever see a wallet
seed; write anything to pages 123–127; retain any per-device secret beyond
the transport keysets (which first boot rotates dead).

Verification coverage from the device side: Phase A directly verifies F2
(R2.1), F8's blank pages (R2.2), and F3's presence (R2.3). F1 is verified
by the *user* over SWD plus the FSBL measurement, not by this flow. F4/F5
are only indirectly checked — Phase B's rotations fail with `E08F0` if the
SEs are not in the expected transport state — and their irreversible
ordering + silicon receipts are exactly the OPEN ship-blocker gates
(S-1/S-2/S-3).
