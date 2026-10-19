# First-boot hardware bring-up checklist (silicon-gated work)

**Purpose.** The device-side `rdp2-self-lock` first-boot flow is implemented and
host-tested, but every property that touches real silicon is **deferred** — it
cannot be validated in the dev environment. This document is the ordered,
actionable plan for when physical hardware is available: what to run, in what
order, what each result unblocks, and which code constant/gate to flip after
each bench passes.

It consolidates the silicon items scattered across
[`first-boot-provisioning.md`](first-boot-provisioning.md) (the detailed runbook
+ error-code table), [`first-boot-requirements.md`](first-boot-requirements.md)
(the normative spec), and
[`../../contracts/verification/docs/HW_ASSUMPTIONS.json`](../../contracts/verification/docs/HW_ASSUMPTIONS.json)
(the assumption ledger). Read those for the detail; use this as the checklist.

## Safety preamble (read before touching a board)

- **RDP-2 is irreversible.** A wrong option-byte burn permanently bricks the die.
  Validate every irreversible step on **sacrificial parts first**, same culture
  as the S-1/S-2/S-3 factory ceremony.
- **Every irreversible attempt needs a fresh owner instruction** naming the
  exact part / operation / range / artifact / operator / authorization window
  (`planning-and-review-workflow.md §11`). Authorization is consumed once a
  command may have launched; a failure does **not** authorize an automatic retry.
- Ship units are verified **connect-under-reset over SWD, before first power**
  (invariant #10). Keep SWD + NRST pads accessible.
- Nothing in this document grants production authority; it is the work that
  *earns* it.

---

## Phase 0 — Prerequisites (before any board test)

- [ ] **A flashable bench image exists.** Today no `rdp2-self-lock` image can be
      built: `mode-production` is blocked by `FW_ROLLBACK_PRODUCTION_BLOCKED`
      (`secure/build.rs`) and needs `FSBL_VENDOR_PUBKEY`; only host tests and the
      negative `make build-rdp2-self-lock` check run. **This is the hard
      prerequisite for everything below.** Stand up the `bench-ship-validation`
      configuration proposed in
      [`first-boot-provisioning.md`](first-boot-provisioning.md) §"Design note …
      bench-buildable image" — a config that satisfies the `nsc/mod.rs` self-lock
      fences and supplies a bench `FSBL_VENDOR_PUBKEY` WITHOUT claiming shipping
      status (stays incompatible with every dev/test feature, renders a loud
      non-shippable boot banner, excluded from release packaging). **Needs owner
      sign-off — it touches the rollback quarantine.**
- [ ] Sacrificial-parts inventory: ≥5 STM32U585 dev boards (B-U585I-IOT02A) for
      the RDP burn; ≥5 SE050E2 (`SE050E2HQ1/Z01Z3Z`, OEF `A921`, matching `PLATFORM_*`; the production part) for PUT KEY;
      the TRUSTMV3SHIELDTOBO1 for OPTIGA.
- [ ] Rigs: probe-rs/SWD; Ledger Donjon Scaffold (Vdd crowbar); a logic analyzer
      on I2C1/I2C2; FaultyCat/EMFI for the RDP-2 downgrade campaign.

---

## Phase 1 — RM0456 register pins (unblocks Phase A)

Two ship-profile checks currently **fail closed until silicon-pinned**, so a
genuine first boot halts at `E0809` (then `E080A`) before the burn. Pin the
register layouts against the STM32U5 reference manual (RM0456, st.com), then flip each
`const` in the commit that records **both** the RM0456 citation **and** a bench
readback.

- [ ] **WRP1AR** (`shared/src/lockdown.rs`, offset `0x58`): confirm
      `STRT[6:0]`, `END[22:16]`, `UNLOCK[31]`. → flip `WRP1A_MASK_PINNED = true`.
- [ ] **OEM-lock status register** (FLASH_NSSR vs FLASH_OPTSR, `FLASH_NS+0x20`)
      + the `OEM1LOCK`/`OEM2LOCK` bit positions (guessed 26/27). **Positive
      detection:** provision an OEM1 key on a sacrificial RDP-0 board and prove
      `verify_ship_profile` REJECTS it. → flip `OEM_LOCK_MASK_PINNED = true`.
- [ ] **SECWM1R1 `@0x50` / SECWM2R1 `@0x60`** offsets + PSTRT/PEND fields.
- [ ] **SECBOOTADD0** field alignment (`secboot_selects`).
- [ ] **`OPTWERR`** bit position in the SEC/NS status register used by
      `program_rdp_level2_and_launch`'s error check (`secure/src/hw/flash.rs`).
- [ ] **BOR_LEV** field (advisory today; pin before treating as load-bearing).

Until this phase completes, Phase-A silicon testing halts at `E0809`.

---

## Phase 2 — Phase-A silicon (the RDP-2 self-lock)

- [ ] **RDP 0→2 transition with TZEN=1** (`HW-ASSUME-RDP2`, issue #401): the
      exact OPTR-modify path, the `OPTSTRT` commit, `OBL_LAUNCH` reset behaviour,
      and the park-on-no-reset path. Confirm the burn preserves every non-RDP bit
      (invariant #10 depends on WRP surviving verbatim).
- [ ] **RDP-2 offensive downgrade campaign** (FaultyCat EMFI + Scaffold voltage
      against the lock, issue #401) — the single highest-leverage unverifiable
      premise; a success is a ship decision.
- [ ] **Confirm-gate interactive pass** (R2.4): on real LCD + the two GPIO
      buttons, verify accept (both-buttons chord → burn), decline (long-left →
      stays RDP-0, re-prompts next boot), and idle. Confirm the prompt blocks
      cleanly with SysTick/IWDG not yet started (no watchdog reset mid-confirm).
- [ ] **Flash/OTP torn-write** (`QW-ATOMIC` + `OTP-ONEWAY`, issue #399): reset-
      only recovery needs no glitcher (probe-rs); torn-master needs Scaffold.

---

## Phase 3 — Phase-B silicon (the SE credential rotation)

### SE050 SCP03 rotation

- [ ] **`HW-ASSUME-PUTKEY-KCV-RESP`** — drive a successful transport→final
      `PUT KEY` and capture the decrypted response body length. `{9,10}` ⇒ KCVs
      are echoed and `verify_put_key_response` checks them; `0` ⇒ no echo. **If
      KCVs ARE echoed, make the 0-length branch fail-closed**
      (`secure/src/scp03_logic.rs`).
- [ ] **`HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT`** — on an already-rotated part,
      re-`PUT KEY` the identical final keys wrapped under the FINAL DEK; a
      non-`0x9000` falsifies idempotency. **Only if accepted** may the
      DEK-liveness torn-write net be enabled as live code (it is deliberately
      NOT shipped today — a second in-place PUT KEY that would brick the flow if
      re-PUT is rejected).
- [ ] **`HW-ASSUME-PUTKEY-ATOMIC`** (ship-blocker, #398/#386): Scaffold crowbar
      on SE050 Vdd across the PUT KEY commit window (I2C trigger on
      `CLA=0x84 INS=0xD8 P1=0x0B P2=0x81`); per part cold-boot and probe
      **ENC/MAC and DEK independently**. A confirmed `ENC/MAC-final +
      DEK-transport` outcome is a **ship-blocker**. Procedure:
      `docs/security/red-teaming.md §5.7`.
- [ ] **Admin re-key**: `verify_session` under transport → delete → recreate
      under FINAL; confirm `SW=0x6986` admin-lockout behaviour does NOT trip
      (the admin UserID is unlimited-attempts).

### OPTIGA PBS rotation

- [ ] **`establish_transport_shield` handshake** at step 5 (the #443 fix): the
      transport-PBS PRL handshake comes up before the salt draw and the
      3-source TRNG can answer.
- [ ] **`SetData(E140)` wedge** (2–3 ops) timing bracketing the salt+PBS
      rotation; the E140 rewrite under the transport shield whether or not the
      factory ratcheted `LcsO=Op`; the re-shield-under-FINAL confirm.
- [ ] **Page-126 program-hostility** re-check on shipping silicon (the bench chip
      returns erase-OK / program-PROGERR) — gates the BHK first-write.

### Cross-cutting

- [ ] **`HW-ASSUME-DHUK-RDP12`** (issue #388): one-shot RDP-1 vs RDP-2 DHUK
      fingerprint compare — the per-die-DHUK-is-final premise Phase B rests on.
- [ ] **SAES Tier-1 (DHUK) self-test** passes on shipping silicon (`E0812` gate).

---

## Phase 4 — Power-cut durability matrix

- [ ] Induced power cuts at **every step boundary**, including the unavoidable
      `OPTSTRT` window and each SE-rotation commit. The host state-machine matrix
      (`first_boot::state::tests::power_cut_at_every_boundary_converges`) proves
      the **logic** converges; silicon must prove the **durability** — the
      journal, the salt record, and each two-phase rotation actually resume.
- [ ] Verify the resume discipline end-to-end: per-SE FINAL-then-TRANSPORT probe,
      the salt reserve-or-fail-closed, and the "RECOVERING / DO NOT POWER OFF"
      screen on a resume.

---

## Phase 5 — Owner decisions + factory-side gates (not device bring-up, but blocking)

- [ ] **Factory handoff/receipt mechanism.** Pick the PQ-clean signing authority
      (symmetric MAC under a factory-station key / SPHINCS+C10 verify against a
      pinned factory key / HSM-mediated record) before implementing the device
      `verify_factory_receipt()` over spare OTP `176..512`. Design note in
      [`first-boot-provisioning.md`](first-boot-provisioning.md).
- [ ] **E140 LcsO ratchet ordering** (owner-gated + silicon-gated): validate on a
      sacrificial part that an `LcsO=Operational` E140 authenticates with the
      transport PBS, accepts the new PBS via `Conf(E140)`, and re-establishes
      under the rotated PBS after a cut. The ratchet stays **factory-side** (R3.6
      forbids Phase B from ratcheting).
- [ ] **Factory ship-blockers S-1/S-2/S-3** (F1D0 `Change=Auto(F1D0)` + LcsO=Op
      ratchet; type-`0x11` trust-anchor pool neutralization; E120 LUC + F1E1
      freeze). Tracked under GitHub `label:ship-blocker`.

---

## "Flip after bench passes" summary

| Flip / enable | File | Prerequisite bench (this doc) |
|---|---|---|
| `WRP1A_MASK_PINNED = true` | `shared/src/lockdown.rs` | Phase 1 — WRP1AR layout pin + readback |
| `OEM_LOCK_MASK_PINNED = true` | `shared/src/lockdown.rs` | Phase 1 — OEM register pin + **positive OEM-key rejection** |
| 0-length `verify_put_key_response` → fail-closed | `secure/src/scp03_logic.rs` | Phase 3 — `HW-ASSUME-PUTKEY-KCV-RESP` shows KCVs echoed |
| Enable DEK-liveness torn-write net | `secure/src/se050/mod.rs` | Phase 3 — `HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT` accepted **and** atomicity bench |
| Claim invariant #10 (immutable FSBL trust root) | CLAUDE.md | Phases 1–2 + FSBL geometry/WRP ceremony/non-monolithic image gates |
| Remove `HW-ASSUME-PUTKEY-ATOMIC` from bare-tcb | `HW_ASSUMPTIONS.json` | Phase 3 — atomicity bench (no torn DEK) |
| Authorize any production ship | — | ALL phases + factory S-1/S-2/S-3 + the buildable-image owner sign-off |

A confirmed torn DEK (Phase 3) or a successful RDP-2 downgrade (Phase 2) is a
**ship-blocker**, not a tuning parameter.
