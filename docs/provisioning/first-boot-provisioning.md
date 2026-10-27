# First-boot self-provisioning (on-device) — work-todo #36

Status: **candidate implemented (`rdp2-self-lock`); not production-approved;
silicon and protocol-closure gates pending** (2026-07-15).

> UPDATE 2026-07-21: the device-side flow now has a normative requirements
> spec at [`first-boot-requirements.md`](first-boot-requirements.md) (what
> the flow MUST/MUST NOT do, incl. the invariant-#10 "verify WRP, never set
> it, before RDP-2" ordering). This file remains the operator/field runbook.

> **CANDIDATE RUNBOOK, NOT AN IRREVERSIBLE CEREMONY.** This document describes
> the current code and its intended factory/device boundary. It does not
> authorize RDP, OTP, SE-key, or OPTIGA lifecycle changes. The authenticated
> per-unit transport handoff/receipt, authenticate-before-rotate rule,
> old/new/KVN recovery proof, exact E140 order, and silicon receipts remain
> OPEN. Follow `docs/planning-and-review-workflow.md` §11 for any future
> owner-authorized hardware attempt.

Devices ship at **RDP-0** with a batch-uniform image (user-verifiable over SWD
before first power). The **first field boot** verifies the ship state,
self-locks the MCU to **RDP Level 2**, and rotates the secure-element pairing
secrets off the factory-installed **transport** keysets to their final
device-unique values — all **before the first PIN entry and before the seed
wizard**. This document is the operator/field-diagnosis reference for that
flow; the design decision record is `docs/archive/work-todo-retired-2026-07-19.md` §36.

Owner amendment (2026-07-14): #36's text places the RDP-2 self-lock in the
FSBL, but it is implemented in the **secure app early-boot** (`secure/src/
first_boot/`) because the FSBL is at ~99 % of its 32 KB WRP1A budget. The FSBL
only branches into signature-verified slots, so "verify slots before lock"
holds structurally; the transit-reflash residual is identical either way. The
lock code can migrate into the FSBL later when the Draft-0.9 flash-map
reshuffle happens anyway.

---

> **UPDATE 2026-10-27: owner direction changes this split (design only, NOT implemented).**
> The factory raises the MCU to **RDP-1** and installs the **final** SE050/OPTIGA credentials, derived on-die from the per-die DHUK alone (no page-126 BHK, no page-127 salt).
> It then regresses RDP 1→0 (mass erase) and ships at RDP-0 with only a small prover in flash.
> The user verifies the device in the Vault desktop app with a USB proof of secure erasure: fill all flash with random data, unplug and replug, read everything back.
> This reverses "no factory RDP burn of any level", "factory MUST NOT install a final credential", and the first-boot transport→final rotation.
> It also moves WRP staging from the factory to first boot.
> Until implemented, the text below still describes the current code.
> Design, prerequisites and the open RDP-1-in-transit caveat: [`user-device-verification.md` § USB path](../security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

<a id="authoritative-factory--first-boot-responsibility-split"></a>
## Candidate factory ⇄ first-boot responsibility split

This boundary is the current candidate realization of the #36 split. It is
mirrored verbatim in `docs/provisioning/factory-provisioning.md` and
`docs/factory-mass-production-model.md`; if you change one, change all three.

### Done at the FACTORY (RDP-0, on the production line, under read-back QA — no secret exists on the MCU yet)

- Flash the reproducible batch-uniform image (FSBL + secure + NS app into the
  A/B slots).
- Set the shipped option-byte profile: **TZEN=1, SECWM1/2, SECBOOTADD0, WRP1A
  on FSBL pages 0–3, BOR_LEV, BOOT_LOCK/nBOOT, OEM-key finalization —
  everything EXCEPT RDP.** RDP stays **0**. There is no RDP-2 burn anywhere at
  the factory.
- Burn the per-device **OTP master** (`otp::ensure_device_master`, TRNG). This
  must be a factory step: the initial two-QW burn is not crash-retry-safe, and
  it is the RDP-invariant root of every transport keyset.
- Provision **SE-internal structure + irreversible locks on transport
  keysets** (transport keys = HKDF over the OTP master, public-by-assumption):
  - **SE050:** create the admin UserID + user-object OID structure/policies;
    rotate the SCP03 keyset from the AN12436 defaults to the **transport**
    keyset (GP `PUT KEY` under `PLATFORM_DEK`); transport lock if applicable.
  - **OPTIGA:** write the **transport PBS** to E140 (metadata keeps the
    `Conf(E140)` arm so the PBS stays shield-rotatable); F1D0
    `Change=Auto(F1D0)` (S-1); close the candidate type-`0x11` Protected-Update
    anchor pool `{0xE0E8, 0xE0E9, 0xE0EF}`, and preserve/ratchet the
    device-certificate surfaces `{0xE0E0, 0xE0E1, 0xE0E2, 0xE0E3}` **without
    retyping them** (S-2 — *no ceremony is authorized*; see the correction
    below); provision the E120 LUC + bind F1D0 `Execute=LUC`, freeze the F1E1
    soft counter (S-3); **LcsO=Op ratchet** on the locked OIDs — the SE
    point-of-no-return.
  - The #22 attestation/binding manifest burn (when it lands).
- Read-back QA over SWD (connect-under-reset) against the reproducible build —
  encouraged, deliberately **not** load-bearing.
- Ship at **RDP-0** with SWD + NRST pads accessible. The only SE pairing
  material in existence is the public transport values.

> **CORRECTION 2026-07-26 — the OPTIGA S-2 step above named the wrong objects,
> and the error was not a harmless no-op.** It previously read "PQ1-HSM
> trust-anchor cert at 0xE0E3 + neutralize the TA-pool 0xE0E4..0xE0E8". Both
> halves are wrong against the 2026-04-22 bench dump and SRM Table 68:
> `0xE0E3` is a **device certificate** (`DataType=0x12`), already full — the
> chip refuses to *retype* it, so it never becomes an anchor;
> `0xE0E4..0xE0E7` hold **no objects at all** (GetDataObject errors); and the
> stale range's only real member, `0xE0E8`, is **one of three** type-`0x11`
> anchors. Following the old text is therefore not a harmless no-op but
> **destructive and false-closing**, as the F8 finding independently established
> (`../security/adversarial-review/findings/full-project-sweep-2026-07-14.md:292-320`):
> a fill-and-lock pass over that range junk-overwrites the `0xE0E3` **device
> certificate**, then aborts at the absent `0xE0E4` — never reaching `0xE0E9`
> or `0xE0EF` — leaving the real anchors open while the step reports done. On
> irreversible `LcsO` transitions, against parts that cost money. The candidate
> pool is `{0xE0E8, 0xE0E9, 0xE0EF}` (`secure/src/optiga/mod.rs:1996`, pinned by
> the source-scanning test
> `optiga_under_test::pure_tests::negative_ta_pool_lockdown_is_exact_and_emits_no_apdu`).
>
> **Do not read this correction as a new instruction.** It replaces a wrong
> target list with a *candidate* one, at a weaker evidence tier than the word
> "exactly" suggests: `{0xE0E8, 0xE0E9, 0xE0EF}` is **documentarily** confirmed
> (SRM Table 68 + deep-research cross-check) but **silicon-unconfirmed for the
> shipping SKU/revision** — which is why both the code docstring and
> [`../STATUS.md`](../STATUS.md) §A still say "pin the SKU/revision inventory".
> Whether those three slots are then **filled-and-locked** with a PQ1-HSM anchor
> or **irreversibly neutralized** is a further unapproved policy choice. The
> `0xE0E0` reading carries its own open confirm: our bench evidence came from a
> TRUSTMV3SHIELDTOBO1 **eval shield**, which may hold the engineering-sample
> Test cert rather than a production chip-unique cert.
>
> Nothing here is runnable: `lockdown_ta_pool` is `cfg`'d on the feature pair
> `optiga-lock-operational + factory-production-irreversible-im-sure`, which
> `OPTIGA_TA_POOL_LOCKDOWN_BLOCKED` (`secure/src/nsc/mod.rs:301-311`) rejects
> outright — so the function **does not exist in any compilable image** — and
> even its body emits **no APDU**, returning `Err(Status(0xEC))`
> (`secure/src/optiga/mod.rs:1971-2003`). `OPTIGA_S2_PRODUCTION_BLOCKED`
> separately rejects every `mode-production + optiga-trust-m` build.
> **S-2 remains an OPEN ship-blocker** — see [`../STATUS.md`](../STATUS.md) §A
> and [`provisioning-reference.md`](provisioning-reference.md) O-3/O-4/O-5.

### Done AT THE USER'S HOME on the first field boot (this flow; before PIN entry, before wallet creation)

- **Phase A (pre-lock):** verify the option-byte ship profile + OEM-locks-clear
  + blank per-device pages 123–127 → show "FIRST BOOT / DO NOT POWER OFF" →
  **program RDP=0xCC → reset.** This is the MCU point-of-no-return, moved off
  the factory line onto the user's device.

  > **UPDATE 2026-07-17 (owner design decision) — Phase A must be
  > CONFIRM-GATED.** The RDP=0xCC burn must not run automatically on first
  > power. Before it, the trusted UI shows "Confirm to lock device — after
  > that verification over SWD not possible anymore." and waits for a
  > deliberate on-device button sequence; until confirmed the device stays at
  > RDP-0, fully re-verifiable, touches no SE/USB/journal state, and every
  > boot re-enters the same prompt. This means accidental or transit
  > power-ups no longer destroy verifiability (today merely powering the
  > board self-locks it), and an attacker who confirms the lock in transit
  > only produces a unit that arrives locked → fails the unboxing
  > verification → returned (no seed exists yet). Not yet implemented —
  > current code runs Phase A unconditionally right after `ui::init()`.
  > User-side procedure this serves:
  > [`../security/user-device-verification.md`](../security/user-device-verification.md).
- **Phase B (post-lock, per-die DHUK now live), journaled + resumable:**
  - **BHK first-write** (TRNG → DHUK-ECB page 126; anti-pre-plant
    erase-and-reprovision).
  - **SE050 SCP03** rotation transport → **final (BHK-rooted)** via GP
    `PUT KEY` (key blocks wrapped under the transport DEK), two-phase confirm.
  - **SE050 admin credential** re-key transport → **final (BHK-rooted)**,
    delete + recreate.
  - **OPTIGA PBS** rotation transport → **final (DHUK + fresh TRNG salt)** via
    shielded `SetData(E140)`, two-phase confirm; salt persisted for device life
    in the page-127 journal.
- Then normal boot → **seed wizard** (PIN + mnemonic) → wallet creation.

### Explicitly NOT done on-device (stays factory-side)

The SE-internal irreversible locks (LcsO=Op ratchet, S-1/S-2/S-3 metadata,
trust-anchor cert), SE object/policy creation, the OTP-master burn, and the
whole option-byte profile except RDP. First boot only self-locks RDP-2 and
*rotates* the pairing secrets it inherits.

---

## Bounded power-loss recovery

The candidate resumes ordinary resets between completed flash quad-word
programs. Each step is idempotent; completion is recorded **commit-LAST** in
the append-only page-127 journal. A reset after one or two complete salt-data
QWs leaves them orphaned and the next attempt appends a new three-QW salt
record. Before starting that record, firmware reserves room for it plus the
two completion markers and otherwise fails closed without another write.

This is a finite recovery budget, not an unlimited guarantee. Repeatedly timed
interruptions or a flash defect can exhaust the 512-QW page and require RMA.
The host matrix models cuts between completed QW programs; partial-program,
retention, and the RDP `OPTSTRT` window remain silicon-validation gates. On a
resume boot the flow re-scans the journal, skips every completed step, and
continues at the first incomplete one. Per-SE rotation is **two-phase**: the
new keyset is confirmed live before the old one is considered dead (resume
probes the FINAL keyset first, then the TRANSPORT keyset).

The user must know: **do not disconnect power during first-boot setup.** The
screen says so. A resume shows "RECOVERING / DO NOT POWER OFF", not an error.

## Field failure UX

An unrecoverable state fails **closed** with a numbered code on the LCD:

```
 FIRST BOOT FAIL
 EXXXX HALT
```

Photograph the `EXXXX` code and send it to the vendor. Codes are STABLE across
firmware versions. Phase-A faults (`0x080x`) halt the unit **unlocked** (still
at RDP-0 → returnable/reflashable); Phase-B faults (`0x081x`+) occur after the
RDP-2 lock (→ RMA).

| Code | Meaning | Class |
|---|---|---|
| `E0801` | *legacy aggregate — retired; the granular `E0804`–`E080B` replace it (stable value kept for old field photos)* | halt unlocked |
| `E0802` | RDP=0xCC program / OPTSTRT failed | halt unlocked |
| `E0803` | OTP master not burned — caught **pre-lock** (R2.3) | halt unlocked (reflash/return) |
| `E0804` | Ship-profile: `TZEN` not set | halt unlocked |
| `E0805` | Ship-profile: `RDP` not the ship byte `0xAA` | halt unlocked |
| `E0806` | Ship-profile: `SECWM1` not all-bank-1-secure | halt unlocked |
| `E0807` | Ship-profile: `SECWM2` not all-bank-2-NS | halt unlocked |
| `E0808` | Ship-profile: `SECBOOTADD0` boot-redirect | halt unlocked |
| `E0809` | Ship-profile: `WRP1A` does not write-protect the FSBL pages, **OR the WRP1A layout is not yet silicon-pinned** (fail-closed — see `lockdown::WRP1A_MASK_PINNED`) | halt unlocked |
| `E080A` | Ship-profile: an OEM key-lock bit is set, **OR the OEM-lock mask is not yet silicon-pinned** (fail-closed — see `lockdown::OEM_LOCK_MASK_PINNED`) | halt unlocked |
| `E080B` | A per-device page (123–127) is not blank at ship | halt unlocked |
| `E0811` | OTP master not burned — Phase-B belt-and-braces (resume boot / FI skip of `E0803`) | RMA |
| `E0812` | SAES Tier-1 (DHUK) self-test failed | RMA |
| `E0821` | BHK provision / load-lock failed | RMA |
| `E0822` | Page-126 refused programming (silicon program-hostility) | RMA |
| `E0831` | SE050 SCP03 establish failed under FINAL and TRANSPORT | RMA |
| `E0832` | SE050 `PUT KEY` (transport → final) failed | retry / RMA |
| `E0833` | Re-establish under the FINAL SCP03 keyset did not confirm | RMA |
| `E0841` | SE050 admin credential re-key failed | RMA |
| `E0851` | TRNG salt could not be persisted to the **journal** before use (narrowed — the draw itself is now `E0854`) | halt |
| `E0852` | OPTIGA `SetData(E140)` of the final PBS failed | retry / RMA |
| `E0853` | Re-shield under the FINAL PBS did not confirm | RMA |
| `E0854` | 3-source TRNG salt **draw** failed (a platform/OPTIGA/SE050 leg or the all-zero gate) | halt |
| `E0855` | Pre-salt OPTIGA **transport-PBS handshake** failed (#443; doubles as authenticate-before-rotate) | halt |
| `E0861` | Journal step-marker write failed | RMA |
| `E0871` | SE050 platform-SCP enforcement: link / SCP03 / transport fault after the bounded retries (#989). Shown as `SE050 FAULT`, **every boot**, not only the first | retry (power-cycle) / RMA |
| `E0872` | SE050 `0x7FFF0207` (`RESERVED_ID_PLATFORM_SCP`) exists, does not open with this device's credential, and could not be deleted: squatted / tampered part (#989) | RMA (tamper) |
| `E0873` | SE050 refused to create the `0x7FFF0207` credential (#989) | RMA |
| `E0874` | SE050 refused `SetPlatformSCPRequest(SCP_REQUIRED)` from the credential's session (#989) | RMA |
| `E08F0` | SEs not in the expected factory transport state (pre-rotated?) | RMA |

(Source of truth: `secure/src/first_boot/state.rs` `FirstBootError`; the
`E087x` platform-SCP codes come from `se050::PlatformScpError::code` and share
this code space. The code space `0x08xx–0x0Fxx` is disjoint from the factory
ceremony's `FactoryErrorCode` `0x01xx–0x07xx`.)

> **UPDATE 2026-10-19 (#989): SE050 `SCP_REQUIRED` is enforced every boot.**
> The SE050E2 ships `SCP_NOT_REQUIRED` (AN12413 §4.6.2), so a keyless I2C party
> can read the version, the full object inventory and SE randomness, and could
> create the absent reserved credentials (e.g. `0x7FFF0205` FACTORY_RESET →
> DeleteAll). Production images (`se050-platform-scp-required`, in
> `PROD_REQUIRED`) run, right after Phase B and before the wallet path touches
> a secret, over SCP03 only: create our `0x7FFF0207` credential (BHK-derived,
> `pqsigner/se050-platform-scp-v1`) if absent, open a session with it, verify
> it (a squatter's credential never passes: `E0872`), and send
> `SetPlatformSCPRequest(SCP_REQUIRED)` — every boot, one NVM write (SE050
> flash endurance 20–100 × 10⁶ cycles). No decision rests on a plaintext reply:
> a first design skipped enforcement when a plain probe looked refused, and the
> 2026-10-19 review showed an interposer or a leftover session could fake that.
> The credential is kept (self-delete-only policy, skipped by the wipe sweep). It is
> deliberately not a journal step: units whose journal is already `ALL_DONE`
> would never run a new step. The factory may run the same step earlier on its
> transport keyset; doing so closes the supply-chain window in which the
> credential slot is open to a squatter (`E0872` catches one). Silicon status:
> see `dvt-silicon-test-checklist.md` 6B.5.

> **Operator note (2026-07-21):** two ship-profile checks are **fail-closed
> until silicon-pinned**, so a genuine first boot halts before the burn until
> the pins land — intended, since the flow cannot ship before them. `E0809`
> (WRP1A) fires FIRST (`WRP1A_MASK_PINNED = false`): the load-bearing invariant
> #10 check must never vacuously pass a removable-WRP unit under a wrong
> register/bit guess (two of its three sub-fields fail open on a mis-guess).
> Once WRP1A is pinned, `E080A` (OEM-lock, `OEM_LOCK_MASK_PINNED = false`) is
> next — it catches a planted OEM2 RDP-regression password. Flip each const in
> the commit that records its RM0456 citation **and** a positive bench detection.

## Where it lives in code

| Piece | File |
|---|---|
| Phase A/B entry points + `FirstBootHw` impl | `secure/src/first_boot/mod.rs` |
| Page-127 journal codec (pure, host-tested) | `secure/src/first_boot/journal.rs` |
| Resumable state machine (pure, host-tested) | `secure/src/first_boot/state.rs` |
| Ship option-byte profile + comparators (pure) | `shared/src/lockdown.rs` |
| RDP-2 write path + OB readers + journal I/O | `secure/src/hw/flash.rs` |
| Transport keysets + salted PBS + `current_pbs` | `secure/src/hw/secret_keys.rs` |
| SE050 rotation methods | `secure/src/se050/mod.rs`, `scp03.rs` |
| OPTIGA PBS rotation | `secure/src/optiga/mod.rs` |
| Boot wiring (Phase A/B, BHK gate, SL7) | `secure/src/main.rs` |
| Feature + ship fences | `secure/Cargo.toml`, `secure/src/nsc/mod.rs` |
| Non-production anti-footgun check | `make build-rdp2-self-lock` (must reject the feature outside `mode-production`) |

## Silicon-validation runbook (MUST complete before any production run)

Nothing here can be done in the dev environment; RDP-2 mistakes are
unrecoverable, so validate on sacrificial parts first (same culture as the
S-1/S-2/S-3 burn ceremony). See also the `EthereumPhone/PQ1` production gates (labels `source:production-todo`, `ship-blocker`).

1. **Power-cut matrix** (#36 (a)–(e)): induced cuts at every step boundary,
   incl. the unavoidable OPTSTRT window. The pure state machine's host
   power-cut matrix test (`first_boot::state::tests`) proves the *logic*
   converges; silicon must prove the *durability*.
2. **Page-126 program-hostility** re-check on shipping silicon (the current
   bench chip returns erase-OK / program-PROGERR) — gates the BHK first-write.
3. **RM0456 pins:** direct RDP 0→2 transition with TZEN=1 (erase behaviour +
   the exact OPTR-modify path); OEM1LOCK/OEM2LOCK register (FLASH_NSSR vs
   FLASH_OPTSR) + bit positions; `OPTWERR` bit for the OB-commit error check;
   BOR_LEV / WRP1AR / SECWM offsets for the Phase-A verifier; DHUK RDP-0 vs ≥1.
4. **SE050:** the transport→final `PUT KEY` flow; re-establish after a failed
   FINAL-probe auth; `SW=0x6986` admin-lockout behaviour during the resume
   verify probes (the admin UserID is unlimited-attempts, so it should not lock).
5. **OPTIGA:** the SetData wedge (2–3 ops) timing bracketing the salt+PBS
   rotation; E140 rewrite under the transport shield whether or not the factory
   ratcheted LcsO=Op.

## UPDATE 2026-07-21 — device-side correctness + hardening pass

Landed device-side (host-tested logic + compile-verified against `thumbv8m`
with the ship feature set; no silicon). Nothing below grants production
authority — the handoff/receipt, silicon-receipt, and E140-ordering gates
remain OPEN.

- **#443 deterministic first-boot brick — FIXED.** Phase-B step 5 drew the
  3-source TRNG salt (`trng_salt` → `rng_strong::fill`) whose OPTIGA leg is
  mandatory, but the OPTIGA shield was not established at that point
  (`load_pbs` runs after Phase B; the in-ceremony shield came up later inside
  `rotate_pbs_to_salted`). Every field unit would have halted at the salt draw
  on first boot. Fix: `optiga::establish_transport_shield` brings the shield up
  under the **transport** PBS (E140 untouched) on the fresh path **before** the
  draw; the state machine calls it in the `salt == None` arm only (a committed
  salt means the chip may already be rotated, where a transport handshake would
  fail). Regression: `first_boot::state::tests` now models the shield
  precondition in `FakeHw` so reverting the ordering fails `clean_run_completes`.
- **SE050 `PUT KEY` response mis-parse — FIXED.** `send_apdu` already strips and
  verifies `SW==0x9000` and returns the body only; both PUT KEY callers
  re-parsed the body tail as a "SW", so a real PUT KEY always false-failed (an
  empty body → `n<2`; a KCV body → a KCV byte ≠ `0x9000`). This path had never
  run on silicon. Now the caller trusts `send_apdu`'s `?` for the status and
  verifies the response KCVs via `scp03_logic::verify_put_key_response`.
- **Authenticate-before-rotate contract.** `scp03_logic::TransportAuthProof`
  (fail-initialized FI-sentinel carrier) is recorded on each transport-auth
  success arm (SCP03 mutual auth / admin `verify_session(tr_pin)` / OPTIGA PRL
  shield) and consumed immediately before the destructive write (PUT KEY /
  `delete_object` / `SetData`). A skipped/glitched auth — or a wrong transport
  credential — leaves the proof pending and the write refused.
- **R2.4 confirm gate.** The RDP-2 burn now requires a deliberate **both-buttons
  chord** on a 2-page lock-confirm screen (reusing the FI-hardened
  `confirm_checked` scroll-to-end + `OK_SENTINEL` gate). Decline/idle stays at
  RDP-0 and re-prompts next boot (no wipe — no wallet exists yet). Phase A runs
  before SysTick and the IWDG, so the prompt blocks on the button (busy-wait
  polling), never idle-wipes, and cannot be watchdog-reset mid-confirm.
- **Zeroize.** OPTIGA `ApduBuf` now zeroizes on drop (it assembles the plaintext
  PBS in `set_data_object`); the SCP03 PUT KEY buffer is `Zeroizing`.

### New bench items (fold into the runbook above)

6. **`HW-ASSUME-PUTKEY-KCV-RESP`** — does the SE050 GP applet echo the per-key
   KCVs in the `PUT KEY` response body? `verify_put_key_response` accepts body
   lengths `{9, 10}` (KCV forms, verified) and `0` (no echo → accepted, since
   `SW==0x9000` already confirmed the write). If the bench shows KCVs ARE
   returned, make the `0`-length case fail-closed.
7. **DEK-liveness / `HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT`** — the resume/confirm
   re-establishes SCP03 under the FINAL **ENC/MAC only**, so a torn write that
   left the DEK at transport is invisible until the next re-rotation
   (`HW-ASSUME-PUTKEY-ATOMIC`, #398/#386). The firmware-side safety net (a
   self-`PUT KEY` of the identical final keys wrapped under the FINAL DEK, which
   fails closed if the on-chip DEK is still transport) is **deliberately NOT
   shipped as live code**: it is a second in-place PUT KEY whose idempotency is
   unconfirmed on silicon, so shipping it would gamble the whole first-boot flow
   on an unproven assumption. Bench procedure: on a sacrificial part, crowbar
   the SE050 Vdd across the PUT KEY commit window (I2C trigger on
   `CLA=0x84 INS=0xD8 P1=0x0B P2=0x81`), then per part cold-boot and probe
   {ENC/MAC establish, DEK re-PUT}. A confirmed `ENC/MAC-final + DEK-transport`
   outcome is a **ship-blocker**; also record whether a re-PUT of identical keys
   is accepted (validates the safety net) and whether KCVs are echoed (resolves
   item 6). Only after both confirm does the DEK-liveness step become
   shippable.

## Design note (candidate, NO production authority) — factory handoff/receipt

The **authenticated per-unit transport handoff/receipt** remains an OPEN owner
gate: the device must be able to tell a genuine factory-provisioned transport
state from an attacker-planted one before it welds RDP-2 shut. The device-side
*interface* can be specified now; the signing authority and primitive are an
**owner decision** and no crypto is implemented until it is made.

- **Where it plugs in.** A new Phase-A check, after R2.3 (OTP-master present)
  and before the R2.4 confirm/burn: read a factory-written per-unit record from
  the **spare OTP region** (`hw/otp.rs` bytes `176..512`, 336 B unallocated),
  verify it, and halt UNLOCKED on failure (new `E080x` code). Placing it
  pre-confirm keeps "verify state, then weld" (invariant #10) intact.
- **What it must bind.** The per-unit transport-keyset identity (so a record
  from unit A can't authorize unit B) plus a factory attestation the device can
  check. It corresponds to the F6 `#22` attestation/binding manifest.
- **The PQ-clean mechanism choice (owner).** No classical signer (invariant #5),
  so the options are: (a) a symmetric MAC under a factory-station key — but the
  only secret the device and factory already share is the OTP master, which
  *roots the transport keyset itself*, so a MAC under it is near-circular and
  needs care to add real assurance; (b) a **SPHINCS+C10** signature over the
  record, verified against a firmware-pinned factory public key (PQ-clean, reuses
  the on-device C10 verifier, heavier); (c) an HSM-/station-mediated record whose
  form the station owns. Until (a)/(b)/(c) is chosen the device-side
  `verify_factory_receipt()` is a spec stub, not code.

## Design note (candidate, needs owner sign-off) — a bench-buildable image

Silicon validation of everything above is currently **blocked at build time**: a
flashable `rdp2-self-lock` image requires `mode-production`, which is
independently quarantined by `FW_ROLLBACK_PRODUCTION_BLOCKED` (`secure/build.rs`)
and needs `FSBL_VENDOR_PUBKEY`. So today only the host tests and the negative
`make build-rdp2-self-lock` check run; no unit can be flashed to exercise the
RDP burn, the SE rotations, or the confirm gate on real hardware.

Proposal (do **not** carve this out silently — it touches the rollback
quarantine, so it needs an explicit owner instruction): a narrowly-scoped
`bench-ship-validation` configuration that satisfies the `nsc/mod.rs` self-lock
fences and supplies a bench `FSBL_VENDOR_PUBKEY`, WITHOUT claiming shipping
status — it must remain incompatible with every dev/test feature (as
`rdp2-self-lock` already is), render a loud non-shippable boot banner, and be
excluded from any release-packaging target. Its only purpose is to let a
sacrificial board run the Phase-A/Phase-B flow end-to-end on silicon so the
runbook items above can actually be executed. This is the prerequisite for
closing the silicon gates, not a relaxation of them.
