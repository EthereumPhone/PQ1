# PQ1 factory mass-production provisioning — tooling model

Status: **design research; not an executable ceremony** (2026-06-17, scoped
update 2026-07-14). Supersedes nothing; extends the single-device
ceremony in [`factory-provisioning.md`](provisioning/factory-provisioning.md) +
[`secure/src/factory_provisioning.rs`](../secure/src/factory_provisioning.rs)
toward a mass-production line that ships a device whose **dual-SE seed
invariant actually holds** ([[project_se_removal_invariant]]).

Historical decisions recorded 2026-06-17 (superseded where the update below
says so):
1. OPTIGA shipping-state lockdown (S-1/S-2/S-3) is **folded into the ceremony**
   as new validated steps, ordered before the irreversible RDP2 bump.
2. S-2 trust anchor closed with a **PQ1 factory-HSM cert** (offline root;
   line carries the public cert only). **Superseded:** HSM-anchor versus
   irreversible neutralization is not selected, and the real type-`0x11` pool
   is still open.
3. **No per-unit traceability** — the OTP sentinel is the only gate.
   **Superseded:** factory-installed transport credentials require an
   authenticated, crash-consistent per-unit handoff/receipt whose owner is
   still open.

> **UPDATE 2026-10-27: owner direction changes this split (design only, NOT implemented).**
> The factory raises the MCU to **RDP-1** and installs the **final** SE050/OPTIGA credentials, derived on-die from the per-die DHUK alone (no page-126 BHK, no page-127 salt).
> It then regresses RDP 1→0 (mass erase), burns the OTP, and ships at RDP-0 with **empty flash**. The option bytes boot ST's mask-ROM USB bootloader, with all flash non-secure.
> The user verifies the device in the Vault desktop app with a USB proof of secure erasure done by that ROM: it fills all 2 MB of flash with random data, the user unplugs and replugs, and it reads everything back. The app then installs the release through the ROM.
> This reverses "no factory RDP burn of any level", "factory MUST NOT install a final credential", and the first-boot transport→final rotation.
> It also moves WRP staging from the factory to first boot.
> Until implemented, the text below still describes the current code.
> Design, prerequisites and the open RDP-1-in-transit caveat: [`user-device-verification.md` § USB path](security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

> **UPDATE 2026-07-14 (work-todo #36).** The actor split survives, but this
> document no longer selects a production-authorized complete ordering.
> The device-side candidate is implemented behind `rdp2-self-lock`, but it
> remains quarantined pending the named silicon and ordering gates. Devices
> are intended to ship at RDP-0
> (batch-uniform and user-verifiable over SWD before first power); first field
> boot performs the MCU RDP2 self-lock, BHK first-write, BHK-rooted SE050
> rotation, and persisted-TRNG-salted OPTIGA PBS rotation from
> factory-installed transport keysets. The factory
> retains S-1/S-2/S-3 object/metadata preparation, required objects, and OPTIGA
> lifecycle responsibility. **The exact E140 LcsO ratchet-versus-field PBS
> rotation order is OPEN, owner-gated, and silicon-gated.** Fixture step 5
> (`bump-rdp2-after-factory`) and the "sentinel → RDP2" gate below are
> superseded; the 10-step table is a historical design input, not an executable
> ceremony. In particular, do not interpret its E140 row as a selected order.
> The candidate factory ⇄ first-boot responsibility split and
> field error model live in
> [`provisioning/first-boot-provisioning.md`](provisioning/first-boot-provisioning.md#authoritative-factory--first-boot-responsibility-split).
> The self-lock is implemented in secure-app early boot, not the FSBL (FSBL
> budget); implementation is not production approval.

---

## 1. Why the current model isn't shippable for mass production

The legacy 7-step ceremony provisions the MCU and **permanently locks it**
(`bump-rdp2-after-factory` → RDP=Level 2), but **none of its steps close the
OPTIGA ship-blockers**:

- **S-1** F1D0 `Change=ALW` — a desoldered OPTIGA can be re-keyed and PIN-brute-forced.
- **S-2** the real type-`0x11` Protected-Update pool is not closed. The retired
  dev reset helper attempts to install Infineon's public sample cert at
  `0xE0E3`, but the observed object is already a full type-`0x12` device cert,
  so that write is a no-op rather than the live anchor path. The candidate
  pool is `{0xE0E8,0xE0E9,0xE0EF}` and remains factory/silicon-gated.
- **S-3** the final F1D0/E120 metadata, lifecycle, reset/power-cut, and limit
  boundary are not yet factory-authorized and silicon-validated. Production
  already requires E120 as lockout authority; F1E1 is only a
  provisioning/reset sentinel.

Shipping with these SE surfaces open would permanently violate the seed-
protection invariant once the first-field RDP2 self-lock completes. The
factory-side S-1/S-2/S-3 obligations must therefore close before shipment, but
the exact E140 ratchet order relative to the first-field final rotation remains
OPEN and must not be inferred here.

Several component primitives already exist (`provision_trust_anchor`,
`optiga-lock-operational` → `build_metadata_auth_ref_luc` +
`Change=Auto(F1D0)`, `optiga-hw-counter` E120 binding,
`SetObjectProtected` CMD 0x83). The `rdp2-self-lock` candidate now also contains
the device-side journal, BHK first-write, transport→BHK SE050 rotation, and
persisted-TRNG-salted OPTIGA PBS rotation. The remaining gap is **not** purely
orchestration: authenticated handoff/receipt, old/new/KVN recovery adequacy,
coordinated OPTIGA/SE050 order, exact E140 timing, and silicon evidence remain
design + validation blockers; the retired reset helper also still embeds the
public sample certificate and must remain absent from every production-shaped
build.

---

## 2. Trust model — the line must not hold final wallet secrets

Under the selected #36 research direction, the line would install only
transport keysets and factory-side SE objects/locks; it must not learn or
inject the final BHK, PBS, SCP03 keys, or seed. The candidate implements the
device-side state machine, but per-device transport-key creation,
authenticated handoff, KVN migration/recovery adequacy, and first-field proof
of possession are not approved. Until those close, this is a constraint on a
candidate protocol, not an executable production-line model. Final pairing
material is intended to be created on-device after the first-field RDP2
self-lock; the OPTIGA final derivation binds fresh TRNG. The legacy
`otp::ensure_device_master` route and unary rollback tally are production-
rejected; Draft 1.1's physical OTP allocation remains OPEN. Therefore:

- **Every device should flash the identical firmware image.** This does not
  imply that transport-key provisioning can avoid per-unit authenticated state;
  the required handoff/receipt mechanism is OPEN and may require a station or
  HSM-mediated per-unit record.
- Factory transport credentials are still per-device secrets even though they
  are not final wallet roots. Their generation, station/HSM custody,
  authenticated handoff, replacement, and deletion receipts must be selected
  before this model can claim that the line holds no secrets.
- If S-2 selects a fleet anchor, only its public object may reach the device
  and the private authority requires a separately reviewed custody/signing
  policy. S-2 may instead select irreversible neutralization of unused
  type-`0x11` slots. This document selects neither option and does not assign
  refurbishment authority to a future fleet key.

The intended final firmware image may remain batch-uniform, but provisioning
units are not interchangeable once per-device transport state exists. Scaling
depends on the still-open authenticated receipt/handoff design rather than on
stateless parallelism.

---

## 3. The extended ceremony (10 steps)

The historical candidate added four SE-lockdown steps and placed an SE
point-of-no-return before wipe/validate. It is retained below to show the
validation obligations, but it is not the selected executable order: E140's
placement must be resolved separately without moving S-1/S-2/S-3 or final key
rotation to the wrong actor. Each eventual step needs read-back validation
before a shipping sentinel can carry authority.

| # | `FactoryStep` | Action | New? | Err range |
|---|---|---|---|---|
| 1 | HardwareSelfTest | SAES Tier-1 + BHK Tier-2 | — | E01xx |
| 2 | OtpMasterKey | **legacy production-ineligible step**; no burn authority (replacement OTP allocation OPEN) | — | E02xx |
| 3 | PrePopulatedStateCheck | refuse non-fresh chip (E0301/E0702 reentry guard) | — | E03xx |
| 4 | DualSeProvisionInfrastructure | factory transport-keyset/object preparation only; final PBS/SCP03 rotation is first-field | — | E04xx |
| 5 | **OptigaS1AuthRef** | F1D0 `Change=Auto(F1D0)` (`build_metadata_auth_ref_luc`); read-back confirms AC | ✅ | E05xx |
| 6 | **OptigaS2TrustAnchor** | **historical invalid step:** the E0E3 write is mis-targeted. A replacement must pin the SKU/revision inventory, preserve/ratchet device-cert surfaces, and install or irreversibly neutralize the real type-`0x11` pool `{0xE0E8,0xE0E9,0xE0EF}` under a separately approved policy | ✅ | E06xx |
| 7 | **OptigaS3HwCounter** | provision E120 LUC and bind F1D0 `Execute=LUC(E120)`; retain or replace the F1E1 provisioning/reset sentinel only under the separately reviewed final sentinel policy | ✅ | E07xx |
| 8 | **OptigaLcsOpRatchet** | candidate factory-side ratchet for required user OIDs; **E140 placement remains OPEN and is not selected by this table** | ✅ | E08xx |
| 9 | WipeUserState + PostWipeValidation | `factory_reset_admin`; confirm user state gone, admin reachable | — | E09xx |
| 10 | WriteOtpSentinel | **historical sentinel claim; invalid as a current ship gate** (post-#36 the unit targets RDP-0 transport, but no sentinel currently authorizes shipment) | — | E10xx |

The historical flow then said “read sentinel → box + ship at RDP-0.” That is
not current authority. Post-#36, the intended **MCU no-take-backs line** moves
to first field boot. Candidate self-lock code exists, but the handoff state,
recovery proof, E140 ordering, silicon evidence, and receipt protocol remain
OPEN; `bump-rdp2-after-factory` is retired.

**Historical validation dependency to carry into a replacement plan:** step 9
wipes user state *after* the LcsO=Op ratchet (step 8). Confirm `factory_reset_admin`
+ the F1Dx data-object clears still succeed under locked metadata — the F1Dx
data AC is `Conf(E140)` (independent of LcsO), so this *should* hold, but it is
load-bearing and must be proven on a real OPTIGA, not assumed. If it fails,
the replacement design must choose and review a safe order; this document does
not authorize swapping or executing either step.

The historical proposal would have made `FactoryStep::total()` 10 and required
the host test to change in lockstep. A replacement ceremony must select its own
state machine and tests; the existing count is not an implementation todo from
this document.

---

## 4. S-2 — pool-closure requirements, not a frozen ceremony

A replacement S-2 design may use a PQ1-controlled offline HSM, but this file
does not select the key type, certificate format, station protocol, or exact
OID write order. At minimum it must:

1. select either a PQ1-controlled Protected-Update authority or irreversible
   neutralization; if an authority is selected, retain its private key under
   reviewed custody and export only the public object required by OPTIGA;
2. prove that the production build cannot carry or provision the retired
   public-sample recovery key;
3. pin the exact SKU/revision metadata inventory before mutation; preserve and
   ratchet the type-`0x12` device-cert surfaces, and install or irreversibly
   close each real type-`0x11` slot in `{0xE0E8,0xE0E9,0xE0EF}`;
4. read back type, access conditions, lifecycle, and, when applicable, the
   selected public-key identity before any one-way ratchet; and
5. define refurbishment authority separately rather than assuming the same
   fleet key and path remain safe forever.

The current `provision_trust_anchor` helper targets `0xE0E3` and is therefore
retired dev recovery code, not the first step of this ceremony. If an HSM
authority is selected, its line connectivity and receipt shape remain OPEN;
the per-unit transport-state receipt is open under either S-2 policy.

---

## 5. Historical line-orchestration sketch — do not run

The earlier proposal fan-out the single-device flow and trusted a sentinel so
no operator watched each OLED. The sketch is retained only as a list of line-
automation requirements; its sentinel and first-field self-lock assumptions
are not approved:

```
HISTORICAL PSEUDOCODE — NOT A COMMAND SEQUENCE
for each station:
  1. probe-rs download   <identical-image.elf>
  2. STM32_Programmer_CLI --optionbytes TZEN=1 ...
  3. probe-rs reset
  4. poll legacy OTP sentinel @0x0BFA_00A0  (INVALID AS A SHIP GATE)
       PRODUCTION_OK / BOTH_OK  -> step 5
       STARTED_FAILED           -> divert bin (read OLED step+code for vendor)
       DID_NOT_START / timeout  -> retry once, else divert bin
  5. historical "box + ship" step — NO CURRENT AUTHORITY
```

- **Historical parallelism assumption:** one fixture controller fans out N
  probe-rs invocations keyed by probe serial and flashes the same image. The
  old “no DB, no per-unit file” assumption is superseded by the required
  authenticated per-unit transport-state handoff/receipt.
- A replacement must define an authenticated, crash-consistent receipt; the
  legacy OTP sentinel and OLED are evidence channels, not current ship gates.
- Any future rehearsal must dry-run destructive SE transitions without
  committing them. Exact steps follow the approved replacement state machine,
  not the historical 5–8 numbering above.

---

## 6. Build-profile guards (extend the existing matrix)

The current candidate guard matrix exercises SE-lockdown and real-TA
requirements, but it is a quarantine/test shape rather than a finalized
production profile. In particular, the combined E140+user-OID feature cannot
settle the still-open E140/final-rotation order:

| Feature combination | Result |
|---|---|
| any STM32U585 `factory-provisioning` combination | **compile error `FW_ROLLBACK_FACTORY_BLOCKED`**; the retained state machine is historical and no acknowledgement relaxes the rollback quarantine |
| `factory-provisioning-rehearsal` | **same compile error** because it activates `factory-provisioning`; it is not a runnable dry-run profile |
| `optiga-lock-operational + factory-production-irreversible-im-sure` | **compile error `OPTIGA_TA_POOL_LOCKDOWN_BLOCKED`**; the named pool has no approved mutation/verification ceremony |
| TA cert == Infineon sample hash / `optiga-reset-oids` | **compile error**; retired mis-targeted evidence cannot become a runnable profile |

The opt-in remains a foot-gun guard, not a security gate.

---

## 7. Traceability — historical omission, not accepted closure

The historical proposal selected no provisioning log, attestation record, or
label. That decision does not make the old OTP sentinel a sufficient current
gate: the revised actor split, transport receipts, E140 ordering, field RDP2
receipt, and final key-rotation receipt must be frozen first. Until then there
is no approved cryptographic tie between a fielded unit and a factory run. If
traceability is later added, the minimal candidate is a per-unit row keyed on
the STM32 UID plus OPTIGA/SE050 UIDs, captured by the actor authorized to read
them at that stage.

---

## 8. Work breakdown (what to actually build)

1. Freeze and test the **factory-owned transport phase**: S-1/S-2/S-3 object and
   metadata preparation, required-object receipts, sample-certificate refusal,
   and no MCU RDP2 or final field key rotation.
2. Resolve the exact E140 LcsO-ratchet-versus-final-PBS-rotation ordering on an
   owner-authorized sacrificial OPTIGA. Until that evidence lands, neither
   factory nor first-field code may claim the final order.
3. Adversarially review and silicon-validate the existing **first-field
   candidate**: MCU RDP2 self-lock, BHK first-write/load, BHK-rooted SE050
   rotation, TRNG-salted final OPTIGA PBS, wizard, and explicit receipts.
   Revise it as required by the handoff/recovery/E140 decisions. No step may
   silently fall back to factory transport credentials.
4. Freeze the S-2 pool/OID policy (selected HSM anchor or irreversible
   neutralization) and replace or remove the mis-targeted E0E3 sample-cert
   helper; retain the compile-time sample-cert fence (§4).
5. Extend rehearsal and the build-profile guard matrix without firing an
   irreversible lifecycle transition in a dev/test build (§5–§6).
6. Build an N-station fixture controller only after phases 1–3 and their
   authority boundaries are frozen; do not wrap the retired
   `bump-rdp2-after-factory` flow.
7. Update the operator manual with the measured phase receipts. It must not say
   "FACTORY OK ⇒ final LcsO=Op + RDP2" while E140 ordering and the first-field
   ceremony remain open.
