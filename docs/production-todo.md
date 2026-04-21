# Production-only TODO

Everything in this file represents a **one-way action** — provisioning
steps, silicon-level commits, or chip-state transitions that cannot be
undone on the target unit. These must NOT be executed during normal
development iteration. They belong on a dedicated factory / end-to-end
validation flow against sacrificial parts, then on the production line.

Compare with `docs/work-todo.md`, which is strictly the
reversible-iteration backlog.

## Ground rules

1. **Dev builds never flip any of these gates.** The default feature
   set keeps every one-way transition behind an opt-in Cargo feature.
   If a normal `make flash-hw-*` target commits silicon, that is a
   bug — file it, fix the default.
2. **Sacrificial parts first.** Every one-way flow below is validated
   against a chip we have explicitly designated as "about to be
   committed and never rolled back." If that chip fails a step, we
   learn and retry on the next sacrificial part, never on a customer
   device.
3. **No feature combinations on dev machines.** The
   `optiga-lock-operational`, future `stm32-burn-device-key`, RDP=2,
   and WRP1A flows are enabled exactly once per physical part, at
   production time. They never appear in a `make flash-*` target
   that developers run day-to-day.
4. **Every gate has an explicit "why this is safe now" checklist.**
   Before flipping a one-way switch, the operator records what was
   validated on the sacrificial parts that justified the commit.

## Irreversible gates, by subsystem

### OPTIGA Trust M V3 — LcsO transitions

Per SRM §"Life Cycle Status" the LcsO state machine only moves forward:
`Creation (0x01) → Initialization (0x03) → Operational (0x07) →
Termination (0x0F)`. No reverse command exists, no authorisation
reverses it, no factory-reset path is exposed. Once you commit,
you are committed.

The `optiga-lock-operational` Cargo feature gates every LcsO=op bump
we emit today. Default OFF. Production builds flip it only at final
provisioning, after every item in the pre-commit checklist below has
passed against sacrificial parts.

#### Production items (each is one-way per chip)

- [ ] **E140 LcsO=Operational.** PBS metadata frozen, chip accepts
      Change only via `Conf(E140)` (shielded connection with matching
      PBS). NOTE: PRL does NOT need this — Shielded Connection works
      with E140 at LcsO=Creation per the Infineon pairing example +
      SRM "Pairing Use Case Pre-conditions" (requires `LcsO <
      operational`). This transition is purely a *post-pairing
      hardening* step that locks the PBS against plaintext rewrite.
      Production chips land here once the PBS derivation is fully
      validated and we're ready to seal the chip's pairing against
      tampering.
- [ ] **F1D0 (AUTH_REF) LcsO=Operational.** Metadata frozen at
      `{Change=ALW, Read=NEV, Exec=ALW, DataType=AUTHREF}`. After
      commit, the chip hard-enforces "PIN HMAC auth only" semantics
      on this slot; attacker with bus access cannot loosen the policy.
- [ ] **F1D1 / F1D2 / F1D3 / F1D4 LcsO=Operational.** Entropy / master
      secret / VK / bootstrap VK. Metadata frozen at `{Change=Auto(F1D0)
      OR Conf(E140), Read=Auto(F1D0) OR Conf(E140)}`. Data remains
      writeable via PIN-HMAC auth or shielded connection — exactly
      the wallet's read/write envelope.
- [ ] **F1E1 (COUNTER) LcsO=Operational.** Metadata frozen at
      `{Change=Conf(E140), Read=ALW}`. Counter writes require shielded
      connection (stronger than PIN auth), which is the anti-brute-
      force gate.
- [ ] **Global chip LcsO (0xE0C0) = Operational** if we ever transition
      it. Currently we leave this alone; if we ever write it, it goes
      in this doc first.

#### Pre-commit checklist (sacrificial part, each run fresh)

Before flipping `optiga-lock-operational=on` on a "real" unit:

1. Run `make flash-hw-optiga-bringup-write-only` (Phase A) with the
   feature OFF. All 6 user OIDs provision; chip stays at
   LcsO=Creation; nothing committed.
2. Reflash with a different commit hash or a comment-only code edit.
   Confirm PBS fingerprint `8ca52e4bc284d822` reproduces identically.
   This is the rebuild-stability proof for the hardcoded-master path.
3. Repeat step 2 twice more. Any drift in the fingerprint aborts the
   flow — root-cause before proceeding.
4. On a second fresh part: flip `otp-hardcoded-master-key` OFF so the
   OTP burn path runs. Validate first-boot TRNG→OTP→readback cycle
   completes cleanly (`[S][otp] device master burned, X bytes`
   appears; second boot shows `device master already burned`).
5. On a third fresh part: full Phase-B with `optiga-lock-operational`
   enabled + `e2e-skip-unlock` off. MasterHello / SlaveHello / record-
   layer exchange all succeed against the committed PBS. Read back
   entropy / master / vk via the shielded channel and confirm bit-
   for-bit match of what was written.
6. Only then: flip `optiga-lock-operational=on` on the production
   build for the unit being provisioned. Single flip, single chip.

#### Escape hatch

`make flash-hw-optiga-reset` uses SetObjectProtected + an Infineon
sample Trust Anchor to reset the F1D0..F1DF user-OID range. Validated
16/16 on the original bench chip. Can recover a user-OID range that
was accidentally LcsO=op'd in dev. Cannot reset E140 once LcsO=op
with a lost PBS (that's the hard brick from the first chip), so the
escape hatch exists for user OIDs only.

### STM32U585 — OTP + option-bytes commits

#### Production items

- [ ] **STM32 OTP master-key burn.** 32 TRNG bytes into
      `0x0BFA_0080..0x0BFA_00A0` on first secure-world boot of a blank
      MCU. Gated today by the absence of the `otp-hardcoded-master-key`
      feature; `ensure_device_master` burns on demand once, locks the
      region, reads back thereafter. Per-MCU, one-way, not rewriteable.
      **Once work-todo #7 Tier 1 (DHUK) lands**, the master-key region
      demotes to salt duty and may be repurposed — at which point burning
      it stops being required for SE-pairing, and the irreversibility
      concern narrows to "whatever salt consumers we later add." Until
      then, this burn stays mandatory.
- [ ] **OTP rollback-counter tally** (`ROLLBACK_WORDS = 32`, 1024
      commits). Each accepted firmware-update CHUNK+COMMIT clears one
      bit; never reset. Exhausted parts are update-dead — treat that as
      the device's end-of-life.
- [ ] **BHK page first-write** (work-todo #7 Tier 2). 32 TRNG bytes
      DHUK-ECB-wrapped and written to the dedicated BHK secret-flash
      page on first-boot provisioning. The wrapped bytes themselves are
      not a silicon commit (flash can be re-erased), BUT once any SE is
      paired with a `secret_keys::*_v1` derivation that consumed this
      BHK, re-generating BHK invalidates that pairing — which is the
      same class of brick as a lost PBS. Treat the first BHK write as
      a per-device one-way event even though the underlying storage is
      erasable. Firmware-update paths MUST NOT touch the BHK page; the
      linker script carves it out of the bank-2 update region and
      `fw_update` rejects writes that overlap it.
- [ ] **DHUK availability probe** (work-todo #7 Tier 1). Before any
      DHUK-based derivation, verify SAES returns stable output for a
      known test vector (`SAES-CMAC(DHUK, b"dhuk-probe-v1") == X_for_this_die`).
      The output is per-die — we cannot pre-compute it at the factory
      across a fleet, but we CAN record each production chip's probe
      output alongside its UID at provisioning time, and compare against
      the same probe on every subsequent boot. A mismatch means chip
      transplant / DHUK regression / SAES peripheral glitch — device
      refuses to unlock. Probe output is non-secret (only proves DHUK
      is reachable, same as a UID read), safe to store in the binding
      manifest from #22.
- [ ] **RDP = Level 2.** Once the factory burns RDP=2, debug access is
      permanently disabled. No JTAG, no SWD, no read-out of flash.
      Required before shipping to prevent flash extraction. Note:
      RDP2 → RDP0 regression on STM32U5 does a mass erase but survives
      for OTP (confirmed behaviour; OTP is the anchor of trust). Also
      confirmed: **DHUK survives RDP2→RDP0 regression** — it's silicon-
      fused, not in flash — so Tier 1 derivations still reproduce after
      a mass erase. **BHK does NOT survive** — its DHUK-wrapped bytes
      live in flash, which is mass-erased. A regressed + re-provisioned
      device generates a fresh BHK → Tier 2 pairings re-key, which means
      SE050 + TROPIC01 (if on BHK per the work-todo #7 split) must be
      re-paired via the normal first-boot provisioning path. Document
      this in the refurbishment / RMA flow.
- [ ] **WRP1A on FSBL pages (0..3).** Writes to the first-stage
      bootloader flash region are rejected post-commit. Makes the FSBL
      immutable in the field.
- [ ] **WRP on BHK page** (work-todo #7 Tier 2). Write-protect the BHK
      page via WRP1B or a second WRP group so no rogue firmware can
      overwrite DHUK-wrapped BHK bytes and force a pairing mismatch.
      Erase-allowed only during factory provisioning.
- [ ] **SECBOOTADD0 set to the FSBL base.** Secure boot points to the
      signed entry.

#### Pre-commit checklist

1. All firmware built with matching `SOURCE_DATE_EPOCH` and
   `--build-id=none`; `make verify-repro` green.
2. `fwsign verify-release` passes against the vendor public key that
   will be baked into the FSBL.
3. OTP master burn validated on at least two sacrificial MCUs —
   first-boot burn + subsequent-boot read back both produce the
   expected derivation outputs.
4. **DHUK probe recorded per part** (work-todo #7 Tier 1). At first
   boot of the sacrificial MCU, compute `SAES-CMAC(DHUK, b"dhuk-probe-v1")`
   and log the 16-byte output. Reboot and confirm it reproduces. This
   per-die value becomes the authenticated anchor stored in the #22
   binding manifest.
5. **BHK first-write + DHUK-wrap readback** (work-todo #7 Tier 2). On
   the same sacrificial MCU: TRNG 32 bytes → SAES-ECB-encrypt under
   DHUK → write to BHK page. Reboot. DHUK-ECB-decrypt the page → compare
   to pre-wrap bytes. Apply a firmware-update cycle (simulated `.pqfw`
   install) and confirm the BHK page is preserved byte-for-byte and
   the re-wrap still yields the same bytes — this is the "BHK survives
   legitimate updates" regression gate. Then rehearse an RDP2→RDP0
   regression on a SECOND sacrificial MCU and confirm the BHK page
   is erased (expected) while DHUK is still reachable.
6. RDP=0 → RDP=1 transition rehearsed on a sacrificial part. Device
   still boots, firmware updates still accepted, debug access denied.
7. RDP=1 → RDP=2 rehearsed on a second sacrificial part. Confirm:
   firmware updates still accepted; no debug interface; OTP survives
   an RDP2→RDP0 regression (mass erase clears main flash, OTP
   persists); DHUK probe still reproduces post-regression; BHK page
   is confirmed gone post-regression (and re-provisionable).
8. Only then: production line flips each part through OTP-burn →
   DHUK-probe-record → BHK-first-write → OPTIGA-provision →
   SE050-provision → option-byte lock in sequence, with per-part
   logs recording every step's observable (fingerprints, return
   codes, readback matches, DHUK probe output).

### SE050 — SCP03 + ADMIN provisioning

The SE050 half of the dual-SE also has irreversible steps (per
`docs/se050-factory-reset.md` + work-todo #20). Summarising here:

- [ ] **SCP03 keys rotated per device**. Derivation root migrates
      alongside work-todo #7 tiers:
      - Today: hardcoded AN12436 defaults.
      - Post-#24 (OTP tier, **landed**): per-device via
        `HKDF(OTP_master, "se050-scp03-{enc,mac}-v1")`.
      - Post-#7 Tier 1 (DHUK): same API surface, underlying primitive
        becomes `SAES-CMAC(DHUK, "se050-scp03-{enc,mac}-v1")`.
      - Post-#7 Tier 2 (BHK, final recommended split): `SAES-CMAC(BHK,
        "se050-scp03-{enc,mac}-v1")` per the per-SE selector split in
        work-todo #7.
      PUT KEY `INS=0xD8` from KVN=0x0B to KVN=0x11 at rotation. Once
      rotated, losing the derivation root means losing the chip — same
      class of failure as the OPTIGA PBS brick.
- [ ] **Admin UserID at 0x7B06_00A0** with two-entry TAG_POLICY
      provisioned. Admin PIN migrates alongside work-todo #7:
      - Today: TRNG-generated at first-boot, persisted plaintext to
        STM32 secure-flash page 125 (`ADMIN_PAGE_ADDR`). Wiped at
        `erase_admin_page()`.
      - Post-#7 Tier 2: derived on demand from BHK as
        `SAES-CMAC(BHK, "se050-admin-pin-v1")`. Page 125 retires.
        Wipe flag migrates to a new home (OTP one-shot bit or a
        dedicated flash page).
      Wipe flow validated today via `make se050-admin-wipe-e2e` +
      `make dual-se-admin-wipe-e2e` (pending, work-todo deferred).
- [ ] **User UserID PIN storage.** Change the UserID's policy to
      whatever we ultimately ship (currently in `docs/se050-userid-
      pin-auth.md`); post-provision, policy is frozen.

### Supply-chain attestation (work-todo #22)

- [ ] **SLH-DSA-128s factory manifest signed with HSM key.** Once the
      HSM key is created, the corresponding trust anchor is baked into
      the FSBL. Rotating the HSM key requires a firmware update on all
      already-shipped devices. Treat the initial HSM-key ceremony as
      a one-way event.
- [ ] **Transparency log append for each device.** Appending is
      trivially reversible (just don't append), but by the time a
      device is shipped, its manifest hash must already be in the log
      for the verification ceremony to succeed. Missing a device →
      that device fails its own box-opening ceremony.

### Firmware-update signing

- [ ] **Vendor signing key(s) established.** SPHINCS+C10 keypair,
      private key kept in Argon2id + XChaCha20-Poly1305 encrypted
      blob (see `fwsign keygen`). Losing the private key means no
      future updates for the installed base. The public key is baked
      into the FSBL at factory provisioning — changing it requires
      an FSBL update, which requires WRP1A unlock, which requires
      RDP regression (mass erase). So: lose the key, lose the fleet.

## Where items come from

When an item is moved out of `docs/work-todo.md` into here, the diff
looks like a removal from work-todo.md and an addition here, with
the context preserved. The intent is that work-todo.md stays
strictly reversible so dev iteration is always safe, while
production-todo.md is the "commit ceremony" checklist.

When a dev flow discovers a new one-way action (say, a new SE
provisioning step), the item lands HERE by default. Only after it
becomes clear that a reversible variant can be written — e.g., gated
behind a feature that keeps the chip at LcsO=Creation — does a
reversible sibling appear in work-todo.md.

## Current validation state

As of 2026-04-21:

- **Phase A (reversible) validated** on a TRUSTMV3SHIELDTOBO1 —
  `docs/work-todo.md` #24 P2. Shielded Connection + PIN unlock +
  factory_reset roundtrip all PASS on real silicon.
- **Phase B (irreversible, E140 LcsO=op)** not yet attempted. No
  sacrificial part burned yet. When it happens, it goes against a
  fresh TRUSTMV3 shield with the pre-commit checklist above fully
  passed.
- **OTP master burn path** still under the hardcoded-master-key
  feature on every dev build. First-burn validation on a
  sacrificial MCU is still owed.
- **DHUK + BHK tiers** (work-todo #7) not implemented yet. All SE
  pairings today derive from the readable OTP master; Tier 1
  migration has not started. The DHUK probe → per-part record flow
  and BHK first-write are all factory-only actions that land
  concurrently with #7.
- **RDP + WRP1A + SECBOOTADD0** never exercised. `make stm32-harden-
  opts` in the Makefile sets BOR/SRAM2_RST only.

Nothing from this list has been committed on any dev unit. When
anything does get committed, this file gets a dated entry recording
which part, which commit hash, and which checklist run justified the
flip.
