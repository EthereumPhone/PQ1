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

      **Pre-production validation — verify OTP actually programs on the
      target chip before shipping.** Not every STM32U585 with clean
      option bytes accepts user-OTP writes. On one B-U585I-IOT02A
      (`Rev W`) dev board we hit `SECSR=0x90` (`WRPERR|PGSERR`) on every
      quad-word in `0x0BFA_0080..0x0BFA_00A0`, with:
      - `RDP = 0xAA` (Level 0)
      - `OTPBLR_CUR = OTPBLR_PRG = 0`
      - No WRP coverage of OTP
      - `HDP1EN = HDP2EN = 0`
      - `TZEN = 1`

      Option bytes looked identical to a known-good board. Suspected
      root cause is a non-display-able RSS / debug-authentication /
      OBK-seal state left by some prior programming session, or a
      silicon quirk on that specific revision (see ST errata ES0499).
      `STM32_Programmer_CLI -psrss` returns "not supported for this
      device" on U5, so there's no host-side command to introspect or
      regress the state once it's latched.

      Production gate: for each chip, **flash a minimal test image that
      calls `otp::ensure_device_master` and confirms the burn + readback
      succeeds** before committing the unit to fulfillment. A chip that
      can't program user OTP cannot run the shipping firmware
      (no real PBS → no Shielded Connection → no dual-SE pairing) and
      must be rejected, not patched with `otp-hardcoded-master-key`.
      The dev-only `optiga-factory-reset-hw` /
      `optiga-preprovision-hw` /
      `flash-hw-optiga-oled-standalone-testkey` targets sidestep this
      check by using a compile-time shared-across-dev-boards PBS
      constant — never enter production with that feature set. The
      `make prod-check` CI gate is what catches this;
      `otp-hardcoded-master-key` in a non-`e2e-test` release build is
      already a `compile_error!` in `secure/src/nsc/mod.rs`.
- [ ] **OTP rollback-counter tally** (`ROLLBACK_WORDS = 32`, 1024
      commits). Each accepted firmware-update CHUNK+COMMIT clears one
      bit; never reset. Exhausted parts are update-dead — treat that as
      the device's end-of-life.
- [ ] **BHK page first-write** (work-todo #7 Tier 2 Phase 2B). 32 TRNG
      bytes DHUK-ECB-wrapped and written to the dedicated BHK secret-
      flash page on first-boot provisioning. The wrapped bytes
      themselves are not a silicon commit (flash can be re-erased), BUT
      once any SE is paired with a `secret_keys::*_v1` derivation that
      consumed this BHK, re-generating BHK invalidates that pairing —
      same class of brick as a lost PBS. Treat the first BHK write as
      a per-device one-way event even though the underlying storage is
      erasable. Firmware-update paths MUST NOT touch the BHK page; the
      linker script carves it out of the bank-2 update region and
      `fw_update` rejects writes that overlap it. **Staged rollout:**
      Phase 2A landed the cryptographic primitive (`cmac_bhk` +
      `derive_into_bhk` + `bhk-hardcoded-master-key` dev fallback) with
      no chip writes; Phase 2B (this checkbox) lands the silicon path;
      Phase 2C migrates SE050 SCP03 + admin PIN + TROPIC01 pairing
      callers from DHUK to BHK with a coordinated re-pair step.
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

- [ ] **SCP03 keys rotated per device** (work-todo #11). Derivation
      root migrates alongside work-todo #7 tiers:
      - Today: hardcoded AN12436 Rev 2.4 defaults for OEF `0xA921`
        at `secure/src/se050/scp03.rs:21-30`. `KEY_VERSION = 0x0B`.
        Every device of the same firmware build shares identical
        keys.
      - Post-#11 Stage A (derivation plumbing, reversible): firmware
        pulls root from `secret_keys::se050_scp03_{enc,mac}_key()`
        under the `se050-derived-scp03` Cargo feature. Chip state
        unchanged at this stage — build just targets what it talks to.
      - Post-#24 (OTP tier, **landed**): derivation is
        `HKDF(OTP_master, "se050-scp03-{enc,mac}-v1")`.
      - Post-#7 Tier 1 (DHUK): same API surface, underlying primitive
        becomes `SAES-CMAC(DHUK, "se050-scp03-{enc,mac}-v1")`.
      - Post-#7 Tier 2 (BHK, final recommended split): `SAES-CMAC(BHK,
        "se050-scp03-{enc,mac}-v1")` per the per-SE selector split in
        work-todo #7.

      **The irreversible part — GP PUT KEY ceremony (stage B)**:

      1. Establish SCP03 against default keyset `KVN=0x0B` with the
         hardcoded AN12436 constants.
      2. Compute per-device keys via `secret_keys::se050_scp03_*_key()`.
      3. Compute Key Check Value per key: `KCV = AES-ECB-Enc(key, zeros)[..3]`.
      4. Wrap each new key: `wrapped = AES-ECB-Enc(current_key, new_key)`.
      5. Send GP `PUT KEY` (`CLA=0x84 INS=0xD8 P1=0x81 P2=0x11`) with
         body `[0x11] [0x88 0x10 wrapped_enc 0x03 kcv_enc]×3` for ENC /
         MAC / DEK (SCP03 always installs all three — AN12436 §5.2.3).
      6. Verify `SW=0x9000`.
      7. Optional stage C (#11): mix SE050 UID into derivation label for
         clone defense. One extra `ReadObject(0xA000_F00E)` on every
         subsequent boot.

      **Failure modes after commit:**
      - Lose derivation root → cannot re-establish → hard brick,
        same class as OPTIGA PBS loss. Mitigated long-term by #7
        Tier 1/2 (derivation moves off readable OTP master onto
        DHUK/BHK).
      - RDP2→RDP0 regression clears MCU flash but OTP survives →
        derivation still reproduces → rotated keyset `0x11` still
        authenticatable. Recoverable.
      - Partial `PUT KEY` (brown-out mid-rotation): potentially leaves
        the chip with one-of-three keys updated, breaking SCP03. Pre-
        commit checklist rehearsal on sacrificial parts MUST verify
        that `PUT KEY` is atomic at the chip level (NXP spec says it
        is; confirm empirically).
- [ ] **Admin UserID at 0x7B10_00A0** (range v6, bumped 2026-04-22 from
      v5 `0x7B0E_00A0` / v4 `0x7B0C_00A0` / v3 `0x7B06_00A0` across
      bench-chip cross-contamination events) with two-entry
      TAG_POLICY provisioned. Admin PIN derivation status:
      - **Today (since 2026-04-23):** derived on demand via
        `hw::secret_keys::se050_admin_pin()` = `HKDF(OTP_master,
        "pqsigner/se050-admin-pin-v1")`. Both `Se050::store_objects`
        (provisioning) and `Se050::factory_reset_admin` (wipe) use
        the derivation — page 125's PIN slot is no longer read on
        the production path. The page still holds the wipe-in-progress
        flag at offset 16 (unchanged). Same HKDF label will flip from
        OTP-master-rooted to DHUK-rooted under #7 Tier 1 with a
        one-shot on-chip rotation.
      - **Cleanup still owed (reversible, tracked in work-todo #7
        early-adopt item):** delete the remaining callers of
        `hw::flash::read_admin_pin` / `write_admin_pin` in
        `se050/mod.rs`, `dual_se.rs`, `main.rs` (five legacy / test
        paths); retire `ADMIN_PIN_OFFSET` entirely. The slot is
        dead storage today — already no code path on a clean
        provisioning reads it — but still burns a flash quadword
        per page.
      - **Post-#7 Tier 2:** same API surface, primitive becomes
        `SAES-CMAC(BHK, "se050-admin-pin-v1")` (work-todo #7).
      Wipe flow validated today via `make dual-se-admin-wipe-e2e`
      (full 8-step roundtrip including step 7 "both chips
      unprovisioned post-wipe") + `make dual-se-multi-unlock-e2e`
      (15 unlocks across 3 cold reboots) PASS on real silicon
      (2026-04-23).
- [ ] **User UserID PIN storage.** Change the UserID's policy to
      whatever we ultimately ship (currently in `docs/se050-userid-
      pin-auth.md`); post-provision, policy is frozen.

#### SE050 SCP03 rotation pre-commit checklist (sacrificial parts)

Before flipping `se050-rotate-scp03=on` on any real unit:

1. On sacrificial SE050 #1: build + flash with `se050-derived-scp03`
   only (no rotate feature). Confirm the build talks to a factory-
   default chip → SCP03 establishment FAILS with key mismatch. This
   is the expected behaviour: post-plumbing-only builds CANNOT talk
   to un-rotated chips. Log the error, no chip state committed.
2. On sacrificial SE050 #2: build + flash with `se050-rotate-scp03`.
   First boot: firmware sees default keyset, runs PUT KEY ceremony,
   rotates to `KVN=0x11` with derived keys. Second boot on the same
   chip: firmware uses `KVN=0x11` + derived keys → SCP03 establishes.
   Third boot: reflash with a comment-only code edit, confirm SCP03
   still establishes (derivation stable across firmware rebuilds).
4. On sacrificial SE050 #3: same as #2 but induce a brown-out
   mid-`PUT KEY` by cutting VCC between the ENC and MAC key writes.
   Verify on restore: either all three keys rotated (atomic), or
   chip reports specific error the code can detect and retry. If
   partial rotation survives the brown-out → halt the rollout and
   re-design.
5. On sacrificial SE050 #4 (only if stage C is shipping): repeat #2
   with UID binding enabled. Confirm derivation depends on UID:
   swap the rotated SE050 to a different STM32 board with
   `se050-rotate-scp03` built for that STM32's OTP → SCP03 establish
   fails (different OTP → different derived keys → key mismatch).
   Swap back → works. This is the clone-resistance proof.
6. Only then: production line runs per-unit `PUT KEY` → provision →
   admin UserID + user UserID install → option-byte lock. Per-part
   logs record: SE050 UID, KVN 0x11 KCV (3 bytes per key), post-
   rotation SCP03 establishment success, first-boot admin PIN
   derivation fingerprint.

#### SE050 SCP03 rotation — escape hatch

**None.** Unlike OPTIGA's SetObjectProtected + Trust Anchor recovery
(which can reset user OIDs at `LcsO=Op`), SE050 has no reset-to-
factory-keys path for SCP03. The `0x0B` default keyset still exists
on the chip (GP `PUT KEY` installs new keysets, doesn't replace the
default), but once the firmware commits to `KVN=0x11` there's no
build-time path back to `0x0B` without an explicit rollback feature
— and rolling back exposes every device to the same factory default
that made rotation necessary in the first place. Treat a lost
derivation root as a total loss of that chip.

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

### Hardening regressions — restore before production

These are pre-production regressions the bring-up branch knowingly
ships with, flagged in `CLAUDE.md` §"Development Posture" and
surfaced by the three-way PIN-sync validation runs (2026-04-22).
None of them affect the PIN-sync / wipe-dispatch paths that were
validated on silicon — the three-way lockstep, boot-time cache
re-sync, and MCU-MAX wipe dispatch all work today. They DO affect
the broader secure-world isolation that production will need.

- [ ] **GTZC1_TZSC_SECCFGR{1,2,3} allowlist restored to invariant #4.**
      Currently `secure/src/sau.rs` clears these to 0 (everything NS)
      because the first attempt at the "CRIT-4 all-secure baseline"
      mis-identified which controller governs USB OTG FS on STM32U585
      — USB OTG FS is AHB2, governed by a separate **GTZC2_TZSC** block
      whose base address we have not yet confirmed (`0x5203_4400`
      bus-faulted on first guess). This makes peripherals like I2C1,
      AES, HASH, PKA, SAES, RNG reachable from the non-secure world —
      a regression of CLAUDE.md invariant #4 ("all secrets live ONLY
      in TrustZone secure world"). Fix: locate the GTZC2 base
      empirically on the STM32U585 silicon (or via RM0456 rev C2+ if
      it lists the address), reinstate a conservative allowlist that
      lets USB OTG FS reach NS while keeping I2C1 / HASH / PKA / SAES
      / RNG strictly secure.

- [ ] **Debug instrumentation stripped from release builds.** The
      bring-up branch shipped with `debug-log` allowed on hardware
      release (the `compile_error!` gate in `secure/src/nsc/mod.rs`
      was removed), `hw::hash::init_clock`'s semihosting prints are
      `DHCSR.C_DEBUGEN`-gated rather than deleted, `secure_log!`
      calls litter the first-boot wizard, and the NS `main()` emits
      pre-USB register dumps. Production CI must gate shipped
      firmware on `debug-log`, `e2e-test`, and `mock-se` being OFF —
      the existing `make prod-check` target is the right hook, but
      needs to actually fail the build rather than warn when these
      features are present.

- [ ] **Destructive / dev-only test feature fence.** The following
      targets exist for silicon validation or bring-up diagnostics
      and must not reach production firmware: `pin-gate-wipe-e2e`,
      `pin-gate-hw-counter-e2e`, `dual-se-admin-wipe-e2e`,
      `dual-se-multi-unlock-e2e`, `optiga-admin-wipe-e2e`,
      `se050-admin-wipe-e2e`, `wipe-for-wizard`, `pin-diag-boot`,
      `dev-testkey`, `otp-hardcoded-master-key`. Most transitively
      require `e2e-test`, which is already in the `compile_error!`
      gate in `secure/src/nsc/mod.rs`, but `make prod-check` must
      fail the build when ANY of these features is enabled — the
      current gate only covers `e2e-test` + `debug-log` + `mock-se`.
      Adding a new destructive / dev-only e2e feature must land
      with a matching `prod-check` entry in the same commit.

- [ ] **`optiga-lock-operational=ON` production commit.** Every
      validated test run to date has kept every OID at
      `LcsO=Creation`. The production bump to `LcsO=Operational` is
      covered by this document's OPTIGA section (and is the defining
      commit ceremony of the OPTIGA subsystem), but also needs
      explicit cross-validation against the PIN-sync paths before
      flipping: confirm that `reset_hw_pin_counter`,
      `factory_reset`, and the three-way lockstep all still work on
      an OID set with `LcsO=Op` metadata. See work-todo.md #25 Gap 5
      for the reversible dry-run on a sacrificial chip that must
      precede any production LcsO=Op flip.

- [ ] **TAMP escalation: log-only → `trigger_lockout_wipe()`.** Today
      the polled handler in `secure/src/hw/tamp.rs` (`tamp::poll()`
      from SysTick) logs the reason via `secure_log!` and write-1-to-
      clears the SR flag — by design, so a false ITAMP9 during a
      probe-rs debug session can't wipe a bench chip. Production must
      flip three things in lockstep:
        1. Replace `secure_log!(...)` + clear in `tamp::poll()` /
           `tamp::on_tamp_irq()` with `trigger_lockout_wipe()` (which
           zeroizes seed material, erases page 124, and reboots).
        2. Move from polled to IRQ — see work-todo.md TAMP IRQ-flip
           item for the `DefaultHandler` dispatch path. IRQ latency
           (~hundreds of cycles) beats SysTick polling (~1 ms) by an
           order of magnitude, which matters when the wipe is racing
           an attacker reading residual-power side channels off the
           backup SRAM.
        3. Audit `TAMP_IER` / NVIC enable bits across all peripherals
           in the same commit — once `DefaultHandler` is dispatching,
           any unmasked IRQ on any peripheral lands there too. Without
           a firmware-wide audit of "which IERs are set right now,"
           this is a footgun. The audit + wipe-flip + IRQ-mode flip
           must all land in one diff so review can verify the trigger
           surface end-to-end.
      Reference: `docs/trezor-comparison.md §2.5`,
      `core/embed/sec/tamper/stm32u5/tamper.c:100-207`. The Trezor
      production handler is the model — `reboot_with_rsod()` after
      backup-SRAM auto-erase via `TAMP_CR3=0`. PQSigner is one
      `secure_log!` line away from that today.

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

As of 2026-04-23:

- **Phase A (reversible) validated** on TRUSTMV3SHIELDTOBO1 —
  `docs/work-todo.md` #24 P2. Shielded Connection + PIN unlock +
  factory_reset roundtrip all PASS on real silicon.
- **Dual-SE entropy reconstruction validated across reboots.**
  `make dual-se-multi-unlock-e2e` does 5 unlocks per boot across
  3 cold boots (15 unlocks total). Boots 2 + 3 detect
  already-provisioned state and skip re-provision → pure NVM
  read + XOR reconstruction, master_secret reproduces byte-identical
  every time. Closes the colleague-reported "works once, fails on
  reboot" class caused by OPTIGA RST jumper on D5 cross-coupling
  into SE050 ENA via the OM-SE050ARD shield. RST wire physically
  moved to D6 (= STM32 PE0 empirically on this board; `header_sweep`
  retained as pre-flight validator for any future board rev).
- **Dual-SE admin-wipe validated end-to-end.** `make dual-se-admin-
  wipe-e2e` PASSES all 8 steps including step 7 (both chips
  unprovisioned post-wipe). Admin PIN derivation now OTP-rooted
  in both provisioning and wipe paths; 6-canary selftest proves
  the 6-delete-under-one-session shape that production
  `admin_factory_reset` depends on is stable on the chip.
- **Phase B (irreversible, E140 LcsO=op)** not yet attempted. No
  sacrificial part burned yet. When it happens, it goes against a
  fresh TRUSTMV3 shield with the pre-commit checklist above fully
  passed.
- **OTP master burn path** still under the hardcoded-master-key
  feature on every dev build. First-burn validation on a
  sacrificial MCU is still owed. The admin-PIN derivation now
  depends on this — migrating off `otp-hardcoded-master-key` is
  a prerequisite for any chip ever leaving the bench.
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
