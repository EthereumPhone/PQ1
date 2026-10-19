# EVT-3D21 burn-down run sheet: one unit, top to bottom

**Created 2026-10-19.** This is an ordered run sheet for sacrificing **one** EVT board
(EVT-3D21, MCU UID `003D0021 30465002 2033314C`). Work through it from top to bottom.
When you reach the end, the unit is fully provisioned and locked at RDP 2, and every
silicon assumption that one unit can test has been tested on it.

**How it relates to the other docs.** This sheet sets the **order** and the **gates**. It
does not repeat procedures. Each step names its row in
[`dvt-silicon-test-checklist.md`](dvt-silicon-test-checklist.md) (written `DVT 7.4`,
`DVT 6B.13` and so on). The procedure, its history and its status cell are kept there.
Record each result in **both** places: tick the box here, and update the status cell and
the Evidence log there.

---

## Permanent changes to this unit (read before using the board)

Every 🟡 step, and anything else that a restore cannot undo, is listed here as it happens.
If you pick up EVT-3D21, this table is what differs from a factory-fresh unit.

| Date | Step | What changed | Undo? |
|---|---|---|---|
| 2026-10-15 | (before this sheet) | SE050 UserID `0x7B5E_00A0` (stress admin, self-delete only); stale e2e objects `0x7B0A_0000`, `0x7B0A_00A0` | the `0x7B0A_*` pair is deleted in G1 |
| 2026-10-15 | (before this sheet) | Option bytes TZEN=1, SECWM2 bank 2 NS, SRAM_RST=0 (factory: TZEN=0) | RDP 0→1→0 with TZEN=0 |
| 2026-10-19 | F (pairing) | OPTIGA E140 = the bench PBS (`otp-hardcoded-master-key`, fp `9aea9d57…`), written by a `se-lcd-diag` boot. Factory value (Infineon's public sample PBS) backed up in `evt-burn/A/` | rewritable while LcsO=creation |
| 2026-10-19 | F3 | OPTIGA F1D0 metadata = hw-counter variant (`Execute=Luc(E120)`, `Change=ALW`); E120 provisioned as the LUC (`Change=Auto(F1D0)`, limit 32) and **lifetime attempts consumed by F3/F4** | metadata rewritable while LcsO=creation; E120 reset needs F1D0 auth |
| 2026-10-19 | F2 (AC probe) | OPTIGA spares now differ from factory: F1D5 = a throwaway AuthRef (`AUTOREF`, `Execute=ALW`, `Read=NEV`, 32 B of TRNG nobody kept); F1D7 and F1E0 = 32 B, `Change=ALW Read=ALW Execute=NEV` (were 100 B / 1500 B of zeros, `Change=LcsO<op`) | rewritable while LcsO=creation |
| 2026-10-19 | F4b (`pin-gate-wipe`) | Ends by re-provisioning a **test wallet** (fixed e2e mnemonic, PIN `00000000`) on both chips: OPTIGA F1D0–F1D4 + F1E1, SE050 `0x7B10_*` objects, page 125 salt | G1 (`wipe-for-wizard`) removes it |
| 2026-10-19 | F7a (`se050-stress-destructive`, 23 PASS / 0 FAIL) | Carve-out UserIDs/objects in `0x7B5E_*`; **exact list not yet taken** (the follow-up `se050-probe` was stopped) | locked/no-admin UserIDs are permanent; run `make se050-probe-hw BOARD=pq1` and list them here |
| 2026-10-19 | F7b (`se050-admin-extract-attempt-e2e`, PASS) | possibly one undeletable carve-out UserID (row 8.3) — same probe owed | — |

### State at stop (2026-10-19 17:18, owner stopped the run)

- **Flash is NOT the baseline:** last image = `se050-probe` secure ELF over a dual-SE e2e
  NS image. **Page 123 is erased** (it held 512 B of records; something in F4 erased it),
  page 125 holds 48 B (the test wallet's salt), pages 124/126/127 erased. Restore with
  `evt-burn/bin/restore.sh <dir>` (mass erase, then the A2 image, page 123 records-only)
  — but only after G1, because page 125 must match the SEs until they are wiped.
- OTP blank (`9f56cda7…`, read at stop). Option bytes unchanged from A2.
- Both SEs hold the F4b test wallet (see table). Next: `sprobe` to list the F7 leftovers,
  then F8, then G1.

## Run log

**2026-10-19 (afternoon), ST-LINK V3SET on J210 + USB-C only** (no panel, buttons, J211
UART, LA or relay). Commit `43dad543`, then `e02471e9` from F3 on. Runners in
`~/Documents/PQ1/evt-burn/bin/` (`b1.sh`, `f.sh`, `build_pair.sh`, `restore.sh`);
evidence in `~/Documents/PQ1/evt-burn/<part>/`.

Harness lessons from this run: `pkill -f <pattern>` kills your own shell when the
pattern appears in its command line (kill by PID); a stale `probe-rs run` holds the
ST-LINK (`interface is busy`); a PASS regex must be anchored to the firmware's `[E2E-…]`
line, because the Makefile's own `echo "(watch for … PASS)"` line matches otherwise
(three false PASSes before this was caught; the images had never run).

---

## 0. Read first

### 0.1 You cannot run this sheet end to end today

Parts A–G (everything reversible) can be run now. **Part H onwards (the irreversible
half) is blocked by code and owner gates.** They are listed in [Part G3](#g3--stop-gate).
In short:

- **No lockable image exists.** `rdp2-self-lock` requires `mode-production`, and every
  `mode-production` hardware build is refused by `FW_ROLLBACK_PRODUCTION_BLOCKED`
  (`secure/src/nsc/mod.rs:522`, `secure/build.rs:37`) and `OPTIGA_S2_PRODUCTION_BLOCKED`
  (`nsc/mod.rs:315`). The `bench-ship-validation` configuration that would solve this
  needs owner sign-off and does not exist yet (#268, DVT O-3).
- **No factory provisioning image can be built.** Every `*factory-provisioning*` target
  is a Makefile `$(error)`, and `FW_ROLLBACK_FACTORY_BLOCKED` fences the code.
- **The SE050 factory→transport `PUT KEY` is not implemented.** The only `PUT KEY` paths
  are the sacrificial BHK-rooted `se050-rotate-scp03`, which you must **not** run on this
  unit (it conflicts with Phase B), and the fenced Phase-B `rotate_scp03_transport_to_final`.
- **Phase A halts at `E0809`, then at `E080A`,** until `WRP1A_MASK_PINNED` and
  `OEM_LOCK_MASK_PINNED` are flipped (`shared/src/lockdown.rs`). Row 2.2 has already
  pinned the WRP1A layout on silicon. The OEM-lock bits still need a positive detection,
  which must **not** be done on this unit (see Appendix A).

### 0.2 You need a panel and two buttons

Every trusted-UI decision reads only GPIO PA0/PA1. Nothing in a lockable image accepts
keys over UART, USB or RTT, and no lockable image mirrors the screen. That covers the
Phase-A lock confirm, the seed wizard, PIN entry and every sign confirm. The PIN pad
starts each digit at a random value, and the wizard shows the 24 words only on the panel.
So without a panel, PIN entry and wallet creation are impossible, not merely
inconvenient. See [§1](#1-equipment-and-board-mods).

### 0.3 Legend

| Mark | Meaning |
|---|---|
| 🟢 | Reversible. Restore afterwards and verify the restore. |
| 🟡 | Consumes counters, or leaves a permanent but harmless leftover (named in the step). |
| 🔴 | **Point of no return.** Before every 🔴 step, write the owner go (date, exact operation, exact range) in the step's `Owner go:` line. Per `planning-and-review-workflow.md` §11, a failure does **not** authorise a retry. |
| 🛑 | STOP. Do not go past this line until every box above it is ticked or explicitly waived. |
| 🛠 | The harness or code for this step does not exist yet. Write it first, or mark the step ⏸ with the reason. |
| ⚡ | Brick risk to this unit. These steps are optional, and the run sheet recommends skipping them. |

### 0.4 Rules that hold for the whole sheet

1. **OTP stays blank until H2.** Every image flashed before H2 must include
   `otp-hardcoded-master-key`, `dev-testkey` (which implies it) or `saes-dhuk`. Otherwise
   `otp::ensure_device_master()` burns the master on first boot (DVT bench rule 1). After
   each image, re-read the OTP under reset and expect `9f56cda7…`. *(10-19: `mock-se`
   images are exempt by construction: they build neither `pin_gate` nor an SE driver
   (`main.rs` gates `pin_gate` on `se050`/`optiga-trust-m`), and nothing else reaches
   `secret_keys::derive_into`. `test-key-speed`, `fw-rollback-hw`, `fwup-transport-hw`
   and friends rely on this.)*
2. **No SE050 image with the AN12436 default keys after H3.** Once the SE050 keyset has
   moved off the factory keys, any bench image that still uses them (`se050-stress*`,
   `se050-probe`, `se050-platform-scp-hw`, all `*-e2e`) sends a **wrong host cryptogram**.
   A GP keyset failure counter could block the platform keyset for the life of the chip.
3. **Before every SE050 image,** check that MCU pages 124 and 125 are erased. Otherwise
   the boot wipe block can `factory_reset_admin()` the chip (DVT §6B rules).
4. **Read flash only with `mode=UR`.** To restore page 123, write only its record QWs,
   never a full 8 KB page image (DVT harness lessons).
5. **Snapshot before and after every Part:** 2 MB flash ×2, OTP ×2, `-ob displ`, plus
   `SHA256SUMS`. Store them in `~/Documents/PQ1/evt-burn/<part>/`.
6. **Freeze the commit for Parts H–K.** Re-run the Part-B regression set on that exact
   commit before H starts. Evidence from an older commit does not count for the shipped
   image.

---

## 1. Equipment and board mods

- [ ] **ST-LINK V3SET on J210** (SWD; NRST on pin 10).
- [ ] **Buttons (required).** Wire open-drain to GND, active-low, using the internal
      pull-ups only. Never drive 3V3 onto the pads.
  - LEFT (PA0): J203, with GND on J204.
  - RIGHT (PA1): J205, with GND on J206.

  Fit a tactile switch on each, and in parallel a host-driven MOSFET or optocoupler
  (FT232H, Arduino or similar), so that long runs can be scripted (K4 needs more than
  100 confirms).
  - Timing: debounce 30 ms, long press ≥ 500 ms.
  - Chord: both keys down within 80 ms, reported as `(Right, Long)` on release
    (`hw/buttons.rs:182-189, 362-415`).
- [ ] **Panel (required from Part B13 on, and for all of I–K).** NV3007 display module on
      the 40-pin J201, as on the sealed screen unit.
- [ ] **USB-UART at 3.3 V on J211:** pin 1 = PA2 TX (USART2), plus GND, at 115200. pq1
      has no ST-LINK VCP, so the `saes-self-test-hw-rdp1` capture must be re-pointed
      here (🛠, DVT harness defect list).
- [ ] **Logic analyser** on I2C1 (PB8/PB9, OPTIGA) and I2C4 (PB6/PB7, SE050). It is the
      only way to observe the SE traffic after RDP 2.
- [ ] **Relay or programmable PSU with a GPIO trigger** on USB VBUS, driven from the LA
      trigger (for power cuts). Optionally, a second relay on the `LDO2_EN` rail.
- [ ] **BOOT0 rescue wire:** TP103 to J210 pin 1. It works only while RDP ≤ 1.
- [ ] **SBU-bridged USB-C adapter** (lent out since 2026-09-21; needed for B4 and I5).
- [ ] Optional: camera at ≥ 240 fps (13.3, 13.6, 13.8); ChipWhisperer-Husky (16.1,
      16.3); Scaffold and FaultyCat (Part L only).

---

## Part A: Intake and baseline 🟢

- [x] **A1. Identity.** Read DBGMCU `0xE0044000` and the UID, and confirm that this is
      EVT-3D21. Record the OPTIGA UID (`cd1633ca…`) and the SE050 UID
      (`0400500157990ff53d289104261f22df1390`). Rows: DVT 1.2, 6B.2.
      *10-19: `0x30076482`, UID `003D0021 30465002 2033314C`, both SE UIDs as above.*
- [x] **A2. Snapshot.** Expect flash `50b0ec89…`, OTP `9f56cda7…` and option bytes equal
      to the golden table. If anything differs, stop and explain it. Rows: DVT 1.1, 1.3,
      1.4. *10-19: flash `50b0ec89…` ×2, OTP `9f56cda7…` ×2 (blank), all 44 `-ob displ`
      fields identical to the 10-17 intake; pages 124–127 erased, page 123 = 512 B of
      records. `evt-burn/A/`.*
- [x] **A3. SE baselines.** *10-19: OPTIGA report identical to the 13:43 run (43
      factory-blank findings, SEC 0 throughout, E120 0/0); SE050 20 objects, 0
      production-range, the two stale `0x7B0A_*` objects still present; platform SCP
      `not_required`, `0x7FFF0207` absent.*
  - `make optiga-probe-hw BOARD=pq1 SWEEP=0` (keep the report).
  - `make se050-probe-hw BOARD=pq1` (expect 20 objects).
  - `make se050-platform-scp-hw BOARD=pq1 ACTION=status SE050_UID=0400500157990ff53d289104261f22df1390`
    (expect `not_required`).

  Rows: DVT 1.6, 1.7, 6B.3.
- [ ] **A4. O-13: the factory OPTIGA PBS in E140.** Part F overwrites it. Choose one:
  - (a) Back up the 64 bytes. While the chip is at LcsO=creation the PBS is
    plaintext-readable. Also check whether it equals Infineon's published sample value:
    its fingerprint `20a7ec84684f7fe1` is the same on two chips.
  - (b) Accept the loss.

  Owner choice: **(a), 2026-10-19.** ✅ Backed up through a one-off, uncommitted
  `PBSDUMP` line in the read-only probe (patch reverted, dump line scrubbed from
  `target/`). Stored as `evt-burn/A/e140-factory-pbs.{bin,hex}` (mode 600, not in git);
  SHA-256 prefix `20a7ec84684f7fe1` matches the probe fingerprint. **Finding: it is
  Infineon's public sample PBS:** byte-identical to `optiga_platform_binding_shared_secret`
  in `Infineon/optiga-trust-m` `extras/pal/linux/pal_os_datastore.c` after its 2-byte
  `0x0040` length prefix. That explains the same fingerprint on two chips: every unpaired
  OPTIGA ships with a public PBS, so the factory transport-PBS write (H4) is what closes
  it, and losing the backup would have cost nothing.
- [ ] **A5. Board mods work.** Use a mock-SE `ui-lcd,debug-log` image
  (`make play-hw-px BOARD=pq1`). Check that:
  - both buttons, and the chord, register in the log;
  - the panel lights;
  - a `uart-console` image prints on J211.

  Then restore the snapshot.

  ⛔ *10-19: no buttons, panel or J211 UART fitted (§1 board mods not done).*

---

## Part B: MCU platform, everything reversible 🟢

Mock-SE images only. Re-read the OTP after each image. Restore the flash at the end of
the Part.

- [ ] **B1. Regression set on the frozen commit.**
  - `test-key-speed`
  - `gtzc-enforcement-hw` with `tools/dvt/gtzc_sys_verify.sh`
  - `gtzc-ship`
  - `dma-probe --expect-locked`
  - `nested-gate-test-hw` and `-nctl-hw`
  - `ns-ptr-probe`
  - `toctou` (phase 1)
  - `idle_hold.sh` (bump, no-bump, no-`iwdg`)
  - `fw-rollback-hw`
  - `test-update-hw`
  - `fwup-transport-hw` and `-iwdg`
  - `saes-self-test-hw`
  - `verify-ship-state` (bench profile)

  All `BOARD=pq1`. Rows: DVT 1.5, 1.10, 1.11, 3.1–3.3, 3.5–3.7, 3.9–3.11, 4.1, 4.2, 4.7,
  5.8, 11.1, 11.2, 11.6, 11.7, 13.9, 13.10. Re-run this whole set on the Part-H commit
  (rule 6).

  ✅ *10-19 on `43dad543` (runner `evt-burn/bin/b1.sh`, logs `evt-burn/B/b1/`), OTP
  re-read blank after every image:* `test-key-speed` PASS · `gtzc-enforcement-hw` PASS ·
  `gtzc-sys` SWD verdict 22/22 · `gtzc-ship` PASS · `dma-probe --expect-locked` PASS ·
  `nested-gate-test-hw` REFUSED · `-nctl-hw` PASS · `ns-ptr-probe` ◐ 223/228, the same five
  sign-entry positive-control rows as 10-18 (B16) · `toctou` phases 0/1 pass (2/3 move no
  data since #982, as expected) · `idle_hold.sh` bump / no-bump / no-`iwdg` PASS ·
  `fw-rollback-hw` PASS · `test-update-hw` PASS · `fwup-transport-hw` and `-iwdg` PASS ·
  `saes-self-test-hw` PASS, DHUK fp `117d822a62a50830` (RDP 0) · `verify-ship-state`
  17/17. *Harness note: right after `fwup-transport-hw` one OTP read returned no file and
  the runner stopped on "OTP CHANGED"; two re-reads were blank. The runner now retries
  and reports a failed read separately (exit 98) from a changed OTP (exit 99).*
- [ ] **B2. GPIO lockdown, fully.**
  - Clock GPIOC and read `GPIOC_SECCFGR` (PC13).
  - Write-probe the SE buses PB6–9, the LCD pins and PA0/PA1 through both ODR and BSRR,
    and watch the pads on the LA.
  - Fix the `0x9110` mask in the verify script.

  Row: DVT 3.4.
- [ ] **B3. WRP really blocks erase and program, in hardware.** Set
      `WRP1A_PSTRT=0 WRP1A_PEND=3 UNLOCK_1A=1`. Then run a firmware
      `erase_secure_page(0)` and a raw `SECCR` PER/STRT erase, and expect `WRPERR` on
      both. Restore `0xFF80FFFF`. 🛠 bench hook. Row: DVT 2.3.
      ⛔ *10-19: the option-byte write + raw erase was refused by the Claude Code auto-mode
      permission gate ("irreversible local destruction"), as on 10-15. Needs an explicit
      owner permission rule, or a human at the keyboard.*
- [ ] **B4. MP strap.** Tie TP103 to GND and power up through the SBU adapter. Expect no
      `0483:df11`. Row: DVT 2.11.
- [ ] **B5. Torn flash writes, reset sweep** on pages 123, 124, 125 and 127. Apply the
      `torn-write-test` harness with the SRAM2 arm word (`run-2026-10-18-loop5/p53/`).
      Pass: every outcome is old, new or fail-closed, and the PIN counter never
      under-counts. Afterwards re-write only page 123's records. Row: DVT 5.3
      (`HW-ASSUME-QW-ATOMIC`, reset half).
- [ ] **B6. SRAM retention by reset type.** Use the relay for the POR legs (0.1, 1 and
      10 s off), a BOR dip, SYSRESETREQ and IWDG. NRST is already done. Row: DVT 5.4.
- [ ] **B7. BOR threshold** with slow and fast ramps on the PSU. This feeds the
      `BOR_LEV` decision used in H5. Row: DVT 5.7.
- [ ] **B8. False-tamper soak.** 72 h with log-only `tamp`, plus USB plug cycles. Pass: zero
      events. This must pass **before** you ship a `tamp-wipe` image in H. Rows: DVT
      5.11, 5.13 (doc fix).
- [ ] **B9. Forced ITAMP drives the full wipe-flag path** (mock SE). Row: DVT 5.12.
- [ ] **B10. FSBL halt paths and slot B.** Measure the stack high-water mark on a halt
      path and on a slot-B fallback. Row: DVT 5.10.
- [ ] **B11. Readout before first power (invariant #10a).**
  1. Erase page 5.
  2. Hold NRST with `adapter assert srst` (openocd).
  3. Unplug and replug USB-C.
  4. Read page 5 under reset: expect all `0xFF`.
  5. Release, then expect 19 markers.

  Row: DVT 10.9.
- [ ] **B12. Update power cuts and slot selection.**
  - A cut at every update step boots the old slot.
  - BEGIN erases the non-running slot.
  - Page 126 is unchanged on a `bhk` build.

  Rows: DVT 11.3, 11.4, 11.5.
- [ ] **B13. Trusted UI on glass** (mock SE, panel and buttons fitted).
  - Sign gesture: on every screen of every family, check that it fires only at
    `sign_point`.
  - Walk all 42 `demo_px_flows.py` flows.
  - Measure the atlas-swap race.
  - Check button debounce and the chord skew, and that NS writes to PA0/PA1 have no
    effect.
  - Measure full-panel frame time and tearing.
  - Run the decoy-flicker check.
  - Camera: measure CS-to-photon latency (input to O-4).

  Rows: DVT 13.1–13.7.
- [ ] **B14. Stack high-water mark on a `ui-lcd`/`ui-px` image** with production roots, so
      that the ERC-7730 renders actually run. Row: DVT 5.9.
- [ ] **B15. FSBL words equal the secure `measured_boot` words** (a bootproof variant
      with a mock-SE slot A). Then film the 4 s FSBL window and compare it with
      `fwmeasure`. Rows: DVT 10.6, 13.8.
- [ ] **B16. Gateway pointer positive controls** for the sign entries, and the `TT`
      vs `TTA` question (needs an NS MPU fixture). Row: DVT 3.8.
- [ ] **B17. Side channels that need no SE.**
  - Check the `sca-trigger` pulse on PB3.
  - Measure SNR/TVLA with the consumption mask on and off. PA6 is NC, so expect to
    demote the claim.
  - Owner decision on the leak of the R-grind count (16.6): reword the claim, or pad
    the grind.
  - Optional: TVLA on WOTS/FORS with the Husky (16.1).

  Rows: DVT 15.2, 16.2, 16.6, 16.1.
- [ ] **B18. 24 h HID fuzz,** continuous, on the frozen commit. Row: DVT 14.1.
      Optional: Facedancer (14.2).
- [ ] **B19. Consumption-mask PRNG** compliance, measured after decision O-6 (the
      reseed-skip rate during a sign). Row: DVT 4.13.

---

## Part C: RDP-1 excursion (mass erase; OTP and SEs survive) 🟢

Do this **now**. No BHK and no BHK-rooted SE state exist yet, and the regression to RDP 0
would erase page 126.

- [ ] **C1.** Run `make saes-self-test-hw-rdp1 BOARD=pq1`, with its capture moved to the
      J211 UART (🛠). Record the RDP-1 DHUK fingerprint. It must **not** be
      `117d822a62a50830`. Power-cycle 3 times and expect the same value each time.
      Row: DVT 4.3.
- [ ] **C2. Optional, while at RDP 1:** CPA on the SAES/DHUK window with the Husky.
      Row: DVT 16.3.
- [ ] **C3.** Run `make saes-self-test-hw-rdp0-regress BOARD=pq1`.
  - Expect a mass erase.
  - OTP still blank.
  - Option bytes back to TZEN=1, SECWM, SECBOOTADD0 and SRAM_RST=0.
  - SE inventories unchanged (re-run A3 read-only).
  - If the unit is stuck at RDP 1, power up with BOOT0 high (TP103 to J210 pin 1).
- [ ] **C4.** Repeat C1 and C3 once. The fingerprint must be identical across an
      RDP 1→0→1 cycle. This covers the gap in the DHUK-RDP12 comparison: the value at
      RDP 2 (I6) is taken in a later epoch.
- [ ] **C5.** Restore the A2 snapshot. Re-write only page 123's records.

**Keep the C1 value. Step I6 compares against it (`HW-ASSUME-DHUK-RDP12`).**

---

## Part D: SE050 deep probe on the factory keys 🟢 (🟡 where marked)

The SE050 stays on the factory E2/A921 keys. No `PUT KEY`. No wrong cryptogram. The
production OID range `0x7B10_*` is not touched. Run `make se050-probe-hw` before and after,
and expect the inventory Δ to be 0.

- [ ] **D1. OS identity.** Select the card manager and read the CPLC (`GET DATA 9F7F`).
      Compare the JCOP release against the certified TOE (🛠 probe extension). Rows:
      DVT 6B.1, 1.8 (`HW-ASSUME-SE050-CERT-VERSION`).
- [ ] **D2. Genuine part.** Dump the NXP device certificates at `0xF0000001/0003/0013`
      and verify the chain on the host. Then run `ReadWithAttestation` of the UID over a
      fresh host nonce and verify it on the host (🛠). Rows: DVT 6B.7, 6.7 (design gap
      O-9).
- [ ] **D3. Config fingerprint.** Rows: DVT 6B.8.
- [ ] **D4. Transport and resets.**
  - TIMINGR (expect ≤ 400 kHz).
  - Parse the ATR/CIP.
  - Latency and WTX per command class.
  - The sustained 128 B stream.
  - Reset retention, including an explanation of `SE1_EN` (ENA = Deep Power-Down).
  - Link-fault hooks.
  - The large-read ceiling.

  Rows: DVT 6B.9–6B.15.
- [ ] **D5. SCP03 channel.**
  - Handshake fields over 1000 handshakes (expect KVN `0x0B` and no card-challenge
    repeat).
  - A downgraded command inside a 0x33 session is refused.
  - The SE-03 bare-SW reply is reachable.
  - A tampered response is rejected.
  - LA capture on I2C4 shows only ciphertext and MAC.

  Rows: DVT 6B.16–6B.20, 6.2 (S-5).
- [ ] **D6. Object semantics on carve-outs:** read bounds, write bounds, session
      isolation, and UserID value lengths. Rows: DVT 6B.24, 6B.25, 6B.26, 6B.28.
- [ ] **D7. TRNG and timing.**
  - ≥ 1 MB plus SP 800-90B `ea_non_iid`.
  - 200 resets of each kind.
  - Welch timing of present, absent and refused objects.

  Rows: DVT 6B.29, 6B.30, 6B.31.
- [ ] **D8. Firmware integration.**
  - `check_provisioned` under a bus fault.
  - The `rng_strong` SE050 leg fails closed and then recovers.
  - `admin_exists()` and `pin_attempt_count_raw()` on silicon.

  Rows: DVT 6B.33, 6B.34, 6B.35.
- [ ] **D9. 🟡 Attempt-burning policy rows, carve-out objects only.**
  - UserID lockout surfacing (`0x6986` at CreateSession, persistence across reinit and
    power, the `0x63Cx` format).
  - S-6: an admin cannot delete a no-admin UserID.
  - Wrong-value verify timing.

  Leaves undeletable `0x7B5E_*` UserIDs on the chip for good; list them in G1. **Not**
  the wrong-cryptogram keyset counter (Appendix A). Rows: DVT §6B.H, 6B.27, 6B.32.

---

## Part E: OPTIGA deep probe on spare objects 🟢 (🟡 where marked)

Follow the §6A rules: never write E140, F1D0–F1DB, E120/E121, F1E1, the trust anchors,
the certificates or LcsG/LcsA; never set an LcsO or a `NEV` access condition. Sessions
open under the factory PBS read in place. Back up each spare object's data and metadata
before the first write, and compare byte for byte after restoring it.

- [ ] **E1. Read and handshake rows.**
  - Opcode and parameter sweep (needs a separately fenced, supervised probe 🛠).
  - Read bounds.
  - `CalcSign(E0F0)` challenge plus CA verify.
  - 200 resets of each kind, including `SE_RST`.
  - 1 MB plus SP 800-90B.
  - 1000 handshakes, logging `random_S`.
  - Error-frame authentication.
  - Timing.
  - Retention matrix.

  Rows: DVT 6A.3–6A.12, 6.8.
- [ ] **E2. ★ 🟡 Is the LUC lockout real?** Test every authentication shape against E122.
      Also cut power during a wrong attempt (≥ 1000 `LDO2_EN` cuts) and check that no
      attempt is refunded. Exercise the counter itself. Rows: DVT 6A.13, 6A.14, 6A.15
      (#122, SE14). **If any shape bypasses the counter, stop and reopen S-3 before
      Part H.**
- [ ] **E3. Auth, access conditions and records.**
  - The interposer auth window.
  - Auth lifetime.
  - Direction of Conf(E140) enforcement.
  - Tampered and replayed records.
  - HMAC replay and timing.
  - Write bounds.
  - **Torn writes on F1D7/F1E0 and metadata.** Phase-B E140 rotation depends on this.
  - Metadata parser.
  - SecurityStatus.
  - Hibernate.
  - Protected Update negatives against F1E0.
  - Link recovery.
  - Driver replay.
  - Wrong-PBS wedge.
  - E0C3/E0C4.

  Rows: DVT 6A.16–6A.31.
- [ ] **E4.** Restore every spare object. Re-run `optiga-probe-hw` and expect the
      metadata to be byte-identical to A3.

---

## Part F: Wallet flows on bench keys (counters, wipes, power cuts) 🟡

Before starting, write the owner decision for A4: from here on E140 holds the bench PBS.
All images include `otp-hardcoded-master-key`, so the OTP stays blank.

**Pairing first (found 10-19).** The dual-SE e2e harnesses assume the OPTIGA is already
paired to the bench PBS. On a chip that still holds its factory PBS, every pre-clean
fails (`factory_reset` → `ensure_shield` → handshake rejected → `InternalError`;
the AC probe fails at `step=shield`). Pair once first: a `se-lcd-diag` image
(`se-lcd-diag,dual-se,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,board-pq1`)
calls `pair_for_first_boot()`.

*10-19 results (`evt-burn/F/summary.txt`):* F1 ✅ ALL 3 BOOTS PASS (after pairing) ·
F2 ✅ AC-PROBE PASS (stored Read AC `23 F1 D5 FD 20 E1 40`, plaintext read → `Status(0xFF)`),
and the wallet probe shows F1D1–F1D4 `Read=Auto(F1D0) && Conf(E140)`, plaintext refused
(`lec=07`) — row 8.2 · F3 ❌→✅: first run failed `setup_pbs FAILED: Shield` (driver bug:
`init()` reset the chip but kept `shield.active`; fixed `e02471e9`), then HW-COUNTER
ROUNDTRIP PASS — row 7.3 · F4 ✅ `pin-gate-hw-counter` SYNC+DESYNC PASS, `pin-gate-wipe`
WIPE+RECOVERY PASS — rows 7.4, 7.5 · F7 ✅ `se050-stress-destructive` 23 PASS / 0 FAIL / 0
SKIP, `se050-admin-extract-attempt-e2e` PASS — row 8.3 (leftover list owed) · F8 not
run (stopped). No `send_command REFUSED` in any log.

- [ ] **F1. Multi-unlock** with the LA on both buses:
  `make dual-se-multi-unlock-e2e BOARD=pq1`.
  - Expect ALL 3 BOOTS PASS.
  - Decrypt the captures offline with the bench session keys: only ciphertext and MAC.
  - Compare the wrong, real and duress APDU sequences.

  Rows: DVT 7.2, 8.1, 6.2, 6.4, 16.5.
- [ ] **F2. #116 access conditions on the real secret OIDs:** run `optiga-ac-probe`, then
      `optiga-probe-hw` on the provisioned wallet. Row: DVT 8.2. Also re-run 6A.16 on the
      wallet.
- [ ] **F3. S-3 on silicon:** `make optiga-hw-counter-e2e BOARD=pq1`. Note that this
      leaves E120 `Change=Auto(F1D0)`. Row: DVT 7.3.
- [ ] **F4. PIN attempts.**
  - `make pin-gate-hw-counter-e2e BOARD=pq1`
  - `make pin-gate-wipe-e2e BOARD=pq1`
  - Directional cold-boot reconciliation, all three legs.
  - PendSV with a persistent SE fault burns nothing.
  - PIN-pad start digits: χ² over 1000 prompts.

  Rows: DVT 7.4, 7.5, 7.6, 7.9, 7.10.
- [ ] **F5. Re-unlock after idle and LOCK.** Use
      `make flash-hw-dual-se-lcd-standalone-debug BOARD=pq1`: idle past 120 s, then
      re-enter the PIN. Also inject a bus fault on a provisioned unit and check that it
      never enters the wizard. Rows: DVT 6.5, 6.6.
- [ ] **F6. Crash safety under real power cuts** (relay, LA-triggered): mid-attempt,
      mid-provision and mid-wipe. Each cut must leave the attempt charged or the
      operation completed. Fix `se050-crash-safety-e2e` first (🛠). Row: DVT 7.7.
- [ ] **F7. 🟡 SE050 policies:**
  - `make se050-stress-destructive BOARD=pq1`
  - `make se050-admin-extract-attempt-e2e BOARD=pq1`

  Leaves one undeletable carve-out UserID. Row: DVT 8.3.
- [ ] **F8. Admin wipe.** Run `make dual-se-admin-wipe-e2e BOARD=pq1`, then do raw reads
      and dump page 125 with `mode=UR`. Then run `tzic-wipe-hw` followed by a dual-SE
      boot to finish the SE leg. Rows: DVT 8.4, 3.12.
- [ ] **F9. Secret residue on a dual-SE image** (PRF outputs, real store) after LOCK, the
      idle wipe and the TZIC wipe. Use `tools/dvt/residue.sh`. Row: DVT 5.5.
- [ ] **F10. BHK.** Run `make dual-se-bhk-e2e BOARD=pq1`. Check that BHKLOCK reads zero,
      that a forced tamper clears BKP0–7, and that a power cycle recovers on the VBAT
      supercap. Afterwards erase page 126. Row: DVT 4.6.
- [ ] **F11. `SCP_REQUIRED` inside a real dual-SE boot** (bench image with
      `se050-platform-scp-required`; #992). Then
      `make se050-platform-scp-hw ACTION=release …` and confirm `not_required`.
- [ ] **F12. Rows that need a decision first.** O-5 (PIN-pad randomisation failure must
      refuse), then re-run `rng-xor-probe`. Row: DVT 4.9.
- [ ] **F13.** Duress (DVT 7.11) is ⏸ until duress ships.

---

## Part G: Clean slate, then STOP

- [ ] **G1. Return both SEs to a known factory-like state.**
  - Run `make wipe-for-wizard BOARD=pq1`. This is safe on a blank OTP because it pulls
    in `dev-testkey`, which implies `otp-hardcoded-master-key`.
  - Delete the stale `0x7B0A_0000` and `0x7B0A_00A0` and every deletable `0x7B5E_*`
    object.
  - Confirm `SCP_REQUIRED` is released and `0x7FFF0207` is absent. A leftover bench
    credential makes the production boot halt at `E0872` on every boot.
  - Run `se050-probe` and `optiga-probe` one last time. **This is the last run of any
    image on the default SE050 keys.**

  Record the leftovers that stay permanently: ______
- [ ] **G2.** Erase pages 123–127 completely (Phase A requires them blank, `E080B`).
      Re-read the OTP: still blank.

### G3 · 🛑 STOP gate

Do not start Part H until every line is closed. Each one is a code change or an owner
decision.

- [ ] **`bench-ship-validation` image** (#268, O-3): satisfies the self-lock fences, uses
      a bench FSBL vendor key, has a slot layout (not monolithic), shows a loud
      non-shippable banner, and is excluded from release packaging. **This EVT has no
      other output channel after RDP 2, so ask for these too** (owner OK needed, all
      non-secret): on J211 it prints
  - the journal step and `E08xx` codes;
  - the DHUK fingerprint with the same KAT as `saes-self-test`;
  - the option-byte words read back by firmware.
- [ ] **A factory bench image that builds on pq1** and does steps H2–H4. Today every
      `*factory-provisioning*` target is `$(error)`. Known code bug to fix first:
      `factory_provisioning.rs:229` programs the OTP sentinel quad-word at step 0, and
      step 7 programs the same quad-word again. `hw/otp.rs:830` itself says the
      STM32U585 rejects that second write.
- [ ] **SE050 transport keyset.** Either implement factory→transport `PUT KEY`, or decide
      that on this unit the AN12436 keyset serves as "transport" and Phase B does a
      single `PUT KEY` from factory to final.
- [ ] **`WRP1A_MASK_PINNED = true`** (silicon readback is already in DVT 2.2).
- [ ] **`OEM_LOCK_MASK_PINNED = true`**, after a positive OEM1 detection on a **dev kit**
      (Appendix A).
- [ ] **FSBL geometry and WRP page range** (#540): today 3 pages at `z`, or 4/5 pages.
      Plus the both-bank policy (#42/#43/#44). `ship-option-b` must have no `PENDING`
      fields left.
- [ ] **Owner decisions:**
  - O-7 IWDG_SW
  - O-8 SRAM banks
  - O-10 post-wipe end state
  - O-11 nSWBOOT0/nBOOT0/BOOT_LOCK
  - `BOR_LEV` (from B7)
  - S-2 trust-anchor policy (fill-and-lock vs neutralise)
  - E140 ordering: LcsO=Op ratchet at the factory before Phase B, or after
  - Factory receipt: stubbed for this bench run, or implemented
  - O-2: written answer from ST on whether the `0x3007` die is in scope
- [ ] **`verify-ship-state` reads OTP and every option-byte field** (DVT harness
      defect list).
- [ ] **Strongly recommended:** dry-run H1–J2 first on the B-U585 dev kit with a loose
      OPTIGA shield and an SE050ARD. Then the EVT run confirms rather than discovers,
      which is what `evt-silicon-validation.md` asks of a ceremony unit.

---

## Part H: Factory provisioning on the EVT 🔴

All on one frozen commit. Build twice in clean target dirs and record the hashes. The
factory image is flashed over the FSBL pages, so **every factory step has to run before
WRP is set in H5.**

- [ ] **H1. Phase-A refusals, all at RDP 0 and reversible.** Flash the ship image (slot
      layout). Before each boot, set up one fault; after each halt, check that the option
      bytes are unchanged and RDP is still `0xAA`.

  | Fault | Expected code |
  |---|---|
  | WRP1A absent | `E0809` |
  | SECWM2 altered (restore after) | `E0807` |
  | A QW written into page 125 (erase after) | `E080B` |
  | OTP still blank | `E0803` |

  Each halt must be unlocked, with the code shown on the panel and printed on J211.
  `E0804`, `E0805` and `E0808` cannot be provoked on a booting unit; record that.
  Row: DVT 12.1.
- [ ] **H2. 🔴 OTP.** Owner go: ______
  1. One-way test first: program one spare QW (chosen by the owner, at the end of
     `176..512`), program it again and expect `PROGERR`, then read it back stable. Row:
     DVT 4.10 (`HW-ASSUME-OTP-ONEWAY`).
  2. Then burn the device master (factory path), read it back twice, and record its
     salted hash for the birth record.
- [ ] **H3. 🔴 SE050 factory step.** Owner go: ______
  - Create the admin UserID and the user-object policies on the transport credentials.
  - Run the transport `PUT KEY`, if G3 chose one. Record the length of the decrypted
    response body: 9 or 10 means KCVs are echoed, 0 means they are not
    (`HW-ASSUME-PUTKEY-KCV-RESP`). If 9 or 10, make the 0-length branch fail closed in
    `scp03_logic.rs` before H6.
  - Optionally set `SCP_REQUIRED` here.
  - Capture the whole step on the LA.

  **Rule 2 applies from now on.**
- [ ] **H4. 🔴 OPTIGA factory step.** Owner go: ______
  1. Write the transport PBS into E140, with the `Conf(E140)` arm kept.
  2. S-1: set F1D0 to `Change=Auto(F1D0)`.
  3. S-3: provision the E120 LUC and bind F1D0 to `Execute=LUC`.
  4. S-2: apply the owner's policy for `{E0E8, E0E9, E0EF}`. Never retype `E0E0–E0E3`.
  5. Ratchet LcsO=Op, in the E140 order chosen in G3.

  Re-read all metadata. Then check plainly that a SetData to F1D0 without auth is
  refused. Rows: DVT 9.1, 9.2, 9.3 (single-part evidence; Appendix A has the multi-part
  half).
- [ ] **H5. 🔴 Option bytes.** Owner go: ______. Write them in this order:
  1. `BOR_LEV`
  2. `SRAM_RST=0`, plus SRAM2/ECC per O-8
  3. IWDG per O-7
  4. nSWBOOT0 and nBOOT0 per O-11
  5. Confirm SECWM1/2 and SECBOOTADD0
  6. WRP2A per the both-bank policy, and HDP if decided
  7. **WRP1A over the FSBL pages with `UNLOCK=0`**. Treat it as irreversible.
  8. **`BOOT_LOCK` last**, if O-11 says yes

  Before step 7, reflash the final ship image. The FSBL pages cannot be written after
  it. Read back after every write. Then run `make verify-ship-state` with the completed
  ship profile.
- [ ] **H6. Birth record.** Under reset (`mode=UR`), dump the flash and compare it byte
      for byte with the reproducible build: everything except pages 123–127, which must
      be blank. Also record the option bytes, the OTP hash and the UID. Row: DVT 10.8.
      This record is the reference for I1.

---

## Part I: The consumer's first boot and the lock 🔴

- [ ] **I1. Consumer readout before first power** (invariant #10a). Repeat B11 on the
      shipped state: hold NRST, connect power, dump flash, option bytes and OTP, and
      compare them with H6. Write down the physical route used (J210), because O-1, the
      route on MP hardware, is still open. Rows: DVT 10.9, 10.11.
- [ ] **I2. First power.**
  - The FSBL shows its 8 words for 4 s; film them and compare with `fwmeasure`.
  - Then the lock prompt appears.
  - **Decline** with a long left press. Expect "NOT LOCKED".
  - Check under reset that RDP is still `0xAA` and the option bytes are unchanged.
  - Power-cycle and expect the prompt again.
  - Leave it at the prompt for 10 min and expect no watchdog reset.

  Rows: DVT 12.2, 13.8.
- [ ] **I3. Last SWD snapshot** (flash, OTP, option bytes, ×2). After I4 none of this can
      be read again.
- [ ] **I4. 🔴 Lock.** Owner go: ______. Page to the second confirm screen and press
      the chord. RDP becomes `0xCC`.
- [ ] **I5. ⚡ Optional power cut across `OPTSTRT`** (DVT 12.3). It may brick the unit.
      **Recommended: skip it on this unit;** do it on dev kits (Appendix A).
- [ ] **I6. After the lock:**
  - SWD connect-under-reset is refused (DVT 2.7).
  - The SBU adapter gives no `0483:df11` (DVT 2.9).
  - The option bytes printed on J211 are unchanged apart from RDP (DVT 2.6).
  - The DHUK fingerprint printed on J211 equals C1 (DVT 4.4, `HW-ASSUME-DHUK-RDP12`).
    Record the result **whichever way it comes out**.

---

## Part J: Phase B (rotation off the transport credentials) 🔴

Phase B runs by itself right after the lock. Watch it on the panel, on J211 and on the LA.

- [ ] **J1. Steps in order.**
  1. BHK first write. Page 126 must be programmable (DVT 12.5).
  2. SE050 `PUT KEY` from transport to final. Record the KCV body length again; the LA
     shows `84 D8 0B 81`.
  3. SE050 admin re-key: delete, then recreate. Expect no `0x6986` (DVT 9.6).
  4. OPTIGA E140 rotation to DHUK plus salt, through `Conf(E140)` on an LcsO=Op chip
     (DVT 9.3).
  5. `SCP_REQUIRED` and the `0x7FFF0207` credential (DVT 6B.5 integrated, #992).

  Pass: the journal reaches `ALL_DONE` and no `E08xx` appears.
- [ ] **J2. Power cuts at step boundaries** (DVT 12.4). Use the LA-triggered relay to cut
      only **after** a step's reply has been seen, once per step (5 cuts). Each resume
      must show "RECOVERING / DO NOT POWER OFF" and converge. Cuts **inside** a
      `PUT KEY` or SetData window are the atomicity question; they belong to loose parts
      (Appendix A).
- [ ] **J3. Option bytes really are frozen** (DVT 2.10). A signed bench update image tries
      an option-byte write and a page-0 erase. Expect both refused (🛠).

---

## Part K: Create the wallet, then acceptance at RDP 2

- [ ] **K1. Wizard.** Choose CREATE NEW WALLET. Write the 24 words on paper and set a PIN.
      Capture J211 from power-up to "Ready": only the allowlisted banner and codes may
      appear. Row: DVT 14.3.
- [ ] **K2. Address.**
  - Derive the address from the mnemonic on the host (🛠 if no tool exists) and compare
    it with `GET_WALLET_ADDRESS`.
  - It must be the same for chain IDs 1, 8453 and 84532 (invariant #6).
  - `GET_INIT_CODE` must be 4280 B.
- [ ] **K3. On-chain, Base Sepolia.**
  - Deploy: `INCLUDE_INIT_CODE` with slot 0.
  - A plain transfer.
  - A rotation (`REGISTER_SLOT`, slot 1).
  - A batch.
  - Safe, multiSend, CoW and ERC-7730 flows read on the panel.

  Every UserOp must be accepted on-chain, and each signature must also verify offline
  with `tools/verify-c10-sig` (invariants #5 and #8).
- [ ] **K4. Off-chain.**
  - EIP-1271, both counterfactual and deployed.
  - Then 100 more off-chain signs: the 101st without a UserOp is refused
    (`MAX_OFFCHAIN_GAP`).
  - `OFFCHAIN_STATUS` matches.
  - An unregistered slot is refused.

  Invariant #9. Script the confirms with the host-driven buttons.
- [ ] **K5. PIN and locking.**
  - Two wrong PINs, then the correct one: `GET_REMAINING` is back to 10.
  - Cut power during a wrong attempt: it is still charged after reboot.
  - The 120 s idle lock fires.
  - `CMD_LOCK` locks.

  Invariant #2, ship configuration. **Do not reach 10** (that is L1).
- [ ] **K6. Firmware update at RDP 2** with the bench key.
  - v+1 is accepted, and the new boot words equal `fwmeasure`.
  - A downgrade is refused.
  - A power cut during the update boots the old slot.

  ⛔ if the bench-ship image has no rollback backend (DVT 11.8, Draft 1.1).
- [ ] **K7. Final record.** Save, with hashes, in `~/Documents/PQ1/evt-burn/final/`:
  - the commit and image hashes;
  - the H6 birth record;
  - the C1 and I6 DHUK fingerprints;
  - the SE inventories from G1;
  - the wallet address;
  - the testnet transaction hashes.

**At this point the unit is fully provisioned.** Stop here if you want to keep it.

---

## Part L: Optional end of life (destroys the provisioned state)

Least destructive first. Each line ends the unit as a wallet.

- [ ] **L1. Ten wrong PINs** under the shipping policy: record the post-wipe end state
      (DVT 7.8, O-10). The user UserID has no admin delete, so the unit may be
      permanently unusable afterwards.
- [ ] **L2. Real tamper and ESD.** A real ITAMP drives the wipe on the ship image; then
      ESD (DVT 5.12, 17.1).
- [ ] **L3. ⚡ Glitch campaigns on the ship configuration:**
  - sign release (15.1)
  - PIN gate (15.3)
  - FSBL verify (15.4, F15)
  - consent gate (15.5)
  - ERC-7730 (15.6)

  At RDP 2 there is no `sca-trigger`, so trigger from LA events on the bus.
- [ ] **L4. ⚡ RDP-2 downgrade** (DVT 2.8, `HW-ASSUME-RDP2`).
- [ ] **L5. ⚡ Desolder each SE and replay a single chip's dump** (DVT 8.5): the Ledger
      Donjon scenario, run against production-configured chips. Pass: no PIN and no
      half. At most 10 guesses in total.

---

## Appendix A: What this unit cannot test

| What | Why not here | Where instead |
|---|---|---|
| DHUK is unique at RDP 2 (DVT 4.5) | needs ≥ 2 locked dies | a second unit (S2) |
| OEM-lock positive detection (DVT 2.4) | a set OEM key makes Phase A fail `E080A` for good | B-U585 dev kit |
| QW/OTP torn writes by crowbar (DVT 4.11, 5.1, 5.2) | can kill the die | loose U585s |
| `HW-ASSUME-PUTKEY-ATOMIC` (DVT 9.5, ship-blocker) | ≥ 5 parts, crowbar | loose SE050E2 |
| `PUTKEY-REPUT-IDEMPOTENT` | a second `PUT KEY` may brick the only SE050 | loose SE050E2 |
| SE050 wrong-cryptogram keyset counter | may block the keyset for good | loose SE050E2 |
| `E0872` squatter path (#992) | the production boot would halt on every boot | loose SE050E2 |
| OPTIGA Protected Update parser fuzzing; S-1/S-2 on 2 parts | only one OPTIGA | TRUSTMV3 shields |
| Power cut in the `OPTSTRT` window (DVT 12.3) | ⚡ brick | dev kits |
| Rollback OTP floor (DVT 10.4, 11.8) | Draft 1.1 is not implemented | after the backend lands |
| Die revision in SESIP scope (DVT 2.1) | paper question | ST |
| DVT-only rows (1.12) | this is an EVT | DVT units |

## Appendix B: Invariant coverage

| Invariant | Where |
|---|---|
| #1 seed split, no PIN to an SE | F1, F2, F9, L5 |
| #2 PIN gate, three-way consumption | E2, F3, F4, F6, K5, L1 |
| #3 encrypted tunnels | D5, F1, F11, J1 |
| #4 secrets only in the secure world | B1, B2, B16, F9 |
| #5 one primitive, C10 | K3, K4 |
| #6 same address on every chain | K2 |
| #7 caps | contract tests (not silicon) |
| #8 stateless slots | K3 |
| #9 off-chain counter cap | K4 |
| #10 verify once physically | B3, B11, H5, H6, I1, I6, J3, K6 |
