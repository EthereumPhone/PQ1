# DVT silicon security test checklist — working doc

**Created 2026-10-15.** **This is a living document:** update a row's status when you run it, and
add a line to the [Evidence log](#evidence-log) at the bottom.

**What it is.** Every security assumption the firmware and its claims make about real silicon,
arranged as tests to run on the PQ1 **DVT** units (`BOARD=pq1`, `AL_A66_MB_V10` pin map,
STM32U585CIU6 + OPTIGA Trust M V3 + SE050).

**How it was built.** Four parallel read-only sweeps covered:
- the secure elements;
- the MCU platform;
- boot, update and lifecycle;
- physical attacks, trusted UI and the host surface.

They read the code, docs, Makefile and `HW-ASSUME-*` registers on master at `baae7c70`. The
load-bearing claims were spot-checked against source. Where a row says **(code read)**, the problem
is a prediction from source that the test exists to confirm or refute; it is not an observed defect.

**Relationship to other docs.**
- `docs/hardware/evt-silicon-validation.md` is the reference **index**: procedures, history, owning
  issues. This file is the **run sheet**: per-unit status and evidence.
- Rows cite the index as `EVT n.m` and the hardware-assumption ledger as `HW-ASSUME-*`
  (`docs/verification/hardware-assumption-boundary-2026-07-17.md` §6).
- **Do not copy procedures here.** Fix them in the owning doc.

---

## How to use this doc

**Status:** ☐ todo · ▶ running · ✅ pass · ⚠ pass with a caveat (stated) · ❌ fail (link an issue) ·
⛔ blocked (blocker named) · ⏸ deferred by owner decision.
A status always carries `unit + date`, e.g. `✅ DVT1 10-15`.

**Class (what a run does to the unit):**

| Class | Meaning | Where it may run |
|---|---|---|
| **N** | Non-destructive. It reads, or flashes test firmware, at RDP 0. | any DVT |
| **R** | Reversible state change. Examples: option bytes at RDP 0, RDP 0→1→0 (mass-erases flash), SE objects rewritten while the OPTIGA is still at LcsO=creation, bench wallet provision/wipe. | any DVT, with a backup taken first |
| **C** | Consumes counters: page 124, OPTIGA E120/E121, SE050 UserID attempts, or carve-out OIDs left behind. Recoverable on bench policy. | dev DVT, logged |
| **X** | Irreversible: RDP 2, OTP burn, WRP with `UNLOCK=0`, BOOT_LOCK, OPTIGA LcsO ratchet, SE050 PUT KEY on a kept part, FI or crowbar that can kill a die, desoldering. | **L** (loose part or dev kit) first, then **S** (S1/S2 ceremony units) only |

Unit tiers follow the EVT sacrificial plan (`evt-silicon-validation.md` "Sacrificial-unit plan"):
- **D**: the dev fleet. Stays at RDP 0 forever.
- **L**: loose parts or a dev kit. Absorbs every destructive test.
- **S**: the two ceremony units S1 and S2.

**Recording a run.**
1. Change the row's status cell.
2. Append an Evidence-log line: date, unit, commit, features or target, result, artifact path.
3. If it failed, open an issue and put its number in the row.
4. Close the owning issue with the evidence.

---

## 0. Bench rules — read before flashing anything on a DVT

1. **Never burn OTP by accident.** A hardware image whose secure features include none of
   `otp-hardcoded-master-key` (implied by `dev-testkey`) or `saes-dhuk` derives keys through
   `otp::ensure_device_master()`, which **burns the OTP device master on a blank die**
   (`secure/src/hw/secret_keys.rs:160-168`, `secure/src/hw/otp.rs:779-783`). `run-hw` is such a
   build. Read the `--features` line of every target, and every ad-hoc `FEAT_S=`, before flashing.
2. **`button-test` and `pin-diag-boot-hw` are not for pq1.** `button-test` omits
   `$(BOARD_FEATURE)` and watches PA8, which on pq1 is `LDO2_EN`, the rail powering both SEs.
   `pin-diag-boot` is an iota2-only `compile_error!`.
3. **Option bytes on a factory chip need two writes.** The recipes' single
   `-ob TZEN=1 SECWM… SECBOOTADD0=…` applies only TZEN to a TZEN=0 chip. Follow it with a second
   write, `SECWM2_PSTRT=0x7F SECWM2_PEND=0x0`, or bank 2 stays secure and any non-secure image fails.
4. **Read flash only with `mode=UR`.** A `HOTPLUG` read returned running code in place of flash
   contents (EVT update 2026-10-14). A wedged ST-LINK reads OTP as all zeros, which looks like a
   rollback floor of 1024.
5. **Take a backup before the first flash of every unit:** 2 MB flash, OTP and option bytes, read
   twice, with hashes compared. See row 1.1.
6. **Know which targets rewrite OPTIGA metadata.** `wipe-for-wizard`, `optiga-hw-counter*`,
   `duress-*` and `dual-se-*-standalone` all do. That is reversible only while the chip is at
   LcsO=creation, and it consumes E120.
7. **Dev-loop wipe hazard.** `tools/evt-dev-flash.sh` mass-erases page 124. On images without
   `optiga-hw-counter`, boot reconciliation wipes both SEs if the OPTIGA F1E1 counter is ahead.
   Make the last PIN entry before reflashing a successful unlock.
8. **Never on a D unit:** `RDP=0xCC`, any OTP program, WRP with `UNLOCK=0`, BOOT_LOCK, an OEM key,
   an OPTIGA LcsO ratchet, an SE050 PUT KEY, FI, or a crowbar.

---

## Units

| Unit | Die UID / REV_ID | OTP | OPTIGA | SE050 part | Current state | Backup |
|---|---|---|---|---|---|---|
| DVT #1 | REV_ID `0x3007` (CubeProg: "Rev U"); OPTIGA UID `cd1633ca01001c00…` | blank (all `0xFF`) | factory-blank: LcsO=creation; factory PBS in E140, fp `20a7ec84684f7fe1` | ACKs at `0x48`; part (E2/C2) **unverified** | RDP 0, TZEN=1, bank 2 non-secure, WRP off, OTP blank (re-read 10-15 PM); flash = `fwup-transport-hw` test image; pages 123–127 as before the session; OPTIGA/SE050 untouched except SE050 stress UserIDs | `~/Documents/PQ1/dvt1-backup-2026-10-15/` (flash sha256 `a9ab0052…`) |
| DVT #2 | | | | | | |

## Equipment

| Have | Status |
|---|---|
| STLINK-V3SET (J210 SWD) | on bench 2026-10-15 |
| Logic analyzer LA1010 (digital only) | on bench |
| Rigol MHO934 scope | on bench |
| Ledger Donjon Scaffold (Vdd crowbar), FaultyCat (EMFI) | on bench |
| SBU-bridged USB-C breakout (BOOT0 → ROM DFU) | lent to a coworker 2026-09-21 |

**Needed**, with the rows that need them:
- USB-UART on J211 (PA2/PA3, 115200): 4.3, 5.4, 14.3.
- Programmable PSU or relay with a GPIO trigger: 5.x, 7.6–7.7, 11.3, 12.3.
- ChipWhisperer-Husky plus EM probe, or ChipSHOUTER: §16.
- ≥240 fps camera: 13.3, 13.6–13.8.
- Loose parts: ≥5 STM32U585, ≥5 SE050 of the shipping part, ≥2 OPTIGA TRUSTMV3 shields. These are needed for every L row.
- Optional: USB fuzzer (Facedancer/Cynthion), ESD gun, thermal chamber.

---

## DVT1 run 2026-10-15 — summary

**UPDATE 2026-10-15 (afternoon run on DVT1, ST-LINK V3SET over J210, master `86d9b2a2` plus the uncommitted harnesses committed with this update).** Per-row detail is in the status cells and the [Evidence log](#evidence-log). This summary is the entry point.

**Failures (issues still to open; not opened because the repo may be public):**
- **FIXED the same evening (rows 3.5, 3.7; evidence log at the bottom).**
- **3.5 (ship-blocker class).** `RCC_SECCFGR`, `PWR_SECCFGR`, `TAMP_SECCFGR` and `EXTI_SECCFGR1` are all `0` on silicon, and nothing in `secure/src` writes them. Non-secure code wrote the TRNG oscillator enable, an APB prescaler, PVD, backup-domain write enable, tamper enables and filter, and `TAMP_BKP0R` (the BHK register on `bhk` builds). Per RM0456 Tables 109/117 the same zeros leave VOS, PLL1, SYSCLK and `RCC_BDCR.BDRST` non-secure-writable, which is a software under-volt/over-clock fault-injection and backup-domain-reset path (not exercised).
- **3.7.** `AIRCR.PRIS` is not set: `sau.rs` uses bit 10 (PRIGROUP), but PRIS is bit 14 (CMSIS `core_cm33.h`). Proven on silicon with a `1 << 14` build.
- **11.2.** Over USB HID, every 5th–9th rejected `FW_BEGIN` gets no reply. The device is not stalled. With `iwdg` the same run reset the device.

**Caveated passes:** 5.5 (two legacy provisioning seeds survive LOCK on the secure stack), 5.4 (all unlocked secrets survive an NRST in SRAM1), 1.8 (SE050 is the **E2**, not the C2 production part), 3.12 (SE-wipe leg not run), 10.10 (profile gaps), 4.12 (pool counters say the pool served nothing; inconclusive), 2.3, 5.8, 6.8, 3.4 (inconclusive in this image).

**Passes:** 1.5, 1.7 (full OID sweep), 1.9, 1.10, 1.11, 2.2, 3.1, 3.3, 3.6, 3.10, 4.7, 6.1, 11.6, 11.7.

**Not run, and why:**
- **E140 hold (O-13):** 6.3, 6.4, 6.5, 7.2–7.5, 8.1–8.4, and the SE leg of 3.12 all overwrite the OPTIGA's factory PBS in E140. Only its fingerprint (`20a7ec84684f7fe1`) is backed up; dumping the 64 bytes was refused by this session's permission policy.
- **Signing passphrase:** 10.1–10.8 and 13.8 need `make bootproof-sign`, which prompts for the vendor-key passphrase.
- **Equipment or a human:** 4.3 (USB-UART on J211), 13.x (buttons, camera), 5.x power cuts (PSU/relay), 6.2/6.4 (LA capture).
- **Class X:** every irreversible row; loose parts only.

**Raw logs, SWD reads and SRAM dumps (local, not in git):** `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/` (SHA256SUMS inside).

**Unit state after the run:** RDP 0, TZEN=1, bank 2 NS, WRP off, OTP blank (re-read after every image that lacked `otp-hardcoded-master-key`), pages 123–127 byte-identical to the start of the session, flash = `fwup-transport-hw` test image.

## Highest-risk untested assumptions — run these first

| # | Row | Why first |
|---|---|---|
| 1 | 3.5 | **Non-secure code may be able to write RCC/PWR/TAMP.** Nothing in `secure/src` configures RCC/PWR security, and `TAMP_SECCFGR` is written only for BHKLOCK. If writable, non-secure code could stop the TRNG clock or disarm every tamper. Cheap N test; a possible ship-blocker. |
| 2 | 3.6 | **The OTP device master may be readable from the non-secure alias.** The rollback architecture doc states the OTP has a non-secure alias that GTZC/SECWM do not cover. On a blank DVT the test needs no burn: a non-secure read returning `0xFF` means readable, RAZ `0` means blocked. Not in `threat-model.md`. |
| 3 | 6.3 | **OPTIGA CCM nonce reuse (audit F-1) is still unproven.** Firmware sets `enc_seq = master_seq+1` with no `max()` (`optiga/shield.rs:915`). If the chip's `slave_seq ≠ master_seq`, one direction reuses a nonce on seed-critical records. Recording the two values settles it. |
| 4 | 2.1 | **This die revision may be outside the SESIP certificate.** DVT #1 is `0x3007`, while SESIP-2400133-01 covers `0x3003`. Until ST confirms scope, `HW-ASSUME-RDP2` has no third-party evidence for this die. |
| 5 | 10.11 | **The consumer verify path (invariant #10a) has no physical route.** `docs/security/user-device-verification.md:50` puts SWD on the USB-C SBU pins. On V10 those pins drive BOOT0, and J210 is DNP on MP units. |
| 6 | 5.5, 13.10 | **Secret residue after lock is unmeasured.** The hardware reset-erase option covers SRAM2, which is non-secure, not the secure SRAM1. Separately, a non-secure ISR may be able to hold the 120 s idle wipe off (code read). |
| 7 | 9.5 | **`HW-ASSUME-PUTKEY-ATOMIC` is a ship-blocker.** A torn DEK is undetectable by the resume probe. |
| 8 | 2.8, 15.1, 15.3 | **No physical glitch campaign has been run.** RDP 2 downgrade, sign release and the PIN gate are all untested; a public result reports ~76% PIN-glitch bypass on U5. |
| 9 | 9.1–9.3 | **The OPTIGA lifecycle chain has never run.** S-1/S-2/E140 have no silicon run. Until they do, one desoldered OPTIGA defeats "neither chip alone". |
| 10 | 7.1 | **The #855 production path has never run.** DHUK PRF, random salt and RDP-2 mint have never been compiled into a runnable image (#268). |

---

## 1. Per-unit intake — every DVT, before anything else (N)

| ID | Assumption under test | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 1.1 | A full pre-flash state backup exists and is reproducible | `STM32_Programmer_CLI -c port=SWD mode=UR -u 0x08000000 0x200000 … -u 0x0BFA0000 0x200 … -ob displ`, run twice | two reads have equal hashes | N | — | ✅ DVT1 10-15 |
| 1.2 | Die identity recorded: DEV_ID `0x482`, REV_ID, 96-bit UID | boot log `[S] die:` or SWD read `0xE0044000` | recorded | N | EVT n=1 | ✅ DVT1 10-15 (REV_ID `0x3007`; UID not yet copied) |
| 1.3 | Every option-byte field is in a known state, compared against a golden table: RDP, TZEN, nSWBOOT0, nBOOT0, SWAP_BANK, BOR_LEV, SRAMx_RST, SRAMx_ECC, IWDG_*, SECWM, SECBOOTADD0, WRP, HDP, BOOT_LOCK, OEM lock status | `-ob displ` diffed against a golden table (to write) | every field matches or is an owner decision | N | — | ◐ DVT1 10-15 (dumped, no golden table) |
| 1.4 | OTP is blank and the FSBL rollback floor reads 0 | OTP dump (1.1) plus a known-good control read in the same session | all `0xFF` | N | — | ✅ DVT1 10-15 |
| 1.5 | SYSCLK is PLL1 at 160 MHz, VOS1 plus booster. `rcc.rs` falls back *silently* to 16 MHz. | SWD read `RCC_CFGR1`, `RCC_CR`, `RCC_PLL1DIVR`, `PWR_VOSR` while running | `0x0F` / PLL1RDY / N=20 R=2 / VOS=3 BOOSTRDY | N | EVT n=1 08-30 | ✅ DVT1 10-15: `RCC_CFGR1=0x0F`, `RCC_CR=0x03003535` (PLL1ON+RDY), `PLL1CFGR=0x0004000E` (HSI16, M=1, REN), `PLL1DIVR=0x01000013` (N=20, R=2), `PWR_VOSR=0x0007C000` (VOS=3, BOOSTEN, VOSRDY, BOOSTRDY), `FLASH_ACR=4` WS. Read over SWD on the parked gtzc image. |
| 1.6 | Both SEs ACK on their buses (V10 pin map fits) | `make se-i2c-probe-hw BOARD=pq1` | `=== PASS ===` | N | EVT 08-30 | ✅ DVT1 10-15 |
| 1.7 | OPTIGA object inventory and access conditions are what S-1/S-2/S-3 assume; the probe is read-only | `make optiga-probe-hw BOARD=pq1`, then `SWEEP=1` for undocumented OIDs | all metadata re-reads unchanged, SEC delta 0, findings classified | N | — | ✅ DVT1 10-15 (SWEEP=0; factory-blank). SWEEP=1 ✅ 10-15 PM: full `0x0000–0xFFFF` OID sweep, **0 undocumented OIDs**; R3 vs R9 metadata byte-identical; SEC 0 at every step; same 43 report findings as SWEEP=0 (all the factory-blank false-positive class). Report `target/optiga-probe/cd1633ca01001c00-readonly-20261015-152450.md`. |
| 1.8 | **SE050 part identity:** E2 (OEF A921, default) or C2 (A201, `se050-part-c2`); AppletConfig; JCOP version inside the certificate's TOE (`HW-ASSUME-SE050-CERT-VERSION`). Wrong part means the wrong keyset and a certificate that does not cover it. | `make se050-stress-only-audit_se050_version_identity BOARD=pq1`. Check the bytes are real: #444, Case-2 Le loss. | applet and config pinned; part matches BOM | R (creates a stress UserID) | dev kit E2 06-02 | ⚠ DVT1 10-15: **SE050E2.** SCP03 established on the default E2/A921 keyset; applet **v7.2.0**, `AppletConfig=0x3F9F` (the pinned E2 fingerprint), SecureBox `0xFFFF`; version bytes structured, not the #444 zero pattern. Caveat: the finalized production part is SE050C2 (memory, 2026-07-20), so DVT1 matches the EVT, not the C2 BOM. Whether JCOP/applet 7.2.0 is inside the E2 certificate's TOE is still unchecked. |
| 1.9 | Flash pages 123–127 erase, program and read back on this die. A bench die had page-126 PROGERR (EVT 4.4). | new small probe image, readback with `mode=UR` | all five pages program and verify | R | bench chip page 126 hostile | ✅ DVT1 10-15 via the debugger (not the firmware driver): each page erased, programmed with 8 KB of random data, CubeProg-verified and read back identical with `mode=UR`. Pages then erased; page 123's 23 counter records (368 B) re-written exactly, only those QWs. Firmware-driver coverage still comes from 7.2/12.5. |
| 1.10 | HW SHA-256 KAT passes; signing timing is sane | `make test-key-speed BOARD=pq1` | `PASS`, KAT line | N | EVT 08-30 | ✅ DVT1 10-15 (first 12.3 s, cached avg 5.76 s); re-run 10-15 PM: first 13.6 / 14.0 s, cached avg 5.56 s (5.37–5.80), KAT PASS; OTP re-read blank after |
| 1.11 | TRNG seed/clock-error rate on this rail. EVT saw `SEIS` about once per sign. | count `rng::fill: seed/clock error` lines over a `test-key-speed` run | rate recorded; recover path never escalates | N | EVT 08-30 | ✅ DVT1 10-15: **0** seed/clock errors in 27 `rng::fill` calls over 7 signs (every entry `SR=0x1`). EVT saw ~1 per sign. |
| 1.12 | The DVT board matches V10 in the security-relevant parts: VBAT/supercap topology, SE part numbers, BOOT0 network, J210/J211 | schematic/BOM delta from the ODM | delta listed | N | — | ☐ (no DVT schematic in hand) |

## 2. Die, option bytes, boot mode, RDP

| ID | Assumption | How | Pass | Cls/Tier | Prior | DVT status |
|---|---|---|---|---|---|---|
| 2.1 | **`HW-ASSUME-REV-U`:** our dies are the SESIP-evaluated revision (`0x3003`). | ES0499 revision table plus a written answer from ST on whether `0x3007` is within TN1545 scope | confirmed in scope, or RDP-2 resistance recorded as uncertified for this die | N | firmware flags it, enforces nothing | ❌ DVT1 10-15 reads `0x3007` (open question). The secure boot log says so itself: `[S] die: NOT the SESIP-2400133-01 die (TN1545 Rev 3 pins dev_id=0x482 rev_id=0x3003 'rev U')`. CubeProgrammer labels this die "Rev U" too, so the name alone does not identify the revision; use REV_ID. |
| 2.2 | RM0456 register layout of WRP1A/WRP2A and OEM lock bits matches `shared/src/lockdown.rs` (EVT 3.9). `WRP1A_MASK_PINNED` and `OEM_LOCK_MASK_PINNED` are `false`, so Phase A fails closed today. | set and clear WRP1A with `UNLOCK_1A=1` at RDP 0, then feed the register value to the decoder | decoded range equals the programmed range | R (only with UNLOCK=1) | never | ✅ DVT1 10-15: `-ob WRP1A_PSTRT=0 WRP1A_PEND=3 UNLOCK_1A=1` → `FLASH_WRP1AR=0xFF83FF80`. Bits 7 and 23 are reserved and read **1** on U585 (RM0456 §7.9.19: 7-bit fields), and the decoder's `& 0x7F` masks give STRT=0, END=3, UNLOCK=1, exactly what was programmed (an 8-bit mask would read STRT=0x80). Layout `STRT[6:0]/END[22:16]/UNLOCK[31]` confirmed on silicon; flipping `WRP1A_MASK_PINNED` is the owner's commit (#46). Restored to `0xFF80FFFF`. |
| 2.3 | **WRP is the only guard for the FSBL pages.** The flash API allows erasing bank-1 pages 0–126 (`secure/src/flash_policy.rs`). Test that WRP1A rejects both a secure-firmware erase and a probe write. | bench image calls `erase_secure_page(0)`; CubeProg write attempt; WRP set with UNLOCK=1 | WRPERR on both | R (UNLOCK=1), D | never | ◐ DVT1 10-15: with WRP1A=0..3, a CubeProg `-e 0` left page 0 intact ("Protected sectors are not erased"), but CubeProg may skip protected sectors client-side. The raw `SECCR` PER/STRT erase that would show hardware WRPERR was refused by this session's permission policy; the firmware `erase_secure_page(0)` path was not run. |
| 2.4 | `HW-ASSUME-OEM2-ABSENT`: OEM1/OEM2 locks are detectable, and the default DA password fails | provision OEM1 on a loose part and read the lock bits; regression with the default password | detected; regression refused | X / L | never | ☐ |
| 2.5 | RDP 1 with TZEN=1 behaves as expected: SWD cannot read secure flash or SRAM, the ROM bootloader cannot read the secure bank, and 1→0 regression mass-erases flash including pages 123–127 | RDP 0→1 (use a monolithic image; a slot-layout FSBL halts at RDP 1), attempt reads, regress | zero secure bytes read; all pages `0xFF` after regression | R / D | dev kit (DHUK), EVT DFU | ☐ |
| 2.6 | The RDP 0→2 burn keeps every other option byte verbatim, and the FSBL then selects the LOCKED profile | ceremony on S1; UART log of post-lock boot | option bytes unchanged | X / S | never | ⛔ #268 |
| 2.7 | SWD attach fails at RDP 2 (EVT 3.10) | connect-under-reset attempt | refused | X / S | never | ⛔ needs 2.6 |
| 2.8 | `HW-ASSUME-RDP2`: RDP 2 resists EMFI and Vdd glitching on **this die revision** without OEM2 (EVT 9.6) | FaultyCat plus Scaffold campaign on loose U585s | no downgrade within budget | X / L | never; SESIP covers `0x3003` with OEM2 | ☐ |
| 2.9 | At RDP 2, an SBU-bridged USB-C cable (BOOT0 high via U111) cannot enter ROM DFU. The ship profile checks neither nSWBOOT0/nBOOT0 nor BOOT_LOCK (`lockdown.rs`). | power-up with the SBU adapter on S1 | no `0483:df11`; FSBL words shown | X / S | works at RDP 0 (EVT 09-18/21) | ⛔ needs 2.6 |
| 2.10 | HDP1/HDP2, BOOT_LOCK and SWAP_BANK are immutable under RDP 2 (EVT 3.5, 3.6, 10.8) | sacrificial ceremony | page-0 program WRPERR; SWAP_BANK write refused | X / S | never; HDP configured nowhere | ⛔ #38 #39 #44 |
| 2.11 | MP strap: with BOOT0 tied to GND there is no USB entry path, and the U5 has no empty-flash bootloader (AN2606 Pattern 12) | tie TP103 to GND, cycle power with the SBU adapter | no DFU enumeration | N / D | datasheet reading only | ☐ |

## 3. TrustZone isolation (`HW-ASSUME-CMSE-SAU`)

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 3.1 | Secure peripherals are read-as-zero from non-secure code, and each access raises one TZIC event | `make gtzc-enforcement-hw BOARD=pq1` | 11/11 | N | dev kit 7/7 05-20; pq1 8/8 | ⚠ DVT1 10-15 11/11. Reads only, and it **excludes SPI1** (trusted display, EVT 10.3) **and IWDG** because it builds without them. |
| 3.2 | Same as 3.1 on the **ship** peripheral set, with non-secure **write** probes | extend `nonsecure/src/gtzc_test.rs`: a `ui-lcd` + `iwdg` secure build, SPI1/IWDG probes, writes | N/N, writes ignored | N | never | ☐ new harness |
| 3.3 | Memory attribution: non-secure code cannot read or write SRAM1, SRAM3, bank-1 flash (pages 123–127 included) or the NSC table | non-secure probes at `0x2000_0000`, `0x2004_0000`, `0x0800_0000`, `0x080F_6000` | RAZ/WI or fault; zero bytes leak | N | never | ✅ DVT1 10-15: NS reads of `0x2000_0000`, `0x2004_0000`, `0x0800_0000`, `0x080F_6000`, `0x3000_0000`, `0x0C00_0000`, the NSC table (`0x0C05_EEA0`) and system memory (`0x0BF9_0000`) each fault before data returns (secure HardFault → reset); positive controls `0x0810_0000`, `0x2003_0000` read. Reads only (`gtzc-sys` + `GTZC_FAULT_ADDR`). |
| 3.4 | GPIO SECCFGR: only PA11/PA12 are non-secure. Non-secure writes to the SE rails (PA8, PB5), SE reset (PA15), SE buses (PB6–9), LCD (PA4/5/7, PB0–2, PB15) and buttons (PA0/PA1) do not move the pads. | SWD read of `GPIOx_SECCFGR` while running; non-secure ODR/MODER/BSRR writes watched on the LA | `GPIOA=0xE7FF`, B/C `0xFFFF`; pads unchanged | N | dev kit readback only | ◐ DVT1 10-15, **inconclusive**: the `gtzc-sys` probes ran on the gtzc image, where `RCC_AHB2ENR1.GPIOAEN/GPIOBEN` = 0 (GPIO unclocked), and every GPIO register read back the MODER reset value (`0xABFFFFFF` / `0xFFFFFEBF`). NS could not enable those clock bits (ignored). Re-run the probe on an image that clocks GPIO (any `ui-lcd`/SE image), with the PA11 MODER positive control. |
| 3.5 | **RCC/PWR/TAMP/EXTI are not non-secure-writable.** No `RCC_SECCFGR`/`PWR_SECCFGR` configuration or `TAMPSEC` in `secure/src` (verified by grep 2026-10-15); GTZC2 is deliberately unlocked (#79 #80 #81). | non-secure writes: `RCC_CR.HSI48ON=0` (TRNG clock), `RCC_AHB2RSTR` (HASH/SAES reset), `TAMP_CR1=0`, `PWR_SVMCR`; read back from the secure side | every write ignored. **If not, it's a ship-blocker.** | N | never | ✅ **FIXED, DVT1 10-15 (evening):** `sau::stm32::secure_system_controllers` sets `RCC_SECCFGR=0x1FFF`, `PWR_SECCFGR=0xF0FF`, `RTC_SECCFGR=0xE00F`, `TAMP_SECCFGR=0x80208020` (TAMPSEC, CNT1SEC, all 32 BKP secure R/W; BHKLOCK preserved), `EXTI_SECCFGR1=0x00FFFFFF` + `EXTI_LOCKR`, each read back fail-closed; TZSC also secures CRS. Re-run with `gtzc-sys` + the new SWD verdict script `tools/dvt/gtzc_sys_verify.sh`: **22/22 ok**, every NS write ignored, including `TAMP_BKP0R`, `RCC_CFGR1.MCOSEL` (SYSCLKSEC), `RCC_PLL1FRACR` (PLL1SEC), `RCC_BDCR.LSCOSEL` (backup domain), `EXTI_EXTICR1` and clearing `EXTI/RTC_SECCFGR`; phase 1 12/12 (CRS added). Silicon note: EXTI_SECCFGR1 implements lines 0–23 only (a 0x03FFFFFF write reads 0x00FFFFFF; the SVD lists SEC24/25). `test-key-speed` PASS, 0 TRNG errors. Original result: ❌ **DVT1 10-15 — ship-blocker, issue to open.** `RCC/PWR/TAMP/EXTI_SECCFGR` all read `0` (secure alias, SWD). NS wrote, confirmed on the secure alias: `RCC_CR.HSI48ON`, `RCC_CFGR3.PPRE3`, `RCC_APB3ENR.RTCAPBEN`, `PWR_SVMCR.PVDE`, `PWR_DBPR.DBP`, `TAMP_CR1.ITAMP5E`, `TAMP_FLTCR`, `TAMP_BKP0R` (the BHK register on `bhk` builds) and `BKP31R`, `EXTI_RTSR1`. Ignored, as expected: `RCC_AHB2ENR1` RNGEN/GPIOxEN (secure-peripheral bits read 0 from NS), `TZSC_SECCFGR1`. By RM0456 Tables 109/117 the same zeros leave **`PWR_VOSR.VOS`, PLL1, SYSCLK, AHB/APB prescalers, `PWR_CR3`** and (with no RTC/TAMP function secure) **`RCC_BDCR.BDRST`** NS-writable — software under-volt/over-clock FI and backup-domain reset; not exercised. HSI48ON=0 did **not** stop the TRNG (HSI48RDY stayed 1 over 2M polls; `RNG_SR`=DRDY, no CECS). Fix: set `RCC_SECCFGR` (SYSCLK/PRESC/PLL1/HSI/HSI48/MSI/LSI/LSE/RMVF), `PWR_SECCFGR` (VDM/VB/LPM/APC), `TAMP_SECCFGR.TAMPSEC` + BKP*SEC, `EXTI_SECCFGR1` for secure pins, then re-run. Follow-up hypothesis (untested, needs a button press): with `EXTI_SECCFGR1=0`, NS can set `EXTI_EXTICR1` to route PA0/PA1 (the secure buttons) to an NS interrupt and learn keypress timing during PIN entry. RM0456 §23 does not say whether a secure GPIO's mux output is masked from NS. |
| 3.6 | **The OTP device master is not readable through the non-secure alias.** The rollback architecture doc states the alias exists and that SECWM/MPCBB don't cover it. | non-secure `read_volatile(0x0BFA_0000…)` on the blank DVT: `0xFF` means readable, `0`/RAZ means blocked | blocked, or a documented residual with owner sign-off | N | never | ✅ DVT1 10-15: the NS read of `0x0BFA_0000` faults (SAU leaves it secure; no SAU NS region covers it) → secure HardFault → reset; no word reached NS. The architecture doc's "non-secure alias" does not exist as an NS-readable path on this image. |
| 3.7 | SAU regions 0–3 are as coded; CSLCKR LOCKSAU/LOCKSVTAIRCR are set; AIRCR PRIS=1, BFHFNMINS=0; no stray `SG` opcode in the 256-B-rounded NSC padding (`sau.rs:776-781`) | SWD register dump; ELF scan for `0xE97FE97F` in [veneer_limit, nsc_end]; post-lock SAU write from non-secure | match; no stray SG; write ignored | N | implicit only | ✅ **FIXED, DVT1 10-15 (evening):** `AIRCR_PRIS = 1 << 14` and the PRIGROUP field cleared (`sau.rs`); secure-view AIRCR now reads `0xFA054000` (PRIS=1, BFHFNMINS=0, PRIGROUP=0), CSLCKR `0x5`, phase-1 gtzc 11/11. Original result: ❌ DVT1 10-15 — **PRIS is not set.** Secure-view AIRCR = `0xFA050400`: BFHFNMINS=0 ✅, but bit 14 (PRIS, CMSIS `core_cm33.h` `SCB_AIRCR_PRIS_Pos=14`) is 0 and bit 10 (PRIGROUP) is 1. `sau.rs:648` defines `AIRCR_PRIS = 1 << 10`, and `main_sau_pure_tests.rs:679` pins that wrong value. A temporary `1 << 14` build booted through the X17-TZ1 verify and read `0xFA054000`, so bit 14 is writable on this die; the 07-19 "bit 14 bricks the boot" (`db46babc`) was the SYSCFG-clock CSLCKR fault fixed in the same commit. Passing: SAU_CTRL=1, TYPE=8, region 3 `0x4000_0000–0x4FFF_FFFF` NS; CSLCKR=`0x5` (LOCKSAU+LOCKSVTAIRCR) and debugger writes to SAU_RNR/RLAR ignored; NSC padding `0x0C05_EF40–0x0C05_F000` all `0xFF`, no SG. Regions 0–2 not enumerable after lock. Needs DSCSR `SBRSEL=1` to see the secure bank over SWD. |
| 3.8 | NS pointer validation rejects secure, NSC and out-of-window addresses at the real boundaries. Design question: the code uses `TT`, not `TTA`. | non-secure fixture issues every `cmd_*` with a boundary pointer table | all `InvalidPointer`, no fault | N | Kani/Miri host only | ☐ new |
| 3.9 | A non-secure GPDMA channel cannot read SRAM1; the secure blit channel is SEC+PRIV (EVT 3.11) | non-secure GPDMA copy from `0x3000_0000` | error or RAZ | N | never | ☐ new |
| 3.10 | Nested gateway calls are refused (#846/#896) | `make nested-gate-test-hw` and `-nctl-hw BOARD=pq1` | refused with the gate, admitted without it | N | pq1 bench 10-14 PASS | ✅ DVT1 10-15: gate on → nested call REFUSED; `-nctl` → ADMITTED; outer signature verifies offline in both (`tools/verify-c10-sig`). Note PRIS=0 (3.7) does not affect this: the refusal is `GATEWAY_GATE`. |
| 3.11 | TOCTOU: a non-secure ISR or GPDMA rewriting the caller buffer mid-sign cannot change what is signed relative to what was shown | `nested-gate-test` variant that mutates the buffer from non-secure SysTick and GPDMA | signed digest equals the displayed digest, 100% of runs | N | never | ☐ new |
| 3.12 | A TZIC illegal access leads to zeroize, then the page-125 wipe flag, then reset, then the SE wipe on next boot | `make tzic-wipe-hw BOARD=pq1` | no `SURVIVED`; wipe completes | R (wipes bench wallet) | dev kit, no receipt found | ⚠ DVT1 10-15: 1 probe, 0 `SURVIVED`, reset intercepted; page 125 QW1 (`0x080F_A010`) = `00ff…` (wipe flag armed). The next-boot SE wipe leg was **not** run (it needs a dual-SE boot that writes both chips, see the E140 hold); the flag was erased afterwards and pages 123–127 verified identical to before. |
| 3.13 | USB OTG non-secure coexists with the ship GTZC image; UCPD1 stays secure | `make fwup-transport-hw-iwdg BOARD=pq1` plus 3.2 | enumerates `1209:7051` | R | dev kit 05-28; EVT 09-21 | ✅ (enumeration part) DVT1 10-15: `1209:7051` enumerates in ~11 s on the gtzc-config secure image; GET_DEVICE_INFO/GET_STATUS SW_OK. The 3.2 write probes on this ship set are not done. See 11.2 for the transport failure. |

## 4. Keys, crypto peripherals, RNG, OTP

| ID | Assumption | How | Pass | Cls/Tier | Prior | DVT status |
|---|---|---|---|---|---|---|
| 4.1 | HW SHA-256 is correct (KAT covers one block only) | boot log; consider a multi-block KAT | PASS | N | EVT | ✅ DVT1 10-15 |
| 4.2 | SAES SW and DHUK round trip at RDP 0 | `make saes-self-test-hw BOARD=pq1` | PASS | N | dev kit, EVT | ✅ DVT1 10-15. The fingerprint `117d822a62a50830` is ST's shared RDP-0 constant, so the per-die key was not exercised. |
| 4.3 | `HW-ASSUME-DHUK-UNIQUE`: the RDP-1 DHUK fingerprint differs from the constant, between DVTs, and is stable across reboots | `make saes-self-test-hw-rdp1` then `-rdp0-regress`. **Recipe needs work on pq1:** it captures the ST-LINK VCP, while the pq1 console is J211. | distinct, stable per die | R / D | dev kit n=2 | ☐ (fix recipe first) |
| 4.4 | `HW-ASSUME-DHUK-RDP12`: DHUK at RDP 1 equals DHUK at RDP 2 on the same die. Record either outcome. | fingerprint at RDP 1, then self-lock, then fingerprint over UART | recorded | X / S | never | ⛔ #268 |
| 4.5 | DHUK unique at RDP 2, n ≥ 2 (EVT 10.7) | S1 vs S2 | distinct | X / S | never | ⛔ |
| 4.6 | BHKLOCK makes the BHK read-as-zero; a confirmed tamper clears BKP0–7; the "recovery = power cycle" claim (`bhk.rs:161-172`) holds with pq1's VBAT topology | `dual-se-bhk` e2e plus a forced tamper and a power cycle | as stated | R | BHKLOCK found sticky 09-21 (#712) | ☐ |
| 4.7 | TRNG configuration is locked as intended (HTCR `0xA2B0`, NSCR `0x17CBB`, CONFIGLOCK), and `RNG_VERR` matches the E11 certificate's revision | boot log plus SWD read | match | N | EVT log | ✅ DVT1 10-15: SWD `RNG_CR=0x80F00D04` (CONFIGLOCK), `NSCR=0x17CBB`, `HTCR=0xA2B0`. RM0456 §48.7 has **no `RNG_VERR`** on U5, so the certificate-revision half of the row needs a different identifier. |
| 4.8 | `HW-ASSUME-TRNG-ENTROPY`: raw TRNG output meets SP 800-90B in our configuration | dump ≥1 MB over semihosting, NIST EA v1.1.8 | min-entropy ≥ the claimed value | N | never | ☐ new dump image |
| 4.9 | `rng_strong` fails closed when any one source (TRNG, OPTIGA, SE050) is missing. The PIN pad falls back **silently to all zeros** on failure (`ui/pin_entry.rs:73-87`). | hold SE050 or OPTIGA in reset during the wizard and the PIN prompt | no seed generated; the zero pad is flagged (owner decision O-5) | R | EVT 09-21 showed the zero pad pre-fix | ☐ |
| 4.10 | `HW-ASSUME-OTP-ONEWAY` part 1: user OTP accepts a burn on this die revision. The Rev W dev kit returned `SECSR=0x90` (EVT 4.1). | program one spare QW of the 21 unallocated, read back, try a second program | programs once; second program → PROGERR | X (one QW) / D or L | dev kit rejected | ☐ |
| 4.11 | `HW-ASSUME-OTP-ONEWAY`/`QW-ATOMIC`: a torn half-burn of the 2-QW master is detected; a torn QW0 does not read unstably | Scaffold crowbar sweep | every shot classified; zero "other" | X / L | never | ☐ |
| 4.12 | FI-delay pool (`fi_delay_pool.rs`): under a **real signing workload**, `MISSES = 0` and no poisoned operations occur. CLAUDE.md carve-out (d) requires a measured fallback rate. | instrumented build logs HITS/MISSES/ZERO_SKIPS plus IPSR-split fallbacks during `test-key-speed` with `consumption-mask` and `iwdg` | `MISSES=0`; fallback rate recorded | N | EVT 10-09 without signing | ◐ DVT1 10-15, inconclusive: `HITS`/`MISSES`/`ZERO_SKIPS` have no reader in a normal image, so LTO drops them (`#[no_mangle]` was not enough; a temporary `#[used] #[no_mangle]` build linked them). After one first-sign plus LOCK with `consumption-mask` (no `iwdg`): HITS=0, MISSES=0, ZERO_SKIPS=0, `BYTES_WRITTEN`=4224, `ZERO_BYTES_WRITTEN`=12. HITS=0 means the pool served **no** delay, contrary to the `fi.rs` "31:1 common case" comment. Either the instrument or the arming is wrong; needs a reader built in and an IPSR split. |
| 4.13 | Does the consumption-mask PRNG meet carve-out (a)–(f)? Code read: xorshift32 (32-bit state, (b) requires ≥246 bits), fail-open silent reseed (`hw/consumption_mask.rs:181-200`), not zeroized on lock. | owner decision (O-6), then measure the reseed-skip rate during a sign | compliant, or the carve-out text amended | N | none | ☐ |

## 5. Flash, SRAM, power, reset, clocks, watchdog, tamper

| ID | Assumption | How | Pass | Cls/Tier | Prior | DVT status |
|---|---|---|---|---|---|---|
| 5.1 | `HW-ASSUME-QW-ATOMIC`: a cut during a QW program or page erase yields old, new or a clean ECC fault | Scaffold or PSU cut at swept offsets; classify the readback | zero "other" | X / L | never | ☐ |
| 5.2 | A flash ECC double error on a torn page-123–127 QW does not reset-loop the device. Code read: `main.rs` says "no NMI source armed", but ECCD may raise an NMI unconditionally (check RM0456). | use 5.1 shots, then boot | reaches a recoverable state | X / L | never | ☐ |
| 5.3 | Reset in the middle of a write (NRST, SYSRESETREQ, IWDG at swept delays) on pages 123/124/125/127 recovers to old, new or fail-closed; the PIN counter never under-counts | probe-rs scripted reset sweep | zero "other" states | R / D | never | ☐ |
| 5.4 | SRAM retention per reset type matches the scrub classification. A BOR+PIN reset is classed Cold and not scrubbed (`reset_cause.rs:180-183`). | fill SRAM1 with a canary; trigger POR (0.1/1/10 s off), BOR dip, NRST, SYSRESETREQ, IWDG; connect under reset and dump | no retained secret in a non-scrubbed class | N / D | flag bits only (dev kit 04-14) | ⚠ DVT1 10-15, **NRST leg only**: unlocked mock-SE e2e image, then a pin reset by connect-under-reset (`RCC_CSR=0x04004400`, PINRSTF), core halted at the reset vector, SRAM dumped. **All unlocked secrets retained in secure SRAM1**: slot master (`STATE`), slot(1,1) sk_seed (`SLOT_CACHE`), both legacy seeds. This fits `SRAM_RST=1` (SRAM1/3/4 not erased on reset). `.bss` is zeroed by secure startup; the stack copies are never zeroed. POR/BOR/SYSRESETREQ/IWDG not run (need PSU/relay). Input for O-8 / 5.6. |
| 5.5 | **No secret residue in SRAM1 after LOCK, idle wipe or TZIC wipe.** Note: `SRAM2_RST` erases SRAM2, which is the **non-secure** bank. | e2e mnemonic; unlock, sign, LOCK; dump SRAM1 with `mode=UR`; search for seed, master, slot sk_seed and PRF outputs | zero hits | N / D | source/IR audit only | ⚠ DVT1 10-15 (mock-SE e2e image, `ui-noop`, no `debug-log`; dumped `0x3000_0000`+768 KB with `mode=HOTPLUG` while NS parked; patterns from the real `pqsigner-domain` crate, 12-byte windows). **Unlocked (control):** slot master in `STATE`, slot(1,1) sk_seed in `SLOT_CACHE`. **After CMD_LOCK and after the 120 s idle wipe (t+140 s):** both gone; BIP-39 seed, HMAC master and master sk_seed never present. **Caveat:** the legacy `slhdsa_seed` (`sphincsc7-sk-seed`) and `bootstrap_seed` (`pqwallet-c7-bootstrap`), 48 B each with a 32-B secret sk_seed, survive both on the secure **stack** (`0x3002_FAB4`, `0x3002_FAD4`, a by-value return copy from `crypto::provision_from_mnemonic`) and in the mock `SE` static (mock artefact). Per `domain/` they feed only cached VKs (no on-chain authority). LOCK does not scrub the stack. Not yet run: dual-SE image (PRF outputs, real store), TZIC wipe. |
| 5.6 | The SRAM reset-erase and ECC option bits protect the bank that holds secrets (`make stm32-harden-opts` sets SRAM2_RST only) | owner decision (O-8), then readback | decision recorded | R | — | ☐ |
| 5.7 | BOR_LEV ≥ 4 resets before the core misbehaves (harden-opts sets only 3; EVT 3.7); a PVD triggers zeroize (no PVD code today) | programmable PSU, slow and fast ramps, scope | measured threshold; no execution below the datasheet minimum | R / D | never | ☐ |
| 5.8 | The IWDG is secure, resets about 6 s after a non-secure hang, and a non-secure `IWDG_KR` write is ignored. The `IWDG_SW` policy conflicts with the 4 s FSBL hold and the Phase-A confirm screen (O-7). | `make fwup-transport-hw-iwdg BOARD=pq1` plus a 3.2 probe | as stated | R | dev kit 05-28 | ◐ DVT1 10-15: `fwup-transport-hw-iwdg` stayed enumerated 12 s idle (no false fire). During the e2e it **reset** (kernel: USB disconnect 15:31:02, re-enumerated 15:31:17) on the 3rd fail-path BEGIN (`bad_signature`); RCC_CSR is cleared at boot, so the cause (IWDG or fault) is unknown. ~6 s timeout and NS `IWDG_KR` write not measured. |
| 5.9 | The worst-case secure stack fits; no MSPLIM is set, so an overflow corrupts `.bss` silently | paint the stack at boot; run the heaviest flows (batch, ERC-7730, ui-px); dump the high-water mark | ≥8 KB headroom | N | never on silicon | ☐ |
| 5.10 | The FSBL stack fits 16 KB. The 10,372 B bound was taken at opt-level `s`; the FSBL is now mostly `z`. | paint RAM, boot, read the high-water mark | below 16 KB with margin | N | host bound only | ☐ |
| 5.11 | **No false internal tamper on the pq1 rail.** `tamp-wipe` is forced on in shipping images, and ES0499 warns of spurious tampers when VBAT=VDD. | 72 h soak with log-only `tamp`, USB plug cycles, thermal | zero events | N | never (driver was at the wrong base until 06) | ☐ |
| 5.12 | A real tamper drives the full wipe | forced ITAMP trigger | wipe completes | R | never | ☐ |
| 5.13 | ITAMP3 (LSE CSS) is described as a clock-glitch detector, but no LSE is used, so it detects nothing | documentation fix | doc corrected | — | — | ☐ |

## 6. Secure elements — identity, channels, bus behaviour

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 6.1 | SE050 SCP03 (level 0x33, R-MAC/R-ENC) works at 400 kHz on I2C4 and `send_apdu` never sends cleartext | `make se050-stress BOARD=pq1` (set `se050-part-c2` if 1.8 says C2) | 0 FAIL | R | dev kit 16/2 05-28; EVT provisioned 09-21 | ✅ DVT1 10-15 (E2 keys): Tier-Safe **10 PASS / 0 FAIL** / 10 SKIP (destructive tier). Includes `scp03_response_encryption_verify`, `scp03_wtx_endurance`, `audit_unauth_read_refused`, `pin_attribute_read_refused_on_user_userid`. Bus speed not separately confirmed from the log. |
| 6.2 | **S-5:** no `half_E`, credential or key block appears in clear on I2C4 (PB6/PB7) | LA capture during `dual-se-multi-unlock-e2e`; decrypt offline with bench session keys | ciphertext + MAC only | N | never captured | ☐ |
| 6.3 | **Audit F-1:** no OPTIGA AES-CCM (key, nonce) pair is reused between handshake Finished frames and later records | `make flash-hw-optiga-bringup BOARD=pq1` logs `slave_seq` and `master_seq`, N ≥ 50 handshakes | `slave_seq == master_seq` every time; otherwise ship the `max()` fix | R (rewrites E140/F1Dx at creation) | the handshake works on EVT (EVT 5.5 "broken" is stale); sequence numbers never recorded | ☐ |
| 6.4 | The OPTIGA wire shows no plaintext secret and no record nonce equal to a handshake nonce | LA on PB8/PB9 alongside 6.3 | as stated | N | never | ☐ |
| 6.5 | Idle relock and CMD_LOCK re-establish both tunnels (SE050 full `init()` with CLA=84; OPTIGA re-handshake); a correct PIN is not charged as wrong | `flash-hw-dual-se-lcd-standalone-debug BOARD=pq1`, idle 120 s, re-enter the PIN | "Re-unlocked"; page 124 back to 0 | C | fixed 07-02; the EVT idle freeze is still open (10-13 bug hunt) | ☐ |
| 6.6 | **Bus fault does not cause a spurious wizard (audit F-2):** SE050 `check_provisioned` is `unwrap_or(false)` and provisioned = AND of both chips, so a glitch on a provisioned unit can enter the wizard. The OPTIGA PRL wedge and F1E1 read-back must also fail closed. | fault-hook image drops `SE1_EN`/`LDO2_EN` or holds `SE_RST` at APDU k during boot, unlock and provisioning | no wizard on a provisioned unit; no wipe; recovers on the next boot | C | dev kit wedge 06-29 | ☐ new |
| 6.7 | **Genuine-part check.** None exists in the boot path. CLAUDE.md lists "SE attest", but no attestation is called in `main.rs`/`dual_se.rs`. Invariant #5 forbids an on-device ECDSA verify. | factory dump of OPTIGA E0E0/E0E3 and the SE050 attestation; host chain verify; swap test | a swapped part is detected (by the host) | N | never | ☐ design gap (O-9) |
| 6.8 | Both SE TRNGs deliver over authenticated channels | `se050-stress` (`trng_quality_basic`); OPTIGA dump for 90B | min-entropy recorded | R | dev kit SE050 | ◐ DVT1 10-15: SE050 `trng_quality_basic` χ²×100 = 22937 over 256 buckets (threshold 33000) PASS. No min-entropy estimate yet (needs a dump + 90B). OPTIGA not run (E140 hold). |

## 7. PIN credential (#855), attempt lockstep, wipe

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 7.1 | **#855 production path:** credentials are `PRF(DHUK, label‖salt‖PIN)`; fresh three-source salt in page 125 at every provisioning; RDP-2 mint; the wipe destroys the salt before any SE command; page 124 is reset only after the salt is gone | needs a bench-ship-validation image; LA plus a page-125 dump; scope + shunt for single-trace CMAC leakage | salt differs across provisionings; salt destroyed before the first wipe APDU on the LA; stored halves XOR ≠ entropy | X (needs RDP 2) | never; every runnable target uses the public `FixedBench` salt/key | ⛔ #268 |
| 7.2 | #855 bench path: the salt record and credentials survive reboots; the SE050 accepts the 16-B UserID value | `make dual-se-multi-unlock-e2e BOARD=pq1` | ALL 3 BOOTS PASS | R | pq1 bench 10-14 | ☐ |
| 7.3 | **S-3:** E120 LUC enforces lockout in silicon (F1D0 `Execute=LUC`, refusal at 32, reset by a correct PIN) | `make optiga-hw-counter-e2e BOARD=pq1` | as stated | R (rewrites F1D0 metadata at creation; consumes E120) | dev kit 04-22, pre-#855/#116 | ☐ |
| 7.4 | Three-way per-attempt consumption: page 124 precharges, then E120 and the SE050 UserID advance; a correct PIN resets all three | `make pin-gate-hw-counter-e2e BOARD=pq1` | SYNC+DESYNC ROUNDTRIP: PASS | C | dev kit 04-23, pre-S-6/#855/#912 | ☐ |
| 7.5 | 10 wrong PINs lock the SE050 (`0x6986`) and wipe both chips. This is a hardware target; EVT 10.6 calls it QEMU. | `make pin-gate-wipe-e2e BOARD=pq1` | WIPE+RECOVERY ROUNDTRIP: PASS | C | dev kit 04-23 | ☐ |
| 7.6 | Directional boot reconciliation: `E120_used > page124_used` wipes, and an MCU lead does not. Code read: it is skipped silently when the shield cannot come up. | 2 wrong PINs, then erase page 124 with `mode=UR`, cold boot (expect TAMPER); separately cut power after a bump (expect no wipe); separately hold `SE_RST` (expect a "skipped" log) | as stated | C | never (no cold-reboot receipt) | ☐ |
| 7.7 | A power cut mid-attempt, mid-provision or mid-wipe leaves no uncharged attempt and no plaintext-readable secret OID. The wipe resumes from page 125. Audit F-3/F-4 are still in code. | `make se050-crash-safety-e2e BOARD=pq1` (reset only) plus PSU/crowbar cuts triggered from the LA | charged or completed at every cut | C | reset-simulated, dev kit | ☐ |
| 7.8 | **Post-wipe end state under the shipping policy.** The user UserID has no admin-delete and `optiga-lock-operational` F1D0 cannot be blanked, so any wipe (including a false tamper) may leave the unit permanently unusable as a wallet. | non-bench SE050 profile on a loose part | a defined, documented end state (owner decision O-10) | X / L | never | ☐ |
| 7.9 | PendSV re-unlock with a persistent SE fault does not burn PIN attempts (#692) | idle past 120 s with one SE held in reset | page 124 does not move without a human PIN entry | C | never | ☐ |
| 7.10 | PIN-pad start digits are uniform (`rng_strong`) | log the start digits over 1,000 prompts | χ² p > 0.01 | C | EVT visual | ☐ |
| 7.11 | Duress objects, counters and timing (F1D8/E121; fenced out of production, #903) | `duress-provision-hw`, `duress-timing-hw` (implies `optiga-hw-counter`) | PASS; \|Δ\| < 1 ms, n ≥ 100 | C | dev kit 05-20, pre-#855 | ⏸ until duress ships |

## 8. Seed split and SE policies

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 8.1 | `half_O ⊕ half_E` (masked) reconstructs byte-exact across cold boots | `make dual-se-multi-unlock-e2e BOARD=pq1` | ALL 3 BOOTS PASS | R | pq1 bench 10-14 | ☐ (same run as 7.2) |
| 8.2 | **#116:** the real secret OIDs carry `D1 07 23 F1 D0 FD 20 E1 40` and refuse plaintext and unauthenticated shielded reads | `optiga-ac-probe` image (spare OIDs), then `optiga-probe-hw` on a freshly provisioned wallet | AC-PROBE PASS; real OIDs read back strict | R | EVT 10-13 (spare OIDs only) | ☐ |
| 8.3 | SE050 policies, five properties: admin cannot read user-gated data; admin cannot delete a no-admin UserID (S-6); attempt-attribute read is denied with `0x6986`; lockout persists across reinit; `half_E` is write-once with unauthenticated reads refused | `make se050-stress-destructive BOARD=pq1`; `make se050-admin-extract-attempt-e2e BOARD=pq1` | 0 FAIL; ADMIN-EXTRACT ATTEMPT: PASS | C (leaves an undeletable carve-out UserID) | dev kit E2 05-28 | ☐ |
| 8.4 | Admin wipe removes OPTIGA F1D1–F1D4 and the duress twins, every SE050 object, and the page-125 salt, then resets page 124 | `make dual-se-admin-wipe-e2e BOARD=pq1`, then raw reads plus a page-125 dump with `mode=UR` | all absent; salt gone. Log whether the salt is zeroed in place or the page erased. | R | pq1 bench 10-14 (salt behaviour not logged) | ☐ |
| 8.5 | Single-chip dump replay (Ledger Donjon): one chip's contents yield neither the PIN nor its half. **Expected to fail today:** E140 is never ratcheted, so the PBS stays plaintext-readable (DVT probe: `PBS_READABLE_PLAIN`), and F1D0 is `Change=ALW` in every buildable image. | desolder, then a bench I2C rig with an emulator | ≤ 10 guesses total | X | never | ☐ (after §9) |

## 9. SE lifecycle and rotation — loose parts first

| ID | Assumption | How | Pass | Cls/Tier | Prior | DVT status |
|---|---|---|---|---|---|---|
| 9.1 | **S-1:** after F1D0 `Change=Auto(F1D0)` and LcsO=Operational, F1D0 cannot be overwritten and E120 cannot be reset without the PIN. Doc conflict: CLAUDE.md says the candidate uses `Auto(F1D0)`, but every runnable image installs `ALW`. | loose TRUSTMV3 shield | no-auth SetData refused; metadata matches | X / L | never | ⛔ fenced (irreversible pair unbuildable) |
| 9.2 | **S-2:** after closure, the E0E8/E0E9/E0EF trust anchors reject attacker-signed Protected Updates, and E0E1–E0E3 cannot be retyped. DVT: all three are type TA, `Change=LcsO<op`. | loose shield; negative manifests | rejected; ACs `NEV`, LcsO=Op | X / L | inventory only (1.7) | ⛔ |
| 9.3 | E140 lifecycle and rotation order: an Operational E140 authenticates with the transport PBS, accepts the final PBS via `Conf(E140)`, re-establishes after a cut, and **stops being plaintext-readable**; the `SetData(E140)` wedge timing is bounded | loose shield, PSU cut, LA | all four observed on two parts | X / L | never | ☐ |
| 9.4 | `HW-ASSUME-PUTKEY-KCV-RESP` / `REPUT-IDEMPOTENT`: does the GP applet echo KCVs (a 0-length response is accepted today), and does a re-PUT of identical keys under the final DEK return `0x9000`? | `make flash-hw-se050-rotate-scp03 BOARD=pq1` on a loose part | response body length recorded; flip-table constants set | X / L | never | ☐ |
| 9.5 | **`HW-ASSUME-PUTKEY-ATOMIC` (ship-blocker):** a power cut never leaves ENC/MAC final with DEK still transport. The resume probe checks only ENC/MAC (`se050/mod.rs:509-520`). | Scaffold crowbar with LA trigger on `84 D8 0B 81`; probe the DEK independently; ≥5 parts | no mixed keyset in any shot | X / L | never | ☐ |
| 9.6 | SE050 admin re-key, transport to final (delete then recreate), does not trip `0x6986` | loose part | completes | X / L | never | ☐ |
| 9.7 | Phase B end to end, plus the power-cut matrix at every journal step | §12 | converges on two units | X / S | never | ⛔ #268 |

## 10. Boot chain, FSBL, measured boot, invariant #10

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 10.1 | The FSBL admits manifest A, re-hashes both slots and branches on DVT silicon | `make bootproof-sign` then `make bootproof-hw BOARD=pq1 BOOTPROOF_FSBL_EXTRA=stage-marker` | `Branching` marker; digests match the read-back | R | pq1 bench 18/18 09-16, 19/19 09-28 (dev key, mock slot, legacy geometry) | ☐ |
| 10.2 | Boot ≈ 6.9 s (2.9 s of work plus the 4 s hold). Only the 10 s-hold version has been measured. | stage-marker deltas | `Branching − RenderFlushed` ≈ 4.0 s | R | 12.9 s with the old hold | ☐ |
| 10.3 | The FSBL owns the display and halts on SPI/AW99703 failure; a good boot paints before handoff | 10.1 plus a mutated-`CHIP_ID` FSBL as negative control; record the panel-unplugged behaviour | negative control: no `Branching` | R | panel-less negative control 09-23 | ☐ |
| 10.4 | A flipped byte in either slot, a bad signature or fingerprint, or `fw_version` ≤ floor halts the FSBL before render | new `bootproof-hw` variant flashing tampered `.bin`s | `SlotAAdmitted=0` or `ImgSecureCmp=0`; no render | R | never | ☐ new |
| 10.5 | The tz-1 option-byte tripwire halts on a persistent mismatch. WRP1A and OEM locks are not checked. | 10.1 plus a deliberate `SECWM2` change | `Tz1Verdict=0`, no render | R | positive case only | ☐ |
| 10.6 | The FSBL words equal the secure-world `measured_boot` words. That screen is compiled out of `mode-production`, so the check exists only in debug builds. | `bootproof` variant with a `dual-se,dev-testkey,ui-lcd,usb` slot A | same 8 words | R | never | ☐ new |
| 10.7 | Host `fwmeasure` words equal the panel. Use the bootproof ELF: `make measure` hashes a monolithic image the FSBL never sees. | `fwmeasure` on the slot ELF vs a photo | match | N | never | ☐ |
| 10.8 | The flashed FSBL is byte-identical to a reproducible build. `verify-repro` diffs only the secure and non-secure images (#189). | `mode=UR` dump vs repro build | identical | N | never | ☐ |
| 10.9 | **Invariant #10(a):** a readout before first power executes zero code | canary image that appends a flash marker each boot; hold NRST (J210 pin 10) low before USB-C power; read with `mode=UR` | no new marker | N | never | ☐ new |
| 10.10 | `make verify-ship-state` works on a DVT. Gaps: it does not read OTP, and checks only listed option bytes. | run with the `bench-rdp0-tzen` profile | OK; gaps fixed | N | never | ⚠ DVT1 10-15: `make verify-ship-state` → OK, 16/16 fields match. Gaps still open: no OTP read, no flash-hash compare, and UNLOCK_1A/1B/2A/2B, nBOOT0, SRAMx_RST, BOR_LEV, IWDG_* are not in the profile. |
| 10.11 | **The consumer verify procedure has a physical path.** The design doc puts SWD on SBU; V10 routes SBU to BOOT0, and J210 is DNP on MP. | owner decision (O-1) | path defined | — | — | ⛔ O-1 |
| 10.12 | FSBL verify and FW-COMMIT single-glitch resistance (F15) | see 15.4 | — | X / L | never | ☐ |

## 11. Firmware update and rollback

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 11.1 | With the device locked, every `CMD_FW_*` (20–24) returns `0x6982` | new non-secure fixture (`fwup-transport-hw` auto-unlocks) | 5/5 refused | N | never | ☐ new |
| 11.2 | Update transport end to end, up to COMMIT | `make fwup-transport-hw` / `-iwdg BOARD=pq1` | PASS | R | dev kit 05-28 (mock SE; stops before write) | ❌ DVT1 10-15, issue to open. Without IWDG: sanity, happy BEGIN/CHUNK/COMMIT (test mode) and all four fail paths pass, then a repeated invalid BEGIN gets **no reply** (30 s host timeout). Isolated with direct bad-signature BEGINs (0.23 s each): every 5th–9th BEGIN gets no reply, while the next GET_STATUS answers at once (3 s-timeout probe: answered at t+3.2 s) and a later valid BEGIN returns `9000`. The device is not stalled: the NS main loop is running (PC sampled twice), no USB disconnect. A request or reply is being dropped in the HID/APDU chain. With IWDG the same run reset the device (see 5.8). |
| 11.3 | The old slot survives a power cut at any step. Code read predicts the legacy selector is inverted: after COMMIT the FSBL boots the old slot, and a cut after the boot-state erase boots the new one. Legacy is production-fenced. | relay or PSU cut per step | old slot boots after every cut | R | never (#480 #696) | ☐ |
| 11.4 | BEGIN erases the non-running slot (VTOR). On monolithic bench images it erases a page inside the running image. | slot-layout image | correct slot erased | R | never | ☐ |
| 11.5 | Page 126 (BHK) hashes the same before and after BEGIN/CHUNK/COMMIT on a `bhk` build | 11.3 variant | unchanged | R | never | ☐ |
| 11.6 | Downgrade logic | `make fw-rollback-hw BOARD=pq1` | `[S][fwrb] === PASS ===` | R | dev kit | ✅ DVT1 10-15: 6/6 (v1/v2 accepted at floor 0; v1, v2 rejected at floor 2; v3 allowed; forged v3 → BadSignature). Literal floors; OTP untouched (re-read). |
| 11.7 | Update command parsing end to end, without commit | `make test-update-hw BOARD=pq1` | `[NS][fwup-test] === PASS ===` | N | dev kit | ✅ DVT1 10-15: T1–T12 PASS, no COMMIT, OTP re-read blank. Note T11 accepts either BadVersion or BadManifest (status 11), so it does not pin *why* the full-chain BEGIN was refused on a floor-0 board. The recipe comment that boot burns the OTP master is stale for this `mock-se` image. |
| 11.8 | Production rollback backend (Draft 1.1, PQFW_V6) | — | — | — | not implemented | ⛔ owner stage decision |

## 12. First-boot self-lock (`rdp2-self-lock`)

**Blocked overall (⛔ #268):** no flashable image exists. Four fences block it:
`RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION`, `FW_ROLLBACK_PRODUCTION_BLOCKED`,
`OPTIGA_S2_PRODUCTION_BLOCKED`, and the FSBL `mode-production` fence. A `bench-ship-validation`
config needs owner sign-off. Runbook: `docs/provisioning/first-boot-hardware-bringup.md`.

| ID | Assumption | Pass | Cls/Tier | DVT status |
|---|---|---|---|---|
| 12.1 | Each Phase-A error E0803–E080B halts unlocked with no option-byte write. E0809 fires on every genuine unit while WRP1A is unpinned (2.2). | halts, option bytes unchanged | R / D | ⛔ |
| 12.2 | The confirm gate: decline or idle stays at RDP 0, re-prompts next boot, and no IWDG/SysTick reset fires during the prompt | option bytes unchanged | R / D | ⛔ |
| 12.3 | A power cut across OPTSTRT/OBL_LAUNCH converges to RDP 2 with a clean boot, or to RDP 0 with a re-prompt | as stated | X / L then S | ⛔ |
| 12.4 | The Phase-B journal resumes after a cut at each of its 5 steps and inside the 3-QW salt record; resume probes final then transport | completes, or halts with a documented `E08xx` | X / L then S | ⛔ |
| 12.5 | Page 126 is programmable on this die (E0822 otherwise) | see 1.9 | R | ☐ via 1.9 |

## 13. Trusted display and user input

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 13.1 | The sign chord fires only on `Confirm?` or the last screen (2026-10-13 policy); hold-right signs nothing; the legacy 16×4 dialog requires the last page seen | `make play-hw-px BOARD=pq1`, `tools/hid_sign*.py`; chord on every screen of every family | signatures only at `sign_point` | N (mock SE) | EVT 09-22/23 under the **old** policy | ☐ |
| 13.2 | All 42 `demo_px_flows.py` flows render correctly on glass; 24 have never been walked | walk them on the panel | all OK | N | 18 walked on EVT | ☐ |
| 13.3 | "Presented" means visible: `presented_at` latches on SPI/DMA completion, and the TE result is discarded (`ui/px/lcd.rs:554`). HARDENING §2.4 says "reached the glass". | ≥240 fps camera synced to the CS line; FPC removed, backlight off and TE cut as variants | CS-end→photon latency recorded; dark-panel and dead-TE behaviour decided (O-4) | N | none | ☐ |
| 13.4 | A non-secure ISR cannot swap atlas glyphs during a dialog and restore them before the post-hash (`ui/px/assets.rs`) | non-secure fixture reprograms and restores the atlas page on the Nth SysTick | caught, or the residual recorded and WRP applied to the atlas pages | R | none | ☐ new |
| 13.5 | Buttons PA0/PA1: 30 ms debounce, 80 ms chord skew window, and non-secure code cannot inject presses (`GPIOA_SECCFGR` bits 0–1 = 1) | relay or second-MCU presser plus LA; non-secure ODR/MODER/PUPDR writes | no double events; skew ≥ 80 ms is never a chord; non-secure writes inert | N | EVT works; debounce unvalidated | ☐ new |
| 13.6 | Frame time and tearing at 40 MHz (`board::LCD_SPI_MBR`). Measured 31 ms vs the 16 ms target; the full-panel blit has never been measured. | `ui-px-frametime`, `ui-px-te-probe` builds | full-panel blit ≥ 24.31 ms floor recorded; tearing characterised | N | EVT 10-05 (partial repaints) | ☐ |
| 13.7 | Seed-wizard decoy frames are invisible at 40 MHz on pq1 | `make decoy-flicker-lcd-hw BOARD=pq1` plus camera | invisible, or `decoy-frames` stays off | N | **failed** at 20 MHz on dev kit 06-09 | ☐ |
| 13.8 | The FSBL fingerprint window lasts ≥ 4.0 s, and its words match `fwmeasure` | camera during 10.1 | as stated | N | no photo receipt | ☐ |
| 13.9 | The idle wipe fires at 120 s even while non-secure code spams `GET_REMAINING`/`IS_UNLOCKED`. Doc mismatch: the timer is the secure SysTick, not an "S-only TIM". | non-secure ping loop; time from last button press to wipe | 120 ± 1 s | N | free-running idle 09-18 (no spam) | ◐ DVT1 10-15, no-spam case only: on the mock-SE e2e image with NS parked (no gateway calls), an SRAM dump at t+140 s after the last sign shows `STATE` and `SLOT_CACHE` wiped (row 5.5). The spam case and the exact firing time are still open. |
| 13.10 | **A hostile non-secure image cannot hold the idle wipe off.** Code read: the wipe is skipped while `handler_is_busy()` (`main.rs`). A non-secure ISR that preempts a sign, parks there and bumps the heartbeat may keep both the wipe and the IWDG at bay. | `nested-gate-test` variant that parks and bumps | zeroize within a stated bound, or the residual recorded | N | none (new hypothesis) | ☐ new |

## 14. Host-facing surface (non-secure world and USB)

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 14.1 | USB HID survives malformed input: oversized frames (> 4096 B `MAX_APDU_RX`), bad framing, stale reassembly (5 s scrub); the IWDG recovers a wedged loop in about 6 s | replay the host fuzz corpora over hidraw for 24 h | no secure fault; no hang > 6 s; no over-length response | N | enumeration only (EVT 09-21) | ☐ new |
| 14.2 | USB descriptor-level robustness | Facedancer/Cynthion | no secure fault | N | never | ☐ |
| 14.3 | A ship-shaped image (`PX_SHIP_FEATURES`) prints nothing secret on USART2/PA2, semihosting or SWO/PB3 | UART capture across wizard, unlock and sign | empty, or allowlisted strings only | N | build-level check only | ☐ |
| 14.4 | Every defence validated here on a bench image is also present in the ship-shaped ELF (pattern: `scripts/check_gateway_gate_in_elf.py`) | per-defence ELF check | present | host | gateway gate only | ☐ |

## 15. Fault injection — loose parts and dev kit first

| ID | Assumption | How | Pass | Cls/Tier | Prior | DVT status |
|---|---|---|---|---|---|---|
| 15.1 | No single glitch releases a divergent or unverified signature (double compute, then `ct_eq`, then verify before release; `crypto.rs`). Take glitch targets from the shipped `z` ELF: the MachineOutliner merges FI call sites. | Scaffold + FaultyCat armed on the PB3 trigger; sweep delay × width × XY; verify each released signature offline | 0 bad signatures in ≥ 10⁵ glitches per window | X / L | emulation smoke run only | ☐ |
| 15.2 | The `sca-trigger` pulse appears on PB3 (J210 pin 6) around sign, `cmac_dhuk` and `gated_unlock` | bench image plus scope | one pulse per operation | N / D | never on pq1 | ☐ |
| 15.3 | PIN gate: no single glitch gives an unbudgeted guess (page-124 bump skip or verdict force) | rig on `gated_unlock`; mock SE first | page 124 rises by ≥ 1 or the device resets on every attempt | C+X / L | never | ☐ |
| 15.4 | FSBL `verify_images` (bare `!=`), FW-COMMIT, signature/digest/rollback checks and the OTP floor vote need two faults (EF-swarm F15, EVT 8.1–8.4) | new sweep around FSBL hashing (1.19 s) and C10 verify (0.38 s) | no tampered slot reaches `Branching` | X / L | never | ☐ new |
| 15.5 | The consent-gate discriminant cannot be flipped into `Sign` off `sign_point` (#421) | glitch the chord-release window, mock SE | 0 signatures without a chord | X / L | never | ☐ |
| 15.6 | On-silicon ERC-7730 descriptor-authority fault campaign (#376) | rig | per #376 | X / L | never | ☐ |

## 16. Side channels

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 16.1 | The C10 signing shuffle (F-16) plus fresh OptRand defeat CPA/TVLA on WOTS/FORS | EM/power capture triggered on PB3; Husky | TVLA \|t\| < 4.5 at 10⁶ traces; key rank does not converge | N | emulation only | ☐ |
| 16.2 | The consumption mask dilutes the signal. On pq1 it drives TIM3_CH1/PA6, which is **NC**, so it has no load. | SNR/TVLA with the mask on vs off | measurable gain, or the claim demoted | N | AF self-test only | ☐ |
| 16.3 | SAES/DHUK and the PIN-credential PRF leak neither DHUK nor the PIN (attacker controls the PIN input). Needs RDP ≥ 1 for the real DHUK. | CPA on the SAES window | TVLA clean at 10⁶ | N | none | ☐ |
| 16.4 | The `checkct` verdict holds on the real core | DWT dudect Welch t-test on `verify()` and the KDF (EVT 9.2) | \|t\| < 4.5 | N | host static analysis only | ☐ |
| 16.5 | Real, wrong and duress unlocks are indistinguishable on the SE buses (APDU count and lengths) | LA on both buses | identical sequences | N | never | ☐ |
| 16.6 | Sign duration depends only on public values (the C10 grinding counter is in the signature) | `test-key-speed` timing vs counter | r ≈ 0 against secret-dependent values | N | DVT1 timings exist | ☐ |

## 17. Electrical and environmental

| ID | Assumption | How | Pass | Cls | Prior | DVT status |
|---|---|---|---|---|---|---|
| 17.1 | ESD ±8 kV contact discharge causes no secure fault, no false tamper wipe, and no GTZC change | ESD gun | as stated | X-risk (use a spare unit) | never | ☐ |
| 17.2 | Boot, sign, TRNG health and SE comms hold at the temperature corners (OPTIGA MK part: −25 to +85 °C) | thermal chamber | all PASS | N | never | ☐ |
| 17.3 | USB-C CC/VBUS abuse does not compromise state (AW35602 instead of TCPP03; FLAGB unread) | PD tester / abuse cable | no fault | N | never | ☐ |

---

## Owner decisions surfaced by this checklist

| # | Decision | Blocks |
|---|---|---|
| O-1 | How a consumer performs the invariant #10(a) readout on V10/MP hardware (SBU drives BOOT0; J210 DNP) | 10.9, 10.11 |
| O-2 | Whether REV_ID `0x3007` dies are acceptable without SESIP coverage (ask ST; check MP die revision) | 2.1, 2.8 |
| O-3 | Authorise a `bench-ship-validation` image (#268) | 7.1, 9.7, §12, 4.4 |
| O-4 | Must a dark panel or dead TE refuse signing? | 13.3 |
| O-5 | Must a failed PIN-pad randomisation refuse, rather than fall back to zeros? | 4.9 |
| O-6 | Consumption-mask PRNG: bring into carve-out compliance, or amend the carve-out | 4.13 |
| O-7 | `IWDG_SW` policy vs the FSBL hold and the Phase-A prompt | 5.8 |
| O-8 | Which SRAM bank the reset-erase and ECC options must cover | 5.6 |
| O-9 | Genuine-part check: a factory-side host verify (invariant #5 forbids an on-device ECDSA verify) | 6.7 |
| O-10 | Post-wipe end state under the shipping SE policy (a bricked wallet is acceptable, or build an OID-bump path) | 7.8 |
| O-11 | Whether to set nSWBOOT0/nBOOT0 and BOOT_LOCK before RDP 2, and add them to the ship profile | 2.9, 2.10 |
| O-12 | Whether an OTP readable from non-secure code is an accepted residual (if 3.6 shows it is) | 3.6 |
| O-13 | Overwriting DVT1's factory OPTIGA PBS (E140) at LcsO=creation. Its 64 bytes are not backed up, so the overwrite is one-way for that value. Allow it, or authorise a plaintext backup first. | 3.12 (SE leg), 6.3–6.5, 7.2–7.5, 8.1–8.4 |

## Harness defects to fix before the DVT run

**Harness lessons from the DVT1 2026-10-15 run** (each cost time once; read before re-running):
- **Semihosting images reset-loop once probe-rs detaches.** After `probe-rs run` exits or is killed, the next `hprintln!`/`secure_log!` BKPT has no debugger, escalates to HardFault, and the handler resets. A HOTPLUG read after that shows boot-time values. For SWD read-back after a run: park the firmware in a busy loop with no semihosting (`GTZC_HOLD=1` for gtzc; `BENCH_RESIDUE` for the bench), and build the secure side with `ui-noop` and without `debug-log`. Check `DHCSR` bit 25 (S_RESET_ST) before trusting a read.
- **Banked SCS registers need the secure view.** Over SWD, `SAU_*` and AIRCR read as the NS bank (SAU all zero) while the core sits in NS. Write `DSCSR` (`0xE000EE08`) = `0x00020003` (SBRSEL=1, SBRSELEN=1, CDSKEY=1) first. CubeProgrammer `-w32` refuses both SCS and the flash-register block; probe-rs writes them.
- **RCC registers hide secure bits from NS.** For example `RCC_AHB2ENR1` reads `0x40000000` from NS and `0xC01F0000` from secure. Judge NS write probes by a secure-alias read, not the NS read-back.
- **The gtzc image leaves GPIO and the TAMP/RTC APB clock off,** so GPIO/TAMP probes on it prove nothing until the clocks are on (the `gtzc-sys` list enables RTCAPBEN itself, which is also an NS-writable finding).
- **`fi_delay_pool` counters are LTO-dead** in every image with no reader: `#[no_mangle]` alone did not keep them; `#[used] #[no_mangle]` did (temporary edit, reverted).
- **CubeProg `-d` of a full 8 KB page image programs the trailing `0xFF` quad-words.** To restore a log-structured page (123), write only the record QWs, or the firmware's next append may hit PROGERR.
- **probe-rs leaves the ST-LINK busy** (`errno 16`) if a run is interrupted; check `pgrep probe-rs` before the next target.
- Reproduction scripts for 5.4/5.5: `tools/dvt/residue.sh`, `tools/dvt/sram_search.py`, `tools/dvt/derive/` (computes the e2e-mnemonic search patterns with the real `pqsigner-domain` crate).


- [x] `gtzc-enforcement-hw` passed `board-pq1board-pq1` (fixed `baae7c70`).
- [x] `saes-self-test-hw` lacked `$(BOARD_FEATURE)` (fixed `baae7c70`).
- [x] `saes-self-test-hw-rdp1` lacked `$(BOARD_FEATURE)` (fixed 2026-10-15).
- [ ] `saes-self-test-hw-rdp1`: its UART capture expects the ST-LINK VCP; pq1 needs a USB-UART on J211.
- [x] `bench-masked-sha-hw` lacked `$(BOARD_FEATURE)` (fixed 2026-10-15).
- [ ] `button-test` lacks `$(BOARD_FEATURE)` and is unsafe on pq1 (PA8). Port it or fence it.
- [ ] Every HW recipe's single option-byte write: add the second `SECWM2` write for TZEN=0 chips.
- [ ] `tools/optiga_probe/report.py`: add an `UNPROVISIONED` class (all-zero data at LcsO=creation). Today a factory chip reports 43 findings.
- [ ] `verify-ship-state`: read OTP and every option-byte field (invariant #10 says OTP is checked).
- [ ] `gtzc-test`: extend per 3.2–3.6, 3.9 and 3.4.
- [ ] `bootproof-build`: add a measured-boot variant with an LCD slot (10.6).
- [x] `gtzc-test` NS write probes for RCC/PWR/TAMP/EXTI/TZSC/GPIO and fault probes: `GTZC_NS_EXTRA=,gtzc-sys`, `GTZC_FAULT_ADDR=0x…`, `GTZC_HOLD=1` (added 2026-10-15). Still to do: a ship-peripheral-set image (3.2) and a GPIO-clocked image (3.4).
- [ ] `tools/optiga_probe`: no supported way to back up E140 before a bench pairing overwrites it (O-13).
- [ ] `fi_delay_pool`: give the counters a reader (or a debug NSC) so 4.12 can be measured without editing source.
- [ ] `tools/fwup-transport-test.py`: on a missing reply, probe GET_STATUS before declaring a hang (11.2 showed a dropped reply, not a hang).

## Doc and code drift found (fix in the owning doc)

- **EVT 5.5 / quick reference:** says the OPTIGA handshake is "broken". It works on EVT #1 (10-13).
- **EVT §6:** calls the part SE050C2 and says it has "never run on silicon". pq1 EVT #1 needed the E2 keyset.
- **EVT 10.6 and `red-teaming.md` §5.3:** call `pin-gate-wipe-e2e` the "QEMU analogue". It is a hardware target.
- **CLAUDE.md:**
  - The inactivity timer is "S-only TIM"; the code uses the secure SysTick.
  - "TE never waited on" is stale.
  - The lifecycle lists "SE attest"; no attestation code exists.
  - "S-1 candidate uses `Auto(F1D0)`"; runnable images install `ALW`.
  - The two-screen fingerprint equality does not hold in release builds.
- **HARDENING §2.4:** "reached the glass" means SPI completion.
- **`red-teaming.md` §4.4/§6.7:** say the consumption mask is TIM2/PA5 seeded from `rng_strong`. On pq1 it is TIM3/PA6, seeded from the TRNG.
- **`red-teaming.md` §8.2:** gives an 8192 B limit; the code's is 4096.
- **`rng.rs:281` and frontier-research 2026-10-11:** describe pre-pool FI-delay behaviour.
- **`hardware-assumption-boundary` ledger:**
  - "no health tests" is stale; minimal zero/repeat tests exist.
  - The `hal` "contradiction" on QW atomicity is stale.
- **`brownout-hardening.md`:** plans to put secrets in SRAM2, which is the non-secure bank.
- **`firmware-update.md`:**
  - COMMIT behaviour and the "stubbed" confirm dialog are stale.
  - "no flash write until COMMIT" is false: BEGIN erases a slot.
- **`measured-boot.md`, EVT §1:** say the FSBL has "no I2C stage". It drives the AW99703.
- **`measured-boot.md` / EVT:** give a 12 s or 10 s hold; the code holds 4 s.
- **`threat-model.md`:**
  - Says duress is "not implemented"; it is implemented and fenced (#903).
  - The non-secure OTP alias is absent.
- **`se050-silicon-findings.md`:** gives the lockout SW as `0x6982`; silicon shows `0x6986`.
- **`secure/memory-stm32u585.x`:** says page 125 holds a "PIN at QW0"; `flash.rs` says QW0 is unused.
- **`sau.rs:363-367`:** cites iota2 GPIOE LCD pins.
- **Found on the DVT1 run (2026-10-15):**
  - **FIXED (fix commit 1):** **`sau.rs:648` / `main_sau_pure_tests.rs:671-681`:** `AIRCR_PRIS = 1 << 10` and the test that pins it were wrong. CMSIS `core_cm33.h` has `SCB_AIRCR_PRIS_Pos 14U`; bit 10 is PRIGROUP. Silicon reads PRIS=0 (row 3.7).
  - **FIXED (fix commit 2):** **`hw/rcc.rs:145`:** "Select HSI48 as RNG clock source" cleared bits [1:0] of offset `0xE0`, which is `RCC_CCIPR1.USART1SEL`. RNGSEL is `RCC_CCIPR2[13:12]` (offset `0xE4`). Harmless today (reset value is HSI48 and RNGSEL is secure because RNG is secure), but the comment and the write disagree with RM0456 §11.8.
  - **Row 4.7:** the U5 RNG has no `RNG_VERR` register (RM0456 §48.7).
  - **`Makefile` `test-update-hw` comment:** says every hardware boot of that image burns the OTP master. With `mock-se` nothing calls `ensure_device_master`; DVT1 OTP stayed blank across four such images.
  - **`a-b-firmware-rollback-architecture.md` (cited by row 3.6):** the "non-secure OTP alias" is not NS-readable on this image (row 3.6).

---

## Evidence log

Append one line per run (newest last): `date · unit · commit · target/features · result · artifact`.

- 2026-10-15 · DVT1 · `62486d98` (+ Makefile fixes, `baae7c70`) · intake 1.1/1.2/1.4 · ✅ · `~/Documents/PQ1/dvt1-backup-2026-10-15/`, sha256 `a9ab0052…`
- 2026-10-15 · DVT1 · same · `se-i2c-probe-hw` (1.6) · ✅ OPTIGA `0x30` attempt 2, SE050 `0x48` attempt 1
- 2026-10-15 · DVT1 · same · `optiga-probe-hw` SWEEP=0 (1.7) · ✅ read-only confirmed, SEC 0, factory-blank · `target/optiga-probe/cd1633ca01001c00-readonly-20261015-121425.md` (local)
- 2026-10-15 · DVT1 · same · `gtzc-enforcement-hw` (3.1) · ⚠ 11/11, excludes SPI1/IWDG
- 2026-10-15 · DVT1 · same · `saes-self-test-hw` (4.2) · ✅ RDP-0 constant `117d822a62a50830`
- 2026-10-15 · DVT1 · same · `test-key-speed` (1.10) · ✅ first sign 12.3 s, cached avg 5.76 s
- 2026-10-15 · DVT1 · — · option bytes: TZEN 0→1, then `SECWM2_PSTRT=0x7F SECWM2_PEND=0x0` · R, RDP 0 unchanged
- 2026-10-15 · DVT1 · `86d9b2a2` + uncommitted `gtzc-sys` harness (`nonsecure/src/gtzc_test.rs::sys_probe`, Makefile `GTZC_NS_EXTRA`) · `make gtzc-enforcement-hw BOARD=pq1 GTZC_NS_EXTRA=,gtzc-sys` (3.1 re-run, 3.5) · 3.1 ✅ 11/11 again; 3.5 ❌ RCC/PWR/TAMP/EXTI NS-writable, secure-alias read-back over SWD with the harness parked (`GTZC_HOLD=1`) · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/gtzc-sys-3.{log,swd}`
- 2026-10-15 · DVT1 · same · `GTZC_FAULT_ADDR=0x0BFA0000` (3.6) · ✅ NS read faults
- 2026-10-15 · DVT1 · same · `GTZC_FAULT_ADDR=` 7 secure addresses + NSC table + 2 NS positive controls (3.3) · ✅ all secure reads fault, controls read
- 2026-10-15 · DVT1 · same · parked gtzc image + SWD (1.5, 3.7, 4.7) · 1.5 ✅, 4.7 ✅, 3.7 ❌ AIRCR.PRIS=0 (bit-10 constant); `1 << 14` test build reads `0xFA054000`; NSC padding clean
- 2026-10-15 · DVT1 · same · `make test-key-speed BOARD=pq1` (1.10, 1.11) · ✅ 0 TRNG errors / 27 fills · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/tks.log`
- 2026-10-15 · DVT1 · same + uncommitted `BENCH_RESIDUE` mode in `nonsecure/src/bench_key_speed.rs` · secure `mock-se,ui-noop,e2e-test,stm32u585,hw-sha256,board-pq1` (5.5) · ⚠ STATE/SLOT_CACHE wiped by LOCK and idle; legacy provisioning seeds remain on stack · scripts `tools/dvt/residue.sh`, `tools/dvt/sram_search.py`, `tools/dvt/derive/` (dumps in `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/`)
- 2026-10-15 · DVT1 · same · `nested-gate-test-hw` + `-nctl-hw` (3.10) · ✅ both
- 2026-10-15 · DVT1 · same · `tzic-wipe-hw` (3.12) · ⚠ flag armed + reset; SE leg not run; page 125 erased after
- 2026-10-15 · DVT1 · — · CubeProg erase/program/verify of pages 123–127 (1.9) · ✅; page 123 records restored
- 2026-10-15 · DVT1 · same · `test-update-hw`, `fw-rollback-hw` (11.7, 11.6) · ✅ both; OTP unchanged
- 2026-10-15 · DVT1 · — · WRP1A 0..3 with UNLOCK=1, decode, restore (2.2, 2.3) · 2.2 ✅, 2.3 ◐
- 2026-10-15 · DVT1 · — · `make verify-ship-state` (10.10) · ⚠ 16/16 OK, gaps unchanged
- 2026-10-15 · DVT1 · same · `se050-stress-only-audit_se050_version_identity`, `se050-stress` (1.8, 6.1, 6.8) · E2 v7.2.0 0x3F9F; 10/0/10 · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/se050-*.log`
- 2026-10-15 · DVT1 · same · `optiga-probe-hw SWEEP=1` (1.7) · ✅ 0 hits, metadata unchanged, SEC 0
- 2026-10-15 · DVT1 · same + temporary `#[used] #[no_mangle]` on pool counters (reverted) · residue image + `consumption-mask` (4.12) · ◐ HITS=0 MISSES=0
- 2026-10-15 · DVT1 · same · NRST via `mode=UR` from the unlocked state, SRAM dump (5.4) · ⚠ all unlocked secrets retained · dump `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/sram-nrst.bin`
- 2026-10-15 · DVT1 · same · `fwup-transport-hw-iwdg`, `fwup-transport-hw` + direct timing script (3.13, 5.8, 11.2) · enumerates ✅; IWDG idle ✅; dropped FW_BEGIN reply every 5–9 invalid BEGINs ❌; IWDG build reset mid-run ◐ · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-pm/fwup-*.log`
- 2026-10-15 · DVT1 · fix 1 (PRIS) · `GTZC_HOLD=1 make gtzc-enforcement-hw BOARD=pq1 GTZC_NS_EXTRA=,gtzc-sys` + SWD (3.7 re-run) · ✅ AIRCR `0xFA054000`, CSLCKR `0x5`, 11/11 · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-fix/pris-gtzc.log`
- 2026-10-15 · DVT1 · fix 2 (system controllers) · `GTZC_HOLD=1 make gtzc-enforcement-hw BOARD=pq1 GTZC_NS_EXTRA=,gtzc-sys` + `tools/dvt/gtzc_sys_verify.sh` (3.5 re-run) · ✅ 12/12 phase 1, SWD verdict 22/22 · `~/Documents/PQ1/dvt1-backup-2026-10-15/run-2026-10-15-fix/sys-gtzc.{log,swd}`
- 2026-10-15 · DVT1 · fix 2 · `make test-key-speed BOARD=pq1` (1.10 regression) · ✅ PASS, 0 TRNG errors; timing A/B vs the PRIS-only image within grinding variance (first sign 12.8–17.0 s across runs on both) · `run-2026-10-15-fix/tks-{sys,fix1-baseline,cur-1}.log`
