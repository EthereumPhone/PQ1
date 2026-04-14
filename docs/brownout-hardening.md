# Brownout & Glitch Hardening — Design + Roadmap

## Why this document exists

A hardware wallet that can lose power mid-operation at any moment must be
designed so that *every possible point of interruption* leaves the device
in a recoverable state. Today PQSigner OS has one targeted crash-safety
mechanism (the wipe-in-progress flag at flash page 125 QW 1) which we
validated end-to-end. Everywhere else, we depend on the chip happening
to not lose power during critical multi-step sequences. That's not good
enough for a production device that stores transaction-signing seeds.

This document defines the failure classes we need to tolerate, catalogues
what the STM32U585 silicon provides for free, audits what we currently
don't use, and lays out a **5-stage rollout** that turns brownout
robustness from "mostly-OK-by-accident" into a measurable property.

## Threat taxonomy

"Brownout" means Vcc sags or collapses at an arbitrary instant during
execution. The failure classes that matter for a wallet, from most to
least catastrophic:

| Class | Event | Today's behaviour |
|---|---|---|
| **A. Torn flash QW** | 128-bit quad-word program interrupted mid-flight. Some bits committed, others indeterminate; ECC may flag on read. | Undetected. `write_quadword` returns Ok if the error flags didn't set, regardless of whether the bytes actually landed correctly. |
| **B. Partial page erase** | 8 KB page erase aborted mid-sweep. Cells partially erased. | Undetected. Next read returns unpredictable mix. |
| **C. Multi-QW write window** | Between QW0 and QW1 of a 32-byte write, Vcc dies. Half-good, half-blank on reboot. | Undetected. No CRC, no length, no magic — readers trust raw bytes. |
| **D. SE050 mid-APDU** | I2C dies during an SCP03 command. SE050 NVM is APDU-atomic but we don't verify post-hoc. | Silent state drift: firmware thinks delete succeeded, object still on chip. |
| **E. Dual-SE ordering** | STM32 wipes SE050 OK, then Vcc dies before `erase_pbs_page` runs. Half-wiped state survives. | Partially covered by the wipe-in-progress flag, but the flag doesn't distinguish "pre-SE050-wipe" from "post-SE050-wipe-pre-OPTIGA-erase". |
| **F. SRAM residue** | Abnormal reset before panic handler runs. Secrets linger in SRAM1 retention until next power-on. | `panic_handler` zeroizes, but any reset path that skips it leaves SRAM intact. No boot-time sanitization. |
| **G. Half-flashed firmware** | OTA / DFU interrupted by brownout. Firmware partially programmed. | Out of scope for this doc — addressed by the separate measured-boot + signed-update work (work-todo.md items 14-16). |
| **H. Option-byte write** | Bricks the chip. | We never write option bytes at runtime. Fine. |

Current design addresses **E partially** (wipe flag) and **F partially**
(panic handler zeroize). Everything else is unmitigated.

## What STM32U585 gives us for free

STMicroelectronics anticipated brownout robustness. The U5 silicon has
extensive supervisor and integrity hardware that we leave at chip
defaults today:

### Power supervision
- **BOR (Brown-Out Reset)**: 5 levels via option byte `BOR_LEV[2:0]` in
  `FLASH_OPTR`. Trips clean reset when Vdd drops below threshold. Levels
  BOR0 (~1.7 V) through BOR4 (~3.0 V). A chip that performs flash writes
  should be at BOR3 (~2.7 V) minimum.
- **PVD (Programmable Voltage Detector)**: configurable threshold via
  `PLS[2:0]` + enable `PVDE` in `PWR_SVMCR`. Fires EXTI line 16 on
  threshold crossing — usable as "last-gasp" warning before BOR.
- **PVM (Peripheral Voltage Monitors)**: independent monitors for VddA,
  VddUSB, VddIO2.

### Reset-cause observability
- **`RCC_CSR`** sticky flags: `BORRSTF`, `PINRSTF`, `SFTRSTF`,
  `IWDGRSTF`, `WWDGRSTF`, `LPWRRSTF`, `OBLRSTF`. Classify every reset and
  respond differently.

### Watchdogs
- **IWDG**: independent watchdog on LSI clock. Immune to main-clock
  failure. 2-5 s timeout bounds any wedged state.

### Memory protection
- **Option byte `SRAM2_RST=0`**: silicon auto-erases all 64 KB of SRAM2
  on every reset of any kind (POR, BOR, software, watchdog). Turn this
  on and put active-window secrets in SRAM2 — get hardware zeroization
  without firmware correctness dependency.
- **ECC** on SRAM2/SRAM3: single-bit correct, double-bit NMI.
- **RAMCFG_MxSR** exposes ECC errors for monitoring.

### Backup domain (Vbat, already wired on B-U585I-IOT02A via CR2032)
- **32 × 32-bit `TAMP_BKPxR`** backup registers: survive Vdd loss.
  Perfect for wipe-phase state machine, diagnostic last-cause log,
  cross-reboot counters.
- **2 KB Backup SRAM** at `0x4002_4000`: Vbat-retained, auto-wiped on
  any TAMP event.

### Flash integrity
- **ECC on flash**: 9 parity bits per 64-bit sub-word. Torn QW writes
  typically flag via `FLASH_ECCR.ECCD`.
- **WRP** (write protect) and **HDP** (hide protection): lock our
  reserved pages against accidental corruption.

### Tamper subsystem (TAMP)
- **Internal tampers**: clock monitoring, temperature monitor, voltage
  monitor. Any of these can auto-wipe backup regs + backup SRAM +
  crypto peripheral state in hardware, in <1 µs.
- **External tamper pins** with edge/level detection and filtering.

## Current posture

From a systematic audit of the codebase:

| Feature | Status | Location |
|---|---|---|
| BOR level | chip default (unknown state) | option bytes unset |
| PVD | disabled | no code |
| `RCC_CSR` read | never | no code |
| IWDG | disabled | no code |
| `SRAM2_RST` | chip default (probably 1 — no auto-erase) | option bytes unset |
| Post-flash-write verify | no — only `ERR_MASK` check | `hw/flash.rs:143-156` |
| Multi-QW tearing guard | none | `hw/flash.rs:180-193, 247-257, 348-349` |
| Flash structure headers (magic/ver/CRC) | none | raw bytes |
| Panic handler zeroize | yes | `main.rs:842-858` |
| Boot-time dirty-reset zeroize | no | N/A |
| Backup regs / backup SRAM | unused | N/A |
| SE050 post-APDU verify | fire-and-forget | `se050/mod.rs:174-177` |
| Dual-SE ordering guard | single-state flag only | `dual_se.rs:216-226` |

## The 5-stage plan

Each stage is independently landable, independently valuable, and leaves
the codebase in a compilable + shippable state. Stages must land in
order — later stages assume infrastructure from earlier ones.

### Stage 1 — Foundational supervision (this PR)

Smallest usable chunk that moves the needle.

- **1a. Reset-cause classification.** New `hw/reset_cause.rs` reads
  `RCC_CSR` before any peripheral init, classifies into `Cold /
  Software / Watchdog / LowPower / OptionByte / Unknown`, clears sticky
  flags, exposes result to `main`. Log each boot's cause.
- **1b. Verified flash writes.** New `write_quadword_verified` in
  `hw/flash.rs` reads back after every write and compares. New error
  variant `VerifyMismatch`. Existing multi-QW writers (`write_key`,
  `write_pbs`, `write_admin_pin`, `arm_wipe_flag`) switch to verified
  form. Torn-write detection: class **A** and class **C** failures now
  observable.
- **1c. Option-byte setup target.** `make stm32-harden-opts` runs
  `STM32_Programmer_CLI` to set `BOR_LEV=3` + `SRAM2_RST=0` on a given
  device. Run once per chip during provisioning. Documents consequences.
- **1d. Dirty-reset boot hygiene.** When `reset_cause()` returns
  anything other than `Cold` or `Software`, main() calls
  `nsc::zeroize_sensitive_state()` before doing any unlock work. Belt-
  and-suspenders for class **F**.

Addresses: A (detect), C (detect), F (mitigate).
Does NOT yet address: B, D, E (beyond existing), G, option-byte side of H.

### Stage 2 — PVD last-gasp + SRAM2 relocation

- **PVD interrupt.** Enable `PVDE` with `PLS` ~200 mV above `BOR_LEV`.
  EXTI16 handler (`PVD_IRQ`) fires when Vdd crosses threshold going
  down. In the ISR: set a "dirty shutdown" flag in a TAMP backup
  register, zeroize master secret + decrypted entropy + PIN buffers in
  SRAM, `wfi()` and let BOR finish.
- **SRAM2 relocation** for active-window secrets. Move `nsc::state`,
  `crypto::master_secret_buf`, entropy decryption buffers from SRAM1 to
  SRAM2 (`0x3003_0000`). Requires linker script split. After this, the
  `SRAM2_RST=0` option byte (set in Stage 1c) guarantees hardware
  zeroization of active secrets on every reset regardless of firmware
  correctness.
- **Abort-on-PVD for flash writes.** If PVD is already asserted, reject
  flash writes immediately — never start a QW program under unstable
  Vcc.

Addresses: A (prevent), C (prevent), F (hardware guarantee).

### Stage 3 — Flash structure integrity

- **Versioned + CRC-protected blob wrapper.** `hw/persist.rs` defines:
  ```
  struct PersistHeader {
      magic: u32,        // per-blob sentinel
      version: u16,      // migration compat
      payload_len: u16,
      crc32: u32,        // over payload bytes
      payload: [u8; N],
  }
  ```
  Every persistent structure (admin PIN, PBS, future items) goes
  through this wrapper. On read: check magic + CRC; mismatch → treat as
  blank + trigger recovery.
- **Migration path** for already-provisioned devices: version 0 =
  legacy raw bytes; auto-upgrade to version 1 on first write after
  upgrade.

Addresses: A (post-hoc detect), C (post-hoc detect + recover).

### Stage 4 — Backup-register wipe state machine + IWDG

- **TAMP backup-register access.** `hw/backup.rs` with `DBP` enable
  and `BKP[0..n]` read/write wrappers.
- **Replace single-bit wipe flag** (currently page 125 QW 1) with a
  multi-state counter in backup register 0:
  ```
  0x00 = idle
  0x01 = wipe_started
  0x02 = se050_cleaned (pending OPTIGA erase)
  0x03 = fully_complete (transient)
  ```
  Boot-time resume picks up at the correct point regardless of when
  power was lost. Solves class **E** completely.
- **IWDG enable** with 5 s timeout. Kick every iteration of the main
  loop. Wedge-recovery: any infinite loop or deadlock triggers a
  watchdog reset, Stage 1d's dirty-reset hygiene kicks in.
- **Reset-cause persistence.** Write `ResetCause` to TAMP_BKPR1 every
  boot for diagnostic cross-reboot visibility.

Addresses: E (complete), general wedge-recovery.

### Stage 5 — A/B slots for critical state

Belt-and-suspenders defense against even the most pathological tearing
scenarios.

- **Page 125 redesign** with A/B slots:
  ```
  QW 0  Slot A header (magic | ver | CRC of PIN_A)
  QW 1  Slot A admin_pin (16 B)
  QW 4  Slot B header
  QW 5  Slot B admin_pin (16 B)
  QW 8  current_slot_pointer (1 byte: 0xFF=A / 0x00=B)
  QW 9+ unused
  ```
  Update protocol: write fully to inactive slot → verify CRC → atomic
  bit-clear flip of pointer. Torn update leaves active slot intact.
- **Same pattern for PBS page 126.**
- **Migration**: detect old single-slot layout at boot, relocate to
  A/B.

Addresses: residual risk at A, B, C even if Stages 1-4 have a bug.

### Beyond Stage 5 (out of scope for this roadmap)

- **Hardware bulk capacitance** — add 22 µF decoupling cap near MCU to
  widen PVD-to-BOR window from ~94 µs to ~440 µs. PCB revision change.
- **TAMP peripheral full config** — external tamper pins, temperature
  monitor, voltage monitor. Wallet-enclosure-design-dependent.
- **Signed firmware update with brownout-safe flashing** — tracked
  separately (`docs/work-todo.md` items 14/15/16).

## Testing methodology

Validated at each stage; the test matrix grows monotonically.

### Software (fast iteration, CI-friendly)

- **Crash-point injection.** Feature flags `crash-inject-{1..N}`
  substitute `panic!()` at labelled points (after every flash write,
  inside every multi-step sequence). CI runs the normal flows and
  validates recovery. Tells us precisely which points are survivable.
- **Flash-tearing simulator.** Wrap `write_quadword` in a test mode
  that probabilistically drops the second QW in multi-QW writes.
  Validates CRC + recovery paths.
- **`FakeFlash` unit tests.** In-memory flash with programmable
  truncation at arbitrary byte offsets. Tests every persistent
  structure at every truncation point.

### Hardware (real silicon, slower)

- **Warm reset via `probe-rs reset`.** Exists (`se050-crash-safety-e2e`
  Makefile target). Exercises STM32 reset path; does NOT cut SE050 Vcc.
- **Hard reset via NRST.** Same scope as probe-rs reset. Slightly more
  thorough (resets analog peripherals).
- **Cold cycle via USB unplug.** True cold boot for both chips.
  Manual, but validated end-to-end: see `docs/se050-factory-reset.md`
  and the `[E2E-CRASH]` test log.
- **Programmable USB power switch** (e.g. uhubctl-compatible hub).
  ~$15. Automated cold cycles at any interval. Enables statistical
  testing: run 1000 cycles, require 100% pass rate.
- **Voltage sag tool** (programmable bench supply). Drop Vdd from
  3.3 V to 1.5 V with configurable slew. Validates PVD timing, BOR
  trip, last-gasp handler actually runs before catastrophic failure.
- **Brownout-during-specific-op injection.** External timer triggered
  by a GPIO from the DUT cuts power N microseconds after a labelled
  point. Rigorous but needs a custom board.

## What NOT to do

- **Do not write option bytes from runtime firmware.** Option-byte
  writes require `OBL_LAUNCH` which resets the chip. Doing it at an
  unexpected time could brick the wallet. Runtime code only *reads*
  option bytes; all writes go through `STM32_Programmer_CLI` during
  provisioning.
- **Do not move the existing wipe-in-progress flag location in Stage 1
  or 2.** Stage 4 will replace it wholesale. Changing its format twice
  risks migration bugs.
- **Do not lower BOR below BOR3 (~2.7 V) while flash writes are
  possible.** Below that threshold the flash controller can commit
  torn QWs silently.
- **Do not assume SRAM contents on reset.** Even with `SRAM2_RST=0`,
  SRAM1 retains unless explicitly cleared. Never trust "SRAM is zero on
  boot."
- **Do not trust `write_quadword` return value alone.** The
  `ERR_MASK`-only check passes torn writes. Always use the verified
  wrapper (Stage 1b onward) for persistent data.
- **Do not skip the post-CRC check when reading** (Stage 3 onward).
  CRC verification is what turns "torn write detected" into "torn write
  recovered from."
- **Do not extend the PVD handler** to do anything longer than ~94 µs
  of work (at our typical 35 mA draw + default 4.7 µF decoupling).
  Page erase is ~3-4 ms — unreachable as last-gasp action.
- **Do not use backup-register state without VBAT present.** A
  CR2032 is wired on B-U585I-IOT02A dev boards but MUST be populated
  on production boards — otherwise backup regs become equivalent to
  SRAM1 (lost on Vdd drop).

## Invariants (post-Stage 5)

At the end of the roadmap the following will hold:

1. **No persistent secret ever stored as raw bytes.** Every flash blob
   has magic + version + length + CRC.
2. **No torn QW write goes undetected.** Verified writes catch it at
   write-time; CRC catches it at read-time.
3. **Every reset classifies its cause.** The first action on boot is
   reading `RCC_CSR`; dispatch follows.
4. **Abnormal resets zeroize SRAM2 in hardware.** `SRAM2_RST=0`
   guarantees this without firmware involvement. Active-window
   secrets live in SRAM2 (Stage 2).
5. **Wipe-in-progress state survives arbitrary crash points.** The
   4-state machine in backup register 0 tells boot-time resume exactly
   where to pick up, whether the crash happened pre-SE050-wipe,
   during, post-SE050-wipe, or during OPTIGA erase.
6. **Statistical confidence**: 1000-cycle cold-boot harness passes
   100%.

## Status

- Stage 1: **in progress** (see this PR / commit)
- Stage 2: not started
- Stage 3: not started
- Stage 4: not started
- Stage 5: not started
- Bench hardware (USB power switch, voltage sag tool): not acquired

## File map (post-Stage 1)

| Concern | File |
|---|---|
| Reset-cause classification | `secure/src/hw/reset_cause.rs` (new) |
| Verified flash writes | `secure/src/hw/flash.rs` (`write_quadword_verified`) |
| Boot-time dispatch | `secure/src/main.rs` |
| Option-byte setup | `Makefile` target `stm32-harden-opts` |
| This doc | `docs/brownout-hardening.md` |
