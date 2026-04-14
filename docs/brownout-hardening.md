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

## Target board: B-U585I-IOT02A

This roadmap is written against the STMicro B-U585I-IOT02A Discovery
kit. Chip is **STM32U585AII6Q** (LQFP144, 2 MB flash, 786 KB SRAM in
four blocks, full peripheral set). Details that affect the plan:

| Feature | B-U585I-IOT02A state | Implication |
|---|---|---|
| CR2032 battery socket (VBAT) | Present; populated on our board | Stage 4 backup-register state machine will work. If production hardware omits VBAT, backup regs are lost on Vdd drop and Stage 4 falls back to flash-only. |
| NRST user button (B2) | Wired directly to MCU NRST pin | "One level more thorough than `probe-rs reset`" option for tests. Still does not cut SE050 Vcc. |
| LSE 32.768 kHz crystal | Present | Enables `LSE` for RTC and IWDG timing. LSI-clocked IWDG works fine without it — LSE is a "nice to have" for accurate timekeeping. |
| On-board ST-LINK V3 | Integrated | `probe-rs reset` uses SWD SYSRESETREQ. Does NOT interrupt USB Vbus → SE050 shield stays powered across reset. True cold cycle requires unplugging USB. |
| On-board STSAFE-A110 | Present, I2C2 bus | Currently unused by this firmware (only the `stsafe-probe` feature detects it). Not in scope for brownout work. |
| OM-SE050ARD-E shield | Arduino-header mounted | SE050 powered from shield's 5V pin which is fed by USB. Any full-power-cycle test must disconnect USB; any warm reset keeps SE050 alive. |

### STM32U585 SRAM layout & integrity

The four SRAM blocks have different integrity features. Relevant to
every stage of this plan:

| Block | Size | Secure alias | ECC | Parity | Notes |
|---|---|---|---|---|---|
| SRAM1 | 192 KB | `0x3000_0000` | Yes (single-bit correct, double-bit detect) | — | Main SRAM, currently hosts nearly all our state. |
| SRAM2 | 64 KB | `0x3003_0000` | Yes | Optional (mutually exclusive with ECC) | Target for Stage 2 secret relocation. Option byte `SRAM2_RST=0` makes silicon auto-erase this on every reset. |
| SRAM3 | 512 KB | `0x3004_0000` | Yes | — | Unused today. Biggest block. |
| SRAM4 | 16 KB | `0x3800_0000` | No | Yes | SmartRun domain; retained through Stop 2. |
| Backup SRAM | 2 KB | `0x4002_4000` | No | No | VBAT-retained; auto-wiped on any TAMP event. |

### How SRAM ECC actually works on U5 (correcting earlier guidance)

On STM32U5, ECC **correction** is **always active in hardware** on the
ECC-capable blocks — it's part of the SRAM cell structure, not a
software-toggleable feature. Any single-bit flip (cosmic ray, voltage
noise, brownout-induced transient) is silently corrected on every read
today, regardless of whether we've configured anything.

What **is** configurable via the RAMCFG peripheral is the
**error reporting**:

- `RAMCFG_MxCR` — block-level config (interrupt enable bits, latch mode).
- `RAMCFG_MxIER.SEIE` — generate interrupt on single-bit corrections.
  Usually left disabled (they're silently corrected; logging is noise).
- `RAMCFG_MxIER.DEIE` — generate NMI on **double-bit detections** (the
  uncorrectable case). **This is what we actually want for brownout
  defense** — a double-bit hit on a secret region means bits have been
  corrupted in a way ECC can't fix, and we should react rather than
  return garbage.
- `RAMCFG_MxISR` — status register (which errors fired since last clear).
- `RAMCFG_MxFEAR` — failure address register, pinpoints the flipped
  location.

Neither our code nor cortex-m-rt touches RAMCFG. So today:
- ✅ Single-bit correction is active (hardware feature).
- ❌ Double-bit NMI is not routed. An uncorrectable ECC error today
  returns corrupted data silently and may cause a hardfault if the hit
  lands on instruction prefetch.

Stage 2 will enable `DEIE` on SRAM1/2/3 and implement the NMI handler
to zeroize + soft-reset on any double-bit event.

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
- **ECC on SRAM1/2/3**: single-bit correction is always active in
  hardware (silicon feature, not a toggle). Double-bit detection is
  also always computed, but reporting requires enabling
  `RAMCFG_MxIER.DEIE` + implementing an NMI handler. See the SRAM
  section above for the full picture.
- **`RAMCFG_MxISR`** — status register that accumulates ECC events
  since last clear. Readable at any time for diagnostics.
- **`RAMCFG_MxFEAR`** — failure address register, pinpoints the
  flipped location of the most recent uncorrectable error.

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
| BOR level | chip default until `make stm32-harden-opts` runs; target BOR3 (~2.7 V) | option bytes |
| PVD | disabled | no code (Stage 2) |
| `RCC_CSR` read | **Stage 1 done**: classified + logged every boot | `secure/src/reset_cause.rs` |
| IWDG | disabled | no code (Stage 4) |
| `SRAM2_RST` | chip default until `make stm32-harden-opts` runs; target 0 (auto-erase) | option bytes |
| Post-flash-write verify | **Stage 1 done**: `write_quadword_verified` + read-back compare | `secure/src/hw/flash.rs` |
| Multi-QW tearing guard | post-hoc detect only (from verified writes); Stage 5 adds A/B slots | `secure/src/hw/flash.rs` |
| Flash structure headers (magic/ver/CRC) | none | raw bytes (Stage 3) |
| Panic handler zeroize | yes | `main.rs` (pre-existing) |
| Boot-time dirty-reset zeroize | **Stage 1 done**: abnormal `ResetCause` triggers `zeroize_sensitive_state` | `main.rs` |
| ECC single-bit correction (SRAM1/2/3) | silicon feature; always active; no config needed | HW |
| ECC double-bit NMI reporting | **off** (RAMCFG untouched); double-bit = silent corruption | no code (Stage 2) |
| RAMCFG diagnostics | none — we don't know actual ECC event counts | no code (Stage 1.5) |
| VBAT presence detection | none — Stage 4 depends on backup regs surviving | no code (Stage 1.5) |
| Backup regs / backup SRAM | unused | N/A (Stage 4) |
| SE050 post-APDU verify | fire-and-forget | `se050/mod.rs` |
| Dual-SE ordering guard | single-state flag only | `dual_se.rs` |

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

### Stage 1.5 — Diagnostic visibility (small, precedes Stage 2)

Two tiny additions that don't change behaviour but give us ground truth
before we start configuring things. Each is ~20-30 lines.

- **1.5a. RAMCFG register dump at boot.** New `hw/ramcfg.rs`: reads
  `RAMCFG_M1ISR..M4ISR` + `RAMCFG_M1CR..M4CR` + `RAMCFG_MxFEAR` once at
  boot, logs via `secure_log!`. Tells us: (a) whether any ECC events
  accumulated since last clear (single-bit corrections are silently
  happening every few minutes at sea level from cosmic rays — we should
  see them); (b) what the actual RAMCFG defaults are on this chip,
  replacing my earlier guesses. No side effects, pure diagnostic.
- **1.5b. VBAT presence canary.** Write a known magic value to
  `TAMP_BKPR31` at first boot; check it on every subsequent boot. If
  the magic survives, VBAT is live. If it's lost, VBAT is dead/absent
  and we should not depend on backup-register persistence in Stage 4.
  Log the result; don't gate on it yet (Stage 4 is where it matters).

Addresses: prerequisite for making informed choices in Stages 2 and 4.

### Stage 2 — PVD last-gasp + SRAM2 relocation + ECC reporting

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
  - **Initialisation gotcha**: ECC-protected SRAM must be fully written
    before being read, or the uninitialised ECC bits produce spurious
    double-bit errors on first access. During early boot, memset the
    relocation region before any other code touches it.
- **ECC double-bit NMI.** Enable `RAMCFG_MxIER.DEIE` on SRAM1, SRAM2,
  SRAM3 (all ECC-capable blocks). Implement `#[exception] fn
  NonMaskableInt()`: read `RAMCFG_MxISR` to identify which block
  faulted, log `RAMCFG_MxFEAR`, zeroize the secret region, trigger a
  soft reset via `SCB::AIRCR`. Stage 1d's dirty-reset path then cleans
  up on the resulting boot (classified as `ResetCause::Software`).
  - Optionally enable `SEIE` too, but route single-bit events to an
    incrementing counter in a backup register rather than an NMI —
    they're already corrected, and flooding an ISR with every
    cosmic-ray hit is noise.
- **Abort-on-PVD for flash writes.** If PVD is already asserted, reject
  flash writes immediately — never start a QW program under unstable
  Vcc.

Addresses: A (prevent), C (prevent), F (hardware guarantee),
uncorrectable ECC (prevent silent corruption).

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
  SRAM1 (lost on Vdd drop). Stage 1.5b adds a canary to detect this.
- **Do not enable ECC reporting without pre-initialising the region.**
  ECC-protected SRAM has hidden parity bits that reset to an
  indeterminate state on power-up. Reading uninitialised ECC memory
  after you've enabled `DEIE` will fire spurious NMIs from
  double-bit-error *detection* even though no real corruption occurred.
  Always memset the block before enabling reporting.
- **Do not assume "ECC is not enabled" means "no protection today".**
  On STM32U5 single-bit correction is a hardware property of the SRAM
  cell itself — cosmic-ray hits are already being corrected right now
  on SRAM1/2/3. What we're adding in Stage 2 is only the *reporting*
  path for the uncorrectable (double-bit) case.
- **Do not wire single-bit correction events to an NMI.** They
  accumulate constantly at sea level. Route them to an incrementing
  counter in a backup register for post-mortem diagnostics; the NMI
  handler should only fire on uncorrectable (double-bit) events.

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
6. **Uncorrectable SRAM corruption never returns silent garbage.**
   `RAMCFG_MxIER.DEIE` is enabled on all ECC-capable blocks; a
   double-bit detection fires an NMI that zeroizes + soft-resets
   rather than returning the corrupted bytes to the caller.
7. **Statistical confidence**: 1000-cycle cold-boot harness passes
   100%.

## Status

- Stage 1: **complete** (commit `b00527e`). Verified on hardware: reset
  classifier correctly reports `software` under `probe-rs run`
  SYSRESETREQ (`RCC_CSR=0x14004400`); admin-wipe e2e test still passes;
  all 7 feature combos build clean.
- Stage 1.5 (RAMCFG + VBAT diagnostics): **not started**
- Stage 2 (PVD + SRAM2 + ECC NMI): not started
- Stage 3 (flash CRC/magic/version): not started
- Stage 4 (backup-register state machine + IWDG): not started
- Stage 5 (A/B slots): not started
- Bench hardware (USB power switch, voltage sag tool): not acquired
- **Option-byte application on the dev board**: `make
  stm32-harden-opts` target exists but has NOT been run yet — chip is
  still at factory defaults for BOR and SRAM2_RST.

## File map (post-Stage 1)

| Concern | File |
|---|---|
| Reset-cause classification | `secure/src/reset_cause.rs` (new, top-level so QEMU can compile) |
| Verified flash writes | `secure/src/hw/flash.rs` (`write_quadword_verified`) |
| Boot-time dispatch | `secure/src/main.rs` |
| Option-byte setup | `Makefile` target `stm32-harden-opts` |
| This doc | `docs/brownout-hardening.md` |
