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

**Cross-references to the 2026-04-14 deep-research round** (see
`docs/production-security.md` for the full synthesis):

- Bundle A (fault injection) confirms: **BOR/IWDG/ECC/TAMP factory
  defaults are directly attackable**. Masaryk U 2024/2025 thesis
  (Simonik) demonstrated 76% PIN-glitch bypass on STM32U5A9 — same
  core family as our U585. Our Stage 2 plan is now a must-ship, not
  a nice-to-have.
- Bundle A also surfaces: **SLH-DSA verify-after-sign is insufficient**
  per RFC 9814 + Genêt TCHES 2023. A single fault during signing
  produces a signature that often still verifies. Double-compute on
  disjoint SRAM is mandatory. Tracked in work-todo.md #18, not in
  this doc (out of brownout scope).
- Bundle C surfaces: **we are currently signing with OptRand = 0**.
  That enables PRF(SK.seed) horizontal-DPA recovery in few traces.
  Fresh TRNG per signature required. Tracked in #18.
- Bundle D surfaces: **DWC2 has silicon errata** (TxFIFO write
  atomicity + ZLP race data-leak) that brownout-adjacent reset paths
  can trip into. Tracked in #19.

## Target board: B-U585I-IOT02A

This roadmap is written against the STMicro B-U585I-IOT02A Discovery
kit. Chip is **STM32U585AII6Q** (LQFP144, 2 MB flash, 786 KB SRAM in
four blocks, full peripheral set). Details that affect the plan:

| Feature | B-U585I-IOT02A state | Implication |
|---|---|---|
| **CR1220 battery holder (VBAT)** | **Present but unpopulated by default** on the dev board. Production hardware will use a **0.47 F–1 F supercapacitor** instead — see "VBAT power source" below. | Dev board needs either a CR1220 installed OR a supercap tack-soldered to the holder pads with a Schottky from Vdd. Stage 4 works either way. |
| NRST user button (B2) | Wired directly to MCU NRST pin | "One level more thorough than `probe-rs reset`" option for tests. Still does not cut SE050 Vcc. |
| LSE 32.768 kHz crystal | Present | Enables `LSE` for RTC and IWDG timing. LSI-clocked IWDG works fine without it — LSE is a "nice to have" for accurate timekeeping. |
| On-board ST-LINK V3 | Integrated | `probe-rs reset` uses SWD SYSRESETREQ. Does NOT interrupt USB Vbus → SE050 shield stays powered across reset. True cold cycle requires unplugging USB. |
| On-board STSAFE-A110 | Present, I2C2 bus | Currently unused by this firmware (only the `stsafe-probe` feature detects it). Not in scope for brownout work. |
| OM-SE050ARD-E shield | Arduino-header mounted | SE050 powered from shield's 5V pin which is fed by USB. Any full-power-cycle test must disconnect USB; any warm reset keeps SE050 alive. |

### STM32U585 SRAM layout & integrity

The four SRAM blocks have different integrity capabilities. Relevant to
every stage of this plan:

| Block | Size | Secure alias | ECC-capable | Parity | Notes |
|---|---|---|---|---|---|
| SRAM1 | 192 KB | `0x3000_0000` | Yes (single-bit correct, double-bit detect) | — | Main SRAM, currently hosts nearly all our state. |
| SRAM2 | 64 KB | `0x3003_0000` | Yes (option byte `SRAM2_ECC`) | Optional (mutually exclusive with ECC) | Target for Stage 2 secret relocation. Option byte `SRAM2_RST=0` makes silicon auto-erase this on every *system* reset (BOR, pin, SW, IWDG, WWDG, OBL — not standby wakeup). |
| SRAM3 | 512 KB | `0x3004_0000` | Yes (option byte `SRAM3_ECC`) | — | Unused today. Biggest block. |
| SRAM4 | 16 KB | `0x3800_0000` | No | Yes (unverified) | SmartRun domain; retained through Stop 2. |
| Backup SRAM | 2 KB | **`0x4003_6400`** (NS) / `0x5003_6400` (S) | Yes (option byte `BKPSRAM_ECC`) — **32-bit ECC** per AN5342 | — | VBAT-retained; auto-wiped on any TAMP event. |

### How SRAM ECC actually works on U5

**Correction from an earlier version of this doc:** ECC on SRAM2, SRAM3
and Backup SRAM is **NOT always-on.** It is configurable per-block via
the option bytes `SRAM2_ECC`, `SRAM3_ECC`, `BKPSRAM_ECC`. AN5342
describes this explicitly: ECC is "configurable for each SRAM block
individually" and "enabled or disabled by the control bits in the OB
space." Factory default is **disabled** on the user-configurable
blocks. The datasheet's line "786-Kbyte SRAM with ECC OFF or 722-Kbyte
SRAM including up to 322-Kbyte SRAM with ECC ON" quantifies the
tradeoff (each ECC-enabled block loses storage to parity bits).

**SRAM1 ECC** is part of the block's definition — cannot be disabled,
always active. Single-bit flips on SRAM1 are silently corrected today
regardless of firmware configuration. That's the only ECC we get for
free right now.

**Everything else** (SRAM2, SRAM3, Backup SRAM) requires an explicit
option-byte write during provisioning to even activate ECC — and then a
runtime config via RAMCFG to route uncorrectable errors somewhere useful:

- `RAMCFG_MxCR.ECCIE` — enable ECC-error interrupt signalling for the block.
- `RAMCFG_MxIER.ECCSEIE` — route single-bit corrections to an
  interrupt. Usually left disabled (already corrected; flooding an ISR
  with every cosmic-ray hit is noise). Stage 2 wires a counter into a
  backup register instead.
- `RAMCFG_MxIER.ECCDEIE` — route double-bit detections to an interrupt.
- `RAMCFG_MxIER.ECCNMI` — promote the double-bit event to an NMI
  instead of a maskable interrupt. **This is the bit we want for
  brownout defense** — a double-bit hit on a secret region must not be
  blockable by a misconfigured NVIC priority.
- `RAMCFG_MxISR` — status register (which errors fired since last
  clear). **Errata ES0499 §2.2.23**: these flags are only updated when
  the corresponding interrupts are enabled. Polling-based ECC monitoring
  without interrupt enable silently misses errors. Stage 2 must enable
  the interrupt (even if we don't take action) to get accurate status.
- `RAMCFG_MxFEAR` — failure address register, pinpoints the flipped
  location of the most recent uncorrectable error.

Current firmware state: **no ECC is enabled anywhere we control.**
SRAM1 has always-on correction (silicon default); everywhere else is
running without ECC until Stage 2 sets the option bytes and configures
RAMCFG.

Stage 2 will:
1. Set `SRAM2_ECC = 1` + `SRAM3_ECC = 1` via option bytes (extending
   the `stm32-harden-opts` target).
2. On first boot after option-byte change, zero SRAM2 + SRAM3 before
   any read (ECC bits for uninitialised memory are indeterminate and
   fire spurious double-bit errors otherwise — AN5342 §4.1.1).
3. Enable `ECCIE + ECCDEIE + ECCNMI` on each ECC-capable block.
4. Implement `#[exception] fn NonMaskableInt()` to zeroize + soft-reset
   on any double-bit event, reading `RAMCFG_MxISR` + `RAMCFG_MxFEAR` to
   log which block + address faulted.

## What STM32U585 gives us for free

STMicroelectronics anticipated brownout robustness. The U5 silicon has
extensive supervisor and integrity hardware that we leave at chip
defaults today:

### Power supervision
- **BOR (Brown-Out Reset)**: 5 levels via option byte `BOR_LEV[2:0]` in
  `FLASH_OPTR`. Trips clean reset when Vdd drops below threshold. Levels
  BOR0 (~1.7 V) through BOR4 (~**2.8 V**).
  - *Clarification*: flash program/erase operations work down to
    V<sub>DD</sub> = 1.71 V per the U5 datasheet; BOR3 is not a hard
    "minimum for flash writes" requirement, it's a best-practice
    threshold that buys margin against wait-state misconfiguration
    during brownout. For a wallet that performs rare flash writes during
    PIN-lockout wipe, BOR3 or BOR4 is appropriate.
- **PVD (Programmable Voltage Detector)**: configurable threshold via
  **`PVDLS[2:0]`** (the U5 spelling; L4-era docs call it `PLS`) in
  `PWR_SVMCR`. Enable with `PVDE` in the same register. Fires EXTI
  line 16 on threshold crossing — usable as "last-gasp" warning before
  BOR.
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
- **ECC on flash**: **9 parity bits per 128-bit quad-word** (total flash
  word = 137 bits). A torn QW write triggers an ECC double-error on the
  entire 128-bit word, not on individual 64-bit halves. Flagged via
  `FLASH_ECCR.ECCD`.
- **Page erase timing**: **typical 1.5 ms** (10k endurance cycles),
  rising to ~1.7 ms at 100k. The datasheet max (3-4 ms) applies at
  worst-case temperature + end-of-life. Use typical for PVD-to-BOR
  energy budgeting; use max for hard-deadline safety analysis.
- **WRP** (write protect) and **HDP** (hide protection): lock our
  reserved pages against accidental corruption.

### Tamper subsystem (TAMP)
- **Internal tampers**: clock monitoring, temperature monitor, voltage
  monitor. Any of these can auto-wipe backup regs + backup SRAM +
  crypto peripheral state in hardware. Exact wipe latency isn't spelled
  out in ST docs; safe to assume "fast enough relative to physical
  attack timescales" but do not rely on a specific µs figure.
- **External tamper pins** with edge/level detection and filtering.

### VBAT power source: supercap, not battery

Production hardware-wallet design choice: the backup-domain power
source is a **supercapacitor**, not a coin cell. Rationale:

- **No battery chemistry in the enclosure.** No leakage, no swelling,
  no age-out, no user-replacement lifecycle, no shipping-restrictions
  associated with lithium cells.
- **Sealed-for-life BOM.** 20+ year capacitor lifetime vs ~10 year
  battery shelf life.
- **Lower assembly cost** than holder + retention + cell.
- **Trade-off**: tamper-monitoring retention after unplug is bounded
  (hours to ~1 day), not indefinite. Acceptable given our dual-SE XOR
  split + EAL6+ decap-out-of-scope threat model.

Reference design:

```
Vdd (3V3) ─[Schottky BAT54]──┬── VBAT pin
                             │
                             ├── [C 0.47 F, 3.3 V supercap]
                             │
                            GND
```

- **Supercap**: 0.47 F / 3.3 V radial (Panasonic EECS-GW0H474H or
  equivalent), ~6.8 mm × 2 mm. Self-leakage 5-10 µA.
- **Schottky BAT54** (or similar): prevents supercap back-feeding Vdd
  during unplug.
- **Optional 10-47 Ω series R** between Vdd and the Schottky anode:
  limits inrush current on first plug-in from empty. Skippable if the
  main Vdd regulator handles the brief surge gracefully.

Expected runtime math at U5 backup-domain load (~2-3 µA backup
peripherals + ~5-10 µA supercap leakage = ~10 µA total, usable
voltage swing 3 V → 1.65 V):

| Supercap | Usable energy | Runtime |
|---|---|---|
| 0.47 F | ~700 mJ | ~12 hours |
| 1 F | ~1.4 J | ~24 hours |
| 5 F (Li-ion capacitor) | ~7 J | ~5 days |

Firmware implications — minimal:

- The Stage 1.5b VBAT canary pattern works unchanged. "Canary missing
  AND device was off for longer than supercap retention" simply means
  "supercap drained between sessions" rather than "battery dead." The
  firmware response is identical: note it in diagnostics, fall back to
  flash-based state, continue.
- **Cold-boot charge-up**: first plug-in from a fully-drained supercap
  charges with τ = R_series × C. With R_series = 47 Ω and C = 0.47 F,
  τ ≈ 22 s; VBAT reaches ~2 V (usable) in ~3τ = ~1 minute. Stage 4
  should gate backup-register writes on a PVM-monitored VBAT threshold,
  or simply wait 60 s after cold boot before writing.

Dev-board addition path (for validation work today, before a custom
PCB exists): tack-solder a 0.47 F supercap across the CR1220 holder
pads (+ and − terminals map to VBAT and GND). If the dev board ties
VBAT to Vdd via a solder bridge (SB), open it and replace with a
Schottky in the same footprint for proper isolation; otherwise the
cap will also drain the Vdd rail on unplug and runtime falls well
short of spec. See the B-U585I-IOT02A schematic for the specific SB
designator.

### STM32U585 security-relevant errata (ES0499)

Material bugs worth knowing before we write code against any of the
above features:

- **§2.2.7 / §2.2.8 — incorrect backup-domain reset.** When VBAT and
  VDD share a source, after power-on the backup domain registers can
  hold unpredictable values, potentially causing spurious tamper events
  that block SRAM2 and PKA access. Workaround: enable backup-domain
  monitoring (`MONEN=1`) or ensure VDD drops below ~100 mV for >200 ms
  before re-powering. Impacts Stage 4 reliability if we rely on
  backup-register state after arbitrary reset sequences.
- **§2.2.10 — system reset during Stop 2 with SRAM power-down can
  permanently lock the device.** Fixed in die revision cut 3.3 (Rev U);
  verify the chip rev on our dev board before using Stop 2. Not a
  concern yet because we don't enter Stop 2.
- **§2.2.23 — SRAM ECC error flags only update when interrupts are
  enabled.** Polling `RAMCFG_MxISR` without enabling `ECCIE` silently
  misses events. Stage 2 must enable ECCIE even if the ISR is a no-op,
  purely to keep the status register accurate.
- **IWDG EWI in Stop modes is broken** on U585. Not fixed. Only Run /
  Sleep modes fire the Early-Wakeup Interrupt. Impacts any future
  low-power design that relies on IWDG EWI as the wake-up path.

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
  - *Stage 2 will extend this target* with `SRAM2_ECC=1`,
    `SRAM3_ECC=1`, `BKPSRAM_ECC=1`, `IWDG_SW=0` (hardware watchdog),
    `IWDG_STOP=0`, `IWDG_STDBY=0`. None of these are at the right
    default — see production-security.md for the full set.
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

- **PVD interrupt.** Enable `PVDE` with `PVDLS` ~200 mV above `BOR_LEV`.
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
- **ECC enablement + double-bit NMI.**
  1. Extend `stm32-harden-opts` Makefile target to set `SRAM2_ECC = 1`,
     `SRAM3_ECC = 1`, and `BKPSRAM_ECC = 1` option bytes. Without
     these, ECC is *not running* on those blocks (correction from an
     earlier version of this doc).
  2. On first boot after the option bytes change, zero every byte of
     SRAM2 / SRAM3 / Backup SRAM before any read — uninitialised ECC
     bits produce spurious double-bit errors per AN5342.
  3. Enable `ECCIE + ECCDEIE + ECCNMI` in `RAMCFG_MxIER` for each
     ECC-enabled block. `ECCNMI=1` promotes the double-bit event to a
     non-maskable interrupt (vs. a regular maskable one).
  4. Implement `#[exception] fn NonMaskableInt()`: read
     `RAMCFG_MxISR` to identify which block faulted, log
     `RAMCFG_MxFEAR`, zeroize the secret region, trigger a soft reset
     via `SCB::AIRCR`. Stage 1d's dirty-reset path then cleans up on
     the resulting boot (classified as `ResetCause::Software`).
  - Route single-bit events to an incrementing counter in a backup
    register, not an NMI — they're already corrected and flooding an
    ISR with every cosmic-ray hit is noise.
  - Per ES0499 §2.2.23, `ECCIE` must be enabled for the status flags
    to update at all. Always enable it even if the ISR is a no-op.
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
- **Do not choose BOR below BOR3 (~2.7 V) for this wallet.** Flash
  actually works down to V<sub>DD</sub> = 1.71 V, so "below BOR3 = torn
  writes" is not an ST spec — it's a design choice. BOR3 gives margin
  against wait-state misconfiguration at low V<sub>DD</sub> and keeps
  us comfortably above flash spec minimums. Lowering it saves nothing
  meaningful for a wallet on USB power.
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
- **Do not use backup-register state without VBAT power.** On the
  B-U585I-IOT02A dev board the CR1220 holder is unpopulated by
  default; production hardware uses a supercap instead of a battery
  (see "VBAT power source" above). Either way, firmware must verify
  via the Stage 1.5b canary that VBAT is live before trusting backup-
  register state. If the canary is missing, Stage 4 falls back to
  flash-based state.
- **Do not assume VBAT is unbounded on production hardware.** With
  the supercap design, backup-domain retention after unplug is ~12-24
  hours, not years. Tamper-auto-erase during long cold-storage periods
  is NOT in our threat model — the 24-word backup is the long-term
  security anchor, not on-device state.
- **Do not enable ECC reporting without pre-initialising the region.**
  ECC-protected SRAM has hidden parity bits that reset to an
  indeterminate state on power-up. Reading uninitialised ECC memory
  after you've enabled `DEIE` will fire spurious NMIs from
  double-bit-error *detection* even though no real corruption occurred.
  Always memset the block before enabling reporting.
- **Do not assume "single-bit ECC correction" is active on SRAM2,
  SRAM3, or Backup SRAM until option bytes `SRAM2_ECC` / `SRAM3_ECC` /
  `BKPSRAM_ECC` are set.** Only SRAM1 has always-on ECC as a silicon
  property. Every other block runs with ECC *off* at factory default.
  This correction replaces earlier guidance in this doc.
- **Do not wire single-bit correction events to an NMI.** They
  accumulate constantly at sea level. Route them to an incrementing
  counter in a backup register for post-mortem diagnostics; the NMI
  handler should only fire on uncorrectable (double-bit) events — and
  only via the `ECCNMI` bit in `RAMCFG_MxIER`, not by promoting a
  regular interrupt.
- **Do not rely on `RAMCFG_MxISR` status without enabling the matching
  ECC interrupt.** ES0499 §2.2.23: the status flags only update when
  the corresponding interrupt is enabled. Pure polling silently misses
  errors.
- **Do not assume the B-U585I-IOT02A ships with a battery.** The board
  has a CR1220 holder that is *unpopulated by default*. Stage 4's
  backup-register state machine requires a populated cell or it
  collapses to "equivalent to SRAM1" (lost on Vdd drop). Stage 1.5
  adds a canary to detect this at runtime.

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
