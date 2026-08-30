# EVT silicon-validation checklist — everything that must be proven on real hardware

**Created 2026-07-24. Snapshot as of that date.** Compiled ahead of the first custom
**PQSigner EVT** PCBs (STM32U585 + OPTIGA Trust M V3 + SE050C2 + NV3007 LCD + 2 buttons).

## What this document is

Until now, everything in this firmware was validated on the ST **B-U585I-IOT02A**
dev kit (jumper-wired Arduino headers + OM-SE050ARD shield) or on **QEMU
mps2-an505**. Neither proves the firmware works on our own board, and a large
class of claims — the entire silicon-lockdown ceremony, per-die key derivation,
fault-injection resistance — has *never* been exercised on any hardware at all.

This is the **single index** of every such item: every assumption baked into the
code that was measured on the dev kit and could differ on our PCB, and every
security property whose proof is an unrun on-silicon test. It exists so that when
boards arrive we work from one list instead of re-deriving it from scattered docs.

**This file is an index, not the authority.** Each item points at the doc /
`file:line` / GitHub issue that owns it. Where a procedure exists, follow that
source. The load-bearing references here were produced by an automated sweep on
2026-07-24 — **spot-check a `file:line` before you act on it**, because the tree
moves.

### How to read the tables

- **Destructive?** — **DESTRUCTIVE** = irreversible on that die/part (RDP burn,
  OTP fuse, WRP/option-byte lock, OPTIGA/SE050 lifecycle ratchet, PUT KEY commit).
  Do these **only on sacrificial parts first**, never on a unit you want back.
  **NON-DEST** = read-only or reversible bench measurement, safe on any board.
  **MIXED** = a non-destructive measurement gates a later destructive burn.
- **Ref** — the owning doc / code site / GitHub issue (`#NNN` = `EthereumPhone/PQ1`).

### Do these in order

1. **§1–§2 first (all NON-DEST).** Board bring-up and pin/clock/bus verification.
   Nothing below is trustworthy until the board runs firmware at the right clock
   with the right pins. These need only an ST-LINK V3 + logic analyzer + UART.
2. **§3–§10 (mostly DESTRUCTIVE) only on sacrificial parts,** and only after §1–§2
   pass. The irreversible ceremony and the FI campaigns consume silicon.
3. **Keep ≥1 EVT unit pristine** (never RDP-locked, never OTP-burned) for
   regression debugging.

### Prerequisites already on the bench / to buy

- **Probe:** ST-LINK V3 (`probe-rs` compatible). **UART:** the EVT exposes a
  PA9/PA10 header — **the dev kit's on-board ST-LINK VCP does not exist on our
  board** (§2, `uart.rs:1-9`), so the RDP≥1 debug channel *is* that header.
- **Logic analyzer** for the I2C1 (PB8/PB9) + LCD SPI pads.
- **FI/SCA rigs already on the bench:** Ledger Donjon Scaffold (Vdd crowbar),
  Electronic Cats FaultyCat (EMFI), Rigol MHO934. **Absent, needed for on-silicon
  power/EM SCA:** ChipWhisperer-Husky / ChipSHOUTER (`docs/tooling-and-systems.md:71,95`).
- **Sacrificial-part budget** (from `docs/provisioning/first-boot-hardware-bringup.md:47-49`,
  `docs/security/red-teaming.md:52-53`): ≥5 STM32U585, ≥5 SE050C2 (OEF A201),
  ≥1 TRUSTMV3SHIELDTOBO1, plus ≥3 units beyond the one RDP-2 "production-config" unit.

### The one-line honest status

From `docs/audits/external-invariants-20-response-20260704.md`: **nothing has
shipped; the code is done, the silicon lockdown ceremony is not.** 16 of 20
external invariants pass from source review; the 4 that fail (HDP, RDP2/WRP/OEM2,
BOOT_LOCK, BOR) are all the unburned option-byte layer below. The single artifact
that would close most of §3 is *a verified option-byte / OTP readback attestation
from a fully-provisioned, RDP2-locked production unit* — which requires doing this.

---

## Sacrificial-unit plan — validate everything while destroying only 2 boards

**Goal (owner decision 2026-07-24):** spend at most **2 EVT PCBs** as sacrificial
units. Every other board stays a reusable **RDP-0** development board forever.

**The core move:** separate *chip-silicon destruction* from *on-board ceremony
proof*. The tests that physically kill a chip — Vdd crowbars, EMFI glitch
campaigns, many-shot atomicity — are about **silicon behavior, not our PCB**, so
they run on **loose parts and dev kits and consume zero EVT boards.** The 2
sacrificial EVT boards are spent only on what genuinely needs the real integrated
board: the irreversible lockdown ceremony, end to end.

### Three board tiers

1. **Dev fleet (every board except 2) — RDP-0 forever, infinitely reusable.** Runs
   the dev feature set (`dev-testkey`/`mock-se`, hardcoded master,
   `make wipe-for-wizard` to re-provision). SWD stays live → always reflashable.
   Carries all daily firmware development **and** every non-destructive validation
   item below.
2. **Loose parts / dev kit (0 EVT boards) — the destruction sink.** ≥5 loose
   STM32U585 (incl. the B-U585I dev kits), ≥5 loose SE050C2/A201, ≥1 OPTIGA
   TRUSTMV3SHIELDTOBO1 shield, + Scaffold/FaultyCat rigs. Absorbs every
   crowbar / glitch / atomicity / torn-write test.
3. **S1 + S2 (exactly 2 EVT boards) — the golden ceremony proof.** Chosen **late**,
   as the two best-behaving fleet boards after bring-up. Each runs the full
   production first-boot self-lock **once** → two independent RDP-2-locked,
   fully-provisioned units.

### Why 2 and not 1

- **DHUK uniqueness at RDP-2 (§10.7) needs n ≥ 2 locked boards** to compare per-die
  fingerprints — one locked board cannot demonstrate uniqueness.
- **A repeatable receipt beats a one-off:** two independent units both reading back
  the correct option-byte/OTP profile is materially stronger evidence for the
  invariant, and gives a clean confirmation run after any fix the first run surfaces.
- **One terminal lock, no retry:** RDP-2 is forever. If the first real on-board run
  reveals an integration surprise, S2 is the held-in-reserve confirmation.

### Phase sequence (with gates)

**Phase 0 — Prep (no EVT boards).** Obtain the loose parts. Build the
bench-ship-validation image (§7.1). Fix the OPTIGA shield handshake (§5.5) on the
dev kit. Discover the option-byte register offsets by non-dest readback +
destructive rehearsal on a loose U585. Run the ship-blocker crowbars — SE050
PUT-KEY atomicity (§6.3) and OTP torn-burn (§4.2) — on loose parts so those
verdicts exist *before* any EVT board is at risk.
*Gate: ceremony offsets/ordering/timings known; crowbar verdicts in hand; firmware frozen.*

**Phase 1 — Fleet bring-up (all EVT boards, RDP-0, non-dest).** §1 pin-map, §2
clock/bus/timing, §4.4 flash-page health, §6.1 SE050C2 fingerprint capture,
§5.5/§5.6 OPTIGA handshake + sign, §3.9/§3.11 readbacks, §10 non-dest platform checks.
*Gate: every board is a known-good RDP-0 dev board. Daily dev proceeds on all of them indefinitely.*

**Phase 2 — Rehearse + select (loose parts + dev kit).** Full dry-run on loose
STM32 + SE050C2 + OPTIGA shield: power-cut/torn-write durability matrices
(§7.3, §4.2), OPTIGA lifecycle ratchet + brick-recovery (§5), SE rotation
(§6.2/§6.6), RDP-2 downgrade campaign (§9.6). Designate the 2 best-behaving fleet
boards as S1/S2.
*Gate: the on-board run will be **confirmation, not discovery**. Do not proceed until a loose-part run completes the whole ceremony cleanly.*

**Phase 3 — S1 (first sacrificial).** RDP-1 DHUK capture over VCP (§7.4) → full
first-boot self-lock (§7) → RDP-2. Read back the option-byte/OTP profile; run the
SWD-must-fail probe (§3.10); confirm OPTIGA/SE in-situ lockdown (§5, §6.2/§6.6).
*Gate: if ANY integration bug appears, STOP — fix firmware, return to Phase 2 on loose parts. Do NOT burn S2 to debug.*

**Phase 4 — S2 (second sacrificial).** Repeat the clean ceremony. Compare S1↔S2
DHUK fingerprints → close §10.7 (n = 2 at RDP-2). Two independent readback receipts
→ discharge the option-byte/OTP invariant.
*Gate: two locked units, two matching-profile receipts, distinct DHUKs.*

**Standing rule:** the remaining boards never leave RDP-0. If S1 *and* S2 both
surface distinct on-board bugs, that means Phase-2 rehearsal was insufficient — do
**not** reflexively promote a third board; reproduce and fix on loose parts first.

### Hard dependency (the plan fails without it)

This plan holds **only if loose SE050C2/A201 samples and OPTIGA shields are
obtainable.** The ship-blocker crowbars (§6.3 PUT-KEY atomicity, §6.8 admin-delete,
§4.2 OTP torn-burn) destroy the chip and need many parts for statistical
confidence; they cannot fit inside 2 boards. If loose production-part SEs cannot be
sourced, those ship-blockers have nowhere to run except EVT boards and the
sacrificial count rises well past 2. **Resolve loose-part sourcing before committing
to the 2-board budget.**

### Item routing — which tier closes each section

| Tier | Closes |
|---|---|
| **Dev fleet (RDP-0, reusable)** | §1, §2, §3.9, §3.11, §4.4, §5.5, §5.6, §6.1, §6.7, §6.10–6.13, §8 (non-dest bench), §9.1–9.5, §10.1, §10.3, §10.6 |
| **Loose parts / dev kit (0 EVT)** | §4.2, §5 ratchet-rehearsal + brick-recovery, §6.2/§6.6 rehearsal, §6.3, §6.5, §6.8, §7.3 durability, §9.6, §11 research |
| **S1 + S2 (2 sacrificial EVT)** | §3.1–3.8, §3.10, §3.12, §4.1, §5 in-situ, §6.2/§6.6 in-situ, §7 full ceremony ×2, §10.7 |

---

## §1 — Board bring-up: pin map cross-check (NON-DEST, do first)

The drivers hardcode **bit positions**, not pin abstractions. If the EVT moves any
signal to a different GPIO bank/pin, that driver's MODER/OTYPER/OSPEEDR/PUPDR/AFR
math is wrong. **Cross-check every row against the EVT schematic before flashing
anything.** Several of these pins were chosen empirically on the dev board (LA
capture), not from a schematic, and are flagged.

| Signal | Firmware pin | Ref | EVT note |
|---|---|---|---|
| LEFT button | PC1 (Arduino D8) | `secure/src/hw/buttons.rs:81,159` | dev-kit jumper wire |
| RIGHT button | PA8 (Arduino D9) | `buttons.rs:82,165` | shares GPIOA with SWD PA13/PA14 |
| USER button (test) | PC13 | `buttons.rs:168` | **on-board only — will not exist on EVT** |
| Consumption-mask PWM | PA5, TIM2_CH1 AF1 | `secure/src/hw/consumption_mask.rs:19,268` | must sit near/across the die supply to matter (§9) |
| Debug UART TX | PA9, USART1 AF7 | `secure/src/hw/uart.rs:113` | **needs an EVT header — no on-board VCP** |
| Debug UART RX | PA10, USART1 AF7 | — | EVT spec pin |
| I2C1 SCL (both SEs) | PB8 AF4 | `secure/src/hw/i2c_hw.rs:12,105` | 400 kHz, **external pull-ups assumed** (§2) |
| I2C1 SDA (both SEs) | PB9 AF4 | `i2c_hw.rs:13` | OPTIGA @0x30 + SE050 @0x48 share this bus |
| I2C2 SCL/SDA (STSAFE probe) | PH4/PH5 AF4 | `secure/src/hw/i2c2_probe.rs:26` | probes on-board STSAFE-A110 @0x20 — **not on EVT** |
| LCD SPI (`ui-lcd`/`spi1-arduino`) | PE12 CS / PE13 SCK / PE14 MISO / PE15 MOSI, SPI1 AF5 | `secure/src/hw/spi_hw.rs:14,36` | shipping display path |
| LCD SPI (default/non-arduino) | PB12–15, SPI2 AF5 | `spi_hw.rs:5,34` | bench builds only |
| LCD DC | PE7 (Arduino D4) | `secure/src/hw/lcd_nv3007.rs:102` | retargeted 2026-06-08 off unreachable PE3/PE1 |
| LCD RES | PE14 | `lcd_nv3007.rs:107,711` | **tied to 3V3 on dev board → SWRESET used, pin never drives** |
| USB D-/D+ | PA11/PA12 OTG_FS AF10 | `secure/src/hw/usb_hw.rs:95` | direct to connector |
| USB CC1/CC2 | PA15/PB15 UCPD1 | `usb_hw.rs:98,384` | through TCPP03 (see below) |
| TCPP03 port-protect EN | PB5 (drive HIGH before USB) | `usb_hw.rs:100,189` | **on-board TCPP03-M20 (U8) — may not exist on EVT** |
| **OPTIGA RST** | **PE0 ("D6")** | `secure/src/optiga/reset_pin.rs:51,14-21` | **empirical, contradicts UM2839, silkscreen off-by-one — almost certainly wrong on EVT** |
| SE050 ENA | Arduino D5 = PE4 (implicit) | `reset_pin.rs:14-21` | why OPTIGA RST was moved off PE4 |

**Highest-risk rows (verify against schematic first):** OPTIGA RST / SE050 ENA
nets (empirical, board-specific — the PE0 choice is almost certainly wrong on the
EVT); the two button pins; TCPP03 PB5. `reset_pin.rs:29-104` also documents a
silicon-write-ordering quirk (a bare BSRR store produced no edge; full
MODER→…→BSRR + 50 ms settle was required) — re-check on EVT silicon.

### UPDATE 2026-08-30 — the cross-check above is DONE

The first PQ1 board (`AL_A66_MB_V10`, MCU marked `STM32U585CU6TR`) is on the
bench. The "cross-check every row against the EVT schematic" instruction has now
been carried out against three sources, in this precedence order:

1. **`STM32U585CIU6TR Pin Functions.xls`** (vendor pin table, carries the AF
   numbers) — authoritative for what the board *uses*.
2. **`AL_A66_MB_V10_20260826_1500.pdf`** sheets 1–2 — net names, I2C addresses,
   power topology.
3. **ST `DS13086` Rev 10** Tables 28/29 and the `STM32U585.svd` shipped with
   STM32CubeProgrammer — authoritative for what the *silicon* supports.

The resolved map now lives in code, one file per board, at
`secure/src/board/{iota2,pq1}.rs`, so the table below is orientation and those
files are the authority. **The package bonds only PA0–15, PB0–15 and PC13** — no
port D/E/F/G/H/I, and PB11 is not bonded either.

| Signal | `iota2` (this table above) | **pq1 (as built)** |
|---|---|---|
| LEFT / UP button | PC1 | **PA0** |
| RIGHT / DOWN button | PA8 | **PA1** |
| USER button | PC13 | **does not exist — only two buttons** |
| Debug UART TX / RX | PA9 / PA10 (USART1 AF7) | **PA2 / PA3, header `J211` pins 1–2** |
| I2C1 SCL / SDA (OPTIGA @0x30) | PB8 / PB9 AF4 | **unchanged — PB8 / PB9 AF4** |
| SE050 @0x48 | shares I2C1 | **own bus: I2C4, PB6 / PB7, AF5** |
| LCD SPI | PE12/13/14/15 SPI1 AF5 | **PA4 CS / PA5 SCK / PA7 MOSI, SPI1 AF5; no MISO** |
| LCD DC / RES | PE7 / PE14 (RES tied to 3V3) | **PB0 / PB1 — RES is genuinely driven here** |
| LCD TE | not wired | **PB2** |
| LCD backlight | unconditional | **`LCM_EN` = PB15 + AW99703 driver @0x36 on I2C2 (PB13/PB14)** |
| OPTIGA RST | PE0 (empirical, flagged above) | **PA15 (`SE_RST`) — from the schematic, not empirical** |
| SE050 ENA | PE4 (implicit) | **PB5 (`SE1_EN`)** |
| SE supply | always on | **`LDO2_EN` = PA8 gates `VDD1_3V3` for BOTH SEs** |
| USB D-/D+ | PA11 / PA12 AF10 | **unchanged** |
| USB CC1/CC2 + TCPP03 EN | PA15 / PB15 / PB5 | **no TCPP03; an AW35602 with `FLAGB` on PB10** |
| SCA trigger | PD2 | **PD2 does not exist — PB3/SWO is the repoint** |
| STSAFE probe I2C2 | PH4 / PH5 | **port H does not exist; I2C2 here is PB13/PB14, carrying the LED drivers** |
| RGB LED enable | — | **PB12** (the schematic's apparent PB11 is not bonded) |

Three findings worth carrying forward:

- **The `OPTIGA RST` row's warning was right.** PE0 was indeed wrong for this
  board; the net is `SE_RST` on PA15. It came from the schematic this time, not
  from an LA capture, so the "empirical, contradicts UM2839" caveat retires.
- **`PA8` is the sharpest collision in the port, and it is silent in both
  directions.** On `iota2` it is the RIGHT button; on pq1 it is `LDO2_EN`, the
  enable for the rail powering both secure elements. The dev-board driver holds
  it as a *pulled-up input*, which on pq1 leaves both SEs unpowered — and the
  symptom is an I2C NACK, which reads as a bus bug rather than a power bug.
- **The console UART's peripheral was ambiguous and is now settled.** The
  schematic names the PA2/PA3 nets `LPUART1_*`; the pin table marks them AF7.
  Both describe real silicon: DS13086 Table 28 gives `AF7 = USART2_TX/RX` on
  those pads and Table 29 gives `AF8 = LPUART1_TX/RX`. The firmware takes
  **USART2/AF7** — an ordinary USART (`BRR = f_ck/baud`, APB1) rather than
  LPUART1's `256*f_ck/baud` on APB3, and in **GTZC1** with everything else
  `sau.rs` configures, where LPUART1 sits in GTZC2 which the firmware never
  touches.

**Not yet cross-checked:** the AW99703 backlight and AW21036 RGB drivers have no
firmware at all, so `LCM_EN` alone may not light the panel; and nothing reads
`FLAGB`.

### UPDATE 2026-08-30 (later) — secure-element path ported to pq1

The SE half of the pin table above is now implemented, not just recorded. What
landed:

| Piece | Change |
|---|---|
| OPTIGA bus | unchanged — I2C1, PB8/PB9, AF4 |
| SE050 bus | `hw::i2c_hw` now brings up a *set* of buses (`board::SE_I2C_BUSES`), so pq1 adds **I2C4 on PB6/PB7, AF5** alongside I2C1 |
| Driver bases | `se050::i2c` / `optiga::i2c` take their base from `board::{SE050,OPTIGA}_I2C_BASE` instead of a shared `i2c_hw::I2C1` |
| OPTIGA reset | `optiga::reset_pin` parameterised on `board::OPTIGA_RST` — PE0 on iota2, **PA15** on pq1 |
| SE power | new `hw::se_power`, asserting **`LDO2_EN` (PA8)** then **`SE1_EN` (PB5)** before any bus traffic; a no-op on iota2 |
| GTZC | `sau.rs` secures **I2C4 (SECCFGR1 bit 16)** on pq1, under four exact-equality `const assert!` arms (iwdg x board) |

Three things found while doing it, each of which would have cost real debugging
time later:

1. **`R130` decides it.** `U108`, the `NCP114AMX330TCG` producing `VDD1_3V3`, has
   a **10 kΩ pull-down (`R130`) on its `EN` node**. At reset PA8 is a high-Z
   analog input, so the LDO is held *off* and both secure elements are unpowered.
   This is not a "nice to set" line — without it there is nothing on either bus
   to answer.
2. **The dev-board button driver would undo it.** `ui::init()` runs *after* the
   SE power-up in `main.rs`, and it calls `hw::buttons::init()`, which claims PA8
   as a **pulled-up input**. The internal pull-up against `R130` lands well below
   the NCP114 enable threshold (~0.66 V taking the pull-up at its typical
   ~40 kΩ — computed, not measured; the margin is large either way), so on pq1
   the SEs would come up and then quietly power off again a few hundred
   microseconds later. That is
   now a `compile_error!` on `board-pq1` rather than a runtime trap. Note
   **`ui-lcd` implies `gpio-buttons`**, so it fences that path too.
3. **`usb` is worse and is likewise fenced.** `hw::usb_hw` puts PA15 (= pq1
   `SE_RST`) and PB15 (= pq1 `LCM_EN`) into ANALOG mode, drives PB5 (= pq1
   `SE1_EN`) high for a TCPP03 that this board does not have, and clears all
   three in `GPIOx_SECCFGR` — handing the non-secure world both SEs' reset and
   enable lines plus the trusted display's backlight (invariant #4). pq1 routes
   no CC lines to the MCU at all, so this must be compiled out rather than
   remapped: a reviewed port, not a pin-table edit.

**Initially left undriven — then refuted by measurement.** `SE_RST` was at first
deliberately not driven on the normal boot path, on the argument that this die's
`PA15_PUPEN` option bit (read off `FLASH_OPTR`) would leave PA15 idling high.
**That argument was wrong.** `hw::se_power::init` now samples `IDR` before
driving, and the first run read PA15 **low**: the OPTIGA was held in reset and
NACKed every probe, while the SE050 on the same rail ACKed immediately. It now
releases the reset explicitly and reports both the before- and after-level.

### UPDATE 2026-08-30 (later still) — BOTH secure elements answer on silicon

`make se-i2c-probe-hw BOARD=pq1` → **PASS**:

```
SePowerState { rail_en: Some(true), se050_en: Some(true),
               optiga_rst_before: Some(false), optiga_rst: Some(true) }
bus I2C1 (OPTIGA 0x30) base=0x50005400 SCL=PB8 SDA=PB9 AF want=4 got=(4,4) OK
  0x30 OPTIGA Trust M -> ACK (attempt 2/10)
bus I2C4 (SE050 0x48) base=0x50008400 SCL=PB6 SDA=PB7 AF want=5 got=(5,5) OK
  0x48 SE050 -> ACK (attempt 1/10)
```

What this closes, without a single data byte having reached either part:

- **`LDO2_EN` (PA8) works and `VDD1_3V3` is up.** Neither chip can ACK without
  it, so step 2's meter is now redundant — the probe proved the rail. (Both
  chips NACKing was the only case that needed the multimeter.)
- **`SE1_EN` (PB5) works**, and **SE050 really is on I2C4 at PB6/PB7 AF5** —
  base, pins and alternate function all confirmed by read-back *and* by a
  device answering.
- **OPTIGA is on I2C1 at PB8/PB9 AF4**, unchanged from iota2, and its reset is
  PA15.
- The two buses are independent: one answered while the other did not.

Nothing here exercises SCP03, the shielded connection, or any lifecycle state —
an address ACK is not a handshake.

### UPDATE 2026-08-30 — Tier 2: buttons ported (compile-verified only)

`hw::buttons` now takes its pins from `board::BTN_*`: iota2 keeps PC1/PA8 (+
PC13 as a bench reference), pq1 uses **PA0 / PA1**, both on GPIOA. The clock
enable is derived (`gpio_rcc_bit(LEFT_PORT) | gpio_rcc_bit(RIGHT_PORT)`), which
folds to GPIOAEN alone on pq1 and GPIOAEN|GPIOCEN on iota2 with no `cfg`. The
USER-button path is gated on `board::BTN_USER` being `Some`, so pq1 does not
configure a pin it has not fitted.

**The `compile_error!` fence is gone, replaced by something stronger.** The
fence kept pq1 out wholesale; a `const assert!` now checks the actual property
on *every* board — that neither button pin collides with the SE supply enable,
either SE reset/enable, the console TX, or SWDIO/SWCLK, and that LEFT != RIGHT.
That is the check which would have caught the original PA8 = `LDO2_EN` bug
instead of quarantining it, and it keeps working as boards are added.

**No UI design decision was needed, contrary to what this document and the
board maps previously said.** The trusted UI has always been two-button:
`ui::Button` has exactly two variants, `ui::Press` adds Short/Long, every
dialog matches all four arms with no wildcard (compile-time proof the event
space is exactly four), confirm is `(Right, Long)`, and
`hw::buttons::wait_combo_release` already implements the both-buttons chord.
The dev board's PC13 was never a UI input — configured, never sampled by
`wait_event`. Those claims have been retracted where they were written.

**NOT verified on hardware.** No buttons are fitted to the board — pads
`J203`/`J204` (LEFT) and `J205`/`J206` (RIGHT) are bare. Each pad pair is
signal + GND with a 100nF cap and an ESD diode and **no board pull-up**, so the
driver's internal pull-up plus active-low read is what makes a press
detectable; that is unchanged from iota2 and is the property the gates pin. To
check it when buttons exist (or with tweezers across a pad pair), build with
`gpio-buttons` and use the `button-test` scanner.

### UPDATE 2026-08-30 (later still) — step 4 CLOSED: the I2C4 SECCFGR receipt

`make gtzc-enforcement-hw BOARD=pq1` → **PASS, 8/8**, with the eighth probe
being the one that matters:

```
[NS][gtzc] target: STM32U585CIU6 AL_A66_MB_V10 (pq1)
[NS][gtzc] probe 8/8  addr=0x40008400 (I2C4_CR1)
[NS][gtzc]   read=0x00000000  tzic_count=8  irqs_for_probe=1
[NS][gtzc] tzic_status final = 8 (delta = 8, expected = 8)
```

**The first run of this target did NOT close the item, and looked like it did.**
`nonsecure/src/gtzc_test.rs` carried a fixed seven-entry probe table written for
iota2 — I2C1, I2C2, AES, HASH, RNG, PKA, SAES. I2C4 was simply not in it, so the
target reported `PASS — GTZC1 TZSC + TZIC enforcement confirmed` on pq1 while
never touching the bit whose whole risk is that it has no functional symptom.
The probe table is now board-conditional (pq1 = 8), which required giving the
non-secure crate the `board-*` axis it did not have; its banner also hardcoded
`B-U585I-IOT02A` regardless of target and now reports the real board.

**Control run — the receipt can fail.** Un-securing I2C4 (dropping the bit from
`SECCFGR1_BOARD_IMAGE` *and* relaxing the two pq1 `const assert!` arms that
guard it, since otherwise the build stops first):

```
[NS][gtzc] probe 8/8  addr=0x40008400 (I2C4_CR1)
[NS][gtzc]   read=0x00000000  tzic_count=7  irqs_for_probe=0
[NS][gtzc] tzic_status final = 7 (delta = 7, expected = 8)
[NS][gtzc] === FAIL n=7 expected=8 ===
```

Worth reading that carefully: **`read` is `0x00000000` in BOTH cases.** The RAZ
value is not the discriminator — I2C4_CR1 reads zero anyway when the peripheral
is idle. Only `irqs_for_probe` (1 → 0) distinguishes "NS was denied" from "NS
was allowed in". A future reader scraping this log for `read=0x0` as evidence of
denial would draw the wrong conclusion.

So invariant #3/#4 for the SE050's dedicated bus now has a silicon denial
receipt on the shipping board, which is what the `const assert!` message in
`sau.rs` demands. **Step 3 (scope/LA both buses during a real transaction)
remains the only open item from this list.**

**Still unverified on silicon — the port compiles and the gates hold, but no SE
has answered yet.** In order:

1. **`make se-i2c-probe-hw BOARD=pq1`** — the non-destructive address probe
   (`hw::se_i2c_probe`, feature `se-i2c-probe`, in `PROD_FORBIDDEN`). Every
   probe is a **zero-data-byte** transfer (`NBYTES=0` + `AUTOEND`, so the
   address phase is the whole transaction): no register pointer, no APDU, no
   T=1' frame, no lifecycle transition. It is deliberately safe to run on a
   virgin OPTIGA, which is why it comes first. It runs before anything else
   addresses the buses, reads back the GPIO AF nibbles, and retries with a
   bounded backoff reporting the attempt number.

   Read the result by pattern, not as a verdict:

   | Symptom | Most likely cause |
   |---|---|
   | both NACK | `VDD1_3V3` never rose — go to step 2 |
   | only `0x48` NACKs | `SE1_EN` (PB5), or probed before the SE050 booted |
   | only `0x30` NACKs | I2C1 pins/AF, or `SE_RST` |
   | ACK on a late attempt | part is fine; the settle time is short |
   | AF `MISMATCH` line | the pin config never landed — not a chip problem |

2. Meter **`VDD1_3V3`** — but only if step 1 comes back all-NACK. If both chips
   ACK, the rail is up by construction and the meter is redundant. The `ODR`
   read-back `se_power::init` returns proves the *latch*, not the rail: a dead
   LDO or an unmet enable threshold reads as success.
3. Scope/LA **PB8/PB9** and **PB6/PB7** for clock during an SE transaction, and
   confirm the two buses are genuinely independent.
4. `make gtzc-enforcement-hw` on pq1 silicon — the I2C4 SECCFGR bit is the one
   item here with **no functional symptom either way**, so only a denial receipt
   closes it. The `const assert!` message names this obligation deliberately.

**Do not extend the probe into a handshake.** `flash-hw-optiga-shield-handshake-only`
already exists for that and is *not* non-destructive on a virgin part. The whole
value of `se-i2c-probe` is that its contract stops at "address ACK, zero data
bytes"; the module header says so, and it should stay true.

---

## §2 — Clock, bus, and timing re-verification (NON-DEST, do first)

Every busy-wait, timeout, baud divisor, and I2C/SPI timing word in the firmware is
calibrated to **160 MHz SYSCLK**. If the EVT power design can't reach VOS1 the part
silently drops to 16 MHz and **all** of it is wrong at once.

| Item | Assumption | Ref | EVT risk |
|---|---|---|---|
| Clock tree | 160 MHz via PLL1, VOS1 + EPOD boost, 4 WS; **falls back to 16 MHz if VOS fails** | `secure/src/hw/rcc.rs:121-138` | LDO-vs-SMPS dependent; BOOSTRDY "may never set" on LDO-only. Drives everything below. **Verify SYSCLK on silicon before trusting any timing.** |
| I2C1 timing | `TIMING_400KHZ = 0x1090_378F` for 160 MHz PCLK1 + 3.3 kΩ external pull-ups | `secure/src/hw/i2c_hw.rs:80-119` | breaks if PCLK≠160 MHz, different pull-ups, or higher bus capacitance. No clock-stretch handling. |
| I2C `asm::delay` calibration | `delay(8000)` = 50 µs nominal but **~150 µs wall-clock (≈3× calibration)** | `secure/src/optiga/i2c.rs:26-47,300` | bench-measured constant; shifts with clock. OPTIGA GUARD_TIME + all IFX poll cadences ride on it (`ifx_i2c.rs:330`). |
| SE050 busy-waits | "wait N nop loops" for interface reset / WTX / read-retry | `secure/src/se050/t1oi2c.rs:137,307` | clock-calibrated; re-verify at EVT clock. |
| LCD SPI clock | **÷8 = 20 MHz cap** — set *because the dev board's LD2 LED on PE13=SCK* rounds 40 MHz edges | `secure/src/hw/spi_hw.rs:219-236` | comment says a board with no LED on SCK "could go back to ÷4 (40 MHz)" — **re-tune up on EVT.** |
| SysTick cadence | `TIMEOUT_TICKS`/`FORCED_FLOW_DEADLINE_MS` in ~1 ms ticks from `setup_systick()` | `secure/src/timeout.rs:26-56` | reload derived from SYSCLK; every wall-clock deadline drifts if clock differs. |
| UART BRR | `BRR=1389` for 115200 at PCLK2 160 MHz | `secure/src/hw/uart.rs:133` | recompute if PCLK2 differs. |
| HASH KAT | SHA-256("abc") self-test halts on mismatch; ALGO=bits17+18, pulse RSTR each hash | `secure/src/hw/hash.rs:122-162,258` | silicon-rev sensitive; runs automatically on every HW boot. |
| RNG | secure alias only, CONDRST bit 30, needs HSI48 | `secure/src/hw/rng.rs:8-94` | noisier EVT rail can raise SEIS/CEIS; recovery-once-then-panic path. |
| Bus decode | OPTIGA = Infineon nibble **CRC-16 KERMIT**, FCS **high-byte-first** (do NOT "fix"); SE050 = **CRC-16/CCITT** | `optiga/ifx_i2c.rs:126-153`; `se050/t1oi2c.rs:74-76` | protocol-not-board, but re-confirm if EVT carries a different SE silicon rev. |

**Bring-up smoke tests (NON-DEST):** `make test-key-speed` (DWT-timed sign, prints
`=== PASS ===`; substantially-slower-than-expected timings ⇒ HASH peripheral or
clock wrong), `make saes-self-test-hw`, `make lcd-test-hw` / `make splash-test-hw`,
`make flash-hw-optiga-shield-handshake-only`, `make pin-gate-hw-counter-e2e`.

### UPDATE 2026-08-30 — §2 partially closed on the first pq1 board

`make test-key-speed BOARD=pq1` **passes** on `AL_A66_MB_V10` s/n
`002F0023 30465002 2033314C` (die UID). What that closes and what it does not:

**Closed — the clock fallback risk this section leads with.** The table warns
that a board unable to reach VOS1 "silently drops to 16 MHz and **all** of it is
wrong at once". Read back over SWD from the running part:

| Register | Value | Meaning |
|---|---|---|
| `RCC_CFGR1` | `0x0000_000F` | `SW = SWS = 0b11` — SYSCLK is PLL1, not the HSI16 fallback |
| `RCC_CR` | `0x0300_3535` | `PLL1ON` + `PLL1RDY` + `HSI48ON` + `HSI48RDY` all set |
| `RCC_PLL1DIVR` | `0x0100_0013` | `N = 20`, `R = 2` → 16 MHz × 20 / 2 = **160 MHz** |
| `PWR_VOSR` | `0x0007_C000` | `VOS = 0b11` (Range 1), `VOSRDY`, `BOOSTRDY`, `BOOSTEN` |

So VOS1 + the EPOD booster do come up on this power design, and every busy-wait,
`TIMINGR`, BRR and SysTick reload calibrated to 160 MHz is on its assumed clock.
The "LDO-vs-SMPS dependent / BOOSTRDY may never set" risk is **not observed on
the first board (n = 1)**. That is one die, at room temperature, on bench power —
enough to unblock bring-up, not enough to call the row closed. Re-read these four
registers on each new board until there is a population behind the claim, and
note that `rcc.rs:132-138` fails *silently* to 16 MHz, so a board where the
booster does not come up will look like a slow board rather than a broken one.

**Also closed:** the clock tree needs neither crystal — `rcc.rs` runs HSI16 → PLL1
and HSI48 for the RNG, and touches HSE/LSE nowhere. pq1's 8 MHz HSE (vs the dev
kit's 16 MHz) therefore cannot matter. The HASH KAT row passes on this silicon
rev: `[S] hash: HW SHA-256 self-test PASS` appears on every boot.

**Open — signing is slower than this repo's own expectation, and the repo
disagrees with itself about what that expectation is.** Measured here, `hw-sha256`
on, 160 MHz confirmed:

| Measurement | pq1, measured | `CLAUDE.md` "expected" | `docs/archive/production-todo-retired-2026-07-19.md:1146` |
|---|---|---|---|
| first-sign | 14.7 s | ≤ 3 s | ~9.2 s |
| type2-only, cached slot (avg of 5) | 6.8 s | ≈ 1.1 s | ~4.0 s |

The two in-repo figures already differ by ~3.6× from each other, so at least one
predates a parameter or build change. **This is very unlikely to be a board
property:** the bench build is `mock-se` and touches no board peripheral in the
timed path, and a *cycle count* is fixed by code and data, not by wiring — the
gap is ~6× in cycles, not in wall-clock. `hw-sha256` is confirmed wired
(`sphincs-c10/src/hash.rs:105-150` routes `Sha256` to the `pqsigner_sha256_*`
externs, and the feature is on). The likely readings are that the HASH
peripheral's per-call MMIO overhead does not pay off for SPHINCS+'s many tiny
hashes, or that the documented numbers are stale.

**To close it:** run `make test-key-speed` on the B-U585I-IOT02A and compare
cycle counts directly. Until that A/B exists, do not attribute the difference to
this board, and treat the `CLAUDE.md` "first-sign ≤ 3 s" line as unverified.

**A `mode-production` pq1 image is currently unsatisfiable, by construction.**
`Makefile` `PROD_SHIP_FEATURES` requires both `consumption-mask` and `ui-lcd`.
The consumption mask is TIM2_CH1 on **PA5** (`hw/consumption_mask.rs:113`), and
PA5 on pq1 is **`SPI1_SCK`** — the LCD clock. The two cannot coexist on this
board without repointing the mask; PA6 is free and carries `AF2 = TIM3_CH1`
(DS13086 Table 28), which is the obvious landing spot. `make prod-feature-check`
passes today *because no board feature is in `PROD_REQUIRED` yet* — that is a
future gate, not a present pass, and it should only be added once the mask has
somewhere to live.

**Also observed, not yet explained:** `[S] rng::fill: seed/clock error —
recovering` fires roughly once per sign (`RNG_SR = 0x41`, `SEIS` set) and the
recovery-once path clears it every time. The §2 RNG row anticipates exactly this
("noisier EVT rail can raise SEIS/CEIS"). It is not the cause of the timing gap
— a `CONDRST` cycle is microseconds — but it should be characterised before the
rail is trusted, since the code's contract is recover-once-then-panic.

---

## §3 — STM32U585 option-byte lockdown ceremony (all DESTRUCTIVE)

The most-repeated cluster and the reason "nothing has shipped." Enforced at build
time by the `nsc/mod.rs` `compile_error!` fences, but **never burned on a die.**
Ordering rule everywhere: **WRP1A → DA/OEM key → RDP2 last.** Register offsets
marked "not silicon-pinned" fail closed today (`shared/src/lockdown.rs`) and must be
confirmed against RM0456 + a positive bench read before the constants are flipped.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 3.1 | **RDP Level 2 burn (`RDP=0xCC`)** — kills SWD/JTAG forever | DESTRUCTIVE | `external-invariants-20-response-20260704.md:37-48`; `main.rs:914-928`; issue **#34**; `tools/factory-provisioning-verify.sh:165` |
| 3.2 | **WRP1A on FSBL pages** — must precede RDP2; `WRP1A_MASK_PINNED=false` | DESTRUCTIVE | `shared/src/lockdown.rs:63-68,189`; issue **#35**; `first-boot-hardware-bringup.md:63` |
| 3.3 | **WRP2A on bank-2 FSBL pages** (both banks) | DESTRUCTIVE | issue **#35, #43** |
| 3.4 | **OEM2KEY / DA-key provisioning + OEM1/2LOCK bit-position pin** — default DA password must fail | MIXED (detection NON-DEST on sacrificial part; finalization DESTRUCTIVE) | `shared/src/lockdown.rs:98-120`; issues **#40, #34**; error `E080A` |
| 3.5 | **HDP1 (HDP1EN + HDP1_PEND) + mirror HDP2** over FSBL — configured nowhere today | DESTRUCTIVE | `external-invariants-20-response-20260704.md:29-35`; issues **#39, #43** |
| 3.6 | **BOOT_LOCK=1** (+ SWAP_BANK=0) — SECBOOTADD0 set but remap still NS-reachable | DESTRUCTIVE | `external-invariants-20-response-20260704.md:50-56`; issues **#38, #44** |
| 3.7 | **BOR_LEV ≥ 4 + SRAM2_RST=0 + armed PVD** — `make stm32-harden-opts` only sets BOR_LEV=3; brownout currently bypasses the SRAM wipe | DESTRUCTIVE | `external-invariants-20-response-20260704.md:205-213`; `shared/src/lockdown.rs:92`; issues **#49, #82**; `reset_cause.rs:72-77` |
| 3.8 | **SECWM1/2 watermarks + SECBOOTADD0 match EVT flash geometry** (not the bench split) | DESTRUCTIVE | `Makefile` `flash-hw*` targets `:195`; issue **#37, #43** |
| 3.9 | **RM0456 register-layout pins** — SECWM1R1@0x50 / SECWM2R1@0x60, SECBOOTADD0 alignment, OPTWERR bit position | NON-DEST (readback) | `first-boot-hardware-bringup.md:55-75`; `shared/src/lockdown.rs:70-76` |
| 3.10 | **SWD-attach-must-fail EOL probe** on every RDP2 unit | NON-DEST (precondition = 3.1 burned) | `external-invariants-20-response-20260704.md:58-67`; issue **#53** |
| 3.11 | **GPDMA blocked from secure SRAM; trusted-path GPIOs stay secure** — verify on silicon | NON-DEST | issue **#53** |
| 3.12 | Sacrificial dry-run: **BOOT_LOCK→OPTWERR lock + both-banks-WRP / identical-FSBL no-op** behavior | DESTRUCTIVE | issues **#45, #41** |

---

## §4 — STM32 OTP: device-master burn + rollback floor (DESTRUCTIVE, one-way fuse)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 4.1 | **Device-master OTP burn viability on EVT silicon.** On the Rev W dev board every attempt hit `SECSR=0x90` (WRPERR\|PGSERR) — such a die "rejects user OTP writes; reject the part." Confirm EVT parts accept the burn. | DESTRUCTIVE | `evt-factory-bringup.md:155,295`; `secure/src/hw/otp.rs:653-741`; issue **#133** |
| 4.2 | **OTP torn half-burn / QW atomicity** (`HW-ASSUME-QW-ATOMIC`, `HW-ASSUME-OTP-ONEWAY`). 32-byte master = two QW writes; power-cut between them silently drops 256→128 bits. Torn/ECC-poisoned QW0 may read unstably → brick. | DESTRUCTIVE (Scaffold Vdd crowbar on sacrificial U585) | `hardware-assumption-boundary-2026-07-17.md:426-484`; `red-teaming.md:574-611`; issues **#93, #94** |
| 4.3 | **Legacy unary rollback tally is production-blocked** — replace before production (Draft 1.1, see §11) | DESTRUCTIVE (OTP) | `otp.rs:9-19`; issue **#31** |
| 4.4 | **Flash page 126/124 per-chip write-hostility.** Bench chip: page 126 erase-OK but QW0 program PROGERR\|PGSERR; page 124 truly untouched; page 123 in reserve. **Re-blank-check on EVT silicon.** | NON-DEST (read/erase probe) → informs DESTRUCTIVE layout | `secure/src/hw/flash.rs:751-757` |

No dedicated OTP make target; exercised via `make build-hw-factory-provisioning` +
`make factory-status-hw`.

---

## §5 — OPTIGA Trust M V3 lifecycle (DESTRUCTIVE ratchets + NON-DEST bring-up)

Ship-blocker cluster S-1/S-2/S-3. LcsO ratchets are points of no return — sacrificial
parts only. **Prerequisite bug:** the Shielded Connection handshake is still broken
on silicon (5.5), which blocks the first real on-silicon C10 sign (5.6).

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 5.1 | **S-1: F1D0 `Change=ALW` → LcsO=Operational ratchet** + sacrificial-part validation | DESTRUCTIVE | `STATUS.md:326`; `optiga/mod.rs::verify_and_lock`; issues **#24, #73** |
| 5.2 | **S-2: real type-`0x11` trust-anchor pool `{0xE0E8,0xE0E9,0xE0EF}` closure** + device-cert retype boundary (observed `0xE0E3` is a full type-`0x12` cert; retired helper is a no-op) | DESTRUCTIVE (neutralize/ratchet) | `STATUS.md:327`; `optiga-bringup-status.md:26-34`; issues **#16, #19, #21, #25, #26, #86** |
| 5.3 | **S-3: silicon-enforced PIN lockout** — E120 LUC + F1D0 `Execute=LUC`, F1E1 freeze; validate ratchet/reset/limit boundary | DESTRUCTIVE | `STATUS.md:328`; `make optiga-hw-counter-e2e` (partial PASS 2026-04-22); issue **#254** |
| 5.4 | **S-4: sentinel lifecycle F1D5↔F1E1 replacement choice** — design + bench evidence | MIXED | `STATUS.md:333`; issue **#215** |
| 5.5 | **Shielded Connection handshake broken on silicon** — SlaveFinished returns 7-byte error `0a 00 02 08 40 75 d4 00`; `shield.establish` bails `HandshakeFailed`. **Blocks 5.6 and the S-5-analog LA capture.** | NON-DEST (LA debug: capture MasterFinished, read 0xE0C5 SEC counter, cross-check TLS-PRF/CCM-8 AAD) | `optiga-bringup-status.md:64-93`; `red-teaming.md:330-345` |
| 5.6 | **First real on-silicon SPHINCS+C10 sign through the OPTIGA path** — never reached (blocked by 5.5) | NON-DEST | `optiga-bringup-status.md:95-97` |
| 5.7 | **Per-session 2-write throttle / CloseApplication no-response** — root cause unconfirmed (suspected SEC counter 0xE0C5); RST-pulse workaround in tree | NON-DEST | `optiga-bringup-status.md:53-56,99` |
| 5.8 | **OPTIGA PBS rotation (first-boot Phase B):** transport-shield handshake (#443), SetData(E140) wedge timing, E140 rewrite, re-shield-under-FINAL, page-126 program-hostility | DESTRUCTIVE (E140 rewrite = brick-risk) | `first-boot-hardware-bringup.md:122-132`; `optiga/mod.rs::rotate_pbs_to_salted`; `optiga-brick-postmortem.md` |
| 5.9 | **E140 LcsO ratchet ordering** — sacrificial part: Operational E140 authenticates with transport PBS, accepts new PBS via Conf(E140), re-establishes after a cut (ratchet stays factory-side) | DESTRUCTIVE | `first-boot-hardware-bringup.md:161-165`; issue **#73** |
| 5.10 | **OP17 residuals** — no PRL self-heal on unlock (wedge burns page-124), E120 wipe gate, boot-reconcile init, DL-frame validation, verdict-confusion in PIN verify | MIXED | issues **#119, #122, #125, #127**; `optiga-bringup-status.md:57,104` |

---

## §6 — SE050C2 (OEF 0xA201) production-part validation (MIXED)

The final part migrated E2→C2/A201 on 2026-07-20 but **has never run on silicon.**
Several SCP03 paths were fixed 2026-07-21 after being found never-executed.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 6.1 | **`TODO(C2-silicon)`: SE050C2 AppletConfig fingerprint not captured.** Anti-substitution gate only knows the E2 bench value `0x3F9F`; capture + pin the C2 `AppletConfig` on first bring-up (a C2 run fails the gate loudly until then) | NON-DEST (unauthenticated identity read) | `secure/src/se050_stress/tests/audit.rs:429`; `docs/SE050C2HQ1_Z01SDZ/README.md`; issue **#61** |
| 6.2 | **SCP03 transport→final `PUT KEY` migration on C2 silicon** — two paths that "had never run on silicon" fixed 2026-07-21, still silicon-unvalidated | DESTRUCTIVE (in-place PUT KEY under transport DEK; torn write → dead keyset) | `first-boot-provisioning.md:249-254`; `secure/src/scp03_logic.rs:27-47,789`; issue **#55** |
| 6.3 | **`HW-ASSUME-PUTKEY-ATOMIC` — highest-leverage bench test (ship-blocker).** Scaffold crowbar across the PUT KEY commit window; probe ENC/MAC and DEK independently. A confirmed `ENC/MAC-final + DEK-transport` is a ship-blocker. | DESTRUCTIVE (sacrificial SE050s, Vdd crowbar) | `red-teaming.md:460-503`; `first-boot-hardware-bringup.md:101-120`; issue **#398** |
| 6.4 | **`HW-ASSUME-PUTKEY-KCV-RESP`** — does the GP applet echo per-key KCVs? If yes, make the 0-length case fail-closed | NON-DEST | `first-boot-provisioning.md:272-276`; issue **#398** |
| 6.5 | **`HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT` / DEK-liveness** — torn-write safety net not shipped until re-PUT idempotency confirmed | DESTRUCTIVE | `first-boot-provisioning.md:277-292` |
| 6.6 | **SE050 admin credential re-key transport→final** — confirm `SW=0x6986` admin-lockout does NOT trip | DESTRUCTIVE (delete+recreate) | `first-boot-hardware-bringup.md:118-120`; issues **#55, #56** |
| 6.7 | **S-5: SCP03 logic-analyzer bus capture** — Rust round-trip silicon-verified 2026-05-28; the LA capture confirming no `half_E` plaintext on the wire is the only remaining leg | NON-DEST (LA) | `STATUS.md:329`; `se050-silicon-findings.md:60`; issue **#7** |
| 6.8 | **S-6: admin-delete policy on USERID_OBJ** — sacrificial-part silicon verification pending | DESTRUCTIVE | issue **#8** |
| 6.9 | **S-7 lower-severity SE050 items** — close in the S-5/S-6 hardening pass | MIXED | issue **#9** |
| 6.10 | **Boot-time SE050 attempt-counter reconcile leg silently skipped** (`ReadObjectAttributes` policy-gated `SW=0x6986`); regression test fires if a future rev honors the read | NON-DEST | `se050-silicon-findings.md:71-114`; `se050/mod.rs:485` |
| 6.11 | **Five A3-recovery sites** (`reinit`, `authenticate_and_read`, `admin_factory_reset`, duress read/verify, `user_factory_reset`) — on-silicon re-run of `se050-stress-destructive` + `pin-gate-hw-counter-e2e` pending | MIXED | `se050-silicon-findings.md:313-364` |
| 6.12 | **SE050 variant/GetVersion assertion** — expect OEF `0xA201`, fail-closed (anti-substitution) | NON-DEST | issue **#61**; `first-boot-provisioning.md` |
| 6.13 | **Case-2 read bug** — `send_apdu` mangles payload-less reads (`get_version_ext` goes on the wire with no Le) | NON-DEST | issue **#444** |
| 6.14 | **half_E: drop ALLOW_WRITE at first provisioning; user/admin UserID final ship policy** | DESTRUCTIVE | issues **#59, #56, #57** |

Targets: `make se050-stress` / `-destructive`, `make se050-reset-e2e`,
`make flash-hw-se050-rotate-scp03`, `make pin-gate-hw-counter-e2e`.

---

## §7 — First-boot self-provisioning (`rdp2-self-lock`) on-device runbook

Status: **candidate implemented, not production-approved; silicon + protocol-closure
gates pending.** Code: `secure/src/first_boot/{mod,journal,state}.rs`,
`shared/src/lockdown.rs`, `secure/src/hw/{flash,secret_keys}.rs`. **The authoritative
runbook is `docs/provisioning/first-boot-hardware-bringup.md` — follow it, not this
summary.** The full ordered silicon matrix is `first-boot-provisioning.md:208-229`.

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 7.1 | **Whole flow is un-flashable today** — needs a `bench-ship-validation` image (owner sign-off); `mode-production` blocked by `FW_ROLLBACK_PRODUCTION_BLOCKED` + needs `FSBL_VENDOR_PUBKEY`. **Hard prerequisite for every §7 bench item.** | NON-DEST (build config) | `first-boot-provisioning.md:320-338`; issue **#268** |
| 7.2 | **Phase-A confirm-gate (R2.4)** interactive pass on real LCD + 2 buttons — accept (chord→burn), decline (long-left→stays RDP-0), idle; prompt must block with SysTick/IWDG not yet started | MIXED (leadup NON-DEST, burn DESTRUCTIVE) | `first-boot-hardware-bringup.md:88-91`; issue **#34** |
| 7.3 | **Flash/OTP torn-write during first boot** (`QW-ATOMIC`+`OTP-ONEWAY`) + **Phase-B power-cut durability matrix** — journal/salt/two-phase rotation must resume at every step boundary | DESTRUCTIVE | `first-boot-hardware-bringup.md:92,141-150`; issue **#399** |
| 7.4 | **`HW-ASSUME-DHUK-RDP12` + SAES Tier-1 DHUK self-test** — one-shot RDP-1 vs RDP-2 DHUK fingerprint compare; the "per-die DHUK is final" premise Phase B rests on | MIXED (RDP-1 fingerprint NON-DEST; RDP-2 lock DESTRUCTIVE, one-shot) | `first-boot-hardware-bringup.md:135-137`; issue **#33**; `red-teaming.md:621-637` |
| 7.5 | **Factory handoff/receipt (`verify_factory_receipt()`)** — device-side stub; PQ-clean signing authority is an OPEN owner decision (ship-blocker) | NON-DEST (design/owner gate) | `first-boot-provisioning.md:294-318`; issues **#76, #268, #249** |
| 7.6 | **Two ship-profile checks fail-closed until silicon-pinned** — `E0809` (WRP1A) then `E080A` (OEM-lock); flip each const with RM0456 citation + positive bench detection | NON-DEST | `first-boot-provisioning.md:159-190`; `shared/src/lockdown.rs:113-120` |
| 7.7 | **BHK page first-write (Tier-2 Phase 2B) + WRP on page 126 + re-pair-after-BHK-loss** | DESTRUCTIVE | issues **#32, #36, #77, #204**; `dual-se-bhk-e2e` |

Flip-after-bench-passes constant table: `first-boot-hardware-bringup.md:172-186`.

---

## §8 — FSBL / FW-update boot trust chain: fault injection (NEEDS-SILICON)

`verify_signature` is sentinel-hardened; the audits flag the surrounding checks as
single-fault-skippable, with physical-glitch feasibility explicitly needs-silicon.
All are **NON-DEST bench** (a glitcher on the target) unless noted.

| # | Item | Ref |
|---|---|---|
| 8.1 | **F15: FW-update/FSBL FI-asymmetry** — `verify_digest`/`verify_rollback` bare while `verify_signature` hardened; `try_once_flag` outside signed preimage; OTP floor single unvoted read. "Physical-FI feasibility requires silicon confirmation." | `ef-swarm-scan-verification-20260626.md:53-66`; `fw_update/mod.rs:417-451`; `fsbl/src/main.rs:124-136`; issue **#376** |
| 8.2 | **FSBL `verify_images` bare `!=` ⊕ FW-COMMIT bare `if let Err`** = 2-fault firmware-replacement chain; per-boot glitch success-rate on `fsbl/src/verify.rs:41` unproven | `fault-injection-20260625-114309.md:94-172`; `fsbl/src/verify.rs:41`; `cmd_fw_commit.rs:49` |
| 8.3 | **Trusted-display consent-gate glitch (WYSIWYS break)** — how reliably does the `(Button,Press)` discriminant flip Left→Right vs crash? | `fault-injection-20260625-114309.md:176-194`; `ui/confirm.rs:74-87`; `buttons.rs:130-136`; issue **#421** |
| 8.4 | **FSBL non-signature `.ok()?` anti-rollback + BEGIN `verify_manifest` bare match** — prior MEDIUMs re-confirmed still open | `fault-injection-20260625-114309.md:198-242`; `fsbl/src/main.rs:124-128` |
| 8.5 | **`tools/sca` has no confirm-button / `fsbl_verify_images` / `fw_commit` sweep** — suite reports green for the FSBL boot path only because it never exercises it | `fault-injection-20260625-114309.md:388` |
| 8.6 | **On-silicon ERC-7730 descriptor-authority fault campaign** (ship-blocker) + physical NV3007 WYSIWYS campaign | issues **#376, #375, #374** |
| 8.7 | Related still-open physical items: **F3** torn-compaction cap rollback, **F10** BEGIN-cancel resets FI wipe budget, **F16** NSC post-verify response FI, **F8a/b** SE-tunnel desync | `ef-swarm-scan-verification-20260626.md:29-88` |

FSBL RAM constraint to respect: 16 KB, no MSPLIM; `fsbl/src/main.rs:99-107` peaked at
~24.7 KB copying manifest pages → HardFault, now borrows from flash. Any EVT SRAM
base/size change re-opens this. `fsbl/memory-stm32u585.x` is legacy bench geometry —
"do not derive WRP or irreversible ops from this linker script."

---

## §9 — SCA / FI rig campaigns (blocked-on: bench)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 9.1 | **Full FI fault-sweep** — 14 rainbow harnesses × full width × all fault models (~40 h); harnesses built, only smoke-run | NON-DEST (compute) | `STATUS.md:312`; `tools/sca/fault_sweep_*.py`; `make -C tools/sca c10-sign` |
| 9.2 | **dudect DWT Welch t-test on real U585** (`verify()`/KDF) — no target/artifact yet | NON-DEST | `STATUS.md:366`; issue **#298** |
| 9.3 | **lascar/scared CPA — on-silicon SHA-2 PRF DPA sufficiency** (emulated half done with a software-AES stand-in; on-silicon open) | NON-DEST | `STATUS.md:367,412`; issues **#228, #236** |
| 9.4 | **Signature FI hardening — verify-before-release on the glitch rig** via `sca-trigger` GPIO (PD2), then re-confirm the gate exists in the prod binary | NON-DEST | `red-teaming.md:284-312`; issue **#139** |
| 9.5 | **RNG raw statistical capture on silicon** — U5 raw-noise limitation means NIST-EA capture needs a sacrificial RDP-0/1 unit | NON-DEST (needs low-RDP part) | `red-teaming.md:176-221`; `hardware-assumption-boundary-2026-07-17.md:337-356` |
| 9.6 | **RDP-2 offensive downgrade campaign** — "single highest-leverage unverifiable premise; a success is a ship decision." FaultyCat EMFI + Scaffold voltage. Note: Šimoník thesis shows ~76% PIN-glitch bypass on STM32U5 silicon | DESTRUCTIVE (sacrificial U585s) | `first-boot-hardware-bringup.md:82-87`; `STATUS.md:372-374`; issues **#301, #133** |

**SCA note:** the on-bench LA1010 is digital-only. On-silicon power/EM SCA (9.2/9.3)
needs a ChipWhisperer-Husky / ChipSHOUTER, which is **not yet on the bench**
(`docs/tooling-and-systems.md:95`) — see the shopping thread.

---

## §10 — Platform: TAMP, GTZC, measured-boot, DHUK, PIN lockstep

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 10.1 | **TAMP tamper response never silicon-validated.** `tamp-wipe` forced ON for shipping dual-SE images; driver was at the wrong base (`0x5600_4400`, now `0x5600_7C00`) — unnoticed because log-only. A false ITAMP9 on a noisy EVT rail would wipe the device. | DESTRUCTIVE (glitch/decap triggering) | `hardware-assumption-boundary-2026-07-17.md:357`; `red-teaming.md:550-570`; `secure/src/hw/tamp.rs:126-132`; issues **#391, #47, #75, #81** |
| 10.2 | **TAMP isolation in GTZC2 unfinished** — SECCFGR/TAMP wiring is a documented follow-up; GTZC2 (RTC-domain TAMP/BKP-SRAM) intentionally NOT locked today | NON-DEST | `secure/src/sau.rs:386-388,548`; issues **#50, #70** |
| 10.3 | **`gtzc-enforcement-hw` C3 gap:** it builds *without* `spi1-arduino`, so the SECCFGR2/SPI1-secure bit (the one keeping NS off the trusted display) is NOT covered by the 7/7 receipt | NON-DEST | `secure/src/sau.rs:389-406`; issue **#239** |
| 10.4 | **F2/F3/F4 platform-security silicon items** — IWDG secure, RCC/PWR clock security, TAMPSEC + DBP hygiene | MIXED | issues **#79, #80, #81** |
| 10.5 | **Measured-boot / FSBL fingerprint on silicon** — immutable FSBL + secure-world display verdict confirmed once resource/silicon gates close | NON-DEST | `red-teaming.md:522-525`; `secure/src/measured_boot.rs` |
| 10.6 | **Three-way PIN-attempt + directional boot cross-check** — E120 LUC + page-124 + SE050 UserID; boot reconciliation lacks a **cold-reboot silicon receipt** (only the directional page124/E120 check exists). `make pin-gate-wipe-e2e` is the QEMU analogue to redo on silicon | MIXED | `STATUS.md:336`; `red-teaming.md:347-384`; issues **#200, #119** |
| 10.7 | **DHUK per-die uniqueness at RDP-2 — n=2, unmeasured at RDP2.** Distinct fingerprints seen at RDP-1; no board has ever been at RDP-2. Capture on the self-locked part | DESTRUCTIVE (RDP-2 self-lock is one-shot) | `hardware-assumption-boundary-2026-07-17.md:330-336`; `red-teaming.md:621-637`; issue **#33** |
| 10.8 | **SWAP_BANK / bank-2 mirror** — SWAP_BANK=0, HDP2+SECWM2 over bank-2 FSBL range, stage identical FSBL in both banks' frozen range | DESTRUCTIVE | issues **#42, #43, #44** |
| 10.9 | **USB-C warm-reset topology** — TCPP03 (PB5) is an on-board dev-kit part; if the EVT omits/changes it, the CC-open/dead-battery re-enumeration choreography must be re-derived | NON-DEST | `secure/src/hw/usb_hw.rs:91-100,209-346`; `fwup-transport-hw-iwdg` |

---

## §11 — Firmware-rollback + SCP03-rotation receipts (DESTRUCTIVE, ship-blockers)

| # | Item | Destructive? | Ref |
|---|---|---|---|
| 11.1 | **HIGH-1: SE050 SCP03 published-key rotation ceremony closure** — journaled candidate exists; production closure needs authenticated per-unit handoff/receipt, authenticate-before-rotate rule, old/new/KVN recovery proof, E140 order, **silicon validation** | DESTRUCTIVE | `STATUS.md:300,334`; `red-teaming.md:435-458`; issues **#55, #76, #204** |
| 11.2 | **FW-RB: A/B rollback + anti-rollback root — Draft 1.1 is NO-GO.** Must close its OPEN silicon gates then obtain separately-authorized Section-13 silicon/factory receipts | DESTRUCTIVE (OTP/TAMP/journal on real silicon) | `STATUS.md:325`; `a-b-firmware-rollback-architecture.md`; `fw-rollback-draft12-candidate-2026-07-21.md` |
| 11.2a | OPEN-PIN-HW-1 — attempt-neutral SE050 prep + one-attempt-cut evidence | DESTRUCTIVE | `a-b-firmware-rollback-architecture.md:444-503` |
| 11.2b | OPEN-JRN-HW-1 / -DUR-1 — physical TAMP journal backend + interrupted-marker durability | DESTRUCTIVE | `:169-172,505-546` |
| 11.2c | OPEN-FLASH-HW-1 — SRAM mutation closure, IWDG timing, cache | DESTRUCTIVE | `:698-750` |
| 11.2d | OPEN-ECC-1 — candidate/marker reads + OTP correction attribution | DESTRUCTIVE | `:605-649` |
| 11.2e | OPEN-RAM-1 — immutable FSBL RAM/stack envelope (38,912 B target / 40,960 B ceiling) | NON-DEST (measure) | `:235,746-752` |
| 11.2f | OPEN-OTP-1..3 — OTP physical record format / rollback-key storage / interrupted-cell authority (after the sacrificial master-closure test) | DESTRUCTIVE | `:1064-1370` |

Draft-manifest work is **not implementation-approved** (CLAUDE.md) — no schema is
current authority. Listed for completeness; do not action without owner stage decision.

---

## Related / duplicate aggregations (do not re-derive; keep in sync)

- **`docs/STATUS.md` §A ship-gate table** — the authoritative ship-blocker list
  (FW-RB, S-1..S-7, HIGH-1, Claim 3) with `blocked-on: bench/factory/code` columns.
- **`docs/provisioning/first-boot-hardware-bringup.md`** — the ordered on-silicon
  runbook (§7 here is a pointer to it).
- **`docs/verification/hardware-assumption-boundary-2026-07-17.md`** — the
  epistemology layer: six assumption surfaces, each with a named falsifying silicon
  test. Establishes ARMv8-M/CMSE and OPTIGA/SE050 internals as permanently
  `silicon-E2E`-or-nothing.
- **`docs/security/red-teaming.md`** — the `HW-ASSUME` ledger + rig-bound tests
  (`PUTKEY-ATOMIC`, `QW-ATOMIC`, `OTP-ONEWAY`, `RDP2`, `DHUK-RDP12`, `OEM2-ABSENT`).
- **`docs/audits/external-invariants-20-response-20260704.md`** — 16 PASS / 4 FAIL,
  all FAILs = this deferred silicon ceremony.
- **`docs/security/adversarial-review/silicon-lockdown-adversarial-review.md`** +
  `shared/src/lockdown.rs:10` — the SL1..SLn "reversible-state-mistaken-for-locked" playbook.
- **GitHub Issues** `EthereumPhone/PQ1`, labels `ship-blocker`, `surface:hardware`,
  and the search `silicon` — the live tracker; close with silicon evidence in the
  comment. This index groups those by subsystem; the issues remain the source of truth.

## Make-target quick reference

| Purpose | Target | Status |
|---|---|---|
| DWT-timed sign smoke | `make test-key-speed` | works on any HW build |
| SAES SW + DHUK domain-sep + fingerprint | `make saes-self-test-hw` | RDP-0 (shared constant) |
| Capture **real per-die DHUK** over VCP | `make saes-self-test-hw-rdp1` | burns RDP=0xBB (SWD dies; UART only) |
| Restore RDP-0 after fingerprint | `make saes-self-test-hw-rdp0-regress` | reversible from RDP1 only |
| GTZC NS-access RAZ-fault | `make gtzc-enforcement-hw` | PASSED 7/7 2026-05-20 (see 10.3 gap) |
| OPTIGA shield handshake only | `make flash-hw-optiga-shield-handshake-only` | currently fails (5.5) |
| OPTIGA E120 LUC + PIN cycles | `make optiga-hw-counter-e2e` | partial PASS 2026-04-22 |
| Three-way PIN per-attempt | `make pin-gate-hw-counter-e2e` | no reboot/reconcile coverage |
| 10-wrong-PIN wipe | `make pin-gate-wipe-e2e` | QEMU; redo on silicon (10.6) |
| SE050 stress | `make se050-stress` / `-destructive` | 16/2 PASS; A3 re-run pending |
| LCD bring-up | `make lcd-test-hw` / `make splash-test-hw` | dev board only so far |
| Brown-out + SRAM2 option bytes | `make stm32-harden-opts` | sets BOR_LEV=3 (target ≥4 — 3.7) |
| One-shot RDP-2 self-lock | first-boot only (`program_rdp_level2_and_launch`) | never run |

*End of index. Amend in place — do not fork a parallel silicon-validation doc.*
