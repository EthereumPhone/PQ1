# EVT/DVT Debug Pins & Test Pads — STM32U585

**Target MCU:** STM32U585xx (Cortex-M33, TrustZone)
**Scope:** Debug access only — for hardware bring-up, validation, and security audit.
**Lifecycle rule:** **Populate for EVT/DVT, DNP / remove for MP** (mass production).

> **UPDATE 2026-08-30 — read the "As built" section at the bottom first.**
>
> Everything between here and that section is the *request* that was sent to the
> hardware team, written against dev-board (B-U585I-IOT02A) pin numbers. The
> board that came back, `AL_A66_MB_V10`, honours the *intent* — an ARM 10-pin SWD
> header, a UART header, bus test points — but on **different pins**, because the
> production MCU is a 48-pin `STM32U585CIU6` that bonds only PA0–15, PB0–15 and
> PC13. Several signals requested below (PE13/PE15/PE7 for the LCD, PD2 for the
> SCA trigger, PH4/PH5) are on ports that do not exist in that package. Verified
> against the board on the bench 2026-08-30.

---

## SWD debug header

1.27 mm Cortex 10-pin connector.

- PA13 — SWDIO
- PA14 — SWCLK
- PB3 — SWO (trace)
- NRST — Reset
- 3V3 — VTref
- GND — Ground

## Debug UART (log console)

- PA9 — USART1_TX (AF7)
- PA10 — USART1_RX (AF7)
- GND — Ground

## Boot select

- BOOT0 — Pad/jumper on EVT/DVT; hard-strap to GND on MP

## Bus test pads (logic-analyzer access)

Through-hole pads / wire loops sized for grabber clips (not bare SMD pads).

- PB8 — I2C1_SCL (SE bus: OPTIGA + SE050)
- PB9 — I2C1_SDA (SE bus)
- PE13 — SPI1_SCK (LCD)
- PE15 — SPI1_MOSI (LCD)
- PE7 — LCD DC
- CC1 — USB-C CC1 (at connector)
- CC2 — USB-C CC2 (at connector)
- VBUS — USB-C VBUS (at connector)
- GND — 2x clip points

## SCA scope trigger

- PD2 — sca-trigger (scope / ChipWhisperer sync)

---

## Notes for the hardware team

- Populate the **SWD** and **UART** as **headers** (plug-in, no soldering required); DNP the connectors for MP.
- Bring bus signals out to **labeled through-hole test points / loops** (grabber-clip friendly), not bare SMD pads.
- EVT has **no on-board ST-Link** → debugging uses an external probe (ST-Link V3 / J-Link) plus a USB-UART dongle and a logic analyzer.
- All items above are debug-only and must be **DNP / removed for MP**.


---

## As built — `AL_A66_MB_V10` (verified on hardware 2026-08-30)

Sources: `STM32U585CIU6TR Pin Functions.xls` (AF numbers),
`AL_A66_MB_V10_20260826_1500.pdf` sheet 2 (connectors), and a live SWD session.
The firmware-side map is `secure/src/board/pq1.rs`.

### `J210` — SWD, ARM Cortex 10-pin (1.27 mm)

Pin-compatible with the first 10 pins of ST's **STDC14**, so the cable shipped
with an STLINK-V3SET plugs straight in and its conductors 11–14 (the VCP/UART
pair) hang free. That is expected, not a wiring mistake — **the UART is a
separate header**, see below.

| Pin | Signal | | Pin | Signal |
|---|---|---|---|---|
| 1 | VDD3V3 (VTref, via `R212` 10 Ω) | | 2 | SWDIO (PA13) |
| 3 | GND | | 4 | SWCLK (PA14) |
| 5 | GND | | 6 | SWO (PB3) |
| 7 | n/c (key) | | 8 | n/c |
| 9 | GND | | 10 | NRST |

Confirmed working: `probe-rs` enumerates the DP and the full ROM table, and
STM32CubeProgrammer reports 3.26 V / device ID `0x482` / Rev U / 2 MB.

### `J211` — debug UART, 4-pin

| Pin | Signal | Notes |
|---|---|---|
| 1 | `LPUART1_TX` net — driven as **USART2_TX**, PA2 AF7 | board → host |
| 2 | `LPUART1_RX` net — **USART2_RX**, PA3 AF7 | host → board |
| 3 | `BOOT0` | leave open or ground; **do not** let it float high |
| 4 | GND | |

The net names say LPUART1 and the pin table says AF7; both are real silicon on
those pads (DS13086 Table 28 `AF7 = USART2`, Table 29 `AF8 = LPUART1`). The
firmware drives **USART2/AF7** — see `secure/src/board/pq1.rs` for why.

`TP101` / `TP102` / `TP103` are test points sitting on the TX / RX / BOOT0 nets
respectively — a row of three labelled pads adjacent to the four connector pads.
If you are hand-clipping, the labelled pads are the easy target and GND can come
from the SWD header. **Identifying pin 1 on the connector — INFERRED, confirm before wiring:**
the ordering above is read off the schematic's net order, *not* off a physical
board, and nothing here establishes which physical end is pin 1. The reliable
identification is electrical, and takes a meter and thirty seconds:

1. The pad reading ~0 Ω to the SWD header's ground is **GND** — that is pin 4,
   i.e. the end *away* from pin 1.
2. Of the remaining three, the one continuous with the pad labelled `TX`
   (`TP101`) is pin 1.

If you would rather not probe: clip to the **labelled `TX`/`RX` test points**
instead and take GND from the SWD header. Getting this wrong wires TX to TX,
which is silent rather than damaging (both are push-pull outputs into each
other's inputs) — you simply see nothing.

There is **no on-board debugger and therefore no VCP** on this board, unlike the
dev kit. For bring-up over SWD, `probe-rs` semihosting works and needs no UART
wiring at all; the UART matters once RDP ≥ 1 kills SWD.

### Bus test points

Requested as PB8/PB9 + PE13/PE15/PE7. As built, the LCD moved off the
non-existent port E:

| Signal | As built | Was requested as |
|---|---|---|
| I2C1 SCL / SDA (OPTIGA) | PB8 / PB9 | same ✔ |
| I2C4 SCL / SDA (SE050 — its own bus) | PB6 / PB7 | not requested |
| SPI1 SCK / MOSI (LCD) | PA5 / PA7 | PE13 / PE15 |
| LCD DC | PB0 | PE7 |
| I2C2 SCL / SDA (backlight + RGB drivers) | PB13 / PB14 | not requested |

### Boot select

`BOOT0` is a `J211` pad (test point `TP103`). It is also *actively driven* by a
3.3 V LDO — the **third `NCP114ASN330T1G`** on sheet 1 of the V10 schematic,
input `VDD3V6`, output reaching the `BOOT0` net through `R131` (5.1 kΩ) to
sheet 2's `J211` pad — and carries an RC network at the MCU pin, which has a
10 kΩ pulldown (`R121`) with `R119` a 0 Ω series link. That LDO's enable comes
from the USB-C **sideband** via `R132` (10 kΩ); on the V10 schematic *both*
`SBU1/A8` and `SBU2/B8` join the same `SBU` net, so the long-running
"`SBU1` or `SBU2`?" question is moot — they are one net.

**The sideband is NOT how production flashing works.** Recorded here because
two separate reviews went down that path: the agreed flow (owner↔ODM,
2026-07-03) is the STM32U585's built-in **USB DFU bootloader over the USB-C
port**, entered by ST's *empty-check* — a blank flash at the boot address makes
the ROM bootloader run **regardless of BOOT0**. That is why `BOOT0` is
hard-strapped to GND on MP: the strap is the plan, not an obstacle. After the
first flash, DFU no longer auto-enters and updates go through the signed
firmware-update path; the SWD **pads** (the 10-pin connector is removed on
lab/MP units, the pads stay) are the recovery path for a unit that fails
mid-flash, since a partially-programmed device no longer auto-enters the
bootloader.

> **CORRECTION 2026-09-21 — there is no empty-check on the STM32U5, and the
> sideband IS the ODM's flashing path.** AN2606 Rev 70 Table 2 assigns the
> U575/585 to activation **Pattern 12**, whose clauses are only BOOT0(pin) /
> nSWBOOT0 / nBOOT0 / NSBOOTADD / SECBOOTADD / RSSCMD combinations — no
> "main flash memory empty" term (that clause exists in Patterns 11/13/16 for
> the G0/L4/… families). RM0456 Table 25: with BOOT0 low the chip boots at
> NSBOOTADD0, factory default `0x0800_0000`; a blank U585 with BOOT0 low simply
> executes erased flash. The ST moderator on community thread 74870 confirms
> the omission is deliberate. KC (F(x)tec, 2026-09-18) confirmed how the IDH
> flashed the test image: a custom USB-C cable shorting **A8 (SBU1) to A9
> (VBUS)**, i.e. the `SBU → U111 → BOOT0` path on this schematic; without it the
> port is power-only. A 24-pin male↔female pass-through breakout with A8
> bridged to the adjacent VCC hole does the same (used on EVT #1, see the
> 2026-09-18/21 updates below). The MP decision to strap BOOT0 to GND therefore
> removes USB flashing entirely (jig/SWD only), it does not preserve a
> first-flash path.

**The trap that follows from this:** a unit that ALREADY carries firmware — for
example the ODM's own factory test image — has non-blank flash, so empty-check
does not fire. With `BOOT0` strapped low, *neither* entry path works and the
unit is SWD-only, which on a sealed device means opening the case. Establish
whether the strap is fitted before assuming a sealed unit can be recovered over
USB-C.

**Measured 2026-09-18 on an untouched bare `AL_A66_MB_V10`.** Asserting BOOT0
by hand does work, and is the bench route when flash is not blank:

1. Remove ALL power first — USB-C **and** ST-LINK, or the probe keeps the board
   alive and there is no reset. `BOOT0` is sampled as the MCU leaves reset, so
   the jumper must be in place across the power cycle.
2. Jumper `J210` pin 1 (`VDD3V3`/VTref, via `R212` 10 Ω) → `BOOT0`
   (`J211` pin 3, or `TP103`). One wire. 3.3 V only — never VBUS.
3. Power up over USB-C to the host.

Result: `0483:df11`, `Product: DFU in FS Mode`; CubeProgrammer then reports
`Device ID 0x482`, `STM32U575/STM32U585`, `NVM 2 MBytes`, `DFU protocol 1.1`.

**`sudo` is required and its absence is misleading.** `/dev/bus/usb/BBB/DDD` is
`crw-rw-r--` and no udev rule exists for `0483:df11`, so CubeProgrammer cannot
claim the interface and fails with `Error: Target device not found` even while
`lsusb` plainly shows the device and you pass the correct `sn=`. `sudo` also
resets `PATH`, so give the binary its full path.

Shipped option bytes, read from an untouched board: `RDP 0xAA` (Level 0),
`TZEN=0`, `nSWBOOT0=1` (BOOT0 taken from the **pin**), `nBOOT0=1`, WRP1A
inverted/empty, `UNLOCK_1A=1`. Two of those gate the route: RDP-0 leaves the
ROM bootloader enabled (RDP-2 disables bootloader selection outright), and
`nSWBOOT0=1` means the BOOT0 pin is honoured at all.

One security consequence survives regardless of mechanism: a cable or dongle
that asserts the sideband can change how the device boots. That is a security
property, not a convenience — but first-flash and recovery are designed around
empty-check and the SWD pads, and must not silently depend on it.

### UPDATE 2026-09-18 — flashing over USB-C with no probe (ROM DFU)

The SBU→U111→BOOT0 circuit above is the ODM's "flash over USB-C" path: a cable
with SBU pulled high forces BOOT0=1 and the STM32 ROM bootloader enumerates as
USB DFU (`0483:df11`) on D+/D-, which the AW35602 passes through unconditionally.
A laptop never drives SBU on a non-PD sink, so on the bench pull BOOT0 high by
hand instead: **TP103 (or `J211` pin 3) → `J210` pin 1 (VTref, 3.3 V via 10R)**,
held while USB-C is plugged in. BOOT0 is only sampled at reset, so the wire can
come off once `lsusb -d 0483:df11` shows the bootloader. The 10K pull-down
(R121) and the 5.1K back into the (discharged) U111 output leave the pin at
~3.29 V. Then:

```
evt-images/build.sh                                   # BOARD=pq1 images → evt-images/<name>/{secure,nonsecure}.bin
tools/flash-evt-dfu.sh evt-images/lcd-test --erase    # first flash over ODM test firmware
tools/flash-evt-dfu.sh evt-images/dual-se-standalone  # full wallet image (see optiga-hw-counter caveat in the recipe)
```

The script writes `nonsecure.bin` @ `0x08100000`, `secure.bin` @ `0x08000000`
(physical address of the `0x0C000000` secure alias) and programs the usual
TZEN/SECWM/SECBOOTADD0 option bytes over DFU via `STM32_Programmer_CLI -c
port=USB1`. If the board boots its old firmware with BOOT0 high, `nSWBOOT0` is 0
and only SWD on `J210` can recover it. Requires `RDP` ≤ 1 (level 1 is regressed
with a mass erase; level 2 is final).

#### UPDATE 2026-09-21 — first DFU flash on silicon: what the bootloader can and cannot do

Done on EVT #1 (die UID serial `2068316E3046`, ODM option bytes were factory
defaults: RDP 0, TZEN 0, nSWBOOT0 1, no WRP). The ODM test image is backed up
at `evt-images/odm-test-image-2MB.bin` (SHA-256
`5316cc30…dcfc36`). Findings that bind the flash order:

- **With TZEN=1 the U5 ROM bootloader runs non-secure.** DFU writes to the
  secure bank are silently dropped and reads return zeros (the `0x0C000000`
  alias is rejected outright: "Data read failed"), while the non-secure bank 2
  reads and verifies fine. So a secure image **must be written with TZEN=0 and
  TZEN enabled afterwards**; activation keeps flash contents (RM0456 §3.5.6).
- `SECWM*`/`SECBOOTADD0` do not exist as option bytes until TZEN=1 has taken
  effect (programmer: "does not exist"). After TZEN=1: SECWM1 = bank 1 all
  secure and SECBOOTADD0 = `0x180000` by default, but **SECWM2 also defaults to
  all secure** — write `SECWM2_PSTRT=0x7F SECWM2_PEND=0x0` in a second step.
- Undoing TZEN over DFU: `-ob RDP=0xBB` then `-tzenreg` (the AN2606 "TrustZone
  disable" special command, valid only at RDP=1 — at RDP=0 it prints "successfully"
  and does nothing). Mass-erases. At RDP=1 the programmer's connect warns
  "Fail to read NVM Size" but the special command still runs.
- The bootloader wedges (reports DevID 0x0000) after a failed upload; a power
  cycle with the SBU bridge in place recovers it.

`tools/flash-evt-dfu.sh` now encodes this order.

### Bench SSD1306 OLED (`make oled-bench-hw BOARD=pq1`)

The board exposes exactly two free GPIOs — everything else on the header and
pads is either committed or a debug line you must not touch:

| OLED | Board | Pin |
|---|---|---|
| VCC | header `VDD` | — |
| GND | header `GND` | — |
| SCL | header `SWO` | **PB3** |
| SDA | `RX` pad | **PA3** |

`PA3` is free because the console is TX-only, so the UART keeps working
alongside the display. Three of the four connections are pins on the 2x5
header.

**Software I2C, necessarily.** No I2C peripheral can reach this pair: `PB3`'s
AF4 is `I2C1_SDA`, but that is the OPTIGA's peripheral and a peripheral has one
SDA pin; `PA3` has no I2C alternate function at all (DS13086 Rev 10, Tables
28/29). PB8/PB9 — the obvious choice — are **not brought out**. So
`hw::soft_i2c` bit-bangs at ~100 kHz, which an SSD1306 does not strain.

Mutually exclusive with `sca-trigger` (also wants PB3) — a `compile_error!`,
not a surprise. Driver auto-probes 0x3C then 0x3D and skips cleanly if neither
answers. Written for **128x32**; a 128x64 module will letterbox into the top
half.

This validates nothing about the NV3007 path and is `PROD_FORBIDDEN`. While a
debugger is attached, `ui-semihosting` shows the same 16x4 text for free.

### SCA scope trigger

PD2 was requested; **port D does not exist** in this package. The repoint is
**PB3/SWO** — already on `J210` pin 6, firmware-unused, and dead at RDP-2.
Recorded in `secure/src/board/pq1.rs` as `SCA_TRIGGER`; the driver
(`hw/sca_trigger.rs`) has not been ported to it yet.