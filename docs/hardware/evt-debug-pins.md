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

`BOOT0` is a `J211` pad, and is also driven by a 3.3 V LDO whose enable is the
USB-C **`SBU2`** line — so its level can depend on what is plugged into the Type-C
port. Worth knowing before debugging a board that "flashes fine but never runs".

### SCA scope trigger

PD2 was requested; **port D does not exist** in this package. The repoint is
**PB3/SWO** — already on `J210` pin 6, firmware-unused, and dead at RDP-2.
Recorded in `secure/src/board/pq1.rs` as `SCA_TRIGGER`; the driver
(`hw/sca_trigger.rs`) has not been ported to it yet.