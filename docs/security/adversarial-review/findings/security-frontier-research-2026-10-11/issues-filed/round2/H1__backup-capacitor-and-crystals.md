TITLE: The V10 schematic has a backup capacitor on VBAT, but two documents say the board has no backup retention and a third lists it as not started: confirm what is fitted, measure the hold time, align the docs
LABELS: documentation,priority:high,surface:hardware,surface:lockdown,surface:docs,source:frontier-research-2026-10
---
## Summary

The board schematic in this repository shows that the STM32's backup supply pin (VBAT) is backed by a small capacitor, and that the MCU has both an 8 MHz and a 32.768 kHz crystal. No document mentions the capacitor. The crystals are mentioned only in passing: `docs/hardware/evt-silicon-validation.md:729-730` says the clock tree needs neither and names pq1's 8 MHz one, and `docs/hardware/hardware_requirements.md:174` lists a 32.768 kHz crystal as optional. Two documents state the opposite about the backup supply ("no VBAT retention", "volatile, cleared by power removal"), and a third still lists the backup capacitor as "board not started". The buyer's pre-power check, the tamper design and the hardware requirements each rest on one of those statements.

This is not a board change. It is a fact about the current board that needs to be confirmed on a unit, measured, and written down, so the firmware and the verification procedure are designed against what is really there.

## What the schematic shows

Source: `docs/hardware/schematics/AL_A66_MB_V10_20260826_1500.pdf`, sheet 1. The file has no text layer, so the part records below were extracted from the PDF's per-component link annotations, and the nets were read from a rendered crop of the sheet.

- **MCU pin 1 (`VBAT`)** connects to `J102` pin 1. `J102` has part type `CPH3225A`, description `BATTERY_3.3V`. Distributor listings give the Seiko CPH3225A as a chip-type electric double-layer capacitor: 0.011 F (11 mF), 3.3 V maximum, 4.6 µAh nominal capacity between 3.3 V and 1.8 V, 160 Ω series resistance ([DigiKey](https://www.digikey.lt/en/product-highlight/s/seiko-instruments/cph3225a), [Farnell](https://de.farnell.com/en-DE/seiko-instruments/cph3225a/double-layer-cap-11000uf-3-3v/dp/3534624)). I did not open Seiko's own datasheet.
- **Charge path:** `VDD3V3` to `D104` (a Schottky diode; the record says `RB551V-30`, part number `RB520S-30`) to `R114` (4.7 kΩ) to the VBAT node. `C119` (22 µF) sits on the same node.
- **Crystals:** `X101`, part type `CRYSTAL_8M`, with `C112` and `C113` (12 pF). `X102`, part type `CRYSTAL_32K`, value 32.768, on MCU pins 3 and 4 (`OSC32_IN`, `OSC32_OUT`), with `C122` (12 pF).

**Not established:** whether these parts are fitted on the units that exist. The repository has no bill of materials (`docs/hardware/pcb/README.md:21`), and the part records carry no "not fitted" mark.

## What the documents say

- `docs/security/user-device-verification.md:91`: "Backup domain (RTC backup regs) | volatile — PQ1 has no VBAT battery; cleared by the step-4 power removal".
- `docs/security/user-device-verification.md:190-191`: "**No VBAT retention** on the production board (no coin cell / supercap on the backup domain), so the step-4 power removal fully clears volatile state." Line `:211` lists the "no-VBAT requirement" as still to be put into the hardware specification.
- `docs/hardware/hardware_requirements.md:139-151` asks for the opposite: a 0.47 to 1 F supercapacitor on VBAT with a Schottky from VDD, sized for "`0.47 F ≈ 12 h`, `1 F ≈ 24 h`" of retention. Row `:245` marks it "board not started".
- `docs/hardware/schematics/README.md:33-43` (the sheet index) lists the `VBAT` rail but not the capacitor or the crystals.
- `docs/hardware/hardware_requirements.md:174` treats the 32.768 kHz crystal as an optional future part; on the schematic it is already there.

So the as-drawn board satisfies neither text. It has retention, which the verification document forbids. And the part is roughly forty to ninety times smaller than the one the requirements document plans its retention times around.

## What it changes, from the reference manual and the code

From RM0456 Rev 7 (read in the PDF, not checked on silicon):

- Section 10.6.4: "The backup domain voltage is VDD when present, VBAT otherwise." With `J102` fitted, the backup domain stays powered after the cable is pulled, for as long as the capacitor holds.
- Table 17: internal tampers 1 (backup-domain voltage), 2 (temperature) and 3 (LSE monitoring) are each "functional in VBAT mode".
- Section 10.6.4 again: tamper 1 fires when the backup-domain voltage is **above** the functional range. When it falls **below** the range, "a brownout reset is generated, erasing all device including backup domain". So a capacitor that simply runs down should end in a clean erase of the backup domain, not in a latched tamper flag.

From the code at master:

- `secure/src/hw/tamp.rs:263` sets `MONEN`, which arms the voltage and temperature monitors. `secure/src/hw/tamp.rs:288-290` enables internal tampers 1, 2 and 3.
- `secure/src/hw/bhk.rs:27-30`: the hardware key that roots the SE050 credentials is kept wrapped in flash page 126 and loaded into the backup registers on every boot. With retention, that key stays in the backup registers after unplugging until the capacitor is empty or a tamper erases it.
- `secure/src/hw/tamp.rs:272` clears every tamper flag at boot before anything reads them (the comment on #75 covers this). So today a tamper that fired while the unit was unplugged is erased unread.
- No image uses either crystal. A search of `secure/src`, `fsbl/src` and `nonsecure/src` for `LSEON`, `HSEON` and `LSECSSON` finds nothing, and the real-time clock runs from the internal oscillator (`secure/src/hw/tamp.rs:257`). Internal tamper 3 is enabled with nothing behind it (#861).

Put together: if the capacitor is fitted, this board already has a short period after unplugging in which the temperature and over-voltage tampers are live and can erase the backup registers in hardware. The report this issue comes from said nothing is armed while the unit is unplugged; for this board that is wrong for the length of the hold time. How long that is has not been measured. From the rated 4.6 µAh and a backup-domain draw in the hundreds of nanoamps, the arithmetic gives hours at most, and the leakage of the diode and of the capacitor itself shortens it. Transit takes days to weeks, so none of this protects a unit in shipping.

## Proposed work

- [ ] Confirm on the open bench board and on one enclosed unit whether `J102`, `D104`, `R114`, `X101` and `X102` are fitted (visual check, or the vendor's bill of materials).
- [ ] Measure the hold time: write a marker to a backup register, remove power for 1 minute, 10 minutes, 1 hour, 6 hours and 24 hours, and read it back. Record the VBAT pin voltage at each point if a meter is to hand.
- [ ] At the same intervals, record what the tamper status register reads at the next power-up **before** the boot code clears it, with the internal tampers enabled. This is the input the #75 fix needs: once flags are read before they are cleared and `tamp-wipe` is on, a flag latched while unplugged becomes a wipe at the next boot.
- [ ] Owner decision: keep the backup capacitor, or remove it at mass production.
  - Keep: `docs/security/user-device-verification.md` must stop relying on "power removal clears volatile state", or state a wait time that the measurement supports. The buyer's tool (#850) should read the backup registers and the tamper configuration, since they can now carry state into the first boot.
  - Remove: `docs/hardware/hardware_requirements.md:139-151` and `:245` change, and "nothing is armed while unplugged" becomes true again.
- [ ] Either way, make the three documents agree, and add `J102`, the charge path and both crystals to the index in `docs/hardware/schematics/README.md`.
- [ ] Record, as a decision and not as work, whether the 32.768 kHz crystal is to be used. With it fitted, the LSE monitor (internal tamper 3) and a clock that keeps running for the hold time are firmware-only changes. Without a decision, remove the tamper 3 enable (#861).

## What it needs

An open bench board with a debug port, a meter, and a few hours of elapsed time. No hardware change. The answers should be in hand before the #75 fix is enabled in a shipping image.

## Limits

- Everything about the board is read from the schematic. Nothing was measured, and no unit was inspected.
- The capacitance is from distributor listings.
- The hold-time estimate is arithmetic from a rated capacity, not a measurement.
- Whether a temperature excursion inside a parked car or a cold warehouse reaches the monitor's thresholds is not known; the thresholds were not looked up.

## Related

#75, #81, #47, #50, #248, #256 (tamper configuration); #850 (the buyer's pre-power check); #861 (internal tampers enabled with nothing behind them); #712, #707 (what the hardware key roots); #695 (enclosed units).

---
<sub>**Provenance.** Security frontier research, 2026-10-11, follow-up pass of 2026-10-12 (hardware asks G1-8 and item N3). The report listed the VBAT population as "not recorded in the repository" and the crystals as a question for the board vendor; both are answered by the schematic, and this issue corrects that. Code and document lines re-read at master `c2fab970`. Evidence: schematic, reference manual and code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
