# PQ1 mainboard — schematics

Schematic sheets for the PQ1 mainboard, revision **V10**, dated 2026-08-26 15:00
(vendor build code `AL_A66_MB_V10_20260826_1500`; `A66` is the ODM's internal
project code for the PQ1 mainboard). Two sheets, A1.

| File | Sheets | Contents |
|------|--------|----------|
| `AL_A66_MB_V10_20260826_1500.pdf` | 1 | MCU, both secure elements, display + backlight, buttons, SWD (`U1xx` / `R1xx` / `C1xx`) |
| | 2 | USB-C, charging + power path, button and debug connectors, EMI (`U2xx` / `C2xx` / `D2xx`) |

> **This file has no text layer.** It is a ClibPDF image-only export, so
> `pdftotext` returns nothing and every fact must be read from a rendered crop
> (`pdftoppm -r 400 -x .. -y .. -W .. -H ..`). The superseded 2026-07-14 sheet
> *did* carry text, so any analysis that relied on text extraction was done
> against that revision and does not automatically carry over.

Unlike the copper plots in [`../pcb/`](../pcb/), these sheets **do** carry full
reference-designator-to-net mapping, so this is the authority for *which MCU pin
carries which net*. It is not the authority for what is safe to physically
probe — [`../evt-debug-pins.md`](../evt-debug-pins.md) is.

## Why this matters right now

[`../evt-silicon-validation.md`](../evt-silicon-validation.md) says, of the
firmware pin table: *"Cross-check every row against the EVT schematic before
flashing anything"*, and flags several rows as chosen empirically on the dev
board rather than from a schematic — notably the OPTIGA RST / SE050 ENA nets,
which it calls *"almost certainly wrong on EVT"*. These sheets are the document
that check was waiting on. The cross-check itself has **not** been done; nothing
in `evt-silicon-validation.md` has been updated against this file.

## Index (read off sheet 1, for orientation only)

Confirm against the PDF before relying on any of it:

- MCU `U101` — **STM32U585CIU6TR** (48-pin; no Port D/E)
- Secure elements — **SLS32AIA010MH** (OPTIGA Trust M) and **SE050E2HQ1**
- Buses — `I2C1`, `I2C2`, `I2C4`; `SPI1` (`SPI1_CS` / `SPI1_SCK` / `SPI1_MOSI`) to the display
- Display — `LCM_DC` / `LCM_RST` / `LCM_TE` / `LCM_EN` / `LCM_LEDA` / `LCM_LEDK`
- Backlight — `AW21036QNR`, `AW99703CSR`; charging + power path on sheet 2 — `AW32901`, `AW35602`
- Rails — `VDD1_3V3`, `VDD3V3`, `VDD3V6`, `VDDA`, `VBAT`
- Buttons — `UP_KEY`, `DOWN_KEY`; debug — `SWDIO`, `SWCLK`

## Provenance

- `sha256 d58e878ca167473208dccc0857d960cd7bad151ffd735bf255bea5a47fc6a1f1`
  (the superseded 2026-07-14 sheet was
  `sha256 5ba0309d30882b1e04f4fef0eeca4cf7603ab921d85994a4290873481f4ff029`)

- **The parts list is machine-readable, and is the right way to diff revisions.**
  Both sheets carry one PDF link annotation per component whose JavaScript action
  is `app.popUpMenu('Ref-Des=…','Part Type=…','Value=…',…)` — 121 parts. Extract
  and compare those instead of diffing text or pixels: the text layer is absent
  from this revision, and the two render in different fonts so a pixel diff is
  almost entirely font noise. The 2026-07-14 → 2026-08-26 comparison reduced to
  exactly five field differences this way.
- Byte-identical to the file received from the ODM. The delivered copy arrived
  through a browser as `…_1500-2.pdf`; the `-2` is a download-dedup suffix, not
  part of the vendor build code, and was dropped so the name matches the
  convention the layer plots in [`../pcb/`](../pcb/) use. Contents unaltered.
- One revision is tracked at a time. **Superseded 2026-09-23:** this file
  replaced `AL_A66_MB_V10_20260714_1500.pdf` (2026-07-14), which had been the
  tracked sheet and is recoverable from git history before that date.

  Worth recording how the swap came about, because the failure mode will recur.
  The 2026-08-26 drop had been sitting in `~/Downloads` and `~/Documents/pq1`
  since mid-September while this README asserted that the tracked file was the
  only revision and that anything else was *earlier* and superseded. It was
  neither — it was six weeks newer. A day of hardware analysis ran against the
  stale sheet before a search for an unrelated artefact (a BOM) turned it up.
  **When an ODM drop arrives, replace the tracked file in the same change**;
  a newer revision outside the repo is worse than no revision in it, because
  this README makes the stale one look authoritative.

- **There is no BOM in this repo**, in any format or anywhere in git history
  (see [`../pcb/README.md`](../pcb/README.md)). Component values and ratings can
  be read *only* from these sheets, so a claim like "C140 is rated 25 V" has
  exactly one source and cannot be cross-checked here. Verified 2026-09-23.

## Scope

- This is the EVT-era board revision, matching the V10 layer artwork in
  [`../pcb/`](../pcb/) (layout snapshot `…_20260715_1100`, one day later).
- These are the ODM's design output — a record of what was built, not a
  design-review artifact. No signal-integrity, EMC, or tamper/side-channel
  review is implied by their presence in this repo.
- `*.pdf` is globally `.gitignore`d in this repo because vendor-copyrighted
  datasheets may not be redistributed (those live outside the repo). This
  directory is an explicit exception: our own board documentation is open
  source. The vendor datasheets for the parts *on* this board are not, and are
  still excluded.
