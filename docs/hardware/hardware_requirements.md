# Hardware Requirements

> **Status.** No custom PCB exists yet — the design runs today on a
> **B-U585I-IOT02A** dev board + **OPTIGA Trust M Shield** + **OM-SE050ARD**
> on Arduino headers (see `docs/hardware/dev-board-setup.md`, `docs/security/brownout-hardening.md`,
> and the memory note on the off-by-one header silkscreen). This file is the
> *requirements* spec for the eventual production board; the authoritative
> sign-off gate is **§A "Hardware design & PCB"** of the Pre-Production Shipping
> Checklist in `README.md`, which this document expands and cross-references.
> Phase 3 of the roadmap ("custom PCB, HUK-SAES, GTZC, production peripheral
> set") is where these get built and validated.

## Microcontroller

- **STM32U5** series (e.g. STM32U585)
  - ARM Cortex-M33 with TrustZone (CMSE)
  - Hardware AES, SHA-256, PKA, SAES (with DHUK), TRNG accelerators
  - Secure boot target via TZEN and RDP level 2. Devices ship at RDP-0 for
    owner verification; an implemented but unapproved secure-app early-boot
    candidate self-locks RDP-2 before final credentials are established.
  - **SWD + NRST remain physically accessible after assembly** for that
    pre-first-power verification. RDP-2 disables debug in silicon after the
    reviewed self-lock; do not cut or hide the pads (see §Connectors & debug).
  - Internal temperature sensor available to firmware (cold-boot defence —
    `docs/security/HARDENING.md`: refuse operation below the rated low temperature)
  - Verify the die revision before relying on Stop-2 / backup-domain behaviour
    (STM32U585 errata ES0499 §2.2.10 — fixed in Rev U; see `docs/security/brownout-hardening.md`)

## Secure Elements

Entropy of the seed phrase is split across two independent secure elements to eliminate single points of compromise (CLAUDE.md invariant #1).

### Infineon OPTIGA Trust M V3

- Holds one share of the seed entropy (XOR-split half)
- **Exact PCB component (pinned 2026-07-20): `SLS32AIA010MKUSON10XTMA2`** — Trust M V3,
  Standard Temperature Range (−25…+85 °C), PG-USON-10-2,-4, tape & reel. Vendor-doc
  pack (datasheet/SRM v3.70, IFX I2C v2.03, Keys & Certs, ConfigGuide, factory object
  dump) is kept locally at `docs/SLS32AIA010MKUSON10XTMA2/` — gitignored, not
  redistributable; see `docs/secure-elements/OPTIGATRUSTM/README.md` for upstream links
- Common Criteria EAL6+ certified (SLS32AIA; PSA Certified Level 3 for the MK variant)
- IFX I2C protocol (4-layer stack) at address 0x30
- Shielded Connection (TLS-PRF + AES-128-CCM-8) for encrypted I2C
- Authorization reference PIN protection (hardware-enforced access conditions),
  with the E120 LUC bound to F1D0 under `optiga-hw-counter`
- Candidate transport Platform Binding Secret — derived from the
  factory-burned per-device OTP master. The candidate final PBS derives from
  Tier-1 SAES-DHUK plus a non-secret fresh TRNG salt persisted in the page-127
  journal; no PBS is stored in page 126. Handoff/recovery, E140 actor/order,
  silicon evidence, and production approval remain OPEN (work-todo #36).
- **Independent reset line** (see §Power, brownout & reset)

### NXP SE050

- Holds one share of the seed entropy
- Common Criteria EAL6+ certified
- T=1' over I2C at address 0x48; SCP03 secure channel (AES-CMAC + AES-CBC)
- UserID PIN authentication; admin UserID (`max_attempts=0`) for crash-safe
  factory reset. Factory transport SCP03/admin credentials derive from the
  per-device OTP master. The candidate final credentials derive from the
  unsalted BHK through `hw::secret_keys`; direct DHUK/BHK helpers remain bench
  configurations. Handoff/recovery, silicon evidence, and production approval
  remain OPEN under work-todo #36.
- **Independent reset line** so a fault on the SE050 cannot wedge the OPTIGA
  (and vice-versa) — see §Power, brownout & reset
- **Production layout review item:** the two SEs share I2C1 today; evaluate
  moving SE050 to a second I²C peripheral so a bus fault on one can't wedge the
  other (`README.md` §A)

> **TROPIC01 note.** Earlier design iterations evaluated TROPIC01 as a
> secondary SE in a dual-SE split. That path was retired in favour of the
> OPTIGA + SE050 pairing above, and the remaining standalone-SE driver and
> `tropic01-se` Cargo feature were removed from the codebase on 2026-07-14
> (owner decision — dual-SE only).

### I²C bus

- Pull-ups on each SE I²C bus, sized for the chosen bus speed and capacitance
- No test pads / probe points on either SE bus (see §Connectors & debug)

## Display

- **Longevity display** (NV3007 TFT LCD — the shipping display; the SSD1306 OLED backend was removed 2026-06-30)
  - Must remain fully functional after extended periods of inactivity (e.g.
    stored for 10+ years between uses)
  - On its own bus (SPI or I²C), kept off any probe-accessible header — it
    renders the trusted-path PIN entry and transaction-confirm screens, so its
    bus is an S-world peripheral for layout purposes
  - On a locked board (RDP ≥ 1, TZEN = 1, no OEM keys) the NV3007 LCD is the **only**
    working diagnostic — UART/SWD/PE13 are all silent (memory: per-die DHUK
    validation). Don't omit it or bury it under the can in a way that defeats
    bring-up.

## User Input

- **2 hardware buttons**
  - Physical confirm / reject for transaction signing
  - No touchscreen — reduces attack surface
  - Buttons directly wired to MCU GPIO (no controller IC in path); debounce in
    RC and/or firmware
  - Only S-world button presses on confirm dialogs reset the inactivity timer
    (CLAUDE.md) — the GPIOs are S-world peripherals for layout purposes

## Anti-tamper & physical security

All from `README.md` §A and `docs/security/HARDENING.md`. The firmware side lives in
`secure/src/hw/tamp.rs` (TAMP driver, currently log-only and not yet wired into
`main()`) and `secure/src/hw/bhk.rs` (the BHK, which lives in the TAMP backup
registers and is erased in hardware on any tamper event).

- **Tamper mesh covering all four PCB layers** across the U585 + *both* SEs,
  routed into a `TAMP_INx` external tamper input
- **Case / enclosure switch** wired to a `TAMP_INx` pin with a hardware
  pull-resistor and an RC noise filter (the `TAMP_FLTCR` precharge/sample
  config in `tamp.rs` is already set for external pins; the pin enable in
  `TAMP_CR1`/`TAMP_CR2` is the missing firmware piece — see §Open items)
- **EMI shielding can** over the U585 + both SEs
- **Power-rail filtering** sized to mitigate the obvious ripple-injection /
  power-analysis paths over the SEs and SAES
- **Crystal-vs-internal-RC oscillator decision documented**, with the guarantee
  that no glitchable clock path reaches an S-world peripheral
- **Internal temperature-sensor path** kept usable across the operating
  envelope; cold-boot threshold tested at the rated low temperature
- Optional / nice-to-have: a side-channel-hardening copper pour and the TIM2
  CH1 consumption-mask PWM on its pin (`secure/src/hw/consumption_mask.rs`,
  `consumption-mask` feature) — dev-board pin is PA5; pick a final pin on the
  custom board

## Power, brownout & reset

From `README.md` §A and `docs/security/brownout-hardening.md`.

- **Bulk decoupling capacitance sized so the wipe ISR completes under
  worst-case current draw before V_dd collapses** — and **measured on real
  hardware**, not estimated. `docs/security/brownout-hardening.md` notes ~22 µF near the
  MCU plus the usual per-rail decoupling as a starting point; the real number
  is bench-determined against the chosen BOR level. (Dev-board default ~4.7 µF
  gives only ~µs of holdup at the typical ~35 mA draw.)
- **BOR threshold** chosen and validated against that capacitance (it's an
  option-byte setting — `FLASH_OPTR.BOR_LEV` — not a part, but it's part of the
  HW power validation)
- **PVD / PVM analog voltage monitors** wired for the brownout interrupt and
  the VBAT-charge-up gate
- **VBAT backup-domain power = supercap, not a coin cell.** Reference design
  (`docs/security/brownout-hardening.md` "VBAT power source"):
  - 0.47–1 F / 3.3 V radial supercap (e.g. Panasonic EECS-GW0H474H, ~6.8 × 2 mm,
    5–10 µA self-leakage) — `0.47 F ≈ 12 h`, `1 F ≈ 24 h` of bounded
    tamper-retention runtime
  - Schottky from V_dd (BAT54 / 1N5819) to stop the supercap back-feeding V_dd
    on unplug
  - Optional 10–47 Ω series R for inrush limiting on first plug-in
  - Rationale: no battery chemistry in the enclosure (no leak/swell/age-out/
    replacement lifecycle), sealed-for-life BOM. Keeps the VBAT canary and the
    TAMP backup registers — **where the BHK lives** — alive across sessions
  - On a board where VBAT and V_dd share a source, enable backup-domain
    monitoring (`MONEN=1`) — ES0499 §2.2.7/§2.2.8 spurious-tamper workaround
- **Independent reset line for each SE** so a fault on one cannot wedge the
  other
- **NRST** routed to an accessible verification pad alongside SWD so the owner
  can use connect-under-reset before first power; after the reviewed RDP2
  self-lock, silicon debug closure—not physical concealment—is the boundary

## Connectors & debug

- **USB-C connector** — USB OTG FS, the companion-app link (HID + Ledger APDU
  framing; `usb` feature, `nonsecure/src/usb/`) — plus ESD/TVS protection on
  the data lines
- **No test pads, debug headers, or probe points** exposing either SE bus, the
  display bus, the button GPIOs, or *any* S-world peripheral (`README.md` §A,
  `docs/security/HARDENING.md`)
- **SWD + NRST pads MUST stay accessible after assembly** — REVERSED 2026-07-14
  by the ship-RDP-0 decision (work-todo #36): devices ship at RDP-0 so buyers
  can verify flash/option-bytes/OTP over SWD (connect-under-reset, which needs
  NRST reachable too) before first power; the first field boot self-locks to
  RDP-2, which disables the debug port in silicon, and ITAMP6 fires on
  post-lock probe attempts. The pads are the verification feature, not a
  liability. (This reverses the earlier "cut traces or fill vias" rule, which
  assumed a factory RDP-2 burn.)
- **LSE 32.768 kHz crystal** — optional / "nice to have" for accurate RTC and
  IWDG timekeeping; the TAMP driver runs LSI-only and works without it
- **No second debug / test connector of any kind**

## BOM & supply chain

From `README.md` §A (and §H of the shipping checklist for the manufacturing
hand-off):

- **Spec'd lead-time and a qualified second-source for every part on the BOM**
  — especially OPTIGA Trust M V3 and SE050. A stockout that forces a vendor
  swap would break pinned attestation / the baked-in CC certs and the
  per-device pairing model
- The factory burns one per-device OTP master and provisions transport
  SCP03/admin/PBS credentials derived from it; these are not final device
  credentials. Secure-app early boot derives final SE050 credentials from the
  post-lock BHK and final OPTIGA PBS from DHUK plus the page-127 salt. The
  authenticated handoff, cut recovery, E140/SE050 order, silicon evidence, and
  production approval remain OPEN (`README.md` §B, work-todo #36).

## Explicitly *not* on the board

- **No coin-cell battery** (supercap instead — see §Power, brownout & reset)
- **No classical-crypto coprocessor / secp256k1 accelerator** — pure-PQ design
  (CLAUDE.md invariant #5)
- **No touchscreen, no fingerprint sensor, no extra microcontrollers** in the
  trusted path (§User Input above; `README.md` §A)
- **No second-stage debug / test connector**

## Open items (firmware work the board design depends on)

Not silicon — the firmware deltas that have to land alongside the board so the
hardware features above actually do something:

- **External `TAMP_INx` pin config** in `secure/src/hw/tamp.rs` — enable the
  `TAMPxE` bit in `TAMP_CR1`, polarity / no-erase / mask bits in `TAMP_CR2`,
  once the pin assignment is fixed on the custom board. `TAMP_FLTCR` is already
  pre-configured for external pins.
- **Wire `tamp::init()` into `main()`** — currently `init()` / `poll()` /
  `on_tamp_irq()` exist but aren't called from the boot path.
- **Flip the TAMP IRQ from log-only to `trigger_lockout_wipe()`** — deliberate
  on the bring-up branch (probe-rs glitches false-trigger ITAMP9); production
  must escalate. See `docs/archive/production-todo-retired-2026-07-19.md`
  "TAMP escalation" and `README.md` Phase-3 step 6.
- **BHK first write/load** exists only inside the `rdp2-self-lock` candidate,
  which is valid only with `mode-production`; do not run it from a generic,
  bench, or factory flow. The authenticated handoff, cut recovery,
  E140/SE050 ordering, silicon evidence, and production approval remain open.
  See `docs/archive/work-todo-retired-2026-07-19.md` §7/#36 and `secure/src/hw/bhk.rs`.

## Cross-reference: feature → requirement → enforced/implemented → status

Legend: ✅ done / works · 🟡 partial (firmware present, board step pending or vice-versa) · ⏳ not started, board-blocked · ❌ not started, blocks shipping.

| PCB feature | Required by | Enforced / implemented in | Status |
|---|---|---|---|
| STM32U585 (M33+TZ, AES/SHA/PKA/SAES/TRNG) | this doc, README §A | whole secure world; `secure/src/hw/*` | ✅ runs on dev board |
| RDP-2 / TZEN; SWD + NRST pads accessible (ship RDP-0, first-boot self-lock — work-todo #36) | README §A, `docs/security/HARDENING.md` | shipped option-byte profile + secure-app early-boot `rdp2-self-lock` candidate; board layout | ⏳ board not started; candidate is production-only and unapproved; self-lock ceremony validation is a sacrificial-unit step |
| OPTIGA Trust M V3 @ I2C 0x30 + Shielded Conn | this doc | `secure/src/optiga/*` | ✅ validated on shield |
| SE050 @ I2C 0x48 + SCP03 + UserID PIN | this doc | `secure/src/se050/*` | ✅ validated on ARD board |
| SE050 on a separate I²C peripheral | README §A | — (layout decision) | ⏳ open layout review item |
| Independent reset per SE | README §A, this doc | — (layout); firmware reset sequencing | ⏳ board not started |
| I²C pull-ups per SE bus | implicit | — (layout) | ⏳ board not started |
| Longevity NV3007 LCD on its own bus, off headers | this doc, README §A | `secure/src/ui/lcd.rs` | 🟢 NV3007 LCD driver silicon-validated (SSD1306 OLED removed 2026-06-30) |
| 2 buttons direct to GPIO, no controller IC | this doc, README §A | `secure/src/hw/buttons.rs`, `secure/src/ui/confirm.rs` | ✅ on dev-board headers |
| Tamper mesh, all 4 layers, over U585 + both SEs | README §A, `docs/security/HARDENING.md` | `secure/src/hw/tamp.rs` (ext-pin cfg pending) | ❌ board not started; firmware ext-pin cfg open |
| Case switch → `TAMP_INx`, hw pull + RC filter | README §A, `docs/security/HARDENING.md` | `secure/src/hw/tamp.rs` (`TAMP_FLTCR` set; pin enable pending) | ❌ board not started |
| TAMP event → erase BHK + lockout-wipe | invariant #2, `docs/security/HARDENING.md` | HW (TAMP clears BKPR + BHKLOCK) + `tamp.rs` IRQ (log-only today) | 🟡 HW path automatic; IRQ escalation pending |
| EMI shielding can over U585 + both SEs | README §A | — (enclosure) | ⏳ board not started |
| Power-rail filtering (anti-ripple-injection) | README §A | — (layout) | ⏳ board not started |
| Bulk cap sized so wipe ISR survives BOR | README §A, `docs/security/HARDENING.md`, `docs/security/brownout-hardening.md` | option-byte BOR level + `NonMaskableInt` zeroize ISR (Stage 1 done; sizing pending real HW) | 🟡 firmware ISR exists; cap sizing needs real board |
| VBAT supercap (0.47–1 F) + Schottky from V_dd | README §A, `docs/security/brownout-hardening.md` | `docs/security/brownout-hardening.md` reference design; VBAT canary firmware (Stage 1.5) | ⏳ board not started; dev-board tack-solder path documented |
| Internal temp sensor → cold-boot refuse | README §A, `docs/security/HARDENING.md` | (firmware boot check — planned) | ⏳ planned |
| Clock: crystal-vs-RC documented, no glitchable S-world clock | README §A | `secure/src/hw/rcc.rs`; `tamp.rs` LSI-only | 🟡 dev-board choices; doc/decision pending custom board |
| USB-C OTG FS + ESD/TVS on data lines | this doc (companion link) | `secure/src/hw/usb_hw.rs`, `nonsecure/src/usb/*` | 🟡 firmware works; TVS is a board item |
| No test pads / debug headers on any S-world bus | README §A, `docs/security/HARDENING.md` | — (layout) | ⏳ board not started |
| Second-source + lead-time for every BOM part | README §A | — (procurement) | ⏳ not started |
