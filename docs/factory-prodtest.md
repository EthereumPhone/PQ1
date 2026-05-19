# PQSigner factory production-line test (prodtest)

The prodtest firmware is the **first** firmware the factory operator
flashes onto a fresh chip. It validates each hardware component
(OLED, SAES, BHK, TRNG, flash) before the factory_provisioning
ceremony burns one-way state.

Internal design notes for engineers are in
[`secure/src/nsc/prodtest.rs`](../secure/src/nsc/prodtest.rs).

For the operator manual covering the post-prodtest provisioning
ceremony, see [`factory-provisioning.md`](factory-provisioning.md).

---

## Factory line workflow

```
┌──────────────────────────────────────────────────────────────┐
│  Per-chip flow on the factory line:                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. probe-rs download prodtest firmware                     │
│  2. Configure TZ option bytes (TZEN=1, ...)                 │
│  3. Reset chip → OLED shows "PRODTEST READY"                │
│  4. tools/factory-prodtest-runner.py over USB HID           │
│     - reads STM32 UID into fixture's traceability DB        │
│     - cycles display patterns (1 s each, camera verify)     │
│     - reads SAES + BHK fingerprints (per-die-uniqueness)    │
│     - flash R/W round-trip on a designated test page       │
│     - 256-byte TRNG sample (χ² entropy check)              │
│  5. On all pass → proceed to factory_provisioning ceremony  │
│     On any fail → set chip aside, log offending CMD_ code  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

The runner script (`tools/factory-prodtest-runner.py`) exits 0
when every test passes, non-zero on any failure. The fixture's
outer script wraps this with the per-unit serial / position
tracking and decides whether to chain `flash-hw-factory-provisioning`.

---

## Command reference

The prodtest firmware exposes 10 USB HID commands. All commands map
to `proto/src/lib.rs::CMD_PRODTEST_*`; keep these IDs STABLE so old
field reports stay interpretable.

| ID | Command | Input | Output | Phase |
|---:|---|---|---|---|
| 100 | `GET_ID` | — | 12 B UID ‖ 4 B fw_version ‖ 8 B reserved | A |
| 101 | `DISPLAY_PATTERN` | 4 B pattern (0..4) | — | A |
| 102 | `SAES_SELFTEST` | — | 8 B DHUK fingerprint | B |
| 103 | `BHK_SELFTEST` | — | 8 B BHK fingerprint | B |
| 104 | `FLASH_RW` | 4 B test pattern | — | B (stub) |
| 105 | `TRNG_SAMPLE` | 4 B count (1..=256) | N B random | B |
| 106 | `OPTIGA_HANDSHAKE` | — | 16 B OPTIGA RNG | C |
| 107 | `SE050_HANDSHAKE` | — | 16 B SE050 RNG | C |
| 108 | `USB_LOOPBACK` | N B input (1..=256) | N B echo | C |
| 109 | `BUTTON_TEST` | — | 4 B step_status | D |

Phase A landed 2026-05-19 (architecture validation). Phase B landed
same day (compute-only commands). Phase C landed 2026-05-19
(communication tests for OPTIGA + SE050 + USB integrity). Phase D
landed 2026-05-19 (interactive button test). Phase E landed
2026-05-19 (NS-launch fix + USB INS dispatch + full Python HID
framing). Phase F (operator manual photos) is tracked in work-todo §30.

Each `CMD_PRODTEST_*` is wired to a unique `INS_V2_PRODTEST_*` code
(0x80..0x89) in the v2 APDU dispatcher; see `proto/src/lib.rs` for
the canonical mapping. The mapping is mechanical: `INS = 0x80 +
(CMD - 100)`. The host runner (`tools/factory-prodtest-runner.py`)
ships the production framing (APDU-over-HID, 64-byte reports,
Ledger-compatible).

### CMD_PRODTEST_GET_ID (100)

Returns the STM32 chip UID + prodtest firmware version. Used by the
fixture's traceability database to log per-unit diagnostic data.

Response layout:
```
bytes  0..12  STM32U585 chip UID (96 bits, from MMIO 0x0BFA_0700)
bytes 12..16  Prodtest firmware version (u32 LE)
bytes 16..24  Reserved (zeroed; future: build-hash prefix)
```

Pass criterion: UID is neither all-zero nor all-`0xFF` (factory-blank
or fully-erased silicon).

### CMD_PRODTEST_DISPLAY_PATTERN (101)

Renders a known full-screen test pattern on the OLED for the
fixture's camera (or operator) to verify.

| Pattern ID | Visible result |
|---:|---|
| 0 | All rows solid (`################` × 4 rows) |
| 1 | All blank |
| 2 | Horizontal stripes (rows 0+2 solid, 1+3 blank) |
| 3 | Vertical stripes (`# # # # # # # # ` × 4 rows) |
| 4 | 8×8 checker |

Phase A note: these are text-grid approximations. A future phase
should reach into the SSD1306 framebuffer directly for true
per-pixel patterns. The text approximations are sufficient for
catching dead-pixel + connector-detach defects.

<!-- TODO photo: side-by-side OLED snapshots of each of the 5 patterns (WHITE / BLACK / HSTRIPES / VSTRIPES / CHECKER) on a known-good unit, so the operator can visually compare against the chip under test. -->

### CMD_PRODTEST_SAES_SELFTEST (102)

Runs the Tier-1 SAES self-test (round-trip encrypt under the DHUK
key selector) and returns the per-die fingerprint. The fixture
correlates this against the per-board expected value (recorded
during initial bring-up) or just logs it for the traceability DB.

Pass criterion: response status is `Ok` (peripheral round-trip
succeeded). The fingerprint is informational — per-die uniqueness
is naturally satisfied at RDP ≥ 1 (the silicon DHUK is per-die).

Requires the build to include both `prodtest` AND `saes-dhuk`
features. Without `saes-dhuk` the command returns `InternalError`
so the fixture knows Tier-1 wasn't actually validated.

### CMD_PRODTEST_BHK_SELFTEST (103)

Tier-2 BHK validation: encrypts a known block under the BHK key
selector. Returns the fingerprint.

Requires `prodtest,bhk,saes-dhuk`. Without `bhk` the command
returns `InternalError` (factory build profile chooses whether to
validate Tier-2 — for small-batch dev this can be skipped).

### CMD_PRODTEST_FLASH_RW (104)

Write a known pattern to a designated test flash page, read back,
verify integrity. Catches flash defects before they wedge a
customer wallet.

**Phase B stub**: the test page + helpers aren't carved out yet.
The command currently returns `InternalError` so the fixture knows
to skip this test until the helpers land (tracked in work-todo §30).

### CMD_PRODTEST_TRNG_SAMPLE (105)

Returns N bytes (1..=256) from the STM32 hardware TRNG, no SE XOR
mix. The fixture runs a statistical entropy check (χ² / Shannon /
distinct-byte-count) to detect a stuck-bit or biased TRNG.

The runner script uses a simple distinct-byte-count threshold: a
healthy TRNG returns at least 32 distinct byte values in 256 bytes.
A defective TRNG repeating the same byte or following a low-entropy
pattern fails this gate.

### CMD_PRODTEST_OPTIGA_HANDSHAKE (106)

Exercises the full IFX I²C → APDU stack against the OPTIGA Trust M
without touching any persistent chip state. The firmware lazily
runs `OptigaTrustM::init()` (RST pulse + `OpenApplication`) on first
call, then sends a `GetRandom(16)` APDU. On a fresh chip there's no
PBS yet, so the APDU goes through the plain (non-shielded) path —
this is exactly what the fixture wants to validate, since the
shielded connection requires `factory_provisioning` to have run.

Catches:
- missing chip / broken solder joint / I²C bus wedged
- RST line wrong (D6 = PE0 on B-U585I-IOT02A; `pin_diag::run` pulse
  must produce a visible falling edge)
- power-rail / clock issues (`OpenApplication` times out)
- chip RNG defect (returns all-zero or all-0xFF)

Pass criterion: response status is `Ok`, all 16 bytes received, AND
the bytes are neither all-zero nor all-0xFF. The host runner also
records the bytes for the per-die-uniqueness traceability database.

### CMD_PRODTEST_SE050_HANDSHAKE (107)

Same shape as OPTIGA_HANDSHAKE but for the SE050 T=1' + SCP03 stack.
`Se050::init()` runs `interface_reset` + ATR exchange + SCP03 session
setup with NXP's default platform keys, then `GetRandom(16)`. On a
fresh chip the default keys are still in place so the session opens
cleanly; on a partially-provisioned chip whose SCP03 keys were
rotated, this command fails — exactly the diagnostic signal the
operator needs.

Catches:
- missing chip / broken solder / I²C bus wedged
- ENA line wrong (SE050 stays in reset → no ATR)
- cold-boot timing issues (handled by the SE050 driver's 3-attempt
  retry loop in `Se050::init`)
- pre-rotated SCP03 keys (chip wasn't blank as expected)
- chip RNG defect

Pass criterion: same as OPTIGA_HANDSHAKE.

### CMD_PRODTEST_USB_LOOPBACK (108)

Echo N bytes back to the host. The fact that the firmware RECEIVED
the command already proves USB RX framing works; this command proves
TX + full round-trip byte integrity for non-trivial payloads up to
the 256 B per-call cap.

The host runner uses a deterministic test pattern: `byte[i] = i ^
0xA5` for `i ∈ [0, N)`. This catches:
- byte-substitution bugs (host sends 0x00 expects 0xA5)
- off-by-one in the USB transport layer (pattern shift would
  surface as a wrong byte at offset 0)
- bit-flip / bit-rot under sustained USB traffic
- buffer-overflow corrupting tail of payload

Pass criterion: every byte byte-identical to the input.

### CMD_PRODTEST_BUTTON_TEST (109)

Interactive 3-step button verification. The firmware drives the OLED
through the sequence "PRESS LEFT" → "PRESS RIGHT" → "PRESS BOTH",
giving the operator up to 10 s per step. The 4-byte output's first
byte encodes step status (compact nibble layout: upper = step,
lower = error kind):

| step_status | Outcome |
|---|---|
| `0x00` | all 3 steps passed |
| `0x11` | step 1 (LEFT) timeout — operator did not press LEFT in 10 s |
| `0x12` | step 1 (LEFT) **wrong button** — RIGHT pressed instead (swapped wires at the connector) |
| `0x21` | step 2 (RIGHT) timeout |
| `0x22` | step 2 (RIGHT) **wrong button** — LEFT pressed instead |
| `0x31` | step 3 (BOTH) timeout — operator pressed only one or neither |

Catches:
- mechanically dead buttons (membrane broken / spring missing)
- broken solder joint on either button
- L/R wires physically swapped at the connector (`0x12` / `0x22`)
- pull-up resistor open (button reads always-pressed → timeout fires
  on a different step than the operator intends)

Diagnostic distinction `timeout` vs `wrong button` matters: timeout
implies dead solder (re-solder + retry), wrong button implies
swapped wires (rewire + retry). Both are recoverable; the fix path
is different.

Pass criterion: `step_status == 0x00`. The firmware returns
`NscStatus::Ok` only when all 3 steps pass; any failure returns
`InternalError` with the diagnostic byte in the output buffer.

<!-- TODO photo: OLED showing each of the 3 button-test prompt panels (PRESS LEFT / PRESS RIGHT / PRESS BOTH) plus the BTN PASS / BTN FAIL outcome panels. -->

---

## Build + run

```bash
# Build the prodtest firmware (secure + nonsecure, both crates).
make build-hw-prodtest

# Flash + run sequence (the factory fixture's outer script wraps
# these into a per-unit operation):
#
#   probe-rs download $(NONSECURE_ELF) $(SECURE_ELF)
#   STM32_Programmer_CLI --optionbytes TZEN=1 ...
#   probe-rs reset
#   python tools/factory-prodtest-runner.py --report this-unit.json
#
# `factory-prodtest-runner.py` exits 0 if every test passed, non-
# zero on any failure. The fixture inspects this exit code (and the
# JSON report's `all_passed` field) to decide whether to chain
# `flash-hw-factory-provisioning` against the same chip.
```

---

## Pre-flight checklist

Run once at the start of every shift, before any units are tested:

1. **Fixture USB cable** — plug a known-good "golden" prodtest unit
   in, run the runner, confirm all 10 commands pass. If they fail
   on the golden unit, the fixture cable / hub / driver host is the
   problem, not the units under test.
2. **probe-rs flash speed** — flash one unit and time it. > 30 s
   for a ~250 KB firmware indicates a debug-adapter or USB hub
   issue; debug before continuing.
3. **Operator station lighting** — `DISPLAY_PATTERN(0)` (all
   solid) and `DISPLAY_PATTERN(1)` (all blank) on the golden unit
   should be visually distinguishable under the line's ambient
   lighting. If patterns blend, the operator can't visually verify.
4. **Anti-static wristband** continuity check — STM32U585 is CMOS;
   ESD on the test pad gates burns FETs before the unit reaches
   the customer. Drains must read < 10 Ω to grounded mat.
5. **Defective-unit bin labeled** — when prodtest fails, that
   unit goes in a tagged bin for triage, NOT back on the line.

<!-- TODO photo: fixture wiring diagram showing probe-rs cable + USB-C cable + unit under test + golden reference unit positions. -->

---

## Troubleshooting matrix

When prodtest reports a failure, the per-command output (status SW
+ raw_response bytes in the JSON report) maps to one of these
remediation classes. The fixture operator picks the matching row;
escalation to vendor (`REPORT VENDOR`) means "set this unit aside
and contact the firmware team — don't repair on the line."

| Command | Failure mode | Likely root cause | Action |
|---|---|---|---|
| GET_ID | `uid == 0x00 × 12` | STM32 boot ROM dead / OTP unreadable | REPORT VENDOR |
| GET_ID | `uid == 0xFF × 12` | OTP wiped or chip never booted | REPORT VENDOR |
| GET_ID | timeout / no response | USB cable unseated, fixture mis-wired, NS world never reached | Reseat cable + retry; if persistent → REPORT VENDOR |
| DISPLAY_PATTERN | OK status, OLED black | OLED I²C dead / connector loose | Reseat connector; if persistent → set aside |
| DISPLAY_PATTERN | OK status, pattern smeared | OLED contrast drift | Set aside (cosmetic — would ship but operator can't verify) |
| SAES_SELFTEST | `SW_INTERNAL_ERROR` | SAES peripheral defective OR `saes-dhuk` feature missing from build | Re-verify build profile; if profile correct → REPORT VENDOR |
| SAES_SELFTEST | all-zero fingerprint | DHUK not provisioned (silicon defect — DHUK is per-die intrinsic) | REPORT VENDOR |
| BHK_SELFTEST | `SW_INTERNAL_ERROR` | BHK feature off in build, or BHK not loaded into TAMP backup regs | Re-verify build (`bhk + saes-dhuk` enabled); if both on → REPORT VENDOR |
| FLASH_RW | `SW_INTERNAL_ERROR` (Phase B stub) | Test-page helpers not yet wired — known-not-implemented | Skip — pass criterion is "command is reachable", not the round-trip itself |
| TRNG_SAMPLE | `< 32 distinct bytes in 256` | STM32 TRNG stuck or biased | REPORT VENDOR — this chip can never be a wallet |
| OPTIGA_HANDSHAKE | `SW_INTERNAL_ERROR` | OPTIGA I²C unwired, RST line floating, OPTIGA chip absent | Reseat OPTIGA shield; rewire RST jumper (D6 → PE0); if persistent → set aside |
| OPTIGA_HANDSHAKE | `rng == 0x00 × 16` or `0xFF × 16` | I²C bus pulled to GND/VCC | Reseat shield; if persistent → set aside |
| SE050_HANDSHAKE | `SW_INTERNAL_ERROR` | SE050 absent, ENA line wrong, SCP03 default keys pre-rotated | Reseat SE050 shield; if persistent → set aside |
| SE050_HANDSHAKE | `rng == 0x00 × 16` or `0xFF × 16` | I²C bus pulled to GND/VCC | Reseat shield; if persistent → set aside |
| USB_LOOPBACK | byte mismatch at offset N | USB OTG TX corruption or HID fragmentation bug | If only this unit → set aside; if multiple → REPORT VENDOR (likely firmware) |
| USB_LOOPBACK | timeout / SW_WRONG_LENGTH | Unit reboots mid-command (power instability) | Check power supply current limit; replace USB cable |
| BUTTON_TEST | step_status `0x11` / `0x21` | LEFT / RIGHT button mechanically dead | Re-solder button; retry. If persistent → set aside |
| BUTTON_TEST | step_status `0x12` / `0x22` | LEFT/RIGHT wires SWAPPED at connector | Rewire connector; retry |
| BUTTON_TEST | step_status `0x31` | Operator did not press both buttons; OR right button works alone but left doesn't | First retry with explicit "press both at once" demo; if persistent → re-solder LEFT button |

REPORT VENDOR means: tag the unit, photograph the per-unit JSON
report, log the chip's UID + lot number, and send the lot info to
the firmware team. Don't attempt board-level repair on a chip whose
silicon has a defect — repair time will exceed the unit's BOM cost.

<!-- TODO photo: per-status decision tree as a printable wallchart for the fixture operator. -->

---

## Engineering reference

### Source map

- Firmware command handlers: `secure/src/nsc/prodtest.rs`
- Command IDs: `proto/src/lib.rs::CMD_PRODTEST_*`
- CMSE veneers (NS→S entry): `secure/src/nsc/mod.rs::nsc_prodtest_*`
- main.rs short-circuit: `#[cfg(feature = "prodtest")]` block after
  the existing `factory-provisioning` short-circuit
- Cargo feature: `prodtest = ["dual-se", "stm32u585", "ui-oled", "usb"]`
- Build target: `make build-hw-prodtest`
- Host-side fixture runner: `tools/factory-prodtest-runner.py`
- Host tests: `cargo test -p sphincs-tz-secure prodtest::tests`
  (4 tests pinning the UID layout + FW version + buffer sizes)

### Build profile safety

Same compile fence as `factory-provisioning`:

| Combination | Result |
|---|---|
| `prodtest + dev-testkey` | builds (dev-safe) |
| `prodtest + bhk` (no opt-in) | **compile error** |
| `prodtest + optiga-lock-operational` (no opt-in) | **compile error** |
| above + `factory-production-irreversible-im-sure` | builds |

Mass-production builds will be `prodtest + saes-dhuk + bhk +
factory-production-irreversible-im-sure` (Phase D in work-todo
§30) so the full Tier-1 + Tier-2 self-test paths are exercised.

### Wire format (Phase E — production framing)

`tools/factory-prodtest-runner.py::ProdtestTransport` wraps each
`CMD_PRODTEST_*` as a v2 APDU and fragments it into 64-byte HID
reports per the Ledger-compatible framing in
`shared/src/apdu_framing.rs`:

```
APDU:   [CLA=0xF0][INS=0x8x][P1=0x00][P2=0x00][LC][data]
HID 0:  [chan(2 BE)][tag=0x05][seq=0x0000][total_len(2 BE)][data ≤ 57 B]
HID N:  [chan(2 BE)][tag=0x05][seq(2 BE)][data ≤ 59 B]
```

The response is the inverse: HID frames reassemble into an APDU
whose last 2 bytes are the ISO 7816-4 status word (`SW_OK = 0x9000`
on success, `SW_INTERNAL_ERROR = 0x6F00` on chip / driver failure).
Output bytes are returned in `resp[:-2]`.

Linux hidapi requires a leading `0x00` report-ID byte on `write`
(kernel hidraw inspects byte 0 as the report ID). The transport
prepends it automatically; macOS / Windows behaviour is identical
since hidapi normalises the host-side API.

---

## Phases roadmap (work-todo §30)

| Phase | Scope | Status |
|---|---|---|
| A | Architecture: Cargo feature + 2 commands (GET_ID, DISPLAY_PATTERN) | **DONE** 2026-05-19 |
| B | Compute-only commands (SAES, BHK, FLASH_RW, TRNG_SAMPLE) | **DONE** 2026-05-19 |
| C | Communication tests (OPTIGA_HANDSHAKE, SE050_HANDSHAKE, USB_LOOPBACK) | **DONE** 2026-05-19 |
| D | Button test (BUTTON_TEST) | **DONE** 2026-05-19 |
| E | Host-side fixture runner (full USB HID framing) | **DONE** 2026-05-19 |
| F | Operator manual production-ready text (photos pending hardware bench) | **DONE** 2026-05-19 (text); photos blocked on hardware-on-bench session |
| G | Compile fences for the irreversible production profile | DONE 2026-05-19 |

Phase F note: every `<!-- TODO photo: ... -->` marker in this file
identifies a place where a visual aid would help the operator. The
markers describe what the photo should show; they do NOT paraphrase
the photo into prose because (a) the operator's authority is the
chip under test in front of them, not the manual, and (b)
descriptions of UI states age into wrong-but-shippable documentation
the moment the firmware changes a glyph. Photos land when the user
runs a hardware-on-bench session and a USB-C camera can capture the
fixture display.
