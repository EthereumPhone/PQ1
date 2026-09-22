# PQSigner factory production-line test (prodtest)

The prodtest firmware is a **reversible acceptance-test candidate** for fresh
bench or sacrificial chips. Its supported profile validates the NV3007 LCD,
SAES/DHUK, MCU TRNG, both SE communication paths, USB, buttons, and identity.
BHK and flash writes are deliberately unsupported. No result grants authority
to continue into an irreversible factory or field ceremony.

Internal design notes for engineers are in
[`secure/src/nsc/prodtest.rs`](../../secure/src/nsc/prodtest.rs).

The former follow-on ceremony is quarantined in
[`factory-provisioning.md`](factory-provisioning.md). A passing prodtest result
does not satisfy, enable, or authorize that document's OTP, option-byte, E140,
or SE050 operations. Until a replacement lifecycle is reviewed, passing units
must be logged and set aside.

---

## Factory line workflow

```
┌──────────────────────────────────────────────────────────────┐
│  Per-chip flow on the factory line:                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. probe-rs download prodtest firmware                     │
│  2. Reset chip → LCD shows "PRODTEST READY"                 │
│  3. tools/factory-prodtest-runner.py over USB HID           │
│     - reads STM32 UID into fixture's traceability DB        │
│     - cycles display patterns (1 s each, camera verify)     │
│     - validates SAES/DHUK and a 254-byte TRNG sample         │
│     - verifies BHK + FLASH remain unsupported               │
│     - validates SE, USB-loopback, and button paths          │
│  4. On profile acceptance → log receipt + set unit aside │
│     On any fail → set chip aside, log offending CMD_ code  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

The runner exits 0 only when all eight required command classes pass and the
two unsupported probes return their exact non-authority responses. Those two
results are recorded as `SKIP_UNSUPPORTED` with `passed=false`; exit zero does
not mean every command passed. Exit 1 is a test/profile failure and exit 2 is a
runner/transport failure. With `--report`, the runner atomically replaces the
JSON receipt even after a transport exception whenever the destination remains
writable. The fixture MUST NOT chain `flash-hw-factory-provisioning` or infer
irreversible authority from an exit-zero result.

---

## Command reference

The prodtest firmware exposes 13 USB HID commands. All commands map
to `proto/src/lib.rs::CMD_PRODTEST_*`; keep these IDs STABLE so old
field reports stay interpretable.

| ID | Command | Input | Output | Profile policy |
|---:|---|---|---|---|
| 100 | `GET_ID` | — | 12 B UID ‖ 4 B fw_version ‖ 8 B reserved | required |
| 101 | `DISPLAY_PATTERN` | 4 B pattern (0..4) | — | required |
| 102 | `SAES_SELFTEST` | — | 8 B DHUK fingerprint | required |
| 103 | `BHK_SELFTEST` | — | 8 zero diagnostic bytes + `SW_INTERNAL_ERROR` | unsupported |
| 104 | `FLASH_RW` | 4 B test pattern | `SW_INTERNAL_ERROR` | unsupported |
| 105 | `TRNG_SAMPLE` | 4 B count (1..=254) | N B random | required |
| 106 | `OPTIGA_HANDSHAKE` | — | 16 B OPTIGA RNG | required |
| 107 | `SE050_HANDSHAKE` | — | 16 B SE050 RNG | required |
| 108 | `USB_LOOPBACK` | N B input (1..=254) | N B echo | required |
| 109 | `BUTTON_TEST` | — | 4 B step_status | required |
| 110 | `RGB_TEST` | 6 B `[r,g,b,gcc,en,rsv]` | 24 B scan ‖ ids ‖ reserved | required (pq1) |
| 111 | `RGB_OSD` | 4 B `[gcc,en,rsv,rsv]` | 24 B open/short scan | required (pq1) |
| 112 | `RNG_CONFIG` | — | 20 B `CR‖NSCR‖HTCR‖VER‖IDCODE` | required |

The runner emits this matrix, the host-required secure/nonsecure feature lists,
the 254-byte cap, and expected prodtest firmware version 5 in every JSON
receipt. The feature lists state fixture/build policy; they are not a
device-attested manifest. The versioned firmware behavior is bound separately
by the `GET_ID` result.
Its machine-readable policy classes are eleven `required`, zero `optional`, and
two `unsupported` commands. An
unexpected `Ok` from either unsupported command is profile drift and fails
acceptance.

Phase A landed 2026-05-19 (architecture validation). Phase B landed
same day (compute-only commands). Phase C landed 2026-05-19
(communication tests for OPTIGA + SE050 + USB integrity). Phase D
landed 2026-05-19 (interactive button test). Phase E landed
2026-05-19 (NS-launch fix + USB INS dispatch + full Python HID
framing). Phase F (operator manual photos) is tracked on `EthereumPhone/PQ1` (label `source:work-todo`, formerly work-todo §30).

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

Pass criterion: UID is neither all-zero nor all-`0xFF` (factory-blank or
fully-erased silicon), and the reported firmware version is exactly 5. A
different version is not interpreted under this profile: the runner records a
firmware/profile mismatch, emits the atomic non-green receipt, and sends no
subsequent command.

### CMD_PRODTEST_DISPLAY_PATTERN (101)

Renders a known full-screen test pattern on the NV3007 LCD for the
fixture's camera (or operator) to verify.

| Pattern ID | Visible result |
|---:|---|
| 0 | All rows solid (`################` × 4 rows) |
| 1 | All blank |
| 2 | Horizontal stripes (rows 0+2 solid, 1+3 blank) |
| 3 | Vertical stripes (`# # # # # # # # ` × 4 rows) |
| 4 | 8×8 checker |

These are text-grid approximations. A display-specific hardware harness can
reach into the NV3007 framebuffer directly for true
per-pixel patterns. The text approximations are sufficient for
catching dead-pixel + connector-detach defects.

<!-- TODO photo: side-by-side NV3007 LCD snapshots of each of the 5 patterns (WHITE / BLACK / HSTRIPES / VSTRIPES / CHECKER) on a known-good unit, so the operator can visually compare against the chip under test. -->

### CMD_PRODTEST_SAES_SELFTEST (102)

Runs the Tier-1 SAES self-test (round-trip encrypt under the DHUK
key selector) and returns the per-die fingerprint. The fixture
correlates this against the per-board expected value (recorded
during initial bring-up) or just logs it for the traceability DB.

Pass criterion: response status is `Ok` (peripheral round-trip
succeeded). The fingerprint is informational only. Prodtest runs in the
reversible RDP-0 acceptance phase, where it is not evidence of a final per-die
DHUK or credential.

The exact supported secure feature profile is
`prodtest,dev-testkey,saes-dhuk`. The command initializes SAES itself, runs the
software-key and DHUK round-trip/domain checks, then returns the first eight
bytes of `SAES-ECB(DHUK, b"PQSIGNER-SAES-v1")`. Without `saes-dhuk`, the
required command returns `InternalError` and acceptance fails.

### CMD_PRODTEST_BHK_SELFTEST (103)

The wire command is retained, but the supported prodtest profile never enables
`bhk`: doing so could consume persistent BHK state before acceptance testing is
complete and is a compile error. The command always returns eight zero
diagnostic bytes plus `SW_INTERNAL_ERROR`. The runner records that exact result
as non-passing `SKIP_UNSUPPORTED`; any other response fails the profile. Any
Tier-2 BHK characterization belongs in a separate, reviewed, owner-authorized
sacrificial harness.

### CMD_PRODTEST_FLASH_RW (104)

The reversible profile has no designated writable test page and grants no
flash-write authority. The stable command accepts the canonical four-byte
request but performs no write and returns `SW_INTERNAL_ERROR` with no data.
The runner records that exact result as non-passing `SKIP_UNSUPPORTED`; an
unexpected success is a profile-drift failure. Destructive flash
characterization requires a separate owner-authorized sacrificial harness.

### CMD_PRODTEST_TRNG_SAMPLE (105)

Returns N bytes (1..=254) from the STM32 hardware TRNG, no SE XOR
mix. The fixture runs a statistical entropy check (χ² / Shannon /
distinct-byte-count) to detect a stuck-bit or biased TRNG.

The runner script uses a simple distinct-byte-count threshold: a
healthy TRNG returns at least 32 distinct byte values in 254 bytes.
A defective TRNG repeating the same byte or following a low-entropy
pattern fails this gate.

### CMD_PRODTEST_OPTIGA_HANDSHAKE (106)

Exercises the full IFX I²C → APDU stack against the OPTIGA Trust M
without touching any persistent chip state. The firmware uses a
`prodtest`-only method that lazily runs `OptigaTrustM::init()` (RST pulse +
`OpenApplication`) on first call, then sends a plaintext `GetRandom(16)` APDU.
It refuses if pairing state was loaded or activated. Production `random()` is
unchanged and always requires the Shielded Connection. This validates only
reversible communication; it neither exercises nor authorizes a later
shielded-connection credential ceremony.

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
the shared 254-byte response-data cap (256-byte buffer minus status word).

The host runner uses a deterministic test pattern: `byte[i] = i ^
0xA5` for `i ∈ [0, N)`. This catches:
- byte-substitution bugs (host sends 0x00 expects 0xA5)
- off-by-one in the USB transport layer (pattern shift would
  surface as a wrong byte at offset 0)
- bit-flip / bit-rot under sustained USB traffic
- buffer-overflow corrupting tail of payload

Pass criterion: every byte byte-identical to the input.

### CMD_PRODTEST_BUTTON_TEST (109)

Interactive 3-step button verification. The firmware drives the NV3007 LCD
through the sequence "PRESS LEFT" → "PRESS RIGHT" → "PRESS BOTH",
giving the operator up to 10 s per step. The 4-byte output's first
byte encodes step status (compact nibble layout: upper = step,
lower = error kind):

| step_status | Outcome |
|---|---|
| `0x00` | all 3 steps passed |
| `0x11` | step 1 (LEFT) timeout — operator did not press LEFT in 10 s |
| `0x12` | step 1 (LEFT) **wrong button** — RIGHT pressed instead (swapped wires at the connector) |
| `0x13` | step 1 (LEFT) **release timeout** — button never released within the step budget (stuck/welded contact) |
| `0x21` | step 2 (RIGHT) timeout |
| `0x22` | step 2 (RIGHT) **wrong button** — LEFT pressed instead |
| `0x23` | step 2 (RIGHT) **release timeout** — button stuck/welded ON |
| `0x31` | step 3 (BOTH) timeout — operator pressed only one or neither |
| `0x33` | step 3 (BOTH) **release timeout** — a button is stuck/welded ON |

The post-press release wait shares the same per-step 10 s budget as the
press wait: a welded button fails the step with the `0x?3` code instead
of hanging the unit (which the runner would see as a HID timeout and
misreport as a harness error rather than a unit FAIL).

Catches:
- mechanically dead buttons (membrane broken / spring missing)
- broken solder joint on either button
- L/R wires physically swapped at the connector (`0x12` / `0x22`)
- welded / stuck button contacts (`0x13` / `0x23` / `0x33`)
- pull-up resistor open (button reads always-pressed → timeout fires
  on a different step than the operator intends)

Diagnostic distinction `timeout` vs `wrong button` matters: timeout
implies dead solder (re-solder + retry), wrong button implies
swapped wires (rewire + retry). Both are recoverable; the fix path
is different.

Pass criterion: `step_status == 0x00`. The firmware returns
`NscStatus::Ok` only when all 3 steps pass; any failure returns
`InternalError` with the diagnostic byte in the output buffer.

<!-- TODO photo: NV3007 LCD showing each of the 3 button-test prompt panels (PRESS LEFT / PRESS RIGHT / PRESS BOTH) plus the BTN PASS / BTN FAIL outcome panels. -->

---

## Build + run

```bash
# Build the prodtest firmware (secure + nonsecure, both crates).
make build-hw-prodtest

# Flash + run sequence (the factory fixture's outer script wraps
# these into a per-unit operation):
#
#   probe-rs download $(NONSECURE_ELF) $(SECURE_ELF)
#   probe-rs reset
#   python tools/factory-prodtest-runner.py --report this-unit.json
#
# This acceptance guide grants no option-byte authority. If a future test
# profile requires an option-byte transition, it needs a separate reviewed,
# owner-authorized plan naming the exact sacrificial unit and values.
#
# Exit 0 means the declared reversible profile was accepted: all required
# checks passed and both unsupported probes returned SKIP_UNSUPPORTED. It does
# not mean all ten commands passed. Exit 1 is a profile failure; exit 2 is a
# runner/transport failure. The atomic JSON receipt remains non-green in both
# cases. Never chain an irreversible provisioning target.
```

---

## Pre-flight checklist

Run once at the start of every shift, before any units are tested:

1. **Fixture USB cable** — plug a known-good "golden" prodtest unit
   in, run the runner, confirm eight required command classes pass and BHK plus
   FLASH are `SKIP_UNSUPPORTED`. If the profile fails
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
| DISPLAY_PATTERN | OK status, LCD black | NV3007 LCD interface dead / connector loose | Reseat connector; if persistent → set aside |
| DISPLAY_PATTERN | OK status, pattern smeared | LCD contrast drift | Set aside (cosmetic — would ship but operator can't verify) |
| SAES_SELFTEST | `SW_INTERNAL_ERROR` | SAES peripheral defective OR `saes-dhuk` feature missing from build | Re-verify build profile; if profile correct → REPORT VENDOR |
| SAES_SELFTEST | all-zero fingerprint | DHUK not provisioned (silicon defect — DHUK is per-die intrinsic) | REPORT VENDOR |
| BHK_SELFTEST | `SW_INTERNAL_ERROR` + 8 zero bytes | Expected unsupported capability | Record `SKIP_UNSUPPORTED` (`passed=false`); any other response fails the profile |
| FLASH_RW | `SW_INTERNAL_ERROR` + no data | Expected unsupported capability | Record `SKIP_UNSUPPORTED` (`passed=false`); any other response fails the profile |
| TRNG_SAMPLE | `< 32 distinct bytes in 254` | STM32 TRNG stuck or biased | REPORT VENDOR — this chip can never be a wallet |
| OPTIGA_HANDSHAKE | `SW_INTERNAL_ERROR` | OPTIGA I²C unwired, RST line floating, OPTIGA chip absent | Reseat OPTIGA shield; rewire RST jumper (D6 → PE0); if persistent → set aside |
| OPTIGA_HANDSHAKE | `rng == 0x00 × 16` or `0xFF × 16` | I²C bus pulled to GND/VCC | Reseat shield; if persistent → set aside |
| SE050_HANDSHAKE | `SW_INTERNAL_ERROR` | SE050 absent, ENA line wrong, SCP03 default keys pre-rotated | Reseat SE050 shield; if persistent → set aside |
| SE050_HANDSHAKE | `rng == 0x00 × 16` or `0xFF × 16` | I²C bus pulled to GND/VCC | Reseat shield; if persistent → set aside |
| USB_LOOPBACK | byte mismatch at offset N | USB OTG TX corruption or HID fragmentation bug | If only this unit → set aside; if multiple → REPORT VENDOR (likely firmware) |
| USB_LOOPBACK | timeout / SW_WRONG_LENGTH | Unit reboots mid-command (power instability) | Check power supply current limit; replace USB cable |
| BUTTON_TEST | step_status `0x11` / `0x21` | LEFT / RIGHT button mechanically dead | Re-solder button; retry. If persistent → set aside |
| BUTTON_TEST | step_status `0x12` / `0x22` | LEFT/RIGHT wires SWAPPED at connector | Rewire connector; retry |
| BUTTON_TEST | step_status `0x31` | Operator did not press both buttons; OR right button works alone but left doesn't | First retry with explicit "press both at once" demo; if persistent → re-solder LEFT button |
| BUTTON_TEST | step_status `0x13` / `0x23` / `0x33` | Button contact welded/stuck ON (never released within the step budget) | Replace button; if persistent → set aside |

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
- Exact secure build profile: `prodtest,dev-testkey,saes-dhuk`
- Exact nonsecure build profile: `stm32u585,usb,prodtest`
- Build target: `make build-hw-prodtest`
- Host-side fixture runner: `tools/factory-prodtest-runner.py`
- Host tests: `cargo test -p pqsigner-proto
  prodtest_response_cap_reserves_status_word` and `python3 -m unittest
  tools/test_factory_prodtest_runner.py -v`
- Exact software-only links use the two feature lists above with
  `--target thumbv8m.main-none-eabi --no-default-features`; they prove profile
  coherence, not hardware behavior.

### Build profile safety

`prodtest` is a reversible acceptance-test image. Its fence cannot be relaxed
by an irreversible acknowledgement:

| Combination | Result |
|---|---|
| `prodtest + dev-testkey + saes-dhuk` | exact supported secure profile |
| `prodtest + bhk` | **compile error** |
| `prodtest + real OTP path` | **compile error** |
| `prodtest + SE rotation / OPTIGA lifecycle / factory ceremony` | **compile error** |
| any row above + `factory-production-irreversible-im-sure` | **still a compile error** |

There is no mass-production prodtest profile that carries BHK or mutates
persistent security state. Tier-2 or destructive characterization uses a
separate, reviewed, owner-authorized sacrificial harness; it is not an
acceptance-test capability.

### Wire format

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
| B | SAES + TRNG required checks; BHK + FLASH negative capability checks | **DONE** (BHK/FLASH remain unsupported by design) |
| C | Communication tests (OPTIGA_HANDSHAKE, SE050_HANDSHAKE, USB_LOOPBACK) | **DONE** 2026-05-19 |
| D | Button test (BUTTON_TEST) | **DONE** 2026-05-19 |
| E | Host-side fixture runner (full USB HID framing) | **DONE** 2026-05-19 |
| F | Operator manual production-ready text (photos pending hardware bench) | **DONE** 2026-05-19 (text); photos blocked on hardware-on-bench session |
| G | Compile fences separating reversible prodtest from irreversible profiles | **DONE** |

Phase F note: every `<!-- TODO photo: ... -->` marker in this file
identifies a place where a visual aid would help the operator. The
markers describe what the photo should show; they do NOT paraphrase
the photo into prose because (a) the operator's authority is the
chip under test in front of them, not the manual, and (b)
descriptions of UI states age into wrong-but-shippable documentation
the moment the firmware changes a glyph. Photos land when the user
runs a hardware-on-bench session and a USB-C camera can capture the
fixture display.
