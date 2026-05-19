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
landed 2026-05-19 (interactive button test). Phases E + F (host
fixture runner with full USB HID framing + operator manual photos)
are tracked in work-todo §30.

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
# Build the prodtest firmware
make build-hw-prodtest

# Phase B/C+: flash + run sequence (host fixture orchestration —
# not yet written; tracked in work-todo §30 Phase E)
#   probe-rs download $(NONSECURE_ELF) $(SECURE_ELF)
#   STM32_Programmer_CLI --optionbytes TZEN=1 ...
#   probe-rs reset
#   python tools/factory-prodtest-runner.py --report this-unit.json
```

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

### Wire format (current scaffold — needs bench validation)

The `tools/factory-prodtest-runner.py` script's transport layer is
a SCAFFOLD that documents the expected interface. The actual byte-
level USB HID framing must be aligned with `nonsecure/src/usb/
transport.rs` (the existing APDU-over-HID framing the production
wallet uses). Phase C of work-todo §30 covers wiring the runner
against the real USB transport.

Until then the script structure is correct (commands, response
parsing, pass/fail criteria) but no actual USB I/O happens — every
command returns `INTERNAL_ERROR` from the transport stub.

---

## Phases roadmap (work-todo §30)

| Phase | Scope | Status |
|---|---|---|
| A | Architecture: Cargo feature + 2 commands (GET_ID, DISPLAY_PATTERN) | **DONE** 2026-05-19 |
| B | Compute-only commands (SAES, BHK, FLASH_RW, TRNG_SAMPLE) | **DONE** 2026-05-19 |
| C | Communication tests (OPTIGA_HANDSHAKE, SE050_HANDSHAKE, USB_LOOPBACK) | **DONE** 2026-05-19 |
| D | Button test (BUTTON_TEST) | **DONE** 2026-05-19 |
| E | Host-side fixture runner (full USB HID framing) | TODO |
| F | Operator manual production-ready text + photos | TODO |
| G | Compile fences for the irreversible production profile | DONE 2026-05-19 |
