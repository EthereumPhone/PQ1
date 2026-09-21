# Sealed EVT dev loop — re-flash over USB-C with no probe and no special cable

**Status 2026-09-21: proven end to end on EVT #1** (AL_A66_MB_V10, sealed case,
STM32U585CIU6, SE050E2 + OPTIGA Trust M, NV3007 LCD). Edit any screen, run one
script, hold both buttons while plugging in, ~2 minutes later the new firmware
is on the panel. This file is the runbook for a person or an LLM picking up
that unit without the SBU-bridged adapter.

Read `evt-debug-pins.md` for *why* the board is like this (BOOT0 only reachable
through the USB-C sideband, no blank-flash bootloader entry on the U5, what the
ROM bootloader can and cannot do under TrustZone). This file is only *how*.

---

## 1. The loop

```
cd ~/Documents/PQ1/sphincs_rust-pq1          # worktree on branch pq1-evt-dfu (Nicola's feat/pq1-board-target + dev bits)
# edit anything: secure/src/ui/**, secure/src/tx/display/**, assets, lcd driver …
tools/evt-dev-flash.sh                        # builds the dev image, then waits
#   when it prints "waiting for 0483:df11":
#   HOLD BOTH BUTTONS, plug the USB-C cable in, keep holding ~2 s
#   (any plain USB-C cable to the laptop; the screen stays dark = bootloader)
# … ~1 min of "verified … / S head OK / NS head OK / DONE"
# unplug, plug in again normally → new firmware boots
```

`tools/evt-dev-flash.sh --no-build` re-flashes the last built image.

What you see on the LCD after a normal power-up: splash → PIN unlock (the
wallet on the two secure elements is already provisioned; the PIN is whatever
was set in the wizard). The wallet only enumerates on USB (`1209:7051`) after
unlock, so "no USB device" on a plain cable is normal, not a failure.

## 2. How it works (so you know what not to break)

Two halves, both bench-only and fenced out of production builds
(`PROD_FORBIDDEN` in the Makefile):

**Firmware, feature `dev-dfu`** (`secure/src/hw/dev_dfu.rs`, called from
`main.rs` immediately after `hw::rcc::init`, before any UI / SE / USB code):
if PA0 and PA1 (the two buttons, active-low) read pressed for 50 ms, it clears
the `nSWBOOT0` and `nBOOT0` option bits and reloads option bytes. Per RM0456
Table 26 / AN2606 Pattern 12 the U585 then boots the ROM bootloader regardless
of the BOOT0 pin and enumerates as USB DFU `0483:df11`.

**Host, `tools/evt-dev-flash.sh`**, driving `STM32_Programmer_CLI` over DFU:

| step | what | why |
|---|---|---|
| 1 | `SECWM1_PSTRT=0x7F SECWM1_PEND=0x0` (bank 1 non-secure) | with TZEN=1 the ROM bootloader runs non-secure and silently drops writes to a secure bank (reads come back as zeros) |
| 2 | `-e all` | under TZEN=1 the programmer classifies the address as "Not flash Memory" and skips its pre-write erase; a write over old contents can only clear bits and verify fails |
| 3 | write + verify `nonsecure.bin @0x08100000`, `secure.bin @0x08000000` (up to 3 attempts each) | the first download after an erase/OB reload sometimes fails with "failed to download Sector[0]"; the retry succeeds |
| 4 | `SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F` (bank 1 secure again) | the firmware expects the shipped TrustZone layout |
| 5 | `nSWBOOT0=1 nBOOT0=1` | boots flash and keeps the BOOT0-pin (adapter) path as a rescue |

Step 5 makes the chip leave the bus mid-command when DFU was entered by
software, so the programmer prints `Downloading Option Bytes Data failed /
Uploading Option Bytes bank: 0 failed`. That is the success case; the script
says so. TZEN, RDP (level 0), SECBOOTADD0 and SECWM2 are never touched, so no
TrustZone regression and no RDP excursion happen in this loop.

The dev image is the real firmware: `dual-se,dev-testkey,ui-lcd,dev-dfu,
stm32u585,usb,board-pq1`. It deliberately omits `optiga-hw-counter` (its first
provisioning rewrites OPTIGA F1D0 metadata irreversibly). Built binaries land
in `evt-images/dev/` (untracked).

## 3. Rules

1. **Never unplug between "mass erase" and "DONE".** The flash is blank in that
   window. If power is lost there, the unit has no firmware and no software
   DFU entry — only the SBU-bridged adapter (`evt-debug-pins.md`) or SWD on the
   J210 pads under the case can revive it.
2. **Do not edit `secure/src/hw/dev_dfu.rs` or its call site at the top of
   `main()`**, and do not move the call later in boot. Every dev image must
   carry it; a build that hangs before that check is a cable job again.
3. **Keep the feature list.** Dropping `dev-dfu` from `FEAT_S` in the script
   flashes an image that cannot re-enter DFU by itself.
4. Hold the buttons *before* applying power and keep holding through the
   first second. BOOT0 semantics do not apply here, but the check runs once,
   ~20 ms into boot.
5. `dev-dfu` is a bench backdoor into the bootloader. It is in
   `PROD_FORBIDDEN`; never add it to a shipping or `mode-production` build.

## 4. When it does not work

| symptom | meaning | do |
|---|---|---|
| script waits forever after the gesture, LCD shows the PIN screen | gesture not seen (buttons released too early, or pressed after power) | unplug, hold both buttons first, then plug |
| `lsusb -d 0483:df11` shows a device but the programmer says `DevID = 0x0000` / `Target device not found` | bootloader wedged after a failed transfer | unplug/replug (with the gesture) and re-run `--no-build` |
| `attempt 1 failed … retrying` | normal, see step 3 | nothing |
| `!! S head mismatch` / `could not be written after 3 attempts` | chip is in DFU with bank 1 non-secure and blank flash | leave it plugged in, re-run `tools/evt-dev-flash.sh --no-build` |
| LCD dark on a plain cable, no `0483:df11`, no `1209:7051` | no firmware (power lost mid-flash) or bank 1 left non-secure | adapter or SWD required; then `tools/flash-evt-dfu.sh <image-dir>` |
| option bytes show `nSWBOOT0=0 nBOOT0=0` and the chip stays in DFU | step 5 never ran | `STM32_Programmer_CLI -c port=USB1 -ob nSWBOOT0=1 nBOOT0=1` |
| DFU device present but `-ob displ` cannot read anything ("under Read Out Protection") | RDP is 1 — should not happen in this loop | `-tzenreg` regresses (mass erase), then `tools/flash-evt-dfu.sh` |

Inspect the chip any time it is in DFU (read-only):

```
STM32_Programmer_CLI -c port=USB1 -ob displ | grep -E 'RDP|TZEN|nSWBOOT0|nBOOT0|SECWM'
```

Expected at rest: `RDP 0xAA`, `TZEN 0x1`, `nSWBOOT0 0x1`, `nBOOT0 0x1`,
`SECWM1 0x0..0x7F`, `SECWM2 0x7F..0x0`.

## 5. Other images on the same loop

Any `board-pq1` image can ride this loop as long as it keeps `dev-dfu`:

- mock secure elements, full wizard, no SE traffic: swap `dual-se,dev-testkey`
  for `mock-se,dev-testkey` in `FEAT_S` (RAM-only mock: the wizard runs on
  every boot).
- display-only bench: `lcd-test,mock-se,debug-log,dev-testkey,ui-lcd,dev-dfu,
  stm32u585,usb,board-pq1` (PIN dialog loop; does not reach the wizard).
- `se-lcd-diag` (add to `FEAT_S`): shows TRNG / SE050 / OPTIGA / rng_strong
  results on the LCD and halts — the probe-less way to see why a boot stops.

Resetting the wallet on the two chips is the repo's `wipe-for-wizard` image
(add `dev-dfu` to its features and flash it the same way); it wipes both SEs
and the MCU PIN page and preserves lifecycle state, then the next boot runs
the wizard.

## 6. Host prerequisites

- `STM32_Programmer_CLI` on `PATH` (2.22.0 works), udev rule for `0483:df11`
  (`/etc/udev/rules.d/50-usb-conf.rules`, MODE 0666), `arm-none-eabi-objcopy`,
  the pinned Rust toolchain (`rust-toolchain.toml`).
- Plain USB-C cable to the laptop. USB 2.0 is enough; nothing here uses the
  sideband.
- The worktree: `~/Documents/PQ1/sphincs_rust-pq1`, branch `pq1-evt-dfu`
  (Nicola's `feat/pq1-board-target` plus the AW99703 backlight driver, the
  DFU scripts and `dev-dfu`). Without the backlight driver every LCD image on
  this board stays dark, so do not build EVT images from a branch that lacks
  `secure/src/hw/aw99703.rs`.
