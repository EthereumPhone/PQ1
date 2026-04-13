# OLED Mirror — adding `mirror` support to a Makefile target

The `ui-mirror` Cargo feature + `tools/oled-mirror` host binary stream the
SSD1306 128×32 framebuffer over RTT to a scaled window on your PC, and
forward keyboard presses back to the firmware as button events. It
replaces `probe-rs run` for any `ui-oled` target where you'd rather not
squint at the physical OLED.

Run any mirror-enabled target with an extra `mirror` goal:

```
make qr-screen          # normal: runs on physical OLED
make qr-screen mirror   # streams to a host window, arrow keys drive UI
```

Currently wired: `qr-screen`, `play-hw-display`.

## Adding mirror support to a new target

The pattern is three edits:

### 1. Feature-set branch

Near the top of the target (or next to its existing feature variable),
add an `ifeq` that swaps `debug-log` for `ui-mirror` when `MIRROR=1`.
Dropping `debug-log` is mandatory: with `ui-mirror` active and no host
servicing semihosting `BKPT`s, any `secure_log!` call hangs the MCU.

```make
ifeq ($(MIRROR),1)
  MYTARGET_FEATURES := ui-oled,stm32u585,<your-other-flags>,ui-mirror
else
  MYTARGET_FEATURES := ui-oled,stm32u585,<your-other-flags>,debug-log
endif
```

### 2. Use the variable in the build

Replace the hard-coded feature list in the target's `cargo build` with
`$(MYTARGET_FEATURES)`:

```make
cargo build --release --target $(TARGET) --target-dir target/secure \
    -p sphincs-tz-secure --no-default-features \
    --features $(MYTARGET_FEATURES)
```

### 3. Swap the run step

Where the target currently has `probe-rs run ... $(SECURE_ELF)`, call
the shared `RUN_OR_MIRROR` recipe:

```make
$(call RUN_OR_MIRROR,$(SECURE_ELF))
```

If the target has conditional post-flash logic (like a Python launcher
alongside `probe-rs run`), wrap that branch in `ifeq`/`endif` so mirror
mode skips it:

```make
ifeq ($(MIRROR),1)
	$(call RUN_OR_MIRROR,$(SECURE_ELF))
else
	@python3 tools/wallet_run_hw.py
endif
```

## What the user experiences

- `make <target>` — unchanged, identical to before the edit.
- `make <target> mirror` — firmware rebuilt with `ui-mirror`, the host
  tool opens a scaled window showing the OLED, keyboard drives buttons.
- `make <target> MIRROR=1` — same as above (explicit variable form).

Key map inside the window (same byte protocol as the existing
semihosting bridge, so firmware `Input::wait_button` handles them
uniformly):

| Key                                  | Firmware event         |
|--------------------------------------|------------------------|
| `Left` / `h` / `a`                   | LEFT button, short     |
| `Right` / `l` / `d`                  | RIGHT button, short    |
| `Shift+Left` / `H` / `A`             | LEFT button, long      |
| `Shift+Right` / `L` / `D`            | RIGHT button, long     |
| `Esc`                                | quit the mirror tool   |

The window must have keyboard focus for key events to be forwarded.

## Constraints worth knowing

- **`ui-mirror` is debug-only.** `make prod-check` rejects any feature
  list containing it, in the same bucket as `debug-log`, `e2e-test`,
  `mock-se`, etc.
- **Single probe-rs session.** `RUN_OR_MIRROR` launches `oled-mirror`
  (which uses probe-rs as a library). Don't run `probe-rs run` or
  `wallet_run_hw.py` in parallel; one debug session per ST-LINK.
- **RTT control-block address.** The Makefile extracts `_SEGGER_RTT`
  from the flashed ELF via `arm-none-eabi-nm` and passes it as
  `--rtt-addr`. probe-rs's STM32U585 chip description doesn't list the
  secure SRAM alias at `0x30000000`, so a range scan misses it —
  `ScanRegion::Exact` is the reliable path.
- **Semihosting incompatibility.** Don't enable `debug-log` together
  with `ui-mirror`. The firmware's `secure_log!` macro calls semihosting
  `BKPT 0xAB`, which blocks forever unless a host is actively servicing
  it. `probe-rs run` services it; `oled-mirror` does not.
- **Button latency.** Firmware polls the down-channel roughly every
  8 ms (`nop` loop in `Input::wait_button`). Imperceptible in practice;
  tighten by reducing the nop count if you need faster response.

## Files involved

| Path | Role |
|------|------|
| `secure/src/ui/mirror.rs` | RTT init, `push()` for framebuffer, `try_read_button()` for input |
| `secure/src/ui/oled.rs::flush_fb` | calls `mirror::push()` before I2C write |
| `secure/src/ui/oled.rs::Input::wait_button` | polls `mirror::try_read_button()` under `ui-mirror` |
| `tools/oled-mirror/` | host binary: flashes? no. attaches RTT, opens winit window, forwards keys |
| `Makefile` | `MIRROR` var, `mirror` phony goal, `RUN_OR_MIRROR` recipe |
