# B-U585I-IOT02A Development Board Setup

**Board:** ST B-U585I-IOT02A (STM32U585AII6Q, Cortex-M33, 2 MB flash, 786 KB SRAM, TrustZone)

This guide walks through setting up the real development board to run PQSigner OS. The firmware uses TrustZone to split into a secure world (bank 1, 1 MB) and a non-secure world (bank 2, 1 MB), with the secure world handling all cryptographic operations.

> **Prerequisites:** A working Rust toolchain with the `thumbv8m.main-none-eabi` target, `arm-none-eabi-ld`, and the QEMU build working (`make all` succeeds). See the main README for base setup.

---

## 1. Physical Connection

The board has **two USB connectors**:

| Connector | Label | Type      | Purpose                        |
|-----------|-------|-----------|--------------------------------|
| CN8       | STLK  | Micro-USB | **ST-LINK/V3E debug probe** — use this one |
| CN1       | USB   | USB-C     | Target MCU USB OTG (not for debug) |

Connect a **Micro-USB data cable** (not charge-only) to the **STLK (CN8)** port. You can optionally also connect USB-C for extra power, but the Micro-USB alone is sufficient.

After connecting, verify the ST-LINK appears:

```bash
lsusb | grep 0483
# Expected: Bus xxx Device xxx: ID 0483:374e STMicroelectronics STLINK-V3
```

The board's COM LED (LED3) should be green or blinking green, indicating active debug communication.

---

## 2. Install Tools

### probe-rs (flash and run)

```bash
cargo install probe-rs-tools
```

Verify:

```bash
probe-rs list
# Expected: [0]: STLink V3 -- 0483:374e:... (ST-LINK)
```

### udev rules (Linux, non-root access)

```bash
curl -fsSL https://probe.rs/files/69-probe-rs.rules | sudo tee /etc/udev/rules.d/69-probe-rs.rules > /dev/null
sudo udevadm control --reload-rules && sudo udevadm trigger
```

**Unplug and re-plug the Micro-USB cable** after installing the rules.

### STM32CubeProgrammer (option byte configuration)

Download from [st.com/en/development-tools/stm32cubeprog.html](https://www.st.com/en/development-tools/stm32cubeprog.html) (free ST account required), then run the Linux installer. Ensure `STM32_Programmer_CLI` is on your PATH:

```bash
export PATH="$PATH:$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin"
```

STM32CubeProgrammer is needed for TrustZone option byte programming. It uses the ST-LINK's proprietary protocol for full secure access — probe-rs and OpenOCD cannot write secure option bytes (SECWM, SECBOOTADD0) when TZEN=1.

### Verify connectivity

```bash
probe-rs info --protocol swd
# Should show: Cortex-M33 r0p4, STMicroelectronics debug port
```

---

## 3. Build the Firmware

The `stm32u585` feature flag switches from QEMU addresses to real STM32U585 addresses throughout the codebase (memory maps, SAU/GTZC, shared gateway).

```bash
make build-hw
```

This builds both worlds with features `mock-se,debug-log,ui-semihosting,stm32u585`:

| World      | Flash address   | Alias  | Bank |
|------------|-----------------|--------|------|
| Secure     | `0x0C000000`    | S      | 1    |
| Non-secure | `0x08100000`    | NS     | 2    |

Verify the ELF addresses are correct:

```bash
arm-none-eabi-readelf -l target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure | head -10
# Entry point should be 0x0c000xxx, LOAD at 0x0c000000

arm-none-eabi-readelf -l target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure | head -10
# Entry point should be 0x08100xxx, LOAD at 0x08100000
```

---

## 4. Flash the Firmware

Flash both ELFs to the board via probe-rs:

```bash
probe-rs download --chip STM32U585AIIx target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
probe-rs download --chip STM32U585AIIx target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
```

The secure world (~315 KB) takes about 20 seconds to flash.

---

## 5. Configure TrustZone Option Bytes

This step configures the STM32U585's TrustZone hardware. It only needs to be done **once** after a chip erase or on a fresh board. Subsequent firmware updates (step 4) preserve the option bytes.

> **Important:** probe-rs's flash algorithm may clear TZEN during programming. Always re-run this step after flashing.

The option bytes to set:

| Register      | Offset | Value        | Meaning                              |
|---------------|--------|--------------|--------------------------------------|
| OPTR          | 0x40   | bit 31 = 1   | TZEN = 1 (enable TrustZone)          |
| SECWM1R1      | 0x50   | `0x007F0000` | Bank 1 pages 0–127 secure (all 1 MB) |
| SECWM2R1      | 0x60   | `0x0000007F` | Bank 2 all non-secure (PSTRT > PEND) |
| SECBOOTADD0R  | 0x4C   | `0x00180000` | Secure boot from `0x0C000000`        |

Run with STM32CubeProgrammer:

```bash
STM32_Programmer_CLI --connect port=SWD \
  --optionbytes TZEN=1 \
  SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
  SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 \
  SECBOOTADD0=0x180000
```

You should see `Option Bytes successfully programmed` in the output.

---

## 6. Run

```bash
probe-rs run --chip STM32U585AIIx target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
```

Expected output:

```
[S] Secure world starting...
[S] SAU + MPC configured
[S] UI initialized
[S] Unprovisioned — running first-boot wizard
    +----------------+
    |                |
    |Set new PIN     |
    ...
```

### One-command shortcut

`make flash-hw` does steps 3–6 in sequence (build, flash, configure OBs, run).

---

## 7. Memory Map (Real Hardware vs QEMU)

### Secure world

| Region        | QEMU mps2-an505      | STM32U585             |
|---------------|----------------------|-----------------------|
| Secure flash  | `0x10000000` (512 K) | `0x0C000000` (1 MB)   |
| NSC veneers   | `0x103FF000` (4 K)   | End of secure flash   |
| Secure SRAM   | `0x38000000` (128 K) | `0x30000000` (192 K)  |

### Non-secure world

| Region        | QEMU mps2-an505      | STM32U585             |
|---------------|----------------------|-----------------------|
| NS flash      | `0x00200000` (256 K) | `0x08100000` (1 MB)   |
| NS SRAM       | `0x28020000` (128 K) | `0x20030000` (64 K)   |

### SRAM allocation

| SRAM    | Size   | Security     | Alias          |
|---------|--------|-------------|----------------|
| SRAM1   | 192 KB | Secure      | `0x30000000`   |
| SRAM2   | 64 KB  | Non-secure  | `0x20030000`   |
| SRAM3   | 832 KB | Non-secure  | (unused)       |

The shared-memory gateway mailbox is at the end of NS SRAM (`0x2802FF00` on QEMU). It is only used by the QEMU transport — on STM32U585 the gateway runs through CMSE `cmse-nonsecure-entry` veneers and the mailbox region is unused (the `SHARED_MAILBOX_BASE = 0x2003FF00` constant is still kept in `sphincs_tz_shared` so `ptr_validate` can exclude the range as a belt-and-braces measure, but no code reads or writes it).

---

## 8. Feature Flags

The `stm32u585` feature propagates through the workspace:

```
secure/Cargo.toml   → stm32u585 = ["sphincs-tz-shared/stm32u585"]
nonsecure/Cargo.toml → stm32u585 = ["sphincs-tz-shared/stm32u585"]
shared/Cargo.toml   → stm32u585 = []
```

What it switches:

| Component    | QEMU                       | STM32U585                     |
|--------------|----------------------------|-------------------------------|
| memory.x     | `memory.x`                 | `memory-stm32u585.x`         |
| SAU/MPC      | MPC (SSE-200 IoTKit)       | GTZC MPCBB (block-based)     |
| build.rs     | Patches link.x for NSC     | No patching needed            |
| NS_FLASH_BASE| `0x00200000`               | `0x08100000`                  |
| SYSTICK_RELOAD| 25000 (25 MHz)            | 4000 (4 MHz MSI default)      |
| Gateway addrs| `0x2802FF00`               | `0x2003FF00`                  |

---

## 9. Known Limitations

- **No interactive input via probe-rs.** The semihosting UI mock uses `SYS_READC` (operation `0x07`) for button input. probe-rs does not support this operation. `make e2e-hw` builds with `ui-semihosting,e2e-test` and boots fine — you'll see `[S] hash: HW SHA-256 self-test PASS`, provisioning complete, the NS-side test runner kick off — and then hang on the `Enter PIN` dialog because the NS driver calls `CMD_REQUEST_UNLOCK` even though the secure world pre-unlocked itself. You'll see a stream of `Target wanted to run semihosting operation 0x7 ... probe-rs does not support this operation yet. Continuing...` warnings.
  Workarounds (pick by what you're testing):
  - **Signing speed / correctness, fully automated:** `make test-key-speed` — DWT-timed bench, no semihosting reads, prints `=== PASS ===` on success. With `hw-sha256` active (implied by `stm32u585`) expect first-sign ≈ 2.77 s on 160 MHz. Any number much higher means the HASH peripheral isn't on.
  - **Driving the wallet by hand on real hardware:** `make play-hw-display` — uses `tools/wallet_run_hw.py` to forward arrow keys through a probe-rs `print`-based handshake (not `SYS_READC`), drives the physical SSD1306 OLED.
  - **Full semihosting console:** **GDB with OpenOCD** instead of probe-rs — `arm-none-eabi-gdb` + `openocd` handle `SYS_READC` correctly, so `make e2e-hw` will actually run to completion.
  - **On-board buttons:** wire real GPIO buttons + OLED (`ui-oled,gpio-buttons`) and drive the device standalone with no debugger at all.

- **HW SHA-256 self-test gates signing.** On `stm32u585` builds, `hw::hash::init_clock()` runs a `SHA-256("abc")` known-answer test at boot and halts the CPU in `loop { wfe() }` on mismatch. You'll always see exactly one of:
  ```
  [S] hash: HW SHA-256 self-test PASS
  [S] hash: HW SHA-256 self-test FAIL — HALT
  ```
  The `stm32u585` feature implies `hw-sha256`, so every real-hardware build routes every SPHINCS+C11 and JARDIN FORS+C hash through the STM32U585 HASH peripheral. Software `sha2::Sha256` is only used on host tests / QEMU.

- **Running at 160 MHz** (post `85673a8`). The firmware configures PLL1 to drive the CPU at 160 MHz via `hw::rcc::init()`. Matches the VOS Range 1 / flash latency combo the datasheet specifies. On 16 MHz HSI fallback builds (ancient commits) signing is ~10× slower.

- **Hardware TRNG.** The `hw::rng` module uses the STM32U585's True Random Number Generator peripheral, clocked by HSI48. This replaces the semihosting `/dev/urandom` backend used on QEMU.

---

## 10. Troubleshooting

### ST-LINK not detected

- Ensure the **Micro-USB (STLK/CN8)** port is connected, not the USB-C
- Try a different cable (must be a data cable, not charge-only)
- Check `lsusb | grep 0483` — should show `0483:374e`

### probe-rs permission denied (errno 13)

```bash
# Install udev rules
curl -fsSL https://probe.rs/files/69-probe-rs.rules | sudo tee /etc/udev/rules.d/69-probe-rs.rules > /dev/null
sudo udevadm control --reload-rules && sudo udevadm trigger
# Unplug and re-plug the board
```

### Option bytes not taking effect

- Use STM32CubeProgrammer (not OpenOCD) for option byte programming — OpenOCD's HLA transport cannot write secure option bytes when TZEN=1
- After `probe-rs download`, re-run the STM32CubeProgrammer option byte command (probe-rs may clear TZEN during flash programming)
- Verify with: `STM32_Programmer_CLI --connect port=SWD --optionbytes displ | grep -E "TZEN|SECWM2"`

### Firmware crashes or HardFault after flash

- The option bytes might be misconfigured. Re-run step 5
- Check that both ELFs were flashed (nonsecure first, then secure)
- Verify the build used the `stm32u585` feature: `arm-none-eabi-readelf -l <elf> | grep 0x0c` should show the secure flash address

### Reverting TrustZone (nuclear option)

TZEN can only be cleared via RDP regression (Level 0 → Level 1 → Level 0), which **mass-erases all flash**. Only do this if the chip is bricked:

```bash
# Step 1: Set RDP to Level 1 (0xBB)
openocd -f interface/stlink.cfg -f target/stm32u5x.cfg \
  -c "init; halt" \
  -c "stm32l4x option_write 0 0x40 0x1feff8bb 0x000000FF" \
  -c "stm32l4x option_load 0" -c "exit"

# Step 2: After power cycle, connect via system bootloader (UART/USB DFU)
# and set RDP back to Level 0 (0xAA). This triggers regression.
```
