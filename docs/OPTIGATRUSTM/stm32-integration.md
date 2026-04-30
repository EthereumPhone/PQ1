# OPTIGA Trust M -- STM32U585 Integration Guide

## TRUSTMV3SHIELDTOBO1 on B-U585I-IOT02A

The TRUSTMV3SHIELDTOBO1 shield plugs into the Arduino R3 headers on the B-U585I-IOT02A dev board.

### Arduino R3 Header Pin Mapping

| Signal | Arduino Pin | STM32 Pin | Peripheral | Notes |
|--------|-------------|-----------|------------|-------|
| SDA | A4 / SDA | PB9 | I2C1_SDA | Open-drain, pull-up on shield |
| SCL | A5 / SCL | PB8 | I2C1_SCL | Open-drain, pull-up on shield |
| RST | Digital GPIO | TBD | GPIO output | Active LOW, push-pull |
| VCC | 3.3V | -- | Power rail | From board regulator |
| GND | GND | -- | Ground | Common ground |

**Note:** The exact RST and VCC-enable pin assignments depend on the shield schematic. Check the TRUSTMV3SHIELDTOBO1 documentation for the specific digital pin used for RST. Common choices are D6, D9, or D10.

### I2C Configuration

| Parameter | Value |
|-----------|-------|
| I2C peripheral | I2C1 |
| Slave address | `0x30` (7-bit) |
| Clock speed | 100 KHz (safe default), up to 400 KHz |
| Mode | Standard I2C, 7-bit addressing |
| Pull-ups | On shield board (typically 4.7k to 3.3V) |
| SDA | PB9 (AF4 for I2C1) |
| SCL | PB8 (AF4 for I2C1) |

### I2C Bus Sharing Considerations

The B-U585I-IOT02A has the SE050 on I2C (address `0x48`). If both OPTIGA Trust M (`0x30`) and SE050 (`0x48`) share the same I2C bus:
- Different addresses, so no conflict
- Use `embedded-hal-bus` `RefCellDevice` or `CriticalSectionDevice` to share the bus
- Alternatively, use separate I2C peripherals if available

If using separate I2C peripherals:
- I2C1 (PB8/PB9) for OPTIGA Trust M (via Arduino headers)
- I2C2 or I2C3 for SE050 (check board schematic for existing wiring)

## GPIO Requirements

### Minimum Required

| GPIO | Function | Config | Notes |
|------|----------|--------|-------|
| PB9 | I2C1_SDA | AF4, open-drain | Data line |
| PB8 | I2C1_SCL | AF4, open-drain | Clock line |
| PE0 | RST      | Push-pull output | Active LOW reset (Arduino D6 on B-U585I-IOT02A) |

### Optional

| GPIO | Function | Config | Notes |
|------|----------|--------|-------|
| TBD | VCC_EN | Push-pull output | Power control for cold reset |

## Hardware Initialization Sequence

### Cold Reset (Power-On or First Boot)

```
1. Configure GPIOs:
   - PB8, PB9 as I2C1 AF4 (open-drain)
   - RST pin as push-pull output, initially LOW
   - VCC_EN pin (if used) as push-pull output, initially LOW

2. Power cycle:
   a. Drive VCC_EN LOW (if using GPIO power control)
   b. Drive RST LOW
   c. Wait 2000 ms (RESET_LOW_TIME)
   d. Drive VCC_EN HIGH (apply power)
   e. Drive RST HIGH (release reset)
   f. Wait 12000 ms (STARTUP_TIME, worst case)
   [NOTE: Community reports shorter waits (~15 ms) may work for warm resets]

3. Configure I2C1:
   - 100 KHz clock (safe default)
   - 7-bit addressing
   - Slave address: 0x30

4. Wake chip:
   - Send I2C address probe (read 0 bytes at 0x30)
   - If NACK: retry up to 10 times with 500 us delay
   - Chip wakes from sleep on address detection

5. Negotiate protocol:
   a. Read I2C_STATE register (0x82): verify chip is responsive
   b. Read MAX_SCL_FREQU register (0x84): get max supported frequency
   c. If desired: switch to 400 KHz and update I2C_MODE (0x89)
   d. Read DATA_REG_LEN register (0x81): get max frame size

6. Initialize data link layer:
   - Reset sequence counters (tx=0, rx=0)
   - Send ReSynch control frame to synchronize with chip

7. Open application:
   - Send OpenApplication APDU (CMD 0x70)
   - AID: D2 76 00 00 04 47 65 6E 41 75 74 68 41 70 70 6C
   - Wait for success response (status 0x00)

8. (Optional) Establish Shielded Connection:
   - Perform 4-step handshake (see shielded-connection.md)

9. Chip is READY for commands
```

### Warm Reset (Soft Reset, No GPIO)

```
1. Write 0x0000 to register 0x88 (SOFT_RESET)
2. Wait ~15 ms
3. Re-open application (step 7 above)
```

### Timing Summary

| Phase | Duration | Notes |
|-------|----------|-------|
| RST hold LOW | 2000 ms | Hard requirement |
| Startup after RST release | 12000 ms | Conservative; may be faster |
| Address probe retries | 5--50 ms | 10 retries x 500 us |
| OpenApplication | ~20 ms | Typical |
| Shielded Connection handshake | ~100 ms | With key derivation |
| **Total cold boot** | **~14 s** | Conservative |
| **Total warm reset** | **~50 ms** | Soft reset path |

## Bare-Metal Rust Driver Architecture

### Trait Requirements

```rust
use embedded_hal::i2c::I2c;
use embedded_hal::digital::OutputPin;
use embedded_hal::delay::DelayNs;

pub struct OptigaTrustM<I2C, RST, DELAY> {
    i2c: I2C,
    rst: RST,
    delay: DELAY,
    // Protocol state
    tx_seq: u8,      // Data link transmit sequence (0-3)
    rx_seq: u8,      // Data link receive sequence (0-3)
    frame_size: u16, // Negotiated max frame size
    // Shielded connection state (optional)
    sc_session: Option<ShieldedSession>,
}
```

### I2C HAL Integration

The STM32U585 HAL (e.g., `stm32u5xx-hal` or raw PAC) provides `I2c` trait implementations:

```rust
// Register write (write reg_addr + data in one transaction)
fn write_register(&mut self, reg: u8, data: &[u8]) -> Result<(), Error> {
    let mut buf = [0u8; 278]; // max frame + 1 for reg addr
    buf[0] = reg;
    buf[1..1 + data.len()].copy_from_slice(data);
    self.i2c.write(0x30, &buf[..1 + data.len()])
}

// Register read (write reg_addr, then read)
fn read_register(&mut self, reg: u8, buf: &mut [u8]) -> Result<(), Error> {
    self.i2c.write_read(0x30, &[reg], buf)
}
```

### TrustZone Considerations

For the PQSigner OS architecture:

- **OPTIGA Trust M I2C bus must be secure-world-only**
  - Configure GTZC to restrict I2C1 peripheral to secure world
  - Same pattern as SE050 I2C and Tropic01 SPI

- **Platform Binding Secret storage**
  - Store in secure flash, SAES-wrapped (same pattern as Tropic01 pairing key)
  - Reserve a flash page for OPTIGA Trust M PBS

- **RST GPIO must be secure-world-only**
  - Prevent non-secure world from resetting the chip

## Bus Sharing with SE050

If both secure elements share I2C1:

```rust
use embedded_hal_bus::i2c::RefCellDevice;
use core::cell::RefCell;

let i2c_bus = RefCell::new(i2c1);

let optiga_i2c = RefCellDevice::new(&i2c_bus);
let se050_i2c = RefCellDevice::new(&i2c_bus);

let optiga = OptigaTrustM::new(optiga_i2c, rst_pin, delay);
let se050 = Se050::new(se050_i2c, se050_rst_pin, delay);
```

Different I2C addresses (`0x30` vs `0x48`) mean no address conflicts.

## Power Considerations

| Parameter | Value | Notes |
|-----------|-------|-------|
| VCC | 3.3V from STM32 board | Within 1.62--5.5V range |
| Active current | 6--15 mA | Configurable via OID 0xE0C4 |
| Sleep current | Very low | Auto-enters after configurable delay |
| Decoupling | 100 nF ceramic | Close to VCC/GND pins |

Configure current limitation via OID `0xE0C4` to match your power budget. Default is appropriate for most cases.

## Debugging Tips

1. **Chip not responding:** Check I2C pull-ups, verify 3.3V on VCC, ensure RST is HIGH
2. **NACKs on every probe:** Chip is in deep sleep or not powered. Hold RST LOW for 2s, release, wait 12s
3. **CRC errors:** Verify CRC-16 implementation matches Infineon's nibble-based algorithm (see ifx-i2c-protocol.md)
4. **OpenApplication fails:** Verify AID bytes are correct: `D2 76 00 00 04 47 65 6E 41 75 74 68 41 70 70 6C`
5. **I2C bus conflict:** If sharing bus, ensure guard times between operations to different slaves
6. **Logic analyzer:** Capture I2C traffic at register level first, then verify frame/protocol layers
