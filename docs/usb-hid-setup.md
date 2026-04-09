# USB HID Setup Guide

USB HID transport for PQSigner on the B-U585I-IOT02A discovery board.

## Hardware Setup

### Board: B-U585I-IOT02A (MB1551)

**Jumper JP4** must be set to **5V_USB_STLK** (routes ST-LINK 5V to VDDUSB).
This powers the USB transceiver from the ST-LINK debugger connection.

**BT_PWR SELECT (SW5/SW6)**: Default positions (3V3 / USB) are fine.

### Cables

You need **two cables** connected simultaneously:

| Port | Cable | Purpose |
|------|-------|---------|
| **CN8** (micro-USB) | USB-A to micro-B | ST-LINK: flashing + debug + VDDUSB power |
| **CN1** (USB-C) | USB-C to USB-A | USB HID: host communication |

## Building

### Auto-provisioned test build (recommended for initial testing)

```bash
make build-hw-usb-test
```

This builds:
- **Secure world**: `mock-se` + `ui-noop` + `e2e-test` (auto-provisions, no interactive wizard)
- **Non-secure world**: `usb` feature (USB HID main loop)

No semihosting — runs standalone without debugger.

### Full build (with real UI/SE, for production)

```bash
make build-hw-usb
```

Requires OLED display + buttons for PIN entry / seed wizard.

## Flashing

```bash
# Flash both worlds
make flash-hw-usb-test

# Or manually:
probe-rs download --chip STM32U585AIIx target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
probe-rs download --chip STM32U585AIIx target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure

# Configure TrustZone option bytes (one-time)
STM32_Programmer_CLI --connect port=SWD \
    --optionbytes TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F \
    SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000

# Reset
probe-rs reset --chip STM32U585AIIx
```

After flashing, **unplug and replug the USB-C cable** from CN1 to trigger
fresh USB enumeration.

## Linux: udev rules

Required for non-root access (WebHID, hidapi, etc.):

```bash
sudo cp tools/99-pqsigner.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
# Unplug and replug the USB-C cable
```

Verify:
```bash
lsusb | grep 1209
# Should show: ID 1209:7051 Generic PQSigner OS

ls -la /dev/hidraw*
# PQSigner's hidraw should show crw-rw-rw-
```

## Testing with WebHID (Chrome)

Open `tools/webhid_test.html` in Chrome:

```bash
google-chrome tools/webhid_test.html
```

1. Click **Connect to PQSigner**
2. Select "PQSigner OS" in the device picker
3. Try **GET_APP_CONF** — returns firmware version + device info
4. Try **GET_PUBLIC_KEY** — returns SLH-DSA verifying key (32 bytes)

## USB Protocol

The device speaks a Keycard Shell compatible APDU-over-HID protocol:

- **VID/PID**: 0x1209 / 0x7051
- **USB Class**: Custom HID (Usage Page 0xFFA0)
- **Endpoints**: EP1 IN + EP1 OUT, 64-byte Interrupt, 1ms poll
- **Framing**: Ledger-compatible (channel ID + sequence + fragmentation)
- **APDU CLA**: 0xE0

### Commands

| INS | Name | Description |
|-----|------|-------------|
| 0x02 | GET_PUBLIC | Export SLH-DSA verifying key (32 bytes) |
| 0x04 | SIGN_ETH_TX | Sign EIP-1559 transaction |
| 0x06 | GET_APP_CONF | Firmware version + device info |
| 0x08 | SIGN_ETH_MSG | Sign Ethereum message (personal_sign) |
| 0x0C | SIGN_EIP712 | Sign EIP-712 typed data |
| 0x10 | GET_PIN_REMAINING | PIN attempts remaining |
| 0x12 | UNLOCK | PIN entry on device |
| 0xC0 | GET_RESPONSE | Retrieve remaining response data |

### Command chaining

For payloads > 255 bytes, use P1-based chaining:
- P1=0x00: First chunk
- P1=0x01: Continuation chunks
- Chain ends when Lc < 255 (last chunk)

### Large responses (signatures)

SLH-DSA signatures are 17,088 bytes. Responses > 253 bytes use
APDU-level chunking:
- First response: 253 bytes data + SW=0x61FF
- Host sends GET_RESPONSE (INS 0xC0) to drain remaining data
- Final chunk: remaining data + SW=0x9000

## Architecture

```
Host PC (WebHID / node-hid / hidapi)
    |
    | USB Full-Speed (12 Mbps)
    |
[64-byte HID reports]           ← USB HID transport
    |
[APDU-over-HID framing]        ← Ledger-compatible
    |
[APDU Command Router]          ← nonsecure/src/usb/commands.rs
    |
[NSC Gateway]                   ← Shared-memory mailbox
    |
[Secure World]                  ← SLH-DSA signing, PIN, ZK verify
```

USB runs entirely in the **non-secure TrustZone world**. The secure
world only handles cryptographic operations via the existing NSC gateway.

## Troubleshooting

**Device not appearing in `lsusb`**:
- Check JP4 is on 5V_USB_STLK
- Unplug and replug USB-C cable after flashing
- Verify ST-LINK micro-USB is also connected (powers VDDUSB)

**Chrome says "no compatible devices"**:
- Install udev rules and replug the cable
- Verify `ls -la /dev/hidraw*` shows `crw-rw-rw-` for PQSigner

**Device enumerates but doesn't respond**:
- The `e2e-test` build auto-provisions with a test mnemonic
- Without `e2e-test`, the device needs OLED + buttons for first-boot wizard
