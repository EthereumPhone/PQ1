# PQSigner factory provisioning — operator manual

This document is for the **factory operator** who flashes and runs
the factory firmware on a fresh PQSigner device. You do not need to
understand what each step does — you flash, power-cycle, watch the
OLED, and report the result.

Internal design notes for engineers are in
[`secure/src/factory_provisioning.rs`](../secure/src/factory_provisioning.rs).

---

## Quick procedure

1. **Flash the firmware** the vendor ships you, using
   `STM32_Programmer_CLI` (or the vendor-provided wrapper script).
2. **Configure the TrustZone option bytes** the vendor specifies
   (`TZEN=1`, secure-world memory split). The vendor's flash script
   does this for you.
3. **Power-cycle the device** (pull and reconnect VCC, or press the
   RESET button if equipped).
4. **Watch the OLED**. Expect either:
   - `FACTORY OK` → device is ready to ship.
   - `FACTORY FAIL @ STEP X` → device needs investigation. Note
     the displayed code and report it to the vendor.

The whole ceremony takes a few seconds. If the OLED is blank for
more than ~30 seconds, treat as failure and report.

---

## Success panel

```
┌────────────────┐
│  FACTORY OK    │
│  6/6  passed   │
│  POWER  OFF    │
│ READY TO SHIP  │
└────────────────┘
```

Power off. Pack and ship. End user will see a first-boot wizard at
their home asking them to set a PIN and back up their recovery
phrase — that part is **NOT** part of the factory ceremony.

---

## Failure panel

```
┌────────────────┐
│  FACTORY FAIL  │
│ STEP X/6 EXXXX │
│ <short hint>   │
│ REPORT VENDOR  │
└────────────────┘
```

- `X` = the step number (1-6) at which the ceremony stopped.
- `EXXXX` = the 16-bit error code in hex.
- The third line is a hint for the vendor's engineers — you can
  ignore it.

**What to do:** photograph or write down the displayed code and
send it to the vendor. Do **not** ship the device. Do **not**
re-flash the same firmware blindly — the vendor will tell you
whether a re-flash is safe or whether the device needs to be set
aside.

---

## Error code lookup

The table below is the engineering reference. As the factory
operator, you only need to report the displayed code; the vendor
uses this table to diagnose.

### Step 1 — Hardware self-test

| Code      | Meaning                                          | Possible remedy                                                |
|-----------|--------------------------------------------------|----------------------------------------------------------------|
| `E0101`   | SAES Tier-1 self-test failed                     | Re-flash, retry. If persistent, set aside — silicon defect.    |
| `E0102`   | BHK Tier-2 lifecycle failed                      | Re-flash, retry. If persistent, set aside — flash page 126.    |

### Step 2 — OTP master key

| Code      | Meaning                                  | Possible remedy                                                |
|-----------|------------------------------------------|----------------------------------------------------------------|
| `E0201`   | OTP master key mismatch / corrupt        | Set aside — OTP is one-way and corruption is unrecoverable.    |

### Step 3 — Pre-populated state check

| Code      | Meaning                                  | Possible remedy                                                |
|-----------|------------------------------------------|----------------------------------------------------------------|
| `E0301`   | Chip already has user wallet state       | Stop! This is not a fresh chip. Set aside, contact vendor.     |
| `E0302`   | Prior partial provisioning residue       | Run vendor's wipe firmware first, then re-flash factory.       |

### Step 4 — Dual-SE provisioning

| Code      | Meaning                                  | Possible remedy                                                |
|-----------|------------------------------------------|----------------------------------------------------------------|
| `E0401`   | Dual-SE provisioning failed (generic)    | Re-flash, retry. Common after a marginal contact / I²C noise.  |
| `E0402`   | OPTIGA Shielded-Connection handshake     | Check OPTIGA chip seating / I²C pull-ups. Re-flash, retry.     |
| `E0403`   | SE050 SCP03 key rotation failed          | Check SE050 chip seating / I²C pull-ups. Re-flash, retry.      |

### Step 5 — Wipe user state

| Code      | Meaning                                  | Possible remedy                                                |
|-----------|------------------------------------------|----------------------------------------------------------------|
| `E0501`   | factory_reset_admin failed mid-wipe      | Set aside — chip in inconsistent state. Contact vendor.        |

### Step 6 — Post-wipe validation

| Code      | Meaning                                  | Possible remedy                                                |
|-----------|------------------------------------------|----------------------------------------------------------------|
| `E0601`   | User state residue after wipe            | Set aside — wipe was incomplete. Contact vendor.               |
| `E0602`   | Admin path unreachable after wipe        | Set aside — chip damaged by partial wipe. Contact vendor.      |
| `E0603`   | PIN attempts counter (MCU page 124) dirty | Re-flash + retry. If persistent, set aside.                    |

---

## Re-running the factory firmware on the same device

The factory firmware refuses to run a second time on a chip that
already passed the ceremony (Step 3 catches this with code
`E0301`). This is a safety guard against accidentally wiping a
device that has already been shipped, used, and returned.

If a device legitimately needs to be re-provisioned (e.g.,
returned-from-customer for refurbishment), the vendor will provide
a **wipe firmware** that clears all user + admin state. Run that
first, then re-flash and re-run the factory firmware.

Never improvise. If anything feels wrong, set the device aside and
contact the vendor.

---

## What the factory ceremony does NOT do

The ceremony **does not**:

- Generate or display the user's recovery phrase. (That happens
  at the end user's home, during the first-boot wizard.)
- Set the user's PIN. (Also end-user wizard.)
- Sign any keys onto the device. (Bootstrap / slot keys are
  derived from the user's recovery phrase at first unlock.)
- Burn any irreversible OTP value that's specific to a customer.
  (The OTP master key is per-device but customer-agnostic.)

The factory ceremony leaves the device in a state where:

- Both secure elements are paired and have working SCP03 /
  Shielded-Connection channels.
- The MCU has its OTP master key and BHK provisioned.
- No user-identifying data is present anywhere.

End users complete setup at their own home, in private, with the
on-device wizard.

---

## Reporting template

When reporting a failure, the vendor needs:

1. **Displayed code**: `EXXXX` (the hex code from the OLED).
2. **Step number**: `X/6` (also from the OLED).
3. **Device serial / batch**: from the device's external label
   or the flash log printed by the vendor's flash script.
4. **Pre-flash state**: was this a brand-new chip, a re-flash, a
   returned device?
5. **Photo of the OLED** (helpful but not required).

Example report:

> Device serial `PQSx-2026-04-1234`. Brand-new chip from batch
> `2026-W18-A`. Flashed `pqsigner-factory-1.0.fw`. OLED shows
> `FACTORY FAIL`, `STEP 4/6 E0402`, `OPTIGA I2C?`. Re-flashed
> once, same result. Setting aside.

---

## Engineering reference

- Firmware source: `secure/src/factory_provisioning.rs`
- Step list + error codes: `FactoryStep` + `FactoryErrorCode` enums in that file
- Build target: `make build-hw-factory-provisioning`
- Host tests: `cargo test -p sphincs-tz-secure factory_provisioning`
  (5 tests pinning the step / error / display invariants)
