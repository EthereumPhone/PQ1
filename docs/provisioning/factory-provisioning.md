# PQSigner factory provisioning — operator manual

> **STOP — QUARANTINED 2026-07-11. Do not run this ceremony or bump RDP2.**
> The legacy receipt writes `BIT_RAN` at entry and then attempts to reprogram
> the same one-program-only STM32U585 OTP quad-word at completion. Production
> and rehearsal builds, both flash targets, and all RDP2 authority now fail
> closed. The procedure below is retained as historical design input only;
> it is not an operator instruction until a replacement receipt codec and the
> full production ceremony are independently reviewed.
>
> **Additionally (2026-07-14, work-todo #36): the production model no longer
> includes ANY factory RDP2 bump.** Devices ship at RDP-0 (user-verifiable
> over SWD before first power) and the device self-locks to RDP-2 on the first
> field boot, then self-provisions pairing keys on-device. The factory scope
> is flash + option-byte profile (everything except RDP-2) + SE-internal
> lockdown on transport keysets.
>
> **The current candidate factory ⇄ first-boot responsibility split lives in
> [`first-boot-provisioning.md`](first-boot-provisioning.md#authoritative-factory--first-boot-responsibility-split)**
> — keep that table and this note in sync. It describes the candidate code and
> is not an approved irreversible ceremony. Factory-side, in one line: flash the
> reproducible image; set the option-byte profile (TZEN/SECWM/SECBOOTADD0/WRP1A/
> BOR/BOOT_LOCK/OEM — **everything EXCEPT RDP**, which stays 0); burn the OTP
> master; provision the SE-internal structure + irreversible locks
> (LcsO=Op ratchet, S-1/S-2/S-3, admin UserID, E120 LUC, the real type-`0x11`
> anchor pool `{0xE0E8, 0xE0E9, 0xE0EF}` — **S-2, policy still unapproved, and
> NOT `0xE0E3`/`0xE0E4..0xE0E8`; see the CORRECTION 2026-07-26 block in
> [`first-boot-provisioning.md`](first-boot-provisioning.md)** —
> #22 manifest) onto per-device **transport** keysets (SCP03 under
> `PLATFORM_DEK`; transport PBS at E140 kept `Conf(E140)`-rotatable); read-back
> QA; box + ship at RDP-0. The device (not the factory) programs RDP=0xCC and
> rotates the transport keysets to their final values on the first field boot.
> (Amendment: the self-lock is implemented in the secure app, not the FSBL —
> see the #36 note in `first-boot-provisioning.md`.) The handoff/receipt,
> recovery/KVN, E140-order, and silicon gates named there remain OPEN.

This document is for the **factory operator** who flashes and runs
the factory firmware on a fresh PQSigner device. You do not need to
understand what each historical step intended to do. The current targets are
refusal-only and no device operation is authorized by this document.

Internal design notes for engineers are in
[`secure/src/factory_provisioning.rs`](../../secure/src/factory_provisioning.rs).

---

> **UPDATE 2026-10-27: owner direction changes this split (design only, NOT implemented).**
> The factory raises the MCU to **RDP-1** and installs the **final** SE050/OPTIGA credentials, derived on-die from the per-die DHUK alone (no page-126 BHK, no page-127 salt).
> It then regresses RDP 1→0 (mass erase) and ships at RDP-0 with only a small prover in flash.
> The user verifies the device in the Vault desktop app with a USB proof of secure erasure: fill all flash with random data, unplug and replug, read everything back.
> This reverses "no factory RDP burn of any level", "factory MUST NOT install a final credential", and the first-boot transport→final rotation.
> It also moves WRP staging from the factory to first boot.
> Until implemented, the text below still describes the current code.
> Design, prerequisites and the open RDP-1-in-transit caveat: [`user-device-verification.md` § USB path](../security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle).

## Current procedure: stop

There is no authorized factory procedure in this revision. All production and
rehearsal build/flash targets and the RDP2 target fail at make-evaluation time,
including under `make -i`. The host verifier's `--bump-rdp2` option always
refuses. `make factory-status-hw` is read-only, but every legacy sentinel value
is reported as **NOT RDP2 AUTHORITY** and returns nonzero.

Do not substitute a direct `cargo`, probe, programmer, or option-byte command.
The historical material below documents the rejected receipt design for review
only.

---

## Historical success panel — non-authoritative

```
┌────────────────┐
│ LEGACY BLOCKED │
│RECEIPT INVALID │
│  NO AUTHORITY  │
│  NOT FOR SHIP  │
└────────────────┘
```

This panel and its legacy receipt do not authorize shipping or RDP2. The host
fixture now reports the corresponding value as non-authoritative and exits
nonzero.

**Rehearsal mode panel** (developer-only build —
`make build-hw-factory-provisioning-rehearsal`):

```
┌────────────────┐
│ REHEARSAL OK  │
│  7/7  panels ok│
│ SE NOT changed │
│ NOT for ship!  │
└────────────────┘
```

This was the intended rehearsal panel. The build and flash targets are now
refusal-only because even rehearsal consumed the broken receipt QW. Use no
factory profile for LCD iteration until a replacement is reviewed.

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

### Step 7 — Write OTP sentinel

| Code      | Meaning                                          | Possible remedy                                                |
|-----------|--------------------------------------------------|----------------------------------------------------------------|
| `E0701`   | OTP sentinel write failed (flash controller)     | Re-flash + retry. If persistent, set aside.                    |
| `E0702`   | Legacy receipt QW is already nonblank | Stop. The value grants no RDP2 authority; set the unit aside. |

`E0702` is surfaced by step 3 (pre-populated state check). It
means a previous production ceremony has already completed on
this chip — re-running production firmware against it is refused
to prevent accidental wipes of a fielded device.

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

### Source map

- Firmware source: `secure/src/factory_provisioning.rs`
- Step list + error codes: `FactoryStep` + `FactoryErrorCode` enums in that file
- OTP sentinel API: `secure/src/hw/otp.rs::factory_sentinel_{read,record}`
- Host-side verifier: `tools/factory-provisioning-verify.sh`
- Production/rehearsal build and flash targets: refusal-only quarantine gates
- RDP2 target: refusal-only quarantine gate
- Read-only legacy sentinel report: `make factory-status-hw` (always
  non-authoritative and nonzero)
- Host tests: `cargo test -p sphincs-tz-secure factory_provisioning`
  (7 tests pinning the step / error / display invariants)

### OTP sentinel format

The factory ceremony writes a 32-bit sentinel at OTP byte offset
160 (`0x0BFA_00A0`). The bits are:

| Bit | Mask          | Cleared by                                 |
|-----|---------------|--------------------------------------------|
| 0   | `0x01`        | Any factory ceremony completion (sentinel) |
| 1   | `0x02`        | Rehearsal mode completion                  |
| 2   | `0x04`        | Production mode completion                 |
| 3–31| reserved      | (must remain `1`)                          |

Read via probe-rs at `0x0BFA_00A0` (4 bytes, little-endian). The
host fixture interprets:

| Raw value     | Historical meaning                     | RDP2 authority? |
|---------------|----------------------------------------|-----------------|
| `0xFFFFFFFF`  | never ran                              | **NO**          |
| `0xFFFFFFFE`  | ran but didn't complete (interrupted)  | **NO**          |
| `0xFFFFFFFC`  | legacy rehearsal bits                  | **NO**          |
| `0xFFFFFFFA`  | legacy production bits                 | **NO**          |
| `0xFFFFFFF8`  | legacy combined bits                   | **NO**          |

Anything else (e.g., the high bits cleared) is a corrupt sentinel
and should be treated as failure.

### RDP2 — no authority in this revision

RDP2 is irreversible, and no legacy receipt value is a valid prerequisite for
it. The repository contains no enabled command that may perform the bump. A
replacement ceremony needs a new receipt codec, independent review, exact
owner authorization, and later named-board evidence.

### Build profile safety guards

The rollback quarantine supersedes the old opt-in matrix. Every factory profile
is currently rejected before compilation:

| Feature combination | Build result |
|---|---|
| any STM32U585 `factory-provisioning` profile | **compile error: `FW_ROLLBACK_FACTORY_BLOCKED`** |

The `factory-production-irreversible-im-sure` opt-in is a foot-gun
guard, not a security gate. Anyone editing the Cargo build profile
can add or remove it. The point is to make the irreversible build
profile something the developer must deliberately type — not
something they can stumble into by forgetting `dev-testkey` in a
Makefile target.
