# SE050 Native UserID PIN Authentication

> **UPDATE 2026-10-13 (#855, Ledger Donjon report).** Everywhere this document
> says the UserID object holds, or is verified against, "the PIN", read **"the
> die-bound PIN credential"**. Until this date the firmware wrote the raw eight
> PIN digits into the UserID and presented them on every unlock, so reading the
> chip gave the PIN. The UserID value is now a 16-byte
> `PRF(DHUK, "pqsigner/pin-cred-E-v1" ‖ salt ‖ PIN)`
> (`secure/src/pin_credential.rs`), derived in the microcontroller before the
> SE050 driver is called; `ENTROPY_OBJ` holds `half_E` XOR a PIN-keyed mask
> from the same PRF. The SE050 still does the comparison and the counting
> itself, exactly as described below.
>
> One consequence for bench work: the UserID can only be deleted by a session
> that presents its own value (S-6). After a wipe the salt is gone, so on a
> shippable build that value can no longer be recomputed and the object stays
> on the chip. Bench builds (`e2e-test` / `otp-hardcoded-master-key`) use a
> fixed public salt **and a fixed public PRF key**, so the credential of a
> known test PIN is the same on every bench build whatever key root that
> build uses. `make se050-reset` and the e2e pre-clean decide the format once
> (a salt record on page 125 means "written by this scheme") and try every
> test PIN in that format, then the default PIN in the other: at most one
> attempt more than before.
>
> **Boards that hold a wallet written by firmware older than this change.**
> This firmware cannot open such a wallet, and there is deliberately no
> migration path (one would have to present the old raw PIN to a chip, and an
> emulated chip could then ask for it). What happens depends on the build:
>
> - **`e2e-test` images on dual-SE hardware** are not affected: at every boot
>   they wipe both chips, delete the SE050 user objects with the known test
>   PINs (old raw format first when page 125 holds no salt record), provision
>   afresh and unlock directly, without `gated_unlock` (`main.rs`, the
>   "dual-se pre-clean" block; not built under `e2e-skip-provision`).
> - **A bench image without `e2e-test`** (for example the EVT dev flow, where
>   `dev-testkey` implies `otp-hardcoded-master-key`): nothing is wiped at
>   boot. A PIN typed at the prompt derives a credential the chips never
>   stored, so the correct PIN is charged as a wrong one on page 124, OPTIGA
>   E120 and the SE050 UserID, and ten such tries end in the lockout wipe.
> - **An image with none of the bench features:** on SE050 and dual-SE
>   hardware the first boot finds a provisioned wallet with no salt and wipes
>   it. The boot wipe block is not compiled for an OPTIGA-only bench build
>   (`main.rs`, `any(feature = "se050", feature = "dual-se")`); there the
>   wallet is refused, without charging an attempt, until a reset tool
>   removes it.
>
> Where a wipe runs, the old user UserID object survives it (S-6),
> and `store_objects` refuses to provision while it exists
> (`Status(0x6986)`), so that SE050 cannot take a new wallet until the object
> is deleted by a session that presents the old PIN, or the OID range is
> bumped. That is the end state ten wrong PINs always had; what is new is
> reaching it with the right one.
>
> Bench boards are re-flashed and re-provisioned as a matter of routine
> (owner, 2026-10-13), so no data depends on this. The practical rule: remove
> an old wallet with something that knows its PIN (`make se050-reset`, or any
> `e2e-test` image, both of which cover the test PINs) rather than by typing
> the PIN into this firmware. Derived from the source; not exercised on a
> board.
>
> The builders in `se050/apdu.rs` no longer take `&[u8]`: they take
> `UserIdValue`, which is a typed credential, a 16-byte device secret, or a
> `&'static` constant. A PIN typed in at run time is none of those.

> **OID range note (2026-04-30 audit).** The OID values shown throughout this doc
> (`0x7B00_2000`, `0x7B04_xxxx`) are from the **v1/v2 era** and are no longer
> the live constants. The shipping range is **v6 = `0x7B10_xxxx`**:
>
> | Symbol            | v1/v2 (this doc) | v6 (shipping)   |
> |-------------------|------------------|-----------------|
> | `USERID_OBJ`      | `0x7B00_2000`    | `0x7B10_0000`   |
> | `ENTROPY_OBJ`     | `0x7B04_0000`    | `0x7B10_0001`   |
> | `VK_OBJ`          | `0x7B04_0002`    | `0x7B10_0002`   |
> | `BOOTSTRAP_VK_OBJ`| `0x7B04_0003`    | `0x7B10_0003`   |
> | `ADMIN_WIPE_OBJ`  | (n/a)            | `0x7B10_00A0`   |
>
> Authoritative constants live in `secure/src/se050/mod.rs:53,56,59,62,83`. The
> version history (v1 → v2 → v3 `0x7B06_xxxx` → v4 `0x7B0C_xxxx` → v5 → v6) is
> documented at `secure/src/se050/mod.rs:23-30`. Ranges retire as bench chips
> accumulate orphaned objects from earlier bring-up attempts (see Lesson 7
> below — stale objects are permanent until factory reset).
>
> The architecture, APDU formats, and hardware-debugging lessons in the rest of
> this document are still correct.

## Overview

PQSigner stores the user's BIP-39 entropy (the 32-byte secret behind their
24-word recovery phrase) on an NXP SE050 secure element. The SE050 is
tamper-resistant silicon — physically hardened against probing, fault
injection, and side-channel attacks. This document describes how we use the
SE050's native UserID authentication to hardware-enforce PIN verification,
replacing the earlier software-based MAC-and-Destroy (MACD) chain.

## Why Not MACD?

The previous design used an MACD chain: the MCU ran HMAC operations on the
SE050, then checked whether the result correctly decrypted a stored blob.
The security problem is that the **MCU makes the trust decision**. If an
attacker replaces the firmware, they can bypass the PIN check entirely. The
SE050 was just a dumb HMAC accelerator — it never knew whether the PIN was
right.

With UserID authentication, the SE050 hardware:

- Verifies the PIN internally (the MCU never sees the comparison)
- Counts failed attempts and locks after 10 failures
- Gates read access at the hardware level — no firmware exploit can bypass it

The security boundary moves from the MCU (which runs arbitrary firmware)
into the SE050 (which runs fixed, certified logic).

## Architecture

```
+---------------------------------------------+
| MCU (STM32U585, Cortex-M33 TrustZone)       |
|                                              |
|  Provisioning:                               |
|    1. SCP03 channel (platform keys)          |
|    2. WriteUserID(PIN, max_attempts=10)      |
|    3. WriteBinary(entropy, policy=UserID)    |
|    4. WriteBinary(VK, policy=UserID)         |
|                                              |
|  Unlock:                                     |
|    1. SCP03 channel                          |
|    2. CreateSession(UserID obj)              |
|    3. VerifySessionUserID(PIN) -- HW check   |
|    4. ReadObject(entropy) via session        |
|    5. master_secret = KDF(entropy)           |
|    6. Derive signing keys on MCU             |
|                                              |
|  I2C1 (PB8/PB9, 400 kHz)                    |
+----------------+----------------------------+
                 | T1oI2C framing
+----------------+----------------------------+
| SE050E (OM-SE050ARD, OEF 0xA921)            |
|                                              |
|  0x7B002000: UserID (PIN, 10 attempts)      |
|  0x7B040000: entropy (32B, policy->UserID)  |
|  0x7B040002: VK (32B, policy->UserID)       |
|  0x7B040003: bootstrap VK (32B, policy->VK) |
|                                              |
|  Hardware enforces:                          |
|    - PIN comparison (constant-time, on-chip) |
|    - Attempt counter (persists across reset) |
|    - Read gating (no session = no data)      |
+----------------------------------------------+
```

## SCP03 Channel

Before any UserID logic runs, we establish a GlobalPlatform SCP03
authenticated channel. This provides:

- **Integrity (C-MAC):** every command is CMAC-AES-128 signed with the
  session MAC key. The SE050 rejects tampered commands.
- **Confidentiality (C-DEC):** command data is AES-128-CBC encrypted. An
  I2C bus sniffer sees ciphertext, not plaintext PINs or entropy.

SCP03 uses factory-provisioned platform keys specific to the SE050E variant
(OEF 0xA921). Session keys are derived via NIST SP 800-108 KDF, so even if
one session's keys leak, past/future sessions remain secure.

Security level: P1=0x03 (C-MAC + C-DEC). The SE050E requires this for
administrative operations like creating auth objects.

Platform keys are in:
`plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h`
under `SSS_PFSCP_ENABLE_SE050E_0001A921`.

## Why Entropy Is Stored Unencrypted

In the MACD design, entropy was encrypted with `master_secret` derived from
itself (`master_secret = KDF("sphincs-master", entropy)`). The MACD chain
made the PIN necessary to recover `master_secret` and thus decrypt the
entropy.

With UserID, the SE050 hardware IS the protection — the object literally
cannot be read without a verified session. Encrypting would create a
circular dependency: you need `master_secret` to decrypt, but
`master_secret` is derived from the entropy you're trying to decrypt.

The SE050's tamper-resistant silicon provides equivalent (arguably stronger)
protection to AES-GCM encryption.

## SE050 Object Layout

| Object ID    | Type    | Contents                    | Policy              |
|--------------|---------|-----------------------------|----------------------|
| `0x7B002000` | UserID  | PIN value, max 10 attempts  | No auth required     |
| `0x7B040000` | Binary  | Raw entropy (32 bytes)      | Require UserID auth  |
| `0x7B040002` | Binary  | Verifying key (32 bytes)    | Require UserID auth  |
| `0x7B040003` | Binary  | Bootstrap VK (32 bytes)     | Require UserID auth  |

## Code Structure

### `secure/src/se050/mod.rs` — Public API (`Se050` struct)

- `Se050::init()` — T1oI2C reset, applet SELECT, SCP03 establish.
- `Se050::is_provisioned()` — checks UserID object existence.
- `Se050::provision(pin, max_attempts, entropy, vk, bootstrap_vk)` —
  creates UserID + 3 binary objects with UserID policy. Idempotent.
- `Se050::unlock(pin) -> [u8; 32]` — CreateSession + VerifySession +
  ReadAuthed(entropy) + CloseSession. Returns raw entropy.

### `secure/src/se050/apdu.rs` — APDU commands (8 total)

- `select_applet()` — GP SELECT with SE050 AID.
- `check_exists()` — object existence check.
- `write_userid()` — INS=0x41, creates hardware PIN.
- `write_binary_gated()` — binary object with UserID policy.
- `create_session()` — returns 8-byte session handle.
- `verify_session()` — INS_PROCESS wrapped PIN verification.
- `read_authed()` — INS_PROCESS wrapped object read.
- `close_session()` — INS_PROCESS wrapped session cleanup.

### `secure/src/se050/scp03.rs` — SCP03 session

- `establish()` — INITIALIZE UPDATE + EXTERNAL AUTHENTICATE (P1=0x03).
- `wrap_apdu()` — C-MAC + C-DEC wrapping for all commands.

### `secure/src/crypto.rs` — Provisioning, unlock, and caching

- `provision_with_mnemonic_se050()` — provisions SE050 and caches VK.
- `verify_pin_se050()` — unlocks SE050 and caches encrypted entropy
  blob + VK in secure SRAM for signing operations.
- `se050_read_cached_entropy_blob()` / `se050_read_cached_vk()` —
  read from SRAM cache (used by signing code).
- `se050_zeroize_caches()` — clear caches on idle wipe.

### Feature gating

The SE050 path is gated behind `#[cfg(feature = "se050")]`. The mock-SE
MACD path (`mock-se` feature) is completely unchanged for QEMU testing.

## APDU Reference

### Policy TLV format

The SE050 policy buffer inside TAG_POLICY (0x11) uses this byte layout:

```
Offset  Field          Size   Notes
0       entry_len      1      Always 0x08 (8 bytes follow)
1-4     auth_obj_id    4      Big-endian. 0x7B002000 for our UserID.
5-8     ar_header      4      Big-endian. Permission bitmask.
```

**auth_obj_id comes BEFORE ar_header.** This matches the NXP constants
`OBJ_POLICY_AUTHID_OFFSET=1` and `OBJ_POLICY_HEADER_OFFSET=5` in
`se05x_const.h`.

AR header bits (from `se05x_const.h`):

| Bit          | Value        | Meaning              |
|--------------|--------------|----------------------|
| ALLOW_READ   | `0x00200000` | Read access          |
| ALLOW_WRITE  | `0x00100000` | Write access         |
| ALLOW_DELETE | `0x00040000` | Delete access        |
| REQUIRE_SM   | `0x00020000` | Require session auth |

We use `0x00360000` = READ + WRITE + DELETE + REQUIRE_SM. The REQUIRE_SM
bit is essential — without it, the SE050 treats the policy as
"allow with platform SCP auth" rather than "require UserID session auth."

### INS_PROCESS wrapping

All commands executed within a UserID session must be wrapped in an
INS_PROCESS (0x05) envelope:

```
Outer APDU:
  CLA  = 0x80
  INS  = 0x05 (PROCESS)
  P1   = 0x00
  P2   = 0x00
  Lc   = length of payload
  Payload:
    TAG_SESSION_ID (0x10): 8-byte session handle
    TAG_1 (0x41):          inner command bytes
  Le   = 0x00 (if response expected)

Inner command (inside TAG_1):
  CLA INS P1 P2 [Lc Data...] [Le]
```

The SE050 parses the PROCESS command, finds the session context from
TAG_SESSION_ID, then executes the inner command within that session's
authorization.

### WriteUserID

```
CLA = 0x80
INS = 0x41  (INS_WRITE | INS_AUTH_OBJECT)
P1  = 0x07  (P1_UserID)
P2  = 0x00
Payload:
  TAG_MAX_ATTEMPTS (0x12): 2-byte BE max attempts (e.g. 0x000A)
  TAG_1 (0x41): 4-byte object ID
  TAG_2 (0x42): PIN value (variable length)
```

No policy TLV on the UserID object itself — it's the auth source, not a
gated object.

### ReadObject (inside session)

Inner command for session-gated read:

```
CLA = 0x80
INS = 0x02  (INS_READ)
P1  = 0x00
P2  = 0x00
Lc  = 0x06
  TAG_1 (0x41): 4-byte object ID
Le  = 0x00
```

**Do NOT include TAG_2 (offset) or TAG_3 (length)** — they cause
SW=0x6985 inside an INS_PROCESS wrapper. Omitting them reads the entire
binary object.

## Lessons Learned (Hardware Debugging)

These are non-obvious behaviors of the SE050E that we discovered during
bring-up. Future developers should be aware of them.

1. **INS=0x41 for auth objects.** Using INS=0x01 (regular WRITE) returns
   SW=0x6985. The SE050 requires the INS_AUTH_OBJECT flag (0x40) to be
   OR'd into INS_WRITE when creating UserID, AESKey, or ECKey auth objects.

2. **Policy byte order matters.** The SE050 silently accepts a policy with
   swapped fields (ar_header before auth_obj_id), creating an object with
   a nonsensical policy. That object then can't be read, written, or
   deleted — it's permanently orphaned until factory reset.

3. **Session ID is 8 bytes.** The SE050 APDU spec says "8-byte session ID"
   in the Le field of CreateSession. Using only 4 bytes causes all
   subsequent session commands to fail because TAG_SESSION_ID doesn't match.

4. **UserID objects can't be deleted.** On SE050E, once a UserID auth
   object is created, `DeleteObject` returns SW=0x6986 (command not
   allowed). This is a security feature. Reprovisioning with a different
   PIN requires an SE050 factory reset.

5. **TAG_2/TAG_3 in session reads cause 0x6985.** Regular ReadObject uses
   TAG_2 (offset) and TAG_3 (length) to specify which part of a file to
   read. Inside an INS_PROCESS wrapper, these tags cause "conditions not
   satisfied." Use TAG_1 (object ID) only.

6. **C-DEC (P1=0x03) is required.** The SE050E rejects auth object
   creation with C-MAC-only (P1=0x01). Upgrading to C-MAC + C-DEC
   (P1=0x03) in the EXTERNAL AUTHENTICATE command resolves this.

7. **Stale objects are permanent.** If you create a binary object with a
   wrong policy (e.g., referencing a non-existent auth object), that
   object becomes undeletable. Use a different object ID range for the
   next attempt. The SE050 has capacity for thousands of objects.

8. **Platform SCP resource ID is 0x7FFF0207.** Not 0x7FFF0200 (which is
   the TRANSPORT key). This matters for applet-level admin operations
   like `SetPlatformSCPRequest`.

## Build and Test

```bash
# Build + flash with semihosting debug output (no screen needed)
make flash-hw-se050-usb-test-debug

# Build without debug (production-like, no semihosting)
make build-hw-se050-usb-test

# Mock-SE build (QEMU, uses old MACD path, unchanged)
make build-hw-usb-test

# Interactive build with screen (mock-SE)
make build-hw
```

The `e2e-test` + `ui-noop` features auto-provision with a fixed test
mnemonic (`abandon...art`) and PIN (`00000000`), bypassing the interactive
UI. No screen or button input needed.
