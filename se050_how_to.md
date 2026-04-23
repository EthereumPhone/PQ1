# Minimal SE050 seed-storage design for STM32 + OM-SE050ARD-E

The simplest implementation that satisfies every requirement uses **two NXP UserID authentication objects and one Binary File**, all driven from the `Se05x_API_*` layer of the **NXP Plug & Trust Nano package**. The 32-byte seed lives in a Binary File whose policy grants `ALLOW_READ` only to a PIN-gated UserID (`max_attempts = 10`); a second UserID provisioned at the reserved slot `RESERVED_ID_FACTORY_RESET` with a **publicly-known, hardcoded value** unlocks `DeleteAll`, giving the user an always-available factory reset. This keeps the design to one object type (UserID + BinaryFile), one policy set, and two top-level APDUs per operation — the minimum the SE050 applet allows.

The catch the user's requirements imply does not exist cleanly: the SE050 applet **has no unauthenticated factory-reset path**. DeleteAll is always gated by a session authenticated against the reserved object `RESERVED_ID_FACTORY_RESET`. The design therefore treats that object as a *public* gate — its UserID value is a compiled-in constant, so anyone running the firmware's factory-reset routine can invoke it without the user-facing PIN. That achieves the spirit of requirement #4 (no PIN needed to recover a bricked device) while being honest about the chip's constraints.

## Stack choice: Plug & Trust Nano, plain `Se05x_API_*` layer

The correct upstream is **github.com/NXPPlugNTrust/nano-package** (latest tag v1.3.0, 17 Jun 2024), distinct from `github.com/NXP/plug-and-trust` (the full simw-top MW). The Nano package advertises a **~1 KB RAM footprint** for SCP03-encrypted I²C and exposes only the thin `Se05x_API_*` / APDU layer — there is no `sss_*` abstraction. Relevant source files:

- `lib/apdu/se05x_APDU_apis.h` — all `Se05x_API_*` prototypes (`WriteUserID`, `CreateSession`, `VerifySessionUserID`, `WriteBinary`, `ReadObject`, `DeleteAll`, `DeleteSecureObject`, `CheckObjectExists`).
- `lib/apdu/se05x_tlv.h` — policy-set TLV helpers and `POLICY_OBJ_*` bit macros.
- `lib/t1oi2c/phNxpEsePal_i2c.c` — T=1-over-I²C framing; uses `SMCOM_I2C_ADDRESS 0x48` and NAD byte `0x5A`.
- `lib/platform/<board>/sm_i2c.c` — the single file the porter must supply.

**STM32 is *not* an officially supported target.** Nano ships port files only for Linux, Zephyr, FRDM-K64F, FRDM-MCXN947, and FRDM-MCXA153. The port contract is well-defined: add a directory `lib/platform/stm32/` providing these functions backed by STM32 HAL I²C calls:

```c
i2c_error_t axI2CInit (void **conn_ctx, const char *pDevName);
void        axI2CTerm (void  *conn_ctx, int mode);
i2c_error_t axI2CWrite(void  *conn_ctx, unsigned char bus,
                       unsigned char addr, unsigned char *pBuf, unsigned short len);
i2c_error_t axI2CRead (void  *conn_ctx, unsigned char bus,
                       unsigned char addr, unsigned char *pBuf, unsigned short len);
void        sm_sleep  (uint32_t msec);          // HAL_Delay wrapper
void        sm_usleep (uint32_t usec);
```

Return codes are `I2C_OK / I2C_NACK_ON_ADDRESS / I2C_NACK_ON_DATA / I2C_FAILED / I2C_BUSY`. Wire the OM-SE050ARD-E Arduino shield header SDA/SCL to the STM32 HAL I²C peripheral of your Nucleo (e.g., I2C1 on PB8/PB9 for F4-series Nucleos). The board's SE050 sits at the **fixed 7-bit address 0x48** (see SE050 datasheet Rev. 3.8 and UM11225 T=1-over-I²C).

For the PoC build with `-DPLUGANDTRUST_SE05X_AUTH=None` (plain I²C). For production, switch to `PlatfSCP03` so the PIN does not cross the I²C bus in clear — the default SCP03 ENC/MAC keys for SE050E dev kits are listed in **AN12436 Table 5** ("Default Platform SCP keys for new generation of SE050 products"). Confirmed by an NXP community reply: users of **OM-SE050ARD-E** enable SCP03 by pasting those keys into `session_ctx->pScp03_enc_key / pScp03_mac_key`.

## Why UserID is the right primitive

**AN12413 (SE050 APDU Specification, Rev. 2.12)** Table 2 defines the auth-object landscape:

| AuthObject type | Value length | `MAX_ATTEMPTS` range | Enforcement on exhaustion |
|---|---|---|---|
| **UserID** | 4–16 bytes | **0–255** (0 = unlimited) | Object locks; auth permanently rejected |
| AESKey (128-bit) | 16 bytes | 0–0x7FFF | Object locks; auth permanently rejected |
| ECKey (Weierstrass) | curve-sized | 0–0x7FFF | Object locks; auth permanently rejected |

`TAG_MAX_ATTEMPTS = 0x12` is a 2-byte field set **only at creation** and **cannot be modified afterward** — this is what makes the 10-try lockout hardware-enforced rather than a software counter. The counter resets to zero on successful authentication and increments on every `VerifySessionUserID` failure; when it reaches the ceiling, the applet rejects all further authentications to that object for the life of the SE050 (only `DeleteAll` can remove it). AN12514 (SE050 User Guidelines) makes this mandatory for PIN-like use: *"for PINs, the value must be smaller than 256"* and non-zero.

Two errata are worth knowing but do not block this design on the SE050E-ARD (which runs applet **7.2**, verified by `ex_se05x_GetInfo` output in NXP community posts):

- **APP.3** — the *reported* max-attempts value of a UserID reads back as 0 via attestation. This is cosmetic; the counter still *enforces*. The workaround "use AESKey instead" is only needed if you want to *query* the remaining attempts.
- **APP.5** — pre-3.x applets had an incomplete UserID value check. Fixed in the 7.x SE050E applet.

**Seed unrecoverability follows automatically.** The seed is a BinaryFile whose `ALLOW_READ` is bound to the PIN UserID. When the PIN UserID locks after 10 failures, no session can ever satisfy that policy again, so `ReadObject` on the BinaryFile returns `SW_SECURITY_STATUS (0x6982)` forever. The object itself is not auto-deleted; it simply becomes unreadable — which is exactly "permanently unrecoverable" for the seed.

## Policy bits and object layout

**AN12413 §3.7** defines the policy set format: each policy is `{LengthOfPolicy (1B), AuthObjectID (4B), AccessRules (4B header + optional extension)}`. AuthObjectID `0x00000000` means "all other users". When building a policy set, concatenate multiple entries; the per-user entry overrides the `0x00000000` default for that user.

Access-rule bit layout (4-byte header, byte order B1/B2/B3/B4, ordered MSB→LSB inside each byte):

| Bit | Macro | Meaning |
|---|---|---|
| B1b6 | `POLICY_OBJ_FORBID_ALL` | Block everything |
| B2b6 | `POLICY_OBJ_ALLOW_READ` | Read the object |
| B2b5 | `POLICY_OBJ_ALLOW_WRITE` | Overwrite the object |
| B2b3 | `POLICY_OBJ_ALLOW_DELETE` | Delete the object |
| B2b2 | `POLICY_OBJ_REQUIRE_SM` | Require secure messaging (SCP03) |
| B2b1 | `POLICY_OBJ_REQUIRE_PCR_VALUE` | Gate on PCR match |

**The three objects on the SE050:**

| # | Role | ObjectID | Type | MAX_ATTEMPTS | Notes |
|---|---|---|---|---|---|
| 1 | Factory-reset gate | `0x7FFF0201` (`RESERVED_ID_FACTORY_RESET` / `kSE05x_AppletResID_FACTORY_RESET`) | UserID | **0 (unlimited)** | Value = hardcoded 8-byte constant compiled into firmware |
| 2 | PIN gate | `0x00000010` (any user slot) | UserID | **10** | Value = 8 ASCII digits of the PIN (8 bytes) |
| 3 | Seed holder | `0x00000020` | BinaryFile, 32 B | — | Policy below |

**Exact policy set for the seed BinaryFile** (two policies, glued together):

```
Policy entry 1  — grants READ to the PIN UserID only:
   08   00 00 00 10   00 20 00 00
   │    └─auth ID──┘  └─ accessRules: B2b6 (ALLOW_READ) ─┘
   └── length of this entry = 8

Policy entry 2  — grants DELETE to everyone else:
   08   00 00 00 00   00 04 00 00
   │    └─auth ID─┘   └─ accessRules: B2b3 (ALLOW_DELETE) ─┘
   └── length = 8
```

Total policy-set TLV: `11 10 08 00000010 00200000 08 00000000 00040000` (tag `TAG_POLICY=0x11`, length `0x10`, then the two 8-byte entries). The Nano helper struct `Se05xPolicy_t` can carry this as `{.value=<buffer above>, .value_len=18}`.

## Host-side C code (STM32, Plug & Trust Nano)

Header aliases used below are those actually exported by `lib/apdu/se05x_APDU_apis.h` in the Nano repo. I have quoted the real prototypes from that file:

```c
smStatus_t Se05x_API_WriteUserID(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy, SE05x_MaxAttemps_t maxAttempt,
    uint32_t objectID, const uint8_t *userId, size_t userIdLen,
    const SE05x_AttestationType_t attestation_type);

smStatus_t Se05x_API_WriteBinary(pSe05xSession_t session_ctx,
    pSe05xPolicy_t policy, uint32_t objectID,
    uint16_t offset, uint16_t length,
    const uint8_t *inputData, size_t inputDataLen);

smStatus_t Se05x_API_CreateSession(pSe05xSession_t session_ctx,
    uint32_t authObjectID, uint8_t *sessionId, size_t *psessionIdLen);

smStatus_t Se05x_API_VerifySessionUserID(pSe05xSession_t session_ctx,
    const uint8_t *userId, size_t userIdLen);

smStatus_t Se05x_API_ReadObject(pSe05xSession_t session_ctx,
    uint32_t objectID, uint16_t offset, uint16_t length,
    uint8_t *data, size_t *pdataLen);

smStatus_t Se05x_API_DeleteAll(pSe05xSession_t session_ctx);
```

### Common setup

```c
#define ID_FACTORY_RESET   kSE05x_AppletResID_FACTORY_RESET   /* 0x7FFF0201 */
#define ID_PIN_USERID      0x00000010u
#define ID_SEED_BINARY     0x00000020u
#define SEED_LEN           32u

/* Public, compiled-in factory-reset token. Anyone with the firmware can trigger reset. */
static const uint8_t k_factory_reset_value[8] = {
    'R','E','S','E','T','0','0','1'
};

/* Policy set bytes for the seed BinaryFile */
static const uint8_t k_seed_policy[] = {
    0x08, 0x00,0x00,0x00,0x10,  0x00,0x20,0x00,0x00,   /* PIN user: ALLOW_READ  */
    0x08, 0x00,0x00,0x00,0x00,  0x00,0x04,0x00,0x00    /* all:      ALLOW_DELETE */
};
static const Se05xPolicy_t k_seed_policy_obj = {
    .value = (uint8_t *)k_seed_policy,
    .value_len = sizeof(k_seed_policy),
};

/* Open a session-less APDU channel over the STM32 I2C port */
smStatus_t se_open(Se05xSession_t *s) {
    memset(s, 0, sizeof(*s));
    /* In PlatformSCP03 builds, set pScp03_enc_key / pScp03_mac_key here (AN12436 Tbl 5). */
    return Se05x_API_SessionOpen(s);   /* wraps axI2CInit + SELECT APPLET */
}
```

### `provision(pin, seed)` — one-time factory setup

```c
smStatus_t provision(const uint8_t pin[8], const uint8_t seed[32]) {
    Se05xSession_t s;
    smStatus_t rv = se_open(&s);
    if (rv != SM_OK) return rv;

    /* (1) Create the factory-reset UserID with UNLIMITED attempts.
           Value is the public compiled-in token. */
    rv = Se05x_API_WriteUserID(&s,
            NULL,                                 /* default policy */
            0 /* max_attempts = unlimited */,
            ID_FACTORY_RESET,
            k_factory_reset_value, sizeof(k_factory_reset_value),
            kSE05x_AttestationType_AUTH);
    if (rv != SM_OK) goto out;

    /* (2) Create the PIN UserID with hardware-enforced MAX_ATTEMPTS = 10. */
    rv = Se05x_API_WriteUserID(&s,
            NULL,
            10 /* SE05x_MaxAttemps_t */,
            ID_PIN_USERID,
            pin, 8,
            kSE05x_AttestationType_AUTH);
    if (rv != SM_OK) goto out;

    /* (3) Create the seed BinaryFile with the READ-by-PIN / DELETE-by-all policy.
           WriteBinary's first call both creates and sets the policy. */
    rv = Se05x_API_WriteBinary(&s,
            (pSe05xPolicy_t)&k_seed_policy_obj,
            ID_SEED_BINARY,
            0 /* offset */, SEED_LEN /* full size */,
            seed, SEED_LEN);
out:
    Se05x_API_SessionClose(&s);
    return rv;
}
```

### `unlock_and_read(pin) → seed`

```c
smStatus_t unlock_and_read(const uint8_t pin[8], uint8_t out_seed[32]) {
    Se05xSession_t s;
    uint8_t sid[8]; size_t sid_len = sizeof(sid);
    size_t outlen = 32;

    smStatus_t rv = se_open(&s);
    if (rv != SM_OK) return rv;

    /* Open a UserID session bound to the PIN object. */
    rv = Se05x_API_CreateSession(&s, ID_PIN_USERID, sid, &sid_len);
    if (rv != SM_OK) goto out;

    /* Authenticate. Wrong PIN => applet increments the on-chip counter.
       After the 10th failure the UserID is permanently locked and no future
       VerifySessionUserID will ever succeed, making the seed unrecoverable. */
    rv = Se05x_API_VerifySessionUserID(&s, pin, 8);
    if (rv != SM_OK) goto out;        /* SW_SECURITY_STATUS=0x6982 when locked */

    /* Policy now grants ALLOW_READ to this session; read all 32 bytes. */
    rv = Se05x_API_ReadObject(&s, ID_SEED_BINARY, 0, SEED_LEN,
                              out_seed, &outlen);
out:
    Se05x_API_SessionClose(&s);
    return rv;
}
```

### `factory_reset()` — no user PIN required

```c
smStatus_t factory_reset(void) {
    Se05xSession_t s;
    uint8_t sid[8]; size_t sid_len = sizeof(sid);

    smStatus_t rv = se_open(&s);
    if (rv != SM_OK) return rv;

    /* Authenticate to the public factory-reset gate with the compiled-in token. */
    rv = Se05x_API_CreateSession(&s, ID_FACTORY_RESET, sid, &sid_len);
    if (rv != SM_OK) goto out;
    rv = Se05x_API_VerifySessionUserID(&s,
            k_factory_reset_value, sizeof(k_factory_reset_value));
    if (rv != SM_OK) goto out;

    /* Wipes ALL non-reserved objects: PIN, Seed, and every other user object.
       Platform SCP03 keys and NXP-provisioned certs on SE050E behave per AN13483:
       “Certificates trust provisioned by NXP will be deleted after factory reset.
        Platform SCP keys are unaffected by the factory reset procedure.” */
    rv = Se05x_API_DeleteAll(&s);
out:
    Se05x_API_SessionClose(&s);
    return rv;
}
```

### Optional `change_pin(old, new)`

UserID **values are immutable after creation** (confirmed in NXP community thread on `Se05x_API_WriteUserID` returning `0x6985` on rewrite). The only way to change the PIN is to delete the old UserID and create a new one. Deletion must happen *inside a session authenticated by the old PIN*, otherwise you'd have a trivial bypass:

```c
smStatus_t change_pin(const uint8_t old_pin[8], const uint8_t new_pin[8]) {
    Se05xSession_t s;
    uint8_t sid[8]; size_t sid_len = sizeof(sid);

    smStatus_t rv = se_open(&s);
    if (rv != SM_OK) return rv;

    rv = Se05x_API_CreateSession(&s, ID_PIN_USERID, sid, &sid_len);
    if (rv != SM_OK) goto out;
    rv = Se05x_API_VerifySessionUserID(&s, old_pin, 8);
    if (rv != SM_OK) goto out;         /* wrong old PIN burns one attempt */

    rv = Se05x_API_DeleteSecureObject(&s, ID_PIN_USERID);
    if (rv != SM_OK) goto out;
    /* Session auto-closes per AN12413 §3.6 ("auth object deleted within its own session"). */
    Se05x_API_SessionClose(&s);

    /* Re-open session-less and recreate the UserID with fresh MAX_ATTEMPTS=10. */
    rv = se_open(&s);
    if (rv != SM_OK) return rv;
    rv = Se05x_API_WriteUserID(&s, NULL, 10, ID_PIN_USERID, new_pin, 8,
                               kSE05x_AttestationType_AUTH);
out:
    Se05x_API_SessionClose(&s);
    return rv;
}
```

## Gotchas specific to OM-SE050ARD-E

The shipping SE050 on this board is the **SE050E variant** (applet 7.2 on JCOP 4.7), not an older SE050C — confirmed on the NXP product page and the Digi-Key/Mouser description *"EdgeLock SE050E Arduino-compatible development kit"*. Practical consequences:

- **I²C address is fixed at 0x48** and the T=1 NAD byte is `0x5A`. Pull-ups are on the board; no external ones needed. Timing-critical: after power-up the SE050 requires ~10 ms before it responds, and a `GP_SELECT_APPLET` (AID `A0000003965453000000010300000000`) is the first APDU — Nano's `Se05x_API_SessionOpen` handles this automatically.
- **Platform SCP03 is not mandated by default** but is enabled with the public "Ease of Use" keys in AN12436 Tbl 5. For a PoC, build Nano with `-DPLUGANDTRUST_SE05X_AUTH=None` (plain). For production, build with `PlatfSCP03` and copy the default ENC/MAC keys; otherwise your 8-digit PIN crosses I²C in plain text inside `VerifySessionUserID` (UserID sessions intentionally do not apply secure messaging per AN12413 §3.6). If you run `se05x_mandate_scp03` once, SCP03 becomes *required* and plain sessions will be rejected thereafter — don't do that on a shared dev board.
- **DeleteAll is not literally unauthenticated.** The SE050 always requires a session built on `RESERVED_ID_FACTORY_RESET = 0x7FFF0201` to accept `DeleteAll` (verified in NXP community threads for OM-SE050ARD-E). The "no user PIN needed" requirement is met by using a well-known UserID value baked into firmware. Do not ever write a BinaryFile to object ID `0x7FFF0201` — a reported gotcha is that a binary file at that ID cannot be used as an auth object, making DeleteAll unreachable and bricking the board; `Se05x_API_DeleteAll_Iterator` is the only escape.
- **NXP-provisioned keypairs are preserved** on a fresh SE050E until you explicitly overwrite them. `DeleteAll` removes only `INTERNAL`/`EXTERNAL`-origin objects plus some pre-provisioned certificates; Platform SCP03 keys survive (AN13483 §factory reset). Memory on SE050E after SCP03 setup is ~616 bytes persistent / 796 bytes transient (reported via `Se05x_API_GetFreeMemory`), so the three-object footprint here (under ~80 bytes persistent) is trivial.
- **There is no official STM32 port of Nano.** Copy `lib/platform/k64` as a template and re-implement `sm_i2c.c` using `HAL_I2C_Master_Transmit/Receive` on your chosen `I2C_HandleTypeDef`. Community confirmation from NXP support: *"MW just supports NXP MCU & MPU products; for non-NXP hosts, port the nano package by modifying `lib/platform/`"* — the public `securitypattern/orshin-STM32-client-scp03-nscp` fork is a reference for the exact STM32 HAL shim (not NXP-endorsed).
- **Host-crypto requirement when SCP03 is enabled.** Nano's SCP03 module needs AES-CMAC and AES-CBC on the host. On STM32 the path of least resistance is to vendor mbedTLS 2.x and point Nano at `lib/apdu/scp03/mbedtls/`. If you build `-DPLUGANDTRUST_SE05X_AUTH=None`, no host crypto is needed at all — which is why that mode is preferable for first bring-up.

## Key takeaways

The design reduces to **one APDU sequence per operation**, uses **one NXP primitive (UserID)** for both the PIN gate and the factory-reset gate, and leans on the **immutable on-chip `MAX_ATTEMPTS = 10` field** of the PIN UserID for tamper-resistant lockout. The 32-byte seed itself sits in a standard BinaryFile, protected by a two-entry policy set that costs 18 bytes to express. No AESKey/ECKey authentication, no PCR tricks, no monotonic-counter self-destruct logic are needed — the UserID attempt counter already provides the exact semantics the requirements ask for, and it does so in applet-enforced silicon that the STM32 host cannot bypass. The only non-obvious compromise is that "auth-free factory reset" is not literally expressible on the SE050; the cleanest honest interpretation is a second UserID with a public value, which this design adopts.

Primary references used:
- NXP Plug & Trust Nano repo: https://github.com/NXPPlugNTrust/nano-package (README + `lib/apdu/se05x_APDU_apis.h`)
- AN12413 SE050 APDU Specification, Rev. 2.12 — https://www.nxp.com/docs/en/application-note/AN12413.pdf (§3.2 objects, §3.6 sessions, §3.7 policies, §4 APDU)
- AN12436 SE050 Configurations, Rev. 2.4 — https://www.nxp.com/docs/en/application-note/AN12436.pdf (default Platform SCP03 keys)
- AN12514 SE050 User Guidelines — MAX_ATTEMPTS requirement for PIN use
- AN13483 SE050E User Guidelines — DeleteAll scope and RESERVED_ID_FACTORY_RESET requirement
- AN12448 SE05x Plug & Trust MW Porting Guidelines — STM32 porting contract (`axI2C*` functions)
- SE050 datasheet Rev. 3.8 — I²C address 0x48, T=1-over-I²C boot sequence
- NXP Community threads on DeleteAll(0x6985), UserID immutability, and OM-SE050ARD-E SCP03 default keys