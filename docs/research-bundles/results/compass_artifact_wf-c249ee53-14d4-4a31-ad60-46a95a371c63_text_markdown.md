# PQSigner OS: provisioning and runtime key-management protocol

**PQSigner OS can achieve strong per-device key isolation and anti-swap protection by rotating SE050 SCP03 keys, wrapping all host-side secrets with the STM32U585 DHUK via the SAES peripheral, and binding all three chip UIDs into an HUK-encrypted attestation record verified at every boot.** The protocol below covers factory provisioning (one-time), runtime key management, flash layout, and firmware-upgrade migration — with concrete APDU sequences, register values, and code patterns drawn from NXP AN12436, Infineon's OPTIGA host library, and RM0456.

---

## 1. End-to-end factory provisioning flow

The entire provisioning protocol executes once on a secure factory jig. The provisioner machine has an HSM containing the Factory Master Key (FMK) and provisioner signing key. Power-loss at any step before the final OTP burn leaves the device in an unpersonalized state that can be re-provisioned.

```
PROVISIONER HSM                       STM32U585 (Secure World)           SE050                OPTIGA Trust M
      │                                       │                            │                        │
      │  ──── Connect via SWD (RDP0) ────────►│                            │                        │
      │                                       │                            │                        │
      │  1. Read STM32 UID ◄──────────────────│ HAL_GetUIDw0/1/2()         │                        │
      │     (0x0BFA0700, 12 bytes)            │                            │                        │
      │                                       │                            │                        │
      │  2. Read SE050 UID ◄──────────────────│── se05x_GetInfo() ────────►│                        │
      │     (18 bytes, plain channel OK)      │◄── UID response ──────────│                        │
      │                                       │                            │                        │
      │  3. Read OPTIGA UID ◄─────────────────│── GetDataObject(0xE0C2) ──►│                        │
      │     (27 bytes, plain channel)         │◄── UID response ───────────────────────────────────│
      │                                       │                            │                        │
      │  4. Derive per-device SCP03 keys      │                            │                        │
      │     ENC = CMAC-KDF(FMK,              │                            │                        │
      │       "SCP03-ENC" ‖ SE050_UID)        │                            │                        │
      │     MAC = CMAC-KDF(FMK,              │                            │                        │
      │       "SCP03-MAC" ‖ SE050_UID)        │                            │                        │
      │     DEK = CMAC-KDF(FMK,              │                            │                        │
      │       "SCP03-DEK" ‖ SE050_UID)        │                            │                        │
      │                                       │                            │                        │
      │  5. Open SCP03 with NXP defaults ─────│── INIT UPDATE (KVN=0x0B)──►│                        │
      │     (keys per AN12436 variant table)  │◄── card challenge ────────│                        │
      │                                       │── EXT AUTHENTICATE ───────►│                        │
      │                                       │◄── 9000 ──────────────────│                        │
      │                                       │                            │                        │
      │  6. PUT KEY (rotate to new keys) ─────│── 84 D8 0B 81 [Lc] ──────►│                        │
      │     new KVN = 0x11                    │◄── [0x11][KCV×3] 9000 ────│                        │
      │                                       │                            │                        │
      │  7. Verify: reopen SCP03 with new keys│── INIT UPDATE (KVN=0x11)──►│                        │
      │                                       │── EXT AUTHENTICATE ───────►│                        │
      │     Set PlatformSCPRequest=REQUIRED   │── SetPlatfSCPReq ─────────►│                        │
      │                                       │                            │                        │
      │  8. Generate PBS (64 bytes TRNG) ─────│── optiga_crypt_random() ──────────────────────────►│
      │     Optionally XOR with STM32 RNG     │◄── 64-byte random ─────────────────────────────────│
      │                                       │── write_data(0xE140, PBS) ──────────────────────────►│
      │                                       │── write_metadata(0xE140,   ──────────────────────────►│
      │                                       │    LcsO=Op, Read=NEV,      │                        │
      │                                       │    Change=Conf(0xE140))    │                        │
      │                                       │                            │                        │
      │  9. Build binding record ─────────────│                            │                        │
      │     provisioner_sig = ECDSA-P256(     │                            │                        │
      │       SHA256(SE050_UID ‖ OPTIGA_UID   │                            │                        │
      │       ‖ STM32_UID ‖ fw_ver ‖ ts),     │                            │                        │
      │       provisioner_privkey)            │                            │                        │
      │                                       │                            │                        │
      │ 10. Store binding record on SEs ──────│── WriteObject(SE050, 0x10000001, binding) ─────────►│
      │                                       │── write_data(OPTIGA, 0xF1D1, binding) ─────────────►│
      │                                       │                            │                        │
      │ 11. Wrap all secrets with DHUK ────────│ HAL_CRYPEx_WrapKey():      │                        │
      │     (CBC mode, per-secret IV)         │   wrapped_scp03_keys       │                        │
      │                                       │   wrapped_pbs              │                        │
      │                                       │   wrapped_binding_record   │                        │
      │                                       │ → write blobs to flash     │                        │
      │                                       │                            │                        │
      │ 12. Burn OTP provisioning flag ────────│ OTP byte 0 = 0x01         │                        │
      │                                       │                            │                        │
      │ 13. Set RDP Level 2 ──────────────────│ FLASH_OBProgramInitConfig()│                        │
      │     (irreversible, kills debug)       │                            │                        │
      └───────────────────────────────────────┘                            │                        │
```

**Critical ordering**: Steps 1-10 execute at RDP0 (debug attached). Step 11 wraps keys with DHUK, but at RDP0 the DHUK is a **known constant** (per ST documentation: "SAES will use a constant value instead of DHUK" at RDP0). Therefore, the provisioner must first set **RDP1** (step 12.5), reset the chip, reconnect via the secure provisioning firmware's USB/UART interface (not SWD), and then execute step 11 to wrap with the real DHUK. Only after verifying wrapped keys unwrap correctly should RDP2 be burned. Alternatively, the provisioning firmware can be pre-flashed and run autonomously — receiving derived keys over a secure UART channel from the provisioner HSM, wrapping them internally at RDP1+, and signaling completion.

---

## 2. SCP03 key rotation from NXP defaults

### Default keys and the PUT KEY command

The SE050 ships with variant-specific AES-128 static platform keys published in **AN12436 Rev 2.4, Tables 5–6**. For the commonly used **SE050C1 (OEF A201)**, the defaults are:

| Key | Value |
|-----|-------|
| ENC | `852B5962E9CCE5D0BE746B833BCC6287` |
| MAC | `DB0AA319A408696C8E107AB4E3C26B47` |
| DEK | `4C2F75C6A278A4AEE5C9AF7C50EEA80C` |

The default Key Version Number is **0x0B**. NXP requires the replacement KVN to be **0x11** for SE050C1 variants.

The GlobalPlatform SCP03 PUT KEY command (GP Card Spec v2.3.1 §11.8) sends all three replacement keys in a single APDU. The command **must** be issued within an authenticated SCP03 session (minimum security level: C-MAC). The APDU before SCP03 session wrapping:

```
CLA  INS  P1   P2   Lc    Data
80   D8   0B   81   [Lc]  [payload below]

Payload:
  11                           // New KVN
  88 18 [AES-KW(S-DEK, new_ENC)] 03 [KCV_ENC]    // Key 1: ENC
  88 18 [AES-KW(S-DEK, new_MAC)] 03 [KCV_MAC]    // Key 2: MAC
  88 18 [AES-KW(S-DEK, new_DEK)] 03 [KCV_DEK]    // Key 3: DEK
```

Each new 16-byte key is wrapped with **AES Key Wrap (RFC 3394)** using the S-DEK session key, producing **24 bytes** output. The Key Type byte `0x88` denotes AES. The 3-byte Key Check Value for each key is computed as **AES-ECB(new_key, 0x01×16)[0:2]** — the first three bytes of encrypting a full block of `0x01` with the new key.

**S-DEK derivation** follows the NIST SP 800-108 counter-mode CMAC KDF used throughout SCP03:

```
S-DEK = AES-CMAC(static_DEK,
    00 00 00 00 00 00 00 00 00 00 00  // 11 bytes zero padding
    04                                  // derivation constant (data encryption)
    00                                  // separator
    00 80                              // L = 128 bits
    01                                  // counter i = 1
    [host_challenge 8B] [card_challenge 8B])
```

After SCP03 session wrapping, the CLA becomes `0x84` and an 8-byte C-MAC is appended.

### APDU sequence on the wire

```
1.  ATR / Power-on
2.  SELECT ISD:  00 A4 04 00 00  (no applet selection — target Card Manager)
3.  INITIALIZE UPDATE:  80 50 0B 00 08 [8-byte host_challenge]
    Response: [10B diversification][3B key_info][8B card_challenge][8B card_cryptogram] 9000
4.  Derive S-ENC, S-MAC, S-RMAC, S-DEK from static keys + challenges
5.  EXTERNAL AUTHENTICATE:  84 82 33 00 [host_cryptogram + C-MAC]
    (security level 0x33 = C-MAC + C-ENC + R-MAC + R-ENC)
6.  PUT KEY (SCP03-wrapped):  84 D8 0B 81 [Lc] [encrypted payload + C-MAC]
    Response: [0x11][KCV_ENC 3B][KCV_MAC 3B][KCV_DEK 3B] 9000
7.  Close session (reset SE050 or power cycle)
8.  INITIALIZE UPDATE with KVN=0x11 using new keys → verify 9000
9.  Se05x_API_SetPlatformSCPRequest(REQUIRED) → reject future plain APDUs
```

**Atomicity**: Per GP Card Spec, PUT KEY is atomic — the old keys remain valid if power is lost mid-command. After successful PUT KEY (SW=9000), the old key set is **immediately and permanently replaced**.

### Per-device key derivation

The recommended approach uses NIST SP 800-108 (CMAC-based KDF) with the SE050 UID as diversification:

```c
// On provisioner HSM:
void derive_scp03_keys(const uint8_t fmk[16],
                       const uint8_t se050_uid[18],
                       uint8_t enc[16], uint8_t mac[16], uint8_t dek[16])
{
    // PRF = AES-128-CMAC, counter mode
    // K_derived = CMAC(FMK, 0x00000001 ‖ Label ‖ 0x00 ‖ Context ‖ 0x0080)
    uint8_t input[64];
    put_be32(input, 1);                        // counter = 1
    memcpy(input+4, "SCP03-ENC", 9);           // label
    input[13] = 0x00;                          // separator
    memcpy(input+14, se050_uid, 18);           // context
    put_be16(input+32, 128);                   // L = 128 bits
    aes_cmac(fmk, input, 34, enc);             // → 16-byte ENC key

    memcpy(input+4, "SCP03-MAC", 9);
    aes_cmac(fmk, input, 34, mac);

    memcpy(input+4, "SCP03-DEK", 9);
    aes_cmac(fmk, input, 34, dek);
}
```

### NXP middleware reference

The **nano-package** repository (`github.com/NXPPlugNTrust/nano-package`) provides `examples/se05x_rotate_scp03_keys/` with a working rotation example. Key implementation detail: the `scp03_dek_key_len` **must** be set to 16 (not 0) for rotation — the DEK static key is required to derive S-DEK. For normal SCP03 operation the DEK can be omitted, but not for PUT KEY.

---

## 3. OPTIGA Trust M PBS wrapping with HUK-SAES

### PBS provisioning at factory

The Platform Binding Secret at **OID 0xE140** is a shared symmetric secret for the Shielded Connection — an AES-128-CCM-8 encrypted I2C channel derived via TLS PRF SHA-256. The OPTIGA Trust M V3 (standard, non-Express) ships with 0xE140 in **Creation** lifecycle state, meaning it is writable. The provisioning sequence:

```c
// Step 1: Open OPTIGA application
optiga_util_open_application(me_util, 0);  // non-persistent context

// Step 2: Verify not already provisioned
optiga_util_read_metadata(me_util, 0xE140, meta_buf, &meta_len);
assert(meta_buf[LcsO_offset] < 0x07);  // Must be < Operational

// Step 3: Generate 64-byte random PBS
optiga_crypt_random(me_crypt, OPTIGA_RNG_TYPE_TRNG, pbs_buf, 64);
// XOR with STM32 RNG output for defense-in-depth:
HAL_RNG_GenerateRandomNumber(&hrng, (uint32_t*)host_rng);
for (int i = 0; i < 64; i++) pbs_buf[i] ^= host_rng[i % 32];

// Step 4: Write PBS to OPTIGA
optiga_util_write_data(me_util, 0xE140,
    OPTIGA_UTIL_ERASE_AND_WRITE, 0, pbs_buf, 64);

// Step 5: Lock metadata — THIS IS IRREVERSIBLE
static const uint8_t metadata_final[] = {
    0x20, 0x11,              // Metadata tag, length=17
    0xC0, 0x01, 0x07,        // LcsO = Operational (irreversible)
    0xD0, 0x03, 0x20, 0xE1, 0x40,  // Change = Conf(0xE140) (shielded conn required)
    0xD1, 0x01, 0xFF,        // Read = Never
    0xD3, 0x01, 0x00,        // Execute = Always
    0xE8, 0x01, 0x22         // Data type = Platform Binding Secret
};
optiga_util_write_metadata(me_util, 0xE140,
    metadata_final, sizeof(metadata_final));

// Step 6: Wrap PBS with SAES-DHUK and store (see Section 4)
saes_wrap_to_flash(KEY_TYPE_OPTIGA_PBS, pbs_buf, 64);

// Step 7: Zeroize plaintext
memset(pbs_buf, 0, 64);
```

After provisioning, OID 0xE140 is **never readable** (Read=0xFF) and **modifiable only via shielded connection** (Change=Conf(0xE140)). This means an attacker who desolders the OPTIGA cannot read the PBS, and cannot establish a shielded connection without already knowing it.

### Runtime shielded connection establishment

At every boot, the secure world unwraps the PBS from flash and feeds it to the OPTIGA host library through the **`pal_os_datastore`** platform abstraction layer:

```c
// Custom pal_os_datastore.c for PQSigner OS
static uint8_t pbs_plaintext[64] __attribute__((section(".secure_sram")));
static volatile bool pbs_loaded = false;

pal_status_t pal_os_datastore_read(uint16_t id,
    uint8_t *buf, uint16_t *len)
{
    if (id == OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID) {
        if (!pbs_loaded) {
            WrappedKeyBlob_t blob;
            secure_flash_read(FLASH_ADDR_PBS_BLOB, &blob, sizeof(blob));
            saes_unwrap(&blob, pbs_plaintext, 64);  // DHUK decrypt
            pbs_loaded = true;
        }
        memcpy(buf, pbs_plaintext, 64);
        *len = 64;
        return PAL_STATUS_SUCCESS;
    }
    return PAL_STATUS_FAILURE;
}

void pbs_zeroize(void) {
    memset(pbs_plaintext, 0, 64);
    pbs_loaded = false;
}
```

The shielded connection handshake proceeds automatically at the IFX I2C presentation layer when the protection level is set. The protocol exchanges a TRNG-generated random, derives session keys via **TLS PRF SHA-256("Platform Binding", RND ‖ PBS)**, and protects subsequent frames with **AES-128-CCM-8**. After the handshake completes, the PBS can be zeroized from SRAM — only the session keys (held internally by the OPTIGA host library) are needed for ongoing communication.

The Security Monitor in OPTIGA Trust M tracks failed handshake attempts via the Security Event Counter (SEC at OID 0xE0C4). After **127 failures**, the chip introduces progressive delays up to **5 seconds per operation**. Normal single-boot-cycle usage is unaffected.

---

## 4. STM32U585 SAES peripheral: HUK wrapping in practice

### DHUK architecture and constraints

The STM32U585 SAES peripheral (base address **`0x420C0C00`**, secure alias `0x520C0C00`) provides side-channel-protected AES with hardware key support. The key hierarchy:

- **RHUK** (Root HUK): Factory-fused, unique per die, never software-accessible
- **DHUK** (Derived HUK): Derived from RHUK by an internal KDF inside SAES silicon. Selected via **KEYSEL=001** in SAES_CR. **256-bit key**
- **BHK** (Boot HUK): Volatile, stored in TAMP backup registers. Not used in this design

**RDP dependency is critical**: at **RDP0, DHUK is a known constant** — wrapped keys are not device-unique. The real DHUK activates at **RDP ≥ 1**. All production wrapping must occur at RDP1+.

The SAES does **not** implement RFC 3394 AES-KW natively. The "wrapping" mode (KMOD=01) is **AES-ECB encryption with DHUK** — no integrity check. Furthermore, **GCM mode cannot be combined with KMOD=01** (the EN bit will not set). This means direct authenticated wrapping with DHUK is not available in a single operation.

### Recommended wrapping strategy: two-level approach

Since SAES wrapping is unauthenticated ECB, the recommended pattern wraps a **master key** with DHUK-ECB, then uses that master key for authenticated encryption of individual secrets via software AES-GCM:

```
Level 1: DHUK-ECB wraps 256-bit MasterKey (stored as 32-byte ECB blob in flash)
Level 2: MasterKey → HKDF-SHA256 → per-purpose keys:
   ├── HKDF(MasterKey, "SCP03")     → wraps SCP03 ENC/MAC/DEK via AES-GCM
   ├── HKDF(MasterKey, "OPTIGA-PBS") → wraps PBS via AES-GCM
   └── HKDF(MasterKey, "BINDING")    → wraps binding record via AES-GCM
```

This provides domain separation and authenticated encryption while using the hardware DHUK as the root of trust. Alternatively, for simplicity, one can use DHUK-CBC with per-secret random IVs plus a software CMAC for integrity, though the two-level approach is cleaner.

### Minimum SAES register-level sequence

**Wrapping the MasterKey with DHUK (Level 1):**

```c
// Prerequisites: RCC_AHB2ENR1 |= RCC_AHB2ENR1_SAESEN; RNG initialized.

// 1. Reset SAES
SAES->CR = (1U << 31);           // IPRST
SAES->CR = 0;                    // Release reset

// 2. Configure: 256-bit key, ECB encrypt, DHUK, wrapped-key mode
//    KEYSIZE=1 (bit 18), MODE=00 (bits 4:3, encrypt),
//    CHMOD=000 (bits 16,6:5, ECB),
//    KEYSEL=001 (bits 27:25), KMOD=01 (bits 25:24)
//    DATATYPE=10 (bit 2:1, byte swap for big-endian keys)
SAES->CR = (1U << 18)   // KEYSIZE = 256-bit
         | (0U << 3)    // MODE = 00 (encryption)
         | (0U << 5)    // CHMOD[1:0] = 00 (ECB)
         | (0U << 16)   // CHMOD[2] = 0
         | (1U << 25)   // KEYSEL[0] = 1 (DHUK) — verify exact field position in RM0456 §33
         | (1U << 24)   // KMOD = 01 (wrapped key)
         | (2U << 1);   // DATATYPE = byte swap

// 3. Wait for KEYVALID
while (!(SAES->SR & SAES_SR_KEYVALID)) {}

// 4. Enable
SAES->CR |= SAES_CR_EN;

// 5. Feed first 128-bit block of MasterKey (4 × 32-bit words)
for (int i = 0; i < 4; i++)
    SAES->DINR = masterkey_words[i];

// 6. Wait for CCF (Computation Complete Flag)
while (!(SAES->SR & SAES_SR_CCF)) {}

// 7. Read wrapped output
for (int i = 0; i < 4; i++)
    wrapped_words[i] = SAES->DOUTR;

// 8. Clear CCF
SAES->ICR = SAES_ICR_CCF;

// 9. Feed second 128-bit block
for (int i = 0; i < 4; i++)
    SAES->DINR = masterkey_words[4 + i];

while (!(SAES->SR & SAES_SR_CCF)) {}
for (int i = 0; i < 4; i++)
    wrapped_words[4 + i] = SAES->DOUTR;

// 10. Disable
SAES->CR &= ~SAES_CR_EN;
```

**Unwrapping (decrypt with DHUK):**

Set `MODE=10` (decryption, bits 4:3 = `10`) instead of `00`. With KMOD=01, the unwrapped key is **loaded directly into the SAES key registers** — DOUTR reads as zero. The key is then available for subsequent SAES operations in normal mode (change KMOD to 00, select desired CHMOD). However, for our two-level approach, we actually want the plaintext MasterKey in SRAM (to feed into HKDF). In that case, use **KMOD=00 (normal mode)** with KEYSEL=001 (DHUK) for direct decryption — this outputs the plaintext to DOUTR.

```c
// Unwrap MasterKey to SRAM (KMOD=00, KEYSEL=DHUK, MODE=decryption)
SAES->CR = (1U << 18) | (2U << 3) | (1U << 25) | (0U << 24) | (2U << 1);
//          KEYSIZE=256  MODE=decrypt  KEYSEL=DHUK  KMOD=normal  DATATYPE=byteswap
```

**I don't know** the exact bit-field positions with certainty across all RM0456 revisions — the KEYSEL and KMOD fields overlap in some register descriptions. Verify against RM0456 Rev 6+ or the CMSIS `stm32u585xx.h` header's `SAES_CR_KEYSEL_Pos`, `SAES_CR_KMOD_Pos` definitions.

### HAL-level code (recommended for production)

```c
CRYP_HandleTypeDef hcryp_saes;

void saes_init_dhuk_ecb(void) {
    hcryp_saes.Instance            = SAES;
    hcryp_saes.Init.DataType       = CRYP_NO_SWAP;
    hcryp_saes.Init.KeySize        = CRYP_KEYSIZE_256B;
    hcryp_saes.Init.Algorithm      = CRYP_AES_ECB;
    hcryp_saes.Init.KeyMode        = CRYP_KEYMODE_WRAPPED;
    hcryp_saes.Init.KeySelect      = CRYP_KEYSEL_HW;  // = DHUK
    hcryp_saes.Init.KeyProtection  = CRYP_KEYPROT_DISABLE;
    HAL_CRYP_Init(&hcryp_saes);
}

// Wrap 32 bytes of MasterKey → 32 bytes ciphertext
HAL_StatusTypeDef wrap_master_key(const uint32_t plain[8], uint32_t wrapped[8]) {
    return HAL_CRYPEx_WrapKey(&hcryp_saes, plain, wrapped, HAL_MAX_DELAY);
}

// Unwrap 32 bytes → plaintext in SRAM (use for HKDF input)
HAL_StatusTypeDef unwrap_master_key(const uint32_t wrapped[8], uint32_t plain[8]) {
    // For SRAM output: use normal decrypt, not HAL_CRYPEx_UnwrapKey
    // (UnwrapKey loads into key registers, not SRAM)
    hcryp_saes.Init.KeyMode = CRYP_KEYMODE_NORMAL;
    HAL_CRYP_Init(&hcryp_saes);
    return HAL_CRYP_Decrypt(&hcryp_saes, (uint32_t*)wrapped, 8, plain, HAL_MAX_DELAY);
}
```

The STM32CubeU5 example `CRYP_SAES_WrapKey` (under `Projects/B-U585I-IOT02A/Examples/CRYP/`) demonstrates this exact pattern.

### Errata ES0499

**Section 2.16.1** documents that TAMP_BKPxR reads for BHK/DHUK⊕BHK must occur in ascending order. This errata **does not affect DHUK-only usage** (KEYSEL=001) because DHUK loading is entirely hardware-internal and does not involve TAMP register reads. The HAL handles this correctly for BHK paths, but since PQSigner uses DHUK-only, no workaround is needed.

**RNG dependency**: SAES requires the RNG peripheral to be initialized before any operation (it fetches random seed internally for SCA countermeasures). Always call `HAL_RNG_Init()` before any SAES function. If the RNG has an error, the SAES sets the **RNGEIF** flag and refuses to operate.

---

## 5. Secure flash layout for wrapped key storage

The STM32U585 has 2 MB dual-bank flash with **8 KB page size** and 16-byte (128-bit aligned) minimum programming granularity. With TrustZone, Bank 1 is assigned to the Secure world.

```
Bank 1 — Secure World (1 MB: 0x0800_0000 – 0x080F_FFFF)
┌─────────────────────────────────────────────────────────────┐
│ 0x0800_0000  Secure Bootloader (HDP-protected)     64 KB   │
│ 0x0801_0000  Secure Firmware (PQSigner Secure)    448 KB   │
│ 0x0808_0000  Key Storage Page A                     8 KB   │
│ 0x0808_2000  Key Storage Page B (redundant copy)    8 KB   │
│ 0x0808_4000  Attestation / Certificates            16 KB   │
│ 0x0808_8000  Monotonic counters / state            8 KB    │
│ 0x0808_A000  Reserved / future                   478 KB    │
└─────────────────────────────────────────────────────────────┘

Bank 2 — Non-Secure World (1 MB: 0x0810_0000 – 0x081F_FFFF)
┌─────────────────────────────────────────────────────────────┐
│ 0x0810_0000  Non-Secure Firmware (UI/USB)         768 KB   │
│ 0x081C_0000  Firmware update staging area         256 KB   │
└─────────────────────────────────────────────────────────────┘

OTP Area (512 bytes):
  Byte 0:      Provisioning state (0xFF=virgin, 0x01=provisioned)
  Bytes 1-4:   Provisioning timestamp
  Byte 5:      Key blob format version
  Bytes 6-37:  SHA-256 of binding record (immutable reference)
  Bytes 38-511: Reserved
```

### Wrapped key blob format

Each secret stored on Key Storage Page A uses this structure:

```c
typedef struct __attribute__((packed)) {
    uint32_t magic;           // 0x504B4559 ("PKEY")
    uint8_t  version;         // Blob format version (1)
    uint8_t  key_type;        // 0=MASTER_KEY, 1=SCP03, 2=PBS, 3=BINDING
    uint8_t  reserved[2];     // Alignment
    uint8_t  iv[12];          // GCM nonce (Level 2), or zeros (Level 1 ECB)
    uint8_t  ciphertext[80];  // Max payload (padded)
    uint8_t  tag[16];         // GCM auth tag (Level 2), or CMAC (Level 1)
    uint32_t crc32;           // Structural integrity (not crypto — for flash bit-rot)
} WrappedKeyBlob_t;           // 116 bytes total
```

Key Storage Page A holds:

| Blob | key_type | Payload | Wrapping |
|------|----------|---------|----------|
| MasterKey | 0 | 32 bytes (AES-256) | DHUK-ECB (Level 1) |
| SCP03 keys | 1 | 48 bytes (3×16) | AES-GCM with HKDF(MK,"SCP03") |
| OPTIGA PBS | 2 | 64 bytes | AES-GCM with HKDF(MK,"OPTIGA-PBS") |
| Binding record | 3 | ~128 bytes | AES-GCM with HKDF(MK,"BINDING") |

Key Storage Page B is an exact mirror, updated atomically (write B, verify, then optionally erase/rewrite A). The 8 KB page holds all four blobs with ample room. A single page erase + rewrite cycle handles any update.

---

## 6. Domain tag migration for firmware upgrades

### Why this is straightforward on STM32U5

Unlike the STM32H5 series (which has HDPL-dependent DHUK derivation and EPOCH counters that change the DHUK on firmware updates), the **STM32U585 DHUK is constant across all firmware versions**. It depends solely on the silicon-fused RHUK, with no firmware measurement input. This eliminates the key-migration problem entirely for Level 1 wrapping.

For Level 2 wrapping (AES-GCM with HKDF-derived keys), the MasterKey is constant (wrapped by constant DHUK), and the HKDF labels are compile-time constants embedded in the blob's `key_type` field. As long as firmware maintains backward-compatible blob parsing, keys survive any firmware update.

### Migration strategy for blob format changes

```
Boot-time wrapped-key migration:
1. Read blob header (magic + version)
2. If version == current_version → unwrap normally
3. If version < current_version → legacy unwrap path:
   a. Unwrap MasterKey (DHUK-ECB — never changes)
   b. Derive per-purpose key using OLD HKDF label (looked up by version)
   c. Decrypt payload with old parameters
   d. Re-encrypt with new format
   e. Write new blob to Page B
   f. Verify new blob by unwrapping
   g. Copy Page B → Page A
4. If version > current_version → refuse (anti-rollback)
```

The blob `version` field plus the OTP `key blob format version` enable forward-compatible parsing. Because the MasterKey wrapping (DHUK-ECB) never changes, the migration only involves re-deriving per-purpose keys with updated HKDF labels — a software-only operation.

### Anti-rollback consideration

Since there is no hardware-enforced anti-rollback on STM32U5 DHUK (unlike STM32H5 EPOCH), anti-rollback must be enforced in software. Use the OPTIGA Trust M's **monotonic counter** (OID `0xF1E0`, type UpCounter) to store the minimum firmware version. At boot, read the counter; if `current_fw_version < counter_value`, refuse to operate. During firmware update, increment the counter. The counter is protected by the shielded connection (access condition: Conf(0xE140)), preventing manipulation without the PBS.

---

## 7. Per-device attestation binding and anti-swap scheme

### Reading all three UIDs

| Chip | UID Source | Size | API |
|------|-----------|------|-----|
| STM32U585 | `0x0BFA0700` (3 × 32-bit registers) | 12 bytes | `HAL_GetUIDw0/1/2()` |
| SE050 | `se05x_GetInfo` proprietary APDU (CLA=0x80, INS=0x04) | 18 bytes | NXP Plug&Trust `Se05x_API_ReadIdList` / `ssscli se05x uid` |
| OPTIGA Trust M | OID `0xE0C2` via `optiga_util_read_data()` | 27 bytes | `GetDataObject(0xE0C2)` |

### Binding record construction

During factory provisioning, the provisioner reads all three UIDs, constructs the binding payload, and signs it:

```c
typedef struct __attribute__((packed)) {
    uint8_t  version;                // 1
    uint8_t  se050_uid[18];          // From se05x_GetInfo
    uint8_t  optiga_uid[27];         // From OID 0xE0C2
    uint8_t  stm32_uid[12];         // From 0x0BFA0700
    uint8_t  fw_version[4];          // Major.Minor.Patch.Build
    uint64_t provisioning_ts;        // Unix timestamp
    uint8_t  provisioner_pubkey[64]; // Uncompressed P-256 public key (X,Y)
    uint8_t  signature[64];          // ECDSA-P256(SHA-256(above fields), provisioner_privkey)
} BindingRecord_t;                   // ~198 bytes
```

The provisioner's public key is embedded in firmware (Secure world, read-only flash, HDP-protected). The binding record is stored in three locations:

- **STM32 flash**: Wrapped with HKDF(MasterKey, "BINDING") via AES-GCM → tied to this STM32's DHUK
- **SE050**: Binary object at ID `0x10000001`, policy = read-only after provisioning, SCP03 required
- **OPTIGA**: Data object at OID `0xF1D1`, access = Conf(0xE140) (shielded connection required)
- **OTP**: SHA-256 of the binding record burned to OTP bytes 6-37 as an immutable reference

### Boot-time verification flow

```
PHASE 1: Hardware init (~10 ms)
  STM32 Secure World boots → verify firmware signature → read STM32 UID

PHASE 2: SE050 binding check (~300-600 ms)
  Unwrap MasterKey from flash (DHUK-ECB) → derive SCP03 wrapping key
  → unwrap SCP03 keys (AES-GCM) → establish SCP03 session (KVN=0x11)
  → read SE050 UID via authenticated channel
  → optionally: ReadObject_W_Attst with key 0xF0000012 + random challenge
    (proves SE050 is genuine NXP silicon, not an emulator)

PHASE 3: OPTIGA binding check (~200-400 ms)
  Derive PBS wrapping key → unwrap PBS (AES-GCM)
  → establish shielded connection (TLS-PRF handshake)
  → read OPTIGA UID from OID 0xE0C2 via protected channel
  → optionally: sign random challenge with key 0xE0F0, verify against
    cert at 0xE0E0 (Infineon OPTIGA ECC Root CA 2 chain)

PHASE 4: Binding verification (~1 ms)
  Unwrap stored binding record (AES-GCM)
  Verify provisioner signature over binding record fields
  Compare: binding.se050_uid == actual SE050 UID
  Compare: binding.optiga_uid == actual OPTIGA UID
  Compare: binding.stm32_uid == actual STM32 UID
  Verify: SHA-256(binding_record) == OTP[6:37]

  IF ANY MISMATCH:
    → Erase Key Storage Pages A + B
    → Attempt to wipe SE050 objects (if SCP03 session is up)
    → Enter permanent brick state (halt in Secure World, no NS transition)

  IF ALL MATCH:
    → Zeroize PBS from SRAM
    → Transition to Non-Secure world (UI/USB firmware)
```

Total boot binding check takes approximately **500 ms to 1.2 seconds**, dominated by I2C communication with the two SEs. This is acceptable for a hardware wallet where the user expects a brief boot screen.

### Why each swap attack fails

**SE050 moved to attacker's board**: The attacker's STM32 has a different DHUK, so it cannot unwrap the SCP03 keys. Even if the attacker provisions fresh SCP03 keys, the binding record inside the SE050 (at `0x10000001`) references the victim's STM32 UID, which won't match the attacker's. The binding record in the attacker's flash is either absent or encrypted with a different DHUK.

**OPTIGA moved to attacker's board**: The attacker's STM32 cannot unwrap the PBS (different DHUK), so the shielded connection fails immediately. The OPTIGA's stored binding record at `0xF1D1` is inaccessible without the shielded connection, and even if somehow read, it references the wrong STM32 UID.

**Both SEs moved together**: Still fails — the attacker's STM32 has a different DHUK, cannot unwrap any secrets. The SEs are cryptographically bricked on the new board.

**STM32 replaced (both SEs kept)**: New STM32 has different DHUK, same result. The wrapped key blobs in flash (transferred with the SEs or re-created) are useless because the new DHUK differs.

**Binding record cloned**: The binding record ciphertext in flash is DHUK-encrypted. Copying the ciphertext to a different STM32 produces garbage on decryption. The OTP hash cannot be replicated (OTP is one-time-write).

### Reference: how Trezor Safe 3/5 implements this

The Trezor Safe 3 and Safe 5 use a closely analogous architecture: **STM32U5 + OPTIGA Trust M V3**. Their implementation uses the PBS at OID 0xE140 for MCU-SE binding, the device private key at 0xE0F0 for attestation challenge-response (signed by Trezor's own CA, not Infineon's default), and cascading access conditions on PIN-related objects that require the shielded connection. The Trezor Safe 5 additionally incorporates the STM32U5 AES hardware key (equivalent to our DHUK usage) as an extra binding factor. A Ledger Donjon security review noted that while this design strongly binds the OPTIGA to the MCU, it does not directly attest what firmware runs on the MCU — a limitation shared by our design. Firmware attestation is a separate concern handled by secure boot signature verification.

PQSigner OS's design extends Trezor's pattern by adding a **second SE (SE050)** with independent SCP03 binding, a **cryptographic binding record signed by the provisioner**, and an **OTP hash anchor** — providing defense-in-depth that Trezor's single-SE design lacks.

---

## Conclusion

The protocol described here achieves strong per-device isolation through three interlocking mechanisms: **DHUK-rooted key wrapping** ensures all host-side secrets are bound to a specific STM32U585 die; **channel-level authentication** (SCP03 for SE050, shielded connection for OPTIGA) ensures the SEs only respond to the MCU that knows their provisioned secrets; and the **signed binding record** with OTP hash creates a tamper-evident chain linking all three chip UIDs.

The most important implementation subtlety is the **RDP-level dependency of DHUK**: all production key wrapping must occur at RDP ≥ 1, not RDP0. The provisioning flow must therefore stage firmware, elevate to RDP1, then perform secret wrapping autonomously before burning RDP2. A second subtlety is that SAES wrapping is unauthenticated ECB — the two-level wrapping approach (DHUK-ECB for a MasterKey, then software AES-GCM for individual secrets) provides the authenticated encryption that raw SAES wrapping lacks.

Key unknowns remaining from public documentation: the exact SAES_CR bit-field positions for KEYSEL and KMOD should be confirmed against the latest RM0456 revision or CMSIS headers (the register map varies slightly across RM revisions); STM32U585 UID readability at RDP2 from user firmware is undocumented by ST (likely works since it is memory-mapped ROM, but should be verified on hardware); and the NXP Root CA public key for SE050 attestation verification is distributed only within the Plug & Trust middleware package, not on public web pages.