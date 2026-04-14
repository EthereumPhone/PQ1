# Research Prompt B — Production Key Management (SCP03 + PBS + HUK-SAES)

## Research question

Design a production provisioning + runtime key-management protocol:

1. Rotate SE050 SCP03 static ENC/MAC keys from NXP defaults to per-
   device-unique at chip personalization. Store the new keys on the
   STM32 side HUK-SAES-wrapped (never in plaintext flash).
2. Wrap the OPTIGA Platform Binding Secret the same way.
3. Handle PQSigner firmware upgrade: if a newer firmware includes a
   different HUK-SAES domain tag, how does it recover existing users'
   keys without requiring chip reset?
4. Establish verifiable per-device attestation binding physical
   SE050 + OPTIGA UIDs to the STM32 chip-unique-ID, so that swap
   attacks (move SE from a victim device to attacker's device) fail
   at boot.

Constraints: key rotation happens at one-time factory provisioning (no
field rekey). Out-of-band transport via a secure provisioner machine
is acceptable. Bricked-HUK recovery is NOT required — the wallet can
be considered dead, user restores from 24-word backup.

Deliverables: protocol diagram + flash-layout sketch + the minimum
STM32U585 SAES API usage pattern. Reference implementations from
other hardware wallets are useful.


---

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant code and design


### `secure/src/se050/scp03.rs`

```rust
//! SCP03 (Secure Channel Protocol 03) for SE050.
//!
//! Establishes an authenticated, encrypted channel with the SE050 using
//! GlobalPlatform SCP03.  After session establishment every APDU is
//! MAC'd (C-MAC) and its data encrypted (C-DEC).
//!
//! HW lesson #6: SE050E requires P1=0x03 (C-MAC + C-DEC) in EXTERNAL
//! AUTHENTICATE.  This module always uses that security level.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use cmac::Cmac;
use cmac::Mac as CmacMac;

use super::apdu::Se050Error;

// ---------------------------------------------------------------------------
// SE050E platform keys (OEF 0xA921)
// ---------------------------------------------------------------------------

const PLATFORM_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7,
    0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
const PLATFORM_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0,
    0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];

const KEY_VERSION: u8 = 0x0B;

// SCP03 derivation data constants
const DD_CARD_CRYPTOGRAM: u8 = 0x00;
const DD_HOST_CRYPTOGRAM: u8 = 0x01;
const DD_S_ENC: u8 = 0x04;
const DD_S_MAC: u8 = 0x06;
const DD_S_RMAC: u8 = 0x07;

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// SCP03 session — holds derived session keys and MAC chaining value.
pub struct Scp03Session {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    /// MAC Chaining Value — updated after every wrapped command.
    pub mcv: [u8; 16],
    /// Command counter for IV derivation (big-endian, incremented per command).
    pub counter: [u8; 16],
    /// Whether the session is established.
    pub active: bool,
}

impl Scp03Session {
    pub const fn new() -> Self {
        Self {
            s_enc: [0; 16],
            s_mac: [0; 16],
            s_rmac: [0; 16],
            mcv: [0; 16],
            counter: [0; 16],
            active: false,
        }
    }

    fn inc_counter(&mut self) {
        for i in (0..16).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// CMAC-AES-128 over the concatenation of all input slices.
fn cmac_aes128(key: &[u8; 16], inputs: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as CmacMac>::new_from_slice(key).unwrap();
    for input in inputs {
        CmacMac::update(&mut mac, input);
    }
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// AES-128 ECB encrypt a single block.
fn aes128_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut out);
    let mut result = [0u8; 16];
    result.copy_from_slice(&out);
    result
}

/// AES-128-CBC encrypt in-place.
pub fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev.copy_from_slice(chunk);
    }
}

/// AES-128-CBC decrypt in-place.
pub fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let mut ct = [0u8; 16];
        ct.copy_from_slice(chunk);
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = ct;
    }
}

// ---------------------------------------------------------------------------
// SCP03 KDF (NIST SP 800-108 Counter Mode with CMAC-AES)
// ---------------------------------------------------------------------------

fn build_derivation_data(
    dd_constant: u8,
    l_bits: u16,
    host_challenge: &[u8; 8],
    card_challenge: &[u8; 8],
) -> [u8; 32] {
    let mut dd = [0u8; 32];
    // Bytes 0-10: zero
    dd[11] = dd_constant;
    dd[12] = 0x00; // separation indicator
    dd[13] = (l_bits >> 8) as u8;
    dd[14] = (l_bits & 0xFF) as u8;
    dd[15] = 0x01; // counter (always 1 for 128-bit output)
    dd[16..24].copy_from_slice(host_challenge);
    dd[24..32].copy_from_slice(card_challenge);
    dd
}

fn kdf(static_key: &[u8; 16], dd: &[u8; 32]) -> [u8; 16] {
    cmac_aes128(static_key, &[dd])
}

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

/// Establish an SCP03 session with the SE050.
///
/// Sends INITIALIZE UPDATE and EXTERNAL AUTHENTICATE, derives session
/// keys, and verifies the card cryptogram. After this succeeds, all
/// APDUs wrapped via `wrap_apdu` will be MAC'd and encrypted.
pub unsafe fn establish(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
) -> Result<(), Se050Error> {
    // Generate 8-byte host challenge from hardware TRNG
    let mut host_challenge = [0u8; 8];
    crate::rng::fill(&mut host_challenge).map_err(|_| Se050Error::Scp03)?;

    // --- INITIALIZE UPDATE ---
    let mut init_update = [0u8; 13];
    init_update[0] = 0x80; // CLA
    init_update[1] = 0x50; // INS_INITIALIZE_UPDATE
    init_update[2] = KEY_VERSION;
    init_update[3] = 0x00;
    init_update[4] = 0x08; // Lc
    init_update[5..13].copy_from_slice(&host_challenge);

    let mut resp = [0u8; 64];
    let n = t1.transceive(&init_update, &mut resp).map_err(|_| Se050Error::Transport)?;

    if n < 31 {
        return Err(Se050Error::Scp03);
    }

    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    if sw != 0x9000 {
        return Err(Se050Error::Status(sw));
    }

    // Parse: KeyDivData(10) + KeyInfo(3) + CardChallenge(8) + CardCryptogram(8)
    let mut card_challenge = [0u8; 8];
    card_challenge.copy_from_slice(&resp[13..21]);
    let mut card_cryptogram = [0u8; 8];
    card_cryptogram.copy_from_slice(&resp[21..29]);

    // --- Derive session keys ---
    let dd_enc = build_derivation_data(DD_S_ENC, 0x0080, &host_challenge, &card_challenge);
    let dd_mac = build_derivation_data(DD_S_MAC, 0x0080, &host_challenge, &card_challenge);
    let dd_rmac = build_derivation_data(DD_S_RMAC, 0x0080, &host_challenge, &card_challenge);

    session.s_enc = kdf(&PLATFORM_ENC, &dd_enc);
    session.s_mac = kdf(&PLATFORM_MAC, &dd_mac);
    session.s_rmac = kdf(&PLATFORM_MAC, &dd_rmac);

    // --- Verify card cryptogram ---
    let dd_card = build_derivation_data(DD_CARD_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    let card_crypto_computed = kdf(&session.s_mac, &dd_card);

    if card_crypto_computed[..8] != card_cryptogram[..] {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] Card cryptogram MISMATCH");
        return Err(Se050Error::Scp03);
    }

    // --- Compute host cryptogram ---
    let dd_host = build_derivation_data(DD_HOST_CRYPTOGRAM, 0x0040, &host_challenge, &card_challenge);
    let host_crypto_full = kdf(&session.s_mac, &dd_host);
    let host_cryptogram = &host_crypto_full[..8];

    // --- EXTERNAL AUTHENTICATE ---
    // P1=0x03: C-MAC + C-DEC (HW lesson #6)
    let header = [0x84u8, 0x82, 0x03, 0x00, 0x10];
    session.mcv = [0; 16];
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, &header, host_cryptogram]);
    session.mcv = mac_full;

    let mut ext_auth = [0u8; 21];
    ext_auth[0] = 0x84;
    ext_auth[1] = 0x82;
    ext_auth[2] = 0x03;
    ext_auth[3] = 0x00;
    ext_auth[4] = 0x10; // Lc = 16 (8 host crypto + 8 MAC)
    ext_auth[5..13].copy_from_slice(host_cryptogram);
    ext_auth[13..21].copy_from_slice(&mac_full[..8]);

    let mut ext_resp = [0u8; 32];
    let ext_n = t1.transceive(&ext_auth, &mut ext_resp).map_err(|_| Se050Error::Transport)?;

    if ext_n < 2 {
        return Err(Se050Error::Scp03);
    }
    let ext_sw = ((ext_resp[ext_n - 2] as u16) << 8) | (ext_resp[ext_n - 1] as u16);
    if ext_sw != 0x9000 {
        #[cfg(feature = "debug-log")]
        secure_log!("[SCP03] EXT AUTH SW=0x{:04x}", ext_sw);
        return Err(Se050Error::Status(ext_sw));
    }

    session.counter = [0; 16];
    session.counter[15] = 0x01;
    session.active = true;

    #[cfg(feature = "debug-log")]
    secure_log!("[SCP03] Session established");

    Ok(())
}

// ---------------------------------------------------------------------------
// APDU MAC + encryption wrapping
// ---------------------------------------------------------------------------

/// Compute the command ICV (Initial Chaining Value) for AES-CBC encryption.
fn command_icv(session: &Scp03Session) -> [u8; 16] {
    aes128_ecb_encrypt(&session.s_enc, &session.counter)
}

/// Wrap an APDU with SCP03 C-MAC and C-DEC (command encryption).
///
/// Always applies both C-MAC and C-DEC (P1=0x03 security level).
pub fn wrap_apdu(
    session: &mut Scp03Session,
    apdu: &[u8],
    out: &mut [u8],
) -> usize {
    if !session.active || apdu.len() < 4 {
        out[..apdu.len()].copy_from_slice(apdu);
        return apdu.len();
    }

    // Parse incoming APDU to locate header and data
    let extended = apdu.len() >= 7 && apdu[4] == 0x00;
    let (hdr_len, data_len) = if extended {
        let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
        (7, lc)
    } else if apdu.len() > 5 {
        (5, apdu.len() - 5)
    } else {
        (apdu.len(), 0)
    };
    let has_data = data_len > 0;

    // --- C-DEC: encrypt command data ---
    let enc_len = if has_data {
        let mut enc_buf = [0u8; 1024];
        enc_buf[..data_len].copy_from_slice(&apdu[hdr_len..hdr_len + data_len]);
        // ISO 7816-4 padding: 0x80 then zeros to next 16-byte boundary
        let mut padded_len = data_len;
        enc_buf[padded_len] = 0x80;
        padded_len += 1;
        while padded_len % 16 != 0 {
            enc_buf[padded_len] = 0x00;
            padded_len += 1;
        }
        let icv = command_icv(session);
        aes128_cbc_encrypt(&session.s_enc, &icv, &mut enc_buf[..padded_len]);
        session.inc_counter();
        // Place encrypted data at offset 7 (extended Lc position)
        out[7..7 + padded_len].copy_from_slice(&enc_buf[..padded_len]);
        padded_len
    } else {
        0
    };

    // New Lc = encrypted data + 8-byte MAC
    let new_lc = enc_len + 8;
    let use_extended = extended || new_lc >= 256;
    let out_hdr_len = if use_extended { 7 } else { 5 };

    // Shift data to correct position if header length changed
    if has_data && !use_extended {
        for i in 0..enc_len {
            out[5 + i] = out[7 + i];
        }
    }

    // Write header
    out[0] = apdu[0] | 0x04; // Set CLA security bit
    out[1] = apdu[1];
    out[2] = apdu[2];
    out[3] = apdu[3];

    if use_extended {
        out[4] = 0x00;
        out[5] = (new_lc >> 8) as u8;
        out[6] = (new_lc & 0xFF) as u8;
    } else {
        out[4] = new_lc as u8;
    }

    // Compute C-MAC
    let mac_header = &out[0..out_hdr_len];
    let mac_data = if has_data {
        &out[out_hdr_len..out_hdr_len + enc_len]
    } else {
        &[] as &[u8]
    };
    let mac_full = cmac_aes128(&session.s_mac, &[&session.mcv, mac_header, mac_data]);

    // Append 8-byte MAC
    let mac_offset = out_hdr_len + enc_len;
    out[mac_offset..mac_offset + 8].copy_from_slice(&mac_full[..8]);
    session.mcv = mac_full;

    mac_offset + 8
}

```


### `secure/src/optiga/shield.rs`

```rust
//! Shielded Connection for OPTIGA Trust M (AES-128-CCM-8).
//!
//! Provides an E2E encrypted I2C channel between the STM32U585 secure world
//! and the OPTIGA Trust M chip. Satisfies Invariant #3 (encrypted tunnel).
//!
//! **Protocol:**
//! - Root of trust: Platform Binding Secret (PBS) at OID 0xE140
//! - Key derivation: TLS 1.2 PRF with HMAC-SHA256
//! - Encryption: AES-128-CCM with 8-byte MAC tag
//! - 4-step handshake establishes per-session keys
//!
//! **Crypto dependencies:** Uses `aes` (block cipher), `hmac`, `sha2` —
//! all already in the project's Cargo.toml. AES-128-CCM is implemented
//! manually (CTR mode + CBC-MAC) to avoid adding a `ccm` crate dependency.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-CCM MAC tag length (8 bytes, "CCM-8").
const CCM_TAG_LEN: usize = 8;
/// AES block size.
const AES_BLOCK: usize = 16;
/// CCM nonce length (we use 8 bytes: 4 base + 4 sequence).
const CCM_NONCE_LEN: usize = 8;

/// Shielded connection header: SCTR(1) + SeqNum(4) = 5 bytes.
const SC_HEADER_LEN: usize = 5;
/// Total overhead per message: header + MAC tag.
const SC_OVERHEAD: usize = SC_HEADER_LEN + CCM_TAG_LEN;

/// SCTR byte values.
const SCTR_HANDSHAKE_HELLO: u8 = 0x00;
const SCTR_HANDSHAKE_FINISHED: u8 = 0x08;
const SCTR_RECORD_FULL: u8 = 0x23; // Record type + full protection
const SCTR_ALERT: u8 = 0x40;

/// Protocol version for pre-shared-secret mode.
const PROTOCOL_VERSION: u8 = 0x01;

/// TLS PRF label for Platform Binding key derivation.
const PRF_LABEL: &[u8] = b"Platform Binding";

/// Session key material length: 2×16 (keys) + 2×4 (nonces) = 40 bytes.
const SESSION_KEY_LEN: usize = 40;

/// Master random length.
const RANDOM_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ShieldError {
    NotActive,
    HandshakeFailed,
    DecryptFailed,
    BufferOverflow,
    NoPbs,
}

// ---------------------------------------------------------------------------
// ShieldedConnection state
// ---------------------------------------------------------------------------

/// Shielded Connection session state.
///
/// Manages the AES-128-CCM keys and sequence counters for encrypted
/// communication with the OPTIGA Trust M chip.
pub struct ShieldedConnection {
    /// Host→OPTIGA encryption key (16 bytes).
    enc_key: [u8; 16],
    /// OPTIGA→Host decryption key (16 bytes).
    dec_key: [u8; 16],
    /// Base nonce for encryption direction (4 bytes).
    enc_nonce_base: [u8; 4],
    /// Base nonce for decryption direction (4 bytes).
    dec_nonce_base: [u8; 4],
    /// Encryption message sequence counter.
    enc_seq: u32,
    /// Decryption message sequence counter.
    dec_seq: u32,
    /// Whether the shielded connection is active.
    pub active: bool,
    /// Platform Binding Secret (loaded from secure flash).
    pbs: [u8; 32],
    /// Whether PBS has been loaded.
    pub pbs_loaded: bool,
}

impl ShieldedConnection {
    pub const fn new() -> Self {
        Self {
            enc_key: [0; 16],
            dec_key: [0; 16],
            enc_nonce_base: [0; 4],
            dec_nonce_base: [0; 4],
            enc_seq: 0,
            dec_seq: 0,
            active: false,
            pbs: [0; 32],
            pbs_loaded: false,
        }
    }

    /// Load the Platform Binding Secret from caller-provided buffer.
    pub fn load_pbs(&mut self, pbs: &[u8; 32]) {
        self.pbs.copy_from_slice(pbs);
        self.pbs_loaded = true;
    }

    /// Derive session keys from the PBS and exchanged random values.
    ///
    /// Uses TLS 1.2 PRF (HMAC-SHA256) to expand:
    ///   `PRF(pbs, "Platform Binding", random_m || random_s)` → 40 bytes
    ///
    /// Output layout:
    ///   [0..16]  = Master Encryption Key (host→chip)
    ///   [16..32] = Master Decryption Key (chip→host)
    ///   [32..36] = Encryption nonce base
    ///   [36..40] = Decryption nonce base
    fn derive_session_keys(&mut self, random_m: &[u8; 32], random_s: &[u8; 32]) {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(random_m);
        seed[32..].copy_from_slice(random_s);

        let mut key_material = [0u8; SESSION_KEY_LEN];
        tls_prf_sha256(&self.pbs, PRF_LABEL, &seed, &mut key_material);

        self.enc_key.copy_from_slice(&key_material[0..16]);
        self.dec_key.copy_from_slice(&key_material[16..32]);
        self.enc_nonce_base.copy_from_slice(&key_material[32..36]);
        self.dec_nonce_base.copy_from_slice(&key_material[36..40]);
        self.enc_seq = 0;
        self.dec_seq = 0;

        key_material.zeroize();
        seed.zeroize();
    }

    /// Build the 8-byte CCM nonce from base + sequence counter.
    fn build_nonce(base: &[u8; 4], seq: u32) -> [u8; CCM_NONCE_LEN] {
        let mut nonce = [0u8; CCM_NONCE_LEN];
        nonce[..4].copy_from_slice(base);
        nonce[4] = (seq >> 24) as u8;
        nonce[5] = (seq >> 16) as u8;
        nonce[6] = (seq >> 8) as u8;
        nonce[7] = seq as u8;
        nonce
    }

    /// Build AAD (Associated Authenticated Data) for CCM.
    ///
    /// AAD format: `SCTR(1) | SeqNum(4 BE) | ProtocolVersion(1) | PlaintextLen(2 BE)`
    fn build_aad(sctr: u8, seq: u32, plaintext_len: u16) -> [u8; 8] {
        [
            sctr,
            (seq >> 24) as u8,
            (seq >> 16) as u8,
            (seq >> 8) as u8,
            seq as u8,
            PROTOCOL_VERSION,
            (plaintext_len >> 8) as u8,
            plaintext_len as u8,
        ]
    }

    // -----------------------------------------------------------------------
    // Encrypt / Decrypt
    // -----------------------------------------------------------------------

    /// Encrypt an APDU command for the shielded connection.
    ///
    /// Output format: `SCTR(1) | SeqNum(4 BE) | Ciphertext | MAC(8)`
    ///
    /// Returns the total output length.
    pub fn wrap_command(
        &mut self,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ShieldError> {
        if !self.active {
            return Err(ShieldError::NotActive);
        }

        let out_len = SC_HEADER_LEN + plaintext.len() + CCM_TAG_LEN;
        if out_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        // Header: SCTR + SeqNum
        out[0] = SCTR_RECORD_FULL;
        out[1] = (self.enc_seq >> 24) as u8;
        out[2] = (self.enc_seq >> 16) as u8;
        out[3] = (self.enc_seq >> 8) as u8;
        out[4] = self.enc_seq as u8;

        // Build nonce and AAD
        let nonce = Self::build_nonce(&self.enc_nonce_base, self.enc_seq);
        let aad = Self::build_aad(SCTR_RECORD_FULL, self.enc_seq, plaintext.len() as u16);

        // AES-128-CCM encrypt
        let mut ciphertext_and_tag = [0u8; 600];
        let ct_len = aes128_ccm_encrypt(
            &self.enc_key,
            &nonce,
            &aad,
            plaintext,
            &mut ciphertext_and_tag,
        );

        out[SC_HEADER_LEN..SC_HEADER_LEN + ct_len].copy_from_slice(&ciphertext_and_tag[..ct_len]);

        self.enc_seq += 1;
        Ok(out_len)
    }

    /// Decrypt a response from the shielded connection.
    ///
    /// Input format: `SCTR(1) | SeqNum(4 BE) | Ciphertext | MAC(8)`
    ///
    /// Returns the plaintext length.
    pub fn unwrap_response(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ShieldError> {
        if !self.active {
            return Err(ShieldError::NotActive);
        }
        if input.len() < SC_OVERHEAD {
            return Err(ShieldError::DecryptFailed);
        }

        let _sctr = input[0];
        let seq = ((input[1] as u32) << 24)
            | ((input[2] as u32) << 16)
            | ((input[3] as u32) << 8)
            | input[4] as u32;

        let ct_and_tag = &input[SC_HEADER_LEN..];
        let plaintext_len = ct_and_tag.len() - CCM_TAG_LEN;

        if plaintext_len > out.len() {
            return Err(ShieldError::BufferOverflow);
        }

        let nonce = Self::build_nonce(&self.dec_nonce_base, seq);
        let aad = Self::build_aad(SCTR_RECORD_FULL, seq, plaintext_len as u16);

        let ok = aes128_ccm_decrypt(
            &self.dec_key,
            &nonce,
            &aad,
            ct_and_tag,
            out,
        );

        if !ok {
            return Err(ShieldError::DecryptFailed);
        }

        self.dec_seq = seq + 1;
        Ok(plaintext_len)
    }

    // -----------------------------------------------------------------------
    // Handshake
    // -----------------------------------------------------------------------

    /// Perform the 4-step Shielded Connection handshake.
    ///
    /// Requires a mutable reference to the IFX I2C state for sending/receiving
    /// handshake messages directly (bypassing the shielded encryption layer).
    ///
    /// This must be called AFTER `open_application()` and BEFORE any protected
    /// APDU commands.
    pub unsafe fn establish(
        &mut self,
        ifx: &mut super::ifx_i2c::IfxState,
    ) -> Result<(), ShieldError> {
        if !self.pbs_loaded {
            return Err(ShieldError::NoPbs);
        }

        // Generate master random from TRNG
        let mut random_m = [0u8; RANDOM_LEN];
        crate::rng::fill(&mut random_m).map_err(|_| ShieldError::HandshakeFailed)?;

        // Step 1: Send MasterHello
        // Format: SCTR(0x00) | ProtocolVersion(0x01)
        let hello = [SCTR_HANDSHAKE_HELLO, PROTOCOL_VERSION];
        let mut resp = [0u8; 64];
        let n = ifx.transceive(&hello, &mut resp)
            .map_err(|_| ShieldError::HandshakeFailed)?;

        // Step 2: Parse SlaveHello
        // Format: SCTR(0x00) | Random_S(32) | SeqNum_S(4)
        if n < 1 + RANDOM_LEN + 4 {
            return Err(ShieldError::HandshakeFailed);
        }
        let mut random_s = [0u8; RANDOM_LEN];
        random_s.copy_from_slice(&resp[1..1 + RANDOM_LEN]);
        let mut seq_s = [0u8; 4];
        seq_s.copy_from_slice(&resp[1 + RANDOM_LEN..1 + RANDOM_LEN + 4]);

        // Step 3: Derive session keys
        self.derive_session_keys(&random_m, &random_s);

        // Step 4: Send MasterFinished
        // Encrypt: Random_M(32) + SeqNum_S(4) with derived enc_key
        let mut finished_plain = [0u8; 36];
        finished_plain[..32].copy_from_slice(&random_m);
        finished_plain[32..36].copy_from_slice(&seq_s);

        let nonce = Self::build_nonce(&self.enc_nonce_base, 0);
        let aad = Self::build_aad(SCTR_HANDSHAKE_FINISHED, 0, 36);

        let mut finished_enc = [0u8; 64];
        let ct_len = aes128_ccm_encrypt(
            &self.enc_key,
            &nonce,
            &aad,
            &finished_plain,
            &mut finished_enc,
        );

        // Build finished message: SCTR(0x08) | SeqNum(4) | ciphertext+tag
        let mut finished_msg = [0u8; 128];
        finished_msg[0] = SCTR_HANDSHAKE_FINISHED;
        finished_msg[1..5].copy_from_slice(&[0, 0, 0, 0]); // seq = 0
        finished_msg[5..5 + ct_len].copy_from_slice(&finished_enc[..ct_len]);
        let msg_len = 5 + ct_len;

        let mut resp2 = [0u8; 128];
        let n2 = ifx.transceive(&finished_msg[..msg_len], &mut resp2)
            .map_err(|_| ShieldError::HandshakeFailed)?;

        // Step 5: Verify SlaveFinished
        if n2 < SC_HEADER_LEN + CCM_TAG_LEN {
            return Err(ShieldError::HandshakeFailed);
        }
        let dec_nonce = Self::build_nonce(&self.dec_nonce_base, 0);
        let slave_ct = &resp2[SC_HEADER_LEN..n2];
        let slave_pt_len = slave_ct.len() - CCM_TAG_LEN;
        let dec_aad = Self::build_aad(SCTR_HANDSHAKE_FINISHED, 0, slave_pt_len as u16);

        let mut slave_plain = [0u8; 64];
        let ok = aes128_ccm_decrypt(
            &self.dec_key,
            &dec_nonce,
            &dec_aad,
            slave_ct,
            &mut slave_plain,
        );
        if !ok {
            return Err(ShieldError::HandshakeFailed);
        }

        // Session established — start sequence counters at 1
        self.enc_seq = 1;
        self.dec_seq = 1;
        self.active = true;

        random_m.zeroize();
        finished_plain.zeroize();

        Ok(())
    }
}

impl Drop for ShieldedConnection {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.dec_key.zeroize();
        self.enc_nonce_base.zeroize();
        self.dec_nonce_base.zeroize();
        self.pbs.zeroize();
    }
}

// ---------------------------------------------------------------------------
// TLS 1.2 PRF (HMAC-SHA256)
// ---------------------------------------------------------------------------

/// TLS 1.2 PRF using HMAC-SHA256 (RFC 5246 §5).
///
/// `P_SHA256(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...`
/// where `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
///
/// The full PRF seed is: `label || seed`.
fn tls_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    // Combine label + seed
    let mut combined = [0u8; 128];
    let combined_len = label.len() + seed.len();
    combined[..label.len()].copy_from_slice(label);
    combined[label.len()..combined_len].copy_from_slice(seed);
    let combined = &combined[..combined_len];

    // A(1) = HMAC(secret, seed)
    let mut a = hmac_sha256(secret, combined);

    let mut offset = 0;
    while offset < output.len() {
        // HMAC(secret, A(i) || seed)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret).unwrap();
        mac.update(&a);
        mac.update(combined);
        let result = mac.finalize().into_bytes();

        let copy_len = (output.len() - offset).min(32);
        output[offset..offset + copy_len].copy_from_slice(&result[..copy_len]);
        offset += copy_len;

        // A(i+1) = HMAC(secret, A(i))
        if offset < output.len() {
            a = hmac_sha256(secret, &a);
        }
    }
}

/// Simple HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// AES-128-CCM-8 (manual implementation using AES block cipher)
// ---------------------------------------------------------------------------
//
// CCM (Counter with CBC-MAC) combines:
// 1. CBC-MAC for authentication (produces tag)
// 2. CTR mode for encryption (encrypts payload + tag)
//
// We use CCM-8: 8-byte MAC tag (t=8), 8-byte nonce (n=8, so q=7).

/// AES-128-CCM encrypt. Returns total output length (ciphertext + 8-byte tag).
fn aes128_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let cipher = Aes128::new(key.into());
    let tag = ccm_cbc_mac(&cipher, nonce, aad, plaintext);

    // CTR mode: encrypt plaintext + tag
    // A_0 = Flags(1) || Nonce(8) || Counter(7, starting at 0)
    // We encrypt the tag with A_0, then plaintext with A_1, A_2, ...
    let mut a_block = [0u8; AES_BLOCK];
    // Flags: (t-2)/2 = 3 in bits 5-3, q-1 = 6 in bits 2-0
    // Actually for CCM with n=8, q=7 (15-8), flags for A_i = q-1 = 6
    a_block[0] = 6; // q - 1 = 7 - 1 = 6
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Encrypt tag with A_0 (counter = 0)
    set_counter(&mut a_block, 0);
    let mut s0 = a_block;
    let s0_block = aes::Block::from_mut_slice(&mut s0);
    cipher.encrypt_block(s0_block);
    let mut encrypted_tag = [0u8; CCM_TAG_LEN];
    for i in 0..CCM_TAG_LEN {
        encrypted_tag[i] = tag[i] ^ s0[i];
    }

    // Encrypt plaintext with A_1, A_2, ...
    let mut counter: u64 = 1;
    let mut pt_offset = 0;
    while pt_offset < plaintext.len() {
        set_counter(&mut a_block, counter);
        let mut keystream = a_block;
        let ks_block = aes::Block::from_mut_slice(&mut keystream);
        cipher.encrypt_block(ks_block);

        let chunk = (plaintext.len() - pt_offset).min(AES_BLOCK);
        for i in 0..chunk {
            out[pt_offset + i] = plaintext[pt_offset + i] ^ keystream[i];
        }
        pt_offset += chunk;
        counter += 1;
    }

    // Append encrypted tag
    out[plaintext.len()..plaintext.len() + CCM_TAG_LEN]
        .copy_from_slice(&encrypted_tag);

    plaintext.len() + CCM_TAG_LEN
}

/// AES-128-CCM decrypt. Returns `true` if tag verification succeeds.
/// Writes plaintext to `out[..ct_and_tag.len() - CCM_TAG_LEN]`.
fn aes128_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut [u8],
) -> bool {
    if ct_and_tag.len() < CCM_TAG_LEN {
        return false;
    }

    let ct_len = ct_and_tag.len() - CCM_TAG_LEN;
    let ciphertext = &ct_and_tag[..ct_len];
    let received_enc_tag = &ct_and_tag[ct_len..];

    let cipher = Aes128::new(key.into());

    // CTR decrypt: A_0 for tag, A_1.. for data
    let mut a_block = [0u8; AES_BLOCK];
    a_block[0] = 6; // q - 1
    a_block[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Decrypt tag with A_0
    set_counter(&mut a_block, 0);
    let mut s0 = a_block;
    let s0_block = aes::Block::from_mut_slice(&mut s0);
    cipher.encrypt_block(s0_block);
    let mut received_tag = [0u8; CCM_TAG_LEN];
    for i in 0..CCM_TAG_LEN {
        received_tag[i] = received_enc_tag[i] ^ s0[i];
    }

    // Decrypt ciphertext with A_1, A_2, ...
    let mut counter: u64 = 1;
    let mut ct_offset = 0;
    while ct_offset < ct_len {
        set_counter(&mut a_block, counter);
        let mut keystream = a_block;
        let ks_block = aes::Block::from_mut_slice(&mut keystream);
        cipher.encrypt_block(ks_block);

        let chunk = (ct_len - ct_offset).min(AES_BLOCK);
        for i in 0..chunk {
            out[ct_offset + i] = ciphertext[ct_offset + i] ^ keystream[i];
        }
        ct_offset += chunk;
        counter += 1;
    }

    // Recompute CBC-MAC over decrypted plaintext
    let expected_tag = ccm_cbc_mac(&cipher, nonce, aad, &out[..ct_len]);

    // Constant-time tag comparison
    let mut diff: u8 = 0;
    for i in 0..CCM_TAG_LEN {
        diff |= received_tag[i] ^ expected_tag[i];
    }
    diff == 0
}

/// Compute CCM CBC-MAC (authentication tag).
///
/// B_0 = Flags || Nonce || Q (message length)
/// If AAD present: B_1 = AAD_length(2) || AAD || padding
/// Then: B_i = plaintext blocks (padded to AES block size)
///
/// Returns the 8-byte truncated tag.
fn ccm_cbc_mac(
    cipher: &Aes128,
    nonce: &[u8; CCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; CCM_TAG_LEN] {
    // B_0: Flags || Nonce || Q
    // Flags: bit 6 = Adata (1 if AAD present), bits 5-3 = (t-2)/2 = 3, bits 2-0 = q-1 = 6
    let has_aad: u8 = if aad.is_empty() { 0 } else { 1 << 6 };
    let flags = has_aad | (((CCM_TAG_LEN as u8 - 2) / 2) << 3) | 6;

    let mut b = [0u8; AES_BLOCK];
    b[0] = flags;
    b[1..1 + CCM_NONCE_LEN].copy_from_slice(nonce);

    // Q: message length in q=7 bytes (big-endian)
    let q_start = 1 + CCM_NONCE_LEN; // byte 9
    let msg_len = plaintext.len() as u64;
    for i in 0..7 {
        b[q_start + 6 - i] = ((msg_len >> (i * 8)) & 0xFF) as u8;
    }

    // CBC-MAC: T = E(K, B_0) XOR B_1, then E(K, T) XOR B_2, etc.
    let mut t = b;
    let t_block = aes::Block::from_mut_slice(&mut t);
    cipher.encrypt_block(t_block);

    // AAD processing
    if !aad.is_empty() {
        let mut aad_buf = [0u8; AES_BLOCK];
        // AAD length encoding (2 bytes for lengths < 0xFF00)
        let aad_len = aad.len() as u16;
        aad_buf[0] = (aad_len >> 8) as u8;
        aad_buf[1] = aad_len as u8;

        // Fill rest of first block with AAD data
        let first_chunk = aad.len().min(AES_BLOCK - 2);
        aad_buf[2..2 + first_chunk].copy_from_slice(&aad[..first_chunk]);

        // XOR and encrypt
        for i in 0..AES_BLOCK {
            t[i] ^= aad_buf[i];
        }
        let t_block = aes::Block::from_mut_slice(&mut t);
        cipher.encrypt_block(t_block);

        // Remaining AAD blocks
        let mut aad_offset = first_chunk;
        while aad_offset < aad.len() {
            let mut block = [0u8; AES_BLOCK];
            let chunk = (aad.len() - aad_offset).min(AES_BLOCK);
            block[..chunk].copy_from_slice(&aad[aad_offset..aad_offset + chunk]);

            for i in 0..AES_BLOCK {
                t[i] ^= block[i];
            }
            let t_block = aes::Block::from_mut_slice(&mut t);
            cipher.encrypt_block(t_block);
            aad_offset += chunk;
        }
    }

    // Plaintext processing
    let mut pt_offset = 0;
    while pt_offset < plaintext.len() {
        let mut block = [0u8; AES_BLOCK];
        let chunk = (plaintext.len() - pt_offset).min(AES_BLOCK);
        block[..chunk].copy_from_slice(&plaintext[pt_offset..pt_offset + chunk]);

        for i in 0..AES_BLOCK {
            t[i] ^= block[i];
        }
        let t_block = aes::Block::from_mut_slice(&mut t);
        cipher.encrypt_block(t_block);
        pt_offset += chunk;
    }

    // Truncate to CCM_TAG_LEN
    let mut tag = [0u8; CCM_TAG_LEN];
    tag.copy_from_slice(&t[..CCM_TAG_LEN]);
    tag
}

/// Set the counter value in an A_i block (last 7 bytes, big-endian).
fn set_counter(a: &mut [u8; AES_BLOCK], counter: u64) {
    let start = 1 + CCM_NONCE_LEN; // byte 9
    for i in 0..7 {
        a[start + 6 - i] = ((counter >> (i * 8)) & 0xFF) as u8;
    }
}

```


### `secure/src/hw/flash.rs`

```rust
//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last two pages of bank 1:
//! - Page 127 (0x0C0F_E000): Tropic01 pairing key / persistent secure data
//! - Page 126 (0x0C0F_C000): OPTIGA Trust M Platform Binding Secret (PBS)
//!
//! The linker script (`memory-stm32u585.x`) must shrink FLASH LENGTH
//! by 16 KB to prevent firmware code from being placed in these pages.

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Flash controller registers (secure alias)
// ---------------------------------------------------------------------------

const FLASH: u32 = 0x5002_2000;

const FLASH_SECKEYR: *mut u32 = (FLASH + 0x0C) as *mut u32;
const FLASH_SECSR: *mut u32 = (FLASH + 0x24) as *mut u32;
const FLASH_SECCR: *mut u32 = (FLASH + 0x2C) as *mut u32;

// Unlock key sequence (same as all STM32 families)
const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

// SECCR bit positions
const PG: u32 = 1 << 0; // Programming
const PER: u32 = 1 << 1; // Page Erase
const PNB_SHIFT: u32 = 3; // Page Number starts at bit 3
const STRT: u32 = 1 << 16; // Start
const LOCK: u32 = 1 << 31; // Lock

// SECSR bit positions
const BSY: u32 = 1 << 16; // Busy
const ERR_MASK: u32 = 0xFA; // PROGERR | WRPERR | PGAERR | SIZERR | PGSERR

// ---------------------------------------------------------------------------
// Key storage page — last 8 KB of secure flash bank 1 (page 127)
// ---------------------------------------------------------------------------

/// Base address of the reserved key storage page (page 127).
pub const KEY_PAGE_ADDR: u32 = 0x0C0F_E000;
const KEY_PAGE_NUM: u32 = 127;

// ---------------------------------------------------------------------------
// PBS storage page — second-to-last 8 KB (page 126)
// ---------------------------------------------------------------------------

/// Base address of the OPTIGA Trust M PBS page (page 126).
pub const PBS_PAGE_ADDR: u32 = 0x0C0F_C000;
const PBS_PAGE_NUM: u32 = 126;

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Wait until the flash controller is not busy.
unsafe fn wait_bsy() {
    while read_volatile(FLASH_SECSR) & BSY != 0 {
        cortex_m::asm::nop();
    }
}

/// Clear any pending error flags in SECSR (write-1-to-clear).
unsafe fn clear_errors() {
    let sr = read_volatile(FLASH_SECSR);
    if sr & ERR_MASK != 0 {
        write_volatile(FLASH_SECSR, sr & ERR_MASK);
    }
}

/// Unlock the secure flash controller for programming/erase.
unsafe fn unlock() {
    // If already unlocked, the key writes are ignored.
    write_volatile(FLASH_SECKEYR, KEY1);
    write_volatile(FLASH_SECKEYR, KEY2);
}

/// Lock the secure flash controller.
unsafe fn lock() {
    let cr = read_volatile(FLASH_SECCR);
    write_volatile(FLASH_SECCR, cr | LOCK);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Erase the key storage page (page 127, 8 KB).
///
/// After erase, all bytes in the page read as 0xFF.
pub unsafe fn erase_key_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    // Set PER + page number, then STRT
    let cr = PER | (KEY_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    // Clear PER
    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Program one quad-word (16 bytes / 128 bits) at the given flash address.
///
/// The address must be quad-word aligned (16-byte boundary) and must
/// point within the key storage page. The destination must be erased
/// (all 0xFF) before writing.
///
/// Returns `Err(())` only if the flash controller set one of the error
/// flags (PROGERR / WRPERR / PGAERR / SIZERR / PGSERR). **Does not
/// verify that the bytes actually landed correctly** — a torn write
/// under brown-out can produce a half-programmed quad-word with no
/// error flag set. For persistent data, use `write_quadword_verified`.
unsafe fn write_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    // Set PG bit
    write_volatile(FLASH_SECCR, PG);

    // Write 4 × 32-bit words to the target address.
    // The flash controller latches all four and programs them atomically.
    let dst = addr as *mut u32;
    for i in 0..4 {
        let word = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        write_volatile(dst.add(i), word);
    }

    wait_bsy();

    // Clear PG
    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Program one quad-word **and read it back to confirm the bytes landed**.
///
/// Detects class-A torn writes (brown-out mid-program leaving some bits
/// committed and others not): NOR flash can leave such a QW readable
/// without flagging PROGERR, so a pure `write_quadword` returns `Ok`
/// while the actual memory differs from `data`. The read-back compare
/// here catches that deterministically.
///
/// Use this for anything that matters (admin PIN, PBS, pairing key,
/// wipe flag). Internal helpers that don't care about durability can
/// keep using `write_quadword`.
pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    write_quadword(addr, data)?;

    let src = addr as *const u8;
    for i in 0..16 {
        if read_volatile(src.add(i)) != data[i] {
            return Err(());
        }
    }
    Ok(())
}

/// Read 32 bytes from the start of the key storage page.
pub unsafe fn read_key(buf: &mut [u8; 32]) {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the key storage page is blank (first 32 bytes = 0xFF).
pub unsafe fn is_key_blank() -> bool {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Write a 32-byte key to the key storage page.
///
/// Erases the page first, then programs two quad-words (2 × 16 bytes).
pub unsafe fn write_key(key: &[u8; 32]) -> Result<(), ()> {
    erase_key_page()?;

    // First quad-word: bytes 0-15
    let mut qw0 = [0u8; 16];
    qw0.copy_from_slice(&key[..16]);
    write_quadword_verified(KEY_PAGE_ADDR, &qw0)?;

    // Second quad-word: bytes 16-31
    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&key[16..]);
    write_quadword_verified(KEY_PAGE_ADDR + 16, &qw1)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// OPTIGA Trust M PBS storage (page 126)
// ---------------------------------------------------------------------------

/// Erase the PBS storage page (page 126, 8 KB).
pub unsafe fn erase_pbs_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    let cr = PER | (PBS_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Read 32 bytes from the start of the PBS storage page.
pub unsafe fn read_pbs(buf: &mut [u8; 32]) {
    let src = PBS_PAGE_ADDR as *const u8;
    for i in 0..32 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the PBS storage page is blank (first 32 bytes = 0xFF).
pub unsafe fn is_pbs_blank() -> bool {
    let src = PBS_PAGE_ADDR as *const u8;
    for i in 0..32 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Write a 32-byte PBS to the PBS storage page.
///
/// Erases the page first, then programs two quad-words (2 × 16 bytes).
pub unsafe fn write_pbs(pbs: &[u8; 32]) -> Result<(), ()> {
    erase_pbs_page()?;

    let mut qw0 = [0u8; 16];
    qw0.copy_from_slice(&pbs[..16]);
    write_quadword_verified(PBS_PAGE_ADDR, &qw0)?;

    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&pbs[16..]);
    write_quadword_verified(PBS_PAGE_ADDR + 16, &qw1)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// SE050 admin-wipe state — page 125
// ---------------------------------------------------------------------------
//
// Holds the per-device admin PIN (16 bytes from STM32 TRNG, used to
// authenticate against ADMIN_WIPE_OBJ on SE050 during PIN-lockout wipe)
// and a crash-safety flag for interrupted wipes. Independent of OPTIGA
// PBS so SE050-standalone builds work without additional dependencies.
//
// Layout of page 125 (0x0C0F_A000, 8 KB):
//   QW 0 (offset  0..15): admin PIN (16 bytes)
//   QW 1 (offset 16..31): wipe flag — byte 0: 0x00 armed / 0xFF blank
//                                     bytes 1..15: padding (0xFF)
//   bytes 32..8192:       unused, 0xFF after erase
//
// Lifecycle:
//   - First boot: page erased (all 0xFF) → generate random admin PIN
//                 via rng::fill(), write QW 0. Wipe flag stays blank.
//   - Wipe start: program QW 1 to [0x00, 0xFF × 15]. This is a 1→0
//                 bit-clear on a blank QW, which NOR flash allows
//                 without page erase — the admin PIN at QW 0 is preserved
//                 so the wipe routine can still authenticate.
//   - Wipe finish: erase_admin_page(). Clears PIN + flag both back to
//                  0xFF, leaving the SE050 side of the device
//                  "unprovisioned" from this page's perspective.

/// Base address of the SE050 admin-state page (page 125).
pub const ADMIN_PAGE_ADDR: u32 = 0x0C0F_A000;
const ADMIN_PAGE_NUM: u32 = 125;

const ADMIN_PIN_OFFSET: u32 = 0;
const WIPE_FLAG_OFFSET: u32 = 16;
const WIPE_FLAG_ARMED: u8 = 0x00;

/// Erase page 125. Clears both the admin PIN and the wipe flag.
pub unsafe fn erase_admin_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    let cr = PER | (ADMIN_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Read the admin PIN from page 125 into `buf`. Caller checks
/// `is_admin_pin_blank()` first to determine if the PIN is populated.
pub unsafe fn read_admin_pin(buf: &mut [u8; 16]) {
    let src = (ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET) as *const u8;
    for i in 0..16 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the admin PIN slot is blank (first 16 bytes all 0xFF).
pub unsafe fn is_admin_pin_blank() -> bool {
    let src = (ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET) as *const u8;
    for i in 0..16 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Persist a 16-byte admin PIN into page 125.
///
/// Erases the whole page first (so any stale wipe flag is cleared too),
/// then programs QW 0 with the PIN. After this call `is_admin_pin_blank()`
/// is false and `is_wipe_armed()` is false.
pub unsafe fn write_admin_pin(pin: &[u8; 16]) -> Result<(), ()> {
    erase_admin_page()?;

    let mut qw = [0u8; 16];
    qw.copy_from_slice(pin);
    write_quadword_verified(ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET, &qw)
}

/// Arm the wipe-in-progress marker. Call immediately before initiating
/// a factory reset so boot-time resume can pick up an interrupted wipe.
///
/// Does NOT erase page 125 — uses a 1→0 bit-clear on a single QW, which
/// NOR flash supports without pre-erase. The admin PIN at QW 0 is
/// preserved so the wipe routine can still authenticate against
/// ADMIN_WIPE_OBJ during resume.
pub unsafe fn arm_wipe_flag() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = WIPE_FLAG_ARMED;
    write_quadword_verified(ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET, &qw)
}

/// Read the wipe-in-progress flag. Returns true iff armed.
pub unsafe fn is_wipe_armed() -> bool {
    let src = (ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET) as *const u8;
    read_volatile(src) == WIPE_FLAG_ARMED
}

```


### From `docs/se050-factory-reset.md`

# SE050 Factory Reset — Design and Production Checklist

## Why this document exists

The PQSigner wallet uses a hardware-enforced PIN on the NXP SE050 secure
element (UserID at `0x7B06_0000`, max 10 attempts before permanent
lockout). After lockout, firmware must be able to wipe every stored
secret so the user can restore from their 24-word BIP-39 backup on the
same physical device. This file explains how that wipe is structured,
why the obvious alternatives don't work, and what needs to change when
moving from dev boards to production silicon.

## What we tried that did NOT work

### Approach 1 — bare `DeleteAll` APDU via `RESERVED_ID_FACTORY_RESET`

NXP's SE05x spec defines a single-APDU nuclear wipe:
`CLA=0x80 INS=0x04 P1=0x00 P2=0x2A`. It wipes everything in one shot but
requires an authenticated session against
`kSE05x_AppletResID_FACTORY_RESET = 0x7FFF_0205`. On the
OM-SE050ARD-E dev shield (SE050E2HQ1/Z01Z3), **customer writes to
`0x7FFF_0205` are rejected with `SW=0x6985`** ("conditions not
satisfied"). The slot is reserved for NXP personalisation at the chip
factory, and we get no access to it on dev parts.

Evidence: no example in `plug-and-trust` anywhere creates
`0x7FFF_0205`. The SetPlatformSCPRequest API at
`hostlib/hostLib/se05x_03_xx_xx/se05x_APDU_apis.h:385` mentions it only
as an auth requirement, never as a create target.

### Approach 2 — iterative delete under plain PlatformSCP03 channel auth

This is what `Se05x_API_DeleteAll_Iterative` does (see
`plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78`). For each
object returned by `ReadIDList`, it calls `DeleteSecureObject` over the
current SCP03 channel. It works only for objects whose policy either
permits deletion under the default channel OR has no restrictive per-object
auth gate.

**It fails on every object that has `auth_obj_id = <UserID>` in its
TAG_POLICY** — SE050 enforces the policy regardless of channel, and
channel-level SCP03 auth does NOT implicitly satisfy a policy entry with
`auth_obj_id = 0x7FFF_0207` (that reserved ID is only used for
SetPlatformSCPRequest, not as a universal "admin" marker). After the
user PIN gets locked out, the UserID can no longer authenticate anyone,
so `delete_object_authed` can't run either. Every UserID-gated object
becomes unreachable.

## The design we shipped

Every gated user object carries a **two-entry TAG_POLICY**:

| Entry | `auth_obj_id`          | `ar_header`                          | Purpose                         |
|-------|------------------------|--------------------------------------|---------------------------------|
| 1     | UserID `0x7B06_0000`   | READ \| WRITE \| DELETE \| REQUIRE_SM| Normal operation (PIN-gated)    |
| 2     | ADMIN `0x7B06_00A0`    | DELETE \| REQUIRE_SM                 | PIN-lockout wipe                |

`ADMIN_WIPE_OBJ = 0x7B06_00A0` is a secondary UserID provisioned at
first boot with a 16-byte PIN generated via the STM32 TRNG and
persisted to secure flash page 125 (`0x0C0F_A000`):

```
// In secure/src/hw/flash.rs page 125 layout:
//   QW 0 (offset  0..15): admin PIN (16 bytes from rng::fill())
//   QW 1 (offset 16..31): wipe flag (byte 0: 0x00 armed / 0xFF blank)
```

The admin PIN never leaves the TrustZone secure world. On first boot
`Se050::provision()` checks `is_admin_pin_blank()`; if true, generates
a fresh PIN via `rng::fill()` and writes it to QW 0. On subsequent
boots it reads the existing PIN. The full page is erased as the final
step of any factory reset, so PIN + flag are atomically cleared together.

This approach is deliberately independent of the OPTIGA Platform Binding
Secret — an earlier iteration derived the admin PIN from the PBS, which
broke SE050-standalone builds (no PBS) and couldn't work for users who
have the SE050 shield without an OPTIGA chip attached. The current
design works for every combination (SE050 alone, dual-SE, future
variants) because the admin state lives on the STM32 side, where
secure flash is guaranteed to exist.

### Admin-wipe policy construction (apdu.rs)

```
TAG_POLICY value (18 bytes for 2-entry):
  [0x08] [auth1:4 BE] [ar1:4 BE]   ← entry 1
  [0x08] [auth2:4 BE] [ar2:4 BE]   ← entry 2
```

Entries are OR'd: if ANY entry's `auth_obj_id` is satisfied by the
current session AND that entry's `ar_header` permits the requested
operation, the operation succeeds. The admin entry has **only
ALLOW_DELETE + REQUIRE_SM** — never ALLOW_READ. That preserves the
hardware-enforced PIN gating on entropy: the admin credential can wipe
the chip but cannot exfiltrate the seed.

### Wipe flow

```
PIN attempt #10 fails
  ↓
SE050 hardware locks UserID (SW=0x6983 on next CreateSession)
  ↓
firmware: read admin_pin from flash page 125 QW 0
          arm wipe flag at page 125 QW 1 (1→0 bit-clear)
  ↓
SE050 admin session:
  CreateSession(ADMIN_WIPE_OBJ)
  VerifySessionUserID(admin_pin)
  DeleteSecureObject_authed(ENTROPY_OBJ)
  DeleteSecureObject_authed(VK_OBJ)
  DeleteSecureObject_authed(BOOTSTRAP_VK_OBJ)
  DeleteSecureObject_authed(USERID_OBJ)       ← user UserID
  DeleteSecureObject_authed(ADMIN_WIPE_OBJ)   ← self-delete
  CloseSession
  ↓
best-effort unauthenticated sweep (iterative_delete_all) for legacy stragglers
  ↓
erase_admin_page()  ← clears admin PIN + wipe flag atomically
(dual-SE only) erase_pbs_page()  ← orphans OPTIGA from STM32
  ↓
zeroize all SRAM state
  ↓
return PinLocked → NS side reboots into first-boot wizard
```

### Crash safety

The wipe flag at `ADMIN_PAGE_ADDR + 16` is armed via a 1→0 bit-clear
(NOR flash allows this without pre-erase, so the admin PIN at QW 0 is
preserved and the wipe routine can still authenticate). If power is
cut mid-wipe, the flag remains set on reboot. The boot path in
`secure/src/main.rs` checks `is_wipe_armed()` before any unlock attempt
and calls `factory_reset_admin()` again (idempotent — duplicate deletes
are harmless, the SCP03 session is re-established from scratch). The
flag is only cleared by the final `erase_admin_page()` call, which runs
after SE050 wipe is verified clean.

### Round-trip self-test during first-boot

`policy_roundtrip_selftest` writes a canary UserID + gated data object
to `0x7B06_00B0/B1` with the same two-entry policy template, then
exercises the admin-delete path end-to-end. If the canary survives, the
TLV byte layout is broken (has happened before — see git history for
the garbled-policy orphans at `0x7B00_xxxx`). First-boot provisioning
aborts with a fatal panic rather than shipping a wallet that cannot
recover from PIN lockout.

This is the guardrail that prevents a future refactor from
re-introducing the unwipeable-orphan problem.

## Production checklist

### 1. PlatformSCP03 keys

Dev chips use NXP default SCP03 keys (`0x40 0x41 0x42 … 0x4F` — encoded
in our `se050/scp03.rs`). Production chips must have these rotated to
per-batch or per-device keys delivered by NXP's secure provisioning
service. The wipe path depends on SCP03 channel being establishable, so
the rotated keys must also be stored in TrustZone secure flash and
loaded before any SE050 operation.

**Action:** add a key-storage slot in secure flash (alongside PBS /
pairing key) and a boot-time load step before `scp03::establish()`.
Today the driver hard-codes the NXP defaults; that's fine for dev, not
for production.

### 2. Lifecycle of ADMIN_WIPE_OBJ PIN

Admin PIN is generated once at first-boot provisioning via STM32 TRNG
(`rng::fill()`) and persisted to secure flash page 125 QW 0. It is
read back from flash on every boot that needs it (factory reset, boot-time
wipe resume). Because it lives in TrustZone secure flash it is never
exposed to non-secure world, USB, or any external interface.

The PIN is erased atomically with the wipe flag when
`erase_admin_page()` runs at the end of a factory reset. After that
erase, any subsequent boot sees `is_admin_pin_blank() == true` and
treats the chip as unprovisioned (runs first-boot wizard, generates a
fresh admin PIN).

If you ever re-provision the firmware without wiping first (e.g. a
dev-mode reflash while keeping the existing SE050 contents), the
already-persisted admin PIN continues to work because it's read from
flash, not regenerated. Only `erase_admin_page()` rotates the PIN.

### 2a. Future optimisation — HUK-SAES derivation

Storing the admin PIN in flash is functional but dependent on flash
integrity. An attacker who can read page 125 off a powered-off chip
(invasive attack) learns the admin PIN and can wipe the device.
A stronger design derives the admin PIN at boot from the STM32U585
Hardware Unique Key via the SAES peripheral — the HUK never leaves the
silicon and is unique per chip. The admin PIN then has no on-flash
representation at all.

This is flagged as a future improvement because HUK-SAES wrapping is
not yet wired up for other secrets either (e.g. SCP03 platform keys —
see docs/work-todo.md item #7). When that infrastructure lands, fold
admin-PIN derivation into the same code path with domain tag
`"pqwallet-se050-admin-pin-huk-v1"` (new tag, not v1 — the v1 tag stays
frozen so already-provisioned flash-persisted devices keep working
during the migration).

### 3. Attestation-based device pairing (not yet implemented)

Today we trust any SE050 that presents a valid SCP03 handshake. A
production build should also verify the SE050 certificate chain against
a pinned NXP root CA + a pinned per-device UID, to defend against
chip-swap attacks. This is orthogonal to factory reset but sits in the
same boot-time init path — bundle them.

### 4. UI for lockout warnings

`secure/src/nsc/cmd_request_unlock.rs` now shows "LAST ATTEMPT — wallet
wipes on fail" on the 9th consecutive wrong PIN. For production, also
show an educational screen during the wipe itself ("Wiping — do not
power off") and a post-wipe screen telling the user their wallet can be
restored from the 24-word backup (wallet address, bootstrap pubkey hash,
and on-chain state are all unchanged after restore).

### 5. Dev chips vs production chips

Do NOT reuse dev chips across firmware generations without a fresh
provision. Our earlier dev chip accumulated 6 unwipeable orphans at
`0x7B00_xxxx` / `0x7B06_0000` because older firmware created objects
without the admin-delete policy entry. Those objects remain stuck
forever on that specific chip — only a fresh OM-SE050ARD-E (or a real
production part) is clean.

For ongoing dev work on such a polluted chip, migrate the production
OID range (`0x7B06_xxxx` → `0x7B08_xxxx` or similar) to avoid slot
collisions. This is a separate one-time change; the admin-wipe design
itself does not depend on the OID range.

## What NOT to do

- **Do NOT remove the admin-delete policy entry.** Every object the
  firmware creates on SE050 must have two TAG_POLICY entries. Objects
  without entry 2 cannot be recovered from PIN lockout and are
  orphans-by-design.
- **Do NOT regenerate the admin PIN without erasing page 125 first.**
  The PIN is TRNG-generated and persisted; overwriting only the PIN
  slot would leave the old wipe flag (if armed) in a stale state. Use
  `erase_admin_page()` to rotate.
- **Do NOT skip the round-trip selftest.** It's the cheap insurance
  against re-introducing garbled-policy orphans on future builds.
- **Do NOT reuse the ADMIN_WIPE_OBJ PIN for user-facing operations.**
  The admin credential exists only to satisfy admin-delete policies;
  its ar_header grants only DELETE, never READ.
- **Do NOT try to provision `0x7FFF_0205` on dev chips.** Wastes time,
  always returns `SW=0x6985`. The FACTORY_RESET credential is
  NXP-controlled.
- **Do NOT run the wipe path without arming the flag first.** A power
  loss mid-wipe leaves the chip in a half-wiped state with no recovery
  signal. The flag is cheap and idempotent; always arm it first.
- **Do NOT bypass the admin-credential install during first-boot.**
  `Se050::provision()` runs `provision_admin` + `policy_roundtrip_selftest`
  automatically on any `stm32u585` target with SE050 — don't "optimise"
  it out. Skipping it ships a wallet that cannot recover from PIN lockout.

## File map

| Concern                       | File                                                       |
|-------------------------------|------------------------------------------------------------|
| TAG_POLICY byte layout        | `secure/src/se050/apdu.rs` (`build_policy`)                |
| UserID + data-obj creation    | `secure/src/se050/apdu.rs` (`write_userid`, `write_binary_gated`) |
| Admin credential provisioning | `secure/src/se050/mod.rs` (`provision_admin`, `store_objects`) — runs automatically inside `WalletStore::provision` on stm32u585 |
| Admin-delete wipe             | `secure/src/se050/mod.rs` (`admin_factory_reset`)          |
| Round-trip selftest           | `secure/src/se050/mod.rs` (`policy_roundtrip_selftest`)    |
| Admin PIN + wipe-flag storage | `secure/src/hw/flash.rs` page 125 (`read_admin_pin`, `write_admin_pin`, `erase_admin_page`, `arm_wipe_flag`, `is_wipe_armed`) |
| SE050 wipe entry point        | `secure/src/se050/mod.rs` `WalletStore::factory_reset_admin` |
| Dual-SE wipe orchestration    | `secure/src/dual_se.rs` `WalletStore::factory_reset_admin` (delegates to SE050, then erases PBS) |
| PIN-lockout trigger           | `secure/src/nsc/cmd_request_unlock.rs` (`trigger_lockout_wipe`) |
| Boot-time resume              | `secure/src/main.rs` (block after `load_pbs`)              |
| Flash layout (linker)         | `secure/memory-stm32u585.x` (`FLASH LENGTH = 1000K`, reserves pages 125-127) |

## References

- NXP UM11225 — SE050 User Manual (TAG_POLICY structure, ar_header bits)
- NXP `plug-and-trust/sss/ex/src/ex_sss_boot.c:94-114` — official factory reset is `DeleteAll_Iterative`, not bare `DeleteAll`
- NXP `plug-and-trust/hostlib/hostLib/se05x/src/se05x_mw.c:22-78` — iterative delete implementation, skips reserved ranges only
- NXP `plug-and-trust/hostlib/hostLib/inc/se05x_const.h:141-176` — `POLICY_OBJ_ALLOW_*` bit values
- PQSigner CLAUDE.md — invariants #1 (dual-chip split), #2 (hardware PIN gating), #3 (E2E encrypted tunnel), #4 (secrets in TrustZone only)

