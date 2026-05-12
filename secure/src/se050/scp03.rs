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

// Factory (NXP-provisioned) SCP03 platform keys for SE050E, OEF `0x0001A921`,
// per AN12436 Rev 2.4 (mirrors `plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h:217-224`).
// These are *published* — an SCP03 channel that still uses them is
// plaintext-equivalent to a bus sniffer with the datasheet. They are the
// *initial* state of a fresh chip; `work-todo #20` rotates them to per-device
// BHK-derived keys via GP `PUT KEY` (replacing keyset `0x0B` in place) at
// production-provisioning time. Until that ceremony has run on a given chip,
// these are the keys it holds — `establish()` falls back to them.
const PLATFORM_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7,
    0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
const PLATFORM_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0,
    0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];
/// Factory Data Encryption Key (DEK) for the same OEF. Used only to *wrap*
/// new key values during a `PUT KEY` ceremony (it never participates in
/// session establishment), so it sits unused until `rotate_platform_keys`
/// runs. Source: `plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h:223`.
#[cfg_attr(not(feature = "se050-rotate-scp03"), allow(dead_code))]
const PLATFORM_DEK: [u8; 16] = [
    0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8,
    0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F,
];

const KEY_VERSION: u8 = 0x0B;

/// Resolve the SCP03 static keys this build should *prefer* — `(S-ENC,
/// S-MAC, DEK)`.
///
/// - Without `se050-derived-scp03` (the default): the published factory
///   constants above.
/// - With `se050-derived-scp03`: the per-device keys from
///   `hw::secret_keys::se050_scp03_{enc,mac,dek}_key()` (BHK-rooted in a
///   `bhk`-on build; DHUK / OTP per build otherwise). A device whose chip
///   has been `PUT KEY`-rotated holds exactly these; one that hasn't still
///   holds the factory keys — `establish()` probes the preferred set first
///   and falls back to `PLATFORM_*` on a card-cryptogram mismatch, so one
///   firmware copes with both. `KEY_VERSION` stays `0x0B` either way (the
///   rotation replaces keyset `0x0B` in place, it does not add a new KVN).
pub fn load_platform_keys() -> Result<([u8; 16], [u8; 16], [u8; 16]), Se050Error> {
    #[cfg(not(feature = "se050-derived-scp03"))]
    {
        Ok((PLATFORM_ENC, PLATFORM_MAC, PLATFORM_DEK))
    }
    #[cfg(feature = "se050-derived-scp03")]
    {
        use crate::hw::secret_keys;
        let enc = secret_keys::se050_scp03_enc_key().map_err(|_| Se050Error::Scp03)?;
        let mac = secret_keys::se050_scp03_mac_key().map_err(|_| Se050Error::Scp03)?;
        let dek = secret_keys::se050_scp03_dek_key().map_err(|_| Se050Error::Scp03)?;
        Ok((enc, mac, dek))
    }
}

/// True iff `(enc, mac, dek)` are exactly the published factory constants.
/// Used by `Se050::rotate_scp03_keys` to refuse `PUT KEY`-ing the
/// published keys over themselves (which would mean the derived-key path
/// isn't actually selecting a per-device root).
#[cfg_attr(not(feature = "se050-rotate-scp03"), allow(dead_code))]
pub fn keys_are_factory_default(enc: &[u8; 16], mac: &[u8; 16], dek: &[u8; 16]) -> bool {
    *enc == PLATFORM_ENC && *mac == PLATFORM_MAC && *dek == PLATFORM_DEK
}

/// GlobalPlatform / SCP03 Key Check Value for an AES key: the first 3
/// bytes of `AES-ECB-Encrypt(key, {0x01}×16)`.
///
/// NOTE — confirm before the `PUT KEY` ceremony runs: GP Amendment D
/// (SCP03) specifies the `0x01`-filled block; some older GP profiles
/// (SCP02) used `0x00`. SE050 follows the SCP03 convention per AN12436
/// §5.2, but this should be cross-checked against a live chip's accepted
/// `PUT KEY` (the chip recomputes the KCV and rejects on mismatch).
#[cfg_attr(not(any(test, feature = "se050-rotate-scp03")), allow(dead_code))]
pub fn scp03_kcv(key: &[u8; 16]) -> [u8; 3] {
    let ct = aes128_ecb_encrypt(key, &[0x01u8; 16]);
    [ct[0], ct[1], ct[2]]
}

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
/// Probe-on-boot: tries the keys this build *prefers* (the derived
/// per-device keys when `se050-derived-scp03` is on; the published
/// factory constants otherwise — see `load_platform_keys`). If that
/// fails the card-cryptogram check (the signal that the chip holds a
/// different key set), it retries once with the factory constants — so
/// a `se050-derived-scp03` build also works against a chip that has not
/// yet been `PUT KEY`-rotated. `KEY_VERSION` is `0x0B` either way.
pub unsafe fn establish(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
) -> Result<(), Se050Error> {
    let (enc, mac, _dek) = load_platform_keys()?;

    match establish_with_keys(session, t1, &enc, &mac) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Only the derived-keys build has a meaningful fallback (the
            // default build's preferred set already *is* the factory
            // constants). Retry on a key-related failure — card-cryptogram
            // mismatch (`Scp03`) or a status word like `0x6A88`; don't
            // retry a pure transport glitch.
            #[cfg(feature = "se050-derived-scp03")]
            if matches!(e, Se050Error::Scp03 | Se050Error::Status(_)) {
                #[cfg(feature = "debug-log")]
                secure_log!("[SCP03] derived-key establish failed ({:?}); falling back to factory keys", e);
                return establish_with_keys(session, t1, &PLATFORM_ENC, &PLATFORM_MAC);
            }
            Err(e)
        }
    }
}

/// One INITIALIZE-UPDATE + EXTERNAL-AUTHENTICATE handshake using the
/// given static `(S-ENC, S-MAC)` keys. Returns `Se050Error::Scp03` on a
/// card-cryptogram mismatch (the "wrong keys" signal the caller uses to
/// decide whether to retry with a different set).
unsafe fn establish_with_keys(
    session: &mut Scp03Session,
    t1: &mut super::t1oi2c::T1State,
    static_enc: &[u8; 16],
    static_mac: &[u8; 16],
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

    session.s_enc = kdf(static_enc, &dd_enc);
    session.s_mac = kdf(static_mac, &dd_mac);
    session.s_rmac = kdf(static_mac, &dd_rmac);

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

// ---------------------------------------------------------------------------
// GP PUT KEY — rotate the SCP03 platform key set (work-todo #20, Stage B)
// ---------------------------------------------------------------------------

/// Total bytes of a PUT-KEY APDU that installs three AES-128 keys, before
/// the SCP03 wrap adds its own header growth + 8-byte C-MAC:
/// 5 (CLA INS P1 P2 Lc) + 1 (new KVN) + 3 × (1+1+16+1+3) = 5 + 1 + 66 = 72.
pub const PUT_KEY_APDU_LEN: usize = 72;
const PUT_KEY_INS: u8 = 0xD8;

/// Build the (un-wrapped) GP `PUT KEY` APDU that **replaces SCP03 keyset
/// `0x0B` in place** with the three given AES-128 keys (S-ENC, S-MAC,
/// DEK, in that order). The new key values are encrypted under the chip's
/// *current* DEK — which, since the only time this ceremony runs is on a
/// factory-fresh chip (`work-todo #20` Stage B: production-provisioning,
/// once per chip), is the published factory `PLATFORM_DEK`.
///
/// The caller MUST transmit the result inside an *established* SCP03
/// session (`apdu::send_apdu` will C-MAC + C-DEC it) — `PUT KEY` is only
/// accepted authenticated.
///
/// Layout (GP 2.3.1 §11.8.2.3.1 "Format 1", SCP03 per GP Amendment D §7.1):
/// ```text
///   CLA = 0x80                   (the SCP03 wrap then ORs in 0x04 → 0x84)
///   INS = 0xD8
///   P1  = 0x0B                   KVN of the keyset to replace — in place
///   P2  = 0x81                   bit8 = "multiple keys follow", id of 1st key = 1
///   Lc  = 0x43                   = 67 = 1 + 3 × 22
///   Data:
///     [0x0B]                     new KVN (same value — replace in place)
///     per key (× 3, S-ENC / S-MAC / DEK):
///       [0x88]                   key type: AES
///       [0x10]                   length of the encrypted key data (16, one ECB block)
///       [enc_key   ; 16 bytes]   AES-ECB-Enc(current_DEK, new_key)
///       [0x03]                   KCV length
///       [kcv       ;  3 bytes]   scp03_kcv(new_key)
/// ```
///
/// **CONFIRM BEFORE THE CEREMONY RUNS** — these are best-effort from the
/// GP spec / AN12436; the chip recomputes the KCV and every field and
/// rejects on any mismatch, so the real validation is a sacrificial-part
/// rehearsal (see `docs/production-todo.md` §"SE050 — SCP03 + ADMIN
/// provisioning"): the `P2` first-key-id / multiple-keys encoding; whether
/// the encrypted-key-data length byte is `0x10` (key only — what we emit)
/// or includes a 1-byte inner length prefix; the KCV filler block; the
/// DEK-encryption mode (we use AES-ECB, no IV/pad, for the 16-byte key).
#[cfg_attr(not(any(test, feature = "se050-rotate-scp03")), allow(dead_code))]
pub fn build_put_key_apdu(
    new_enc: &[u8; 16],
    new_mac: &[u8; 16],
    new_dek: &[u8; 16],
) -> ([u8; PUT_KEY_APDU_LEN], usize) {
    const DATA_LEN: usize = 1 + 3 * 22; // 67
    let mut a = [0u8; PUT_KEY_APDU_LEN];
    a[0] = 0x80; // CLA — wrap_apdu adds the secure-messaging bit
    a[1] = PUT_KEY_INS; // INS = PUT KEY
    a[2] = KEY_VERSION; // P1 = KVN to replace (0x0B) — in place
    a[3] = 0x81; // P2 = multiple keys (0x80) | first key id (0x01)
    a[4] = DATA_LEN as u8; // Lc = 67
    a[5] = KEY_VERSION; // new KVN (same value)
    let mut o = 6usize;
    for k in [new_enc, new_mac, new_dek] {
        a[o] = 0x88; // key type: AES
        a[o + 1] = 0x10; // encrypted key data length = 16
        let wrapped = aes128_ecb_encrypt(&PLATFORM_DEK, k);
        a[o + 2..o + 18].copy_from_slice(&wrapped);
        a[o + 18] = 0x03; // KCV length
        let kcv = scp03_kcv(k);
        a[o + 19..o + 22].copy_from_slice(&kcv);
        o += 22;
    }
    debug_assert_eq!(o, PUT_KEY_APDU_LEN);
    (a, PUT_KEY_APDU_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scp03_kcv_is_deterministic_3_bytes() {
        let k = [0x11u8; 16];
        let a = scp03_kcv(&k);
        let b = scp03_kcv(&k);
        assert_eq!(a, b);
        // sanity: it's the first 3 bytes of AES-ECB-Enc(k, {0x01}×16)
        let full = aes128_ecb_encrypt(&k, &[0x01u8; 16]);
        assert_eq!(a, [full[0], full[1], full[2]]);
    }

    #[test]
    fn load_platform_keys_default_is_factory_triple() {
        // Without `se050-derived-scp03` this returns the published constants.
        let (enc, mac, dek) = load_platform_keys().expect("no error on the const path");
        assert_eq!(enc, PLATFORM_ENC);
        assert_eq!(mac, PLATFORM_MAC);
        assert_eq!(dek, PLATFORM_DEK);
    }

    #[test]
    fn put_key_apdu_layout() {
        let new_enc = [0xA0u8; 16];
        let new_mac = [0xB1u8; 16];
        let new_dek = [0xC2u8; 16];
        let (a, n) = build_put_key_apdu(&new_enc, &new_mac, &new_dek);
        assert_eq!(n, PUT_KEY_APDU_LEN);
        assert_eq!(n, 72);
        // header
        assert_eq!(&a[..5], &[0x80, 0xD8, 0x0B, 0x81, 67]);
        // new KVN
        assert_eq!(a[5], 0x0B);
        // each of the 3 key blocks
        for (i, k) in [&new_enc, &new_mac, &new_dek].iter().enumerate() {
            let base = 6 + i * 22;
            assert_eq!(a[base], 0x88, "key type AES");
            assert_eq!(a[base + 1], 0x10, "enc-key len");
            assert_eq!(&a[base + 2..base + 18], &aes128_ecb_encrypt(&PLATFORM_DEK, k)[..]);
            assert_eq!(a[base + 18], 0x03, "kcv len");
            assert_eq!(&a[base + 19..base + 22], &scp03_kcv(k)[..]);
        }
    }
}
