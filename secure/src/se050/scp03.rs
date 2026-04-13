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
