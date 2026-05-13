//! SCP03 (Secure Channel Protocol 03) for SE050.
//!
//! Establishes an authenticated, encrypted channel with the SE050 using
//! GlobalPlatform SCP03.  After session establishment every APDU is
//! MAC'd (C-MAC) and its data encrypted (C-DEC).
//!
//! HW lesson #6: SE050E requires P1=0x03 (C-MAC + C-DEC) in EXTERNAL
//! AUTHENTICATE.  This module always uses that security level.

// Pure-logic primitives live in `crate::scp03_logic` so the NIST
// AES-128 / CMAC vectors + the GP `PUT KEY` layout tests run under
// `cargo test -p sphincs-tz-secure` (this module is `feature = "se050"`
// + `not(test)`-gated in `main.rs`, so its own `#[cfg(test)]` blocks
// would never compile). Re-export the surface so existing call sites
// (and `Se050::rotate_scp03_keys`) keep working unchanged.
pub use crate::scp03_logic::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_ecb_encrypt, build_put_key_apdu, cmac_aes128,
    keys_are_factory_default, scp03_kcv, KEY_VERSION, PLATFORM_DEK, PLATFORM_ENC, PLATFORM_MAC,
    PUT_KEY_APDU_LEN, PUT_KEY_INS,
};
use crate::scp03_logic::{
    build_derivation_data, kdf, DD_CARD_CRYPTOGRAM, DD_HOST_CRYPTOGRAM, DD_S_ENC, DD_S_MAC,
    DD_S_RMAC,
};

use super::apdu::Se050Error;

// Constants `PLATFORM_ENC/MAC/DEK`, `KEY_VERSION`, the SCP03 KDF
// derivation-data constants, and the pure crypto helpers all live in
// `crate::scp03_logic` now (see the `use` block at the top of this
// file) — kept un-gated so the host test build can run the NIST KATs
// + the GP `PUT KEY` layout assertions.

/// Resolve the SCP03 static keys this build should *prefer* — `(S-ENC,
/// S-MAC, DEK)`.
///
/// - Without `se050-derived-scp03` (the default): the published factory
///   constants from `scp03_logic::PLATFORM_*`.
/// - With `se050-derived-scp03`: the per-device keys from
///   `hw::secret_keys::se050_scp03_{enc,mac,dek}_key()` (BHK-rooted in a
///   `bhk`-on build; DHUK / OTP per build otherwise). A device whose chip
///   has been `PUT KEY`-rotated holds exactly these; one that hasn't still
///   holds the factory keys — `establish()` probes the preferred set first
///   and falls back to `PLATFORM_*` on a card-cryptogram mismatch, so one
///   firmware copes with both. `KEY_VERSION` stays `0x0B` either way (the
///   rotation replaces keyset `0x0B` in place, it does not add a new KVN).
///
/// Lives here (not in `scp03_logic`) because the derived-key path imports
/// `hw::secret_keys`, and the `hw` module is `not(test)`-gated — keeping
/// this stub in the gated `se050` module keeps `scp03_logic` host-clean.
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

// AES-128 ECB/CBC + CMAC primitives and the SP 800-108 derivation-data
// builder + `kdf` block-emitter all live in `crate::scp03_logic` now
// (imported at the top of this file).

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

// `PUT_KEY_APDU_LEN`, `PUT_KEY_INS`, and `build_put_key_apdu` live in
// `crate::scp03_logic` now (re-exported via `pub use` at the top of this
// file). Tests for the APDU layout + KCV + AES/CMAC primitives also live
// there — and unlike the `#[cfg(test)]` block that used to be here, they
// actually run under `cargo test -p sphincs-tz-secure` because
// `scp03_logic` is un-gated.
