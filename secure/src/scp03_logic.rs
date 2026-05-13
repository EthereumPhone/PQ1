//! Pure-logic primitives for SE050 SCP03 — the AES / CMAC primitives, the
//! NIST SP 800-108 counter-mode KDF inputs, the SCP03 KCV, the GP `PUT
//! KEY` APDU builder, and the OEF-`0xA921` factory key constants. Nothing
//! in this module depends on `t1oi2c`, `crate::rng`, `secure_log!`, or any
//! other firmware-only facility, so it compiles for the host target and
//! `#[cfg(test)] mod tests` runs under `cargo test -p sphincs-tz-secure`.
//!
//! The session state machine (`Scp03Session`, `establish`, `wrap_apdu`,
//! `load_platform_keys`) stays in `se050::scp03` because it depends on
//! the I2C transport + `secret_keys` derivation — see that module.
//!
//! ## Why this module exists
//!
//! `main.rs` gates `mod se050;` (and `mod hw;`) on `not(test)` — the
//! SE050 driver pulls in I2C / RNG / secure-log dependencies that aren't
//! reachable in a host test build. So `#[cfg(test)] mod tests` inside
//! `se050::scp03` is never compiled and never runs. Moving the pure
//! primitives here (un-gated) lets the NIST AES-128-ECB / -CMAC KATs +
//! the GP `PUT KEY` layout assertion fire on every `cargo test`.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use cmac::Cmac;
use cmac::Mac as CmacMac;

// ---------------------------------------------------------------------------
// SE050E factory platform keys, OEF `0x0001A921`
// ---------------------------------------------------------------------------
//
// Per AN12436 Rev 2.4 (mirrored in
// `plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h:217-224`). These are
// *published* — an SCP03 channel that still uses them is plaintext-
// equivalent to a bus sniffer with the datasheet. They are the *initial*
// state of a fresh chip; `work-todo #20` rotates them to per-device
// BHK-derived keys via GP `PUT KEY` (replacing keyset `0x0B` in place) at
// production-provisioning time.

pub const PLATFORM_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7,
    0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
pub const PLATFORM_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0,
    0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];
pub const PLATFORM_DEK: [u8; 16] = [
    0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8,
    0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F,
];

/// SCP03 key-version-number for the SE050's platform keyset. `PUT KEY`
/// replaces this set *in place* — the data-field KVN stays `0x0B`.
pub const KEY_VERSION: u8 = 0x0B;

/// GP / SCP03 derivation-data constants (NIST SP 800-108 counter-mode
/// KDF byte 11 — see GP 2.3 §B.4 + Amendment D §6.2).
pub(crate) const DD_CARD_CRYPTOGRAM: u8 = 0x00;
pub(crate) const DD_HOST_CRYPTOGRAM: u8 = 0x01;
pub(crate) const DD_S_ENC: u8 = 0x04;
pub(crate) const DD_S_MAC: u8 = 0x06;
pub(crate) const DD_S_RMAC: u8 = 0x07;

// ---------------------------------------------------------------------------
// AES primitives
// ---------------------------------------------------------------------------

/// AES-128 ECB encrypt a single 16-byte block.
pub fn aes128_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut out);
    let mut result = [0u8; 16];
    result.copy_from_slice(&out);
    result
}

/// AES-128-CBC encrypt in-place. Caller is responsible for padding —
/// matches what `wrap_apdu` needs (ISO 7816-4 `0x80` padding applied by
/// the caller).
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
    use aes::cipher::BlockDecrypt;
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

/// CMAC-AES-128 over the concatenation of all input slices.
pub fn cmac_aes128(key: &[u8; 16], inputs: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as CmacMac>::new_from_slice(key).unwrap();
    for input in inputs {
        CmacMac::update(&mut mac, input);
    }
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

// ---------------------------------------------------------------------------
// SCP03 KDF (NIST SP 800-108 counter-mode CMAC)
// ---------------------------------------------------------------------------

/// Build the 32-byte derivation-data block for one SCP03 KDF call. See
/// GP Amendment D §6.2.2 + the inline calls in `establish_with_keys`.
pub(crate) fn build_derivation_data(
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

/// One block of CMAC-keyed SP 800-108 counter-mode KDF output (the SCP03
/// session keys + the card/host cryptograms are each one block here).
pub(crate) fn kdf(static_key: &[u8; 16], dd: &[u8; 32]) -> [u8; 16] {
    cmac_aes128(static_key, &[dd])
}

// ---------------------------------------------------------------------------
// SCP03 KCV (GP Amendment D §7.1)
// ---------------------------------------------------------------------------

/// GlobalPlatform / SCP03 Key Check Value for an AES key: the first 3
/// bytes of `AES-ECB-Encrypt(key, {0x01}×16)`.
///
/// NOTE — pin before the `PUT KEY` ceremony runs: GP Amendment D (SCP03)
/// specifies the `0x01`-filled block; some older GP profiles (SCP02)
/// used `0x00`. SE050 follows the SCP03 convention per AN12436 §5.2,
/// but the chip recomputes the KCV and rejects on mismatch, so a
/// sacrificial-part rehearsal is the real validation (see
/// `docs/production-todo.md`).
pub fn scp03_kcv(key: &[u8; 16]) -> [u8; 3] {
    let ct = aes128_ecb_encrypt(key, &[0x01u8; 16]);
    [ct[0], ct[1], ct[2]]
}

// ---------------------------------------------------------------------------
// GP PUT KEY — replace SCP03 keyset 0x0B in place
// ---------------------------------------------------------------------------

/// Total bytes of a `PUT KEY` APDU that installs three AES-128 keys,
/// before the SCP03 wrap adds its own header growth + 8-byte C-MAC:
/// 5 (CLA INS P1 P2 Lc) + 1 (new KVN) + 3 × (1+1+16+1+3) = 5 + 1 + 66 = 72.
pub const PUT_KEY_APDU_LEN: usize = 72;
pub const PUT_KEY_INS: u8 = 0xD8;

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

/// True iff `(enc, mac, dek)` are exactly the published factory
/// constants. Used by `Se050::rotate_scp03_keys` to refuse `PUT KEY`-ing
/// the published keys over themselves (which would mean the derived-key
/// path isn't actually selecting a per-device root).
pub fn keys_are_factory_default(enc: &[u8; 16], mac: &[u8; 16], dek: &[u8; 16]) -> bool {
    *enc == PLATFORM_ENC && *mac == PLATFORM_MAC && *dek == PLATFORM_DEK
}

// ---------------------------------------------------------------------------
// Tests — these now actually run under `cargo test -p sphincs-tz-secure`
// because `scp03_logic` (unlike `se050::scp03`) is not `not(test)`-gated.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----- AES-128-ECB KAT — FIPS 197 §C.1 ("AES-128 Cipher Example") -----
    #[test]
    fn aes128_ecb_fips197_c1() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let expected: [u8; 16] = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
        ];
        assert_eq!(aes128_ecb_encrypt(&key, &plaintext), expected);
    }

    // ----- CMAC-AES-128 KATs — NIST SP 800-38B Appendix D.1 -----
    // Key (all 4 vectors): 2b7e1516 28aed2a6 abf71588 09cf4f3c
    const NIST_D1_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    #[test]
    fn cmac_aes128_nist_sp800_38b_d1_empty() {
        let mac = cmac_aes128(&NIST_D1_KEY, &[&[]]);
        let expected: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn cmac_aes128_nist_sp800_38b_d1_16() {
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let mac = cmac_aes128(&NIST_D1_KEY, &[&msg]);
        let expected: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn cmac_aes128_nist_sp800_38b_d1_40() {
        let msg: [u8; 40] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let mac = cmac_aes128(&NIST_D1_KEY, &[&msg]);
        let expected: [u8; 16] = [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
            0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn cmac_aes128_concatenation_matches_single_call() {
        // Sanity: `cmac_aes128(k, [a, b])` must equal
        // `cmac_aes128(k, [a||b])` — confirms we feed inputs in order
        // and don't reset state between them.
        let a = [0x11u8; 7];
        let b = [0x22u8; 11];
        let mut concat = [0u8; 18];
        concat[..7].copy_from_slice(&a);
        concat[7..].copy_from_slice(&b);
        assert_eq!(
            cmac_aes128(&NIST_D1_KEY, &[&a, &b]),
            cmac_aes128(&NIST_D1_KEY, &[&concat]),
        );
    }

    // ----- SCP03 KCV -----
    #[test]
    fn scp03_kcv_deterministic_3_bytes() {
        let k = [0x11u8; 16];
        let a = scp03_kcv(&k);
        let b = scp03_kcv(&k);
        assert_eq!(a, b);
        // KCV = first 3 bytes of AES-ECB-Enc(k, {0x01}×16).
        let full = aes128_ecb_encrypt(&k, &[0x01u8; 16]);
        assert_eq!(a, [full[0], full[1], full[2]]);
    }

    #[test]
    fn scp03_kcv_is_3_bytes_of_known_ct_for_zero_key() {
        // AES-128-ECB({0}×16, {0x01}×16) — precomputable; pin the first
        // 3 bytes as a regression on the KCV filler convention. If this
        // ever fails, the filler was changed (0x01 → 0x00 etc.) and the
        // SE050 will reject `PUT KEY` with a KCV mismatch.
        let kcv = scp03_kcv(&[0u8; 16]);
        let full = aes128_ecb_encrypt(&[0u8; 16], &[0x01u8; 16]);
        assert_eq!(kcv, [full[0], full[1], full[2]]);
    }

    // ----- keys_are_factory_default -----
    #[test]
    fn keys_are_factory_default_true_for_published_consts() {
        assert!(keys_are_factory_default(
            &PLATFORM_ENC, &PLATFORM_MAC, &PLATFORM_DEK
        ));
    }

    #[test]
    fn keys_are_factory_default_false_for_any_byte_change() {
        let mut enc = PLATFORM_ENC;
        enc[0] ^= 1;
        assert!(!keys_are_factory_default(&enc, &PLATFORM_MAC, &PLATFORM_DEK));

        let mut mac = PLATFORM_MAC;
        mac[15] ^= 1;
        assert!(!keys_are_factory_default(&PLATFORM_ENC, &mac, &PLATFORM_DEK));

        let mut dek = PLATFORM_DEK;
        dek[8] ^= 1;
        assert!(!keys_are_factory_default(&PLATFORM_ENC, &PLATFORM_MAC, &dek));
    }

    // ----- build_put_key_apdu — layout -----
    #[test]
    fn put_key_apdu_layout_header_and_lc() {
        let new_enc = [0xA0u8; 16];
        let new_mac = [0xB1u8; 16];
        let new_dek = [0xC2u8; 16];
        let (a, n) = build_put_key_apdu(&new_enc, &new_mac, &new_dek);
        assert_eq!(n, PUT_KEY_APDU_LEN);
        assert_eq!(n, 72);
        // Header: CLA INS P1 P2 Lc
        assert_eq!(&a[..5], &[0x80, 0xD8, 0x0B, 0x81, 67]);
        // Data byte 0: new KVN, in-place replacement
        assert_eq!(a[5], 0x0B);
    }

    #[test]
    fn put_key_apdu_layout_key_blocks() {
        let new_enc = [0xA0u8; 16];
        let new_mac = [0xB1u8; 16];
        let new_dek = [0xC2u8; 16];
        let (a, _) = build_put_key_apdu(&new_enc, &new_mac, &new_dek);
        for (i, k) in [&new_enc, &new_mac, &new_dek].iter().enumerate() {
            let base = 6 + i * 22;
            assert_eq!(a[base], 0x88, "key #{i}: type=AES");
            assert_eq!(a[base + 1], 0x10, "key #{i}: enc-key len = 16");
            assert_eq!(
                &a[base + 2..base + 18],
                &aes128_ecb_encrypt(&PLATFORM_DEK, k)[..],
                "key #{i}: wrapped key bytes",
            );
            assert_eq!(a[base + 18], 0x03, "key #{i}: KCV len = 3");
            assert_eq!(
                &a[base + 19..base + 22],
                &scp03_kcv(k)[..],
                "key #{i}: KCV bytes",
            );
        }
    }

    // ----- DD constants pin -----
    #[test]
    fn derivation_data_constants_match_gp_amendment_d() {
        // GP Amendment D §6.2.2 Table 6-2. Pin these so a refactor
        // can't silently shuffle the byte-11 constant for one of the
        // KDF labels (which would silently produce wrong session keys).
        assert_eq!(DD_CARD_CRYPTOGRAM, 0x00);
        assert_eq!(DD_HOST_CRYPTOGRAM, 0x01);
        assert_eq!(DD_S_ENC, 0x04);
        assert_eq!(DD_S_MAC, 0x06);
        assert_eq!(DD_S_RMAC, 0x07);
    }

    #[test]
    fn derivation_data_layout_is_per_gp_amendment_d() {
        let host = [0x11u8; 8];
        let card = [0x22u8; 8];
        let dd = build_derivation_data(DD_S_ENC, 0x0080, &host, &card);
        // Bytes 0..11 are zero (label bytes; SCP03 uses none → all 0).
        for i in 0..11 {
            assert_eq!(dd[i], 0, "byte {i} should be zero");
        }
        assert_eq!(dd[11], DD_S_ENC, "byte 11 = DD constant");
        assert_eq!(dd[12], 0x00, "byte 12 = separation indicator");
        assert_eq!([dd[13], dd[14]], [0x00, 0x80], "L (output bits, BE)");
        assert_eq!(dd[15], 0x01, "i (counter, always 1)");
        assert_eq!(&dd[16..24], &host[..], "host_challenge");
        assert_eq!(&dd[24..32], &card[..], "card_challenge");
    }
}
