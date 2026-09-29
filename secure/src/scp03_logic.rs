//! Pure-logic primitives for SE050 SCP03 — the AES / CMAC primitives, the
//! NIST SP 800-108 counter-mode KDF inputs, the SCP03 KCV, the GP `PUT
//! KEY` APDU builder, the published factory key constants for the fitted
//! SE050 variant (`se050-part-c2` selects which), and
//! the FI-hardened R-MAC authentication-receipt verifier. Nothing in this
//! module depends on `t1oi2c`, `crate::rng`, `secure_log!`, or any other
//! firmware-only facility (`crate::fi` is always-compiled and host-safe),
//! so it compiles for the host target and `#[cfg(test)] mod tests` runs
//! under `cargo test -p sphincs-tz-secure`.
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
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use cmac::Cmac;
use cmac::Mac as CmacMac;

// ---------------------------------------------------------------------------
// Published factory platform keys for the FITTED SE050 variant
//   default            → SE050E2, OEF `0x0001A921`
//   `se050-part-c2`    → SE050C2, OEF `0x0001A201` (SE050C2HQ1/Z01SDZ)
// ---------------------------------------------------------------------------
//
// Both sets are from AN12436 Rev 2.4 §3.4 Table 6 (previous-generation default
// Platform SCP keys), mirrored in
// `plug-and-trust/sss/ex/inc/ex_sss_tp_scp03_keys.h`
// (`SSS_PFSCP_ENABLE_SE050C2` / the A921 row).
//
// ⚠ Table 6's OEF column is a known NXP typo — it prints `A200` on the
// SE050C2 row, contradicting AN12436 Tables 2 and 13 (SE050C2 = OEF `A201`).
// The C2 bytes below are keyed on the *variant name* SE050C2, which the MW macro
// and Tables 2/13 agree on — NOT on the mis-printed OEF cell. Do not "correct"
// them to the A200 (SE050C1) row.
//
// These are *published* — an SCP03 channel that still uses them is plaintext-
// equivalent to a bus sniffer with the datasheet. They are the *initial* state
// of a fresh chip; `work-todo #20` rotates them to per-device BHK-derived keys
// via GP `PUT KEY` (replacing keyset `0x0B` in place) at production time.
//
// WHY THE DEFAULT IS E2 (owner decision 2026-09-17). `df8468d8` (2026-07-20)
// hard-swapped these constants E2→C2 because the production part had been
// finalized as SE050C2HQ1/Z01SDZ. That commit's own message predicted the
// consequence — "the SE050E2 bench board fails SCP03 until swapped" — and on
// 2026-09-17 it came true on the pq1 board, which carries an **SE050E2HQ1**
// (`secure/src/board/pq1.rs:135`, `docs/hardware/schematics/README.md:32`).
// Measured both ways on that silicon, same image except these bytes:
//
//                                  C2 keys     E2 keys
//     "Card cryptogram MISMATCH"        11           0
//     "[SCP03] Session established"      0           3
//     factory_reset_admin          Err(Scp03)     success
//     boot outcome            panic @ crypto.rs:458  provisioning completes
//
// So the keyset is now SELECTABLE and defaults to the part we actually have.
// `docs/hardware/evt-silicon-validation.md` still says the production part is a
// C2; §6 of that same doc records that the C2 "has never run on silicon", so it
// is an ordering intent rather than an observation. When C2 hardware does
// arrive, build it with `se050-part-c2` — do not flip these constants again.
//
// A C2 on a plain OM-SE050ARD dev kit is a third case: it presents the separate
// A375 "Development Board" keyset (ENC `35C25645…`), not encoded here; try that
// if `establish` fails on dev-kit hardware before suspecting the driver.

#[cfg(not(feature = "se050-part-c2"))]
pub const PLATFORM_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7,
    0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
#[cfg(not(feature = "se050-part-c2"))]
pub const PLATFORM_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0,
    0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];
#[cfg(not(feature = "se050-part-c2"))]
pub const PLATFORM_DEK: [u8; 16] = [
    0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8,
    0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F,
];

#[cfg(feature = "se050-part-c2")]
pub const PLATFORM_ENC: [u8; 16] = [
    0xBD, 0x1D, 0xE2, 0x0A, 0x81, 0xEA, 0xB2, 0xBF,
    0x3B, 0x70, 0x9A, 0x9D, 0x69, 0xA3, 0x12, 0x54,
];
#[cfg(feature = "se050-part-c2")]
pub const PLATFORM_MAC: [u8; 16] = [
    0x9A, 0x76, 0x1B, 0x8D, 0xBA, 0x6B, 0xED, 0xF2,
    0x27, 0x41, 0xE4, 0x5D, 0x8D, 0x42, 0x36, 0xF5,
];
#[cfg(feature = "se050-part-c2")]
pub const PLATFORM_DEK: [u8; 16] = [
    0x9B, 0x99, 0x3B, 0x60, 0x0F, 0x1C, 0x64, 0xF5,
    0xAD, 0xC0, 0x63, 0x19, 0x2A, 0x96, 0xC9, 0x47,
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

/// AES-128-CBC decrypt in-place — inverse of `aes128_cbc_encrypt`.
/// `data` must be a multiple of 16 bytes; caller strips padding
/// afterwards.  Used by `unwrap_response` to decrypt R-ENC response
/// bodies under the SCP03 session's `S-ENC` key.
pub fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let ct_block: [u8; 16] = {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            b
        };
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        chunk.copy_from_slice(&block);
        prev = ct_block;
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

/// Publish R-MAC authentication only after two independent full R-MAC
/// recomputations.
///
/// This is the authoritative release gate for every SCP03 protected
/// response (both empty-body `R-MAC || SW` frames and full encrypted
/// frames). The caller fail-initializes `receipt`, calls this helper, and
/// then requires **two independent volatile success checks** (separated by
/// `crate::fi::wait_random()`) before any protected-response copy, counter
/// advance, or `Ok` return.
///
/// Design notes (F-28 rework, 2026-08-03 — see `tools/sca/README.md`
/// §F-28):
///
/// * **Fail-initialized.** The receipt is forced to `FAIL_SENTINEL` first,
///   so a skipped call, a skipped store, or any early return leaves
///   failure authoritative. `OK_SENTINEL` has exactly one publication
///   point, after both recomputations match.
/// * **Two independent full recomputations.** The complete R-MAC
///   (`CMAC(S-RMAC, MCV || body || SW)[..8]`) is recomputed twice, with a
///   `wait_random()` between so one faulted or elided computation cannot
///   satisfy both; `black_box` stops LLVM proving the two compares
///   equivalent and folding them into one branch.
/// * **No infective mask.** The previous gate folded the mismatch into
///   the released bytes as an XOR-`0xFF` complement. That transform is a
///   public bijection: a forging attacker who can form R-ENC ciphertext
///   submits the *complement* of the desired payload and receives the
///   exact attacker-selected plaintext (with attacker-chosen SW, advanced
///   counter, and an `Ok` return) after a single fault skips the early
///   rejection. Authentication is published as a receipt instead, and
///   nothing is copied or advanced without it.
/// * **Constant-time compare.** `subtle::ConstantTimeEq`, same as the
///   `ct_eq_8` it replaces at this site.
///
/// `#[inline(never)]` + `#[export_name]` keep the duplicated verification a
/// distinct optimized-ELF symbol that LTO cannot fold into the caller or
/// collapse into a single check; the symbol is the production-audit
/// receipt (`scripts/prod_symbol_audit.sh`).
#[inline(never)]
#[export_name = "pqsigner_se050_scp03_rmac_verify_into"]
pub fn verify_rmac_into(
    s_rmac: &[u8; 16],
    mcv: &[u8; 16],
    body: &[u8],
    sw: &[u8],
    rmac_recv: &[u8],
    receipt: &mut u32,
) {
    use subtle::ConstantTimeEq;

    debug_assert_eq!(rmac_recv.len(), 8);

    // SAFETY: unique caller-owned receipt. A skipped or shortened
    // verifier (or a skipped caller-side initialization) leaves failure
    // authoritative: both sides write FAIL before any success path.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }

    // First independent full R-MAC recomputation.
    let mac_a = cmac_aes128(s_rmac, &[mcv, body, sw]);
    let ok_a: bool = mac_a[..8].ct_eq(rmac_recv).into();
    if !core::hint::black_box(ok_a) {
        return;
    }

    crate::fi::wait_random();

    // Second independent full R-MAC recomputation — an opaque possible-write
    // call sits between the two, so the compiler cannot common them up and a
    // single fault cannot falsify both.
    let mac_b = cmac_aes128(s_rmac, &[mcv, body, sw]);
    let ok_b: bool = mac_b[..8].ct_eq(rmac_recv).into();
    if !core::hint::black_box(ok_b) {
        return;
    }

    // SAFETY: both independent full recomputations matched the received
    // R-MAC in constant time. This is the sole success publication.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Publish ciphertext↔plaintext relation authentication only after two
/// independent full R-ENC re-encryptions, each under an independently
/// recomputed response ICV.
///
/// The R-MAC receipt (`verify_rmac_into`) authenticates the *ciphertext* of
/// a protected response. It cannot see a fault that corrupts the
/// *decryption*: a single skip of the per-block writeback inside
/// `aes128_cbc_decrypt` leaves bus-visible ciphertext in the released
/// "plaintext" (wave-18 GPT-5.6 blocker, coordinator-reproduced on the
/// wave-18 candidate: `Ok` + intact TLV header + SW `9000` + advanced
/// counter, with the second block byte-for-byte the on-wire ciphertext).
///
/// This helper binds the decrypted padded buffer back to the authenticated
/// ciphertext: CBC re-encryption with the same key and response ICV is the
/// identity on a faithfully decrypted buffer, so any skipped or corrupted
/// staging copy, decrypt, or writeback fails the equality. The ICV is
/// **recomputed inside each pass** (`AES-ECB(S-ENC, 0x80 || counter[1..])`,
/// GP Amd D §6.2.7): sharing the caller's ICV would let one faulted ICV
/// computation make the decrypt and this check consistently wrong (garbage
/// first block, valid equality — observed in the FI sweep). Two independent
/// full re-encryption passes (fresh buffer and fresh ICV each, constant-time
/// compare, `black_box`ed, separated by `wait_random`) publish `OK_SENTINEL`
/// at one point only; the receipt is fail-initialized on entry so any skip
/// or early return leaves failure authoritative. The caller requires two
/// independent volatile success checks before the plaintext is copied out.
///
/// `#[inline(never)]` + `#[export_name]` keep the duplicated verification a
/// distinct optimized-ELF symbol that LTO cannot fold into the caller or
/// collapse into a single pass; the symbol is the production-audit receipt
/// (`scripts/prod_symbol_audit.sh`).
#[inline(never)]
#[export_name = "pqsigner_se050_scp03_renc_verify_into"]
pub fn verify_renc_relation_into(
    s_enc: &[u8; 16],
    counter: &[u8; 16],
    plain_padded: &[u8],
    body: &[u8],
    receipt: &mut u32,
) {
    use subtle::ConstantTimeEq;

    // SAFETY: unique caller-owned receipt. A skipped or shortened
    // verifier (or a skipped caller-side initialization) leaves failure
    // authoritative: both sides write FAIL before any success path.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }

    // Relation shape: equal lengths, AES-CBC blocks, bounded buffer.
    if plain_padded.len() != body.len() || body.is_empty() || body.len() % 16 != 0 || body.len() > 1024
    {
        return;
    }

    // First independent full re-encryption + constant-time compare, under a
    // freshly computed response ICV (GP Amd D §6.2.7).
    let ok_a = {
        let mut icv_block = *counter;
        icv_block[0] = 0x80;
        let icv = aes128_ecb_encrypt(s_enc, &icv_block);
        let mut buf = zeroize::Zeroizing::new([0u8; 1024]);
        buf[..body.len()].copy_from_slice(plain_padded);
        aes128_cbc_encrypt(s_enc, &icv, &mut buf[..body.len()]);
        let eq: bool = buf[..body.len()].ct_eq(body).into();
        core::hint::black_box(eq)
    };
    if !ok_a {
        return;
    }

    crate::fi::wait_random();

    // Second independent full re-encryption — independent ICV recomputation
    // as well, and an opaque possible-write call between the passes, so one
    // faulted computation (ICV, encryption, or compare) cannot falsify both.
    let ok_b = {
        let mut icv_block = *counter;
        icv_block[0] = 0x80;
        let icv = aes128_ecb_encrypt(s_enc, &icv_block);
        let mut buf = zeroize::Zeroizing::new([0u8; 1024]);
        buf[..body.len()].copy_from_slice(plain_padded);
        aes128_cbc_encrypt(s_enc, &icv, &mut buf[..body.len()]);
        let eq: bool = buf[..body.len()].ct_eq(body).into();
        core::hint::black_box(eq)
    };
    if !ok_b {
        return;
    }

    // SAFETY: both independent full re-encryptions reproduced the
    // authenticated ciphertext in constant time. Sole success publication.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
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
/// `docs/archive/production-todo-retired-2026-07-19.md`).
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
/// *current* DEK, passed as `wrap_dek`:
/// - **Factory rotation** (AN12436 defaults → per-device *transport* keyset,
///   `work-todo #20` Stage B): the chip's current DEK is the published
///   `PLATFORM_DEK`.
/// - **First-boot rotation** (transport → final, `work-todo #36`): the chip's
///   current DEK is the per-device *transport* DEK
///   (`secret_keys::transport_se050_scp03_dek()`), since the factory already
///   moved the chip off the AN12436 defaults.
///
/// Passing the wrong `wrap_dek` produces key blocks the chip cannot decrypt,
/// so `PUT KEY` fails closed (the ceremony never silently installs garbage).
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
/// rehearsal (see `docs/archive/production-todo-retired-2026-07-19.md` §"SE050 — SCP03 + ADMIN
/// provisioning"): the `P2` first-key-id / multiple-keys encoding; whether
/// the encrypted-key-data length byte is `0x10` (key only — what we emit)
/// or includes a 1-byte inner length prefix; the KCV filler block; the
/// DEK-encryption mode (we use AES-ECB, no IV/pad, for the 16-byte key).
pub fn build_put_key_apdu(
    new_enc: &[u8; 16],
    new_mac: &[u8; 16],
    new_dek: &[u8; 16],
    wrap_dek: &[u8; 16],
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
        let wrapped = aes128_ecb_encrypt(wrap_dek, k);
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
///
/// "Factory" means *for the variant this build was compiled for* — the
/// `PLATFORM_*` constants are selected by `se050-part-c2` (E2/A921 by
/// default, C2/A201 with the flag). A C2 chip's genuine factory keys
/// therefore read as NOT-factory to a default-built host, which is the
/// correct answer for this function's one caller: it guards against
/// rotating published keys onto themselves, and a keyset the host cannot
/// even open a session with is not a keyset it can rotate.
pub fn keys_are_factory_default(enc: &[u8; 16], mac: &[u8; 16], dek: &[u8; 16]) -> bool {
    *enc == PLATFORM_ENC && *mac == PLATFORM_MAC && *dek == PLATFORM_DEK
}

// ---------------------------------------------------------------------------
// GP PUT KEY response verification (work-todo #36 / #398 — HW-ASSUME-PUTKEY-ATOMIC)
// ---------------------------------------------------------------------------

/// Verify the GP `PUT KEY` **response body** against the KCVs of the three keys
/// we intended to install. `send_apdu` has already stripped and checked the
/// status word (`SW==0x9000`), so `body` is the KCV echo the applet returns so
/// the host can confirm the write landed. Catches a garbled / partially-torn
/// write at write time (`HW-ASSUME-PUTKEY-ATOMIC`, #398/#386).
///
/// This function is the implementation side of `HW-ASSUME-PUTKEY-KCV-RESP`:
/// that the SE050 GP applet echoes the per-key KCVs in the PUT KEY
/// (P1=0x0B, P2=0x81) response body at all. If the applet returns an empty
/// body instead, this check degenerates to a status-only check and the
/// torn-write detection it provides is not there. Unconfirmed on silicon —
/// the falsifying test needs a sacrificial SE050 and a logic analyser on
/// I2C2 (contracts/verification/docs/HW_ASSUMPTIONS.json).
///
/// Observed / spec layouts (GP 2.3.1 §11.8.2.4):
/// - `10` bytes: `KVN(1) || KCV_enc(3) || KCV_mac(3) || KCV_dek(3)`
/// - `9`  bytes:          `KCV_enc(3) || KCV_mac(3) || KCV_dek(3)`
/// - `0`  bytes: the SE05x applet echoes **no** KCV — accepted here because the
///   `0x9000` already confirmed the chip took the write; the DEK-liveness bench
///   step (runbook) is the torn-DEK safety net for this case. Whether the SE050
///   actually echoes KCVs is **`HW-ASSUME-PUTKEY-KCV-RESP`** (the driver has
///   never exercised this path on silicon); once pinned, a `0`-length body may
///   become fail-closed.
///
/// Any other length is unexpected → fail closed. Returns
/// [`crate::fi::OK_SENTINEL`] on success (Hamming-distant FI verdict), never a
/// bare bool.
#[must_use]
pub fn verify_put_key_response(
    body: &[u8],
    enc: &[u8; 16],
    mac: &[u8; 16],
    dek: &[u8; 16],
) -> u32 {
    let off = match body.len() {
        // No KCV echoed — accepted (SW==0x9000 already confirmed the write; see
        // HW-CONFIRM above). Routed through the double-evaluated sentinel path,
        // not a bare `return OK_SENTINEL`, so it matches the {9,10} branches.
        0 => return crate::fi::check_true_into_sentinel(|| true),
        10 => 1usize,
        9 => 0usize,
        _ => return crate::fi::FAIL_SENTINEL,
    };
    let kvn_ok = body.len() != 10 || body[0] == KEY_VERSION;
    let want = [scp03_kcv(enc), scp03_kcv(mac), scp03_kcv(dek)];
    crate::fi::check_true_into_sentinel(|| {
        // OR the byte differences so the compare is data-independent in shape.
        let mut diff = 0u8;
        let mut i = 0;
        while i < 3 {
            let mut j = 0;
            while j < 3 {
                diff |= body[off + i * 3 + j] ^ want[i][j];
                j += 1;
            }
            i += 1;
        }
        kvn_ok && diff == 0
    })
}

// ---------------------------------------------------------------------------
// Authenticate-before-rotate proof (work-todo #36 — named production gate)
// ---------------------------------------------------------------------------

// Context tags binding a proof to ONE credential so an SCP03 proof can't gate
// an admin delete, etc. Distinct, non-zero, and mutually Hamming-distant.
pub const AUTH_CTX_SCP03_TRANSPORT: u32 = 0x5343_5033; // "SCP3"
pub const AUTH_CTX_ADMIN_TRANSPORT: u32 = 0x4144_4D4E; // "ADMN"
pub const AUTH_CTX_PBS_TRANSPORT: u32 = 0x5042_5321; // "PBS!"

/// A fail-initialized proof that a rotation write was preceded by a **verified
/// authentication under the factory transport credential** (the named
/// "authenticate-before-rotate" production gate). Mirrors the codebase's
/// `DeploymentConfirmReceipt` FI-sentinel-carrier idiom: a freshly constructed
/// proof authorizes NOTHING, so a single glitch that skips the whole
/// transport-auth call leaves the write refused. The verdict can only become
/// `OK_SENTINEL` by running [`record`](Self::record) on the auth success arm.
///
/// `!Copy + !Clone` so a proof can't be duplicated past its one write.
#[must_use]
pub struct TransportAuthProof {
    verdict: u32,
    context: u32,
}

impl TransportAuthProof {
    /// Fail-closed constructor: a pending proof authorizes nothing. (The
    /// struct is already `#[must_use]`, so the result cannot be dropped.)
    pub const fn pending(context: u32) -> Self {
        Self {
            verdict: crate::fi::FAIL_SENTINEL,
            context,
        }
    }

    /// Record success on the transport-auth success arm. `verified` is
    /// re-evaluated through the double-checked FI sentinel path, so a fault on
    /// one evaluation fails closed. A context mismatch (or `verified == false`,
    /// e.g. a wrong transport credential) leaves the proof pending.
    #[inline(never)]
    pub fn record<F: FnMut() -> bool>(&mut self, expect_ctx: u32, verified: F) {
        if self.context != expect_ctx {
            return; // stays FAIL_SENTINEL
        }
        self.verdict = crate::fi::check_true_into_sentinel(verified);
    }

    /// Consume immediately before a destructive rotation write. Returns
    /// [`crate::fi::OK_SENTINEL`] iff this proof is for `expect_ctx` AND its
    /// verdict is OK. Voted volatile reads defeat a single load-glitch; the
    /// result is a Hamming-distant sentinel, not a bare bool.
    #[inline(never)]
    #[must_use]
    pub fn authorize_write(&self, expect_ctx: u32) -> u32 {
        let v = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.verdict))
            .unwrap_or(crate::fi::FAIL_SENTINEL);
        let c = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.context)).unwrap_or(0);
        crate::fi::check_true_into_sentinel(|| v == crate::fi::OK_SENTINEL && c == expect_ctx)
    }
}

// ---------------------------------------------------------------------------
// Tests — these now actually run under `cargo test -p sphincs-tz-secure`
// because `scp03_logic` (unlike `se050::scp03`) is not `not(test)`-gated.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----- F-28 rework: R-MAC authentication receipt -----
    //
    // Fixed SCP03 session material (arbitrary bytes; the verifier is
    // key-value-independent). These tests pin the BEHAVIOUR of
    // `verify_rmac_into`; the FI sweep (`make -C tools/sca scp03-fi`) and
    // the source pins in `se050_under_test` pin the caller-side gate.
    const T_S_RMAC: [u8; 16] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];
    const T_MCV: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    ];
    const T_BODY: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    const T_SW: [u8; 2] = [0x90, 0x00];

    fn good_rmac(body: &[u8], sw: &[u8]) -> [u8; 8] {
        let mac = cmac_aes128(&T_S_RMAC, &[&T_MCV, body, sw]);
        let mut out = [0u8; 8];
        out.copy_from_slice(&mac[..8]);
        out
    }

    #[test]
    fn verify_rmac_publishes_ok_on_exact_match_full_body() {
        let rmac = good_rmac(&T_BODY, &T_SW);
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &T_SW, &rmac, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }

    #[test]
    fn verify_rmac_publishes_ok_on_exact_match_empty_body() {
        // Case 2 shape (R-MAC over MCV || SW only) must pass the same gate.
        let rmac = good_rmac(&[], &T_SW);
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &[], &T_SW, &rmac, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }

    #[test]
    fn verify_rmac_rejects_all_zero_rmac() {
        // The forged-frame shape from the FI harness: a valid R-ENC body
        // with an all-zero R-MAC must never authenticate.
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &T_SW, &[0u8; 8], &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        let mut receipt_empty = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &[], &T_SW, &[0u8; 8], &mut receipt_empty);
        assert_eq!(receipt_empty, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_rmac_rejects_single_bit_flip() {
        let mut rmac = good_rmac(&T_BODY, &T_SW);
        rmac[3] ^= 0x01;
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &T_SW, &rmac, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_rmac_rejects_mac_for_tampered_body_or_sw() {
        let rmac = good_rmac(&T_BODY, &T_SW);
        let mut tampered_body = T_BODY;
        tampered_body[0] ^= 0x01;
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &tampered_body, &T_SW, &rmac, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);

        let tampered_sw: [u8; 2] = [0x69, 0x85];
        let mut receipt_sw = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &tampered_sw, &rmac, &mut receipt_sw);
        assert_eq!(receipt_sw, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_rmac_rejects_mac_from_other_mcv() {
        // A MAC replayed from a different command (different MCV) must fail.
        let other_mcv = [0x11u8; 16];
        let mac = cmac_aes128(&T_S_RMAC, &[&other_mcv, &T_BODY, &T_SW]);
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &T_SW, &mac[..8], &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_rmac_fail_initializes_receipt_before_rejecting() {
        // Mutation control: deleting the callee-side FAIL store (or the whole
        // call) must leave a pre-seeded/stale receipt failed, never OK.
        let mut receipt = crate::fi::OK_SENTINEL;
        verify_rmac_into(&T_S_RMAC, &T_MCV, &T_BODY, &T_SW, &[0u8; 8], &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_rmac_receipt_is_not_published_on_wrong_key() {
        let rmac = good_rmac(&T_BODY, &T_SW);
        let wrong_key = [0x42u8; 16];
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_rmac_into(&wrong_key, &T_MCV, &T_BODY, &T_SW, &rmac, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    // ----- Wave-18 rework: R-ENC decrypt-fidelity relation receipt -----

    const T_S_ENC: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];
    const T_COUNTER: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// Response ICV for T_COUNTER (`AES-ECB(S-ENC, 0x80 || counter[1..])`,
    /// GP Amd D §6.2.7) — what the helper recomputes internally per pass.
    fn t_icv() -> [u8; 16] {
        let mut block = T_COUNTER;
        block[0] = 0x80;
        aes128_ecb_encrypt(&T_S_ENC, &block)
    }

    /// A 48-byte padded plaintext (32-byte TLV + 0x80 pad) and its R-ENC
    /// ciphertext — the valid3 shape from the FI harness.
    fn valid3_plain_and_body() -> ([u8; 48], [u8; 48]) {
        let mut plain = [0u8; 48];
        plain[0] = 0x41;
        plain[1] = 0x1e;
        for (i, b) in plain[2..32].iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        plain[32] = 0x80;
        let mut body = plain;
        aes128_cbc_encrypt(&T_S_ENC, &t_icv(), &mut body);
        (plain, body)
    }

    #[test]
    fn verify_renc_relation_publishes_ok_on_faithful_decrypt() {
        let (plain, body) = valid3_plain_and_body();
        // Simulate the firmware path: decrypt the body, then verify the
        // relation between the decrypted buffer and the ciphertext.
        let mut decrypted = body;
        aes128_cbc_decrypt(&T_S_ENC, &t_icv(), &mut decrypted);
        assert_eq!(decrypted, plain);
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &decrypted, &body, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }

    #[test]
    fn verify_renc_relation_rejects_skipped_writeback_ciphertext() {
        // The confirmed wave-18 mechanism: a skipped per-block writeback in
        // CBC decrypt leaves the raw (bus-visible) ciphertext block in the
        // "plaintext" buffer. The relation must fail closed.
        let (_plain, body) = valid3_plain_and_body();
        let mut corrupted = body;
        aes128_cbc_decrypt(&T_S_ENC, &t_icv(), &mut corrupted[..16]); // block 0 only
        // block 1..3 still hold ciphertext — exactly the skipped-writeback shape.
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &corrupted, &body, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_renc_relation_rejects_decrypt_under_a_faulted_icv() {
        // The ICV-sharing flaw the helper's per-pass ICV recomputation
        // closes: decrypting under a WRONG ICV yields garbage block 0 but
        // correct later blocks — and a relation check that shared that ICV
        // would accept. The helper recomputes the ICV from the counter, so
        // it must reject.
        let (_plain, body) = valid3_plain_and_body();
        let wrong_icv = [0xABu8; 16];
        let mut corrupted = body;
        aes128_cbc_decrypt(&T_S_ENC, &wrong_icv, &mut corrupted);
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &corrupted, &body, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_renc_relation_rejects_zeroed_or_flipped_plaintext() {
        let (plain, body) = valid3_plain_and_body();
        // Skipped staging copy leaves zeros.
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &[0u8; 48], &body, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        // A single flipped bit anywhere in the padded plaintext.
        let mut flipped = plain;
        flipped[47] ^= 0x01;
        let mut receipt2 = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &flipped, &body, &mut receipt2);
        assert_eq!(receipt2, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_renc_relation_fail_initializes_receipt_before_rejecting() {
        let (_plain, body) = valid3_plain_and_body();
        let mut receipt = crate::fi::OK_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &[0u8; 48], &body, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn verify_renc_relation_rejects_wrong_key_counter_and_bad_shapes() {
        let (plain, body) = valid3_plain_and_body();
        let wrong_key = [0x99u8; 16];
        let mut receipt = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&wrong_key, &T_COUNTER, &plain, &body, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
        // A different counter derives a different ICV, so the honest
        // plaintext no longer re-encrypts to `body`.
        let wrong_counter = [9u8; 16];
        let mut receipt2 = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &wrong_counter, &plain, &body, &mut receipt2);
        assert_eq!(receipt2, crate::fi::FAIL_SENTINEL);
        // Shape violations: length mismatch, non-block length, empty body.
        let mut r3 = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &plain[..32], &body, &mut r3);
        assert_eq!(r3, crate::fi::FAIL_SENTINEL);
        let mut r4 = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &plain[..20], &body[..20], &mut r4);
        assert_eq!(r4, crate::fi::FAIL_SENTINEL);
        let mut r5 = crate::fi::FAIL_SENTINEL;
        verify_renc_relation_into(&T_S_ENC, &T_COUNTER, &[], &[], &mut r5);
        assert_eq!(r5, crate::fi::FAIL_SENTINEL);
    }


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
        let (a, n) = build_put_key_apdu(&new_enc, &new_mac, &new_dek, &PLATFORM_DEK);
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
        let (a, _) = build_put_key_apdu(&new_enc, &new_mac, &new_dek, &PLATFORM_DEK);
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

    /// work-todo #36: the first-boot rotation wraps the new key blocks under
    /// the per-device *transport* DEK, not `PLATFORM_DEK`. Prove `wrap_dek`
    /// is actually the encryption key: a different `wrap_dek` MUST produce
    /// different wrapped bytes (and match the ECB KAT under that DEK), while
    /// the KCV — computed over the plaintext new key — is unchanged.
    #[test]
    fn put_key_wrap_dek_selects_the_encryption_key() {
        let new_enc = [0xA0u8; 16];
        let new_mac = [0xB1u8; 16];
        let new_dek = [0xC2u8; 16];
        // A stand-in per-device transport DEK, distinct from PLATFORM_DEK.
        let transport_dek = [0x5Au8; 16];
        assert_ne!(transport_dek, PLATFORM_DEK);

        let (factory, _) = build_put_key_apdu(&new_enc, &new_mac, &new_dek, &PLATFORM_DEK);
        let (field, _) = build_put_key_apdu(&new_enc, &new_mac, &new_dek, &transport_dek);

        for (i, k) in [&new_enc, &new_mac, &new_dek].iter().enumerate() {
            let base = 6 + i * 22;
            // Field build wraps under the transport DEK (KAT).
            assert_eq!(
                &field[base + 2..base + 18],
                &aes128_ecb_encrypt(&transport_dek, k)[..],
                "block #{i}: field build must wrap under the transport DEK",
            );
            // ...and differs from the factory (PLATFORM_DEK) wrap.
            assert_ne!(
                &field[base + 2..base + 18],
                &factory[base + 2..base + 18],
                "block #{i}: transport-DEK wrap must differ from PLATFORM_DEK wrap",
            );
            // KCV is over the plaintext key, so it is identical for both.
            assert_eq!(
                &field[base + 19..base + 22],
                &factory[base + 19..base + 22],
                "block #{i}: KCV is over plaintext → unchanged by wrap_dek",
            );
        }
        // Everything outside the wrapped-key bytes is identical.
        assert_eq!(&factory[..6], &field[..6], "header unchanged by wrap_dek");
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

    // ──────────────────────────────────────────────────────────────────
    // Additional positive coverage for AES-128 CBC, KDF wrapper, and the
    // PLATFORM_* factory constants.
    // ──────────────────────────────────────────────────────────────────

    /// AES-128 CBC encrypts the first block as `AES(K, P0 XOR IV)`; pins
    /// that the in-place CBC path matches the FIPS 197 §C.1 KAT when
    /// applied to a single block with a zero IV.
    #[test]
    fn positive_aes128_cbc_single_block_with_zero_iv_matches_ecb() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let mut data: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        let iv = [0u8; 16];
        aes128_cbc_encrypt(&key, &iv, &mut data);
        let expected: [u8; 16] = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
        ];
        assert_eq!(data, expected, "CBC with zero IV must equal ECB on first block");
    }

    /// CBC chains: the second block's input is `P1 XOR C0`. Pin that the
    /// implementation actually uses the previous ciphertext (not, say,
    /// the previous plaintext) — a silent regression here would make the
    /// SCP03 wrap output decryptable under ECB.
    #[test]
    fn positive_aes128_cbc_two_blocks_chain_through_previous_ciphertext() {
        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let mut data = [0u8; 32];
        aes128_cbc_encrypt(&key, &iv, &mut data);
        // Reconstruct manually: c0 = E(P0 XOR IV) = E(0..0), and
        // c1 = E(P1 XOR c0) = E(c0).
        let c0 = aes128_ecb_encrypt(&key, &[0u8; 16]);
        let c1 = aes128_ecb_encrypt(&key, &c0);
        assert_eq!(&data[..16], &c0[..], "block 0 must equal E(0)");
        assert_eq!(&data[16..32], &c1[..], "block 1 must equal E(c0) (chained)");
    }

    /// AES-128-CBC encrypt then decrypt is the identity — pin the
    /// `aes128_cbc_decrypt` primitive added for SCP03 `unwrap_response`
    /// against the existing `aes128_cbc_encrypt`.  Round-trip is the
    /// strongest single test: if decrypt has any bug (key/IV
    /// misordering, chain through plaintext instead of ciphertext,
    /// wrong block direction) the output won't equal the input.
    #[test]
    fn positive_aes128_cbc_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 16];
        let iv = [0xA5u8; 16];
        let original = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let mut data = original;
        aes128_cbc_encrypt(&key, &iv, &mut data);
        assert_ne!(data, original, "encrypt must produce non-identity output");
        aes128_cbc_decrypt(&key, &iv, &mut data);
        assert_eq!(data, original, "decrypt(encrypt(x)) must equal x");
    }

    /// CBC decrypt with a single-block input + zero IV is just
    /// AES-ECB-decrypt of the block.
    #[test]
    fn positive_aes128_cbc_decrypt_single_block_zero_iv_matches_ecb() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        // FIPS 197 §C.1 ciphertext.
        let ciphertext: [u8; 16] = [
            0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A,
        ];
        let mut data = ciphertext;
        let iv = [0u8; 16];
        aes128_cbc_decrypt(&key, &iv, &mut data);
        let expected: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ];
        assert_eq!(data, expected, "CBC decrypt with zero IV must equal ECB decrypt on first block");
    }

    /// CBC chains forward: decrypt of block 2 uses CT block 1 as the
    /// XOR mask, NOT plaintext block 1. Mirrors the negative
    /// `positive_aes128_cbc_two_blocks_chain_through_previous_ciphertext`
    /// test in the encrypt direction.
    #[test]
    fn positive_aes128_cbc_decrypt_two_blocks_uses_previous_ciphertext() {
        // Construct: c0 = AES-ECB-Enc(K, 0), c1 = AES-ECB-Enc(K, c0).
        // Decrypt should give back [0; 32] with zero IV.
        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let c0 = aes128_ecb_encrypt(&key, &[0u8; 16]);
        let c1 = aes128_ecb_encrypt(&key, &c0);
        let mut data = [0u8; 32];
        data[..16].copy_from_slice(&c0);
        data[16..].copy_from_slice(&c1);
        aes128_cbc_decrypt(&key, &iv, &mut data);
        assert_eq!(data, [0u8; 32]);
    }

    /// CBC is keyed: the same plaintext under different keys produces
    /// different ciphertexts.
    #[test]
    fn positive_aes128_cbc_distinct_keys_diverge() {
        let key_a = [0x11u8; 16];
        let key_b = [0x22u8; 16];
        let iv = [0u8; 16];
        let mut a = [0xAAu8; 16];
        let mut b = [0xAAu8; 16];
        aes128_cbc_encrypt(&key_a, &iv, &mut a);
        aes128_cbc_encrypt(&key_b, &iv, &mut b);
        assert_ne!(a, b, "different keys must produce different ciphertext");
    }

    /// `kdf` is exactly `cmac_aes128(K, dd)` — pin the byte-equality so
    /// a future refactor can't silently swap `kdf` for, say, an HKDF
    /// expand.
    #[test]
    fn positive_kdf_equals_cmac_aes128_over_derivation_data() {
        let key = [0x33u8; 16];
        let host = [0x55u8; 8];
        let card = [0x66u8; 8];
        let dd = build_derivation_data(DD_S_ENC, 0x0080, &host, &card);
        let via_kdf = kdf(&key, &dd);
        let via_cmac = cmac_aes128(&key, &[&dd]);
        assert_eq!(via_kdf, via_cmac);
    }

    /// Both SE050 factory keysets are published in AN12436 Rev 2.4 §3.4
    /// Table 6 (previous-generation) and are the **plaintext-equivalent**
    /// state until `PUT KEY` lands. Pin the constants so a typo or a
    /// `// TODO swap with random` regression surfaces immediately — these
    /// bytes are load-bearing for the derived-keys fallback in `establish()`,
    /// and a wrong keyset fails closed in a way that also locks the
    /// `admin_factory_reset` recovery path (pq1 silicon, 2026-09-17).
    ///
    /// Which set is compiled in is chosen by `se050-part-c2`; each arm below
    /// ALSO asserts the other variant's identifying byte is absent, so a
    /// copy-paste that made both arms identical — silently turning the
    /// feature into a no-op — fails instead of passing in both configs.
    #[test]
    fn positive_platform_keyset_bytes_match_an12436() {
        // First and last bytes are the unique identifier for each constant.
        // The KCV test below pins the remainder structurally.
        #[cfg(not(feature = "se050-part-c2"))]
        {
            // SE050E2 / OEF A921 — the default, and the part on every board
            // we physically have.
            assert_eq!(PLATFORM_ENC[0], 0xD2);
            assert_eq!(PLATFORM_ENC[15], 0x64);
            assert_eq!(PLATFORM_MAC[0], 0x73);
            assert_eq!(PLATFORM_MAC[15], 0x5B);
            assert_eq!(PLATFORM_DEK[0], 0x67);
            assert_eq!(PLATFORM_DEK[15], 0x7F);
            // Anti-no-op: must NOT be the C2 keyset.
            assert_ne!(PLATFORM_ENC[0], 0xBD, "default build must use E2 keys");
        }
        #[cfg(feature = "se050-part-c2")]
        {
            // SE050C2 / OEF A201 (SE050C2HQ1/Z01SDZ).
            assert_eq!(PLATFORM_ENC[0], 0xBD);
            assert_eq!(PLATFORM_ENC[15], 0x54);
            assert_eq!(PLATFORM_MAC[0], 0x9A);
            assert_eq!(PLATFORM_MAC[15], 0xF5);
            assert_eq!(PLATFORM_DEK[0], 0x9B);
            assert_eq!(PLATFORM_DEK[15], 0x47);
            // Anti-no-op: must NOT be the E2 keyset.
            assert_ne!(PLATFORM_ENC[0], 0xD2, "se050-part-c2 must use C2 keys");
        }
        // The three factory constants MUST be pairwise distinct (a
        // chip whose ENC == MAC etc. would have a trivial cross-protocol
        // weakness, and would also be a typo signal).
        assert_ne!(PLATFORM_ENC, PLATFORM_MAC);
        assert_ne!(PLATFORM_ENC, PLATFORM_DEK);
        assert_ne!(PLATFORM_MAC, PLATFORM_DEK);
    }

    /// SCP03 KVN for the platform keyset is the GP/AN12436-defined value
    /// `0x0B`. `PUT KEY` replaces this slot in place; any drift here
    /// breaks the rotation ceremony.
    #[test]
    fn positive_key_version_is_0x0b() {
        assert_eq!(KEY_VERSION, 0x0B);
    }

    /// `PUT KEY` INS byte is `0xD8` per GP 2.3 §11.8.2.3.1 and is the
    /// only INS the SE050 accepts for keyset rotation.
    #[test]
    fn positive_put_key_ins_is_0xd8() {
        assert_eq!(PUT_KEY_INS, 0xD8);
    }

    /// `PUT_KEY_APDU_LEN == 72` — this is wire-format and must match
    /// what `wrap_apdu` budgets for; a drift would either truncate or
    /// over-read at SCP03 send time. Layout: `5 (hdr) + 1 (KVN) +
    /// 3 × 22 (key blocks) = 72`.
    #[test]
    fn positive_put_key_apdu_len_layout_arithmetic_is_72() {
        assert_eq!(PUT_KEY_APDU_LEN, 72);
        assert_eq!(PUT_KEY_APDU_LEN, 5 + 1 + 3 * (1 + 1 + 16 + 1 + 3));
    }

    // ──────────────────────────────────────────────────────────────────
    // Negative coverage — challenges assumptions the SCP03 code holds.
    // ──────────────────────────────────────────────────────────────────

    /// PIN: SCP03 KCV uses an `0x01`-filled filler block (GP Amendment D
    /// §7.1), NOT the `0x00`-filled block used by older SCP02 profiles.
    /// If a future refactor silently flips to `0x00`, the SE050 will
    /// reject every `PUT KEY` ceremony with a KCV mismatch and we lose
    /// the entire derived-keys rotation path. This test pins the
    /// observable convention.
    ///
    /// Attack scenario: a developer "cleans up" magic numbers and
    /// uses `[0u8; 16]` instead of `[0x01u8; 16]`. The chip would then
    /// see KCV bytes that don't match its recomputation, and every
    /// `PUT KEY` would fail silently.
    #[test]
    fn negative_scp03_kcv_filler_is_0x01_not_0x00() {
        let k = [0u8; 16];
        let kcv_0x01 = scp03_kcv(&k);
        let kcv_0x00 = aes128_ecb_encrypt(&k, &[0u8; 16]);
        assert_ne!(
            kcv_0x01, [kcv_0x00[0], kcv_0x00[1], kcv_0x00[2]],
            "SCP03 KCV must use the 0x01-filled block per GP Amendment D §7.1; \
             a silent flip to 0x00 (SCP02 convention) would make every PUT KEY \
             fail with KCV mismatch on the chip"
        );
    }

    /// PIN: changing any single byte of `PLATFORM_ENC` / `MAC` / `DEK`
    /// must flip `keys_are_factory_default` to `false`. The previous
    /// `keys_are_factory_default_false_for_any_byte_change` test
    /// probes only three byte positions; this exhaustive sweep
    /// strengthens it to "every byte position matters." A regression
    /// that compared only a prefix would let attacker-chosen keys with
    /// a matching prefix bypass the "refuse to PUT KEY the published
    /// keys over themselves" rotation guard.
    #[test]
    fn negative_keys_are_factory_default_rejects_every_byte_flip() {
        for arr in [&PLATFORM_ENC, &PLATFORM_MAC, &PLATFORM_DEK] {
            for i in 0..16 {
                let mut tweaked = *arr;
                tweaked[i] ^= 0xFF;
                let res = if core::ptr::eq(arr, &PLATFORM_ENC) {
                    keys_are_factory_default(&tweaked, &PLATFORM_MAC, &PLATFORM_DEK)
                } else if core::ptr::eq(arr, &PLATFORM_MAC) {
                    keys_are_factory_default(&PLATFORM_ENC, &tweaked, &PLATFORM_DEK)
                } else {
                    keys_are_factory_default(&PLATFORM_ENC, &PLATFORM_MAC, &tweaked)
                };
                assert!(
                    !res,
                    "byte {i} of one factory key was flipped but keys_are_factory_default \
                     still reported true — prefix-only compare would let attacker-chosen \
                     keys bypass the rotation guard in Se050::rotate_scp03_keys",
                );
            }
        }
    }

    /// PIN: each DD-byte-11 constant (S-ENC / S-MAC / S-RMAC /
    /// card-cryptogram / host-cryptogram) MUST be pairwise distinct.
    /// Two SCP03 KDF labels sharing a byte-11 value would produce
    /// identical session keys for different purposes — e.g. the MAC
    /// key and the encryption key would coincide, collapsing the
    /// channel's separation guarantees.
    #[test]
    fn negative_dd_constants_are_pairwise_distinct() {
        let labels = [
            ("DD_CARD_CRYPTOGRAM", DD_CARD_CRYPTOGRAM),
            ("DD_HOST_CRYPTOGRAM", DD_HOST_CRYPTOGRAM),
            ("DD_S_ENC", DD_S_ENC),
            ("DD_S_MAC", DD_S_MAC),
            ("DD_S_RMAC", DD_S_RMAC),
        ];
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(
                    labels[i].1, labels[j].1,
                    "DD constants {} and {} collide → SCP03 session keys would alias",
                    labels[i].0, labels[j].0,
                );
            }
        }
    }

    /// PIN: changing the host challenge changes the derivation data and
    /// therefore the KDF output. Defends against a hypothetical bug
    /// where `build_derivation_data` writes the host challenge into the
    /// wrong slice slot (e.g. into bytes 24..32 instead of 16..24) —
    /// the function would still return *some* bytes, the chip would
    /// just compute a different session key and reject every command.
    #[test]
    fn negative_kdf_output_changes_with_host_challenge() {
        let key = [0x33u8; 16];
        let card = [0xAAu8; 8];
        let host_a = [0x11u8; 8];
        let host_b = [0x22u8; 8];
        let dd_a = build_derivation_data(DD_S_ENC, 0x0080, &host_a, &card);
        let dd_b = build_derivation_data(DD_S_ENC, 0x0080, &host_b, &card);
        assert_ne!(kdf(&key, &dd_a), kdf(&key, &dd_b));
    }

    /// PIN: same as above for the card challenge.
    #[test]
    fn negative_kdf_output_changes_with_card_challenge() {
        let key = [0x33u8; 16];
        let host = [0xAAu8; 8];
        let card_a = [0x11u8; 8];
        let card_b = [0x22u8; 8];
        let dd_a = build_derivation_data(DD_S_ENC, 0x0080, &host, &card_a);
        let dd_b = build_derivation_data(DD_S_ENC, 0x0080, &host, &card_b);
        assert_ne!(kdf(&key, &dd_a), kdf(&key, &dd_b));
    }

    /// PIN: same DD with different DD-byte-11 constants must yield
    /// different KDF outputs. This is the "label" separation guarantee.
    #[test]
    fn negative_kdf_output_changes_with_dd_constant() {
        let key = [0x33u8; 16];
        let host = [0x11u8; 8];
        let card = [0x22u8; 8];
        let dd_enc = build_derivation_data(DD_S_ENC, 0x0080, &host, &card);
        let dd_mac = build_derivation_data(DD_S_MAC, 0x0080, &host, &card);
        assert_ne!(
            kdf(&key, &dd_enc), kdf(&key, &dd_mac),
            "S-ENC and S-MAC must derive distinct session keys; aliasing them \
             would collapse SCP03 channel separation"
        );
    }

    /// PIN: KCV is exactly 3 bytes. Anything else and the SE050's
    /// `PUT KEY` parser rejects the APDU. Concretely guards against an
    /// over-eager refactor changing the return type to `[u8; 4]` or
    /// truncating to `[u8; 2]`.
    #[test]
    fn negative_scp03_kcv_returns_exactly_three_bytes() {
        let k = [0u8; 16];
        let kcv = scp03_kcv(&k);
        assert_eq!(core::mem::size_of_val(&kcv), 3);
        // `[u8; 3]` is `Copy`; this is a compile-time pin via the
        // type system + the size assertion above.
    }

    /// PIN: `PUT KEY` APDU header is exactly `CLA=0x80 INS=0xD8 P1=0x0B
    /// P2=0x81 Lc=0x43`. The on-chip parser rejects every field
    /// individually; a silent off-by-one in any of them turns into a
    /// silent rotation failure during production-provisioning.
    #[test]
    fn negative_put_key_apdu_header_bytes_are_frozen() {
        let (a, _) = build_put_key_apdu(&[0u8; 16], &[0u8; 16], &[0u8; 16], &PLATFORM_DEK);
        assert_eq!(a[0], 0x80, "CLA must be 0x80 — wrap_apdu later ORs in 0x04");
        assert_eq!(a[1], 0xD8, "INS must be PUT KEY (0xD8)");
        assert_eq!(a[2], 0x0B, "P1 must be KVN 0x0B (the slot to replace)");
        assert_eq!(a[3], 0x81, "P2 must be 'multiple keys' (0x80) | first key id (0x01)");
        assert_eq!(a[4], 0x43, "Lc must equal 67 (= 1 + 3*22)");
        assert_eq!(a[5], 0x0B, "data byte 0 must be the new KVN (same value, in-place)");
    }

    /// PIN: the encrypted-key-data length byte inside each key block is
    /// `0x10` (=16). The SE050 parser uses this to seek to the KCV
    /// bytes; if the firmware emits a different length (e.g. `0x11`
    /// because someone added a 1-byte inner length prefix without
    /// updating the constant), the chip silently misaligns and rejects
    /// the KCV.
    #[test]
    fn negative_put_key_enc_data_len_byte_is_0x10_per_block() {
        let (a, _) = build_put_key_apdu(&[0u8; 16], &[0u8; 16], &[0u8; 16], &PLATFORM_DEK);
        for i in 0..3 {
            let base = 6 + i * 22;
            assert_eq!(a[base], 0x88, "key #{i} type byte must be 0x88 (AES)");
            assert_eq!(a[base + 1], 0x10, "key #{i} enc-data length must be 16");
            assert_eq!(a[base + 18], 0x03, "key #{i} KCV length must be 3");
        }
    }

    /// PIN: each `PUT KEY` block carries the AES-ECB encryption of the
    /// new key under the *current* DEK. If a refactor accidentally
    /// reuses the previous block's wrapped value, or pads/IVs the ECB
    /// call (turning it into CBC with zero IV — different bytes when
    /// the new key isn't zero), the chip rejects every subsequent
    /// SCP03 session because the KCV won't match.
    #[test]
    fn negative_put_key_wrapped_bytes_match_ecb_under_platform_dek() {
        let new_enc = [0xA0u8; 16];
        let new_mac = [0xB1u8; 16];
        let new_dek = [0xC2u8; 16];
        let (a, _) = build_put_key_apdu(&new_enc, &new_mac, &new_dek, &PLATFORM_DEK);
        for (i, k) in [&new_enc, &new_mac, &new_dek].iter().enumerate() {
            let base = 6 + i * 22;
            let expected_wrap = aes128_ecb_encrypt(&PLATFORM_DEK, k);
            assert_eq!(
                &a[base + 2..base + 18],
                &expected_wrap[..],
                "block #{i} wrapped bytes diverged from AES-ECB(PLATFORM_DEK, new_key); \
                 a non-ECB primitive here breaks the SE050 PUT KEY parse"
            );
        }
    }

    /// PIN: keys are emitted in ENC → MAC → DEK order. Reordering them
    /// would not change the byte length but would silently mis-rotate
    /// the chip (its DEK becomes the firmware's ENC and vice versa),
    /// permanently bricking that SE050 unit for derived-keys
    /// authentication.
    #[test]
    fn negative_put_key_emits_keys_in_enc_mac_dek_order() {
        let enc = [0xE0u8; 16];
        let mac = [0xC1u8; 16];
        let dek = [0xD2u8; 16];
        let (a, _) = build_put_key_apdu(&enc, &mac, &dek, &PLATFORM_DEK);
        assert_eq!(
            &a[6 + 0 * 22 + 2..6 + 0 * 22 + 18],
            &aes128_ecb_encrypt(&PLATFORM_DEK, &enc)[..],
            "block 0 must be ENC",
        );
        assert_eq!(
            &a[6 + 1 * 22 + 2..6 + 1 * 22 + 18],
            &aes128_ecb_encrypt(&PLATFORM_DEK, &mac)[..],
            "block 1 must be MAC",
        );
        assert_eq!(
            &a[6 + 2 * 22 + 2..6 + 2 * 22 + 18],
            &aes128_ecb_encrypt(&PLATFORM_DEK, &dek)[..],
            "block 2 must be DEK",
        );
    }

    /// PIN: `cmac_aes128` MUST treat the inputs slice as concatenation.
    /// Already covered as a positive test above; the negative side is:
    /// the empty inputs slice case (`&[]` rather than `&[&[]]`)
    /// produces the same bytes as the all-empty case, so a refactor
    /// can't silently introduce an "if inputs.is_empty() return zeros"
    /// shortcut that would diverge from a CMAC-of-empty-string.
    #[test]
    fn negative_cmac_aes128_no_input_slices_equals_one_empty_slice() {
        let key = [0x99u8; 16];
        let a = cmac_aes128(&key, &[]);
        let b = cmac_aes128(&key, &[&[]]);
        assert_eq!(
            a, b,
            "cmac of no inputs must equal cmac of one empty input — both are 'message = empty'"
        );
    }

    // ----- verify_put_key_response (work-todo #36 / #398) -----

    fn kcv_body_10(enc: &[u8; 16], mac: &[u8; 16], dek: &[u8; 16]) -> [u8; 10] {
        let mut b = [0u8; 10];
        b[0] = KEY_VERSION;
        b[1..4].copy_from_slice(&scp03_kcv(enc));
        b[4..7].copy_from_slice(&scp03_kcv(mac));
        b[7..10].copy_from_slice(&scp03_kcv(dek));
        b
    }

    #[test]
    fn put_key_response_accepts_matching_kcvs_and_empty_body() {
        let (enc, mac, dek) = ([0xA0u8; 16], [0xB1u8; 16], [0xC2u8; 16]);
        let b10 = kcv_body_10(&enc, &mac, &dek);
        assert_eq!(verify_put_key_response(&b10, &enc, &mac, &dek), crate::fi::OK_SENTINEL);
        // 9-byte form: the three KCVs without the leading KVN.
        assert_eq!(verify_put_key_response(&b10[1..], &enc, &mac, &dek), crate::fi::OK_SENTINEL);
        // 0-byte form: no KCV echoed → accepted (HW-ASSUME-PUTKEY-KCV-RESP).
        assert_eq!(verify_put_key_response(&[], &enc, &mac, &dek), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn put_key_response_rejects_torn_wrong_kvn_and_bad_length() {
        let (enc, mac, dek) = ([0xA0u8; 16], [0xB1u8; 16], [0xC2u8; 16]);
        let b10 = kcv_body_10(&enc, &mac, &dek);
        // Torn DEK: flip a DEK-KCV byte — the exact HW-ASSUME-PUTKEY-ATOMIC
        // scenario the check exists to catch.
        let mut torn = b10;
        torn[9] ^= 0xFF;
        assert_eq!(verify_put_key_response(&torn, &enc, &mac, &dek), crate::fi::FAIL_SENTINEL);
        // Wrong KVN in the 10-byte form.
        let mut bad_kvn = b10;
        bad_kvn[0] ^= 0x01;
        assert_eq!(verify_put_key_response(&bad_kvn, &enc, &mac, &dek), crate::fi::FAIL_SENTINEL);
        // Unexpected length → fail closed.
        assert_eq!(verify_put_key_response(&[0u8; 5], &enc, &mac, &dek), crate::fi::FAIL_SENTINEL);
        // Right length, all-zero KCVs (chip stored different keys) → reject.
        assert_eq!(verify_put_key_response(&[0u8; 9], &enc, &mac, &dek), crate::fi::FAIL_SENTINEL);
    }

    // ----- TransportAuthProof (authenticate-before-rotate) -----

    #[test]
    fn transport_auth_proof_pending_refuses_write() {
        let p = TransportAuthProof::pending(AUTH_CTX_SCP03_TRANSPORT);
        assert_ne!(p.authorize_write(AUTH_CTX_SCP03_TRANSPORT), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn transport_auth_proof_records_then_authorizes() {
        let mut p = TransportAuthProof::pending(AUTH_CTX_SCP03_TRANSPORT);
        p.record(AUTH_CTX_SCP03_TRANSPORT, || true);
        assert_eq!(p.authorize_write(AUTH_CTX_SCP03_TRANSPORT), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn transport_auth_proof_context_mismatch_refuses() {
        // A proof recorded for SCP03 cannot gate an ADMIN write, and vice versa.
        let mut p = TransportAuthProof::pending(AUTH_CTX_SCP03_TRANSPORT);
        p.record(AUTH_CTX_ADMIN_TRANSPORT, || true); // wrong ctx → no-op
        assert_ne!(p.authorize_write(AUTH_CTX_SCP03_TRANSPORT), crate::fi::OK_SENTINEL);
        let mut q = TransportAuthProof::pending(AUTH_CTX_SCP03_TRANSPORT);
        q.record(AUTH_CTX_SCP03_TRANSPORT, || true);
        assert_ne!(q.authorize_write(AUTH_CTX_ADMIN_TRANSPORT), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn transport_auth_proof_false_predicate_stays_failed() {
        // A wrong transport credential (verified == false) must NOT authorize.
        let mut p = TransportAuthProof::pending(AUTH_CTX_PBS_TRANSPORT);
        p.record(AUTH_CTX_PBS_TRANSPORT, || false);
        assert_ne!(p.authorize_write(AUTH_CTX_PBS_TRANSPORT), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn transport_auth_ctx_tags_are_distinct() {
        assert_ne!(AUTH_CTX_SCP03_TRANSPORT, AUTH_CTX_ADMIN_TRANSPORT);
        assert_ne!(AUTH_CTX_SCP03_TRANSPORT, AUTH_CTX_PBS_TRANSPORT);
        assert_ne!(AUTH_CTX_ADMIN_TRANSPORT, AUTH_CTX_PBS_TRANSPORT);
    }
}
