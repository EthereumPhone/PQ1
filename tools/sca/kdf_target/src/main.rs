//! Side-channel-leakage target ELF for `tools/sca/leakage_kdf.py` (first lascar
//! target). Two functions:
//!
//!  * `sca_aesgcm_wrap` — a **structural mirror** of the AES-GCM entropy-blob
//!    wrap in `secure/src/crypto.rs` → `pqsigner_domain::encrypt_entropy_blob`:
//!    derive a fixed AES-256 key + 12-byte nonce from a fixed `master_secret`,
//!    then `Aes256Gcm::encrypt_in_place_detached(nonce, &[], entropy)`. NOT a
//!    `#[path]` include — `pqsigner-domain` uses `{ workspace = true }` deps and
//!    can't be path-dep'd from a detached workspace — but it uses the *same*
//!    crates.io deps (`aes-gcm` 0.10 / `aes` 0.8 / `sha2` 0.10), so the AES's
//!    leakage behaviour matches. The exact key/nonce KDF is irrelevant to this
//!    test (what matters is: fixed AES-256 key + nonce, then AES-CTR/GHASH over
//!    attacker-varied `entropy`); the real `derive_wrap_key` / `derive_entropy_
//!    nonce` live in `domain/src/lib.rs`. **KEEP IN SYNC** if `encrypt_entropy_
//!    blob`'s shape changes (e.g. a different AEAD).
//!
//!  * `sca_leaky_sbox` — a deliberately-leaky **positive control**:
//!    `out[i] = AES_SBOX[in[i] ^ SECRET_KEY[i]]` for i in 0..16. Has both a
//!    secret-dependent table access (mem_address leakage) and a secret-dependent
//!    register value (the loaded S-box byte) — TVLA should light up on this, and
//!    a CPA over `SECRET_KEY[i]` with selection `HW(AES_SBOX[in[i] ^ guess])`
//!    recovers it. Confirms the lascar pipeline detects leakage when it's there;
//!    contrast with `sca_aesgcm_wrap`, where the bitsliced AES is constant-time.
//!
//! Build:  cargo build --release --target thumbv8m.main-none-eabi
//!         (or: make -C tools/sca build-kdf)
#![no_std]
#![no_main]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use cortex_m_rt::entry;
use panic_halt as _;
use sha2::{Digest, Sha256};

/// Fixed "master secret" — the secret a real wrap key/nonce is derived from.
/// Constant here so the AES-256 key + nonce are fixed across runs (the harness
/// varies only the entropy plaintext).
const SCA_MASTER_SECRET: [u8; 32] = *b"PQSIGNER-SCA-LEAKAGE-TARGET-MSEC";

const SCA_ENTROPY_LEN: usize = 32; // pqsigner_domain::ENTROPY_LEN (256-bit BIP-39 entropy)

#[inline(never)]
fn derive_wrap_key(master: &[u8; 32]) -> [u8; 32] {
    // Stand-in for pqsigner_domain::derive_wrap_key — exact KDF irrelevant here.
    let mut h = Sha256::new();
    h.update(b"sca/wrap-key/v1");
    h.update(master);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d);
    k
}

#[inline(never)]
fn derive_entropy_nonce(master: &[u8; 32]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"sca/entropy-nonce/v1");
    h.update(master);
    let d = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&d[..12]);
    n
}

/// Mirror of `encrypt_entropy_blob`'s wrap: AES-256-GCM-encrypt the 32-byte
/// `entropy` (read from `entropy_ptr`) under a fixed key+nonce; write
/// `ciphertext(32) ‖ tag(16)` to `out_ptr` (48 bytes). The harness varies the
/// entropy across runs and TVLAs the execution traces.
#[no_mangle]
pub extern "C" fn sca_aesgcm_wrap(entropy_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness passes valid, mapped 32-byte / 48-byte buffers.
    let entropy = unsafe { core::slice::from_raw_parts(entropy_ptr, SCA_ENTROPY_LEN) };
    let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, SCA_ENTROPY_LEN + 16) };

    let mut wrap = derive_wrap_key(&SCA_MASTER_SECRET);
    let nonce = derive_entropy_nonce(&SCA_MASTER_SECRET);

    out[..SCA_ENTROPY_LEN].copy_from_slice(entropy);
    let cipher = Aes256Gcm::new_from_slice(&wrap).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut out[..SCA_ENTROPY_LEN])
        .expect("entropy encryption");
    out[SCA_ENTROPY_LEN..].copy_from_slice(&tag);

    use zeroize::Zeroize;
    wrap.zeroize();
}

// --- raw AES-256 block: the "is the `aes` crate's AES constant-time?" target ----

/// A fixed AES-256 key — the secret a CPA over `Aes256::encrypt_block` would
/// target. Constant across runs (the harness varies only the plaintext block).
const SCA_AES_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

/// `out[0..16] = AES-256-ENC(SCA_AES_KEY, plaintext[0..16])` — a raw block
/// encryption with a fixed key, the `aes` crate's bitsliced "soft" backend on
/// thumbv8m. The harness varies the 16-byte plaintext; TVLA across the traces
/// should be **flat** (constant-time: no plaintext-dependent control flow or
/// memory addresses) — i.e. SubBytes/AddRoundKey don't leak the round keys via
/// the standard CPA channels in emulation. (This is the AES `pqsigner-domain`'s
/// entropy-blob wrap uses.)
#[no_mangle]
pub extern "C" fn sca_aes256_encrypt_block(plaintext_ptr: *const u8, out_ptr: *mut u8) {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit as _};
    // SAFETY: harness passes valid, mapped 16-byte buffers.
    let pt = unsafe { core::slice::from_raw_parts(plaintext_ptr, 16) };
    let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, 16) };
    let cipher = aes::Aes256::new(GenericArray::from_slice(&SCA_AES_KEY));
    let mut block = GenericArray::clone_from_slice(pt);
    cipher.encrypt_block(&mut block);
    out.copy_from_slice(&block);
}

// --- positive control: a deliberately-leaky byte-at-a-time S-box ----------------

/// AES forward S-box.
#[rustfmt::skip]
static SCA_AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// A fixed 16-byte "key" the toy mixes with its input — the CPA target.
const SCA_LEAKY_KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

/// `out[i] = SBOX[in[i] ^ KEY[i]]`, i in 0..16. Deliberately leaky (table access
/// + the loaded byte in a register both depend on the secret) — the positive
/// control for `leakage_kdf.py`.
#[no_mangle]
pub extern "C" fn sca_leaky_sbox(in_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness passes valid, mapped 16-byte buffers.
    let inp = unsafe { core::slice::from_raw_parts(in_ptr, 16) };
    let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, 16) };
    for i in 0..16 {
        let idx = inp[i] ^ SCA_LEAKY_KEY[i];
        out[i] = SCA_AES_SBOX[idx as usize];
    }
}

/// Returns the address of `SCA_AES_SBOX` (so the harness can build a precise
/// mem-address selection function for the CPA against the toy).
#[no_mangle]
pub extern "C" fn sca_leaky_sbox_table_addr() -> u32 {
    SCA_AES_SBOX.as_ptr() as u32
}

// ---------------------------------------------------------------------------
// Tier 2 leakage subjects — PQ crypto primitives whose constant-time behaviour
// we want to verify with lascar TVLA (fix-vs-random on the secret input).
// ---------------------------------------------------------------------------

/// `HMAC-SHA512("sphincs-c6-v1", seed)` — bit-equivalent to
/// `pqsigner_domain::derive_c10_master_from_bip39_seed`'s first step (account 0).
/// Input: 64-byte `bip39_seed` (the secret). Output: 64-byte HMAC tag.
/// TVLA varies the seed; the HMAC key is a fixed 13-byte domain tag.
#[no_mangle]
pub extern "C" fn sca_hmac_sha512_kdf(seed_ptr: *const u8, out_ptr: *mut u8) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    // SAFETY: harness maps 64 B at seed_ptr and 64 B at out_ptr.
    let seed: &[u8; 64] = unsafe { &*(seed_ptr as *const [u8; 64]) };
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(b"sphincs-c6-v1")
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(seed);
    let tag = mac.finalize().into_bytes();
    unsafe {
        for (i, &b) in tag.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
    }
}

// ---------------------------------------------------------------------------
// Secret-bearing derivation paths (audit follow-up to F-22).
//
// Each function mirrors a `pqsigner_domain` call that takes the 64-byte
// `bip39_seed` (the SECRET output of PBKDF2-HMAC-SHA512) and feeds it
// into one or two SHA-256 invocations to derive downstream key material.
// The `sha2::Sha256` backend on thumbv8m is the same bitsliced soft
// implementation that `sca_hmac_sha512_kdf` and `sca_aes256_encrypt_block`
// have already characterised as constant-time on `mem_address`. We
// expect these targets to come out flat — but unless the harness
// actually checks, "expected to be clean" is not a finding.
//
// Run via `make bip39-leak` (the same harness runs all the secret-bearing
// derivation TVLAs in series).
// ---------------------------------------------------------------------------

/// Mirror of `pqsigner_domain::kdf_sha256(domain, input, index)`:
/// `SHA-256(domain || input || [index])`. Used by the three derivation
/// targets below. Kept inline so the cost is the same as the production
/// call (the wrapper has a `#[must_use]` + thin call).
#[inline(always)]
fn sca_kdf_sha256(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

/// Mirror of `pqsigner_domain::slhdsa_seed_from_bip39`. Takes the 64-byte
/// `bip39_seed` (the secret) and runs two `kdf_sha256` calls to derive
/// the 48-byte SLH-DSA seed (32 B `sk_seed` ‖ 16 B `pk_seed`). TVLA
/// varies the seed; both SHA-256 invocations execute on the secret.
///
/// Input: 64 B `bip39_seed` at `seed_ptr`. Output: 48 B at `out_ptr`.
#[no_mangle]
pub extern "C" fn sca_slhdsa_seed_from_bip39(seed_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness maps 64 B at seed_ptr and 48 B at out_ptr.
    let seed: &[u8; 64] = unsafe { &*(seed_ptr as *const [u8; 64]) };
    let chunk0 = sca_kdf_sha256(b"sphincsc7-sk-seed", seed, 0);
    let chunk1 = sca_kdf_sha256(b"sphincsc7-pk-seed", seed, 0);
    unsafe {
        for (i, &b) in chunk0.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
        for (i, &b) in chunk1.iter().take(16).enumerate() {
            core::ptr::write_volatile(out_ptr.add(32 + i), b);
        }
    }
}

/// Mirror of `pqsigner_domain::bootstrap_seed_from_bip39`. Same shape
/// as the SLH-DSA derivation but with different domain tags so the
/// bootstrap signer's keypair is independent of the account-0 wallet
/// keypair. TVLA varies the seed.
///
/// Input: 64 B `bip39_seed` at `seed_ptr`. Output: 48 B at `out_ptr`.
#[no_mangle]
pub extern "C" fn sca_bootstrap_seed_from_bip39(seed_ptr: *const u8, out_ptr: *mut u8) {
    // SAFETY: harness maps 64 B at seed_ptr and 48 B at out_ptr.
    let seed: &[u8; 64] = unsafe { &*(seed_ptr as *const [u8; 64]) };
    let chunk0 = sca_kdf_sha256(b"pqwallet-c7-bootstrap-sk-seed", seed, 0);
    let chunk1 = sca_kdf_sha256(b"pqwallet-c7-bootstrap-pk-seed", seed, 0);
    unsafe {
        for (i, &b) in chunk0.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
        for (i, &b) in chunk1.iter().take(16).enumerate() {
            core::ptr::write_volatile(out_ptr.add(32 + i), b);
        }
    }
}

/// Mirror of `pqsigner_domain::slot_master_entropy_from_bip39` for the
/// `account_index == 0` path (the single-account formula that 99 %+ of
/// users hit). A single `kdf_sha256` call over the seed. TVLA varies
/// the seed.
///
/// Input: 64 B `bip39_seed` at `seed_ptr`. Output: 32 B at `out_ptr`.
#[no_mangle]
pub extern "C" fn sca_slot_master_entropy_from_bip39(
    seed_ptr: *const u8, out_ptr: *mut u8,
) {
    // SAFETY: harness maps 64 B at seed_ptr and 32 B at out_ptr.
    let seed: &[u8; 64] = unsafe { &*(seed_ptr as *const [u8; 64]) };
    let chunk = sca_kdf_sha256(b"pqwallet-slot-master", seed, 0);
    unsafe {
        for (i, &b) in chunk.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
    }
}

/// SPHINCS+C10 keygen — `SigningKey::keygen(sk_seed, pk_seed)`. Input: a
/// 32-byte `sk_seed` (the secret); `pk_seed` is fixed at compile time.
/// Output: the 16-byte `pk_root` written to `out_ptr`. TVLA varies sk_seed.
#[no_mangle]
pub extern "C" fn sca_c10_keygen(sk_seed_ptr: *const u8, out_ptr: *mut u8) {
    const FIXED_PK_SEED: [u8; sphincs_c10::params::N] = [0x77u8; sphincs_c10::params::N];
    // SAFETY: harness maps 32 B at sk_seed_ptr and 16 B at out_ptr.
    let sk_seed_arr: [u8; 32] = unsafe { *(sk_seed_ptr as *const [u8; 32]) };
    let sk = sphincs_c10::SigningKey::keygen(sk_seed_arr, FIXED_PK_SEED);
    let pk_root: &[u8; sphincs_c10::params::N] = sk.pk_root();
    unsafe {
        for (i, &b) in pk_root.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
    }
}

/// SPHINCS+C10 sign — `SigningKey::sign(msg, None)`. Input: a 32-byte
/// `msg_hash` (the "plaintext"); the SigningKey is built from a fixed
/// sk_seed/pk_seed/pk_root (the latter pre-computed in build.rs). Output:
/// the 4008-byte signature written to `out_ptr`. TVLA varies msg_hash; the
/// SK is fixed. Detects message-dependent leakage inside the FORS / WOTS+
/// / hypertree subroutines.
///
/// Using `from_parts` (with build.rs-baked pk_root) instead of `keygen` is
/// load-bearing for the leakage analysis: without it, the first ~2.5 B
/// emulated instructions are the (msg-independent) keygen, and the TVLA's
/// max_samples cap is exhausted before reaching the actual sign phase
/// (giving max|t| = 0 as a degenerate "no msg-dependent variation seen"
/// result because we never sampled where msg-dependent addresses live).
#[no_mangle]
pub extern "C" fn sca_c10_sign(msg_hash_ptr: *const u8, out_ptr: *mut u8) {
    const FIXED_SK_SEED: [u8; 32] = [0x42u8; 32];
    const FIXED_PK_SEED: [u8; sphincs_c10::params::N] = [0x77u8; sphincs_c10::params::N];
    const FIXED_PK_ROOT: [u8; sphincs_c10::params::N] =
        *include_bytes!(concat!(env!("OUT_DIR"), "/pk_root.bin"));
    let sk = sphincs_c10::SigningKey::from_parts(FIXED_SK_SEED, FIXED_PK_SEED, FIXED_PK_ROOT);
    // SAFETY: harness maps 32 B at msg_hash_ptr and SIGNATURE_LEN at out_ptr.
    let msg: &[u8; 32] = unsafe { &*(msg_hash_ptr as *const [u8; 32]) };
    let sig = sk.sign(msg, None);
    unsafe {
        for (i, &b) in sig.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
    }
}

/// SPHINCS+C10 sign WITH F-16 shuffle + F-13 hedged R (post-F-13/F-16
/// production re-test target for F-9). Input layout is 80 bytes:
/// `[msg(32) || opt_rand(16) || shuffle_seed(32)]`.
///
///   - `msg`: the message hash (varied between TVLA groups).
///   - `opt_rand`: the per-call randomiser mixed into `grind_r`'s
///     R-derivation. Closes the F-9 transparent leak channel by
///     making the grind iteration count depend on opt_rand instead of
///     just msg.
///   - `shuffle_seed`: per-call WOTS/FORS shuffle. F-16's defense.
///
/// In the TVLA harness, both `opt_rand` and `shuffle_seed` are
/// INDEPENDENTLY random per trace (regardless of which msg group the
/// trace is in), so the within-group means average over many
/// randomisation positions and the only thing the test detects is
/// residual msg-dependent leakage AFTER F-13 hedging and F-16
/// shuffling.
#[no_mangle]
pub extern "C" fn sca_c10_sign_shuffled(in_ptr: *const u8, out_ptr: *mut u8) {
    const FIXED_SK_SEED: [u8; 32] = [0x42u8; 32];
    const FIXED_PK_SEED: [u8; sphincs_c10::params::N] = [0x77u8; sphincs_c10::params::N];
    const FIXED_PK_ROOT: [u8; sphincs_c10::params::N] =
        *include_bytes!(concat!(env!("OUT_DIR"), "/pk_root.bin"));
    // SAFETY: harness maps 80 B at in_ptr (msg ‖ opt_rand ‖ shuffle_seed)
    // and SIGNATURE_LEN B at out_ptr.
    let msg: &[u8; 32] = unsafe { &*(in_ptr as *const [u8; 32]) };
    let opt_rand: [u8; sphincs_c10::params::N] =
        unsafe { *(in_ptr.add(32) as *const [u8; sphincs_c10::params::N]) };
    let shuffle_seed: [u8; 32] = unsafe { *(in_ptr.add(48) as *const [u8; 32]) };
    let sk = sphincs_c10::SigningKey::from_parts(FIXED_SK_SEED, FIXED_PK_SEED, FIXED_PK_ROOT);
    let shuffle = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed);
    let sig = sk.sign_with_shuffle(msg, Some(&opt_rand), &shuffle, |_| {});
    unsafe {
        for (i, &b) in sig.iter().enumerate() {
            core::ptr::write_volatile(out_ptr.add(i), b);
        }
    }
}

#[used]
static _KEEP_WRAP: extern "C" fn(*const u8, *mut u8) = sca_aesgcm_wrap;
#[used]
static _KEEP_AES_BLOCK: extern "C" fn(*const u8, *mut u8) = sca_aes256_encrypt_block;
#[used]
static _KEEP_LEAKY: extern "C" fn(*const u8, *mut u8) = sca_leaky_sbox;
#[used]
static _KEEP_LEAKY_ADDR: extern "C" fn() -> u32 = sca_leaky_sbox_table_addr;
#[used]
static _KEEP_HMAC: extern "C" fn(*const u8, *mut u8) = sca_hmac_sha512_kdf;
#[used]
static _KEEP_C10_KG: extern "C" fn(*const u8, *mut u8) = sca_c10_keygen;
#[used]
static _KEEP_C10_SIGN: extern "C" fn(*const u8, *mut u8) = sca_c10_sign;
#[used]
static _KEEP_C10_SIGN_SHUF: extern "C" fn(*const u8, *mut u8) = sca_c10_sign_shuffled;
#[used]
static _KEEP_BIP39_WORD_INDICES: extern "C" fn(*const u8, *mut u8) = sca_bip39_word_indices;
#[used]
static _KEEP_BIP39_WORDLIST_LOOKUP: extern "C" fn(*const u8, *mut u8) =
    sca_bip39_wordlist_lookup;
#[used]
static _KEEP_BIP39_WORDLIST_LOOKUP_CT: extern "C" fn(*const u8, *mut u8) =
    sca_bip39_wordlist_lookup_ct;
#[used]
static _KEEP_SLHDSA_SEED: extern "C" fn(*const u8, *mut u8) =
    sca_slhdsa_seed_from_bip39;
#[used]
static _KEEP_BOOTSTRAP_SEED: extern "C" fn(*const u8, *mut u8) =
    sca_bootstrap_seed_from_bip39;
#[used]
static _KEEP_SLOT_MASTER: extern "C" fn(*const u8, *mut u8) =
    sca_slot_master_entropy_from_bip39;

// BIP-39 wordlist included verbatim from the production crate. The bip39
// crate uses `hmac = { workspace = true }` which is unreachable from this
// detached workspace, but `wordlist.rs` is dep-free — a single
// `pub static WORDLIST: [&str; 2048]`. `#[path]`-include it as a module
// so any drift in the production list breaks this build.
#[path = "../../../../bip39/src/wordlist.rs"]
mod wordlist;

/// First half of `Mnemonic::from_entropy`: SHA-256(entropy) → checksum
/// bits, then split (entropy ‖ checksum) into 24 × 11-bit word indices.
/// Writes 48 bytes to `out_ptr` (24 × u16 LE; each u16 ∈ [0, 2047]).
///
/// **The interesting samples here**: the loop that extracts 11-bit
/// indices reads from `entropy_with_check[byte_idx]` where `byte_idx`
/// is loop-counter-derived (NOT entropy-derived), so the addresses
/// shouldn't depend on the secret. TVLA fixed-vs-random entropy should
/// be flat — modulo the per-byte values flowing into the AES-NI-style
/// VALUE channel which `mem_address` doesn't see.
#[no_mangle]
pub extern "C" fn sca_bip39_word_indices(entropy_ptr: *const u8, out_ptr: *mut u8) {
    use sha2::Digest as _;
    // SAFETY: harness passes 32 B entropy + 48 B output buffer.
    let entropy: &[u8; 32] = unsafe { &*(entropy_ptr as *const [u8; 32]) };

    // checksum = top 8 bits of SHA-256(entropy) for a 256-bit entropy.
    let mut h = sha2::Sha256::new();
    h.update(entropy);
    let digest = h.finalize();
    let checksum = digest[0];

    // 33-byte buffer = entropy ‖ checksum, 264 bits total = 24 × 11.
    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(entropy);
    buf[32] = checksum;

    // Extract 24 × 11-bit indices, BE bit order per BIP-39.
    for i in 0..24 {
        let bit = i * 11;
        let byte = bit / 8;
        let off = bit % 8;
        // u32 to fit the 24-bit shift window.
        let hi = buf[byte] as u32;
        let mid = buf[byte + 1] as u32;
        let lo = if byte + 2 < buf.len() { buf[byte + 2] as u32 } else { 0 };
        let win = (hi << 16) | (mid << 8) | lo;
        let shifted = win >> (24 - off - 11);
        let idx = (shifted & 0x07FF) as u16;
        // SAFETY: i in 0..24 → offset 2i+1 < 48.
        unsafe {
            core::ptr::write_volatile(out_ptr.add(i * 2), idx as u8);
            core::ptr::write_volatile(out_ptr.add(i * 2 + 1), (idx >> 8) as u8);
        }
    }
}

// F-22 constant-time wordlist scan — mirrors the post-fix
// `bip39/src/lib.rs::ct_load_word`. Used by `sca_bip39_wordlist_lookup_ct`
// below to validate that the production fix actually closes the leak.

const MAX_WORD_BYTES: usize = 8;

const fn flatten_wordlist() -> ([[u8; MAX_WORD_BYTES]; 2048], [u8; 2048]) {
    let mut flat = [[0u8; MAX_WORD_BYTES]; 2048];
    let mut lens = [0u8; 2048];
    let mut i = 0;
    while i < 2048 {
        let w = wordlist::WORDLIST[i].as_bytes();
        let mut j = 0;
        while j < w.len() {
            flat[i][j] = w[j];
            j += 1;
        }
        lens[i] = w.len() as u8;
        i += 1;
    }
    (flat, lens)
}

const FLAT_AND_LENS: ([[u8; MAX_WORD_BYTES]; 2048], [u8; 2048]) = flatten_wordlist();
static WORDLIST_FLAT: [[u8; MAX_WORD_BYTES]; 2048] = FLAT_AND_LENS.0;
static WORDLIST_LENS: [u8; 2048] = FLAT_AND_LENS.1;

#[inline(always)]
fn ct_eq_u16(a: u16, b: u16) -> u8 {
    let x: u32 = a as u32 ^ b as u32;
    let nz: u32 = (x | x.wrapping_neg()) >> 31;
    (nz as u8).wrapping_sub(1)
}

#[inline(never)]
fn ct_load_word(target_idx: u16) -> ([u8; MAX_WORD_BYTES], u8) {
    use core::hint::black_box;
    let mut bytes = [0u8; MAX_WORD_BYTES];
    let mut len: u8 = 0;
    let mut entry_idx: u16 = 0;
    while entry_idx < 2048 {
        let entry_idx_obf = black_box(entry_idx);
        let entry = &WORDLIST_FLAT[entry_idx_obf as usize];
        let entry_len = WORDLIST_LENS[entry_idx_obf as usize];
        let mask = black_box(ct_eq_u16(entry_idx_obf, target_idx));
        let mut b = 0;
        while b < MAX_WORD_BYTES {
            bytes[b] = black_box(bytes[b] | (entry[b] & mask));
            b += 1;
        }
        len = black_box(len | (entry_len & mask));
        entry_idx += 1;
    }
    (bytes, len)
}

/// **F-22 POST-FIX VALIDATOR** — same entropy → 24 word indices, but
/// loads each word via `ct_load_word` (the constant-time scan that
/// `bip39/src/lib.rs` now uses internally in `Mnemonic::to_seed`).
/// Per-iteration access pattern is fixed: read `WORDLIST_FLAT[entry_idx]`
/// sequentially over 2048 entries with a constant 8-byte stride and
/// mask-OR into a stack-resident accumulator. No load address depends
/// on the secret `target_idx`.
///
/// Expected: `max|t| ≤ 4.5` on the same harness that produces
/// `max|t| ≈ 28` for the leaky `sca_bip39_wordlist_lookup`.
#[no_mangle]
pub extern "C" fn sca_bip39_wordlist_lookup_ct(entropy_ptr: *const u8, out_ptr: *mut u8) {
    use sha2::Digest as _;
    // SAFETY: harness passes 32 B entropy + 48 B output buffer.
    let entropy: &[u8; 32] = unsafe { &*(entropy_ptr as *const [u8; 32]) };

    let mut h = sha2::Sha256::new();
    h.update(entropy);
    let digest = h.finalize();
    let checksum = digest[0];

    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(entropy);
    buf[32] = checksum;

    for i in 0..24 {
        let bit = i * 11;
        let byte = bit / 8;
        let off = bit % 8;
        let hi = buf[byte] as u32;
        let mid = buf[byte + 1] as u32;
        let lo = if byte + 2 < buf.len() { buf[byte + 2] as u32 } else { 0 };
        let win = (hi << 16) | (mid << 8) | lo;
        let shifted = win >> (24 - off - 11);
        let idx = (shifted & 0x07FF) as u16;

        let (word_bytes, word_len) = ct_load_word(idx);

        // Same output layout as `sca_bip39_wordlist_lookup`: write len + first byte.
        // SAFETY: i in 0..24 → 2i+1 < 48.
        unsafe {
            core::ptr::write_volatile(out_ptr.add(i * 2), word_len);
            core::ptr::write_volatile(out_ptr.add(i * 2 + 1), word_bytes[0]);
        }
    }
}

/// The actual leak suspect: given 24 entropy-derived word indices, look
/// up `WORDLIST[index]` for each. The load address is
/// `WORDLIST_BASE + index * STRIDE` (STRIDE = sizeof(&str) = 8 on a
/// 32-bit target), so the low bits of every load address ENCODE the
/// secret index — exactly the T-table-style address-bus leak that
/// rainbow's `mem_address` channel detects.
///
/// Input: 32 B raw entropy. We re-derive the indices internally rather
/// than taking them as input, so the TVLA can vary the entropy and see
/// the FULL secret-handling chain — index derivation + wordlist
/// lookup — rolled into one symbol. Output: a packed buffer of the
/// 24 word lengths + first-byte-of-each-word (48 B); the body of each
/// word isn't copied to keep the trace short and the leak focused on
/// the table-lookup samples.
#[no_mangle]
pub extern "C" fn sca_bip39_wordlist_lookup(entropy_ptr: *const u8, out_ptr: *mut u8) {
    use sha2::Digest as _;
    // SAFETY: harness passes 32 B entropy + 48 B output buffer.
    let entropy: &[u8; 32] = unsafe { &*(entropy_ptr as *const [u8; 32]) };

    let mut h = sha2::Sha256::new();
    h.update(entropy);
    let digest = h.finalize();
    let checksum = digest[0];

    let mut buf = [0u8; 33];
    buf[..32].copy_from_slice(entropy);
    buf[32] = checksum;

    for i in 0..24 {
        let bit = i * 11;
        let byte = bit / 8;
        let off = bit % 8;
        let hi = buf[byte] as u32;
        let mid = buf[byte + 1] as u32;
        let lo = if byte + 2 < buf.len() { buf[byte + 2] as u32 } else { 0 };
        let win = (hi << 16) | (mid << 8) | lo;
        let shifted = win >> (24 - off - 11);
        let idx = (shifted & 0x07FF) as usize;

        // THE LEAK SUSPECT. `WORDLIST[idx]` loads at
        // `&WORDLIST[0] + idx * size_of::<&str>()`. The address depends
        // on `idx` which depends on the entropy.
        let w: &'static str = wordlist::WORDLIST[idx];
        let wb = w.as_bytes();

        // Write the word length + first byte. Avoids copying the full
        // word body which would add more index-dependent reads from
        // the (also-flash-resident) word body and dilute the lookup
        // signal in noise.
        // SAFETY: i in 0..24 → 2i+1 < 48.
        unsafe {
            core::ptr::write_volatile(out_ptr.add(i * 2), wb.len() as u8);
            core::ptr::write_volatile(out_ptr.add(i * 2 + 1), wb[0]);
        }
    }
}

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_WRAP);
    core::hint::black_box(&_KEEP_AES_BLOCK);
    core::hint::black_box(&_KEEP_LEAKY);
    core::hint::black_box(&_KEEP_LEAKY_ADDR);
    core::hint::black_box(&_KEEP_HMAC);
    core::hint::black_box(&_KEEP_C10_KG);
    core::hint::black_box(&_KEEP_C10_SIGN);
    core::hint::black_box(&_KEEP_C10_SIGN_SHUF);
    core::hint::black_box(&_KEEP_BIP39_WORD_INDICES);
    core::hint::black_box(&_KEEP_BIP39_WORDLIST_LOOKUP);
    core::hint::black_box(&_KEEP_BIP39_WORDLIST_LOOKUP_CT);
    core::hint::black_box(&_KEEP_SLHDSA_SEED);
    core::hint::black_box(&_KEEP_BOOTSTRAP_SEED);
    core::hint::black_box(&_KEEP_SLOT_MASTER);
    loop {
        cortex_m::asm::nop();
    }
}
