//! Host-side positive + negative test suite for the `secure-hw-crypto`
//! slice.
//!
//! Slice files in scope:
//!   - `secure/src/hw/mmio.rs`        (typed MMIO wrapper)
//!   - `secure/src/hw/hash.rs`        (STM32U585 HASH peripheral)
//!   - `secure/src/hw/saes.rs`        (Secure-AES coprocessor)
//!   - `secure/src/hw/saes_cmac.rs`   (CMAC-AES-256 over SAES-DHUK)
//!   - `secure/src/hw/secret_keys.rs` (domain-separated subkey API)
//!   - `secure/src/hw/otp.rs`         (rollback counter + device master)
//!   - `secure/src/hw/bhk.rs`         (Tier-2 BHK lifecycle)
//!
//! Because every file except `mmio.rs` imports `cortex_m` or peers that
//! drag it in, the slice cannot be link-checked on host. We therefore
//! pin the slice through two host-runnable mechanisms:
//!
//!   1. **`include_str!` source-text pins.** Constants, addresses,
//!      domain tags, feature gates, FI guards and zeroization sites
//!      are asserted against the file text. A future refactor that
//!      breaks one of these invariants fails this test before it
//!      reaches silicon. The text-pin is intentional — the cost of a
//!      silently-renamed KDF tag (every paired SE on every device
//!      becomes useless) is many orders of magnitude higher than the
//!      cost of a CI false-positive when someone reformats whitespace.
//!
//!   2. **Reference algorithm tests.** We re-implement the slice's
//!      HKDF-Expand here, validate it against the RFC 5869 SHA-256
//!      vectors, and assert that the firmware copy in
//!      `secret_keys.rs` shares the same construction. We also test
//!      the OTP rollback bit-walk planning algorithm.
//!
//! Negative tests are framed by the assumption they attack: each
//! `negative_*` test's panic message names the attack and cites the
//! CLAUDE.md invariant or in-file safety comment whose silent removal
//! it would otherwise enable. Per the test-writing brief, the negative
//! suite is the most important deliverable here.

#![cfg(test)]

use hmac::Mac;
use sha2::Sha256;

const HASH_SRC: &str = include_str!("../hw/hash.rs");
const SAES_SRC: &str = include_str!("../hw/saes.rs");
const SAES_CMAC_SRC: &str = include_str!("../hw/saes_cmac.rs");
const SECRET_KEYS_SRC: &str = include_str!("../hw/secret_keys.rs");
const OTP_SRC: &str = include_str!("../hw/otp.rs");
/// The pure Virgin/Partial/Complete rule `hw/otp.rs` consumes. Unlike the rest
/// of this slice it is MMIO-free, so its behaviour is tested for real in its
/// own module — these text pins only hold the *shape* of the D4 rule in place.
const OTP_STATE_SRC: &str = include_str!("../otp_state.rs");
const BHK_SRC: &str = include_str!("../hw/bhk.rs");
const MMIO_SRC: &str = include_str!("../hw/mmio.rs");

// ─────────────────────────────────────────────────────────────────────
// 1. Positive — register addresses + constants
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_hash_base_secure_alias_0x520c_0400() {
    assert!(
        HASH_SRC.contains("const HASH_BASE: u32 = 0x520C_0400;"),
        "HASH peripheral must use secure alias 0x520C_0400 per STM32U5 RM (TZSC blocks NS-alias access)"
    );
}

#[test]
fn positive_saes_base_secure_alias_0x520c_0c00() {
    assert!(
        SAES_SRC.contains("const SAES_BASE: u32 = 0x520C_0C00;"),
        "SAES peripheral must use secure alias 0x520C_0C00"
    );
}

/// `load_and_lock` must PROVE the active BHK is the intended one.
///
/// Measured on silicon 2026-09-21 (issue #712, `tools/bhklock-reset-scope.sh`):
/// `TAMP_SECCFGR.BHKLOCK` is sticky, survives a system reset, blocks software
/// reads AND writes of `BKP0..7`, and software cannot clear it. So writing the
/// key into already-locked registers is a silent no-op. The old code did
/// exactly that and returned `Ok`, which is how a first-boot retry could
/// rotate SE050 credentials against the PREVIOUS key while flash held the new
/// one — stranding the SE050 with no mass erase involved.
///
/// These pins live here, not in `bhk.rs`'s own test module: that module is
/// inside a target-only feature gate and never runs host-side (#708).
#[test]
fn positive_bhk_load_and_lock_verifies_the_active_key() {
    // The reference ciphertext must come from the INTENDED key via the
    // software key path. A `Bhk` round trip is self-consistent under any key,
    // including a stale one, so it cannot substitute for this.
    assert!(
        BHK_SRC.contains("KeySel::Software, Some(&bhk), &ACTIVE_KEY_KAT_BLOCK"),
        "the expected value must be computed from the key we intend to install"
    );
    assert!(
        BHK_SRC.contains("saes::encrypt_ecb_block(KeySel::Bhk, None, &ACTIVE_KEY_KAT_BLOCK)"),
        "the active value must come from the hardware BHK key path"
    );
    // ...and the two must actually be compared, in constant time.
    assert!(
        BHK_SRC.contains("ConstantTimeEq::ct_eq(&expected[..], &actual[..])"),
        "expected and actual must be compared"
    );
    // A mismatch must be an error, never a log-and-continue.
    assert!(
        BHK_SRC.contains("BhkError::ActiveKeyMismatch") && BHK_SRC.contains("BhkError::AlreadyLocked"),
        "a mismatched active key must surface as an error"
    );
    // The already-locked case must be detected explicitly, because that is the
    // condition under which the hardware ignores the write.
    assert!(
        BHK_SRC.contains("let already_locked = read_volatile(TAMP_SECCFGR) & TAMP_BHKLOCK != 0;"),
        "load_and_lock must know whether the registers were already locked"
    );
    // But being locked with the RIGHT key is the ordinary warm-reset case and
    // must stay non-fatal — failing there would break a working device.
    assert!(
        BHK_SRC.contains("if !already_locked {"),
        "the install must be skipped, not failed, when already locked"
    );
}

#[test]
fn positive_saes_rcc_uses_secure_alias_for_shsi() {
    // RM0456: "The SHSI configuration and status bits are secured when the SAES
    // is configured as secure." `sau.rs` marks SAES SECURE (GTZC1_TZSC_SECCFGR3
    // bit 15), so SHSION/SHSIRDY (RCC_CR bits 14/15) are secure-only. Driven
    // through the NS alias (0x4602_0C00) the enable is silently dropped,
    // SHSIRDY never rises, and `saes::init()` fails `ShsiTimeout` — which is
    // exactly what pq1 silicon did on 2026-09-21 (bare board AND sealed EVT),
    // taking the whole DHUK / Tier-1 KDF path with it.
    assert!(
        SAES_SRC.contains("const RCC: u32 = 0x5602_0C00;"),
        "SAES must reach RCC through the SECURE alias or SHSI never starts"
    );
    assert!(
        !SAES_SRC.contains("const RCC: u32 = 0x4602_0C00;"),
        "the NS RCC alias silently drops the SHSI enable"
    );
}

#[test]
fn positive_hash_register_offsets() {
    assert!(HASH_SRC.contains("cr: Reg32::new(HASH_BASE + 0x00)"), "HASH_CR at offset 0x00");
    assert!(HASH_SRC.contains("din: Reg32::new(HASH_BASE + 0x04)"), "HASH_DIN at offset 0x04");
    assert!(HASH_SRC.contains("str_: Reg32::new(HASH_BASE + 0x08)"), "HASH_STR at offset 0x08");
    assert!(HASH_SRC.contains("sr: Reg32::new(HASH_BASE + 0x24)"), "HASH_SR at offset 0x24");
    assert!(
        HASH_SRC.contains("hr0: RoReg32::new(HASH_BASE + 0x310)"),
        "HR0 at offset 0x310 (STM32U5 HASH v4 digest bank)"
    );
}

#[test]
fn positive_hash_sha256_algo_bits() {
    assert!(
        HASH_SRC.contains("const CR_ALGO_SHA256: u32 = (1 << 17) | (1 << 18);"),
        "STM32U5 ALGO field is 2 bits at 17-18, SHA-256 = 0b11"
    );
}

#[test]
fn positive_saes_keyr_offsets_split_around_ivr() {
    // KEYR0..3 = 0x10..0x1C contiguous; IVR0..3 = 0x20..0x2C; then
    // KEYR4..7 = 0x30..0x3C. Pointer-arithmetic across the bank would
    // hit IVR, not high KEYRs.
    assert!(SAES_SRC.contains("keyr0: Reg32::new(SAES_BASE + 0x10)"));
    assert!(SAES_SRC.contains("keyr3: Reg32::new(SAES_BASE + 0x1C)"));
    assert!(SAES_SRC.contains("keyr4: Reg32::new(SAES_BASE + 0x30)"));
    assert!(SAES_SRC.contains("keyr7: Reg32::new(SAES_BASE + 0x3C)"));
}

#[test]
fn positive_saes_keysel_bit_pattern_matches_hal() {
    // Per STM32 HAL CRYP_KEYSEL_* table reproduced in saes.rs:
    //   Software=0b000  Dhuk=0b001  Bhk=0b010  DhukXorBhk=0b100
    assert!(SAES_SRC.contains("Software = 0b000"));
    assert!(SAES_SRC.contains("Dhuk = 0b001"));
    assert!(SAES_SRC.contains("Bhk = 0b010"));
    assert!(SAES_SRC.contains("DhukXorBhk = 0b100"));
}

#[test]
fn positive_otp_layout_constants() {
    assert!(OTP_SRC.contains("pub const OTP_BASE: u32 = 0x0BFA_0000;"));
    assert!(OTP_SRC.contains("pub const ROLLBACK_WORDS: u32 = 32;"));
    assert!(OTP_SRC.contains("pub const MAX_FW_VERSION: u32 = ROLLBACK_WORDS * 32;"));
    assert!(OTP_SRC.contains("pub const MASTER_KEY_OFFSET: u32 = ROLLBACK_WORDS * 4;"));
    assert!(OTP_SRC.contains("pub const MASTER_KEY_SIZE: usize = 32;"));
}

#[test]
fn positive_bhk_page_addresses() {
    // The address is registry-derived (Foundation A slice FA-1.1); pin both
    // the new source form AND the value it must keep computing.
    assert!(BHK_SRC.contains(
        "pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, BHK_PAGE_NUM as u8);"
    ));
    assert_eq!(
        pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, 126),
        0x0C0F_C000
    );
    assert!(BHK_SRC.contains("pub(crate) const BHK_PAGE_NUM: u32 = 126;"));
    assert!(BHK_SRC.contains("const TAMP_BHKLOCK: u32 = 1 << 30;"));
}

// ─────────────────────────────────────────────────────────────────────
// 2. Positive — KDF labels, function signatures
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_secret_keys_labels_present() {
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/optiga-pbs-v1""#));
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-enc-v1""#));
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-mac-v1""#));
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-dek-v1""#));
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-admin-pin-v1""#));
}

#[test]
fn positive_secret_keys_output_sizes() {
    // OPTIGA PBS: 64 bytes per SRM; SCP03 + admin: 16 bytes per spec. The SCP03
    // static keys now return `Zeroizing<[u8; 16]>` (finding F12 — auto-wipe on
    // every caller return path); the inner `[u8; 16]` still pins the size.
    assert!(SECRET_KEYS_SRC.contains("pub fn optiga_pairing_secret() -> Result<[u8; 64], OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn se050_scp03_enc_key() -> Result<Zeroizing<[u8; 16]>, OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn se050_scp03_mac_key() -> Result<Zeroizing<[u8; 16]>, OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn se050_scp03_dek_key() -> Result<Zeroizing<[u8; 16]>, OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn se050_admin_pin() -> Result<[u8; 16], OtpError>"));
}

// ─────────────────────────────────────────────────────────────────────
// 3. Positive — HKDF-Expand reference (RFC 5869) + algorithm shape
// ─────────────────────────────────────────────────────────────────────

type HmacSha256 = hmac::Hmac<Sha256>;

/// Byte-for-byte port of `secret_keys::hkdf_expand`. Acts as the
/// reference oracle for the firmware copy: any future divergence
/// between this function and the source-text-pinned shape below would
/// produce different SE pairing secrets on every device.
fn hkdf_expand_ref(prk: &[u8; 32], info: &[u8], output: &mut [u8]) {
    let n = output.len().div_ceil(32);
    assert!(n <= 255, "HKDF-Expand output must be ≤ 255 × HashLen");

    let mut prev_t = [0u8; 32];
    let mut have_prev = false;

    for i in 1..=n as u8 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk).unwrap();
        if have_prev {
            mac.update(&prev_t);
        }
        mac.update(info);
        mac.update(&[i]);
        let t_i = mac.finalize().into_bytes();
        prev_t.copy_from_slice(&t_i);
        have_prev = true;

        let start = (i as usize - 1) * 32;
        let end = core::cmp::min(start + 32, output.len());
        output[start..end].copy_from_slice(&t_i[..end - start]);
    }
}

#[test]
fn positive_hkdf_expand_matches_rfc5869_test_case_1() {
    // RFC 5869 Test Case 1 (Basic test case with SHA-256).
    //   PRK = HMAC-SHA256(salt=0x000102...0c, IKM=0x0b*22)  — published.
    //   info = 0xf0f1f2f3f4f5f6f7f8f9
    //   L = 42
    //   OKM = 3cb25f25 faacd57a 90434f64 d0362f2a 2d2d0a90 cf1a5a4c
    //         5db02d56 ecc4c5bf 34007208 d5b88718 5865
    let prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected_okm: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let mut okm = [0u8; 42];
    hkdf_expand_ref(&prk, &info, &mut okm);
    assert_eq!(okm, expected_okm, "RFC 5869 Test Case 1 OKM mismatch");
}

#[test]
fn positive_hkdf_expand_single_block_equals_t1() {
    // L ≤ 32 must equal a prefix of HMAC(prk, info || 0x01).
    let prk = [0x42u8; 32];
    let info = b"pqsigner/optiga-pbs-v1";
    let mut full = [0u8; 32];
    hkdf_expand_ref(&prk, info, &mut full);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac.update(info);
    mac.update(&[1u8]);
    let t1 = mac.finalize().into_bytes();
    assert_eq!(&full[..], &t1[..]);
}

#[test]
fn positive_hkdf_expand_64_bytes_equals_t1_concat_t2() {
    // The 64-byte OPTIGA PBS uses two blocks: T(1) || T(2). Pin it.
    let prk = [0x55u8; 32];
    let info = b"pqsigner/optiga-pbs-v1";
    let mut full = [0u8; 64];
    hkdf_expand_ref(&prk, info, &mut full);

    let mut mac1 = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac1.update(info);
    mac1.update(&[1u8]);
    let t1 = mac1.finalize().into_bytes();
    let mut mac2 = <HmacSha256 as Mac>::new_from_slice(&prk).unwrap();
    mac2.update(&t1);
    mac2.update(info);
    mac2.update(&[2u8]);
    let t2 = mac2.finalize().into_bytes();

    assert_eq!(&full[..32], &t1[..]);
    assert_eq!(&full[32..], &t2[..]);
}

#[test]
fn positive_hkdf_distinct_labels_diverge() {
    let prk = [0x11u8; 32];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    hkdf_expand_ref(&prk, b"pqsigner/se050-scp03-enc-v1", &mut a);
    hkdf_expand_ref(&prk, b"pqsigner/se050-scp03-mac-v1", &mut b);
    assert_ne!(a, b, "distinct domain labels must yield independent keys");
}

// ─────────────────────────────────────────────────────────────────────
// work-todo #36: transport keysets + salted-final PBS.
//
// The transport keys HKDF the REAL OTP master with `pqsigner/transport/*`
// labels (RDP-invariant, public-by-assumption); the final OPTIGA PBS mixes
// a persisted TRNG salt into a `-v2` label. These KATs use the same
// reference HKDF the real derivation runs under `otp-hardcoded-master-key`.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn wt36_transport_labels_domain_separate_from_final_and_each_other() {
    let prk = [0x33u8; 32];
    // A transport key must be independent of its final counterpart even
    // though they share a suffix — the "transport/" prefix separates them.
    let mut t = [0u8; 16];
    let mut f = [0u8; 16];
    hkdf_expand_ref(&prk, b"pqsigner/transport/se050-scp03-enc-v1", &mut t);
    hkdf_expand_ref(&prk, b"pqsigner/se050-scp03-enc-v1", &mut f);
    assert_ne!(t, f, "transport SCP03-enc must differ from the final SCP03-enc");

    // All five transport labels pairwise-distinct.
    let labels: [&[u8]; 5] = [
        b"pqsigner/transport/se050-scp03-enc-v1",
        b"pqsigner/transport/se050-scp03-mac-v1",
        b"pqsigner/transport/se050-scp03-dek-v1",
        b"pqsigner/transport/se050-admin-pin-v1",
        b"pqsigner/transport/optiga-pbs-v1",
    ];
    for i in 0..labels.len() {
        for j in (i + 1)..labels.len() {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            hkdf_expand_ref(&prk, labels[i], &mut a);
            hkdf_expand_ref(&prk, labels[j], &mut b);
            assert_ne!(a, b, "transport labels {i},{j} collided");
        }
    }
}

#[test]
fn wt36_salted_pbs_differs_from_unsalted_and_varies_with_salt() {
    let prk = [0x77u8; 32];
    let mut unsalted = [0u8; 64];
    hkdf_expand_ref(&prk, b"pqsigner/optiga-pbs-v1", &mut unsalted);

    // info = "pqsigner/optiga-pbs-v2" || salt (matches optiga_pairing_secret_salted).
    let build = |salt: &[u8; 32]| {
        let mut info = [0u8; 22 + 32];
        info[..22].copy_from_slice(b"pqsigner/optiga-pbs-v2");
        info[22..].copy_from_slice(salt);
        let mut out = [0u8; 64];
        hkdf_expand_ref(&prk, &info, &mut out);
        out
    };
    let s1 = build(&[0xAAu8; 32]);
    let s2 = build(&[0xBBu8; 32]);
    assert_ne!(&s1[..], &unsalted[..], "salted-final PBS must differ from the unsalted transport-era PBS");
    assert_ne!(s1, s2, "a different salt must yield a different final PBS");
}

#[test]
fn wt36_secret_keys_new_labels_and_fns_pinned() {
    // Tag drift on any of these strands every field device — same rule as the
    // existing label pins below.
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/transport/""#), "transport prefix drifted");
    assert!(SECRET_KEYS_SRC.contains(r#"b"pqsigner/optiga-pbs-v2""#), "salted PBS label drifted");
    for suffix in [
        r#"b"se050-scp03-enc-v1""#,
        r#"b"se050-scp03-mac-v1""#,
        r#"b"se050-scp03-dek-v1""#,
        r#"b"se050-admin-pin-v1""#,
        r#"b"optiga-pbs-v1""#,
    ] {
        assert!(SECRET_KEYS_SRC.contains(suffix), "transport suffix {suffix} missing");
    }
    // Transport keys root in the REAL OTP master (read_device_master, no burn),
    // NOT derive_into (which would route through the RDP-variant DHUK).
    assert!(SECRET_KEYS_SRC.contains("otp::read_device_master()"), "transport must read OTP master");
    assert!(SECRET_KEYS_SRC.contains("pub fn transport_optiga_pbs() -> Result<[u8; 64], OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn optiga_pairing_secret_salted(salt: &[u8; 32]) -> Result<[u8; 64], OtpError>"));
    assert!(SECRET_KEYS_SRC.contains("pub fn current_pbs() -> Result<[u8; 64], OtpError>"));
    // current_pbs gates the salted path on the ship feature.
    assert!(SECRET_KEYS_SRC.contains(r#"feature = "rdp2-self-lock""#), "current_pbs must gate salted path");
}

#[test]
fn legacy_otp_rollback_logical_bit_walk_is_lsb_first() {
    // Pins the quarantined software model only. STM32U585 OTP cannot perform
    // these repeated per-bit transitions inside one ECC quad-word.
    let mut w: u32 = 0xFFFF_FFFF;
    let bit = w.trailing_zeros();
    w &= !(1u32 << bit);
    assert_eq!(w, 0xFFFF_FFFE);
    let bit = w.trailing_zeros();
    w &= !(1u32 << bit);
    assert_eq!(w, 0xFFFF_FFFC);
}

#[test]
fn legacy_otp_rollback_model_has_1024_logical_bits() {
    // Arithmetic shape of the quarantined model, not physical update capacity.
    assert_eq!(32u32 * 32, 1024);
}

// ─────────────────────────────────────────────────────────────────────
// 4. NEGATIVE — KDF / domain-tag stability
//
// CLAUDE.md "What NOT to do": **No casual KDF tag changes**. A rename
// here invalidates every paired SE on every device in the field — a
// silent catastrophic regression. These tests fail loudly the moment
// anyone edits a tag.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_secret_keys_optiga_pbs_v1_label_unchanged() {
    assert!(
        SECRET_KEYS_SRC.contains(r#"b"pqsigner/optiga-pbs-v1""#),
        "OPTIGA PBS KDF tag drift would brick every paired Trust M chip — \
         CLAUDE.md 'No casual KDF tag changes'"
    );
}

#[test]
fn negative_secret_keys_se050_scp03_enc_v1_label_unchanged() {
    assert!(
        SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-enc-v1""#),
        "SE050 SCP03-ENC KDF tag drift would break the SE050 secure channel \
         on every device — CLAUDE.md 'No casual KDF tag changes'"
    );
}

#[test]
fn negative_secret_keys_se050_scp03_mac_v1_label_unchanged() {
    assert!(
        SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-mac-v1""#),
        "SE050 SCP03-MAC KDF tag drift would break the SE050 secure channel"
    );
}

#[test]
fn negative_secret_keys_se050_scp03_dek_v1_label_unchanged() {
    assert!(
        SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-scp03-dek-v1""#),
        "SE050 SCP03-DEK KDF tag drift would desync a future PUT KEY rotation"
    );
}

#[test]
fn negative_secret_keys_se050_admin_pin_v1_label_unchanged() {
    assert!(
        SECRET_KEYS_SRC.contains(r#"b"pqsigner/se050-admin-pin-v1""#),
        "SE050 admin-PIN KDF tag drift would lock every device out of admin-wipe"
    );
}

#[test]
fn negative_secret_keys_labels_are_versioned_with_v1_suffix() {
    // Bumping a label without on-chip rotation is a silent
    // data-corruption bug; module docstring requires `-v1`. Catch a
    // rename to a tag without a version suffix.
    for label in [
        "pqsigner/optiga-pbs",
        "pqsigner/se050-scp03-enc",
        "pqsigner/se050-scp03-mac",
        "pqsigner/se050-scp03-dek",
        "pqsigner/se050-admin-pin",
    ] {
        let unversioned = format!(r#"b"{}""#, label);
        assert!(
            !SECRET_KEYS_SRC.contains(&unversioned),
            "found unversioned KDF tag {label:?} — every label must carry a -vN suffix"
        );
    }
}

#[test]
fn negative_optiga_pairing_secret_signature_is_64_bytes() {
    // 64 bytes per OPTIGA Trust M SRM §"Platform Binding Secret". A
    // future refactor shrinking to 32 B would silently produce a PBS
    // the chip rejects.
    assert!(SECRET_KEYS_SRC.contains("pub fn optiga_pairing_secret() -> Result<[u8; 64], OtpError>"));
}

// ─────────────────────────────────────────────────────────────────────
// 5. NEGATIVE — register addresses + bit positions
//
// A silent address rename would corrupt every signature the device
// produces. These are the smallest catchable regressions.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_hash_module_uses_secure_alias_not_ns_alias() {
    // NS alias HASH_BASE_NS = 0x420C_0400. TZSC default-secure blocks NS
    // access; the wrong alias would bus-fault at first SHA-256 push.
    assert!(HASH_SRC.contains("0x520C_0400"));
    assert!(
        !HASH_SRC.contains("const HASH_BASE: u32 = 0x420C_0400;"),
        "HASH must NOT use NS alias 0x420C_0400 — TZSC default-secure blocks it"
    );
}

#[test]
fn negative_saes_keyr4_does_not_collide_with_ivr() {
    // KEYR0..3 ends at 0x1C; IVR0..3 lives at 0x20..0x2C; KEYR4 must
    // be at 0x30. A copy-paste bug putting KEYR4 at 0x20 would write
    // the key into IVR and silently produce IV-corrupted ciphertexts.
    assert!(
        !SAES_SRC.contains("keyr4: Reg32::new(SAES_BASE + 0x20)"),
        "KEYR4 must NOT collide with IVR0 at offset 0x20"
    );
    assert!(SAES_SRC.contains("keyr4: Reg32::new(SAES_BASE + 0x30)"));
}

#[test]
fn negative_saes_keysel_bhk_is_2_not_3() {
    // Per HAL table: Bhk=0b010 (decimal 2). 0b011 / decimal 3 would
    // select an unimplemented selector and SR.KEYVALID would stick.
    assert!(SAES_SRC.contains("Bhk = 0b010"));
    assert!(!SAES_SRC.contains("Bhk = 0b011"));
}

#[test]
fn negative_legacy_otp_layout_shape_does_not_drift_silently() {
    assert!(OTP_SRC.contains("pub const MAX_FW_VERSION: u32 = ROLLBACK_WORDS * 32;"));
    // This pins the legacy layout so bench fixtures do not drift while the
    // path is quarantined. It makes no lifetime/capacity claim: each physical
    // OTP QW is one-program-only. Draft 1.1's replacement codec is an
    // unapproved research candidate and remains OPEN.
    assert!(OTP_SRC.contains("pub const ROLLBACK_WORDS: u32 = 32;"));
}

#[test]
fn negative_otp_master_key_offset_unchanged_at_128() {
    // Moving the master-key region would (a) overlap the rollback tally
    // → corrupt readback, or (b) overflow OTP_RESERVED_BYTES bounds.
    assert!(OTP_SRC.contains("pub const MASTER_KEY_OFFSET: u32 = ROLLBACK_WORDS * 4;"));
    assert!(OTP_SRC.contains("pub const MASTER_KEY_SIZE: usize = 32;"));
}

#[test]
fn negative_hash_module_self_test_kat_bytes_unchanged() {
    // SHA-256("abc") canonical KAT. Silent tweak here would make the
    // boot self-test pass on a broken HASH peripheral.
    assert!(HASH_SRC.contains("0xba, 0x78, 0x16, 0xbf"));
    assert!(HASH_SRC.contains("0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad"));
}

#[test]
fn negative_hash_self_test_failure_halts_cpu() {
    // The whole point of the boot KAT is to refuse to sign with a
    // broken hash. A future refactor that turns the FAIL path into a
    // logged-but-continue would defeat the gate.
    assert!(
        HASH_SRC.contains("loop { cortex_m::asm::wfe(); }"),
        "HW SHA-256 self-test failure must halt the CPU, not return"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 6. NEGATIVE — feature gates + cross-feature compile_error fences
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_bhk_module_is_feature_gated() {
    // `bhk` requires deliberate per-device first-boot provisioning. The
    // BHK file must be feature-gated so a generic build cannot accidentally
    // pull in zero-keyed-at-reset derivations.
    assert!(
        BHK_SRC.contains(r##"#![cfg(feature = "bhk")]"##),
        "bhk.rs must be `#![cfg(feature = \"bhk\")]` — see module docs"
    );
}

#[test]
fn negative_saes_cmac_module_is_feature_gated() {
    assert!(
        SAES_CMAC_SRC.contains(r##"#![cfg(feature = "saes-dhuk")]"##),
        "saes_cmac.rs must be `#![cfg(feature = \"saes-dhuk\")]`"
    );
}

#[test]
fn negative_secret_keys_bhk_plus_otp_hardcoded_combo_is_compile_error() {
    // The two dev features are incompatible: BHK boot wiring is
    // `not(otp-hardcoded-master-key)`-gated, so under that combo BHK
    // would never load and every se050_admin_pin() call would fail
    // with KeyInvalid at runtime. The compile_error! converts the
    // runtime-only foot-gun into a build-time error.
    assert!(
        SECRET_KEYS_SRC.contains(r##"#[cfg(all(feature = "bhk", feature = "otp-hardcoded-master-key"))]"##),
    );
    assert!(
        SECRET_KEYS_SRC.contains("compile_error!"),
        "secret_keys.rs must compile_error! on the bhk + otp-hardcoded combo"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 7. NEGATIVE — secret-handling invariants (zeroize, no leak)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_saes_software_key_zeroized_after_op() {
    // CLAUDE.md "No secrets in NS world." A future refactor that
    // drops the post-op KEYR scrub would leave the 32-byte software
    // key sitting in peripheral registers across operations, where
    // a subsequent DHUK op could leak via timing or the SR.KEYVALID
    // path. Pin every KEYRn write(0).
    for n in 0..=7 {
        let needle = format!("REG.keyr{n}.write(0);");
        assert!(
            SAES_SRC.contains(&needle),
            "missing key-register scrub `{needle}` — see saes.rs \"Zero the key registers on exit\" block"
        );
    }
}

#[test]
fn negative_saes_decrypt_scratch_zeroized() {
    // d0..d3 are the 16-byte ciphertext returned to the caller — but
    // their stack scratch must be zeroized in place too (the caller
    // owns Zeroize of the returned buffer; this scrubs intermediates).
    for n in 0..=3 {
        let needle = format!("d{n}z.zeroize();");
        assert!(SAES_SRC.contains(&needle), "missing scratch scrub for `d{n}z`");
    }
}

#[test]
fn negative_saes_key_stack_copies_zeroized_after_load() {
    // S2-F23 / #452: k0..k7 hold the full 256-bit software key as u32
    // locals. Zeroizing only the OUTPUT scratch d0..d3 while leaving
    // the key copies on the stack is inverted priority — the key must
    // be wiped right after the KEYR load so it cannot linger on any
    // exit path. Pin each wipe.
    for n in 0..=7 {
        let needle = format!("k{n}.zeroize();");
        assert!(
            SAES_SRC.contains(&needle),
            "missing stack-key wipe `{needle}` — see saes.rs key-load block (S2-F23/#452)"
        );
    }
}

#[test]
fn negative_saes_error_exits_wipe_key_registers() {
    // S2-F23 / #452: the KeyInvalid / BusError / CcfTimeout exits sit
    // AFTER the software-key load — returning Err there without the
    // KEYR scrub left the 32-byte key engine-resident until the next
    // op (CR_IPRST is asserted-but-unverified to clear KEYR). Every
    // post-load error return must be immediately preceded by
    // wipe_sw_key(); the helper must exist and scrub all 8 registers.
    assert!(
        SAES_SRC.contains("fn wipe_key_regs() {"),
        "the shared KEYR scrub helper must exist (S2-F23/#452)"
    );
    for variant in ["KeyInvalid", "BusError", "CcfTimeout"] {
        let ret = format!("return Err(SaesError::{variant});");
        let mut seen = 0usize;
        for (idx, _) in SAES_SRC.match_indices(&ret) {
            let before = SAES_SRC[..idx].trim_end();
            let last_line = before.lines().last().unwrap_or("").trim();
            assert_eq!(
                last_line, "wipe_sw_key();",
                "{ret} must be immediately preceded by wipe_sw_key(); (S2-F23/#452)"
            );
            seen += 1;
        }
        assert!(seen > 0, "expected at least one {ret} exit to pin");
    }
}

#[test]
fn negative_hkdf_expand_zeroizes_prev_t() {
    // Final T(i) is the same bytes as the user's last 32 bytes of OKM;
    // the explicit zeroize defeats a future change that tried to
    // cache prev_t across calls or panic mid-loop.
    assert!(
        SECRET_KEYS_SRC.contains("prev_t.zeroize();"),
        "secret_keys::hkdf_expand must zeroize prev_t before return"
    );
}

#[test]
fn negative_otp_burn_zeroizes_key_on_every_exit_path() {
    // OTP burn handles 32-byte TRNG output. Every `return` path must
    // zeroize the buffer; a missed scrub leaks the device master to
    // a future stack reuse. Count `key.zeroize()` occurrences.
    let count = OTP_SRC.matches("key.zeroize();").count();
    assert!(
        count >= 4,
        "burn_device_master must zeroize `key` on every exit path; \
         found {count} occurrences, expected ≥ 4"
    );
}

#[test]
fn negative_otp_burn_uses_rng_strong_not_plain_rng() {
    // The device master is irreversibly burned; a biased TRNG cannot
    // be corrected. rng_strong XOR-folds STM32+OPTIGA+SE050 entropy.
    assert!(
        OTP_SRC.contains("rng_strong::fill(&mut key)"),
        "burn_device_master must use rng_strong::fill (XOR-fold) not plain rng::fill"
    );
}

#[test]
fn negative_bhk_zeroizes_plaintext_on_every_path() {
    // The plaintext BHK never leaves provision()/load_and_lock(). Any
    // missed scrub would leak it into stack reuse.
    let provision_zeroize = BHK_SRC.matches("bhk.zeroize();").count();
    assert!(
        provision_zeroize >= 2,
        "bhk.rs must zeroize the plaintext BHK on every exit path"
    );
    assert!(BHK_SRC.contains("wrapped.zeroize();"));
}

// ─────────────────────────────────────────────────────────────────────
// 8. NEGATIVE — FI hardening, verify-before-release, one-way bounds
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_otp_bump_uses_fi_double_check_sentinel() {
    // CLAUDE.md / fi.rs: a single `if cond` is glitchable. The OTP
    // bump's "did we really reach `target`?" check uses the
    // hamming-distant FI sentinel + double read.
    assert!(OTP_SRC.contains("crate::fi::wait_random();"));
    assert!(OTP_SRC.contains("crate::fi::check_true_into_sentinel"));
    assert!(OTP_SRC.contains("crate::fi::OK_SENTINEL"));
}

#[test]
fn negative_otp_program_qw_bounds_checked() {
    // program_otp_qw is the only path that flips OTP bits; if the
    // bounds check were ever removed, a caller bug could burn into the
    // reserved future-use region.
    assert!(OTP_SRC.contains("debug_assert!(addr >= OTP_BASE);"));
    assert!(OTP_SRC.contains("debug_assert!(addr + 16 <= OTP_BASE + OTP_RESERVED_BYTES);"));
    assert!(OTP_SRC.contains("debug_assert_eq!(addr & 0xF, 0);"));
}

#[test]
fn negative_otp_burn_refuses_when_already_burned() {
    // OTP is one-way. burn_device_master against an already-burned
    // region would produce garbage on the unburned bits.
    //
    // D4: the refusal must key on `Complete`, NOT on "any bit cleared". The
    // master spans TWO quad-words and takes two separate programs, so a reset
    // between them leaves a region that is neither blank nor complete. The old
    // any-bit test called that "burned" — which is the defect, not the guard.
    assert!(OTP_SRC.contains("if state == MasterKeyState::Complete"));
    assert!(OTP_SRC.contains("return Err(OtpError::AlreadyBurned);"));
}

#[test]
fn negative_otp_master_state_is_per_quad_word_not_per_bit() {
    // D4 regression guard. `is_device_master_burned` must mean "both
    // quad-words programmed", never "some bit somewhere is cleared" — a
    // per-bit test reports an interrupted burn as burned, and
    // read_device_master then hands back [QW0 || 0xFF x16], rooting every SE
    // transport credential in a 128-bit master, silently and irreversibly.
    assert!(
        OTP_SRC.contains("matches!(master_key_state(), Ok(MasterKeyState::Complete))"),
        "is_device_master_burned must mean Complete (both quad-words), not any-bit-cleared"
    );
    // The rule itself is pure and lives in `otp_state.rs` so it is executable
    // on the host (see the behavioural suite in that module). `hw/otp.rs` must
    // consume it rather than re-implement it beside the MMIO.
    assert!(OTP_SRC.contains("classify_master_words(&read_master_words())"));
    assert!(
        OTP_STATE_SRC.contains("(false, false) => MasterKeyState::Virgin"),
        "the pure classifier must treat an all-blank region as Virgin"
    );
    assert!(
        OTP_STATE_SRC.contains("(true, true) => MasterKeyState::Complete"),
        "the pure classifier must require BOTH quad-words for Complete"
    );
    assert!(
        OTP_STATE_SRC.contains("_ => MasterKeyState::Partial"),
        "exactly-one-quad-word-programmed must be Partial — this is D4"
    );
}

#[test]
fn negative_otp_read_master_refuses_partial_region() {
    // The barrier that makes D4 unreachable: no caller may obtain a
    // half-blank master, so no credential can ever root in one.
    assert!(OTP_SRC.contains("MasterKeyState::Partial => return Err(OtpError::MasterKeyPartial)"));
    assert!(OTP_SRC.contains("MasterKeyState::Virgin => return Err(OtpError::NotBurned)"));
}

#[test]
fn negative_otp_master_state_fails_closed_on_unstable_read() {
    // The verdict gates an irreversible OTP write AND a key derivation, so a
    // glitched classification must abort, not be voted. Contrast
    // `rollback_floor`, which votes max(a,b) — correct for a monotonic
    // admission check, wrong here.
    assert!(OTP_SRC.contains("return Err(OtpError::MasterKeyUnstable);"));
    // Two passes with an FI delay between them.
    let state_fn = OTP_SRC
        .split("pub fn master_key_state()")
        .nth(1)
        .expect("master_key_state must exist");
    assert!(
        state_fn.contains("crate::fi::wait_random();"),
        "master_key_state must place an FI delay between its two classification passes"
    );
}

#[test]
fn negative_otp_burn_readback_verified() {
    // Brown-out mid-program is a real failure mode. The readback
    // gate catches a partially-programmed OTP (returns
    // ReadbackMismatch → caller bricks safely).
    assert!(OTP_SRC.contains("OtpError::ReadbackMismatch"));
    assert!(OTP_SRC.contains("readback == key"));
}

#[test]
fn negative_otp_bump_to_rejects_above_max_fw_version() {
    // Software cap before any flash op.
    assert!(OTP_SRC.contains("if target > MAX_FW_VERSION"));
    assert!(OTP_SRC.contains("OtpError::OutOfBudget"));
}

#[test]
fn negative_saes_init_clears_rng_seed_error_and_surfaces_it() {
    // RngSeedError must be detected before any encrypt op — running on
    // an unseeded SAES would emit side-channel-vulnerable ciphertexts.
    assert!(SAES_SRC.contains("RngSeedError"));
    assert!(SAES_SRC.contains("REG.icr.write(ICR_RNGEIF);"));
}

#[test]
fn negative_saes_self_test_includes_domain_collision_check() {
    // The on-chip self-test must verify DHUK ≠ Software for the same
    // plaintext — a KEYSEL bypass that silently routed DHUK back to
    // software-key bytes would otherwise go undetected.
    assert!(SAES_SRC.contains("SelfTestDomainCollision"));
    assert!(SAES_SRC.contains("if ct_dhuk == ct_sw"));
}

#[test]
fn negative_saes_polls_keyvalid_before_encrypt() {
    // Starting an op without SR.KEYVALID asserted leaves the engine
    // waiting forever and CCF never sets.
    assert!(SAES_SRC.contains("SR_KEYVALID"));
    assert!(SAES_SRC.contains("while REG.sr.read() & SR_KEYVALID == 0"));
}

#[test]
fn negative_saes_decrypt_runs_key_derivation_pass_first() {
    // CLAUDE.md / STM32 HAL: decrypt requires MODE=key-derivation (0b01)
    // before MODE=decrypt (0b10), with EN held high across the
    // transition. A future refactor that skipped KD would silently
    // produce nonsense plaintext.
    assert!(SAES_SRC.contains("0b01u32 << CR_MODE_POS"));
    assert!(SAES_SRC.contains("0b10u32 << CR_MODE_POS"));
}

#[test]
fn negative_hash_module_pulses_hashrst_before_each_init() {
    // STM32U5 HASH errata: setting INIT alone is not enough to recover
    // from a completed hash. RSTR pulse wipes FIFO state.
    let rstr_set = HASH_SRC.matches("REG.rcc_ahb2rstr1.set_bits(RCC_HASHRST);").count();
    let rstr_clr = HASH_SRC.matches("REG.rcc_ahb2rstr1.clear_bits(RCC_HASHRST);").count();
    assert!(rstr_set >= 2, "HASHRST must be pulsed in both init_clock and pqsigner_sha256_init");
    assert!(rstr_clr >= 2);
}

#[test]
fn negative_bhk_provision_refuses_when_already_provisioned() {
    // First write is per-device one-way. A re-provision would
    // invalidate any paired SE050 channel.
    assert!(BHK_SRC.contains("if is_provisioned()"));
    assert!(BHK_SRC.contains("return Err(BhkError::AlreadyProvisioned);"));
}

#[test]
fn negative_bhk_load_and_lock_sets_bhklock() {
    // After unwrap, BHKLOCK must be raised in TAMP_SECCFGR so software
    // cannot read the BKPR. Without this the in-RAM BHK would be
    // dumpable by any S-world RCE.
    assert!(BHK_SRC.contains("seccfgr | TAMP_BHKLOCK"));
}

// ─────────────────────────────────────────────────────────────────────
// 9. NEGATIVE — algorithmic edge cases the slice's algorithms must
// handle (reference implementations).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_hkdf_expand_n_blocks_capped_at_255() {
    // RFC 5869 §2.3 cap: L ≤ 255 × HashLen = 8160 bytes. The
    // implementation must surface or assert against violations rather
    // than silently wrap the counter byte.
    assert!(SECRET_KEYS_SRC.contains("debug_assert!(n <= 255"));
}

#[test]
fn negative_hkdf_expand_truncated_output_takes_tag_prefix() {
    // Truncating must be the *prefix* of the last T(i), not a
    // hash-of-hash or any other reshape — callers compute keys at
    // their natural lengths and assume prefix-stability.
    let prk = [0xA5u8; 32];
    let info = b"truncation/test";
    let mut full = [0u8; 32];
    let mut short = [0u8; 10];
    hkdf_expand_ref(&prk, info, &mut full);
    hkdf_expand_ref(&prk, info, &mut short);
    assert_eq!(short, full[..10]);
}

#[test]
fn negative_legacy_otp_bump_skips_program_when_target_is_already_reached() {
    // Pins only the quarantined software early return. It says nothing about a
    // launched/torn QW, which must never be retried under STM32U585 OTP rules.
    assert!(OTP_SRC.contains("if current >= target"));
    assert!(OTP_SRC.contains("return Ok(());"));
}

#[test]
fn negative_mmio_reg32_construction_is_unsafe() {
    // The whole point of the typed-MMIO wrapper is to confine `unsafe`
    // to a single per-address construction. If Reg32::new were ever
    // made safe, every caller would lose the address-validity audit.
    assert!(
        MMIO_SRC.contains("pub const unsafe fn new(addr: u32) -> Self"),
        "Reg32::new must remain `unsafe` — see mmio.rs safety contract"
    );
}

#[test]
fn negative_mmio_read_at_is_unsafe_with_bank_bound_safety_doc() {
    // read_at / write_at MUST keep their `unsafe` markers + bank-bound
    // safety contract; without that, peripherals like HASH_HR0..HR7
    // could be walked off the end of their register block.
    assert!(MMIO_SRC.contains("pub unsafe fn read_at(self, offset: usize) -> u32"));
    assert!(MMIO_SRC.contains("pub unsafe fn write_at(self, offset: usize, v: u32)"));
}

// ─────────────────────────────────────────────────────────────────────
// 10. NEGATIVE — algorithm policy. No classical signer or alt-crypto
// has ever been a path through this slice; assert nothing snuck in.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_no_classical_signer_in_slice() {
    // CLAUDE.md invariant #5: One signature primitive (SPHINCS+C10).
    // The HW-crypto slice is a tempting place to wedge in ECDSA / Ed25519
    // (HASH peripheral, SAES key wrapper) — confirm the slice has no
    // such references.
    for needle in ["ecdsa", "Ecdsa", "ECDSA", "ed25519", "Ed25519", "secp256k1", "Secp256k1"] {
        for (name, src) in [
            ("hash.rs", HASH_SRC),
            ("saes.rs", SAES_SRC),
            ("saes_cmac.rs", SAES_CMAC_SRC),
            ("secret_keys.rs", SECRET_KEYS_SRC),
            ("otp.rs", OTP_SRC),
            ("bhk.rs", BHK_SRC),
            ("mmio.rs", MMIO_SRC),
        ] {
            assert!(
                !src.contains(needle),
                "classical signer reference {needle:?} found in {name} — \
                 CLAUDE.md invariant #5 forbids any non-C10 primitive"
            );
        }
    }
}

#[test]
fn negative_no_rotate_master_keys_path_in_secret_keys() {
    // CLAUDE.md "What NOT to do": No rotateMasterKeys / resetBootstrapUses
    // / increaseMax*. The slice exposes derivation; a rotate primitive
    // here would change every derived secret in the field.
    for needle in ["rotate_master", "rotateMaster", "reset_bootstrap", "resetBootstrap", "increase_max", "increaseMax"] {
        assert!(
            !SECRET_KEYS_SRC.contains(needle),
            "forbidden rotation/reset path {needle:?} found in secret_keys.rs"
        );
    }
}
