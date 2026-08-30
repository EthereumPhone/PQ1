//! Host-runnable positive + negative test suite for the `secure-se050`
//! slice.
//!
//! Slice files in scope (under `secure/src/se050/`):
//!   * `mod.rs`     — `Se050` driver, lifecycle, OID assignments,
//!                    provision / unlock / admin_factory_reset
//!   * `apdu.rs`    — APDU builder + every SE050 command wrapper used
//!                    in production (write_userid, write_binary_gated,
//!                    create_session, verify_session, read_authed,
//!                    delete_object{,_authed}, iterative_delete_all,
//!                    get_random, close_session)
//!   * `scp03.rs`   — SCP03 session establish + wrap_apdu C-MAC + C-DEC
//!   * `t1oi2c.rs`  — T=1' over I²C transport (GP 1.0 CRC-16, NAD/PCB/
//!                    LEN frame, R/S/I-block protocol, interface reset,
//!                    WTX, I-frame chaining)
//!   * `i2c.rs`     — bare-metal STM32U585 I²C1 master (driver shared
//!                    with the OPTIGA path; SE050 slave address pinned
//!                    here)
//!
//! Every file in this slice sits behind `feature = "se050", not(test)`
//! and pulls in `crate::hw::i2c_hw` MMIO or `cortex_m::asm::nop()` for
//! its busy-wait loops; neither links on host. We therefore exercise
//! the slice through three complementary mechanisms:
//!
//!   1. `include_str!` source-text pins for every wire constant /
//!      invariant assertion whose silent regression matters
//!      (`negative_*_pin` tests).
//!   2. Reference-vector verifications of the pure-logic algorithms
//!      the slice depends on, by re-implementing them in the test
//!      module and asserting the file text still reads identically
//!      (`positive_crc16_*`, `positive_scp03_*`).
//!   3. Cross-checks against the always-on `scp03_logic` /
//!      `iso7816` modules to confirm the SE050 driver actually
//!      calls into the same primitives the host tests cover
//!      (`positive_apdu_imports_iso7816_tlv`,
//!      `positive_scp03_re_exports_pure_logic`).
//!
//! On-target tests (real SCP03 handshake against a chip, three-way PIN
//! lockstep, admin-auth wipe, crash-safety resume) happen under
//! `make pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`,
//! `make se050-admin-wipe-e2e`, `make se050-crash-safety-e2e`,
//! `make se050-admin-extract-attempt-e2e` and are NOT exercised here.
//! The host suite below catches regressions that would either prevent
//! those tests from booting at all or silently degrade the security
//! properties (KDF-tag drift, OID-range shift, policy-bit weakening,
//! plaintext-channel reintroduction).

#![cfg(test)]

use crate::iso7816::{tlv_parse, tlv_put, tlv_put_u32};

// ─────────────────────────────────────────────────────────────────────
// Source-text snapshots
// ─────────────────────────────────────────────────────────────────────

const APDU_SRC: &str = include_str!("../se050/apdu.rs");
const RNG_EXACT_SRC: &str = include_str!("../rng_exact.rs");
const SCP03_LOGIC_SRC: &str = include_str!("../scp03_logic.rs");
const SCP03_SRC: &str = include_str!("../se050/scp03.rs");
const T1OI2C_SRC: &str = include_str!("../se050/t1oi2c.rs");
/// The pure T=1' framing, extracted to `sphincs-tz-shared` (2026-07-17) so it
/// is Kani-provable host-side. The wire-format pins below follow it: a Kani
/// round-trip proves build/validate agree with EACH OTHER, so only these text
/// pins tie us to the chip's silicon-locked CRC/NAD/LEN choices.
const T1_FRAME_SRC: &str = include_str!("../../../shared/src/t1_frame.rs");
const I2C_SRC: &str = include_str!("../se050/i2c.rs");
const MOD_SRC: &str = include_str!("../se050/mod.rs");

/// Returns true if `needle` appears in any non-comment line of `src`.
/// A line is treated as comment-only after the first `//` token; the
/// portion before `//` (if any) is still scanned. None of the slice's
/// source files use block comments (`/* ... */`).
fn contains_in_code(src: &str, needle: &str) -> bool {
    for line in src.lines() {
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        if code.contains(needle) {
            return true;
        }
    }
    false
}

// ═════════════════════════════════════════════════════════════════════
// Reference implementations of the slice's pure-logic algorithms.
// Cross-checked against the production source text by the
// `negative_*_algorithm_shape_stable` tests below.
// ═════════════════════════════════════════════════════════════════════

/// GP 1.0 CRC-16 as the SE050 T=1' transport uses it. Reflected
/// polynomial 0x8408 (bit-reversed 0x1021), init 0xFFFF, final XOR
/// 0xFFFF, NO final byte-swap. Copy of `se050::t1oi2c::crc16`. The
/// matching pin (`negative_crc16_algorithm_shape_stable`) asserts the
/// production file still reads identically — a "modernisation" to
/// CRC-16/CCITT-FALSE / KERMIT / XMODEM / ARC would silently break
/// every frame.
fn gp10_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xFFFF;
    crc
}

/// Reference re-implementation of `se050::t1oi2c::build_frame` for the
/// GP 1.0 frame shape (`NAD(1) | PCB(1) | LEN(2) | INF(N) | CRC16(2)`).
/// Returns the total frame length written into `buf`.
fn ref_build_frame(pcb: u8, inf: &[u8], buf: &mut [u8]) -> usize {
    const NAD: u8 = 0x5A;
    let len = inf.len();
    buf[0] = NAD;
    buf[1] = pcb;
    buf[2] = (len >> 8) as u8;
    buf[3] = (len & 0xFF) as u8;
    buf[4..4 + len].copy_from_slice(inf);
    let crc = gp10_crc16(&buf[..4 + len]);
    buf[4 + len] = (crc >> 8) as u8;
    buf[4 + len + 1] = (crc & 0xFF) as u8;
    4 + len + 2
}

// ═════════════════════════════════════════════════════════════════════
// 1. POSITIVE — `t1oi2c.rs` transport primitives
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_crc16_empty_input_known_vector() {
    // GP 1.0 CRC-16 over an empty input: init 0xFFFF, no bytes, final
    // XOR 0xFFFF → 0x0000. Pin to catch a refactor that changed the
    // init constant from 0xFFFF to 0x0000 (silent silicon mismatch).
    assert_eq!(gp10_crc16(&[]), 0x0000);
}

#[test]
fn positive_crc16_deterministic_for_known_input() {
    let a = gp10_crc16(b"123456789");
    let b = gp10_crc16(b"123456789");
    assert_eq!(a, b, "CRC must be deterministic");
}

#[test]
fn positive_build_frame_layout_pin() {
    // NAD(1) | PCB(1) | LEN(2 BE) | INF | CRC(2 BE)
    let mut buf = [0u8; 32];
    let inf = [0xAAu8, 0xBB, 0xCC];
    let n = ref_build_frame(0x00, &inf, &mut buf);
    assert_eq!(n, 4 + 3 + 2, "frame = header(4) + inf(3) + CRC(2)");
    assert_eq!(buf[0], 0x5A, "NAD host->SE = 0x5A");
    assert_eq!(buf[1], 0x00, "PCB byte preserved");
    assert_eq!([buf[2], buf[3]], [0x00, 0x03], "LEN big-endian");
    assert_eq!(&buf[4..7], &inf, "INF bytes copied verbatim");
    let crc_received = ((buf[7] as u16) << 8) | (buf[8] as u16);
    assert_eq!(crc_received, gp10_crc16(&buf[..7]));
}

#[test]
fn positive_build_frame_empty_inf() {
    let mut buf = [0u8; 16];
    let n = ref_build_frame(0xCF /* INTF_RESET_REQ */, &[], &mut buf);
    assert_eq!(n, 6, "empty INF still emits NAD+PCB+LEN+CRC = 6 bytes");
    assert_eq!(&buf[..4], &[0x5A, 0xCF, 0x00, 0x00]);
}

// ═════════════════════════════════════════════════════════════════════
// 2. POSITIVE — `iso7816.rs` TLV primitives the slice imports
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_apdu_imports_iso7816_tlv() {
    // The slice MUST share the always-on TLV decoder so a fuzz failure
    // in `crate::iso7816::tlv_parse` surfaces in the SE050 path too —
    // see iso7816 module docstring.
    assert!(
        APDU_SRC.contains("use crate::iso7816::{tlv_parse, tlv_put, tlv_put_u32};"),
        "apdu.rs must import the always-on TLV helpers; forking the decoder \
         loses the fuzz_props coverage that's the whole point of the split"
    );
}

#[test]
fn positive_tlv_put_short_form_byte_for_byte() {
    // SE050 TLV uses the same `(tag, len, value)` shape ISO 7816-4
    // mandates; the always-on `tlv_put` is the one the slice calls.
    let mut buf = [0u8; 32];
    let n = tlv_put(&mut buf, 0, 0x41, &[0xAA, 0xBB]);
    assert_eq!(n, 4);
    assert_eq!(&buf[..n], &[0x41, 0x02, 0xAA, 0xBB]);
}

#[test]
fn positive_tlv_put_u32_big_endian() {
    let mut buf = [0u8; 32];
    let n = tlv_put_u32(&mut buf, 0, 0x41, 0x7B10_00A0);
    assert_eq!(n, 6);
    assert_eq!(&buf[..n], &[0x41, 0x04, 0x7B, 0x10, 0x00, 0xA0]);
}

#[test]
fn positive_tlv_parse_round_trip() {
    let mut buf = [0u8; 32];
    let n = tlv_put(&mut buf, 0, 0x42, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let (t, v, rest) = tlv_parse(&buf[..n]).expect("round-trip");
    assert_eq!(t, 0x42);
    assert_eq!(v, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(rest.is_empty());
}

// ═════════════════════════════════════════════════════════════════════
// 3. POSITIVE — `scp03_logic` re-export surface
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_scp03_re_exports_pure_logic() {
    // The SCP03 session module MUST use the always-on `scp03_logic`
    // primitives — host-side AES-128 / CMAC KATs in `scp03_logic::tests`
    // are the production code's regression coverage. A future refactor
    // that re-introduces a private AES impl in `se050::scp03` would
    // silently lose the KAT coverage.
    assert!(SCP03_SRC.contains("pub use crate::scp03_logic::"));
    assert!(SCP03_SRC.contains("aes128_cbc_encrypt"));
    assert!(SCP03_SRC.contains("aes128_ecb_encrypt"));
    assert!(SCP03_SRC.contains("cmac_aes128"));
    assert!(SCP03_SRC.contains("build_put_key_apdu"));
    assert!(SCP03_SRC.contains("keys_are_factory_default"));
    assert!(SCP03_SRC.contains("KEY_VERSION"));
    assert!(SCP03_SRC.contains("PLATFORM_DEK"));
    assert!(SCP03_SRC.contains("PLATFORM_ENC"));
    assert!(SCP03_SRC.contains("PLATFORM_MAC"));
}

#[test]
fn positive_scp03_kdf_derivation_constants_present() {
    // The five SP 800-108 DD constants (`DD_S_ENC = 0x04`,
    // `DD_S_MAC = 0x06`, `DD_S_RMAC = 0x07`, `DD_CARD_CRYPTOGRAM = 0x00`,
    // `DD_HOST_CRYPTOGRAM = 0x01`) live in `scp03_logic` and are
    // tested there. Pin the import so a refactor can't fork a copy.
    assert!(SCP03_SRC.contains("DD_CARD_CRYPTOGRAM"));
    assert!(SCP03_SRC.contains("DD_HOST_CRYPTOGRAM"));
    assert!(SCP03_SRC.contains("DD_S_ENC"));
    assert!(SCP03_SRC.contains("DD_S_MAC"));
    assert!(SCP03_SRC.contains("DD_S_RMAC"));
}

// ═════════════════════════════════════════════════════════════════════
// 4. POSITIVE — `apdu.rs` wire constants (SE050 AID, INS, P1, P2,
//    TLV tags)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_se050_aid_byte_exact_pin() {
    // NXP-published SE05x AID from AN12413. Any single-byte drift makes
    // GP SELECT BY NAME return SW=0x6A82 ("file not found") and aborts
    // every subsequent APDU. 16 bytes total.
    let expected = "0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,\n\
                    \x20\x20\x20\x200x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,";
    assert!(
        APDU_SRC.contains(expected),
        "SE050 AID must remain the NXP-published constant; a refactor that \
         shifted any byte would brick every SELECT APDU"
    );
}

#[test]
fn positive_apdu_ins_codes_pin() {
    // SE05x ISO 7816-4 INS values. The OR with INS_AUTH_OBJECT (0x40)
    // is HW lesson #1 — UserID create needs INS=0x41 (WRITE |
    // AUTH_OBJECT). Writing INS=0x01 alone silently downgrades to a
    // plain binary write and chip rejects with SW=0x6985.
    assert!(APDU_SRC.contains("const INS_WRITE: u8 = 0x01;"));
    assert!(APDU_SRC.contains("const INS_READ: u8 = 0x02;"));
    assert!(APDU_SRC.contains("const INS_MGMT: u8 = 0x04;"));
    assert!(APDU_SRC.contains("const INS_PROCESS: u8 = 0x05;"));
    assert!(APDU_SRC.contains("const INS_AUTH_OBJECT: u8 = 0x40;"));
}

#[test]
fn positive_apdu_p1_values_pin() {
    assert!(APDU_SRC.contains("const P1_DEFAULT: u8 = 0x00;"));
    assert!(APDU_SRC.contains("const P1_BINARY: u8 = 0x06;"));
    assert!(APDU_SRC.contains("const P1_USERID: u8 = 0x07;"));
}

#[test]
fn positive_apdu_p2_values_pin() {
    assert!(APDU_SRC.contains("const P2_DEFAULT: u8 = 0x00;"));
    assert!(APDU_SRC.contains("const P2_CREATE_SESSION: u8 = 0x1B;"));
    assert!(APDU_SRC.contains("const P2_EXIST: u8 = 0x27;"));
    assert!(APDU_SRC.contains("const P2_VERIFY_SESSION_USERID: u8 = 0x2C;"));
    assert!(APDU_SRC.contains("const P2_RANDOM: u8 = 0x49;"));
    assert!(APDU_SRC.contains("const P2_LIST: u8 = 0x25;"));
    assert!(APDU_SRC.contains("const P2_ATTRIBUTES: u8 = 0x3B;"));
}

#[test]
fn positive_apdu_p2_delete_object_inline_is_0x28() {
    // DELETE_OBJECT P2 is inlined in both `delete_object` and
    // `delete_object_authed`; pin both call sites so a renamed constant
    // can't silently desync one of them.
    assert!(contains_in_code(APDU_SRC, "0x28"));
    // Specifically pin the inline literal patterns.
    assert!(APDU_SRC.contains("P1_DEFAULT, 0x28); // P2=DELETE_OBJECT"));
    assert!(APDU_SRC.contains("inner[3] = 0x28; // P2 = DELETE_OBJECT"));
}

#[test]
fn positive_apdu_close_session_p2_is_0x1c() {
    // CloseSession is the inner P2=0x1C inside an INS_PROCESS wrapper.
    assert!(APDU_SRC.contains("0x80, INS_MGMT, P1_DEFAULT, 0x1C];"));
}

#[test]
fn positive_apdu_tlv_tags_pin() {
    // ISO 7816-4 / GP application-class context-specific tags used in
    // every SE050 APDU. SESSION_ID=0x10 wraps the inner command;
    // POLICY=0x11 carries the auth-object policy entries;
    // MAX_ATTEMPTS=0x12 caps UserID failures; TAG_1..TAG_4 are the
    // positional payload tags.
    assert!(APDU_SRC.contains("const TAG_SESSION_ID: u8 = 0x10;"));
    assert!(APDU_SRC.contains("const TAG_POLICY: u8 = 0x11;"));
    assert!(APDU_SRC.contains("const TAG_MAX_ATTEMPTS: u8 = 0x12;"));
    assert!(APDU_SRC.contains("const TAG_1: u8 = 0x41;"));
    assert!(APDU_SRC.contains("const TAG_2: u8 = 0x42;"));
    assert!(APDU_SRC.contains("const TAG_3: u8 = 0x43;"));
    assert!(APDU_SRC.contains("const TAG_4: u8 = 0x44;"));
}

#[test]
fn positive_apdu_sw_ok_is_0x9000() {
    assert!(APDU_SRC.contains("const SW_OK: u16 = 0x9000;"));
}

// ═════════════════════════════════════════════════════════════════════
// 5. POSITIVE — `apdu.rs` AR (policy access-rule) bits
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_ar_bits_byte_exact_pin() {
    // Per the SE05x SRM (POLICY_OBJ_ALLOW_*). Each bit is a separate
    // permission; mis-OR'ing them silently grants the wrong access rule.
    assert!(APDU_SRC.contains("const AR_ALLOW_READ: u32 = 0x0020_0000;"));
    assert!(APDU_SRC.contains("const AR_ALLOW_WRITE: u32 = 0x0010_0000;"));
    assert!(APDU_SRC.contains("const AR_ALLOW_DELETE: u32 = 0x0004_0000;"));
    assert!(APDU_SRC.contains("const AR_REQUIRE_SM: u32 = 0x0002_0000;"));
}

#[test]
fn positive_policy_user_entry_layout_pin() {
    // build_policy writes a 9-byte entry: [entry_len=0x08][auth_obj_id(4 BE)]
    // [ar_header(4 BE)]. Pin the layout — HW lesson #2 says auth_obj_id
    // comes BEFORE ar_header; reversing them silently breaks every chip.
    assert!(APDU_SRC.contains("out[0] = 0x08;"));
    assert!(APDU_SRC.contains("out[1..5].copy_from_slice(&a);"));
    assert!(APDU_SRC.contains("out[5..9].copy_from_slice(&ar);"));
    // Admin entry mirrors the layout at offset 9:
    assert!(APDU_SRC.contains("out[9] = 0x08;"));
    assert!(APDU_SRC.contains("out[10..14].copy_from_slice(&a2);"));
    assert!(APDU_SRC.contains("out[14..18].copy_from_slice(&ar2);"));
}

#[test]
fn positive_userid_write_uses_or_of_write_and_auth_object() {
    // HW lesson #1: UserID create needs INS=0x41 = INS_WRITE |
    // INS_AUTH_OBJECT. Writing INS=0x01 alone makes the chip reject
    // with SW=0x6985.
    assert!(APDU_SRC.contains("INS_WRITE | INS_AUTH_OBJECT"));
}

#[test]
fn positive_write_binary_data_uses_plain_ins_write() {
    // write_binary_gated must NOT OR in AUTH_OBJECT — that header is
    // reserved for auth-object create (UserID).
    assert!(APDU_SRC.contains("ApduBuf::new(0x80, INS_WRITE, P1_BINARY, P2_DEFAULT);"));
}

// ═════════════════════════════════════════════════════════════════════
// 6. POSITIVE — `scp03.rs` session control bytes
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_scp03_key_version_is_0x0b() {
    // SE050 platform keyset is KVN 0x0B (generic across SE05X variants,
    // incl. SE050C2); PUT KEY replaces it in place,
    // so a refactor that bumped the constant to 0x0C would silently
    // open the wrong keyset and the chip would reject EXTERNAL AUTH.
    assert!(SCP03_SRC.contains("init_update[2] = KEY_VERSION;"));
    // The KEY_VERSION constant itself is in scp03_logic; the always-on
    // tests there pin its value at 0x0B.
}

#[test]
fn positive_scp03_external_authenticate_p1_is_0x33() {
    // S-5 fix (docs/security/security-review-2026-05.md §C-7): EXTERNAL
    // AUTHENTICATE P1 must be 0x33 = C-MAC | C-DECRYPTION | R-MAC |
    // R-ENCRYPTION (GP Amendment D Table 7-6 page 35; mirrored in
    // NXP plug-and-trust `fsl_sss_se05x_scp03.c:186-198`
    // `SECLVL_CDEC_RENC_CMAC_RMAC`).  Pre-S-5 the driver negotiated
    // P1=0x03 (C-MAC + C-DEC only — no R-MAC, no R-ENC) which left
    // every response in cleartext on the I²C bus, leaking `half_E`
    // on every unlock.  Regressing to 0x03 or 0x13 (no R-ENC) or
    // 0x11 (no C-DEC) breaks invariant #3 ("E2E encrypted SE
    // tunnels") and must fire this test.
    assert!(SCP03_SRC.contains("let header = [0x84u8, 0x82, 0x33, 0x00, 0x10];"));
    assert!(SCP03_SRC.contains("ext_auth[2] = 0x33;"));
}

#[test]
fn positive_scp03_unwrap_response_exists() {
    // S-5: unwrap_response must exist and be called from send_apdu.
    // Without it, even at level 0x33 the driver would feed wrapped
    // ciphertext to the TLV parser upstream → garbage reads / silent
    // policy bypass.
    assert!(SCP03_SRC.contains("pub fn unwrap_response("));
    assert!(SCP03_SRC.contains("fn response_icv("));
    assert!(SCP03_SRC.contains("block[0] = 0x80;")); // §6.2.7 MSB pad
    assert!(APDU_SRC.contains("super::scp03::unwrap_response("));
}

// ─────────────────────────────────────────────────────────────────────
// 6b. F-28 REWORK (2026-08-03) — R-MAC authentication receipt
//
// Wave-17 GPT-5.6 blocker: the legacy F-28 "infective" gate folded a fresh
// R-MAC mismatch into the released bytes as XOR-0xFF — but returned `Ok`,
// preserved the attacker-chosen SW, and advanced the counter. XOR-0xFF is a
// public bijection, so a forging attacker submits the *complement* of the
// desired payload and receives exactly it after one fault skips the early
// rejection. These pins make any mutation that reintroduces that shape (or
// weakens the replacement receipt gate) a test failure.
// ─────────────────────────────────────────────────────────────────────

/// Extract `unwrap_response`'s body from `SCP03_SRC` (up to the next
/// top-level item) so order and count pins can't be satisfied by text
/// elsewhere in the file.
fn unwrap_response_src() -> &'static str {
    let start = SCP03_SRC
        .find("pub fn unwrap_response(")
        .expect("unwrap_response exists");
    let rest = &SCP03_SRC[start..];
    let end = rest
        .find("\n// `aes128_cbc_decrypt` lives")
        .map_or(rest.len(), |o| o);
    &rest[..end]
}

#[test]
fn positive_scp03_rmac_verify_helper_is_exported_and_duplicated() {
    // The verifier must be an out-of-line exported symbol (LTO cannot fold it
    // into the caller or CSE the duplicate checks; the production symbol
    // audit requires exactly one copy in the optimized ELF).
    assert!(SCP03_LOGIC_SRC.contains("#[inline(never)]"));
    assert!(
        SCP03_LOGIC_SRC.contains("#[export_name = \"pqsigner_se050_scp03_rmac_verify_into\"]")
    );
    assert!(SCP03_LOGIC_SRC.contains("pub fn verify_rmac_into("));
    // Two independent full R-MAC recomputations inside the helper.
    let start = SCP03_LOGIC_SRC
        .find("pub fn verify_rmac_into(")
        .expect("verify_rmac_into exists");
    let rest = &SCP03_LOGIC_SRC[start..];
    let end = rest
        .find("pub fn verify_renc_relation_into(")
        .map_or(rest.len(), |o| o);
    let helper = &rest[..end];
    assert_eq!(
        helper.matches("cmac_aes128(s_rmac, &[mcv, body, sw])").count(),
        2,
        "verify_rmac_into must recompute the full R-MAC twice independently"
    );
    // The recomputations are separated by wait_random (an opaque
    // possible-write call so LLVM cannot common them up).
    assert!(helper.contains("crate::fi::wait_random();"));
    // Fail-initialized receipt with a sole success publication.
    assert!(helper.contains("core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);"));
    assert_eq!(
        helper
            .matches("core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);")
            .count(),
        1,
        "exactly one OK publication point"
    );
    // Constant-time comparison preserved.
    assert!(helper.contains(".ct_eq(rmac_recv)"));
}

#[test]
fn positive_scp03_renc_verify_helper_is_exported_and_duplicated() {
    // Wave-18: the decrypt-fidelity relation verifier — same exported,
    // duplicated, fail-initialized shape as the R-MAC verifier.
    assert!(
        SCP03_LOGIC_SRC.contains("#[export_name = \"pqsigner_se050_scp03_renc_verify_into\"]")
    );
    assert!(SCP03_LOGIC_SRC.contains("pub fn verify_renc_relation_into("));
    let start = SCP03_LOGIC_SRC
        .find("pub fn verify_renc_relation_into(")
        .expect("verify_renc_relation_into exists");
    let rest = &SCP03_LOGIC_SRC[start..];
    let end = rest.find("\n// ---").map_or(rest.len(), |o| o);
    let helper = &rest[..end];
    // Two independent full CBC re-encryptions of the padded plaintext, each
    // under an independently recomputed response ICV (a shared caller ICV
    // would let one faulted ICV computation make decrypt and check
    // consistently wrong).
    assert_eq!(
        helper.matches("aes128_cbc_encrypt(s_enc, &icv,").count(),
        2,
        "verify_renc_relation_into must re-encrypt twice independently"
    );
    assert_eq!(
        helper.matches("aes128_ecb_encrypt(s_enc, &icv_block)").count(),
        2,
        "each pass must recompute the response ICV independently"
    );
    assert_eq!(helper.matches("icv_block[0] = 0x80;").count(), 2);
    assert!(helper.contains("crate::fi::wait_random();"));
    assert!(helper.contains("core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);"));
    assert_eq!(
        helper
            .matches("core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);")
            .count(),
        1,
        "exactly one OK publication point"
    );
    // Constant-time compare against the authenticated ciphertext body, with
    // shape validation (equal lengths, AES blocks, bounded buffer).
    assert!(helper.contains(".ct_eq(body)"));
    assert!(helper.contains("plain_padded.len() != body.len()"));
    assert!(helper.contains("body.len() % 16 != 0"));
}

#[test]
fn positive_scp03_unwrap_gates_on_fail_initialized_receipt_twice() {
    let f = unwrap_response_src();
    // Caller fail-initializes BOTH receipts (a skipped verifier call stays FAIL).
    assert!(f.contains("let mut rmac_auth_receipt: u32 = crate::fi::FAIL_SENTINEL;"));
    assert!(f.contains("let mut renc_receipt: u32 = crate::fi::FAIL_SENTINEL;"));
    assert!(f.contains("core::ptr::write_volatile(&mut rmac_auth_receipt, crate::fi::FAIL_SENTINEL);"));
    assert!(f.contains("core::ptr::write_volatile(&mut renc_receipt, crate::fi::FAIL_SENTINEL);"));
    // Exactly one call to each verifier, and exactly two independent volatile
    // success checks per receipt before any depad/copy/counter/Ok.
    assert_eq!(f.matches("verify_rmac_into(").count(), 1);
    assert_eq!(f.matches("verify_renc_relation_into(").count(), 1);
    assert_eq!(
        f.matches("core::ptr::read_volatile(&rmac_auth_receipt)").count(),
        2,
        "two independent volatile R-MAC receipt checks required"
    );
    assert_eq!(
        f.matches("core::ptr::read_volatile(&renc_receipt)").count(),
        2,
        "two independent volatile R-ENC relation receipt checks required"
    );
    // Order: R-MAC gate → case-2 branch → decrypt → R-ENC relation gate →
    // depad → receipt-bound copy → counter advance → Ok. The relation gate
    // must sit between the decrypt and the depad (verify-then-parse).
    let p_rmac = f.find("verify_rmac_into(").unwrap();
    let p_case2 = f.find("if body_end == 0 {").unwrap();
    let p_dec = f.find("aes128_cbc_decrypt(&session.s_enc, &icv, &mut plain[..body_end]);").unwrap();
    let p_renc = f.find("verify_renc_relation_into(").unwrap();
    let p_depad = f.find("// ISO 7816-4 depad").unwrap();
    let p_copy = f.find("crate::rng_exact::copy_exact(&plain[..plaintext_len], &mut out[..plaintext_len])").unwrap();
    let p_inc = f.rfind("session.inc_counter();").unwrap();
    assert!(
        p_rmac < p_case2 && p_case2 < p_dec && p_dec < p_renc && p_renc < p_depad && p_depad < p_copy && p_copy < p_inc,
        "gate order: R-MAC → case2 → decrypt → R-ENC relation → depad → copy_exact → counter"
    );
}

#[test]
fn negative_scp03_unwrap_has_no_infective_mask_or_early_sentinel_gate() {
    let f = unwrap_response_src();
    // The complementing infective mask is gone — it returned Ok on a
    // mismatch and was invertible by the attacker.
    assert!(!f.contains("release_mask"));
    assert!(!f.contains("mac_matches"));
    assert!(!f.contains("wrapping_sub(1)"));
    assert!(!f.contains("p ^ "));
    // The single-skip-defeatable early sentinel gate is gone — the receipt
    // gate is the only R-MAC decision.
    assert!(!f.contains("check_true_into_sentinel"));
    // The plaintext release must go through the receipt-bound exact copy,
    // never a plain memcpy (a skipped memcpy releases stale bytes behind Ok).
    assert!(f.contains("crate::rng_exact::copy_exact(&plain[..plaintext_len], &mut out[..plaintext_len])"));
    assert!(!f.contains("out[..plaintext_len].copy_from_slice(&plain[..plaintext_len]);"));
}

#[test]
fn positive_scp03_send_apdu_copy_is_receipt_bound() {
    // Wave-18 follow-up: send_apdu's handoff into the caller buffer must be
    // the receipt-bound exact copy — a skipped plain memcpy would leave stale
    // bytes from a previous response behind an Ok, and the downstream
    // exact-copy receipts would faithfully certify the stale staging buffer.
    assert!(APDU_SRC.contains("crate::rng_exact::copy_exact(&resp_slice[..data_len], &mut resp_buf[..data_len])"));
    assert!(!APDU_SRC.contains("resp_buf[..data_len].copy_from_slice(&resp_slice[..data_len]);"));
}

#[test]
fn positive_scp03_bare_error_handling_unchanged() {
    // Legitimate bare-error handling (GP Amd D §6.2.5 first paragraph: no
    // R-MAC on an error SW) must NOT be weakened by the receipt gate: the
    // n == 2 arm still copies the SW, advances the counter (the card burned
    // the command's counter value), and returns Ok(2).
    let f = unwrap_response_src();
    let bare = f.find("if n == 2 {").expect("bare-error arm exists");
    let gate = f.find("verify_rmac_into(").expect("receipt gate exists");
    assert!(bare < gate, "bare-error arm stays ahead of (outside) the receipt gate");
    let bare_body = &f[bare..gate];
    assert!(bare_body.contains("out[0] = wrapped[0];"));
    assert!(bare_body.contains("out[1] = wrapped[1];"));
    assert!(bare_body.contains("session.inc_counter();"));
    assert!(bare_body.contains("return Ok(2);"));
}


#[test]
fn positive_scp03_counter_starts_at_one() {
    // GP Amendment D: the SCP03 command counter starts at 1 after
    // EXTERNAL AUTH. Starting at 0 would compute the wrong ICV for the
    // first command (since ICV = AES-ECB(s_enc, counter)) and every
    // wrapped APDU would fail.
    assert!(SCP03_SRC.contains("session.counter = [0; 16];"));
    assert!(SCP03_SRC.contains("session.counter[15] = 0x01;"));
}

#[test]
fn positive_scp03_command_icv_uses_s_enc_aes_ecb() {
    assert!(SCP03_SRC.contains("fn command_icv(session: &Scp03Session) -> [u8; 16] {"));
    assert!(SCP03_SRC.contains("aes128_ecb_encrypt(&session.s_enc, &session.counter)"));
}

#[test]
fn positive_scp03_iso7816_padding_used_in_wrap() {
    // ISO 7816-4 padding: 0x80 then zeros to next 16-byte block.
    assert!(SCP03_SRC.contains("enc_buf[padded_len] = 0x80;"));
    assert!(SCP03_SRC.contains("while padded_len % 16 != 0 {"));
    assert!(SCP03_SRC.contains("enc_buf[padded_len] = 0x00;"));
}

#[test]
fn positive_scp03_cmac_8byte_truncation() {
    // SCP03 truncates the 16-byte CMAC tag to the first 8 bytes.
    // Pin both the MAC append in `wrap_apdu` and the host-cryptogram
    // truncation in `establish_with_keys`. Forgetting the truncation
    // emits a 16-byte tag and the chip rejects.
    assert!(SCP03_SRC.contains("out[mac_offset..mac_offset + 8].copy_from_slice(&mac_full[..8]);"));
    assert!(SCP03_SRC.contains("let host_cryptogram = &host_crypto_full[..8];"));
    assert!(SCP03_SRC.contains("ext_auth[13..21].copy_from_slice(&mac_full[..8]);"));
}

#[test]
fn positive_scp03_cla_flips_secure_messaging_bit() {
    // Per ISO 7816-4 / GP secure messaging, the CLA byte gets bit 2
    // (0x04) set for an SCP03-wrapped APDU. Drop this and the chip
    // misparses every wrapped command as raw.
    assert!(SCP03_SRC.contains("out[0] = apdu[0] | 0x04; // Set CLA security bit"));
}

#[test]
fn positive_scp03_inc_counter_carries_correctly() {
    // The counter is a 16-byte big-endian integer; wrapping_add carries
    // upward through every byte until a non-zero byte is reached.
    // Cross-check the docs claim with a small Rust re-implementation.
    fn inc(counter: &mut [u8; 16]) {
        for i in (0..16).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
    let mut c = [0u8; 16];
    c[15] = 0xFF;
    inc(&mut c);
    assert_eq!(c[15], 0x00);
    assert_eq!(c[14], 0x01, "carry should propagate to byte 14");
    let mut c2 = [0xFFu8; 16];
    inc(&mut c2);
    assert_eq!(c2, [0u8; 16], "full wrap → all zeros");
    // Pin the production loop too.
    assert!(SCP03_SRC.contains("fn inc_counter(&mut self) {"));
    assert!(SCP03_SRC.contains("for i in (0..16).rev() {"));
    assert!(SCP03_SRC.contains("self.counter[i] = self.counter[i].wrapping_add(1);"));
}

// ═════════════════════════════════════════════════════════════════════
// 7. POSITIVE — `mod.rs` OID assignments
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_userid_obj_in_v6_range() {
    assert!(MOD_SRC.contains("pub const USERID_OBJ: u32 = 0x7B10_0000;"));
}

#[test]
fn positive_entropy_vk_bvk_obj_byte_exact() {
    assert!(MOD_SRC.contains("pub const ENTROPY_OBJ: u32 = 0x7B10_0001;"));
    assert!(MOD_SRC.contains("pub const VK_OBJ: u32 = 0x7B10_0002;"));
    assert!(MOD_SRC.contains("pub const BOOTSTRAP_VK_OBJ: u32 = 0x7B10_0003;"));
}

#[test]
fn positive_admin_wipe_obj_is_v6_a0() {
    assert!(MOD_SRC.contains("pub const ADMIN_WIPE_OBJ: u32 = 0x7B10_00A0;"));
}

// ═════════════════════════════════════════════════════════════════════
// 8. POSITIVE — `apdu.rs` GetRandom + iterative-delete reserved range
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_get_random_chunks_large_requests() {
    // Silicon (2026-05-28): a single GetRandom over SCP03 caps at 224 B
    // (240 B → SW=0x6985). `get_random` therefore chunks any request
    // larger than GET_RANDOM_MAX_CHUNK across multiple APDUs (mirrors
    // the NXP SDK loop). Pin: the empty guard, the per-chunk cap, and
    // the fill loop.
    assert!(APDU_SRC.contains("if out.is_empty() {"));
    assert!(APDU_SRC.contains("const GET_RANDOM_MAX_CHUNK: usize = 128;"));
    assert!(APDU_SRC.contains("(out.len() - filled).min(GET_RANDOM_MAX_CHUNK)"));
    // The old unconditional `> 256 → InvalidParam` reject must be gone
    // (it would have rejected legitimate larger requests).
    assert!(!APDU_SRC.contains("out.len() > 256"));
}

#[test]
fn positive_iterative_delete_skips_reserved_ranges() {
    // The applet-reserved range (0x7FFFxxxx), the demo-auth range
    // (0x7DA0xxxx), and the IoT-Hub trust-provisioned range
    // (>=0xF000_0000) MUST be skipped. Wiping them returns SW=0x6986
    // and can desync the chip's internal state.
    assert!(APDU_SRC.contains("(id & 0xFFFF_0000) == 0x7FFF_0000"));
    assert!(APDU_SRC.contains("(id & 0xFFF0_0000) == 0x7DA0_0000"));
    assert!(APDU_SRC.contains("id >= 0xF000_0000"));
    assert!(APDU_SRC.contains("if id == 0"));
}

#[test]
fn positive_delete_object_swallows_0x6985_idempotent() {
    // delete_object treats 0x6985 ("already deleted" / "not found") as
    // Ok so the cleanup loop is idempotent on objects that vanish
    // between read_id_list and delete.  Per AN12413 Table 125 page 71
    // the only documented SW for DELETE is 0x9000; 0x6985 is the
    // empirical "no such OID" code (NXP plug-and-trust accepts it the
    // same way).
    assert!(APDU_SRC
        .contains("Err(Se050Error::Status(0x6985)) => Ok(()), // doesn't exist — idempotent"));
}

#[test]
fn negative_delete_object_does_not_swallow_0x6986() {
    // S-7b fix: SW=0x6986 (`kSE05x_SW12_COMMAND_NOT_ALLOWED` per
    // NXP plug-and-trust `se05x_enums.h:84`) is policy-DENIED —
    // distinct from "not found".  Pre-S-7b the code silently mapped
    // this to Ok, hiding real policy-denial bugs (unauthenticated
    // sweep pretending to succeed on UserID objects).  Now it MUST
    // propagate as Err so callers can distinguish "already gone"
    // from "needs different auth".  Regression: a future refactor
    // re-adding `0x6986 => Ok(())` breaks this test.
    assert!(!APDU_SRC.contains("0x6986)) => Ok(())"));
}

#[test]
fn positive_check_exists_swallows_0x6985_as_not_found() {
    assert!(APDU_SRC.contains("Err(Se050Error::Status(0x6985)) => Ok(false),"));
}

// ═════════════════════════════════════════════════════════════════════
// 9. POSITIVE — `apdu.rs` session-wrapped commands (HW lesson #5)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn positive_read_authed_inner_uses_tag_1_only() {
    // HW lesson #5: DO NOT include TAG_2 (offset) or TAG_3 (length)
    // inside an INS_PROCESS wrapper — that triggers SW=0x6985 from the
    // chip. The inner read APDU only carries TAG_1(obj_id) + Le.
    assert!(APDU_SRC.contains("io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);"));
    assert!(APDU_SRC.contains("inner[io] = 0x00; // Le inside inner command"));
    // Make sure we DON'T put TAG_2 or TAG_3 inside read_authed.
    let read_authed_body = APDU_SRC
        .split("pub unsafe fn read_authed(")
        .nth(1)
        .expect("read_authed defined");
    let body_only = read_authed_body
        .split("pub unsafe fn ")
        .next()
        .expect("isolate read_authed body");
    assert!(
        !body_only.contains("TAG_2") && !body_only.contains("TAG_3"),
        "HW lesson #5: read_authed inner must not include TAG_2 or TAG_3"
    );
}

#[test]
fn positive_verify_session_dual_status_word_coalesce() {
    // Both 0x6985 (auth method not satisfied) and any 0x63xx (counter
    // decrement) collapse to a single `PinIncorrect` so the firmware
    // doesn't expose a side channel discriminating one from the other.
    assert!(
        APDU_SRC.contains("Err(Se050Error::Status(sw)) if sw == 0x6985 || (sw & 0xFF00) == 0x6300")
    );
    assert!(APDU_SRC.contains("Err(Se050Error::PinIncorrect)"));
}

#[test]
fn positive_session_wrapping_uses_tag_session_id_outer() {
    // Every session-bound command wraps as TAG_SESSION_ID(8) + TAG_1
    // inside an INS_PROCESS APDU. Pin the outer envelope shape so
    // a refactor that flipped the tag order silently breaks every
    // session-authed APDU.
    let session_callers = [
        "pub unsafe fn verify_session(",
        "pub unsafe fn read_authed(",
        "pub unsafe fn delete_object_authed(",
        "pub unsafe fn close_session(",
    ];
    for caller in session_callers {
        let body = APDU_SRC
            .split(caller)
            .nth(1)
            .unwrap_or("")
            .split("pub unsafe fn ")
            .next()
            .unwrap_or("");
        assert!(
            body.contains("apdu.tlv(TAG_SESSION_ID, session_id);"),
            "{caller} must wrap with TAG_SESSION_ID at outer level"
        );
        assert!(
            body.contains("ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);"),
            "{caller} must use INS_PROCESS outer envelope"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 10. NEGATIVE — wire-format / algorithm stability pins
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_crc16_algorithm_shape_stable() {
    // The IFX/GP 1.0 nibble polynomial 0x8408 is silicon-locked at the
    // chip side; a refactor that swapped to the standard 0x1021 form
    // (CRC-16/CCITT-FALSE) would silently break every frame and every
    // ATR. Pin the exact algorithm lines verbatim.
    // The algorithm moved to `sphincs_tz_shared::t1_frame` (2026-07-17) so it
    // could be Kani-proven; the driver re-exports it. These pins follow it —
    // they are NOT deleted, because the Kani round-trip proves build/validate
    // agree with EACH OTHER and would stay green if BOTH were changed to a
    // different CRC. Only these constants tie us to the chip's silicon-locked
    // choice, which no host-side proof can reach.
    assert!(
        T1_FRAME_SRC.contains("let mut crc: u16 = 0xFFFF;"),
        "init constant must remain 0xFFFF"
    );
    assert!(
        T1_FRAME_SRC.contains("crc = (crc >> 1) ^ 0x8408;"),
        "the reflected polynomial constant 0x8408 (mirror of 0x1021) must remain"
    );
    assert!(
        T1_FRAME_SRC.contains("crc ^= 0xFFFF;"),
        "final XOR with 0xFFFF must remain"
    );
    assert!(
        T1_FRAME_SRC.contains("crc // GP 1.0: no byte-swap"),
        "GP 1.0 explicitly does NOT byte-swap the CRC; the standard \
         T1 variant DOES — swapping the comment away tells future devs \
         the byte-swap is OK, which silently breaks every frame"
    );
    // And the driver must consume the proven copy, not grow a second one.
    assert!(
        !T1OI2C_SRC.contains("fn crc16(data: &[u8]) -> u16 {"),
        "t1oi2c.rs re-grew a local crc16 — a second copy beside the proven one \
         proves only that the two copies agree. Re-export, do not duplicate."
    );
}

#[test]
fn negative_crc16_not_standard_ccitt_false() {
    // CRC-16/CCITT-FALSE produces 0x29B1 for the canonical "123456789"
    // input. GP 1.0 must produce something else; if they ever match,
    // someone "fixed" the CRC to be more standard and broke the chip.
    let gp10 = gp10_crc16(b"123456789");
    assert_ne!(
        gp10, 0x29B1,
        "GP 1.0 CRC-16 must NOT equal CRC-16/CCITT-FALSE; if they match \
                the polynomial / init / reflection have been silently swapped"
    );
}

#[test]
fn negative_crc16_catches_single_bit_flip() {
    let base = b"hello world";
    let crc_a = gp10_crc16(base);
    let mut mutated = *base;
    mutated[0] ^= 0x01;
    let crc_b = gp10_crc16(&mutated);
    assert_ne!(
        crc_a, crc_b,
        "CRC-16 must catch single-bit flips; equal CRCs would mean \
                we're emitting a constant rather than hashing the bytes"
    );
}

#[test]
fn negative_build_frame_layout_matches_production_pins() {
    // Pin every byte position of the GP 1.0 build_frame implementation
    // so a refactor that moved to the legacy LEN(1) layout (compatible
    // with the older T=1' variant) silently breaks every chip.
    // Followed the extraction to `sphincs_tz_shared::t1_frame` (2026-07-17).
    assert!(T1_FRAME_SRC.contains("buf[0] = NAD_HOST_TO_SE;"));
    assert!(T1_FRAME_SRC.contains("buf[1] = pcb;"));
    assert!(T1_FRAME_SRC.contains("buf[2] = (len >> 8) as u8; // LEN MSB"));
    assert!(T1_FRAME_SRC.contains("buf[3] = (len & 0xFF) as u8; // LEN LSB"));
    assert!(T1_FRAME_SRC.contains("pub const HEADER_LEN: usize = 4;"));
    assert!(T1_FRAME_SRC.contains("HEADER_LEN + len + 2 // NAD + PCB + LEN(2) + INF + CRC16"));
    // The driver must call the proven builder rather than re-implement it.
    assert!(
        T1OI2C_SRC.contains("pub use sphincs_tz_shared::t1_frame::build_frame;"),
        "t1oi2c.rs must re-export the Kani-proven build_frame"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 11. NEGATIVE — T1' protocol bytes
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_t1_nad_host_to_se_is_0x5a() {
    // SE050 UM11225: NAD 0x5A is the host-to-card direction byte;
    // 0xA5 is the SOF the chip emits on the return path. Swapping them
    // silently makes every write malformed at the chip and every read
    // ignored at the host.
    assert!(T1_FRAME_SRC.contains("pub const NAD_HOST_TO_SE: u8 = 0x5A;"));
}

#[test]
fn negative_t1_sof_byte_is_0xa5() {
    // The SE050 → host SOF (start-of-frame) byte. The read loop polls
    // until it sees this value, then bulk-reads the rest of the frame.
    // Changing it makes the SOF poll spin forever (T1Error::Timeout).
    assert!(T1OI2C_SRC.contains("const SOF: u8 = 0xA5;"));
}

#[test]
fn negative_t1_pcb_constants_pin() {
    // Each PCB bit position carries a specific meaning per ISO 7816-3
    // T=1. Mistyping any bit silently changes the frame type the SE050
    // sees.
    assert!(T1OI2C_SRC.contains("const PCB_I_BLOCK: u8 = 0x00;"));
    assert!(T1OI2C_SRC.contains("const PCB_I_CHAIN: u8 = 0x20;"));
    assert!(T1OI2C_SRC.contains("const PCB_I_SEQ: u8 = 0x40;"));
    assert!(T1OI2C_SRC.contains("const PCB_R_BLOCK: u8 = 0x80;"));
    assert!(T1OI2C_SRC.contains("const PCB_S_WTX_REQ: u8 = 0xC3;"));
    assert!(T1OI2C_SRC.contains("const PCB_S_WTX_RSP: u8 = 0xE3;"));
    assert!(T1OI2C_SRC.contains("const PCB_S_INTF_RESET_REQ: u8 = 0xCF;"));
}

#[test]
fn negative_t1_ifsc_is_254() {
    // SE050 spec maxes the I-frame info-field size at 254 bytes; any
    // larger and the chip silently drops the trailing bytes. Pin both
    // the constant and the derived MAX_FRAME.
    assert!(T1OI2C_SRC.contains("const IFSC: usize = 254;"));
    assert!(T1OI2C_SRC.contains("const MAX_FRAME: usize = IFSC + 6;"));
}

#[test]
fn negative_t1_wtx_retry_ceiling_present() {
    // Without a retry cap the chip can keep requesting WTX forever,
    // turning a transient I/O glitch into an infinite hang in the
    // secure-world transceive loop (DoS the gateway).
    assert!(T1OI2C_SRC.contains("const MAX_WTX_RETRIES: u32 = 500;"));
    assert!(T1OI2C_SRC.contains("if wtx_count > MAX_WTX_RETRIES {"));
    assert!(T1OI2C_SRC.contains("return Err(T1Error::Timeout);"));
}

#[test]
fn negative_t1_read_retry_ceiling_present() {
    // Same DoS reasoning: bounded retries on the SOF-polling read loop.
    assert!(T1OI2C_SRC.contains("const MAX_READ_RETRIES: u32 = 1000;"));
    assert!(T1OI2C_SRC.contains("for _ in 0..MAX_READ_RETRIES {"));
}

#[test]
fn negative_t1_interface_reset_resets_sequence_numbers() {
    // GP 1.0 mandates that after an interface reset the N(S)/N(R)
    // counters restart at 0; otherwise the very first I-frame after
    // boot uses a stale PCB sequence bit and the chip refuses it.
    assert!(T1OI2C_SRC.contains("self.ns = 0;"));
    assert!(T1OI2C_SRC.contains("self.nr = 0;"));
}

#[test]
fn negative_t1_wtx_response_echoes_inf() {
    // The S(WTX_RSP) MUST echo the byte from the matching S(WTX_REQ);
    // sending an empty INF makes the chip retry and eventually give up.
    assert!(
        T1OI2C_SRC.contains("let wtx_frame_len = build_frame(PCB_S_WTX_RSP, inf, &mut tx_buf);")
    );
}

// ═════════════════════════════════════════════════════════════════════
// 12. NEGATIVE — APDU constants (defence against silent renames)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_max_apdu_buffer_is_1024() {
    // SE050 maximum APDU buffer size. A tighter limit cuts off long
    // chunked writes; a larger one risks stack overflow in the
    // secure-world ApduBuf which is `[u8; MAX_APDU]`.
    assert!(APDU_SRC.contains("const MAX_APDU: usize = 1024;"));
}

#[test]
fn negative_se050_aid_is_16_bytes_long() {
    // GP SELECT BY NAME with an AID of any other length is rejected by
    // the chip; pin the explicit slice length the `select_applet`
    // function emits.
    assert!(APDU_SRC.contains("apdu[4] = SE050_AID.len() as u8; // Lc"));
    assert!(APDU_SRC.contains("apdu[5..5 + SE050_AID.len()].copy_from_slice(SE050_AID);"));
}

#[test]
fn negative_session_id_is_8_bytes() {
    // GP / SE05x session IDs are 8 bytes. Truncating or extending
    // silently corrupts every session-wrapped command.
    assert!(APDU_SRC.contains("Result<[u8; 8], Se050Error>"));
    assert!(APDU_SRC.contains("let mut session_id = [0u8; 8];"));
    assert!(APDU_SRC.contains("session_id.copy_from_slice(&value[..8]);"));
    assert!(APDU_SRC.contains("session_id: &[u8; 8]"));
}

#[test]
fn negative_apdu_short_form_lc_cutoff_at_256() {
    // Short Lc is single-byte (0..=255); 256+ bytes MUST use the
    // extended-Lc 3-byte form (0x00 | hi | lo). A `< 255` typo here
    // silently truncates the 255-byte payload.
    assert!(APDU_SRC.contains("if payload_len < 256 {"));
    assert!(APDU_SRC.contains("self.buf[4] = 0x00;"));
    assert!(APDU_SRC.contains("self.buf[5] = (payload_len >> 8) as u8;"));
    assert!(APDU_SRC.contains("self.buf[6] = (payload_len & 0xFF) as u8;"));
}

#[test]
fn negative_admin_policy_grants_delete_only_not_read() {
    // CLAUDE.md invariant: even an admin-authenticated session must NOT
    // be able to READ user-PIN-gated secrets. The admin entry in
    // build_policy must OR exactly (AR_ALLOW_DELETE | AR_REQUIRE_SM) —
    // never AR_ALLOW_READ. A silent regression would let a leaked admin
    // PIN extract entropy.
    assert!(
        APDU_SRC.contains("let ar2 = (AR_ALLOW_DELETE | AR_REQUIRE_SM).to_be_bytes();"),
        "admin entry MUST be DELETE-only; granting READ here would let a \
         leaked admin PIN extract entropy gated by the user PIN"
    );
    // Make sure ALLOW_READ does NOT appear next to admin construction.
    let after_admin = APDU_SRC
        .split("if let Some(admin) = admin_auth {")
        .nth(1)
        .expect("admin branch present");
    let admin_block = after_admin
        .split("    }\n")
        .next()
        .expect("admin block isolated");
    assert!(
        !admin_block.contains("AR_ALLOW_READ"),
        "admin policy block must not reference AR_ALLOW_READ"
    );
}

#[test]
fn negative_user_policy_grants_full_access_through_user_userid() {
    // The default `write_binary_gated` user entry forwards the full
    // READ | WRITE | DELETE | REQUIRE_SM set to the shared core (the AR
    // is now an inline argument, not a `let primary_ar` binding). Scope
    // the search to write_binary_gated's body so we don't accidentally
    // match write_binary_write_once's (deliberately weaker) set.
    let gated_body = APDU_SRC
        .split("pub unsafe fn write_binary_gated(")
        .nth(1)
        .expect("write_binary_gated defined")
        .split("pub unsafe fn ")
        .next()
        .expect("isolate write_binary_gated body");
    assert!(gated_body.contains("AR_ALLOW_READ | AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM"));
}

#[test]
fn negative_write_once_drops_allow_write_keeps_read_delete() {
    // `write_binary_write_once` (half_E / VK / bootstrap_vk) must OMIT
    // ALLOW_WRITE — so a live PIN session can't re-seed the share in
    // place — while keeping READ (seed reconstruction) + DELETE
    // (admin/self teardown) + REQUIRE_SM. Pinning the exact forwarded AR
    // string proves WRITE is absent (a regression that re-added it would
    // change the string and fail this assert).
    let once_body = APDU_SRC
        .split("pub unsafe fn write_binary_write_once(")
        .nth(1)
        .expect("write_binary_write_once defined")
        .split("pub unsafe fn ")
        .next()
        .expect("isolate write_binary_write_once body");
    assert!(once_body.contains("AR_ALLOW_READ | AR_ALLOW_DELETE | AR_REQUIRE_SM"));
}

#[test]
fn negative_userid_policy_grants_write_delete_not_read() {
    // A UserID auth object itself shouldn't be ALLOW_READ — it stores
    // a PIN. Pin write_userid's primary_ar to (WRITE | DELETE | SM).
    let userid_body = APDU_SRC
        .split("pub unsafe fn write_userid(")
        .nth(1)
        .expect("write_userid defined")
        .split("pub unsafe fn ")
        .next()
        .expect("isolate write_userid body");
    assert!(
        userid_body.contains("let primary_ar = AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;"),
        "UserID primary_ar must NOT include AR_ALLOW_READ"
    );
    assert!(
        !userid_body.contains("AR_ALLOW_READ"),
        "write_userid body must not OR in AR_ALLOW_READ"
    );
}

#[test]
fn negative_get_random_rejects_empty_and_nonexact_response() {
    // A 0-byte request is rejected (would send a useless APDU); pin the
    // empty guard + InvalidParam. Also pin the under-fill guard: if the
    // chip returns fewer bytes than the chunk requested, `get_random`
    // must error rather than leave the caller's buffer partially stale.
    assert!(APDU_SRC.contains("if out.is_empty() {"));
    assert!(APDU_SRC.contains("return Err(Se050Error::InvalidParam);"));
    assert!(APDU_SRC.contains("crate::rng_exact::copy_exact_into("));
    assert!(APDU_SRC.contains("value.as_ptr(),"));
    assert!(APDU_SRC.contains("let expected_value_offset = match n.checked_sub(chunk)"));
    assert!(APDU_SRC.contains(
        "let expected_value_pointer = unsafe { resp.as_ptr().add(expected_value_offset) };"
    ));
    assert!(APDU_SRC.contains("expected_value_pointer,"));
    assert!(APDU_SRC.contains("core::ptr::addr_of!(published_expected_source)"));
    assert!(APDU_SRC.contains("out.as_mut_ptr(),"));
    assert!(APDU_SRC.contains("filled,"));
    assert!(APDU_SRC.contains("crate::rng_exact::publish_region_pointer_into("));
    assert!(APDU_SRC.contains("core::ptr::addr_of!(published_destination)"));
    assert!(APDU_SRC.contains("crate::rng_exact::initialize_exact_progress_into("));
    assert!(APDU_SRC.contains("fn publish_verified_get_random_progress_into("));
    assert!(
        APDU_SRC.contains("let filled = unsafe { core::ptr::read_volatile(&completed_bytes) };")
    );
    assert!(APDU_SRC.contains("completed_a != current_a || current_a >= total_a"));
    assert!(APDU_SRC.contains("copied_a != expected_a"));
    assert!(APDU_SRC.contains("copied_b != expected_b"));
    assert!(APDU_SRC.contains("publish_verified_get_random_progress_into("));
    assert!(
        APDU_SRC
            .matches("core::ptr::read_volatile(&progress_init_receipt)")
            .count()
            >= 2
    );
    assert!(
        APDU_SRC
            .matches("core::ptr::read_volatile(&progress_receipt)")
            .count()
            >= 2
    );
    assert!(APDU_SRC.contains("crate::rng_exact::verify_exact_pair_into("));
    assert!(APDU_SRC.contains("tag as usize,"));
    assert!(APDU_SRC.contains("rest.len(),"));
    assert!(APDU_SRC.contains("core::ptr::read_volatile(&frame_receipt)"));
    assert!(RNG_EXACT_SRC.contains(
        "verify_exact_progress_into(&source_len, destination_len, &mut length_receipt)"
    ));
    assert!(RNG_EXACT_SRC.contains("source: *const u8,"));
    assert!(RNG_EXACT_SRC.contains("expected_source_slot: *const *const u8,"));
    assert!(RNG_EXACT_SRC.contains("destination_base: *mut u8,"));
    assert!(RNG_EXACT_SRC.contains("destination_offset: usize,"));
    assert!(RNG_EXACT_SRC.contains(
        "expected_destination_slot: *const *const u8,"
    ));
    assert!(
        RNG_EXACT_SRC
            .matches("copy_regions_are_disjoint(")
            .count()
            >= 3,
        "SE050 response copy must reject fault-created source/output aliasing twice"
    );
}

#[test]
fn negative_send_apdu_buffer_overflow_guarded() {
    // The post-response copy MUST refuse to overflow the caller's
    // `resp_buf` — a silent overflow into the SCP03 wrap scratch space
    // would let a malicious chip stomp on next-call state.
    assert!(APDU_SRC.contains("if data_len > resp_buf.len() {"));
    assert!(APDU_SRC.contains("return Err(Se050Error::BufferOverflow);"));
}

#[test]
fn negative_send_apdu_status_word_check_before_data_copy() {
    // If sw != SW_OK we must short-circuit BEFORE copying response
    // bytes into resp_buf — otherwise an error response can write
    // garbage into the caller's buffer and a subsequent `unwrap_or`
    // path may treat it as valid data.
    let send_body = APDU_SRC
        .split("pub unsafe fn send_apdu(")
        .nth(1)
        .expect("send_apdu defined")
        .split("pub unsafe fn ")
        .next()
        .expect("isolate body");
    let status_idx = send_body
        .find("if sw != SW_OK {")
        .expect("status-word check present");
    let copy_idx = send_body
        .find("crate::rng_exact::copy_exact(&resp_slice[..data_len]")
        .expect("response copy present");
    assert!(
        status_idx < copy_idx,
        "status-word check must come BEFORE the response copy; otherwise an \
         error response can stomp on the caller buffer"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 13. NEGATIVE — `i2c.rs` SE050 address
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_se050_i2c_address_is_0x48() {
    // OM-SE050ARD default 7-bit address. Any other value silently
    // addresses a different I²C slave (or no slave at all) and every
    // SE050 transaction NACKs.
    assert!(I2C_SRC.contains("pub const SE050_ADDR: u8 = 0x48;"));
}

#[test]
fn negative_i2c_uses_secure_alias_from_board_map() {
    // The SE050 bus address must come from an always-Secure alias so NS
    // code cannot redirect SE writes through a softer one. Which physical
    // bus that is became a board fact when pq1 moved the SE050 onto its own
    // I2C4, so the driver now imports `board::SE050_I2C_BASE` — pin the
    // import line, and pin BOTH boards' values for it so neither can drift
    // to a non-secure alias unnoticed.
    assert!(I2C_SRC.contains("use crate::board::SE050_I2C_BASE as I2C_BASE;"));
    assert!(I2C_SRC.contains("use crate::hw::mmio::{Reg32, RoReg32};"));

    const BOARD_MOD_SRC: &str = include_str!("../board/mod.rs");
    const BOARD_IOTA2_SRC: &str = include_str!("../board/iota2.rs");
    const BOARD_PQ1_SRC: &str = include_str!("../board/pq1.rs");

    // iota2: shares OPTIGA's I2C1. pq1: its own I2C4.
    assert!(BOARD_IOTA2_SRC.contains("pub const SE050_I2C_BASE: u32 = I2C1_S;"));
    assert!(BOARD_PQ1_SRC.contains("pub const SE050_I2C_BASE: u32 = I2C4_S;"));
    // Both are SECURE aliases (0x5..., not 0x4...).
    assert!(BOARD_MOD_SRC.contains("pub const I2C1_S: u32 = 0x5000_5400;"));
    assert!(BOARD_MOD_SRC.contains("pub const I2C4_S: u32 = 0x5000_8400;"));
    assert!(
        !I2C_SRC.contains("0x4000_"),
        "SE050 driver must never name a non-secure peripheral alias"
    );
}

#[test]
fn negative_i2c_nack_flag_clears_register() {
    // The NACK / BERR / ARLO error flags MUST be cleared via ICR after
    // detection — leaving them set traps the next transfer into the
    // same error path and the bus stays wedged.
    assert!(I2C_SRC.contains("REG.icr.write(ICR_NACKCF);"));
    assert!(I2C_SRC.contains("REG.icr.write(ICR_BERRCF);"));
    assert!(I2C_SRC.contains("REG.icr.write(ICR_ARLOCF);"));
}

#[test]
fn negative_i2c_timeout_bound_present() {
    // Otherwise a stuck flag loops forever in S-world — DoS for the
    // SE050 leg.
    assert!(I2C_SRC.contains("const TIMEOUT_LOOPS: u32 = 1_000_000;"));
    assert!(I2C_SRC.contains("for _ in 0..TIMEOUT_LOOPS {"));
}

// ═════════════════════════════════════════════════════════════════════
// 14. NEGATIVE — CLAUDE.md invariant pins (driver-level)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_se050_module_no_classical_signer_references() {
    // Invariant #5 — SPHINCS+C10 only. No classical signer (ECDSA,
    // P-256, Ed25519, secp256k1) MAY appear anywhere in the SE050
    // driver. Even a doc-comment reference is a smell because it
    // suggests future re-introduction.
    let needles = [
        "ecdsa",
        "ECDSA",
        "ed25519",
        "Ed25519",
        "secp256k1",
        "secp256r1",
        "p256",
        "P256",
    ];
    let all_sources = [APDU_SRC, SCP03_SRC, T1OI2C_SRC, I2C_SRC, MOD_SRC];
    for src in all_sources {
        for needle in needles {
            assert!(
                !src.contains(needle),
                "classical signer string `{needle}` appeared in SE050 driver \
                 — invariant #5 (SPHINCS+C10 only) violated"
            );
        }
    }
}

#[test]
fn negative_se050_admin_pin_is_zeroized_on_factory_reset_admin() {
    // Invariant #4: secrets must NOT linger. After factory_reset_admin,
    // the in-RAM admin_pin must be zeroized.
    assert!(MOD_SRC.contains("admin_pin.zeroize();"));
}

#[test]
fn negative_user_factory_reset_zeroizes_caches() {
    // Invariant #4 again — clearing UserID also clears the in-RAM
    // entropy / VK / bootstrap_vk caches; otherwise a re-unlock could
    // return stale secrets bound to a now-deleted UserID.
    assert!(MOD_SRC.contains("self.entropy_blob_cache.zeroize();"));
    assert!(MOD_SRC.contains("self.vk_cache.zeroize();"));
    assert!(MOD_SRC.contains("self.bootstrap_vk_cache.zeroize();"));
    assert!(MOD_SRC.contains("self.blob_cached.set_false();"));
}

#[test]
fn negative_unlock_uses_zeroize_barrier() {
    // The reconstructed entropy passes through S-RAM during unlock;
    // it MUST be zeroized + a fi::zeroize_barrier MUST follow so the
    // compiler can't elide the wipe.
    assert!(MOD_SRC.contains("entropy.zeroize();"));
    assert!(MOD_SRC.contains("crate::fi::zeroize_barrier();"));
}

#[test]
fn negative_blob_cached_uses_fi_bool_not_plain_bool() {
    // A plain `bool` for the "blob is loaded" flag is fault-injection
    // glitchable. The slice must use `crate::fih::FihBool` so a single
    // bit-flip can't bypass the `is_true_fi()` gate.
    assert!(MOD_SRC.contains("blob_cached: crate::fih::FihBool,"));
    assert!(MOD_SRC.contains("self.blob_cached.is_true_fi()"));
}

#[test]
fn negative_remaining_attempts_shared_max_attempts_const() {
    // The in-RAM `remaining` cache must initialise to
    // `sphincs_tz_shared::MAX_ATTEMPTS` — a hard-coded literal would
    // drift away from the user-facing max-10 policy shared by the SE050
    // runtime mirror and MCU page 124. OPTIGA E120 has its separate 32-use
    // hardware limit and is not governed by this cache constant.
    assert!(MOD_SRC.contains("remaining: sphincs_tz_shared::MAX_ATTEMPTS,"));
    assert!(MOD_SRC.contains("self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;"));
}

#[test]
fn negative_admin_userid_unlimited_via_explicit_api() {
    // S-7a: the admin UserID is provisioned with UNLIMITED attempts
    // — but via the explicit `write_userid_unlimited` function
    // (which omits TAG_MAX_ATTEMPTS, the AN12413-documented
    // unlimited encoding), NOT by passing the silent `0` sentinel
    // to `write_userid`.  Pre-S-7a `write_userid(..., 0, ...)`
    // silently dropped the TLV and produced an unlimited UserID —
    // a footgun: a caller meaning "lock after 0 attempts" got
    // "never lock".  Now `write_userid` rejects 0 with InvalidParam;
    // callers that need unlimited must say so explicitly.
    assert!(MOD_SRC.contains("write_userid_unlimited("));
    assert!(MOD_SRC.contains("ADMIN_WIPE_OBJ, admin_pin, None,"));
    assert!(MOD_SRC.contains("ADMIN_WIPE_OBJ, admin, None,"));
}

#[test]
fn negative_admin_userid_provisioning_uses_no_admin_ref() {
    // The admin UserID itself must NOT have a higher admin ref —
    // there is no "super-admin" above it.  Passing `Some(...)`
    // here would let a leaked secondary credential delete the
    // admin UserID and brick recovery on the next PIN lockout.
    //
    // S-7a refactor: the admin is now created via
    // `write_userid_unlimited` (the signature has no
    // `max_attempts` field; the admin entry is the trailing
    // argument).  Pin `None` as that trailing arg.
    assert!(MOD_SRC.contains("ADMIN_WIPE_OBJ, admin_pin, None,"));
}

#[test]
fn negative_user_userid_has_no_admin_ref_post_s6() {
    // S-6 fix (docs/security/security-review-2026-05.md §C-8): the user
    // UserID's policy MUST NOT contain an admin-delete entry.
    // If admin had DELETE on the user UserID, an admin
    // compromise could delete USERID_OBJ → recreate at the same
    // OID with attacker PIN → read ENTROPY_OBJ (whose policy
    // gates on USERID_OBJ by OID, not by instance).
    //
    // Pin the literal `USERID_OBJ, pin, max_attempts, None,`
    // — the trailing `None` is what closes the substitution
    // attack.  A future refactor that flips this back to
    // `admin_ref` (or `Some(...)`) re-opens the vulnerability
    // and must trip this test.
    assert!(MOD_SRC.contains("USERID_OBJ, pin, max_attempts, None,"));
    // Data objects KEEP admin-delete (DoS-wipe is acceptable —
    // the safety contract is data destruction, which the admin
    // path must be able to effect).  Pin that the data write
    // still passes `admin_ref`.
    assert!(MOD_SRC.contains("USERID_OBJ, admin_ref,"));
}

// ═════════════════════════════════════════════════════════════════════
// 15. NEGATIVE — feature-gate / dev-only fences
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_debug_log_only_gated_by_feature() {
    // Every `secure_log!` invocation in the slice must be either
    // `#[cfg(feature = "debug-log")]`-gated or live in code that's
    // itself feature-gated. Production builds must not emit log
    // messages (could leak side-channel info via timing of UART
    // emission). Pin that secure_log! appears only inside debug-log
    // gates.
    //
    // Direct check: count `secure_log!(` occurrences vs the count of
    // `#[cfg(feature = "debug-log")]` immediately preceding them. We
    // use a weaker assertion — every `secure_log!` call in `apdu.rs`,
    // `t1oi2c.rs`, `scp03.rs` (drivers without their own feature gate)
    // must have a `debug-log` cfg gate within 2 lines above it.
    for src in [APDU_SRC, T1OI2C_SRC, SCP03_SRC] {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("secure_log!(") {
                // Scan backward through the enclosing block: an opening
                // `{`, a same-indent `#[cfg(...)]`, or a `pub fn` line
                // bounds the search. If we find a debug-log gate along
                // the way, the call is properly fenced.
                let window_start = i.saturating_sub(8);
                let preceded =
                    (window_start..i).any(|j| lines[j].contains("#[cfg(feature = \"debug-log\")]"));
                assert!(
                    preceded,
                    "secure_log!() at line {} must be guarded by \
                     #[cfg(feature = \"debug-log\")] within 8 lines above; \
                     production builds must emit no driver logs",
                    i + 1
                );
            }
        }
    }
}

#[test]
fn negative_mod_se050_gate_present_in_main() {
    // The production `se050` module must remain gated on
    // `feature = "se050", not(test)`. Without `not(test)` the
    // hardware-only code would be pulled into host builds and break
    // every `cargo test` for the whole secure crate.
    let main_src = include_str!("../main.rs");
    assert!(
        main_src.contains("#[cfg(all(feature = \"se050\", not(test)))]\nmod se050;"),
        "main.rs must gate `mod se050` on (feature = \"se050\", not(test))"
    );
}

// ═════════════════════════════════════════════════════════════════════
// 16. NEGATIVE — KDF / domain-tag stability (CLAUDE.md "no casual
//     KDF tag changes")
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_unlock_kdf_tag_sphincs_master_unchanged() {
    // The master-secret KDF tag is what `derive_keypair_from_entropy`
    // is keyed against. Renaming silently re-keys every wallet ever
    // provisioned with the prior tag.
    assert!(MOD_SRC.contains("crate::crypto::kdf(b\"sphincs-master\", &entropy, 0);"));
}

// ═════════════════════════════════════════════════════════════════════
// 17. NEGATIVE — APDU buffer cursor and Lc encoding edge cases
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_apdu_buf_cursor_starts_at_7_for_extended_lc() {
    // The cursor reserves space for `header(4) + extended_Lc(3) = 7`,
    // then `finish()` compacts to short-Lc when the payload is small.
    // A regression to `cursor=5` would leave the extended-Lc slot
    // unwritten when the payload spills past 255 bytes.
    assert!(
        APDU_SRC.contains("// Cursor starts at offset 7 (past header + 3-byte extended Lc slot).")
    );
    assert!(APDU_SRC.contains("Self { buf, cursor: 7 }"));
}

#[test]
fn negative_apdu_buf_finish_handles_case1_and_case2() {
    // Case 1: zero payload, no Le → 4-byte header alone.
    // Case 2: zero payload, Le → header + Le=0x00 = 5 bytes.
    // Skipping these special cases makes `select_applet`-style minimal
    // commands malformed.
    assert!(APDU_SRC.contains("if payload_len == 0 && !with_le {"));
    assert!(APDU_SRC.contains("return &self.buf[..4];"));
    assert!(APDU_SRC.contains("if payload_len == 0 && with_le {"));
    assert!(APDU_SRC.contains("return &self.buf[..5];"));
}

#[test]
fn negative_apdu_buf_short_form_shifts_payload_left_by_two() {
    // After `finish()` decides short Lc, the payload (sitting at offset
    // 7 because we reserved extended-Lc room) must shift left to offset
    // 5; a missed shift leaves two zero bytes between Lc and payload
    // and the chip rejects the malformed APDU.
    assert!(APDU_SRC.contains("for i in 0..payload_len {"));
    assert!(APDU_SRC.contains("self.buf[5 + i] = self.buf[7 + i];"));
}

// ═════════════════════════════════════════════════════════════════════
// 18. NEGATIVE — Se050Error From<T1Error> + variant exhaustion
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_se050_error_variants_pin() {
    // The variants the unlock path matches on exhaustively MUST exist;
    // dropping `PinIncorrect` or `NotProvisioned` would compile-fail
    // call sites, but the safety story is that they must remain
    // distinct error classes (PIN attempt counter behaves differently
    // from a Transport glitch). Pin them.
    assert!(APDU_SRC.contains("pub enum Se050Error {"));
    assert!(APDU_SRC.contains("Transport,"));
    assert!(APDU_SRC.contains("Scp03,"));
    assert!(APDU_SRC.contains("Status(u16),"));
    assert!(APDU_SRC.contains("PinIncorrect,"));
    assert!(APDU_SRC.contains("NotProvisioned,"));
    assert!(APDU_SRC.contains("BufferOverflow,"));
    assert!(APDU_SRC.contains("InvalidParam,"));
}

#[test]
fn negative_se050_error_from_t1_collapses_to_transport() {
    // Every T1Error variant maps to Se050Error::Transport — a refactor
    // that distinguished e.g. CRC vs Timeout at the SE050 layer would
    // create a side channel (timing-distinguishable error response)
    // that's currently absent by design.
    assert!(APDU_SRC.contains("impl From<T1Error> for Se050Error {"));
    assert!(APDU_SRC.contains("Se050Error::Transport"));
}

// ═════════════════════════════════════════════════════════════════════
// 19. NEGATIVE — scp03 establish() probe-on-boot fallback
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_scp03_establish_fallback_requires_derived_and_allow_flags() {
    // The factory-key fallback in establish() must be gated on BOTH
    // `se050-derived-scp03` AND `se050-scp03-allow-factory-fallback`, so
    // a runtime-signing image (fallback flag off) FAILS CLOSED rather
    // than retrying with the published AN12436 keys. Scope to
    // establish()'s body and pin both required cfg features + the
    // fallback call they guard.
    let establish_body = SCP03_SRC
        .split("pub unsafe fn establish(")
        .nth(1)
        .expect("establish defined")
        .split("unsafe fn establish_with_keys(")
        .next()
        .expect("isolate establish body");
    assert!(establish_body.contains("feature = \"se050-derived-scp03\""));
    assert!(establish_body.contains("feature = \"se050-scp03-allow-factory-fallback\""));
    assert!(establish_body.contains("&PLATFORM_ENC, &PLATFORM_MAC"));
    // And the nonsense combo (fallback without derived) is compile-fenced.
    assert!(SCP03_SRC.contains("se050-scp03-allow-factory-fallback requires se050-derived-scp03"));
}

#[test]
fn negative_scp03_card_cryptogram_verified_before_session_active() {
    // The card cryptogram check MUST happen BEFORE `session.active =
    // true` — otherwise a malicious chip could short-circuit the auth
    // by sending OK status but a garbage cryptogram, and we'd happily
    // wrap-and-send our admin PIN under the chip's keys.
    let establish_body = SCP03_SRC
        .split("unsafe fn establish_with_keys(")
        .nth(1)
        .expect("establish_with_keys defined");
    let crypt_check = establish_body
        .find("if card_ok != crate::fi::OK_SENTINEL")
        .expect("hardened card cryptogram check present");
    let active_set = establish_body
        .find("session.active = true;")
        .expect("session.active set");
    assert!(
        crypt_check < active_set,
        "card cryptogram MUST be verified before session.active is set; \
         otherwise a malicious chip can fast-path itself into a session"
    );
    // The card-cryptogram verify is the twin of the R-MAC verify and must be
    // hardened identically (it authenticates the SE to the MCU on a tunnel a
    // desolder/bus-tamper adversary can attack). Pin CT + FI: recompute in a
    // double-evaluated `check_true_into_sentinel` closure, constant-time
    // `ct_eq_8`, `black_box` against CSE. (A plain `!=` here is both a timing
    // forgery oracle and single-fault-skippable — the class `make scp03-fi`
    // found on the R-MAC.)
    let region = &establish_body[..crypt_check];
    assert!(
        region.contains("check_true_into_sentinel"),
        "card cryptogram verify must be FI-doubled via check_true_into_sentinel"
    );
    assert!(
        region.contains("ct_eq_8(&mac[..8], &card_cryptogram[..])"),
        "card cryptogram verify must be constant-time via ct_eq_8"
    );
    assert!(
        region.contains("black_box"),
        "card cryptogram verify must use black_box to stop LLVM CSE-collapse"
    );
}

#[test]
fn negative_scp03_init_update_uses_ins_50_known_response_length() {
    // GP INITIALIZE UPDATE: INS=0x50, Lc=0x08 host challenge. The
    // response is parsed at fixed offsets; n<31 must be rejected
    // (KeyDivData(10)+KeyInfo(3)+CardChallenge(8)+CardCryptogram(8)
    // + SW(2) = 31).
    assert!(SCP03_SRC.contains("init_update[1] = 0x50; // INS_INITIALIZE_UPDATE"));
    assert!(SCP03_SRC.contains("init_update[4] = 0x08; // Lc"));
    assert!(SCP03_SRC.contains("if n < 31 {"));
}

#[test]
fn negative_scp03_session_state_zeroed_on_new() {
    // Fresh Scp03Session must be inactive with all-zero key material;
    // a stale value would let `wrap_apdu` MAC commands under wrong keys.
    assert!(SCP03_SRC.contains("pub const fn new() -> Self {"));
    assert!(SCP03_SRC.contains("s_enc: [0; 16],"));
    assert!(SCP03_SRC.contains("s_mac: [0; 16],"));
    assert!(SCP03_SRC.contains("s_rmac: [0; 16],"));
    assert!(SCP03_SRC.contains("mcv: [0; 16],"));
    assert!(SCP03_SRC.contains("counter: [0; 16],"));
    assert!(SCP03_SRC.contains("active: false,"));
}

#[test]
fn negative_scp03_wrap_apdu_no_op_when_inactive() {
    // Before `establish()` runs, `wrap_apdu` must passthrough — wrapping
    // under all-zero session keys would emit a recognisable garbage
    // pattern on the bus that's a known fingerprint of "we hold no
    // session yet".
    assert!(SCP03_SRC.contains("if !session.active || apdu.len() < 4 {"));
    assert!(SCP03_SRC.contains("out[..apdu.len()].copy_from_slice(apdu);"));
    assert!(SCP03_SRC.contains("return apdu.len();"));
}

#[test]
fn negative_scp03_counter_increments_per_command() {
    // Each wrapped command must bump the counter so the next ICV is
    // unique. Without the increment, the same plaintext under the same
    // session keys would emit identical ciphertexts (ECB-equivalent
    // leak).
    assert!(SCP03_SRC.contains("session.inc_counter();"));
}

// ═════════════════════════════════════════════════════════════════════
// 20. NEGATIVE — iterative_delete_all auth flow
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_iterative_delete_auth_ok_is_falsy_on_failure() {
    // The third return value distinguishes "wrong PIN" from "policy-
    // blocked" survivors — a refactor that lost the bool degrades the
    // caller's ability to gate retries.
    assert!(APDU_SRC.contains("Result<(u16, u16, bool), Se050Error>"));
    assert!(APDU_SRC.contains("return Ok((deleted, failed, false));"));
    assert!(APDU_SRC.contains("return Ok((deleted, 0, true));"));
}

#[test]
fn negative_iterative_delete_self_deletes_userid_after_auth_sweep() {
    // After the authed sweep, the UserID itself must be self-deleted —
    // otherwise the auth object lingers with a stale PIN and the next
    // provisioning trips Bug #28 ("USERID_OBJ exists after stale sweep").
    assert!(APDU_SRC.contains("if delete_object_authed(t1, scp03, &session_id, uid).is_ok()"));
    assert!(APDU_SRC.contains("&& !check_exists(t1, scp03, uid).unwrap_or(true)"));
}

#[test]
fn negative_iterative_delete_session_always_closed() {
    // Open sessions are a chip-side resource (max 4); leaking them
    // turns one failed cleanup into permanent session exhaustion.
    assert!(APDU_SRC.contains("let _ = close_session(t1, scp03, &session_id);"));
}

#[test]
fn negative_iterative_delete_per_id_ber_tlv_long_form_handled() {
    // ReadIDList responses can exceed 127 bytes; the parser must accept
    // the 0x81 / 0x82 long-form length encodings. Without them the
    // response after ~30 OIDs is truncated and the sweep falsely
    // declares success.
    assert!(APDU_SRC.contains("} else if len_byte == 0x81"));
    assert!(APDU_SRC.contains("} else if len_byte == 0x82"));
}

// ═════════════════════════════════════════════════════════════════════
// 21. NEGATIVE — admin_factory_reset / admin_exists invariants
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_admin_factory_reset_returns_err_on_survivors() {
    // The contract for the caller (page-125 erase gate, multi-chip wipe
    // coordinator): if any user object survives, return Err so the
    // caller doesn't advance state. Returning Ok would falsely confirm
    // a complete wipe.
    assert!(MOD_SRC.contains("if surviving_count > 0 {"));
    assert!(MOD_SRC.contains("return Err(Se050Error::Status(0x6986));"));
}

#[test]
fn negative_admin_factory_reset_only_clears_caches_on_success() {
    // Caches must NOT be zeroized if the wipe was incomplete — leaving
    // them in a "ready for fresh provision" state lets the next unlock
    // try to read entropy that's still on the chip under a UserID we
    // no longer have a PIN for.
    let body = MOD_SRC
        .split("pub fn admin_factory_reset(")
        .nth(1)
        .expect("admin_factory_reset defined")
        .split("    pub fn ")
        .next()
        .expect("isolate body");
    let err_idx = body
        .find("return Err(Se050Error::Status(0x6986));")
        .expect("err return present");
    let zeroize_idx = body
        .find("self.entropy_blob_cache.zeroize();")
        .expect("zeroize present");
    assert!(
        err_idx < zeroize_idx,
        "early-return on survivors must happen BEFORE the cache zeroize"
    );
}

#[test]
fn negative_admin_exists_returns_false_on_init_failure() {
    // A failing `init()` (e.g. cold-boot timeout) MUST NOT trick the
    // caller into thinking the admin object is gone — that would let
    // the wipe-completion path erase page 125 prematurely.
    let body = MOD_SRC
        .split("pub fn admin_exists(")
        .nth(1)
        .expect("admin_exists defined")
        .split("    pub ")
        .next()
        .expect("body");
    assert!(body.contains("if self.init().is_err() {"));
    assert!(body.contains("return false;"));
}

#[test]
fn negative_pin_attempt_count_raw_skips_unlimited_userid() {
    // max_attempts == 0 is the SE050 sentinel for "unlimited"
    // (admin UserID). The boot-time reconcile must NOT compare against
    // it — otherwise an admin UserID would look "fully consumed"
    // because `auth_attempts` may be non-zero from prior probes.
    assert!(MOD_SRC.contains("if max_attempts == 0 {"));
    assert!(MOD_SRC.contains("// 0 = unlimited (admin UserID); reconcile is meaningless."));
    assert!(MOD_SRC.contains("return None;"));
}

#[test]
fn negative_pin_attempt_count_raw_requires_auth_attr_set() {
    // If `auth_attr != 0x01` the `auth_attempts` field is not the PIN
    // counter (object is a data blob, not an auth object). Pin the
    // explicit check.
    assert!(MOD_SRC.contains("if buf[5] != 0x01 {"));
}

// ═════════════════════════════════════════════════════════════════════
// 22. NEGATIVE — Se050::init() cold-boot retry loop
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_init_has_bounded_cold_boot_retry() {
    // Without a retry cap, a hung SE050 spins forever during init —
    // S-world DoS. Without the retry at all, a true cold-boot fails
    // first-attempt and the wallet appears unprovisioned.
    assert!(MOD_SRC.contains("const MAX_RESET_ATTEMPTS: u32 = 20;"));
    assert!(MOD_SRC.contains("for attempt in 0..MAX_RESET_ATTEMPTS {"));
    assert!(MOD_SRC.contains("if !reset_ok {"));
    assert!(MOD_SRC.contains("return Err(Se050Error::Transport);"));
}

#[test]
fn negative_init_idempotent_via_ready_flag() {
    // Repeated init() must short-circuit; otherwise every command
    // re-runs the slow interface-reset sequence (~50 ms wasted per call)
    // and bumps the cold-boot retry counter unnecessarily.
    assert!(MOD_SRC.contains("if self.ready {"));
    assert!(MOD_SRC.contains("return Ok(());"));
    assert!(MOD_SRC.contains("self.ready = true;"));
}

// ═════════════════════════════════════════════════════════════════════
// 23. NEGATIVE — feature-fence assertions for never-ship cfgs
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_e2e_only_force_remaining_gated_by_feature() {
    // `_e2e_force_remaining_to_max` must NEVER be in a production
    // build — it lets the test harness reset the chip-counter mirror
    // without burning a PIN attempt.
    assert!(MOD_SRC.contains("#[cfg(feature = \"e2e-test\")]\nimpl Se050 {"));
    assert!(MOD_SRC.contains("pub fn _e2e_force_remaining_to_max(&mut self) {"));
}

#[test]
fn negative_reset_e2e_objs_in_distinct_range() {
    // Test object IDs MUST be in the `0x7B07_xxxx` range so a chip with
    // production objects at `0x7B10_xxxx` isn't contaminated by running
    // the e2e selftest.
    assert!(MOD_SRC.contains("const TEST_USERID_OBJ: u32 = 0x7B07_0000;"));
    assert!(MOD_SRC.contains("const TEST_DATA_OBJ_A: u32 = 0x7B07_0001;"));
    assert!(MOD_SRC.contains("const TEST_DATA_OBJ_B: u32 = 0x7B07_0002;"));
}

// ═════════════════════════════════════════════════════════════════════
// 24. NEGATIVE — every `unsafe fn` is properly marked unsafe
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_apdu_command_wrappers_remain_unsafe() {
    // The SE05x wire-format command wrappers all touch hardware via T1
    // / SCP03 (and ultimately MMIO). Demoting them to safe would let
    // an NS caller invoke them without the secure-world precondition
    // dance (PIN unlock, dual-SE init order). Pin the `unsafe` keyword
    // on each public command function.
    let must_be_unsafe = [
        "pub unsafe fn send_apdu(",
        "pub unsafe fn select_applet(",
        "pub unsafe fn check_exists(",
        "pub unsafe fn write_userid(",
        "pub unsafe fn write_binary_gated(",
        "pub unsafe fn create_session(",
        "pub unsafe fn verify_session(",
        "pub unsafe fn read_authed(",
        "pub unsafe fn delete_object(",
        "pub unsafe fn delete_object_authed(",
        "pub unsafe fn read_object_attributes(",
        "pub unsafe fn iterative_delete_all(",
        "pub unsafe fn get_random(",
        "pub unsafe fn close_session(",
    ];
    for line in must_be_unsafe {
        assert!(
            APDU_SRC.contains(line),
            "{line} must remain `pub unsafe fn` — demoting to safe \
             would expose the wire-format wrappers to callers without \
             the secure-world preconditions"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 25. NEGATIVE — wrap_apdu output framing
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_wrap_apdu_extended_lc_used_when_new_lc_overflows_short() {
    // After SCP03 wrap, the new Lc = encrypted_data + 8-byte MAC. If
    // this exceeds 255 the APDU MUST switch to extended Lc; otherwise
    // the byte truncates to 0 and the chip mis-parses the Lc.
    assert!(SCP03_SRC.contains("let use_extended = extended || new_lc >= 256;"));
}

#[test]
fn negative_wrap_apdu_iso7816_padding_present() {
    // Encryption needs padding to a block boundary; SCP03 mandates
    // ISO 7816-4 (0x80 then zeros). Forgetting it makes the
    // AES-CBC final block underflow and the chip rejects.
    assert!(SCP03_SRC.contains("// ISO 7816-4 padding: 0x80 then zeros to next 16-byte boundary"));
}

// ═════════════════════════════════════════════════════════════════════
// 26. NEGATIVE — rotate_scp03_keys safety gate
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_rotate_scp03_refuses_published_keys() {
    // `rotate_scp03_keys` must refuse to PUT KEY the published factory
    // constants over themselves — that would mean the derived path
    // isn't actually selecting a per-device root and the ceremony is at
    // best a no-op, at worst a desync hazard.
    assert!(MOD_SRC.contains("if scp03::keys_are_factory_default(&new_enc, &new_mac, &new_dek) {"));
    assert!(MOD_SRC.contains("return Err(Se050Error::Scp03);"));
}

#[test]
fn negative_rotate_scp03_requires_active_session() {
    // The PUT KEY APDU must travel inside an established SCP03 session
    // (GP mandates auth). Pin the active-session check.
    assert!(MOD_SRC.contains("if !self.scp03.active {"));
}

// ═════════════════════════════════════════════════════════════════════
// 27. NEGATIVE — provision flow honours the dual-SE invariant
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_provision_admin_pin_derived_from_huk() {
    // Invariant #1 + the admin PIN reproducibility property: derive
    // from `secret_keys::se050_admin_pin()` (BHK / DHUK / OTP-master
    // depending on build). NEVER hard-code a literal admin PIN in
    // provisioning. Pin the call site.
    assert!(MOD_SRC.contains("crate::hw::secret_keys::se050_admin_pin()"));
}

#[test]
fn negative_provision_admin_pin_zeroized_at_end() {
    // Same secret-handling rule: the admin PIN passes through S-RAM
    // during provision and MUST be zeroized at the end.
    assert!(MOD_SRC.contains("admin_pin.zeroize();"));
}

// ═════════════════════════════════════════════════════════════════════
// 28. NEGATIVE — never-ship admin canary self-test runs at provision
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_provision_runs_policy_roundtrip_selftest() {
    // Bug #29 hardening: before installing user data we must run the
    // 6-canary admin-delete selftest so a TLV byte-order regression or
    // session-invalidation quirk crashes provisioning instead of
    // silently shipping with an un-wipeable admin policy.
    assert!(MOD_SRC.contains("self.policy_roundtrip_selftest(&admin_pin)"));
}

#[test]
fn negative_policy_roundtrip_uses_six_canaries() {
    // The original 2-canary selftest would miss a session-invalidation
    // quirk that bites on the Nth delete for N>2. Pin the 5 data
    // canaries + 1 UserID = 6 deletes.
    assert!(MOD_SRC.contains("const CANARY_DATA_OBJS: &[(u32, &str)] = &["));
    assert!(MOD_SRC.contains("(0x7B10_00B1, \"CANARY_DATA_1\"),"));
    assert!(MOD_SRC.contains("(0x7B10_00B2, \"CANARY_DATA_2\"),"));
    assert!(MOD_SRC.contains("(0x7B10_00B3, \"CANARY_DATA_3\"),"));
    assert!(MOD_SRC.contains("(0x7B10_00B4, \"CANARY_DATA_4\"),"));
    assert!(MOD_SRC.contains("(0x7B10_00B5, \"CANARY_DATA_5\"),"));
}

// ═════════════════════════════════════════════════════════════════════
// 29. NEGATIVE — store_objects (Bug #28) — fails loudly when stale
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_store_objects_fails_loud_on_stale_userid() {
    // If `userid_exists` after the admin-stale sweep, something went
    // wrong (either the sweep silently failed, or the on-chip policy
    // doesn't match the current ADMIN_WIPE_OBJ). Pin the loud
    // 0x6986 return; a silent skip would inherit a stale PIN gate.
    assert!(MOD_SRC.contains("if userid_exists && admin_pin.is_some() {"));
    assert!(MOD_SRC.contains("return Err(Se050Error::Status(0x6986));"));
}

// ═════════════════════════════════════════════════════════════════════
// 30. NEGATIVE — sync_remaining_with_mcu only shrinks, never grows
// ═════════════════════════════════════════════════════════════════════

#[test]
fn negative_sync_remaining_with_mcu_monotonic_down() {
    // This helper ratchets the SE050 driver's runtime mirror downward after
    // MCU accounting. It is not a three-input boot-reconciliation receipt:
    // the production UserID attribute read is policy-denied (0x6986).
    // Letting the runtime mirror GROW from an MCU-reported value would
    // silently extend the lockout horizon — an attacker who burns
    // attempts via a tamper sequence shouldn't get them back at boot.
    assert!(MOD_SRC.contains("if mcu_remaining < self.remaining {"));
    assert!(MOD_SRC.contains("self.remaining = mcu_remaining;"));
}

// ═════════════════════════════════════════════════════════════════════
// 31. §25 Gap 4 — UserID silicon-lock SW maps to PinLocked, fires wipe
// ═════════════════════════════════════════════════════════════════════
//
// When SE050's UserID auth_attempts hits max_attempts, the chip's
// object policy refuses further VERIFY and the chip returns
// SM_ERR_COMMAND_NOT_ALLOWED = 0x6986 ("Command not allowed — access
// denied based on object policy", per `se05x_tlv.h::smStatus_t` +
// AN13030 wording). The nominal production path never reaches this
// state — `MAX_ATTEMPTS = 10` is the same on MCU page-124 and SE050,
// so the MCU counter hits MAX first and `trigger_lockout_wipe` fires.
// But the corruption/desync case (MCU counter reset via flash fault,
// RDP regression mid-cycle, or dev-tool intervention while SE050 is
// silicon-locked) needs the runtime path to also wipe. Pre-fix, the
// 0x6986 fell through to the `Status(sw)` catch-all → `InternalError`
// → gateway treats it as transient → device stuck in a no-wipe loop.
//
// The fix lives in two places (both pinned below):
//   1. `apdu::verify_session`'s status-code match translates 0x6986
//      to a new `Se050Error::AuthMethodBlocked` variant.
//   2. `Se050::unlock`'s map_err (via the pure `classify_se050_unlock_
//      error` helper) maps `AuthMethodBlocked` to
//      `UnlockError::PinLocked`, which the gateway's
//      `Err(UnlockError::PinLocked) => trigger_lockout_wipe()` arm
//      handles directly.
//
// On-silicon empirical confirmation is the deferred step (next bench
// session with a throwaway UserID).

#[test]
fn gap4_apdu_translates_0x6986_to_auth_method_blocked() {
    // The apdu-layer arms that lift 0x6986 to a typed variant. If they
    // go away, 0x6986 would surface as `Se050Error::Status(0x6986)`
    // which the classify-fn maps to `InternalError` (no wipe) — exactly
    // the bug Gap 4 closes.
    //
    // Silicon correction (2026-05-28, `docs/secure-elements/se050-silicon-findings.md`
    // §4a): the lockout surfaces at `create_session` with SW=0x6986
    // (the chip refuses to open a session against a locked UserID),
    // not only at `verify_session`. BOTH call sites must translate it.
    assert!(
        APDU_SRC.contains("Err(Se050Error::AuthMethodBlocked)"),
        "apdu.rs must translate the lockout SW to AuthMethodBlocked"
    );
    assert!(
        APDU_SRC.contains("sw == 0x6986"),
        "verify_session must translate 0x6986 to AuthMethodBlocked"
    );
    assert!(
        APDU_SRC.contains(
            "Err(Se050Error::Status(0x6986)) => return Err(Se050Error::AuthMethodBlocked)"
        ),
        "create_session must translate the locked-UserID 0x6986 to AuthMethodBlocked; \
         on B-U585I-IOT02A the lockout is enforced at session creation"
    );
    // The variant must exist in the enum definition.
    assert!(
        APDU_SRC.contains("AuthMethodBlocked,"),
        "apdu.rs::Se050Error must declare the AuthMethodBlocked variant"
    );
    // 0x6982 must NOT be mapped to the lockout variant — it is the
    // recoverable A3 session-pending transient; mapping it would risk
    // a false-positive device wipe.
    assert!(
        !APDU_SRC.contains("sw == 0x6982"),
        "0x6982 must NOT map to AuthMethodBlocked — it is the recoverable A3 \
         session-pending transient, not a permanent lockout (false-positive wipe risk)"
    );
}

#[test]
fn gap4_unlock_dispatch_maps_auth_method_blocked_to_pin_locked() {
    // The unlock dispatch's pure helper. If this arm regresses to
    // `_ => UnlockError::InternalError` the gateway won't wipe on
    // silicon-lock — exact bug being defended against.
    assert!(
        MOD_SRC.contains("Se050Error::AuthMethodBlocked => UnlockError::PinLocked,"),
        "classify_se050_unlock_error must map AuthMethodBlocked to PinLocked"
    );
    // The bookkeeping side-effect (zeroing the in-RAM remaining
    // counter) must fire too — otherwise the remaining mirror lies
    // about the chip's actual state.
    assert!(
        MOD_SRC.contains("Se050Error::AuthMethodBlocked => {")
            && MOD_SRC.contains("self.remaining = 0;"),
        "unlock's side-effect arm must zero self.remaining on AuthMethodBlocked"
    );
}

#[test]
fn gap4_pin_incorrect_still_maps_to_pin_incorrect() {
    // Belt-and-braces: confirm the WRONG-PIN path didn't accidentally
    // get rerouted to PinLocked during the Gap 4 refactor. Mapping
    // wrong-PIN to PinLocked would wipe on the first mistyped digit —
    // catastrophic UX.
    assert!(
        MOD_SRC.contains("Se050Error::PinIncorrect => UnlockError::PinIncorrect,"),
        "classify_se050_unlock_error must keep PinIncorrect on the wrong-PIN path"
    );
}

#[test]
fn gap4_catch_all_still_maps_to_internal_error() {
    // Transport glitches, SCP03 errors, and unknown SWs must STILL
    // surface as InternalError (gateway treats as transient, no wipe).
    // A regression that broadened the wipe trigger to all errors would
    // silently DoS the user on a noisy I²C bus.
    assert!(
        MOD_SRC.contains("_ => UnlockError::InternalError,"),
        "classify_se050_unlock_error must keep the catch-all on InternalError"
    );
}

// ─────────────────────────────────────────────────────────────────────
// D1 — an inconclusive probe must never drive a mutation
// ─────────────────────────────────────────────────────────────────────

/// Slice `mod.rs` from a fn signature to the start of the next `    pub fn` /
/// `    fn` at the same indent, **with `//` line comments stripped**. Same
/// find-based idiom the OPTIGA slice uses.
///
/// The comment-stripping is load-bearing, not tidiness: these are
/// absence-assertions ("this fn must no longer contain X"), and the fix for X
/// is normally accompanied by a comment *explaining* X. Without stripping, the
/// explanation trips the gate that the explanation exists to document — and the
/// tempting "fix" is to weaken the assertion or delete the comment. Read code,
/// not prose.
fn fn_code(sig: &str) -> String {
    let start = MOD_SRC.find(sig).unwrap_or_else(|| panic!("{sig} exists"));
    let rest = &MOD_SRC[start + sig.len()..];
    let end = rest
        .find("\n    pub fn ")
        .or_else(|| rest.find("\n    fn "))
        .map_or(MOD_SRC.len(), |o| start + sig.len() + o);
    MOD_SRC[start..end]
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<std::vec::Vec<_>>()
        .join("\n")
}

/// `Se050Error::Transport` is a T=1' framing/CRC/timeout fault: the SE may
/// never have seen the command, or may have executed it and lost the reply. It
/// is NOT evidence about a credential or an object. Every other variant is
/// authoritative *because the SE spoke*.
#[test]
fn positive_se050_error_classifies_transport_as_inconclusive() {
    assert!(
        APDU_SRC.contains("matches!(self, Se050Error::Transport)"),
        "is_inconclusive must classify exactly Transport — a bus fault is the \
         only variant that is not an answer the SE gave"
    );
    assert!(APDU_SRC.contains("pub const fn is_inconclusive(&self) -> bool"));
}

/// **D1 regression guard — the SCP03 rotation probe.**
///
/// `rotate_scp03_transport_to_final` probes the FINAL keyset and, if the probe
/// fails, falls through to a PUT KEY that irreversibly installs it. The old
/// code used `establish_with(...).is_ok()`, which collapses "the SE rejected
/// these keys" (authoritative → not rotated yet) into the same bucket as "the
/// bus faulted" (inconclusive → we learned nothing). A single T=1' glitch
/// during a read-only probe therefore drove an irreversible key install.
#[test]
fn negative_scp03_rotation_probe_does_not_collapse_inconclusive_into_reject() {
    let f = fn_code("pub fn rotate_scp03_transport_to_final");
    assert!(
        !f.contains(
            "establish_with(&mut self.scp03, &mut self.t1, &final_enc, &final_mac).is_ok()"
        ),
        "D1: the FINAL-keyset probe collapsed a transport fault into 'not \
         rotated' and fell through to PUT KEY. Classify with is_inconclusive() \
         and fail closed — the ceremony is journal-resumable, so failing closed \
         IS the retry."
    );
    assert!(
        f.contains("Err(e) if e.is_inconclusive() => return Err(e)"),
        "the FINAL-keyset probe must fail closed on an inconclusive result \
         rather than proceed to the irreversible PUT KEY"
    );
}

/// **D1 regression guard — the admin existence probe.**
///
/// `check_exists` returns `Ok(bool)` when the SE answered and `Err` when we
/// could not ask. `.unwrap_or(false)` mapped "I don't know" onto "it's
/// missing" — and "missing" is the branch that WRITES a credential.
#[test]
fn negative_admin_existence_probe_does_not_unwrap_or_false_into_a_write() {
    let f = fn_code("pub fn rekey_admin_transport_to_final");
    assert!(
        !f.contains("unwrap_or(false)"),
        "D1: `check_exists(...).unwrap_or(false)` turns a bus glitch on a \
         READ-ONLY existence probe into 'object missing', which drives \
         write_userid_unlimited. Match on Ok(false)/Ok(true)/Err instead."
    );
    assert!(
        f.contains("Err(e) => return Err(e)"),
        "an unanswerable existence probe must propagate, not write"
    );
}
