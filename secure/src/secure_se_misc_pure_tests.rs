//! Host-side positive + negative test suite for the `secure-se-misc`
//! slice's two firmware-only files: `tropic01_se.rs` and
//! `semihosting_spi.rs`.
//!
//! Both files are gated `#[cfg(all(feature = "tropic01-se", not(test)))]`
//! (with an additional `not(stm32u585)` clause for `semihosting_spi.rs`)
//! at the crate root in `main.rs:115-120`. They cannot be host-compiled
//! because they depend on `cortex_m_semihosting`, `tropic01`, and
//! `x25519-dalek` — none of which link on x86_64 without target-arm
//! features. The pure-logic helpers in `scp03_logic.rs`, `cmac.rs`, and
//! `secure_element.rs` get the full `#[cfg(test)] mod tests` treatment
//! inline (see the bottom of each of those files); this scaffold
//! handles only the two firmware-only files.
//!
//! ## Mounting strategy
//!
//! Because these modules are firmware-only, the tests below are
//! `include_str!`-based source-text pins. Each pin encodes a
//! load-bearing invariant whose silent removal would otherwise pass
//! every host-side check while breaking a security property on
//! silicon. The patterns we pin:
//!
//!   * **`tropic01_se`** — constant-time tag verification (`ct_eq`),
//!     `Zeroize` on the recovered candidate + per-slot keys,
//!     `MAX_ATTEMPTS = 10`, PIN-state layout = 1+32+10*32 = 353 bytes,
//!     all SE ops are wrapped in `with_session!` (no plaintext I2C),
//!     the brick-on-10th-wrong-PIN path erases slots 0..3,
//!     `pairing_priv` private field name (no `pub` leakage),
//!     `setup_pairing` switches to slot 1, X25519 + AES-GCM in the
//!     session establishment doc-comment.
//!   * **`semihosting_spi`** — `MAX_FRAME = 300`, hex-only protocol
//!     framing (`"x\n"` suffix, `"OK\r\n"` ack on CS deassert), and
//!     the SpiError variants for every failure path.

#![cfg(test)]

// Source text of the two firmware-only files.
const TROPIC01_SRC: &str = include_str!("tropic01_se.rs");
const SEMIHOSTING_SRC: &str = include_str!("semihosting_spi.rs");

// ─────────────────────────────────────────────────────────────────────
// 1. semihosting_spi.rs — wire-format constants and protocol bytes
// ─────────────────────────────────────────────────────────────────────

mod semihosting_spi_tests {
    use super::SEMIHOSTING_SRC;

    /// Positive: `MAX_FRAME = 300` is the documented L2 limit + overhead.
    /// Pinned because the constant feeds into stack-allocated buffer
    /// sizes (`HEX_BUF_SIZE`, `READ_BUF_SIZE`); silently shrinking it
    /// would clip large frames mid-transfer; silently growing it would
    /// blow the secure-world stack.
    #[test]
    fn positive_max_frame_constant_is_300() {
        assert!(
            SEMIHOSTING_SRC.contains("const MAX_FRAME: usize = 300;"),
            "semihosting_spi MAX_FRAME constant changed — stack-buffer \
             sizes downstream depend on this exact value"
        );
    }

    /// Positive: hex buffer size is `MAX_FRAME * 2 + 4` (2 hex chars per
    /// byte + "x\n" terminator + margin).
    #[test]
    fn positive_hex_buf_size_equation_is_max_frame_times_two_plus_four() {
        assert!(
            SEMIHOSTING_SRC.contains("const HEX_BUF_SIZE: usize = MAX_FRAME * 2 + 4;"),
            "hex-buf size equation drifted — would clip the 'x\\n' framing terminator"
        );
    }

    /// Positive: the protocol's "send" terminator is `b"x\n"`. The
    /// host-side dongle script keys off this exact byte sequence; any
    /// drift breaks the encoded SPI bridge.
    #[test]
    fn positive_protocol_terminator_is_x_newline() {
        assert!(
            SEMIHOSTING_SRC.contains("tx_buf[tx_len] = b'x';")
                && SEMIHOSTING_SRC.contains("tx_buf[tx_len + 1] = b'\\n';"),
            "hex-protocol 'x\\n' terminator missing — host dongle parser \
             relies on this exact byte sequence"
        );
    }

    /// Positive: CS deassert sends `"CS=0\n"` and expects `"OK\r\n"`.
    /// These are part of the dongle's wire contract.
    #[test]
    fn positive_cs_deassert_protocol_strings() {
        assert!(SEMIHOSTING_SRC.contains("b\"CS=0\\n\""));
        assert!(SEMIHOSTING_SRC.contains("b\"OK\\r\\n\""));
    }

    /// PIN (negative): `SpiError` enum carries all five documented
    /// variants. If a refactor silently dropped one (say
    /// `HexParseError`), the parse-failure path would either panic or
    /// silently return arbitrary bytes from `data[..]`.
    #[test]
    fn negative_spi_error_variants_all_present() {
        for variant in [
            "OpenFailed",
            "WriteFailed",
            "ReadFailed",
            "ProtocolError",
            "HexParseError",
        ] {
            assert!(
                SEMIHOSTING_SRC.contains(variant),
                "SpiError variant {variant} missing — wire-protocol failure modes \
                 must each be distinguishable for telemetry + retry logic"
            );
        }
    }

    /// PIN (negative): the response length validator rejects
    /// `end != data.len() * 2`. A weaker check (e.g. `end <=
    /// data.len() * 2`) would let a short response through and the
    /// remaining bytes of `data[..]` would carry stale memory contents
    /// — an information-disclosure path if those bytes later get
    /// returned to the NS world.
    #[test]
    fn negative_response_length_validator_is_strict_equality() {
        assert!(
            SEMIHOSTING_SRC.contains("if end != data.len() * 2 {"),
            "response-length check weakened from strict equality — would \
             let a short response pass and leak stale buffer bytes downstream"
        );
    }

    /// PIN (negative): `parse_hex_nibble` rejects every byte not in
    /// `[0-9a-fA-F]`. A permissive parser (e.g. one that mod-16'd
    /// arbitrary bytes) would silently produce a different decoded
    /// value than the host sent — corrupting every SPI transfer.
    #[test]
    fn negative_parse_hex_nibble_returns_error_on_non_hex() {
        // The function has a catch-all arm that returns
        // Err(SpiError::HexParseError) for everything not in the hex range.
        assert!(
            SEMIHOSTING_SRC.contains("_ => Err(SpiError::HexParseError),"),
            "parse_hex_nibble's catch-all error arm missing — non-hex bytes \
             would be silently mod-16'd into the decoded data"
        );
    }

    /// PIN (negative): the read-byte retry loop terminates after
    /// 100_000 polls and returns `ReadFailed`. If the cap is silently
    /// removed (e.g. switched to `loop {}`), a stuck host serial port
    /// would hang the secure world indefinitely with no way to recover.
    #[test]
    fn negative_read_byte_retry_loop_is_bounded() {
        assert!(
            SEMIHOSTING_SRC.contains("for _ in 0..100_000 {"),
            "read_byte retry loop no longer bounded at 100_000 — a stuck \
             host serial port would hang the secure world indefinitely"
        );
    }

    /// PIN (negative): `SpiError::kind()` reports `ErrorKind::Other`
    /// (no specific embedded-hal mapping). Bumping this to a more
    /// specific kind without coordinating with the embedded-hal
    /// version in `Cargo.toml` would break the SpiDevice trait impl.
    #[test]
    fn negative_spi_error_kind_is_other() {
        assert!(
            SEMIHOSTING_SRC.contains("spi::ErrorKind::Other"),
            "embedded-hal ErrorKind mapping changed — coordinate with the \
             SpiDevice trait impl version"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 2. tropic01_se.rs — security-critical constants and patterns
// ─────────────────────────────────────────────────────────────────────

mod tropic01_se_tests {
    use super::TROPIC01_SRC;

    // ─────── positive coverage ────────────────────────────────────────

    /// Positive: `TROPIC01_MAX_ATTEMPTS = 10` matches the SE050 / Mock
    /// `MAX_ATTEMPTS = 10` in `pqsigner-proto`. Pinned because the
    /// reconcile path in `nsc::reconcile_pin_attempts` cross-checks the
    /// three counters; a drift would falsely flag tamper.
    #[test]
    fn positive_max_attempts_is_ten() {
        assert!(
            TROPIC01_SRC.contains("const TROPIC01_MAX_ATTEMPTS: u8 = 10;"),
            "TROPIC01_MAX_ATTEMPTS drifted from 10 — three-way PIN counter \
             reconciliation will false-positive tamper"
        );
    }

    /// Positive: per-slot ciphertext is exactly 32 bytes (XOR scheme,
    /// no AES-GCM tag). Saving the 16 bytes/slot from a GCM tag is
    /// what lets 10 attempts fit in the 475-byte r-mem limit.
    #[test]
    fn positive_per_slot_ct_len_is_32() {
        assert!(TROPIC01_SRC.contains("const T01_CT_LEN: usize = 32;"));
    }

    /// Positive: verification tag is 32 bytes (SHA-256 output).
    #[test]
    fn positive_pin_tag_len_is_32() {
        assert!(TROPIC01_SRC.contains("const T01_TAG_LEN: usize = 32;"));
    }

    /// Positive: PIN-state layout = `counter(1) + tag(32) + 10*ct(32) =
    /// 353` bytes, fits the 475-byte r-mem cap. A drift in any of the
    /// three sub-constants must surface here.
    #[test]
    fn positive_pin_state_total_is_353_bytes() {
        assert!(
            TROPIC01_SRC.contains(
                "const T01_PIN_STATE_LEN: usize = 1 + T01_TAG_LEN + TROPIC01_MAX_ATTEMPTS as usize * T01_CT_LEN;"
            ),
            "T01_PIN_STATE_LEN definition drifted — recompute against the \
             475-byte r-mem cap before changing"
        );
        // Cross-check the arithmetic in case the constants flip.
        assert_eq!(1 + 32 + 10 * 32, 353);
    }

    /// Positive: the on-success tag compare uses `ct_eq`
    /// (subtle::ConstantTimeEq) — defends timing side-channel on the
    /// happy path. A `==` byte compare leaks the first mismatching
    /// byte position.
    #[test]
    fn positive_pin_tag_compare_uses_constant_time_eq() {
        assert!(
            TROPIC01_SRC.contains("expected_tag.ct_eq(&ps.tag)"),
            "Tropic01 PIN tag compare must use ct_eq — a == compare leaks \
             the first mismatching byte position"
        );
        assert!(
            TROPIC01_SRC.contains("use subtle::ConstantTimeEq;"),
            "ConstantTimeEq trait import missing — ct_eq call would fail to compile"
        );
    }

    /// Positive: every secret-bearing temporary is zeroized. The
    /// wrong-PIN path explicitly zeroes the recovered-candidate
    /// `recovered_s`, and both paths zero the per-slot key `k_j` and
    /// MACD output `w_j` after use.
    #[test]
    fn positive_secrets_are_zeroized_on_pin_paths() {
        for needle in [
            "use zeroize::Zeroize;",
            "recovered_s.zeroize();",
            "k_j.zeroize();",
            "w_j.zeroize();",
        ] {
            assert!(
                TROPIC01_SRC.contains(needle),
                "missing zeroize call: {needle} — TROPIC01 PIN secret would \
                 linger in SRAM past its lifetime"
            );
        }
    }

    /// Positive: PIN state is laid out per the AppNote: byte 0 =
    /// counter (`next_index`), bytes 1..=32 = verification tag, bytes
    /// 33..353 = ten 32-byte XOR-encrypted master_secret blobs.
    #[test]
    fn positive_pin_state_layout_serializes_in_order() {
        // The `serialize_t01_pin_state` body writes the fields in
        // that order — pin the exact constants & layout.
        assert!(TROPIC01_SRC.contains("buf[0] = state.next_index;"));
        assert!(TROPIC01_SRC.contains("buf[1..1 + T01_TAG_LEN].copy_from_slice(&state.tag);"));
        assert!(TROPIC01_SRC.contains("let mut offset = 1 + T01_TAG_LEN;"));
    }

    /// Positive: brick-on-lockout erases slots 0..3 (entropy + PIN
    /// state + VK + bootstrap VK). All four wallet-data slots must be
    /// wiped, not just the entropy.
    #[test]
    fn positive_lockout_erases_all_four_wallet_slots() {
        let new_index_branch = TROPIC01_SRC
            .find("if new_index >= TROPIC01_MAX_ATTEMPTS {")
            .expect("brick-on-10th-attempt branch missing in tropic01_se.rs");
        // Look at the next ~500 chars for the four erase calls.
        let region = &TROPIC01_SRC[new_index_branch..new_index_branch.saturating_add(500)];
        for slot in 0u32..4 {
            let needle = format!("r_mem_data_erase(U16::new({slot}))");
            assert!(
                region.contains(&needle),
                "brick path missing erase of wallet slot {slot}",
            );
        }
    }

    /// Positive: `Tropic01SecureElement` exposes only the
    /// `pub const fn new()` constructor and `setup_pairing` (+
    /// `load_pairing_key`) — no `pub` accessor for `pairing_priv`.
    #[test]
    fn positive_pairing_priv_is_not_publicly_exposed() {
        assert!(
            TROPIC01_SRC.contains("pairing_priv: [u8; 32],"),
            "pairing_priv field renamed or removed"
        );
        // Any `pub` qualifier on the field would be a leak; the
        // surrounding `pub fn` accessors are OK, the field itself is not.
        assert!(
            !TROPIC01_SRC.contains("pub pairing_priv"),
            "pairing_priv must NOT be `pub` — leaking the per-device X25519 \
             private key over module boundaries breaks the Noise_KK1 model"
        );
    }

    /// Positive: per-device pairing key is written to slot 1, slot 0
    /// (devkit keys) is intentionally NOT invalidated as a fallback.
    /// The doc-comment explicitly calls this out.
    #[test]
    fn positive_setup_pairing_uses_slot_1_keeps_slot_0_fallback() {
        assert!(TROPIC01_SRC.contains("self.pairing_slot = 1;"));
        assert!(
            TROPIC01_SRC.contains("Slot 0 (devkit keys) is NOT invalidated"),
            "doc comment about slot 0 fallback removed — implementations \
             might assume slot 0 is destroyed after setup_pairing"
        );
    }

    // ─────── negative coverage ────────────────────────────────────────

    /// PIN: every chip op MUST go through `with_session!` — i.e. an
    /// end-to-end-encrypted Noise_KK1 + AES-256-GCM tunnel. A bare
    /// `session.r_mem_data_*` or `tropic.r_mem_*` outside the macro
    /// would mean unencrypted I2C/SPI — directly violating invariant
    /// #3 ("E2E encrypted SE tunnels").
    ///
    /// The macro expands to a `with_session!($se, $session, $body)`
    /// invocation; we count macro invocations and assert that every
    /// `Tropic01SecureElement` SE operation appears inside one.
    #[test]
    fn negative_every_se_op_is_wrapped_in_with_session() {
        // Three sites should NOT exist anywhere in the file outside
        // a `with_session!` macro body: bare `Tropic01::new(...)` or
        // `tropic.r_mem_data_*` or `tropic.mac_and_destroy*`.
        // The only `Tropic01::new(spi)` reference is inside the
        // macro itself.
        let new_count = TROPIC01_SRC.matches("Tropic01::new(spi)").count();
        assert_eq!(
            new_count, 1,
            "exactly one `Tropic01::new(spi)` allowed (inside `with_session!`); \
             every other call site MUST go through the macro to keep the \
             session encrypted",
        );
        // The bare `tropic.r_mem_...` / `tropic.mac_and_destroy` accesses
        // must NEVER appear outside the macro body. Grep for them:
        for forbidden in ["tropic.r_mem_data_read", "tropic.r_mem_data_write", "tropic.mac_and_destroy"] {
            assert!(
                !TROPIC01_SRC.contains(forbidden),
                "bare tropic.{forbidden}(...) call detected outside `with_session!` — \
                 would bypass the e2e-encrypted tunnel (invariant #3)"
            );
        }
    }

    /// PIN: tag compare MUST NOT use `==` on the recovered tag —
    /// would leak timing on the first mismatching byte and let an
    /// attacker brute-force the per-slot XOR key prefix.
    ///
    /// The check has two parts: (a) the file uses `ct_eq`, (b) there
    /// is no `== ps.tag` literal compare that would have shorted the
    /// constant-time path.
    #[test]
    fn negative_pin_tag_compare_does_not_use_byte_equality() {
        assert!(
            !TROPIC01_SRC.contains("== ps.tag")
                && !TROPIC01_SRC.contains("ps.tag ==")
                && !TROPIC01_SRC.contains("== expected_tag")
                && !TROPIC01_SRC.contains("expected_tag =="),
            "byte-equality compare on PIN tag — replaces the ct_eq path and \
             leaks first-mismatch timing"
        );
    }

    /// PIN: wrong-PIN path MUST zeroize the recovered master-secret
    /// candidate BEFORE returning. If a future refactor drops this
    /// call, the candidate (which encodes information about whether
    /// any of the 10 stored ciphertexts could be a valid wallet)
    /// lingers on the secure-world stack past the function return.
    #[test]
    fn negative_wrong_pin_path_zeroizes_recovered_secret() {
        // Find the wrong-PIN branch (the `else` after `if tag_ok`).
        let else_branch_idx = TROPIC01_SRC
            .find("} else {\n                // Wrong PIN")
            .expect("wrong-PIN branch marker missing from tropic01_se.rs");
        let region = &TROPIC01_SRC[else_branch_idx..else_branch_idx.saturating_add(400)];
        assert!(
            region.contains("recovered_s.zeroize();"),
            "wrong-PIN branch missing recovered_s.zeroize() — secret candidate \
             would linger on the secure-world stack past return"
        );
    }

    /// PIN: per-slot XOR key `k_j` is zeroized after the XOR
    /// reconstruction. A leaked k_j would let an attacker who has
    /// snooped one ciphertext blob recover the master_secret offline
    /// without the chip.
    #[test]
    fn negative_per_slot_xor_key_is_zeroized() {
        // Count occurrences in the function bodies — both
        // `store_data_session` and `batch_verify_pin` allocate a k_j.
        let count = TROPIC01_SRC.matches("k_j.zeroize();").count();
        assert!(
            count >= 2,
            "expected >=2 occurrences of k_j.zeroize() (store + verify paths); \
             found {count}"
        );
    }

    /// PIN: MACD output `w_j` is zeroized after use on every code path
    /// that allocates it. `w_j` is the per-slot master-derived secret
    /// — leaking it lets the chip's MACD result be replayed offline.
    #[test]
    fn negative_macd_output_is_zeroized() {
        let count = TROPIC01_SRC.matches("w_j.zeroize();").count();
        assert!(
            count >= 2,
            "expected >=2 occurrences of w_j.zeroize() (store + verify paths); \
             found {count}"
        );
    }

    /// PIN: the documented "wrong PIN → SlotExpired on 10th attempt"
    /// path returns `Err(SeError::SlotExpired)` from `batch_verify_pin`,
    /// which the `WalletStore::unlock` impl maps to
    /// `UnlockError::PinLocked`. The mapping table at the bottom of
    /// the file must reflect this 1:1.
    #[test]
    fn negative_se_error_to_unlock_error_mapping_is_correct() {
        // The mapping closure inside `impl WalletStore for
        // Tropic01SecureElement` must contain these arms.
        assert!(TROPIC01_SRC.contains("SeError::SlotExpired => UnlockError::PinLocked,"));
        assert!(TROPIC01_SRC.contains("SeError::InvalidParameter => UnlockError::PinIncorrect,"));
        assert!(TROPIC01_SRC.contains("_ => UnlockError::InternalError,"));
    }

    /// PIN: SPI / chip-init path on QEMU goes through
    /// `SemihostingSpi::open(DEVICE_PATH)` with the null-terminated
    /// `/dev/ttyACM0\0` path. Any rename / drop of the trailing NUL
    /// would crash the semihosting SYS_OPEN syscall on QEMU.
    #[test]
    fn negative_qemu_device_path_is_null_terminated_ttyacm0() {
        assert!(
            TROPIC01_SRC.contains(r#"const DEVICE_PATH: &[u8] = b"/dev/ttyACM0\0";"#),
            "DEVICE_PATH constant drifted; SemihostingSpi::open expects \
             a NUL-terminated path"
        );
    }

    /// PIN: the QEMU pairing-key fallback MUST be deterministic and
    /// distinct from the production STM32 path. Using the same key
    /// across boards is OK on QEMU (the chip's UID isn't queryable),
    /// but the KDF tag must NOT leak into production where the real
    /// per-device key lives in secure flash.
    #[test]
    fn negative_qemu_uid_fallback_is_cfg_gated() {
        // The QEMU-only function exists ONLY under `not(stm32u585)`.
        let cfg_idx = TROPIC01_SRC
            .find("fn derive_pairing_key_from_uid()")
            .expect("derive_pairing_key_from_uid missing");
        let preceding = &TROPIC01_SRC[..cfg_idx];
        // The closest preceding cfg attribute must mention stm32u585.
        let last_cfg = preceding.rfind("#[cfg(").unwrap_or(0);
        let cfg_attr = &preceding[last_cfg..];
        assert!(
            cfg_attr.contains("not(feature = \"stm32u585\")")
                || cfg_attr.contains("not(feature=\"stm32u585\")"),
            "derive_pairing_key_from_uid no longer cfg-gated to QEMU — \
             a UID-derived pairing key in a production build would let any \
             attacker with the source recover the per-device session keys"
        );
    }

    /// PIN: `setup_pairing` short-circuits under `e2e-test` so the
    /// second Noise session doesn't run (a known SPI-hardware issue).
    /// If this cfg gate is silently dropped, the e2e test target hangs.
    #[test]
    fn negative_setup_pairing_call_is_cfg_e2e_test_gated() {
        assert!(
            TROPIC01_SRC.contains(r#"#[cfg(not(feature = "e2e-test"))]"#),
            "setup_pairing call is no longer cfg(not(feature=\"e2e-test\"))-gated \
             — would hang the e2e-test target on the second Noise session"
        );
    }

    /// PIN: deserialize_t01_pin_state rejects inputs whose length
    /// doesn't EXACTLY equal `T01_PIN_STATE_LEN` (353). A weaker check
    /// (e.g. `>=`) would let a truncated PIN state through and the
    /// later `copy_from_slice` would either panic or alias stale
    /// bytes from `buf` into the encrypted-secrets array.
    #[test]
    fn negative_pin_state_deser_requires_exact_length() {
        assert!(
            TROPIC01_SRC.contains("if len != expected {"),
            "deserialize_t01_pin_state length check weakened from `!=` to \
             something permissive — would let a truncated PIN state through"
        );
    }

    /// PIN: each MACD slot is initialised, used, AND re-initialised
    /// inside `store_data_session` (three calls per slot). If a
    /// refactor drops the third call, the slot's stored state ends up
    /// at `pin_in` instead of `init_in` — and the next correct-PIN
    /// unlock would observe a *different* w_j than the one used at
    /// provisioning, recovering a garbage candidate that fails the
    /// tag check.
    #[test]
    fn negative_macd_slot_init_use_reinit_pattern() {
        // The store_data_session per-slot loop must contain three
        // `session.mac_and_destroy(U16::new(j as u16)` invocations.
        let body_start = TROPIC01_SRC
            .find("for j in 0..TROPIC01_MAX_ATTEMPTS {")
            .expect("store_data_session MACD loop missing");
        let body_end = body_start + 2000;
        let region = &TROPIC01_SRC[body_start..body_end.min(TROPIC01_SRC.len())];
        let macd_count = region.matches("mac_and_destroy(U16::new(j as u16)").count();
        assert!(
            macd_count >= 3,
            "store_data_session per-slot loop has {macd_count} MACD calls; \
             expected init + pin + re-init (3 total). Missing re-init means \
             the slot's stored state diverges from what unlock expects",
        );
    }

    /// PIN: doc-comment claims X25519 Noise_KK1 + AES-256-GCM — pin
    /// the documentation so a refactor that swaps either component
    /// (X25519 for, say, P-256, or AES-256-GCM for ChaCha20-Poly1305)
    /// has to update the contract.
    #[test]
    fn negative_session_doc_pins_x25519_noise_kk1_aes_gcm() {
        for needle in ["X25519", "Noise_KK1", "AES-256-GCM"] {
            assert!(
                TROPIC01_SRC.contains(needle),
                "session establishment doc-comment no longer claims {needle} — \
                 the e2e tunnel parameters changed without auditing"
            );
        }
    }

    /// PIN: invariant #4 says secrets stay in TrustZone secure world.
    /// `Tropic01SecureElement` MUST NOT derive `Debug` on the struct
    /// itself (that would print `pairing_priv` bytes via the default
    /// derive). Pin the absence of `#[derive(Debug)]` near the
    /// struct declaration.
    #[test]
    fn negative_tropic01_struct_has_no_debug_derive() {
        let struct_decl = TROPIC01_SRC
            .find("pub struct Tropic01SecureElement {")
            .expect("Tropic01SecureElement struct decl missing");
        let preceding = &TROPIC01_SRC[..struct_decl];
        let last_attr_window = &preceding[preceding.len().saturating_sub(200)..];
        assert!(
            !last_attr_window.contains("#[derive(Debug"),
            "Tropic01SecureElement has #[derive(Debug)] — `pairing_priv` \
             bytes would leak via Debug formatting (invariant #4 violation)"
        );
    }

    /// PIN: invariant #2 says PIN compare happens in SE silicon. The
    /// recovered candidate is checked against a STORED TAG, not against
    /// the user's PIN bytes — i.e. the secure world never reconstructs
    /// the PIN, only the master secret. Pin the absence of any direct
    /// PIN comparison.
    #[test]
    fn negative_no_software_pin_compare() {
        // The PIN bytes flow into `macd_pin_input(pin, j)` as a MACD
        // input — never compared bytewise. A compare like
        // `pin == stored_pin` or `pin.ct_eq(&stored)` would mean
        // software PIN compare, violating invariant #2.
        assert!(
            !TROPIC01_SRC.contains("== pin")
                && !TROPIC01_SRC.contains("pin ==")
                && !TROPIC01_SRC.contains("pin.ct_eq("),
            "software PIN-byte compare detected — TROPIC01 PIN compare must \
             go through MACD silicon (invariant #2: 'PIN compare in SE silicon, \
             never in MCU')"
        );
    }

    /// PIN: locked-state branch (already at `next_index >=
    /// TROPIC01_MAX_ATTEMPTS`) erases all four wallet slots AND
    /// returns `Err(SeError::SlotExpired)`. A regression that returned
    /// `Ok(...)` here would let a locked-out wallet still issue
    /// signatures.
    #[test]
    fn negative_already_locked_branch_returns_err_slot_expired() {
        let branch_idx = TROPIC01_SRC
            .find("if ps.next_index >= TROPIC01_MAX_ATTEMPTS {")
            .expect("already-locked branch missing");
        let region = &TROPIC01_SRC[branch_idx..branch_idx.saturating_add(500)];
        assert!(region.contains("return Err(SeError::SlotExpired);"));
        // And all four wallet slots get wiped.
        for slot in 0u32..4 {
            let needle = format!("r_mem_data_erase(U16::new({slot}))");
            assert!(
                region.contains(&needle),
                "already-locked branch missing erase of wallet slot {slot}"
            );
        }
    }
}
