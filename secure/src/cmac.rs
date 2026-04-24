//! Generic CMAC-AES core per RFC 4493 / NIST SP 800-38B §6.2.
//!
//! The algorithm is pulled out of the SAES-DHUK backend (`hw::saes_cmac`)
//! so it can be exercised on the host with a software AES via the `aes`
//! crate against the NIST SP 800-38B Appendix D.3 AES-256 test vectors.
//! The device path wraps the same function with an AES closure that
//! routes through the STM32U585 SAES coprocessor using `KeySel::Dhuk`,
//! so the firmware never re-implements the CMAC math — only the AES
//! primitive differs between host and device.
//!
//! ## Algorithm (RFC 4493 §2.4)
//!
//! ```text
//! Step 1: L = E(K, 0^128)
//!         K1 = dbl(L)
//!         K2 = dbl(K1)
//! Step 2: if len(M) == 0:  M = K2 XOR (0x80 || 0^{127})
//!         elif |M| is multiple of 128: M_n = M_n XOR K1
//!         else:                        M_n = pad(M_n) XOR K2
//! Step 3: CBC-MAC through all blocks, final AES output is the tag.
//! ```
//!
//! `dbl(x)` is GF(2^128) doubling with the irreducible polynomial `0x87`
//! (added to the low byte when the original MSB was set).

/// GF(2^128) doubling per RFC 4493 §2.3. MSB-first byte order (the
/// "high" bit is bit 7 of `x[0]`).
///
/// Shift-left by 1 bit across the whole 16-byte block. If the original
/// top bit was set, XOR the result's low byte with the constant `0x87`
/// (the low byte of the Rb polynomial `x^128 + x^7 + x^2 + x + 1`
/// reduced to 128 bits).
pub(crate) fn double_l(input: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry: u8 = 0;
    for i in (0..16).rev() {
        let b = input[i];
        out[i] = (b << 1) | carry;
        carry = (b >> 7) & 1;
    }
    if (input[0] & 0x80) != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// Core CMAC-AES over an arbitrary 128-bit block cipher supplied as the
/// closure `aes_encrypt`. Writes the 16-byte MAC tag into `tag`. `msg`
/// can be any length including zero.
///
/// The closure is called once per AES invocation (key schedule is the
/// closure's responsibility — on the device side the key is DHUK and
/// lives in SAES key registers; on the host side it's the test key
/// scheduled into an `aes::Aes256` instance once and captured by the
/// closure). Errors from the closure propagate verbatim.
pub(crate) fn cmac_generic<E, F>(
    msg: &[u8],
    mut aes_encrypt: F,
    tag: &mut [u8; 16],
) -> Result<(), E>
where
    F: FnMut(&[u8; 16]) -> Result<[u8; 16], E>,
{
    // Step 1: L = E(K, 0^128), K1 = dbl(L), K2 = dbl(K1).
    let zero = [0u8; 16];
    let l = aes_encrypt(&zero)?;
    let k1 = double_l(&l);
    let k2 = double_l(&k1);

    // How many 128-bit blocks? Empty message is still one (synthetic)
    // block — CMAC handles it as pad(empty) XOR K2.
    let n = if msg.is_empty() {
        1
    } else {
        msg.len().div_ceil(16)
    };
    let last_is_complete = !msg.is_empty() && msg.len() % 16 == 0;

    // Step 3a: CBC-MAC through the first (n - 1) blocks.
    let mut state = [0u8; 16];
    for i in 0..(n - 1) {
        let base = i * 16;
        for j in 0..16 {
            state[j] ^= msg[base + j];
        }
        state = aes_encrypt(&state)?;
    }

    // Step 3b: build the last block.
    let last_offset = (n - 1) * 16;
    let mut last = [0u8; 16];
    if msg.is_empty() {
        // pad(empty) = 0x80 || 0^{127}; XOR with K2.
        last[0] = 0x80;
        for j in 0..16 {
            last[j] ^= k2[j];
        }
    } else if last_is_complete {
        // Complete last block: XOR with K1 directly.
        last.copy_from_slice(&msg[last_offset..last_offset + 16]);
        for j in 0..16 {
            last[j] ^= k1[j];
        }
    } else {
        // Partial last block: copy, append 0x80, zero-pad, XOR with K2.
        let rem = msg.len() - last_offset;
        last[..rem].copy_from_slice(&msg[last_offset..]);
        last[rem] = 0x80;
        for j in 0..16 {
            last[j] ^= k2[j];
        }
    }

    // Step 4: final AES encrypt yields the tag.
    for j in 0..16 {
        state[j] ^= last[j];
    }
    *tag = aes_encrypt(&state)?;
    Ok(())
}

/// Error returned by [`kdf_cmac_counter_generic`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum KdfError<E> {
    /// Label is too long to fit the caller's scratch buffer (one byte
    /// must remain for the counter).
    LabelTooLong,
    /// Output length would require more than 255 counter blocks
    /// (255 × 16 = 4080 bytes). No firmware label today goes near
    /// this cap.
    OutputTooLong,
    /// AES backend failed (SAES peripheral error on device; never
    /// reachable on host since `aes::Aes256` can't fail).
    Backend(E),
}

/// Simplified SP 800-108-style CMAC-based counter KDF. Fills `output`
/// with `ceil(output.len() / 16)` blocks of `CMAC(K, label || counter)`
/// where counter is a single byte starting at 1. Each label is
/// domain-separated by construction; each output block within a label
/// is domain-separated by the counter.
///
/// `scratch` is a caller-provided buffer that holds `label || counter`.
/// It must be strictly larger than `label.len()` — at least one byte
/// must remain after the label for the counter byte. A fixed stack
/// buffer (e.g. `[u8; 65]`) is the expected shape on the device side;
/// tests reuse the same buffer.
///
/// Separating this from the SAES wrapper lets host tests verify the
/// exact label-and-counter packing against a software AES. Silicon
/// paths share the byte-identical core.
pub(crate) fn kdf_cmac_counter_generic<E, F>(
    label: &[u8],
    scratch: &mut [u8],
    mut aes_encrypt: F,
    output: &mut [u8],
) -> Result<(), KdfError<E>>
where
    F: FnMut(&[u8; 16]) -> Result<[u8; 16], E>,
{
    if scratch.len() <= label.len() {
        return Err(KdfError::LabelTooLong);
    }
    let n_blocks = output.len().div_ceil(16);
    if n_blocks > 255 {
        return Err(KdfError::OutputTooLong);
    }

    scratch[..label.len()].copy_from_slice(label);
    let info_end = label.len() + 1;

    let mut pos = 0usize;
    let mut counter: u8 = 1;
    while pos < output.len() {
        scratch[label.len()] = counter;
        let mut tag = [0u8; 16];
        cmac_generic(&scratch[..info_end], &mut aes_encrypt, &mut tag)
            .map_err(KdfError::Backend)?;

        let take = core::cmp::min(16, output.len() - pos);
        output[pos..pos + take].copy_from_slice(&tag[..take]);

        pos += take;
        if pos < output.len() {
            counter = counter.wrapping_add(1);
            debug_assert!(counter != 0, "n_blocks cap should make wrap unreachable");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! NIST SP 800-38B Appendix D.3 — CMAC-AES-256 known-answer tests.
    //!
    //! Vectors reproduced verbatim from the NIST examples document
    //! (<https://csrc.nist.gov/publications/detail/sp/800-38b/final>
    //! referencing <https://csrc.nist.gov/CSRC/media/Publications/sp/800-38b/final/documents/sp_800-38b_updated-examples.pdf>,
    //! Appendix D.3 "CMAC-AES256"). Exercising the four message lengths
    //! (empty / 16 / 40 / 64 bytes) covers every code path in
    //! `cmac_generic`:
    //! - empty → synthetic last block with K2 XOR (0x80 || 0^127)
    //! - 16-byte → single complete last block with K1
    //! - 40-byte → multi-block with partial last block using K2
    //! - 64-byte → multi-block with complete last block using K1
    //!
    //! Missing these in the initial Tier-1 landing would let a silent
    //! math bug ship to silicon undetected (the on-chip self-test only
    //! asserts domain separation and self-consistency — it cannot
    //! distinguish a correct CMAC from a subtly-wrong one that still
    //! yields different bytes per label).
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;

    /// NIST SP 800-38B §D.3 key K.
    const KEY: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];

    /// NIST §D.3 message M (64 bytes — all four vectors slice from this).
    const M: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];

    /// Example 9 — Mlen = 0. Expected tag T.
    const T_EMPTY: [u8; 16] = [
        0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e, 0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9,
        0x83,
    ];
    /// Example 10 — Mlen = 128 bits (16 bytes). Expected tag T.
    const T_16: [u8; 16] = [
        0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82, 0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3,
        0x5c,
    ];
    /// Example 11 — Mlen = 320 bits (40 bytes). Expected tag T.
    const T_40: [u8; 16] = [
        0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11,
        0xe6,
    ];
    /// Example 12 — Mlen = 512 bits (64 bytes). Expected tag T.
    const T_64: [u8; 16] = [
        0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5, 0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54,
        0x10,
    ];

    fn aes256_encryptor(key: &[u8; 32]) -> impl FnMut(&[u8; 16]) -> Result<[u8; 16], ()> {
        let cipher = Aes256::new(key.into());
        move |block| {
            let mut b = *aes::Block::from_slice(block);
            cipher.encrypt_block(&mut b);
            let mut out = [0u8; 16];
            out.copy_from_slice(&b);
            Ok(out)
        }
    }

    #[test]
    fn nist_sp800_38b_aes256_empty() {
        let mut tag = [0u8; 16];
        cmac_generic::<(), _>(&[], aes256_encryptor(&KEY), &mut tag).unwrap();
        assert_eq!(tag, T_EMPTY, "empty-message CMAC-AES-256 mismatch");
    }

    #[test]
    fn nist_sp800_38b_aes256_16() {
        let mut tag = [0u8; 16];
        cmac_generic::<(), _>(&M[..16], aes256_encryptor(&KEY), &mut tag).unwrap();
        assert_eq!(tag, T_16, "16-byte CMAC-AES-256 mismatch");
    }

    #[test]
    fn nist_sp800_38b_aes256_40() {
        let mut tag = [0u8; 16];
        cmac_generic::<(), _>(&M[..40], aes256_encryptor(&KEY), &mut tag).unwrap();
        assert_eq!(tag, T_40, "40-byte CMAC-AES-256 mismatch (partial last block, K2 path)");
    }

    #[test]
    fn nist_sp800_38b_aes256_64() {
        let mut tag = [0u8; 16];
        cmac_generic::<(), _>(&M[..64], aes256_encryptor(&KEY), &mut tag).unwrap();
        assert_eq!(tag, T_64, "64-byte CMAC-AES-256 mismatch (complete last block, K1 path)");
    }

    /// Sanity: double_l of all-zeros is all-zeros (top bit clear, no
    /// polynomial reduction). Tiny but catches obvious shift bugs.
    #[test]
    fn double_l_zero() {
        assert_eq!(double_l(&[0u8; 16]), [0u8; 16]);
    }

    /// Sanity: double_l of 0x80||0^15 is 0^15||0x87 (top bit set triggers
    /// XOR with 0x87 in the low byte).
    #[test]
    fn double_l_top_bit_reduction() {
        let mut input = [0u8; 16];
        input[0] = 0x80;
        let mut expected = [0u8; 16];
        expected[15] = 0x87;
        assert_eq!(double_l(&input), expected);
    }

    // --- kdf_cmac_counter_generic coverage --------------------------
    //
    // These tests pin down the label-and-counter packing that
    // `hw::secret_keys::derive_into_saes_kdf` relies on. The NIST KATs
    // above cover `cmac_generic`; these cover the scratch-buffer
    // layout (`label || counter` with counter starting at 1), the
    // multi-block packing, and the length caps.

    /// Single-block output (≤16 bytes) must equal `CMAC(K, label || 0x01)`
    /// exactly. Demonstrates the counter-byte placement and that the
    /// first block uses counter=1 (not 0).
    #[test]
    fn kdf_single_block_matches_cmac_label_counter_one() {
        let label = b"pqsigner/test-v1";
        let mut out = [0u8; 16];
        let mut scratch = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(label, &mut scratch, aes256_encryptor(&KEY), &mut out)
            .unwrap();

        // Expected: CMAC(K, label || 0x01).
        let mut expected_input = Vec::with_capacity(label.len() + 1);
        expected_input.extend_from_slice(label);
        expected_input.push(0x01);
        let mut expected = [0u8; 16];
        cmac_generic::<(), _>(&expected_input, aes256_encryptor(&KEY), &mut expected).unwrap();

        assert_eq!(out, expected, "single-block KDF must equal CMAC(K, label || 0x01)");
    }

    /// Truncated single-block output (< 16 bytes) takes the prefix
    /// of the first CMAC tag.
    #[test]
    fn kdf_truncated_output_takes_tag_prefix() {
        let label = b"pqsigner/short-v1";
        let mut full = [0u8; 16];
        let mut scratch_a = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(label, &mut scratch_a, aes256_encryptor(&KEY), &mut full)
            .unwrap();

        let mut short = [0u8; 10];
        let mut scratch_b = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(label, &mut scratch_b, aes256_encryptor(&KEY), &mut short)
            .unwrap();

        assert_eq!(short, full[..10]);
    }

    /// Two-block output must concatenate `CMAC(K, label || 0x01)` with
    /// `CMAC(K, label || 0x02)`. Covers the counter increment and that
    /// the packing appends in order.
    #[test]
    fn kdf_two_blocks_concatenate_counters_1_and_2() {
        let label = b"pqsigner/two-v1";
        let mut out = [0u8; 32];
        let mut scratch = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(label, &mut scratch, aes256_encryptor(&KEY), &mut out)
            .unwrap();

        let mut block1 = [0u8; 16];
        let mut block2 = [0u8; 16];
        let mut in1 = Vec::from(label.as_slice());
        in1.push(0x01);
        let mut in2 = Vec::from(label.as_slice());
        in2.push(0x02);
        cmac_generic::<(), _>(&in1, aes256_encryptor(&KEY), &mut block1).unwrap();
        cmac_generic::<(), _>(&in2, aes256_encryptor(&KEY), &mut block2).unwrap();

        assert_eq!(&out[0..16], &block1, "first 16 bytes must be CMAC(K, label || 0x01)");
        assert_eq!(&out[16..32], &block2, "next 16 bytes must be CMAC(K, label || 0x02)");
    }

    /// Partial-second-block output takes the prefix of the second
    /// CMAC tag after a complete first block.
    #[test]
    fn kdf_partial_second_block_takes_prefix() {
        let label = b"pqsigner/partial-v1";
        let mut out = [0u8; 24];
        let mut scratch = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(label, &mut scratch, aes256_encryptor(&KEY), &mut out)
            .unwrap();

        let mut block1 = [0u8; 16];
        let mut block2 = [0u8; 16];
        let mut in1 = Vec::from(label.as_slice());
        in1.push(0x01);
        let mut in2 = Vec::from(label.as_slice());
        in2.push(0x02);
        cmac_generic::<(), _>(&in1, aes256_encryptor(&KEY), &mut block1).unwrap();
        cmac_generic::<(), _>(&in2, aes256_encryptor(&KEY), &mut block2).unwrap();

        assert_eq!(&out[0..16], &block1);
        assert_eq!(&out[16..24], &block2[..8]);
    }

    /// Distinct labels must yield distinct bytes (domain separation).
    #[test]
    fn kdf_distinct_labels_diverge() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut sa = [0u8; 65];
        let mut sb = [0u8; 65];
        kdf_cmac_counter_generic::<(), _>(b"a", &mut sa, aes256_encryptor(&KEY), &mut a).unwrap();
        kdf_cmac_counter_generic::<(), _>(b"b", &mut sb, aes256_encryptor(&KEY), &mut b).unwrap();
        assert_ne!(a, b);
    }

    /// Scratch buffer must be strictly larger than the label (needs
    /// one byte for the counter).
    #[test]
    fn kdf_label_too_long_is_rejected() {
        let label = [0u8; 64];
        let mut scratch = [0u8; 64]; // same size, no room for counter
        let mut out = [0u8; 16];
        let result = kdf_cmac_counter_generic::<(), _>(
            &label,
            &mut scratch,
            aes256_encryptor(&KEY),
            &mut out,
        );
        assert_eq!(result, Err(KdfError::LabelTooLong));
    }

    /// Output > 255 × 16 bytes is rejected — counter would wrap.
    #[test]
    fn kdf_output_too_long_is_rejected() {
        let mut scratch = [0u8; 65];
        let mut out = vec![0u8; 256 * 16];
        let result = kdf_cmac_counter_generic::<(), _>(
            b"x",
            &mut scratch,
            aes256_encryptor(&KEY),
            &mut out,
        );
        assert_eq!(result, Err(KdfError::OutputTooLong));
    }

    /// Boundary: exactly 255 × 16 bytes is accepted (max valid size).
    #[test]
    fn kdf_max_valid_output_is_accepted() {
        let mut scratch = [0u8; 65];
        let mut out = vec![0u8; 255 * 16];
        let result = kdf_cmac_counter_generic::<(), _>(
            b"x",
            &mut scratch,
            aes256_encryptor(&KEY),
            &mut out,
        );
        assert!(result.is_ok());
    }

    /// Empty output is a no-op success.
    #[test]
    fn kdf_empty_output_succeeds() {
        let mut scratch = [0u8; 65];
        let mut out = [0u8; 0];
        kdf_cmac_counter_generic::<(), _>(b"x", &mut scratch, aes256_encryptor(&KEY), &mut out)
            .unwrap();
    }
}
