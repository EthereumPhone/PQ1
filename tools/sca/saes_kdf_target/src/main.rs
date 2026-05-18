//! SAES-DHUK CMAC leakage target.
//!
//! Re-exposes the production CMAC wrapper (`secure/src/cmac.rs::cmac_generic`)
//! to scared / lascar's emulator. The wrapper is `#[path]`-included verbatim
//! so any drift in the production file fails this build loudly (the prod
//! file is `pub(crate)` — within this crate that means "visible everywhere
//! in this crate," which is what we want).
//!
//! ## What this target tests
//!
//! In production:
//!   - `secret_keys::derive_into_saes_kdf(label, output)` is called.
//!   - It calls `cmac_dhuk(scratch_with_label_and_counter, &mut tag)`.
//!   - `cmac_dhuk` calls `cmac_generic(msg, |block| saes::encrypt_ecb_block(KeySel::Dhuk, ...), tag)`.
//!   - DHUK lives in SAES_KEY silicon registers — never in CPU memory.
//!
//! In this emulation target:
//!   - We can't model the SAES coprocessor — rainbow only sees CPU instructions.
//!   - So we replace `saes::encrypt_ecb_block` with a **software** AES-256
//!     closure that takes the key from a function parameter. The key DOES enter
//!     CPU memory here.
//!   - This means the AES primitive itself becomes a leakage source in our
//!     traces — that's the EXPECTED, well-known leakage of software AES.
//!   - The INTERESTING question this target answers: does the WRAPPER
//!     (`cmac_generic` / `kdf_cmac_counter_generic`) leak ADDITIONAL key
//!     information OUTSIDE the AES calls — e.g., does any of the L/K1/K2
//!     doubling, the CBC chain XOR, the final-block padding logic, or the
//!     KDF's label-counter packing exhibit key-dependent timing or memory
//!     access patterns?
//!
//! The TVLA hypothesis: a constant-time wrapper will produce traces where
//! key-dependent samples are CONFINED to the AES invocations (the 4 calls
//! to `aes_encrypt` inside a single-block CMAC: L=E(K,0), then E(K, state)
//! per block, then the final tag E(K, last)). Samples OUTSIDE these
//! windows should be flat under fixed-input-varying-key TVLA.
//!
//! ## Symbols
//!
//! `sca_saes_cmac` — single-block CMAC over a fixed 16-byte input
//! under the caller-supplied 32-byte key. Input layout: 32B key, output:
//! 16B tag. The harness varies the key across traces with a fixed
//! 16-byte all-zero message.
//!
//! `sca_saes_kdf_one_block` — full `kdf_cmac_counter_generic` path with
//! caller-supplied 32-byte key + 16-byte label, output 16B. Tests the
//! KDF wrapper around CMAC for additional leakage.

#![no_std]
#![no_main]

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use cortex_m_rt::entry;
use panic_halt as _;

// Include the production CMAC byte-for-byte. `pub(crate)` in the source
// becomes "visible everywhere in this target" after the path-include, so
// `cmac::cmac_generic` is reachable.
#[path = "../../../../secure/src/cmac.rs"]
mod cmac;

const MSG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const LABEL_LEN: usize = 16;

/// AES-256 closure builder. The closure captures the 32-byte key and
/// runs `Aes256::encrypt_block` per call — same crate (`aes` 0.8) that
/// `pqsigner-domain` falls through to, so the software-AES leakage
/// behaviour is identical to `kdf_target`'s `sca_aesgcm_wrap`.
///
/// In production this closure would route to `saes::encrypt_ecb_block`
/// with `KeySel::Dhuk` — the key would NOT be a function parameter and
/// would never enter CPU memory.
#[inline(never)]
fn aes256_closure(key: &[u8; KEY_LEN]) -> impl FnMut(&[u8; 16]) -> Result<[u8; 16], ()> + '_ {
    let cipher = Aes256::new(key.into());
    move |block| {
        let mut b = *aes::Block::from_slice(block);
        cipher.encrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        Ok(out)
    }
}

/// Single-block CMAC under a caller-supplied key. The harness wraps this
/// to TVLA "varying key, fixed message" — every key-dependent sample
/// SHOULD live inside the four `aes_encrypt` calls (L derivation +
/// final tag), and the wrapper bookkeeping (`double_l`, CBC XOR, the
/// last-block branch dispatch) should be key-independent because it
/// only touches `L`, `K1`, `K2`, and the message — never the key directly.
///
/// Input layout (48 bytes at `input_ptr`):
///   - bytes 0..32: 32-byte AES-256 key (DHUK stand-in; harness varies)
///   - bytes 32..48: 16-byte message (harness fixes to all-zero by default)
///
/// Output (16 bytes at `output_ptr`): the CMAC tag.
#[no_mangle]
pub extern "C" fn sca_saes_cmac(input_ptr: *const u8, output_ptr: *mut u8) {
    // SAFETY: harness passes valid 48-byte input + 16-byte output buffers.
    let input = unsafe { core::slice::from_raw_parts(input_ptr, KEY_LEN + MSG_LEN) };
    let output = unsafe { core::slice::from_raw_parts_mut(output_ptr, TAG_LEN) };

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&input[..KEY_LEN]);
    let mut msg = [0u8; MSG_LEN];
    msg.copy_from_slice(&input[KEY_LEN..KEY_LEN + MSG_LEN]);

    let mut tag = [0u8; TAG_LEN];
    let _ = cmac::cmac_generic(&msg, aes256_closure(&key), &mut tag);

    output[..TAG_LEN].copy_from_slice(&tag);
}

/// Full `kdf_cmac_counter_generic` path: derive 16 bytes from
/// `(key, label)` via `CMAC(K, label ‖ 0x01)`. Tests the KDF wrapper
/// AROUND `cmac_generic` for additional leakage in the label-and-counter
/// packing logic (`scratch[..label.len()].copy_from_slice(label);
/// scratch[label.len()] = counter;`).
///
/// Input layout (48 bytes at `input_ptr`):
///   - bytes 0..32: 32-byte key
///   - bytes 32..48: 16-byte label
///
/// Output (16 bytes at `output_ptr`): first KDF block.
#[no_mangle]
pub extern "C" fn sca_saes_kdf_one_block(input_ptr: *const u8, output_ptr: *mut u8) {
    // SAFETY: harness passes valid 48-byte input + 16-byte output buffers.
    let input = unsafe { core::slice::from_raw_parts(input_ptr, KEY_LEN + LABEL_LEN) };
    let output = unsafe { core::slice::from_raw_parts_mut(output_ptr, TAG_LEN) };

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&input[..KEY_LEN]);
    let mut label = [0u8; LABEL_LEN];
    label.copy_from_slice(&input[KEY_LEN..KEY_LEN + LABEL_LEN]);

    let mut scratch = [0u8; LABEL_LEN + 1];
    let mut out_buf = [0u8; TAG_LEN];
    let _ = cmac::kdf_cmac_counter_generic::<(), _>(
        &label,
        &mut scratch,
        aes256_closure(&key),
        &mut out_buf,
    );

    output[..TAG_LEN].copy_from_slice(&out_buf);
}

#[entry]
fn entry() -> ! {
    // Touch the symbols so cortex-m-rt's `--gc-sections` doesn't strip them.
    // Same trick the other SCA targets use.
    let sink_in = [0u8; 48];
    let mut sink_out = [0u8; 16];
    sca_saes_cmac(sink_in.as_ptr(), sink_out.as_mut_ptr());
    sca_saes_kdf_one_block(sink_in.as_ptr(), sink_out.as_mut_ptr());
    loop {
        cortex_m::asm::nop();
    }
}

// Pin the externs so LTO + gc-sections can't strip them. The other targets
// use `#[used]` statics; mirror that here.
#[used]
static SCA_SAES_CMAC_KEEP: extern "C" fn(*const u8, *mut u8) = sca_saes_cmac;
#[used]
static SCA_SAES_KDF_KEEP: extern "C" fn(*const u8, *mut u8) = sca_saes_kdf_one_block;
