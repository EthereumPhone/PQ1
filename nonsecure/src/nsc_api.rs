// Shared memory gateway (derived from shared crate constants)
use sphincs_tz_shared::SHARED_MAILBOX_BASE;
const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
const SHARED_RESULT: *const u32 = (SHARED_MAILBOX_BASE + 16) as *const u32;
const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

const CMD_GET_REMAINING: u32 = 1;
const CMD_REQUEST_UNLOCK: u32 = 2;
const CMD_GET_PUBKEY: u32 = 3;
const CMD_SIGN: u32 = 4;
const CMD_CLEAR_SIGN: u32 = 5;
const CMD_CLEAR_SIGN_MSG: u32 = 6;

unsafe fn gateway_call(cmd: u32, arg0: u32, arg1: u32, arg2: u32) -> u32 {
    core::ptr::write_volatile(SHARED_DONE, 0);
    core::ptr::write_volatile(SHARED_ARG0, arg0);
    core::ptr::write_volatile(SHARED_ARG1, arg1);
    core::ptr::write_volatile(SHARED_ARG2, arg2);
    core::ptr::write_volatile(SHARED_CMD, cmd);

    while core::ptr::read_volatile(SHARED_DONE as *const u32) == 0 {
        cortex_m::asm::nop();
    }
    core::ptr::read_volatile(SHARED_RESULT)
}

pub fn get_remaining_attempts() -> u32 {
    unsafe { gateway_call(CMD_GET_REMAINING, 0, 0, 0) }
}

/// Ask the secure world to prompt the user for their PIN on the trusted UI.
/// The PIN never crosses the gateway — NS only sees the result.
pub fn request_unlock() -> u32 {
    unsafe { gateway_call(CMD_REQUEST_UNLOCK, 0, 0, 0) }
}

pub fn get_pubkey(buf: &mut [u8; 32]) -> u32 {
    unsafe { gateway_call(CMD_GET_PUBKEY, 0, buf.as_mut_ptr() as u32, 32) }
}

/// Send a CMD_SIGN request whose payload is already laid out in the
/// new wrapper format expected by the secure world:
///
/// ```text
///   [0]              has_bundle u8        (0 or 1)
///   [1..5]           tx_len     u32 LE
///   [5..5+tx_len]    EIP-1559 envelope
///   [5+tx_len..]     optional [bundle_len u32 LE][bundle bytes]
/// ```
///
/// Most callers should go through [`sign`] / [`sign_with_bundle`]
/// rather than building this layout themselves.
pub fn sign_raw(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    unsafe {
        gateway_call(
            CMD_SIGN,
            payload.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            payload.len() as u32,
        )
    }
}

/// Sign an EIP-1559 envelope with no metadata bundle attached. The
/// secure world will fall through to plain value-transfer rendering
/// (or to BLIND SIGNING if calldata is non-empty and no bundle is
/// supplied).
pub fn sign(unsigned_tx: &[u8], sig_buf: &mut [u8], payload_buf: &mut [u8]) -> u32 {
    let mut p = 0usize;
    payload_buf[p] = 0u8; // has_bundle = false
    p += 1;
    let tx_len_bytes = (unsigned_tx.len() as u32).to_le_bytes();
    payload_buf[p..p + 4].copy_from_slice(&tx_len_bytes);
    p += 4;
    payload_buf[p..p + unsigned_tx.len()].copy_from_slice(unsigned_tx);
    p += unsigned_tx.len();
    sign_raw(&payload_buf[..p], sig_buf)
}

/// Sign an EIP-1559 envelope and attach an ERC20 metadata bundle for
/// the recipient contract. The bundle was already built by the
/// non-secure DB lookup; the secure world Merkle-verifies it before
/// trusting any of the bytes for trusted-UI display.
pub fn sign_with_bundle(
    unsigned_tx: &[u8],
    bundle: &[u8],
    sig_buf: &mut [u8],
    payload_buf: &mut [u8],
) -> u32 {
    let mut p = 0usize;
    payload_buf[p] = 1u8; // has_bundle = true
    p += 1;
    let tx_len_bytes = (unsigned_tx.len() as u32).to_le_bytes();
    payload_buf[p..p + 4].copy_from_slice(&tx_len_bytes);
    p += 4;
    payload_buf[p..p + unsigned_tx.len()].copy_from_slice(unsigned_tx);
    p += unsigned_tx.len();
    let blen_bytes = (bundle.len() as u32).to_le_bytes();
    payload_buf[p..p + 4].copy_from_slice(&blen_bytes);
    p += 4;
    payload_buf[p..p + bundle.len()].copy_from_slice(bundle);
    p += bundle.len();
    sign_raw(&payload_buf[..p], sig_buf)
}

/// ZK clear-sign: forward a Groth16 proof + a (Merkle-verified by S)
/// VK bundle for an Aave-style protocol. The secure world walks the
/// VK bundle's proof up to its embedded `VK_DB_ROOT`, runs Groth16
/// verification with the verified VK, displays the
/// circuit-attested readable string, and signs.
///
/// The fixed header layout (proof || calldata || readable || tx_len ||
/// tx) is followed by `[bundle_len u32 LE][vk bundle bytes]`.
pub fn clear_sign(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    unsafe {
        gateway_call(
            CMD_CLEAR_SIGN,
            payload.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            payload.len() as u32,
        )
    }
}

/// EIP-712 typed-data clear signing (M4 — CowSwap GPv2Order).
///
/// The payload layout is:
///
/// ```text
///   [0..384)         Groth16 proof (π.A || π.B || π.C)
///   [384..548)       canonical bytes (164 bytes, packed GPv2Order)
///   [548..612)       readable string (64 bytes, null-padded)
///   [612..616)       bundle_len u32 LE
///   [616..)          VK bundle bytes
/// ```
///
/// The secure world Merkle-verifies the VK bundle, runs Groth16 to
/// confirm `Poseidon(canonical) ‖ Poseidon(readable)` are the bound
/// public signals, recomputes the EIP-712 digest natively from the
/// SAME canonical bytes, displays the readable string on the trusted
/// UI, and signs the digest with SLH-DSA.
pub fn clear_sign_msg(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    unsafe {
        gateway_call(
            CMD_CLEAR_SIGN_MSG,
            payload.as_ptr() as u32,
            sig_buf.as_mut_ptr() as u32,
            payload.len() as u32,
        )
    }
}
