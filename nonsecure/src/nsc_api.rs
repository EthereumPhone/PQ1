// This module declares every gateway command surfaced by the secure
// world; individual entry points only consume a subset (the interactive
// QEMU demo just calls unlock + sign, the USB router uses the full
// surface). The default-features smoke build flags the unused helpers
// as dead, which is expected — keep the full API compiled so callers
// don't have to chase cfg gates.
#![allow(dead_code)]

//! NS-side gateway API — thin shim over two transports.
//!
//! * **QEMU mps2-an505**: shared-memory mailbox in NS SRAM. NS writes
//!   the command word + args, the SysTick handler in the secure world
//!   polls the mailbox, runs the handler, and flips `DONE`. NS spins
//!   on `DONE`. This is a workaround for QEMU 8.2.2's broken SG
//!   instruction check on mps2-an505.
//! * **Real STM32U585**: the handful of gateway commands are exposed
//!   as proper ARMv8-M CMSE `extern "cmse-nonsecure-entry"` veneers
//!   on the secure side. Each call is a `BLXNS` → SG → secure handler
//!   → `BXNS` synchronously. No shared memory, no polling.

// ---------------------------------------------------------------------------
// QEMU transport: shared-memory mailbox
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
mod transport {
    use sphincs_tz_shared::SHARED_MAILBOX_BASE;
    const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
    const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
    const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
    const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
    const SHARED_RESULT: *const u32 = (SHARED_MAILBOX_BASE + 16) as *const u32;
    const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

    const CMD_GET_REMAINING: u32 = 1;
    const CMD_REQUEST_UNLOCK: u32 = 2;
    const CMD_SIGN_USEROP: u32 = 7;
    const CMD_IS_UNLOCKED: u32 = 11;
    const CMD_LOCK: u32 = 12;
    const CMD_GET_WALLET_ADDRESS: u32 = 14;
    const CMD_GET_INIT_CODE: u32 = 15;
    const CMD_SIGN_OFFCHAIN: u32 = 16;
    const CMD_OFFCHAIN_STATUS: u32 = 17;
    const CMD_OFFCHAIN_SYNC: u32 = 18;
    const CMD_SIGN_USEROP_BATCH: u32 = 30;

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

    #[inline]
    pub(super) fn get_remaining_attempts() -> u32 {
        unsafe { gateway_call(CMD_GET_REMAINING, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn request_unlock() -> u32 {
        unsafe { gateway_call(CMD_REQUEST_UNLOCK, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_SIGN_USEROP, payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn sign_userop_batch_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe {
            gateway_call(
                CMD_SIGN_USEROP_BATCH,
                payload_ptr as u32,
                sig_ptr as u32,
                total_len,
            )
        }
    }

    #[inline]
    pub(super) fn is_unlocked() -> u32 {
        unsafe { gateway_call(CMD_IS_UNLOCKED, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn lock() -> u32 {
        unsafe { gateway_call(CMD_LOCK, 0, 0, 0) }
    }

    #[inline]
    pub(super) fn get_wallet_address(out_ptr: *mut u8, account_index: u32) -> u32 {
        unsafe { gateway_call(CMD_GET_WALLET_ADDRESS, out_ptr as u32, account_index, 0) }
    }

    #[inline]
    pub(super) fn get_init_code(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_GET_INIT_CODE, in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn sign_offchain_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_SIGN_OFFCHAIN, in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn offchain_status_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { gateway_call(CMD_OFFCHAIN_STATUS, in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn offchain_sync_call(in_ptr: *const u8, in_len: u32) -> u32 {
        unsafe { gateway_call(CMD_OFFCHAIN_SYNC, in_ptr as u32, 0, in_len) }
    }

    #[cfg(feature = "e2e-test")]
    const CMD_TEST_PIN_LOCKOUT: u32 = 200;

    #[cfg(feature = "e2e-test")]
    #[inline]
    pub(super) fn test_pin_lockout() -> u32 {
        unsafe { gateway_call(CMD_TEST_PIN_LOCKOUT, 0, 0, 0) }
    }
}

// ---------------------------------------------------------------------------
// STM32U585 transport: direct CMSE veneer calls
// ---------------------------------------------------------------------------

#[cfg(feature = "stm32u585")]
mod transport {
    extern "C" {
        fn nsc_get_remaining_attempts() -> u32;
        fn nsc_request_unlock() -> u32;
        fn nsc_sign_userop(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_sign_userop_batch(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
        fn nsc_is_unlocked() -> u32;
        fn nsc_lock() -> u32;
        fn nsc_get_wallet_address(out_ptr: u32, account_index: u32) -> u32;
        fn nsc_get_init_code(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
        fn nsc_sign_offchain(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
        fn nsc_offchain_status(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
        fn nsc_offchain_sync(in_ptr: u32, in_len: u32) -> u32;

        // Firmware-update veneers.
        fn nsc_fw_begin(manifest_ptr: u32, manifest_len: u32) -> u32;
        fn nsc_fw_chunk(chunk_ptr: u32, chunk_len: u32) -> u32;
        fn nsc_fw_commit() -> u32;
        fn nsc_fw_status(out_ptr: u32) -> u32;
        fn nsc_fw_abort() -> u32;

        #[cfg(feature = "e2e-test")]
        fn nsc_test_pin_lockout() -> u32;

        #[cfg(feature = "e2e-test")]
        fn nsc_tzic_status() -> u32;

        // Prodtest CMSE veneers. The secure side declares these under
        // `#[cfg(feature = "prodtest")]`; the NS side mirrors the gate
        // so non-prodtest builds don't link against missing symbols.
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_get_id(out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_display_pattern(in_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_saes_selftest(out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_bhk_selftest(out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_flash_rw(in_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_trng_sample(in_ptr: u32, out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_optiga_handshake(out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_se050_handshake(out_ptr: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_usb_loopback(in_ptr: u32, out_ptr: u32, n: u32) -> u32;
        #[cfg(feature = "prodtest")]
        fn nsc_prodtest_button_test(out_ptr: u32) -> u32;
    }

    #[inline]
    pub(super) fn get_remaining_attempts() -> u32 {
        unsafe { nsc_get_remaining_attempts() }
    }

    #[inline]
    pub(super) fn request_unlock() -> u32 {
        unsafe { nsc_request_unlock() }
    }

    #[inline]
    pub(super) fn sign_userop_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_userop(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn sign_userop_batch_call(
        payload_ptr: *const u8,
        sig_ptr: *mut u8,
        total_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_userop_batch(payload_ptr as u32, sig_ptr as u32, total_len) }
    }

    #[inline]
    pub(super) fn is_unlocked() -> u32 {
        unsafe { nsc_is_unlocked() }
    }

    #[inline]
    pub(super) fn lock() -> u32 {
        unsafe { nsc_lock() }
    }

    #[inline]
    pub(super) fn get_wallet_address(out_ptr: *mut u8, account_index: u32) -> u32 {
        unsafe { nsc_get_wallet_address(out_ptr as u32, account_index) }
    }

    #[inline]
    pub(super) fn get_init_code(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { nsc_get_init_code(in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn sign_offchain_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { nsc_sign_offchain(in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn offchain_status_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        in_len: u32,
    ) -> u32 {
        unsafe { nsc_offchain_status(in_ptr as u32, out_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn offchain_sync_call(in_ptr: *const u8, in_len: u32) -> u32 {
        unsafe { nsc_offchain_sync(in_ptr as u32, in_len) }
    }

    #[inline]
    pub(super) fn fw_begin_call(manifest_ptr: *const u8, manifest_len: u32) -> u32 {
        unsafe { nsc_fw_begin(manifest_ptr as u32, manifest_len) }
    }
    #[inline]
    pub(super) fn fw_chunk_call(chunk_ptr: *const u8, chunk_len: u32) -> u32 {
        unsafe { nsc_fw_chunk(chunk_ptr as u32, chunk_len) }
    }
    #[inline]
    pub(super) fn fw_commit_call() -> u32 {
        unsafe { nsc_fw_commit() }
    }
    #[inline]
    pub(super) fn fw_status_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_fw_status(out_ptr as u32) }
    }
    #[inline]
    pub(super) fn fw_abort_call() -> u32 {
        unsafe { nsc_fw_abort() }
    }

    #[cfg(feature = "e2e-test")]
    #[inline]
    pub(super) fn test_pin_lockout() -> u32 {
        unsafe { nsc_test_pin_lockout() }
    }

    #[cfg(feature = "e2e-test")]
    #[inline]
    pub(super) fn tzic_status() -> u32 {
        unsafe { nsc_tzic_status() }
    }

    // -----------------------------------------------------------------
    // Prodtest transport wrappers
    // -----------------------------------------------------------------

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_get_id_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_get_id(out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_display_pattern_call(in_ptr: *const u8) -> u32 {
        unsafe { nsc_prodtest_display_pattern(in_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_saes_selftest_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_saes_selftest(out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_bhk_selftest_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_bhk_selftest(out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_flash_rw_call(in_ptr: *const u8) -> u32 {
        unsafe { nsc_prodtest_flash_rw(in_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_trng_sample_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
    ) -> u32 {
        unsafe { nsc_prodtest_trng_sample(in_ptr as u32, out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_optiga_handshake_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_optiga_handshake(out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_se050_handshake_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_se050_handshake(out_ptr as u32) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_usb_loopback_call(
        in_ptr: *const u8,
        out_ptr: *mut u8,
        n: u32,
    ) -> u32 {
        unsafe { nsc_prodtest_usb_loopback(in_ptr as u32, out_ptr as u32, n) }
    }

    #[cfg(feature = "prodtest")]
    #[inline]
    pub(super) fn prodtest_button_test_call(out_ptr: *mut u8) -> u32 {
        unsafe { nsc_prodtest_button_test(out_ptr as u32) }
    }
}

// ---------------------------------------------------------------------------
// Transport-agnostic public surface
// ---------------------------------------------------------------------------

pub fn get_remaining_attempts() -> u32 {
    transport::get_remaining_attempts()
}

/// Ask the secure world to prompt the user for their PIN on the trusted UI.
/// The PIN never crosses the gateway — NS only sees the result.
pub fn request_unlock() -> u32 {
    transport::request_unlock()
}

/// Unified sign-userop command (Type 1 + Type 2 state machine).
///
/// `payload` is the `SIGN_USEROP_HEADER_LEN`-byte header plus the
/// inner-tx calldata. `sig_buf` must be large enough to hold the
/// bundled response (`MAX_SIGN_RESPONSE_LEN` bytes).
pub fn sign_userop(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_userop_call(payload.as_ptr(), sig_buf.as_mut_ptr(), payload.len() as u32)
}

/// Atomic batch sign — see `sphincs_tz_shared::CMD_SIGN_USEROP_BATCH`.
///
/// `payload` is the `SIGN_USEROP_BATCH_HEADER_LEN`-byte header plus N
/// repeated `(to(20) || value(32) || data_len(2 BE) || data)` inner-tx
/// blocks. `sig_buf` must hold `MAX_SIGN_RESPONSE_LEN` bytes — the
/// response framing is byte-identical to `sign_userop`.
pub fn sign_userop_batch(payload: &[u8], sig_buf: &mut [u8]) -> u32 {
    transport::sign_userop_batch_call(
        payload.as_ptr(),
        sig_buf.as_mut_ptr(),
        payload.len() as u32,
    )
}

/// Returns 1 if the device is PIN-unlocked this session, 0 otherwise.
pub fn is_unlocked() -> bool {
    transport::is_unlocked() == 1
}

/// Explicitly lock the device: zeroize cached secrets and mark as locked.
pub fn lock() -> u32 {
    transport::lock()
}

/// Test-only: drive the secure-world PIN lockout self-test.
/// Returns `NscStatus::Ok` when brute-force is blocked (correct PIN
/// rejected after MAX_ATTEMPTS wrong attempts), `CryptoError` when
/// brute-force would succeed. Compiled out unless `e2e-test` is set.
#[cfg(feature = "e2e-test")]
pub fn test_pin_lockout() -> u32 {
    transport::test_pin_lockout()
}

/// Test-only: read the GTZC1 TZIC illegal-access counter. Returns the
/// running u32 count of NS→SECURE access violations the IRQ has logged
/// since boot. Pairs with the `gtzc-test` validation driver — see
/// `nonsecure/src/gtzc_test.rs`.
#[cfg(all(feature = "e2e-test", feature = "stm32u585"))]
pub fn tzic_status() -> u32 {
    transport::tzic_status()
}

/// Compute the CREATE2-predicted wallet address for `account_index`
/// (0..=255) from the per-account bootstrap C10 pubkey + firmware-
/// embedded factory / proxy-init-code-hash constants. Writes 20 bytes
/// into `out`. First call for a given index takes <1 s (bootstrap
/// keygen); subsequent calls hit the in-SRAM LRU cache and return in
/// <1 ms.
///
/// `account_index = 0` reproduces the legacy single-account address so
/// pre-multi-account seeds keep their existing wallet.
pub fn get_wallet_address(out: &mut [u8; 20], account_index: u32) -> u32 {
    transport::get_wallet_address(out.as_mut_ptr(), account_index)
}

/// Compute the 4280-byte ERC-4337 initCode for
/// `(account_index, chain_id)`. Used by the companion's gas estimator
/// to include a cryptographically-valid factory call in
/// `eth_estimateUserOperationGas` for not-yet-deployed wallets. The
/// produced bytes are byte-identical to what the deploy path of
/// `sign_userop` would emit, and safe to cache (SPHINCS+C10 is
/// stateless; the signed message depends only on chain_id + slot-0
/// keys). Requires an unlocked device.
///
/// `input` MUST be 12 bytes: `[account_index(u32 BE) || chain_id(u64 BE)]`.
/// `out` MUST be `PQ_INIT_CODE_LEN` (4280) bytes. First call for a
/// given `(account, chain)` incurs ~10 s of keygens; subsequent
/// calls reuse the SRAM slot cache.
pub fn get_init_code(input: &[u8], out: &mut [u8]) -> u32 {
    transport::get_init_code(input.as_ptr(), out.as_mut_ptr(), input.len() as u32)
}

/// CMD_SIGN_OFFCHAIN — produce a SPHINCS+C10 sig over an EIP-1271
/// hash. `input` is 45 bytes:
///   `[account_index(1) || chain_id(u64 BE) || slot_index(u32 BE) || hash(32)]`.
/// `out` is 4016 bytes:
///   `[new_local_offchain_count(u64 BE) || c10_sig(4008)]`.
/// Returns `NscStatus::Ok` on success or one of `OffchainSlot
/// Unregistered`, `OffchainGapExceeded`, `OffchainCapExceeded`,
/// `CryptoError`. Requires an unlocked device.
pub fn sign_offchain(input: &[u8], out: &mut [u8]) -> u32 {
    transport::sign_offchain_call(input.as_ptr(), out.as_mut_ptr(), input.len() as u32)
}

/// CMD_OFFCHAIN_STATUS — read per-slot off-chain state. `input` is 13
/// bytes (`account_index(1) || chain_id(u64 BE) || slot_index(u32 BE)`),
/// `out` is 24 bytes — see `shared::CMD_OFFCHAIN_STATUS` for the layout.
pub fn offchain_status(input: &[u8], out: &mut [u8]) -> u32 {
    transport::offchain_status_call(input.as_ptr(), out.as_mut_ptr(), input.len() as u32)
}

/// CMD_OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
/// companion-supplied floor. `input` is 21 bytes:
///   `[account_index(1) || chain_id(u64 BE) || slot_index(u32 BE) || target(u64 BE)]`.
/// No response body; SW only. Idempotent and "set if greater".
pub fn offchain_sync(input: &[u8]) -> u32 {
    transport::offchain_sync_call(input.as_ptr(), input.len() as u32)
}

// ---------------------------------------------------------------------------
// Firmware-update command wrappers
// ---------------------------------------------------------------------------
//
// Each of these is a thin pass-through to the CMSE veneer. The secure
// world is the one doing all the work — validating the manifest, writing
// flash, re-hashing images, waiting for the user's confirm. NS just
// handles USB framing and progress reporting.

/// CMD_FW_BEGIN — kick off an update with the supplied 8 KB manifest.
///
/// Only works on the STM32U585 transport (the QEMU mailbox path doesn't
/// expose the update commands). Returns `FwUpdate*` / `NotInitialized`
/// status codes — the caller maps them to SW words for the APDU response.
#[cfg(feature = "stm32u585")]
pub fn fw_begin(manifest: &[u8]) -> u32 {
    transport::fw_begin_call(manifest.as_ptr(), manifest.len() as u32)
}

/// CMD_FW_CHUNK — stream one pre-assembled header+data chunk.
#[cfg(feature = "stm32u585")]
pub fn fw_chunk(chunk: &[u8]) -> u32 {
    transport::fw_chunk_call(chunk.as_ptr(), chunk.len() as u32)
}

/// CMD_FW_COMMIT — finalise; may reset the device on success.
#[cfg(feature = "stm32u585")]
pub fn fw_commit() -> u32 {
    transport::fw_commit_call()
}

/// CMD_FW_STATUS — read current progress into `out`.
#[cfg(feature = "stm32u585")]
pub fn fw_status(out: &mut [u8; sphincs_tz_shared::FW_STATUS_RESPONSE_LEN]) -> u32 {
    transport::fw_status_call(out.as_mut_ptr())
}

/// CMD_FW_ABORT — discard any in-progress session.
#[cfg(feature = "stm32u585")]
pub fn fw_abort() -> u32 {
    transport::fw_abort_call()
}

// ---------------------------------------------------------------------------
// Prodtest public API (`prodtest` feature only)
//
// Each wrapper mirrors a `CMD_PRODTEST_*` from `proto/src/lib.rs` and
// is routed by the USB dispatcher to the matching CMSE veneer in
// `secure/src/nsc/mod.rs::nsc_prodtest_*`. Buffers are caller-owned
// — typical caller is `usb::commands::cmd_prodtest_*`.
// ---------------------------------------------------------------------------

#[cfg(feature = "prodtest")]
pub fn prodtest_get_id(out: &mut [u8; 24]) -> u32 {
    transport::prodtest_get_id_call(out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_display_pattern(pattern: u32) -> u32 {
    let buf = pattern.to_le_bytes();
    transport::prodtest_display_pattern_call(buf.as_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_saes_selftest(out: &mut [u8; 8]) -> u32 {
    transport::prodtest_saes_selftest_call(out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_bhk_selftest(out: &mut [u8; 8]) -> u32 {
    transport::prodtest_bhk_selftest_call(out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_flash_rw(pattern: u32) -> u32 {
    let buf = pattern.to_le_bytes();
    transport::prodtest_flash_rw_call(buf.as_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_trng_sample(n: u32, out: &mut [u8]) -> u32 {
    let len_buf = n.to_le_bytes();
    transport::prodtest_trng_sample_call(len_buf.as_ptr(), out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_optiga_handshake(out: &mut [u8; 16]) -> u32 {
    transport::prodtest_optiga_handshake_call(out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_se050_handshake(out: &mut [u8; 16]) -> u32 {
    transport::prodtest_se050_handshake_call(out.as_mut_ptr())
}

#[cfg(feature = "prodtest")]
pub fn prodtest_usb_loopback(input: &[u8], out: &mut [u8]) -> u32 {
    transport::prodtest_usb_loopback_call(
        input.as_ptr(),
        out.as_mut_ptr(),
        input.len() as u32,
    )
}

#[cfg(feature = "prodtest")]
pub fn prodtest_button_test(out: &mut [u8; 4]) -> u32 {
    transport::prodtest_button_test_call(out.as_mut_ptr())
}
