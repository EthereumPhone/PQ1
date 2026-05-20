// The router holds its response buffers as module-level `static mut`
// because they outlive any single dispatch call (e.g. the GET_RESPONSE
// chunker pages out of SIG_BUF across multiple HID polls). Every access
// runs inside an `unsafe fn` on the single-threaded NS main loop with
// no interrupts re-entering this module, so the rust-2024
// `static_mut_refs` lint is suppressed per the same pattern as
// `e2e_test.rs` / `bench_key_speed.rs` / `fwup_hw_test.rs`.
#![allow(static_mut_refs)]

//! APDU command router — PQSigner v2 native protocol only (post-cutover).
//!
//! One class byte: `APDU_CLA_V2 = 0xF0`. One signing command. Every
//! legacy shim (v1 Keycard Shell, bootstrap/main signing, ZK clear-
//! signing, EIP-191, EIP-712) is gone — the single sign-userop Type 1 /
//! Type 2 state machine in the secure world absorbs the lot.
//!
//! Supported v2 instructions:
//!
//! | INS  | Name                     |
//! |------|--------------------------|
//! | 0x01 | GET_DEVICE_INFO          |
//! | 0x02 | GET_STATUS               |
//! | 0x10 | UNLOCK                   |
//! | 0x11 | LOCK                     |
//! | 0x30 | SIGN_USEROP (unified)    |
//! | 0x60 | GET_WALLET_ADDRESS       |
//! | 0x61 | GET_INIT_CODE            |
//! | 0xC0 | GET_RESPONSE             |

use sphincs_tz_shared::*;
use sphincs_tz_shared::apdu_framing::{
    parse_apdu_header, route_v2, ChainState, ChainStepOutcome,
};

use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data across chained APDUs. Size reflects
/// the worst-case unified sign payload: `SIGN_USEROP_HEADER_LEN`-byte
/// header + max inner-tx calldata (`MAX_TX_LEN`) + optional 2-byte prefix
/// + max ERC-20 bundle + optional 2-byte prefix + max ZK clear-sign
/// bundle (proof + calldata + readable + VK bundle).
///
/// Also accommodates `INS_V2_FW_BEGIN`'s 8 KB manifest — the max
/// function below resolves to whichever of the two use cases is
/// larger. `const fn max` isn't available in no_std stable, so we
/// hand-expand via a pair of `const` branches and compile-asserts.
const CHAIN_BUF_LEN_SIGN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2
    + 1120
    + 2
    + ZK_CLEAR_SIGN_FIXED_LEN
    + ZK_VK_BUNDLE_MAX_LEN
    // v3 CoW EIP-712 trailer: 2-byte length + fixed prefix + VK bundle.
    + 2
    + ZK_V3_FIXED_LEN
    + ZK_VK_BUNDLE_MAX_LEN
    // ERC-7730 clear-signing descriptor trailer (Phase 3): 2-byte
    // length + bundle (up to ERC7730_MAX_TRAILER_LEN = 5130 B). Sits
    // between self-attest and names per the wire-format ordering in
    // `docs/handoff-erc7730-phase3.md` §"Canonical wire formats".
    + 2
    + sphincs_tz_shared::ERC7730_MAX_TRAILER_LEN
    // Names trailer: 1-byte count + up to 4 × (2-byte length + bundle).
    // The 1200-byte-per-bundle figure is the MAX_NAME_BUNDLE_LEN upper
    // bound plus the 2-byte length prefix, rounded to the 32-bit
    // proof-depth cap.
    + 1
    + 4 * (2 + 1200)
    + 64;
const CHAIN_BUF_LEN_FW: usize = fw_manifest::MANIFEST_SIZE + 64;
/// Worst-case batch sign payload: header + N × (per-tx prefix +
/// MAX_TX_LEN data). Defined in the shared crate as
/// [`sphincs_tz_shared::SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN`].
const CHAIN_BUF_LEN_BATCH: usize = SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN;
const CHAIN_BUF_LEN_SIGN_OR_BATCH: usize = if CHAIN_BUF_LEN_SIGN > CHAIN_BUF_LEN_BATCH {
    CHAIN_BUF_LEN_SIGN
} else {
    CHAIN_BUF_LEN_BATCH
};
const CHAIN_BUF_LEN: usize = if CHAIN_BUF_LEN_SIGN_OR_BATCH > CHAIN_BUF_LEN_FW {
    CHAIN_BUF_LEN_SIGN_OR_BATCH
} else {
    CHAIN_BUF_LEN_FW
};

/// Response buffer — sized for the maximum unified output plus
/// the 2-byte SW.
static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN + 2] = [0u8; MAX_SIGN_RESPONSE_LEN + 2];

/// Short response buffer (non-signature responses).
static mut RESP_BUF: [u8; 256] = [0u8; 256];

/// Command chaining accumulation buffer.
static mut CHAIN_BUF: [u8; CHAIN_BUF_LEN] = [0u8; CHAIN_BUF_LEN];

/// Pending GET_RESPONSE state.
static mut PENDING_PTR: *const u8 = core::ptr::null();
static mut PENDING_LEN: usize = 0;
static mut PENDING_POS: usize = 0;

// ---------------------------------------------------------------------------
// Firmware version
// ---------------------------------------------------------------------------

const FW_VERSION: [u8; 3] = [0x03, 0x00, 0x00];

// ---------------------------------------------------------------------------
// Capability bits (reported by GET_DEVICE_INFO).
// ---------------------------------------------------------------------------

const CAP_SIGN_USEROP: u32 = 1 << 0; // the one sign command
// Bit 1 (CAP_FLASH_NEXT_Q) is retired — post-C10-cutover the firmware
// is stateless for slot selection; the companion drives rotation.

// ---------------------------------------------------------------------------
// Response wrapper
// ---------------------------------------------------------------------------

pub struct Response {
    pub ptr: *const u8,
    pub len: usize,
}

// ---------------------------------------------------------------------------
// Command Router
// ---------------------------------------------------------------------------

pub struct CommandRouter {
    /// Chained-APDU state. The ISO 7816-4 framing — INS-mid-chain
    /// detection, monotonic write cursor, overflow-safe length checks
    /// — lives in `sphincs_tz_shared::apdu_framing` so the production
    /// path here and the proptest harness in
    /// `shared/src/apdu_framing.rs` exercise byte-identical logic.
    chain: ChainState,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain: ChainState::new(),
        }
    }

    pub unsafe fn dispatch(&mut self, apdu: &[u8]) -> Response {
        // Pure header parser — host-fuzzed in
        // `sphincs_tz_shared::apdu_framing::fuzz_props`.
        let header = match parse_apdu_header(apdu) {
            Ok(h) => h,
            Err(e) => return self.sw_response(e.to_sw()),
        };

        // GET_RESPONSE is CLA-agnostic so the companion can keep using
        // it without tracking which chain the pending bytes belong to.
        if header.ins == INS_V2_GET_RESPONSE {
            return self.get_response();
        }
        if let Err(e) = route_v2(&header) {
            return self.sw_response(e.to_sw());
        }

        let ins = header.ins;
        let p1 = header.p1;
        let lc = header.lc;
        let data = header.data;

        // Non-chained commands (full payload fits in one APDU).
        match ins {
            INS_V2_GET_DEVICE_INFO => return self.cmd_get_device_info(),
            INS_V2_GET_STATUS => return self.cmd_get_status(),
            INS_V2_UNLOCK => return self.cmd_unlock(),
            INS_V2_LOCK => return self.cmd_lock(),
            INS_V2_GET_WALLET_ADDRESS => return self.cmd_get_wallet_address(data),
            INS_V2_GET_INIT_CODE => return self.cmd_get_init_code(data),
            // INS_V2_SIGN_OFFCHAIN is chained — see `execute_chain`.
            // PersonalSign payloads can run up to ~700 bytes, well past
            // the single-APDU Lc=255 limit.
            INS_V2_OFFCHAIN_STATUS => return self.cmd_offchain_status(data),
            INS_V2_OFFCHAIN_SYNC => return self.cmd_offchain_sync(data),

            // Firmware-update non-chained commands. CHUNK carries the
            // 8-byte header + up to 1024 bytes of data — well under
            // the 253-byte APDU data limit, so it's NOT chained:
            // each CMD_FW_CHUNK is exactly one APDU. COMMIT / STATUS
            // / ABORT have no payload.
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_CHUNK => return self.cmd_fw_chunk(data),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_COMMIT => return self.cmd_fw_commit(),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_STATUS => return self.cmd_fw_status(),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_ABORT => return self.cmd_fw_abort(),

            // Prodtest INSes (companion → device, prodtest builds only).
            // No PIN gating — the prodtest firmware runs before any
            // user state exists. Each command writes its output bytes
            // into `RESP_BUF` followed by the 2-byte SW.
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_GET_ID => return self.cmd_prodtest_get_id(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_DISPLAY_PATTERN => return self.cmd_prodtest_display_pattern(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_SAES_SELFTEST => return self.cmd_prodtest_saes_selftest(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_BHK_SELFTEST => return self.cmd_prodtest_bhk_selftest(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_FLASH_RW => return self.cmd_prodtest_flash_rw(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_TRNG_SAMPLE => return self.cmd_prodtest_trng_sample(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_OPTIGA_HANDSHAKE => return self.cmd_prodtest_optiga_handshake(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_SE050_HANDSHAKE => return self.cmd_prodtest_se050_handshake(),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_USB_LOOPBACK => return self.cmd_prodtest_usb_loopback(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_BUTTON_TEST => return self.cmd_prodtest_button_test(),

            _ => {}
        }

        // Chained commands. The state machine, INS-mismatch detection,
        // and overflow-safe length checks all live in
        // `ChainState::step` — see `shared/src/apdu_framing.rs`. We
        // only need to copy `lc` bytes into `CHAIN_BUF` at the cursor
        // the helper hands us, then either ack or execute.
        match self.chain.step(ins, p1, lc, CHAIN_BUF_LEN) {
            ChainStepOutcome::Appended { write_at, lc } => {
                if lc > 0 {
                    CHAIN_BUF[write_at..write_at + lc].copy_from_slice(data);
                }
                self.sw_response(SW_OK)
            }
            ChainStepOutcome::Execute { ins, final_len, write_at, lc } => {
                if lc > 0 {
                    CHAIN_BUF[write_at..write_at + lc].copy_from_slice(data);
                }
                self.execute_chain(ins, final_len)
            }
            ChainStepOutcome::ProtocolError => {
                self.sw_response(ChainStepOutcome::protocol_error_sw())
            }
            ChainStepOutcome::WrongLength => {
                self.sw_response(ChainStepOutcome::wrong_length_sw())
            }
        }
    }

    unsafe fn execute_chain(&mut self, ins: u8, len: usize) -> Response {
        match ins {
            INS_V2_SIGN_USEROP => self.cmd_sign_userop(len),
            INS_V2_SIGN_USEROP_BATCH => self.cmd_sign_userop_batch(len),
            INS_V2_SIGN_OFFCHAIN => self.cmd_sign_offchain(len),
            #[cfg(feature = "stm32u585")]
            INS_V2_FW_BEGIN => self.cmd_fw_begin(len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // Command handlers
    // ===================================================================

    /// 0x01 GET_DEVICE_INFO.
    unsafe fn cmd_get_device_info(&self) -> Response {
        let mut p = 0usize;

        RESP_BUF[p..p + 2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        p += 2;

        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;

        RESP_BUF[p..p + 16].fill(0); // device_uid placeholder
        p += 16;

        let caps = CAP_SIGN_USEROP;
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        RESP_BUF[p] = 2; // sig_param_set: 2 = SPHINCS+C10 (128-bit) everywhere
        p += 1;

        // Type 2 sig size — now fixed at `SIG_TYPE2_LEN` bytes.
        RESP_BUF[p..p + 2].copy_from_slice(&(SIG_TYPE2_LEN as u16).to_be_bytes());
        p += 2;

        // Unused legacy version fields, zeroed.
        RESP_BUF[p..p + 4].fill(0);
        p += 4;
        RESP_BUF[p..p + 4].fill(0);
        p += 4;

        // ep_version: 0x0006 (EntryPoint v0.6).
        RESP_BUF[p..p + 2].copy_from_slice(&0x0006u16.to_be_bytes());
        p += 2;

        // Wrapper-overhead: header bytes prepended to each signed tx.
        RESP_BUF[p..p + 2].copy_from_slice(&(SIG_TYPE2_HEADER_LEN as u16).to_be_bytes());
        p += 2;

        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response {
            ptr: RESP_BUF.as_ptr(),
            len: p,
        }
    }

    /// 0x02 GET_STATUS.
    unsafe fn cmd_get_status(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        let unlocked = nsc_api::is_unlocked();

        let provisioned: u8 = if remaining <= MAX_ATTEMPTS as u32 { 1 } else { 0 };

        RESP_BUF[0] = provisioned;
        RESP_BUF[1] = if unlocked { 0 } else { 1 };
        RESP_BUF[2] = remaining as u8;
        RESP_BUF[3] = (SW_OK >> 8) as u8;
        RESP_BUF[4] = (SW_OK & 0xFF) as u8;

        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 5,
        }
    }

    /// 0x10 UNLOCK.
    unsafe fn cmd_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    /// 0x11 LOCK.
    unsafe fn cmd_lock(&self) -> Response {
        nsc_api::lock();
        self.sw_response(SW_OK)
    }

    /// 0x60 GET_WALLET_ADDRESS — return the 20-byte CREATE2-predicted
    /// sender for this device's bootstrap C10 pubkey at `account_index`.
    /// Requires unlock.
    ///
    /// APDU body layout: 4 bytes big-endian `account_index` (0..=255).
    /// An empty body is accepted as `account_index == 0` so legacy
    /// companion builds that pre-date multi-account derivation still
    /// see their original single wallet.
    unsafe fn cmd_get_wallet_address(&self, data: &[u8]) -> Response {
        let account_index = match data.len() {
            0 => 0u32,
            4 => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            _ => return self.sw_response(SW_WRONG_LENGTH),
        };
        let mut addr = [0u8; 20];
        let status = nsc_api::get_wallet_address(&mut addr, account_index);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        RESP_BUF[..20].copy_from_slice(&addr);
        RESP_BUF[20..22].copy_from_slice(&SW_OK.to_be_bytes());
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 22,
        }
    }

    /// 0x61 GET_INIT_CODE — return the 4280-byte ERC-4337 initCode for
    /// `(account_index, chain_id)`. Used by the companion's gas
    /// estimator for not-yet-deployed wallets; the bytes are
    /// byte-identical to what the deploy path of SIGN_USEROP emits
    /// and safe to cache. Requires an unlocked device.
    ///
    /// APDU body: 12 bytes `[account_index u32 BE || chain_id u64 BE]`.
    /// Response: 4280 bytes streamed via `GET_RESPONSE` chaining.
    unsafe fn cmd_get_init_code(&self, data: &[u8]) -> Response {
        if data.len() != 12 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::get_init_code(
            data,
            &mut SIG_BUF[..PQ_INIT_CODE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        // PQ_INIT_CODE_LEN = 4280 > APDU_MAX_RESP (253), so this always
        // enters the GET_RESPONSE chaining path. The chunker lives in
        // `setup_chunked_response` and reuses the caller's existing
        // PENDING_PTR/LEN/POS cursor.
        self.setup_chunked_response(PQ_INIT_CODE_LEN)
    }

    /// 0x30 SIGN_USEROP — unified Type 1 / Type 2 state machine.
    ///
    /// The payload is the `SIGN_USEROP_HEADER_LEN`-byte header plus
    /// the inner tx calldata (see `sphincs_tz_shared::SIGN_USEROP_HEADER_LEN`
    /// for the canonical layout). The secure world writes a bundled
    /// response into `SIG_BUF`:
    ///
    /// ```text
    ///   [init_code_len u32 BE] [init_code_bytes...]
    ///   [type1_len     u32 BE] [type1_bytes...]
    ///   [type2_len     u32 BE] [type2_bytes...]
    /// ```
    ///
    /// `init_code_len` is non-zero only when the companion set
    /// `FLAG_INCLUDE_INIT_CODE` on the request (fresh wallet, first deploy
    /// on this chain). Similarly `type1_len == 0` means slot registration
    /// was not needed and the companion should submit only Type 2.
    unsafe fn cmd_sign_userop(&self, data_len: usize) -> Response {
        if data_len < SIGN_USEROP_HEADER_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        // Opportunistically attach an ERC-20 metadata bundle if the
        // companion didn't already include a trailer and the (chain_id,
        // tx.to) pair matches a known token. The secure world still
        // Merkle-verifies every byte before trusting it for display.
        let effective_len = Self::maybe_inject_erc20_bundle(data_len);
        // If the companion attached a ZK clear-sign trailer with just
        // proof + calldata + readable (no VK bundle), look up the VK by
        // (chain_id, tx.to) and append it so the secure world's
        // Groth16 verifier has a Merkle-proven key to work with.
        let effective_len = Self::maybe_inject_vk_bundle(effective_len);
        // v3 CoW EIP-712 clear-sign: same treatment, but the lookup key
        // is the COWSWAP_EIP712_SENTINEL rather than `tx.to` (the real
        // GPv2Settlement contract). Must run AFTER the v1 injector so
        // the outer trailer shape it parses is stable.
        let effective_len = Self::maybe_inject_vk_bundle_v3(effective_len);
        // Append address-name bundles for every tx address that hits
        // the NS names DB. Secure world merkle-verifies each before
        // letting any name reach the trusted UI.
        let effective_len = Self::maybe_inject_names_bundles(effective_len);

        let status = nsc_api::sign_userop(
            &CHAIN_BUF[..effective_len],
            &mut SIG_BUF[..MAX_SIGN_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        match Self::total_sign_response_len() {
            Some(total) => self.setup_chunked_response(total),
            None => self.sw_response(SW_INTERNAL_ERROR),
        }
    }

    /// 0x32 SIGN_USEROP_BATCH — atomic multi-call sign command. The
    /// payload is the `CMD_SIGN_USEROP_BATCH` wire format
    /// (`SIGN_USEROP_BATCH_HEADER_LEN` header + N inner-tx blocks);
    /// the response framing is byte-identical to
    /// [`Self::cmd_sign_userop`]'s (the only on-chain difference is
    /// that the resulting UserOp's callData is
    /// `executeBatchWithOffchainCount(...)` instead of the
    /// single-call `executeWithOffchainCount(...)`).
    ///
    /// No NS-side trailer injection: batch-tx clear-signing renders
    /// through the basic value/erc20-shape/blind-sign ladder. ZK,
    /// Safe, and ERC-20 metadata trailers are single-tx-only by
    /// construction.
    unsafe fn cmd_sign_userop_batch(&self, data_len: usize) -> Response {
        if data_len < SIGN_USEROP_BATCH_HEADER_LEN + SIGN_USEROP_BATCH_TX_PREFIX_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let status = nsc_api::sign_userop_batch(
            &CHAIN_BUF[..data_len],
            &mut SIG_BUF[..MAX_SIGN_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        match Self::total_sign_response_len() {
            Some(total) => self.setup_chunked_response(total),
            None => self.sw_response(SW_INTERNAL_ERROR),
        }
    }

    /// Parse the bundled sign-userop response framing — same shape for
    /// the single-call and batch sign paths — out of `SIG_BUF` and return
    /// the total length to ship to the host, or `None` if any declared
    /// length overflows the response buffer (which can only happen on a
    /// firmware bug, hence the `SW_INTERNAL_ERROR` mapping at the call
    /// site).
    ///
    /// Framing (after the firmware's gateway write):
    /// ```text
    ///   [new_offchain_count(8 BE)]
    ///   [init_code_len(4 BE)] [init_code...]
    ///   [type1_len(4 BE)]    [type1...]
    ///   [type2_len(4 BE)]    [type2...]
    /// ```
    unsafe fn total_sign_response_len() -> Option<usize> {
        const COUNT_LEN: usize = 8;

        let ic_len_off = COUNT_LEN;
        let ic_len = read_be_u32(&SIG_BUF, ic_len_off)? as usize;

        let t1_len_off = ic_len_off + 4 + ic_len;
        let t1_len = read_be_u32(&SIG_BUF, t1_len_off)? as usize;

        let t2_len_off = t1_len_off + 4 + t1_len;
        let t2_len = read_be_u32(&SIG_BUF, t2_len_off)? as usize;

        let total = t2_len_off + 4 + t2_len;
        if total > MAX_SIGN_RESPONSE_LEN {
            return None;
        }
        Some(total)
    }

    /// 0x62 SIGN_OFFCHAIN — produce a SPHINCS+C10 sig for an EIP-1271
    /// request. Body is variable-length (`SIGN_OFFCHAIN_HEADER_LEN +
    /// payload_len`); the secure world parses the `kind` byte and
    /// validates `payload_len` against the per-kind constraints. The
    /// hard upper bound (`SIGN_OFFCHAIN_INPUT_MAX_LEN`) is enforced
    /// here so an oversize HID body is rejected before the gateway
    /// call. PersonalSign payloads can run up to ~700 bytes — past the
    /// single-APDU Lc=255 limit — so the request is APDU-chained;
    /// `execute_chain` calls us with the assembled payload pulled out
    /// of `CHAIN_BUF`.
    ///
    /// Response length depends on the `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`
    /// bit in the input flags byte:
    ///   * set (deployed): 4016 B (8 count + 4008 C10 sig)
    ///   * clear (counterfactual): 8616 B (8 count + 8608 ERC-6492
    ///     wrapped sig)
    unsafe fn cmd_sign_offchain(&self, data_len: usize) -> Response {
        if data_len < sphincs_tz_shared::SIGN_OFFCHAIN_HEADER_LEN
            || data_len > sphincs_tz_shared::SIGN_OFFCHAIN_INPUT_MAX_LEN
        {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let flags = CHAIN_BUF[sphincs_tz_shared::SIGN_OFFCHAIN_INPUT_FLAGS_OFF];
        let account_deployed =
            flags & sphincs_tz_shared::OFFCHAIN_FLAG_ACCOUNT_DEPLOYED != 0;
        let out_len = if account_deployed {
            sphincs_tz_shared::SIGN_OFFCHAIN_OUTPUT_LEN
        } else {
            sphincs_tz_shared::SIGN_OFFCHAIN_OUTPUT_LEN_6492
        };
        let status = nsc_api::sign_offchain(&CHAIN_BUF[..data_len], &mut SIG_BUF[..out_len]);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(out_len)
    }

    /// 0x63 OFFCHAIN_STATUS — read per-slot off-chain state. Body: 13
    /// bytes. Response: 24 bytes (fits in a single APDU).
    unsafe fn cmd_offchain_status(&self, data: &[u8]) -> Response {
        if data.len() != sphincs_tz_shared::OFFCHAIN_STATUS_INPUT_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::offchain_status(
            data,
            &mut RESP_BUF[..sphincs_tz_shared::OFFCHAIN_STATUS_OUTPUT_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        let total = sphincs_tz_shared::OFFCHAIN_STATUS_OUTPUT_LEN;
        RESP_BUF[total..total + 2].copy_from_slice(&SW_OK.to_be_bytes());
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: total + 2,
        }
    }

    /// 0x64 OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
    /// companion-supplied floor. Input is the 21-byte
    /// `OFFCHAIN_SYNC_INPUT_LEN` payload. No response body, SW only.
    unsafe fn cmd_offchain_sync(&self, data: &[u8]) -> Response {
        if data.len() != sphincs_tz_shared::OFFCHAIN_SYNC_INPUT_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::offchain_sync(data);
        self.nsc_status_to_response(status)
    }

    /// If the companion sent a bare `[header | data]` payload (no
    /// trailer sections) and `(chain_id, tx.to)` hits the NS-side ERC-20
    /// database, append an `[u16 BE len | bundle]` trailer inside
    /// `CHAIN_BUF` so the secure world can render a token-aware
    /// confirmation page instead of falling back to "Unknown token".
    ///
    /// Returns the (possibly extended) payload length. On any failure
    /// (lookup miss, payload already has trailers, no room) returns
    /// `received_len` unchanged — the secure world degrades gracefully
    /// to `Erc20Unknown`.
    unsafe fn maybe_inject_erc20_bundle(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }

        let data_len = u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let payload_end = SIGN_USEROP_HEADER_LEN + data_len;
        if payload_end > received_len {
            return received_len;
        }
        // Only augment bare payloads. If the companion already provided
        // trailer sections, trust its layout.
        if received_len != payload_end {
            return received_len;
        }
        // Plain value transfer — no ERC-20 metadata needed.
        if data_len == 0 {
            return received_len;
        }

        let chain_id = u64::from_be_bytes([
            CHAIN_BUF[0],
            CHAIN_BUF[1],
            CHAIN_BUF[2],
            CHAIN_BUF[3],
            CHAIN_BUF[4],
            CHAIN_BUF[5],
            CHAIN_BUF[6],
            CHAIN_BUF[7],
        ]);
        // Default lookup key is the outer tx.to. For Safe `execTransaction`
        // UserOps the outer `to` is the Safe contract (which won't be in
        // the ERC-20 DB), but the inner SafeTx target — encoded as the
        // first head word of the calldata — IS the token contract when
        // the Safe is being used to dispatch an ERC-20 transfer. Detect
        // that selector and pivot the lookup to the inner address so the
        // secure-world renderer sees a Merkle-verified Erc20Metadata
        // bundle and surfaces the "Send USDC / Base USDC / amount" pages
        // the user would get on a direct ERC-20 call.
        //
        // The inner read is purely advisory for DB lookup; the secure
        // world still Merkle-verifies the bundle and re-decodes the
        // execTransaction calldata via the strict verifier in
        // `tx::eip712::safe::verify_and_bind_exec`, then enforces
        // `bundle.contract == exec.decoded.to` inside
        // `display::pick_sign_pages` before applying the metadata. A
        // hostile companion that lies here only succeeds in either
        // (a) hitting an unrelated DB row that mismatches the verifier's
        // inner-to → bundle gets dropped → degrade to Erc20Unknown, or
        // (b) hitting nothing at all → degrade to Erc20Unknown. No
        // attribution can be lent to a wrong token.
        let mut to = [0u8; 20];
        let data_start = SIGN_USEROP_HEADER_LEN;
        let data_end = data_start + data_len;
        let exec_inner = data_len >= EXEC_TRANSACTION_MIN_CALLDATA_LEN
            && CHAIN_BUF[data_start..data_start + 4] == EXEC_TRANSACTION_SELECTOR
            // Canonical address word: top 12 bytes must be zero. If the
            // companion / Safe encoded something non-canonical we fall
            // back to the outer-to lookup (still safe — just no boost).
            && CHAIN_BUF[data_start + 4..data_start + 4 + 12]
                .iter()
                .all(|&b| b == 0)
            && data_end <= received_len;
        if exec_inner {
            to.copy_from_slice(&CHAIN_BUF[data_start + 4 + 12..data_start + 4 + 32]);
        } else {
            to.copy_from_slice(&CHAIN_BUF[276..296]);
        }

        // Matches `MAX_ERC20_BUNDLE_LEN` in `secure/src/erc20/bundle.rs`.
        let mut bundle_buf = [0u8; 1120];
        let Some(bundle_len) = crate::erc20_db::build_bundle(chain_id, &to, &mut bundle_buf) else {
            return received_len;
        };

        let new_len = payload_end + 2 + bundle_len;
        if new_len > CHAIN_BUF_LEN {
            return received_len;
        }

        CHAIN_BUF[payload_end..payload_end + 2]
            .copy_from_slice(&(bundle_len as u16).to_be_bytes());
        CHAIN_BUF[payload_end + 2..new_len].copy_from_slice(&bundle_buf[..bundle_len]);
        new_len
    }

    /// Append a VK bundle to a fixed-length trailer section living at
    /// `CHAIN_BUF[trailer_offset..received_len]`.
    ///
    /// Shared implementation for the v1 and v3 VK injectors — both
    /// follow the same pattern: verify the trailer's declared length
    /// matches `fixed_len` (the bare companion-sent shape, pre-bundle),
    /// verify the trailer ends exactly at `received_len` (no further
    /// sections after), look up the `(chain_id, contract_key)` pair in
    /// the NS VK DB, append the bundle, rewrite the trailer's length
    /// header. Any failure returns `received_len` unchanged — the
    /// secure world handles the degraded case downstream.
    ///
    /// The only non-shared piece is `(trailer_offset, fixed_len,
    /// contract_key)` — the v1 injector passes `after_erc20`,
    /// `ZK_CLEAR_SIGN_FIXED_LEN`, and the tx's `to` address; the v3
    /// injector passes `after_zk`, `ZK_V3_FIXED_LEN`, and the
    /// `COWSWAP_EIP712_SENTINEL`.
    unsafe fn inject_vk_bundle_at(
        received_len: usize,
        trailer_offset: usize,
        fixed_len: usize,
        contract_key: &[u8; 20],
    ) -> usize {
        if trailer_offset + 2 > received_len {
            return received_len;
        }
        let declared_len =
            u16::from_be_bytes([CHAIN_BUF[trailer_offset], CHAIN_BUF[trailer_offset + 1]]) as usize;
        // Only act on the exact bare shape. Anything else either already
        // has a VK bundle attached or is malformed; let the secure world
        // do the rejection.
        if declared_len != fixed_len {
            return received_len;
        }
        let trailer_end = trailer_offset + 2 + declared_len;
        if trailer_end != received_len {
            return received_len;
        }

        let chain_id = u64::from_be_bytes([
            CHAIN_BUF[0], CHAIN_BUF[1], CHAIN_BUF[2], CHAIN_BUF[3],
            CHAIN_BUF[4], CHAIN_BUF[5], CHAIN_BUF[6], CHAIN_BUF[7],
        ]);

        let mut vk_bundle_buf = [0u8; ZK_VK_BUNDLE_MAX_LEN];
        let Some(vk_bundle_len) =
            crate::vk_db::build_bundle(chain_id, contract_key, &mut vk_bundle_buf)
        else {
            return received_len;
        };

        let new_declared_len = declared_len + vk_bundle_len;
        let new_len = trailer_end + vk_bundle_len;
        if new_len > CHAIN_BUF_LEN || new_declared_len > u16::MAX as usize {
            return received_len;
        }

        CHAIN_BUF[trailer_end..new_len].copy_from_slice(&vk_bundle_buf[..vk_bundle_len]);
        CHAIN_BUF[trailer_offset..trailer_offset + 2]
            .copy_from_slice(&(new_declared_len as u16).to_be_bytes());
        new_len
    }

    /// If the companion attached a v1 ZK clear-sign trailer containing
    /// just the fixed `proof + calldata + readable` block
    /// (exactly `ZK_CLEAR_SIGN_FIXED_LEN` bytes) and
    /// `(chain_id, tx.to)` hits the NS-side VK database, append the
    /// looked-up VK bundle so the secure world's Groth16 verifier has
    /// a Merkle-proven key to work with.
    ///
    /// Delegates to [`inject_vk_bundle_at`]; the only v1-specific work
    /// is locating the v1 trailer (past the ERC-20 section) and
    /// sourcing the contract key from the tx's `to` address.
    unsafe fn maybe_inject_vk_bundle(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }
        let data_len = u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let after_data = SIGN_USEROP_HEADER_LEN + data_len;
        if after_data + 2 > received_len {
            return received_len;
        }
        let erc20_len =
            u16::from_be_bytes([CHAIN_BUF[after_data], CHAIN_BUF[after_data + 1]]) as usize;
        let after_erc20 = after_data + 2 + erc20_len;

        let mut to = [0u8; 20];
        to.copy_from_slice(&CHAIN_BUF[276..296]);

        Self::inject_vk_bundle_at(received_len, after_erc20, ZK_CLEAR_SIGN_FIXED_LEN, &to)
    }

    /// Companion of `maybe_inject_vk_bundle`, but for the v3 CoW
    /// EIP-712 clear-sign trailer: when the companion sends a 716-byte
    /// `zk_v3` section (proof + canonical + readable, no VK bundle),
    /// look up the v3 VK at `(chain_id, COWSWAP_EIP712_SENTINEL)` in
    /// the VK DB and append the matching bundle so the secure world's
    /// 3-pub Groth16 verifier has a Merkle-proven key.
    ///
    /// Looks up the VK by the sentinel, NOT by `tx.to` — the real
    /// GPv2Settlement address keys the v1 setPreSignature VK; the
    /// sentinel keys the v3 order VK. Both live in the same VK DB
    /// under the same `(chain_id, contract)` schema.
    unsafe fn maybe_inject_vk_bundle_v3(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }
        let data_len = u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let after_data = SIGN_USEROP_HEADER_LEN + data_len;
        if after_data + 2 > received_len {
            return received_len;
        }
        let erc20_len =
            u16::from_be_bytes([CHAIN_BUF[after_data], CHAIN_BUF[after_data + 1]]) as usize;
        let after_erc20 = after_data + 2 + erc20_len;
        if after_erc20 + 2 > received_len {
            return received_len;
        }
        let zk_len =
            u16::from_be_bytes([CHAIN_BUF[after_erc20], CHAIN_BUF[after_erc20 + 1]]) as usize;
        let after_zk = after_erc20 + 2 + zk_len;

        Self::inject_vk_bundle_at(received_len, after_zk, ZK_V3_FIXED_LEN, &COWSWAP_EIP712_SENTINEL)
    }

    /// Append address-name bundles for every candidate address the
    /// trusted UI is about to display whose `(chain_id, addr)` matches
    /// an entry in the NS names DB. The secure world re-verifies each
    /// bundle against the embedded `NAMES_DB_ROOT`, so failed or
    /// tampered bundles only ever degrade the display back to raw hex.
    ///
    /// Candidates scanned (in order, deduplicated):
    ///   * `tx.to`
    ///   * ERC-20 `transfer` / `transferFrom` recipient
    ///   * ERC-20 `approve` spender
    ///
    /// Trailer wire format (appended at `CHAIN_BUF[received_len..]`):
    ///   `[count u8][len u16 BE][bundle] ... repeat `count` times`
    ///
    /// A count of 0 is never emitted — if there are no hits the
    /// trailer is absent, which the secure world treats as "no
    /// names bundles".
    /// Ensure the `[erc20][v1_zk][v3_zk][safe_v1][selector]` u16-prefixed
    /// trailer skeleton is fully present before `received_len`, padding
    /// any missing prefix with `[0x00, 0x00]`.
    ///
    /// Background: the secure-world sign_userop parser walks trailers
    /// positionally in that exact order and then reads the `names`
    /// trailer at whatever cursor lands after them. If a caller sent a
    /// payload that stops earlier in the chain (e.g. a CoW v3 sign-userop
    /// emits only `erc20+v1_zk+v3_zk` and stops there, since the v3 VK
    /// injector requires `trailer_end == received_len`), the secure
    /// parser will consume the `[count][bundle_len][...]` framing of the
    /// names trailer as `safe_v1`'s u16 length and the next pair as
    /// `selector`'s — bytes that are almost always > the per-trailer
    /// caps and trip "bad safe bundle" or "bad selector bundle" on the
    /// OLED. (Earlier symptom: "Sign v3 len>cap" when only 1 prefix was
    /// padded.)
    ///
    /// This helper walks the trailer chain and appends empty `[0, 0]`
    /// u16 prefixes for any section not yet encoded, returning the
    /// updated `received_len`. For a payload that already contains a
    /// full skeleton this is a no-op.
    unsafe fn ensure_trailer_skeleton(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }
        let data_len =
            u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let after_data = SIGN_USEROP_HEADER_LEN + data_len;
        if after_data > received_len {
            return received_len;
        }
        let mut pos = after_data;
        let mut new_len = received_len;
        // Six empty u16 prefixes to ensure, in secure-parser order:
        // erc20, v1_zk, v3_zk, safe_v1, selector, self_attest. Must match
        // the parse sequence in `secure/src/nsc/cmd_sign_userop.rs::run`
        // exactly — any divergence causes the names trailer to misalign
        // with the secure parser's cursor and surfaces on the OLED as a
        // "bad <section> bundle" / "bad self-attest" error.
        // (Bumped from 5 → 6 when commit 33cd0ed added the self_attest
        // slot to the secure parser; without this the NS-injected names
        // count byte got read as the self_attest u16 length and tripped
        // "bad self-attest" on every ETH transfer to a named address.)
        for _ in 0..6 {
            if pos + 2 > new_len {
                if pos + 2 > CHAIN_BUF_LEN {
                    return new_len;
                }
                CHAIN_BUF[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
                new_len = pos + 2;
                pos += 2;
            } else {
                let section_len =
                    u16::from_be_bytes([CHAIN_BUF[pos], CHAIN_BUF[pos + 1]]) as usize;
                pos += 2 + section_len;
                if pos > new_len {
                    // Declared section extends past received_len — leave
                    // it to the secure parser to reject; don't attempt
                    // recovery that could mask a real truncation bug.
                    return new_len;
                }
            }
        }
        new_len
    }

    unsafe fn maybe_inject_names_bundles(received_len: usize) -> usize {
        // Complete the `[erc20][v1_zk][v3_zk]` skeleton before appending
        // names. See `ensure_trailer_skeleton` for the full rationale —
        // without this, NS-injected names mis-parse as v1/v3 zk lengths
        // in the secure world and fire "Sign v3 len>cap".
        let received_len = Self::ensure_trailer_skeleton(received_len);
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }

        let chain_id = u64::from_be_bytes([
            CHAIN_BUF[0],
            CHAIN_BUF[1],
            CHAIN_BUF[2],
            CHAIN_BUF[3],
            CHAIN_BUF[4],
            CHAIN_BUF[5],
            CHAIN_BUF[6],
            CHAIN_BUF[7],
        ]);
        let mut tx_to = [0u8; 20];
        tx_to.copy_from_slice(&CHAIN_BUF[276..296]);

        // Collect up to 4 distinct candidate addresses.
        let mut candidates: [[u8; 20]; 4] = [[0u8; 20]; 4];
        let mut cand_n = 0usize;
        let push = |buf: &mut [[u8; 20]; 4], n: &mut usize, a: &[u8; 20]| {
            if *a == [0u8; 20] {
                return;
            }
            for slot in &buf[..*n] {
                if slot == a {
                    return;
                }
            }
            if *n < buf.len() {
                buf[*n] = *a;
                *n += 1;
            }
        };
        push(&mut candidates, &mut cand_n, &tx_to);

        // Parse ERC-20 calldata off the unsigned tx to surface
        // recipient/spender addresses too.
        let data_len =
            u16::from_be_bytes([CHAIN_BUF[328], CHAIN_BUF[329]]) as usize;
        let data_end = SIGN_USEROP_HEADER_LEN + data_len;
        if data_end <= received_len && data_len >= 4 + 32 + 32 {
            let data = &CHAIN_BUF[SIGN_USEROP_HEADER_LEN..data_end];
            let sel = &data[..4];
            // transfer(address,uint256) = 0xa9059cbb
            // approve(address,uint256)  = 0x095ea7b3
            // transferFrom(address,address,uint256) = 0x23b872dd
            if sel == [0xa9, 0x05, 0x9c, 0xbb] || sel == [0x09, 0x5e, 0xa7, 0xb3] {
                let mut a = [0u8; 20];
                a.copy_from_slice(&data[4 + 12..4 + 32]);
                push(&mut candidates, &mut cand_n, &a);
            } else if sel == [0x23, 0xb8, 0x72, 0xdd] && data_len >= 4 + 32 + 32 + 32 {
                let mut from_a = [0u8; 20];
                from_a.copy_from_slice(&data[4 + 12..4 + 32]);
                let mut to_a = [0u8; 20];
                to_a.copy_from_slice(&data[4 + 32 + 12..4 + 64]);
                push(&mut candidates, &mut cand_n, &from_a);
                push(&mut candidates, &mut cand_n, &to_a);
            }
        }

        if cand_n == 0 {
            return received_len;
        }

        // Reserve the count byte; we backfill it once we know how many
        // bundles actually verified.
        let count_off = received_len;
        if count_off + 1 > CHAIN_BUF_LEN {
            return received_len;
        }
        let mut cursor = count_off + 1;
        let mut emitted = 0u8;
        let mut bundle_buf = [0u8; 1200];

        for i in 0..cand_n {
            let addr = &candidates[i];
            let Some(bundle_len) =
                crate::names_db::build_bundle(chain_id, addr, &mut bundle_buf)
            else {
                continue;
            };
            if cursor + 2 + bundle_len > CHAIN_BUF_LEN || bundle_len > u16::MAX as usize {
                break;
            }
            CHAIN_BUF[cursor..cursor + 2].copy_from_slice(&(bundle_len as u16).to_be_bytes());
            cursor += 2;
            CHAIN_BUF[cursor..cursor + bundle_len].copy_from_slice(&bundle_buf[..bundle_len]);
            cursor += bundle_len;
            emitted += 1;
            if emitted as usize >= crate::names_db::MAX_NAME_BUNDLES {
                break;
            }
        }

        if emitted == 0 {
            // Revert: nothing to attach, don't emit a lone count byte.
            return received_len;
        }

        CHAIN_BUF[count_off] = emitted;
        cursor
    }

    // ===================================================================
    // GET_RESPONSE (CLA-agnostic)
    // ===================================================================

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_LEN == 0 {
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        let remaining = PENDING_LEN - PENDING_POS;
        let chunk = core::cmp::min(remaining, APDU_MAX_RESP);
        static mut CHUNK_BUF: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
        core::ptr::copy_nonoverlapping(PENDING_PTR.add(PENDING_POS), CHUNK_BUF.as_mut_ptr(), chunk);
        PENDING_POS += chunk;

        if PENDING_POS < PENDING_LEN {
            let left = PENDING_LEN - PENDING_POS;
            CHUNK_BUF[chunk] = SW_MORE_DATA;
            CHUNK_BUF[chunk + 1] = if left > 255 { 0xFF } else { left as u8 };
        } else {
            CHUNK_BUF[chunk] = (SW_OK >> 8) as u8;
            CHUNK_BUF[chunk + 1] = (SW_OK & 0xFF) as u8;
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
        }

        Response {
            ptr: CHUNK_BUF.as_ptr(),
            len: chunk + 2,
        }
    }

    // ===================================================================
    // Firmware-update command handlers (STM32U585 only)
    // ===================================================================

    /// CMD_FW_BEGIN — the 8 KB manifest has been accumulated in
    /// `CHAIN_BUF[..len]`. Hand the whole buffer to the secure world.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_begin(&self, len: usize) -> Response {
        if len != fw_manifest::MANIFEST_SIZE {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::fw_begin(&CHAIN_BUF[..len]);
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_CHUNK — one APDU, payload is `[header(8) | data(N)]`.
    /// Pass straight through; the secure world does the monotonic /
    /// bounds checks against its in-SRAM streaming state.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_chunk(&self, data: &[u8]) -> Response {
        if data.len() < FW_CHUNK_HEADER_LEN
            || data.len() > FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK
        {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let status = nsc_api::fw_chunk(data);
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_COMMIT — may not return if the commit succeeds (the
    /// device resets). Maps to a cancelled status word if the user
    /// rejects the dialog.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_commit(&self) -> Response {
        let status = nsc_api::fw_commit();
        self.sw_response(nsc_status_to_sw(status))
    }

    /// CMD_FW_STATUS — returns `[state|recv_s|recv_ns|slot]` + SW.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_status(&self) -> Response {
        let mut out = [0u8; FW_STATUS_RESPONSE_LEN];
        let status = nsc_api::fw_status(&mut out);
        if status != 0 {
            return self.sw_response(nsc_status_to_sw(status));
        }
        // Copy response + SW into RESP_BUF.
        RESP_BUF[..FW_STATUS_RESPONSE_LEN].copy_from_slice(&out);
        RESP_BUF[FW_STATUS_RESPONSE_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[FW_STATUS_RESPONSE_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: FW_STATUS_RESPONSE_LEN + 2,
        }
    }

    /// CMD_FW_ABORT — discard partial update. Always returns OK; the
    /// secure-side drop is idempotent.
    #[cfg(feature = "stm32u585")]
    unsafe fn cmd_fw_abort(&self) -> Response {
        let status = nsc_api::fw_abort();
        self.sw_response(nsc_status_to_sw(status))
    }

    // ===================================================================
    // Prodtest command handlers (`prodtest` feature only)
    // ===================================================================
    //
    // Each handler wraps a `CMD_PRODTEST_*` veneer. Response layout:
    //   [output_bytes ... | sw_hi | sw_lo]
    // SW is `SW_OK` on Ok, `SW_INTERNAL_ERROR` otherwise. Output bytes
    // are appended even on failure paths so the host fixture can still
    // log diagnostic data (e.g. the BUTTON_TEST step-status byte).

    #[cfg(feature = "prodtest")]
    unsafe fn prodtest_finalize(&self, n: usize, status: u32) -> Response {
        let sw = if status == 0 { SW_OK } else { SW_INTERNAL_ERROR };
        RESP_BUF[n] = (sw >> 8) as u8;
        RESP_BUF[n + 1] = (sw & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: n + 2,
        }
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_get_id(&self) -> Response {
        let mut out = [0u8; 24];
        let status = nsc_api::prodtest_get_id(&mut out);
        RESP_BUF[..24].copy_from_slice(&out);
        self.prodtest_finalize(24, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_display_pattern(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let pattern = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let status = nsc_api::prodtest_display_pattern(pattern);
        self.prodtest_finalize(0, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_saes_selftest(&self) -> Response {
        let mut out = [0u8; 8];
        let status = nsc_api::prodtest_saes_selftest(&mut out);
        RESP_BUF[..8].copy_from_slice(&out);
        self.prodtest_finalize(8, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_bhk_selftest(&self) -> Response {
        let mut out = [0u8; 8];
        let status = nsc_api::prodtest_bhk_selftest(&mut out);
        RESP_BUF[..8].copy_from_slice(&out);
        self.prodtest_finalize(8, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_flash_rw(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let pattern = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let status = nsc_api::prodtest_flash_rw(pattern);
        self.prodtest_finalize(0, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_trng_sample(&self, data: &[u8]) -> Response {
        if data.len() != 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let n = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if n == 0 || n > 256 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let n_usize = n as usize;
        // Buffer carved from RESP_BUF directly to avoid a stack copy.
        let status = nsc_api::prodtest_trng_sample(n, &mut RESP_BUF[..n_usize]);
        self.prodtest_finalize(n_usize, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_optiga_handshake(&self) -> Response {
        let mut out = [0u8; 16];
        let status = nsc_api::prodtest_optiga_handshake(&mut out);
        RESP_BUF[..16].copy_from_slice(&out);
        self.prodtest_finalize(16, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_se050_handshake(&self) -> Response {
        let mut out = [0u8; 16];
        let status = nsc_api::prodtest_se050_handshake(&mut out);
        RESP_BUF[..16].copy_from_slice(&out);
        self.prodtest_finalize(16, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_usb_loopback(&self, data: &[u8]) -> Response {
        if data.is_empty() || data.len() > 256 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        // RESP_BUF == 256 bytes; we need data + 2 bytes SW. Worst case
        // 256 + 2 = 258 > 256, so cap at 254 to be safe. The Phase C
        // cap in the firmware is 256 but the single-APDU LC max is 255
        // before SW; staying at 254 keeps headroom for the SW suffix
        // inside RESP_BUF without needing GET_RESPONSE chunking.
        if data.len() > 254 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        // Use a stack buffer for the input copy so the input and
        // output don't overlap on the secure side (`crate::SE` may not
        // tolerate aliased ptrs).
        let mut buf = [0u8; 256];
        buf[..data.len()].copy_from_slice(data);
        let status = nsc_api::prodtest_usb_loopback(
            &buf[..data.len()],
            &mut RESP_BUF[..data.len()],
        );
        self.prodtest_finalize(data.len(), status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_button_test(&self) -> Response {
        let mut out = [0u8; 4];
        let status = nsc_api::prodtest_button_test(&mut out);
        RESP_BUF[..4].copy_from_slice(&out);
        self.prodtest_finalize(4, status)
    }

    // ===================================================================
    // Helpers
    // ===================================================================

    /// Set up chunked GET_RESPONSE state for `total_data` bytes in SIG_BUF.
    unsafe fn setup_chunked_response(&self, total_data: usize) -> Response {
        SIG_BUF[total_data] = (SW_OK >> 8) as u8;
        SIG_BUF[total_data + 1] = (SW_OK & 0xFF) as u8;

        if total_data <= APDU_MAX_RESP {
            return Response {
                ptr: SIG_BUF.as_ptr(),
                len: total_data + 2,
            };
        }

        let first_chunk = APDU_MAX_RESP;
        let remaining = total_data - first_chunk;

        PENDING_PTR = SIG_BUF.as_ptr().add(first_chunk);
        PENDING_LEN = remaining;
        PENDING_POS = 0;

        static mut FIRST_RESP: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
        core::ptr::copy_nonoverlapping(SIG_BUF.as_ptr(), FIRST_RESP.as_mut_ptr(), first_chunk);
        FIRST_RESP[first_chunk] = SW_MORE_DATA;
        FIRST_RESP[first_chunk + 1] = if remaining > 255 { 0xFF } else { remaining as u8 };

        Response {
            ptr: FIRST_RESP.as_ptr(),
            len: first_chunk + 2,
        }
    }

    unsafe fn sw_response(&self, sw: u16) -> Response {
        RESP_BUF[0] = (sw >> 8) as u8;
        RESP_BUF[1] = (sw & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 2,
        }
    }

    unsafe fn nsc_status_to_response(&self, status: u32) -> Response {
        self.sw_response(nsc_status_to_sw(status))
    }
}

/// Read a big-endian u32 starting at `off` in `buf`, returning `None`
/// if reading 4 bytes (or the implicit follow-on length field at
/// `off + 4 + len`) would walk past the buffer end. The reads are
/// length-only — callers are responsible for keeping the response
/// pointer inside `SIG_BUF` once the framing has been validated.
#[inline]
fn read_be_u32(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

/// Free function so new FW_* command handlers can reuse the mapping
/// without going through a `&self` method. (The existing sign path
/// keeps using `nsc_status_to_response` which wraps this.)
fn nsc_status_to_sw(status: u32) -> u16 {
    match NscStatus::from(status) {
        NscStatus::Ok => SW_OK,
        NscStatus::PinIncorrect => SW_SECURITY_NOT_SATISFIED,
        NscStatus::PinLocked => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::NotInitialized => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::UserRejected => SW_SECURITY_NOT_SATISFIED,
        NscStatus::InvalidPointer => SW_INTERNAL_ERROR,
        NscStatus::CryptoError => SW_INTERNAL_ERROR,
        NscStatus::IdleWipe => SW_REFERENCED_DATA_INVALIDATED,
        // Firmware-update statuses. Map to APDU status words that
        // distinguish "transient retriable" from "permanent — abort".
        //
        // BadState, BadChunk, FlashError → SW_CONDITIONS_NOT_SATISFIED
        //   The companion can issue CMD_FW_ABORT and retry from BEGIN.
        // BadManifest, BadVersion, BadImage → SW_WRONG_DATA
        //   The release the companion holds is unacceptable to this
        //   device. The companion must fetch a different release.
        // OtpExhausted → SW_FEATURE_NOT_SUPPORTED
        //   This device will never accept another update. Surface a
        //   clear end-of-life message in the companion UI.
        NscStatus::FwUpdateBadState => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadChunk => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateFlashError => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadManifest => SW_WRONG_DATA,
        NscStatus::FwUpdateBadVersion => SW_WRONG_DATA,
        NscStatus::FwUpdateBadImage => SW_WRONG_DATA,
        NscStatus::FwUpdateOtpExhausted => SW_FEATURE_NOT_SUPPORTED,
        // Off-chain (EIP-1271) sign refusals. All recoverable on the
        // companion side: register a slot / publish a UserOp / rotate.
        NscStatus::OffchainSlotUnregistered => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainGapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainCapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::InternalError => SW_INTERNAL_ERROR,
    }
}
