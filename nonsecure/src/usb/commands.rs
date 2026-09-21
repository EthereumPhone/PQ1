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
//! legacy signing shim is gone — the single sign-userop Type 1 /
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
    parse_apdu_header, route_v2, router_lease_allows, ChainState, ChainStepOutcome,
};

use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data across chained APDUs. Size reflects
/// the worst-case unified sign payload: `SIGN_USEROP_HEADER_LEN`-byte
/// header + max inner-tx calldata (`MAX_TX_LEN`) + optional 2-byte prefix
/// + max ERC-20 bundle + the 2-byte reserved compatibility slot.
///
/// Also accommodates `INS_V2_FW_BEGIN`'s 8 KB manifest — the max
/// function below resolves to whichever of the two use cases is
/// larger. `const fn max` isn't available in no_std stable, so we
/// hand-expand via a pair of `const` branches and compile-asserts.
const CHAIN_BUF_LEN_SIGN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2
    + 1120
    + 2 // reserved compatibility slot (length field only, must be 0)
    // CoW order trailer: 2-byte length + canonical + two ERC-20 bundles.
    + 2
    + COW_ORDER_TRAILER_MAX_LEN
    // ERC-7730 clear-signing descriptor trailer: 2-byte length plus
    // either one legacy bundle or a two-bundle proof set (up to
    // ERC7730_MAX_TRAILER_LEN = 10268 B). Sits
    // between self-attest and names per the wire-format ordering in
    // `docs/archive/handoff-erc7730-phase3.md` §"Canonical wire formats".
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

/// Per-CMD upper bound on accumulated chain payload. The global
/// `CHAIN_BUF_LEN` is the max of all chained CMDs; passing it to
/// `ChainState::step` would let a hostile host accumulate up to that
/// global max for any one CMD before the per-CMD execute-time length
/// check rejected it (e.g. fill ~8 KB for FW_BEGIN even though the
/// real bound is `MANIFEST_SIZE = 8192`). Tighten per-CMD here so the
/// step layer itself rejects oversized accumulations as soon as `lc`
/// pushes past the *real* limit for that CMD. See finding #4 in
/// `docs/security/usb-fw-update-hardening.md`.
///
/// Unknown CMDs fall back to the global max — execute_chain returns
/// `INS_NOT_SUPPORTED` at the next layer, no behaviour change.
const fn per_cmd_chain_bound(ins: u8) -> usize {
    match ins {
        INS_V2_SIGN_USEROP => CHAIN_BUF_LEN_SIGN,
        INS_V2_SIGN_USEROP_BATCH => CHAIN_BUF_LEN_BATCH,
        INS_V2_SIGN_OFFCHAIN => SIGN_OFFCHAIN_INPUT_MAX_LEN,
        // `INS_V2_FW_BEGIN`'s handler is `#[cfg(feature = "stm32u585")]`-
        // gated; the wire constant exists unconditionally, so we match it
        // here without a cfg so this stays a `const fn`. On a non-
        // stm32u585 build, `execute_chain` returns `INS_NOT_SUPPORTED` —
        // tightening the bound costs nothing.
        INS_V2_FW_BEGIN => CHAIN_BUF_LEN_FW,
        _ => CHAIN_BUF_LEN,
    }
}

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

/// Single-session router lease owner (finding F11). `Some(channel_id)` while an
/// exchange (a live chained command OR a pending chunked `GET_RESPONSE` drain)
/// is in progress, recording which HID channel started it; `None` when the
/// router is idle. `dispatch` refuses any APDU from a different channel while
/// the lease is held, so a second client on the same physical device can
/// neither drain another channel's queued response nor scrub its chain/pending
/// state. Owned by the single-threaded NS dispatcher, same as `PENDING_*`.
static mut ROUTER_OWNER: Option<u16> = None;

/// 30-second inter-chunk timeout for an in-progress GET_RESPONSE drain
/// (§19 P1 "Response-buffer locking … 30 s timeout"). If the host
/// declares a chunked SLH-DSA-signature response (SW=0x61xx) and then
/// stops issuing GET_RESPONSE entirely — no command at all, so the
/// `dispatch` scrub-on-interleave never fires — the pending buffer
/// would otherwise sit referenced indefinitely. `check_response_timeout`
/// (driven from the NS poll loop by the `OTG_DSTS.FNSOF` frame clock)
/// accumulates elapsed frames between checks and scrubs the pending
/// cursor once `PENDING_TIMEOUT_FRAMES` pass without a GET_RESPONSE.
///
/// Accumulating per-iteration deltas (rather than a single start→now
/// delta) sidesteps the 14-bit FNSOF wrap at 16.384 s: the NS loop
/// polls at kHz, so each `(now - last) & 0x3FFF` delta is tiny and
/// always wrap-correct, and 30 s > one wrap is handled by summation.
static mut PENDING_LAST_FRAME: u16 = 0;
static mut PENDING_ELAPSED_FRAMES: u32 = 0;
/// 30 s at the nominal 1 ms USB SOF cadence.
const PENDING_TIMEOUT_FRAMES: u32 = 30_000;

/// Absolute total-drain deadline (sweep finding F2): the inter-chunk
/// timeout above is activity-reset by every GET_RESPONSE, so a
/// slow-drain keepalive (one GET_RESPONSE every <30 s, final chunk
/// never taken) would pin the F11 router lease forever. This second
/// accumulator is NOT reset by drain activity; once it reaches
/// `PENDING_ABS_TIMEOUT_FRAMES` the drain is scrubbed and the lease
/// released regardless of keepalives. 120 s is ~7× the time a
/// worst-case legitimate drain (17 initCode chunks, even at a
/// pathological 5 s per GET_RESPONSE round-trip) could need.
static mut PENDING_ABS_ELAPSED_FRAMES: u32 = 0;
/// 120 s at the nominal 1 ms USB SOF cadence.
const PENDING_ABS_TIMEOUT_FRAMES: u32 = 120_000;

/// USB SOF frame of the last `check_chain_timeout` call — same
/// wrap-safe delta pattern as `PENDING_LAST_FRAME`.
static mut CHAIN_LAST_FRAME: u16 = 0;

// ---------------------------------------------------------------------------
// Firmware version
// ---------------------------------------------------------------------------

// Hardcoded placeholder, NOT the running image's identity: nothing
// plumbs the real build version into this constant, so GET_DEVICE_INFO
// returns these same bytes for every firmware. Companions must NOT key
// protocol decisions (e.g. wire-format selection) on it.
const FW_VERSION: [u8; 3] = [0x03, 0x00, 0x00];

// ---------------------------------------------------------------------------
// Capability bits (reported by GET_DEVICE_INFO).
// ---------------------------------------------------------------------------

// Bit 1 (CAP_FLASH_NEXT_Q) is retired — post-C10-cutover the firmware
// is stateless for slot selection; the companion drives rotation.
// Bit 2 advertises the versioned ERC-7730 proof-set envelope. Both live bits
// are sourced from pqsigner-proto through sphincs-tz-shared.

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

    /// Router entry point. Enforces the single-session lease (F11) around the
    /// real dispatch: a foreign channel is refused while another channel owns a
    /// live exchange, and the lease is re-derived from the resulting state so it
    /// releases the instant no chain and no pending drain remain.
    pub unsafe fn dispatch(&mut self, channel: u16, apdu: &[u8]) -> Response {
        if !router_lease_allows(ROUTER_OWNER, channel) {
            // A different channel acted while the owner holds the lease. Reject
            // WITHOUT disturbing the owner's chain/pending state, so a foreign
            // channel can neither siphon its response nor DoS it by scrubbing.
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }
        let resp = self.dispatch_inner(apdu);
        // Re-derive the lease: a chain still in progress or a pending chunked
        // drain keeps the lease with `channel`; otherwise it is released.
        ROUTER_OWNER = if PENDING_PTR.is_null() && self.chain.active_ins() == 0 {
            None
        } else {
            Some(channel)
        };
        resp
    }

    unsafe fn dispatch_inner(&mut self, apdu: &[u8]) -> Response {
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

        // Any command OTHER than GET_RESPONSE arriving while a chunked
        // response is still pending means the host abandoned the drain.
        // Reset the pending cursor so the leftover bytes can't be
        // siphoned by a later GET_RESPONSE that belongs to a different
        // logical exchange. §19 P1 "Response-buffer locking … scrub on
        // anything other than GET_RESPONSE arriving". The 30 s
        // wall-clock half of that item is still owed (NS clock
        // plumbing); this closes the command-interleave half now.
        if !PENDING_PTR.is_null() {
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
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

            // Firmware-update non-chained commands. CHUNK is not in
            // the chained-INS set, so each CMD_FW_CHUNK is exactly one
            // APDU: the u8 `Lc` caps one APDU at 255 payload bytes,
            // i.e. the 8-byte header plus at most 247 bytes of chunk
            // data on the wire (the `FW_MAX_CHUNK = 1024` protocol cap
            // checked in `cmd_fw_chunk` is unreachable in one APDU).
            // COMMIT / STATUS / ABORT have no payload.
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
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_RGB_TEST => return self.cmd_prodtest_rgb_test(data),
            #[cfg(feature = "prodtest")]
            INS_V2_PRODTEST_RGB_OSD => return self.cmd_prodtest_rgb_osd(data),

            _ => {}
        }

        // INS allowlist for the chained-command path. Reject unknown
        // INS *before* `chain.step` accepts any payload bytes — a
        // hostile host could otherwise burn up to `CHAIN_BUF_LEN`
        // (~8 KB) of buffer accumulation for a bogus INS before the
        // execute-time `_ => SW_INS_NOT_SUPPORTED` arm finally rejects
        // it. Matches §19 "APDU CLA/INS allowlist at non-secure
        // *before* any NSC gateway call" in `docs/security/production-security.md`.
        // Mirrors the explicit set in `execute_chain` below.
        let is_chained_ins = matches!(
            ins,
            INS_V2_SIGN_USEROP | INS_V2_SIGN_USEROP_BATCH | INS_V2_SIGN_OFFCHAIN
        );
        #[cfg(feature = "stm32u585")]
        let is_chained_ins = is_chained_ins || ins == INS_V2_FW_BEGIN;
        if !is_chained_ins {
            return self.sw_response(SW_INS_NOT_SUPPORTED);
        }

        // Chained commands. The state machine, INS-mismatch detection,
        // and overflow-safe length checks all live in
        // `ChainState::step` — see `shared/src/apdu_framing.rs`. We
        // only need to copy `lc` bytes into `CHAIN_BUF` at the cursor
        // the helper hands us, then either ack or execute.
        match self.chain.step(ins, p1, lc, per_cmd_chain_bound(ins)) {
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

        let caps = DEVICE_CAPABILITIES;
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

        // Work-todo X17-UC2: the response carries NO `provisioned`
        // byte. It used to lead the reply, derived as
        // `remaining <= MAX_ATTEMPTS` — always true, so the byte was a
        // constant-1 that lied on blank devices. The honest options
        // were a real provisioning-state veneer (rejected: no such
        // veneer exists and provisioning state is a live SE-chip probe,
        // far too heavy and too much new NS-callable surface for a
        // status poll) or deleting the byte — deleted. Companions must
        // detect the unprovisioned state from the on-device first-boot
        // wizard instead.
        RESP_BUF[0] = if unlocked { 0 } else { 1 };
        RESP_BUF[1] = remaining as u8;
        RESP_BUF[2] = (SW_OK >> 8) as u8;
        RESP_BUF[3] = (SW_OK & 0xFF) as u8;

        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 4,
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
    /// APDU body layout: 4 bytes big-endian `account_index` (0..=255),
    /// optionally followed by a 1-byte `show` flag (PROTOCOL_VERSION
    /// 0x0202+): `0` (or absent) returns the address with no trusted-UI
    /// round-trip; `1` first shows the address on the device OLED behind
    /// a physical confirm (#472) — a user cancel fails closed with
    /// `UserRejected` and no address bytes. Any flag value above 1 is
    /// rejected. An empty body is accepted as `account_index == 0` so
    /// legacy companion builds that pre-date multi-account derivation
    /// still see their original single wallet.
    unsafe fn cmd_get_wallet_address(&self, data: &[u8]) -> Response {
        let (account_index, show) = match data.len() {
            0 => (0u32, 0u32),
            4 => (u32::from_be_bytes([data[0], data[1], data[2], data[3]]), 0u32),
            5 => {
                let flag = u32::from(data[4]);
                if flag > 1 {
                    return self.sw_response(SW_WRONG_DATA);
                }
                (u32::from_be_bytes([data[0], data[1], data[2], data[3]]), flag)
            }
            _ => return self.sw_response(SW_WRONG_LENGTH),
        };
        let mut addr = [0u8; 20];
        let status = nsc_api::get_wallet_address(&mut addr, account_index, show);
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
    ///   [new_offchain_count u64 BE]
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

        // All metadata trailers (ERC-20 / native CoW / names / selector /
        // ERC-7730 / …) are built by the companion and arrive inside the
        // request — the DBs live host-side, the device holds only the
        // pinned Merkle roots and verifies every byte in S-world. NS no
        // longer looks anything up. We only normalise the positional
        // trailer skeleton so a companion that sent a short prefix (or no
        // trailers at all) still presents a well-formed, fail-safe layout
        // to the secure parser — missing slots degrade to "unknown token"
        // / raw-hex / blind-sign, never a forged display.
        let effective_len = Self::ensure_trailer_skeleton(data_len);

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
    /// No NS-side trailer injection: the companion supplies the wire-v2
    /// routed TLV list. ERC-20 metadata, native CoW (frozen wire kind 3),
    /// Safe, selector, ERC-7730, and name trailers all have batch routes;
    /// reserved wire kind 2 is rejected at every payload length.
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

    /// Ensure the `[erc20][reserved_v1][cow_order][safe_v1][selector][self_attest][erc7730]`
    /// u16-prefixed trailer skeleton is fully present before `received_len`,
    /// padding any missing prefix with `[0x00, 0x00]`.
    ///
    /// Background: the secure-world sign_userop parser walks trailers
    /// positionally in that exact order and then reads the `names`
    /// trailer at whatever cursor lands after them. If the companion
    /// sent a payload that stops earlier in the chain (e.g. only
    /// `erc20+reserved_v1+cow_order`, or a bare `header+data` with no trailers at
    /// all), the secure parser would consume the `[count][bundle_len][...]`
    /// framing of the names trailer as `safe_v1`'s u16 length and the
    /// next pair as `selector`'s — bytes that are almost always > the
    /// per-trailer caps and trip "bad safe bundle" or "bad selector
    /// bundle" on the OLED. (Earlier symptom: "Sign v3 len>cap" when
    /// only 1 prefix was padded.)
    ///
    /// This helper walks the trailer chain and appends empty `[0, 0]`
    /// u16 prefixes for any section not yet encoded, returning the
    /// updated `received_len`. For a payload that already contains a
    /// full skeleton this is a no-op. It is the ONLY trailer
    /// normalisation NS does now that the metadata DBs live host-side:
    /// the companion builds every real bundle; NS just guarantees a
    /// parseable, fail-safe skeleton so missing trailers degrade
    /// gracefully (unknown token / raw hex / blind-sign).
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
        // Seven empty u16 prefixes to ensure, in secure-parser order:
        // erc20, reserved_v1, cow_order, safe_v1, selector, self_attest, erc7730.
        // Must match the parse sequence in
        // `secure/src/nsc/cmd_sign_userop.rs::run` exactly — any
        // divergence causes the names trailer to misalign with the
        // secure parser's cursor and surfaces on the OLED as a
        // "bad <section> bundle" / "bad names count" / etc. error.
        //
        // History:
        // - Bumped from 5 → 6 when commit 33cd0ed added the self_attest
        //   slot; without this the NS-injected names count byte got read
        //   as the self_attest u16 length and tripped "bad self-attest"
        //   on every ETH transfer to a named address.
        // - Bumped from 6 → 7 when the ERC-7730 clear-signing trailer
        //   slot landed (after self_attest, before names). Without this
        //   bump, an NS-injected ERC-20 bundle / names section for a
        //   companion that ships no ERC-7730 trailer caused the secure
        //   parser to read the names `[count][bundle_len]` as the
        //   erc7730 trailer's u16 length, skip 256–1024 bytes of names
        //   payload, then sample a random byte from inside the names
        //   bundle as the next names_count → "bad names count" on the
        //   OLED. The fix simply pads a 7th `[0, 0]` u16 so the secure
        //   parser sees an absent erc7730 slot and lands on the real
        //   NS-written names count byte.
        for _ in 0..7 {
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


    // ===================================================================
    // GET_RESPONSE (CLA-agnostic)
    // ===================================================================

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_LEN == 0 {
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        // Progress — the host is actively draining, so reset the
        // inter-chunk idle timeout accumulator. The absolute drain
        // deadline (`PENDING_ABS_ELAPSED_FRAMES`, finding F2) is
        // deliberately NOT reset here: keepalive activity must not
        // extend the total-exchange bound.
        PENDING_ELAPSED_FRAMES = 0;

        let remaining = PENDING_LEN - PENDING_POS;
        // FI-hardened length clamp — a glitched `chunk` value here
        // would either overflow CHUNK_BUF (if it exceeds APDU_MAX_RESP)
        // or read past `PENDING_PTR + PENDING_POS + remaining` (if it
        // exceeds `remaining`), in either case leaking adjacent memory
        // into the response. See `pqsigner_fi::fi_min` docstring.
        let chunk = pqsigner_fi::fi_min(remaining, APDU_MAX_RESP);
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

    /// Enforce the GET_RESPONSE drain timeouts. Call once per NS
    /// poll-loop iteration with the current `OTG_DSTS.FNSOF`
    /// (`usb::usb_frame_number`). Two bounds, either one scrubs the
    /// pending cursor and releases the router lease:
    ///   * idle: no GET_RESPONSE for `PENDING_TIMEOUT_FRAMES` (30 s), so
    ///     a stalled host can't pin the buffer;
    ///   * absolute: `PENDING_ABS_TIMEOUT_FRAMES` (120 s) of total drain
    ///     lifetime regardless of keepalive activity (finding F2), so a
    ///     slow-drain can't pin the F11 lease indefinitely.
    /// No-op when no drain is in progress.
    ///
    /// # Safety
    /// Touches the module `PENDING_*` static-mut state under the
    /// single-threaded NS dispatcher invariant (same as `get_response`
    /// / `dispatch`).
    pub unsafe fn check_response_timeout(&self, now_frame: u16) {
        if PENDING_PTR.is_null() {
            // No drain in progress — keep the clock reference fresh so
            // the first frame of the next drain measures a small delta.
            PENDING_ELAPSED_FRAMES = 0;
            PENDING_ABS_ELAPSED_FRAMES = 0;
            PENDING_LAST_FRAME = now_frame;
            return;
        }
        let delta = now_frame.wrapping_sub(PENDING_LAST_FRAME) & 0x3FFF;
        PENDING_LAST_FRAME = now_frame;
        PENDING_ELAPSED_FRAMES = PENDING_ELAPSED_FRAMES.saturating_add(delta as u32);
        // Activity resets the idle accumulator in `get_response` but
        // never this absolute one.
        PENDING_ABS_ELAPSED_FRAMES = PENDING_ABS_ELAPSED_FRAMES.saturating_add(delta as u32);
        if PENDING_ELAPSED_FRAMES >= PENDING_TIMEOUT_FRAMES
            || PENDING_ABS_ELAPSED_FRAMES >= PENDING_ABS_TIMEOUT_FRAMES
        {
            // Abandoned or over-long drain — scrub, and release the router
            // lease (F11) so a new channel can start a fresh exchange. A
            // pending drain and a live chain are mutually exclusive, so
            // clearing the owner here is safe.
            PENDING_PTR = core::ptr::null();
            PENDING_LEN = 0;
            PENDING_POS = 0;
            PENDING_ELAPSED_FRAMES = 0;
            PENDING_ABS_ELAPSED_FRAMES = 0;
            ROUTER_OWNER = None;
        }
    }

    /// Enforce the 30-second total-lifetime bound on a chained-APDU
    /// exchange (work-todo X17-UC1). Call once per NS poll-loop
    /// iteration, next to `check_response_timeout`. The chain state
    /// machine itself (`ChainState::tick_timeout`) owns the clock and
    /// the reset; on expiry this releases the F11 router lease so a
    /// crashed or keepalive-dripping chain-opener cannot lock out every
    /// other channel until power-cycle. No-op when no chain is live.
    ///
    /// # Safety
    /// Touches the module `ROUTER_OWNER` static-mut state under the
    /// single-threaded NS dispatcher invariant (same as `dispatch`).
    pub unsafe fn check_chain_timeout(&mut self, now_frame: u16) {
        let delta = now_frame.wrapping_sub(CHAIN_LAST_FRAME) & 0x3FFF;
        CHAIN_LAST_FRAME = now_frame;
        if self.chain.tick_timeout(delta as u32) {
            // Chain lifetime expired — `tick_timeout` already reset the
            // chain state. A live chain and a pending drain are mutually
            // exclusive, so clearing the owner here is safe.
            ROUTER_OWNER = None;
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
        // Reserve the shared two-byte status-word suffix in RESP_BUF.
        if n == 0 || n as usize > PRODTEST_MAX_RESPONSE_DATA_LEN {
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
        if data.is_empty() || data.len() > PRODTEST_MAX_RESPONSE_DATA_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        // Use a stack buffer for the input copy so the input and
        // output don't overlap on the secure side (`crate::SE` may not
        // tolerate aliased ptrs).
        let mut buf = [0u8; PRODTEST_MAX_RESPONSE_DATA_LEN];
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

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_rgb_test(&self, data: &[u8]) -> Response {
        if data.len() != PRODTEST_RGB_IN_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut req = [0u8; PRODTEST_RGB_IN_LEN];
        req.copy_from_slice(data);
        let mut out = [0u8; PRODTEST_RGB_OUT_LEN];
        let status = nsc_api::prodtest_rgb_test(&req, &mut out);
        RESP_BUF[..PRODTEST_RGB_OUT_LEN].copy_from_slice(&out);
        self.prodtest_finalize(PRODTEST_RGB_OUT_LEN, status)
    }

    #[cfg(feature = "prodtest")]
    unsafe fn cmd_prodtest_rgb_osd(&self, data: &[u8]) -> Response {
        if data.len() != PRODTEST_RGB_OSD_IN_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut req = [0u8; PRODTEST_RGB_OSD_IN_LEN];
        req.copy_from_slice(data);
        let mut out = [0u8; PRODTEST_RGB_OSD_OUT_LEN];
        let status = nsc_api::prodtest_rgb_osd(&req, &mut out);
        RESP_BUF[..PRODTEST_RGB_OSD_OUT_LEN].copy_from_slice(&out);
        self.prodtest_finalize(PRODTEST_RGB_OSD_OUT_LEN, status)
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
        //   (FlashError is also what the post-FA-1.5 fail-closed COMMIT
        //   refusal returns; on this build shape COMMIT can never
        //   succeed, so the "retry" advice is moot but harmless.)
        // BadManifest, BadVersion, BadImage → SW_WRONG_DATA
        //   The release the companion holds is unacceptable to this
        //   device. The companion must fetch a different release.
        // (FwUpdateOtpExhausted → SW_FEATURE_NOT_SUPPORTED was RETIRED in
        //   FA-1.5 with the removed unary OTP floor writer.)
        NscStatus::FwUpdateBadState => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadChunk => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateFlashError => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::FwUpdateBadManifest => SW_WRONG_DATA,
        NscStatus::FwUpdateBadVersion => SW_WRONG_DATA,
        NscStatus::FwUpdateBadImage => SW_WRONG_DATA,
        // Off-chain (EIP-1271) sign refusals. All recoverable on the
        // companion side: register a slot / publish a UserOp / rotate.
        NscStatus::OffchainSlotUnregistered => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainGapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::OffchainCapExceeded => SW_CONDITIONS_NOT_SATISFIED,
        NscStatus::InternalError => SW_INTERNAL_ERROR,
    }
}
