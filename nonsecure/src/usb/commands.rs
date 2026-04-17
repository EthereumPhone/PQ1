//! APDU command router — PQSigner v2 native protocol only (post-cutover).
//!
//! One class byte: `APDU_CLA_V2 = 0xF0`. One signing command. Every
//! legacy shim (v1 Keycard Shell, bootstrap/main signing, ZK clear-
//! signing, EIP-191, EIP-712) is gone — the single JARDÍN Type 1 /
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
//! | 0xC0 | GET_RESPONSE             |

use sphincs_tz_shared::*;

use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data across chained APDUs. Size reflects
/// the worst-case unified sign payload: 266-byte header + max inner-tx
/// calldata (MAX_TX_LEN) + optional 2-byte prefix + max ERC-20 bundle +
/// optional 2-byte prefix + max ZK clear-sign bundle (proof + calldata
/// + readable + VK bundle).
const CHAIN_BUF_LEN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2
    + 1120
    + 2
    + ZK_CLEAR_SIGN_FIXED_LEN
    + ZK_VK_BUNDLE_MAX_LEN
    + 64;

/// Response buffer — sized for the maximum unified JARDÍN output plus
/// the 2-byte SW.
static mut SIG_BUF: [u8; MAX_JARDIN_RESPONSE_LEN + 2] = [0u8; MAX_JARDIN_RESPONSE_LEN + 2];

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

const CAP_JARDIN_SIGN: u32 = 1 << 0; // the one sign command
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
    chain_ins: u8,
    chain_pos: usize,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain_ins: 0,
            chain_pos: 0,
        }
    }

    pub unsafe fn dispatch(&mut self, apdu: &[u8]) -> Response {
        if apdu.len() < 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];

        // GET_RESPONSE is CLA-agnostic so the companion can keep using
        // it without tracking which chain the pending bytes belong to.
        if ins == INS_V2_GET_RESPONSE {
            return self.get_response();
        }

        if cla != APDU_CLA_V2 {
            return self.sw_response(SW_CLA_NOT_SUPPORTED);
        }

        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained commands (full payload fits in one APDU).
        match ins {
            INS_V2_GET_DEVICE_INFO => return self.cmd_get_device_info(),
            INS_V2_GET_STATUS => return self.cmd_get_status(),
            INS_V2_UNLOCK => return self.cmd_unlock(),
            INS_V2_LOCK => return self.cmd_lock(),
            _ => {}
        }

        // Chained commands per ISO 7816-4:
        //   P1 bit 7 = 0 → this is the LAST (or only) block
        //   P1 bit 7 = 1 → MORE blocks follow
        //
        // The chain state machine:
        //   - `chain_ins == 0` means no chain is active.
        //   - On "more follows", append to the active chain (starting one
        //     if none exists) and return SW_OK.
        //   - On "last or only", append and execute.
        let is_more = (p1 & 0x80) != 0;

        // Append (or start) into the chain buffer.
        if self.chain_ins == 0 {
            self.chain_ins = ins;
            self.chain_pos = 0;
        } else if ins != self.chain_ins {
            // New INS mid-chain is a protocol error.
            self.chain_ins = 0;
            self.chain_pos = 0;
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }
        if self.chain_pos + lc > CHAIN_BUF_LEN {
            self.chain_ins = 0;
            self.chain_pos = 0;
            return self.sw_response(SW_WRONG_LENGTH);
        }
        if lc > 0 {
            CHAIN_BUF[self.chain_pos..self.chain_pos + lc].copy_from_slice(data);
            self.chain_pos += lc;
        }

        if is_more {
            // More chunks to come.
            return self.sw_response(SW_OK);
        }

        // Last (or only) chunk — execute.
        self.execute_chain(ins)
    }

    unsafe fn execute_chain(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_V2_SIGN_USEROP => self.cmd_sign_userop(len),
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

        let caps = CAP_JARDIN_SIGN;
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        RESP_BUF[p] = 2; // sig_param_set: 2 = SPHINCS+C10 (128-bit) everywhere
        p += 1;

        // Type 2 sig size — now fixed at `JARDIN_TYPE2_LEN` bytes.
        RESP_BUF[p..p + 2].copy_from_slice(&(JARDIN_TYPE2_LEN as u16).to_be_bytes());
        p += 2;

        // Unused legacy version fields, zeroed.
        RESP_BUF[p..p + 4].fill(0);
        p += 4;
        RESP_BUF[p..p + 4].fill(0);
        p += 4;

        // ep_version: 0x0009 (EntryPoint v0.9).
        RESP_BUF[p..p + 2].copy_from_slice(&0x0009u16.to_be_bytes());
        p += 2;

        // Wrapper-overhead: header bytes prepended to each signed tx.
        RESP_BUF[p..p + 2].copy_from_slice(&(JARDIN_TYPE2_HEADER_LEN as u16).to_be_bytes());
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

    /// 0x30 SIGN_USEROP — unified JARDÍN Type 1 / Type 2 state machine.
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

        let status = nsc_api::sign_userop(
            &CHAIN_BUF[..effective_len],
            &mut SIG_BUF[..MAX_JARDIN_RESPONSE_LEN],
        );
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // Parse the three-chunk bundle to compute the total length.
        let ic_len = u32::from_be_bytes([SIG_BUF[0], SIG_BUF[1], SIG_BUF[2], SIG_BUF[3]]) as usize;
        if 4 + ic_len + 4 > MAX_JARDIN_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }
        let t1_len_off = 4 + ic_len;
        let t1_len = u32::from_be_bytes([
            SIG_BUF[t1_len_off],
            SIG_BUF[t1_len_off + 1],
            SIG_BUF[t1_len_off + 2],
            SIG_BUF[t1_len_off + 3],
        ]) as usize;
        if t1_len_off + 4 + t1_len + 4 > MAX_JARDIN_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }
        let t2_len_off = t1_len_off + 4 + t1_len;
        let t2_len = u32::from_be_bytes([
            SIG_BUF[t2_len_off],
            SIG_BUF[t2_len_off + 1],
            SIG_BUF[t2_len_off + 2],
            SIG_BUF[t2_len_off + 3],
        ]) as usize;
        let total = t2_len_off + 4 + t2_len;
        if total > MAX_JARDIN_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }

        self.setup_chunked_response(total)
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

        let data_len = u16::from_be_bytes([CHAIN_BUF[264], CHAIN_BUF[265]]) as usize;
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
        let mut to = [0u8; 20];
        to.copy_from_slice(&CHAIN_BUF[212..232]);

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

    /// If the companion attached a ZK clear-sign trailer containing just
    /// the fixed `proof + calldata + readable` block (exactly
    /// `ZK_CLEAR_SIGN_FIXED_LEN` bytes) and `(chain_id, tx.to)` hits the
    /// NS-side VK database, append the looked-up VK bundle so the secure
    /// world's Groth16 verifier has a Merkle-proven key to work with.
    ///
    /// Returns the (possibly extended) payload length. On any failure
    /// returns `received_len` unchanged; the secure world will then
    /// reject the ZK trailer and the signer will fall back to the plain
    /// contract-call display path.
    unsafe fn maybe_inject_vk_bundle(received_len: usize) -> usize {
        if received_len < SIGN_USEROP_HEADER_LEN {
            return received_len;
        }

        let data_len = u16::from_be_bytes([CHAIN_BUF[264], CHAIN_BUF[265]]) as usize;
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

        let zk_len_off = after_erc20;
        let zk_len =
            u16::from_be_bytes([CHAIN_BUF[zk_len_off], CHAIN_BUF[zk_len_off + 1]]) as usize;
        // Only act when the companion sent exactly the fixed block with
        // no VK bundle attached. Any other shape is either an invalid
        // trailer (which the secure world will reject) or already
        // includes a VK bundle the companion built itself.
        if zk_len != ZK_CLEAR_SIGN_FIXED_LEN {
            return received_len;
        }
        let zk_end = zk_len_off + 2 + zk_len;
        if zk_end != received_len {
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
        let mut to = [0u8; 20];
        to.copy_from_slice(&CHAIN_BUF[212..232]);

        let mut vk_bundle_buf = [0u8; ZK_VK_BUNDLE_MAX_LEN];
        let Some(vk_bundle_len) = crate::vk_db::build_bundle(chain_id, &to, &mut vk_bundle_buf)
        else {
            return received_len;
        };

        let new_zk_len = zk_len + vk_bundle_len;
        let new_len = zk_end + vk_bundle_len;
        if new_len > CHAIN_BUF_LEN || new_zk_len > u16::MAX as usize {
            return received_len;
        }

        CHAIN_BUF[zk_end..new_len].copy_from_slice(&vk_bundle_buf[..vk_bundle_len]);
        CHAIN_BUF[zk_len_off..zk_len_off + 2].copy_from_slice(&(new_zk_len as u16).to_be_bytes());
        new_len
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
        let sw = match NscStatus::from(status) {
            NscStatus::Ok => SW_OK,
            NscStatus::PinIncorrect => SW_SECURITY_NOT_SATISFIED,
            NscStatus::PinLocked => SW_CONDITIONS_NOT_SATISFIED,
            NscStatus::NotInitialized => SW_CONDITIONS_NOT_SATISFIED,
            NscStatus::UserRejected => SW_SECURITY_NOT_SATISFIED,
            NscStatus::InvalidPointer => SW_INTERNAL_ERROR,
            NscStatus::CryptoError => SW_INTERNAL_ERROR,
            NscStatus::IdleWipe => SW_REFERENCED_DATA_INVALIDATED,
            NscStatus::InternalError => SW_INTERNAL_ERROR,
        };
        self.sw_response(sw)
    }
}
