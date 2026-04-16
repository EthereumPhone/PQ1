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
//! | 0x72 | GET_JARDIN_SLOT_INFO     |
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
const CAP_FLASH_NEXT_Q: u32 = 1 << 1; // firmware owns `next_q` in flash

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
            INS_V2_GET_JARDIN_SLOT_INFO => return self.cmd_get_jardin_slot_info(data, lc),
            _ => {}
        }

        // Chained commands (P1 bit 7 = 0x80 → more follows).
        let is_more = (p1 & 0x80) != 0;
        if !is_more {
            self.chain_ins = ins;
            self.chain_pos = 0;
            if lc > CHAIN_BUF_LEN {
                self.chain_ins = 0;
                return self.sw_response(SW_WRONG_LENGTH);
            }
            if lc > 0 {
                CHAIN_BUF[..lc].copy_from_slice(data);
                self.chain_pos = lc;
            }
            if lc < APDU_MAX_DATA {
                return self.execute_chain(ins);
            }
            self.sw_response(SW_OK)
        } else {
            if ins != self.chain_ins {
                self.chain_ins = 0;
                self.chain_pos = 0;
                return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
            }
            if self.chain_pos + lc > CHAIN_BUF_LEN {
                self.chain_ins = 0;
                self.chain_pos = 0;
                return self.sw_response(SW_WRONG_LENGTH);
            }
            CHAIN_BUF[self.chain_pos..self.chain_pos + lc].copy_from_slice(data);
            self.chain_pos += lc;
            if lc < APDU_MAX_DATA {
                return self.execute_chain(ins);
            }
            self.sw_response(SW_OK)
        }
    }

    unsafe fn execute_chain(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_V2_SIGN_USEROP => self.cmd_sign_userop(&CHAIN_BUF[..len]),
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

        let caps = CAP_JARDIN_SIGN | CAP_FLASH_NEXT_Q;
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        RESP_BUF[p] = 1; // sig_param_set: 1 = JARDÍN FORS+C (128-bit)
        p += 1;

        // Maximum sig size (Type 2 at q=95) for companion buffer sizing.
        RESP_BUF[p..p + 2].copy_from_slice(&(JARDIN_TYPE2_MAX_LEN as u16).to_be_bytes());
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
    ///   [type1_len u32 BE] [type1_bytes...] [type2_len u32 BE] [type2_bytes...]
    /// ```
    ///
    /// When `type1_len == 0` no slot registration is needed; the
    /// companion submits only the Type 2 UserOp.
    unsafe fn cmd_sign_userop(&self, data: &[u8]) -> Response {
        if data.len() < SIGN_USEROP_HEADER_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let status = nsc_api::sign_userop(data, &mut SIG_BUF[..MAX_JARDIN_RESPONSE_LEN]);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // Parse the two-chunk bundle to compute the total length.
        let t1_len = u32::from_be_bytes([SIG_BUF[0], SIG_BUF[1], SIG_BUF[2], SIG_BUF[3]]) as usize;
        if 4 + t1_len + 4 > MAX_JARDIN_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }
        let t2_len_off = 4 + t1_len;
        let t2_len = u32::from_be_bytes([
            SIG_BUF[t2_len_off],
            SIG_BUF[t2_len_off + 1],
            SIG_BUF[t2_len_off + 2],
            SIG_BUF[t2_len_off + 3],
        ]) as usize;
        let total = 4 + t1_len + 4 + t2_len;
        if total > MAX_JARDIN_RESPONSE_LEN {
            return self.sw_response(SW_INTERNAL_ERROR);
        }

        self.setup_chunked_response(total)
    }

    /// 0x72 GET_JARDIN_SLOT_INFO — query persisted slot state.
    unsafe fn cmd_get_jardin_slot_info(&self, data: &[u8], lc: usize) -> Response {
        if lc < 8 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        // The NS-side API takes (chain_id, slot_index) for historical
        // reasons; the secure handler only uses chain_id.
        let chain_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        // Pack chain_id into an 8-byte payload.
        let mut out = [0u8; 45];
        let status = nsc_api::get_jardin_slot_info(chain_id, 0, &mut out);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // 45-byte response + 2 SW bytes.
        RESP_BUF[..45].copy_from_slice(&out);
        RESP_BUF[45] = (SW_OK >> 8) as u8;
        RESP_BUF[46] = (SW_OK & 0xFF) as u8;
        Response {
            ptr: RESP_BUF.as_ptr(),
            len: 47,
        }
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
            NscStatus::SlotExhausted => SW_FEATURE_NOT_SUPPORTED,
            NscStatus::InternalError => SW_INTERNAL_ERROR,
        };
        self.sw_response(sw)
    }
}
