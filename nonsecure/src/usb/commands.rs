//! APDU command router — Keycard Shell compatible.
//!
//! Implements the same command set as Keycard Shell so that wallets
//! (MetaMask, Rabby, imToken, BlueWallet, Sparrow, Specter) can
//! communicate with PQSigner using their existing hardware wallet
//! transport code.
//!
//! Protocol differences from Keycard Shell:
//! - Signature is SLH-DSA (17 KB) instead of ECDSA (65 bytes)
//! - Public key is SLH-DSA verifying key (32 bytes) instead of secp256k1
//! - BIP32 derivation paths are accepted but ignored (SLH-DSA uses a
//!   single key derived from the BIP-39 seed)

use sphincs_tz_shared::*;
use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data (across chained APDUs).
const CHAIN_BUF_LEN: usize = 8192;

/// Signature buffer with room for SW.
static mut SIG_BUF: [u8; SIGNATURE_LEN + 2] = [0u8; SIGNATURE_LEN + 2];

/// Sign payload assembly buffer.
const SIGN_PAYLOAD_BUF_LEN: usize = 1 + 4 + 4096 + 4 + 1120 + 64;
static mut SIGN_PAYLOAD_BUF: [u8; SIGN_PAYLOAD_BUF_LEN] = [0u8; SIGN_PAYLOAD_BUF_LEN];

/// Clear-sign payload buffer.
const CLEAR_SIGN_BUF_LEN: usize = ZK_HEADER_LEN + 4096 + 4 + 2048;
static mut CLEAR_SIGN_BUF: [u8; CLEAR_SIGN_BUF_LEN] = [0u8; CLEAR_SIGN_BUF_LEN];

/// Short response buffer (for non-signature responses).
static mut RESP_BUF: [u8; 256] = [0u8; 256];

/// Command chaining accumulation buffer.
static mut CHAIN_BUF: [u8; CHAIN_BUF_LEN] = [0u8; CHAIN_BUF_LEN];

/// Pending GET_RESPONSE buffer (points into SIG_BUF or RESP_BUF).
/// When a response is too large for one APDU, we store the full
/// response here and serve chunks via GET_RESPONSE.
static mut PENDING_PTR: *const u8 = core::ptr::null();
static mut PENDING_LEN: usize = 0;
static mut PENDING_POS: usize = 0;

// ---------------------------------------------------------------------------
// Firmware version
// ---------------------------------------------------------------------------

const FW_VERSION: [u8; 3] = [0x01, 0x00, 0x00];

// ---------------------------------------------------------------------------
// Response wrapper
// ---------------------------------------------------------------------------

/// A response APDU fragment: up to APDU_MAX_RESP bytes of data + 2 bytes SW.
pub struct Response {
    pub ptr: *const u8,
    pub len: usize,
}

// ---------------------------------------------------------------------------
// Command Router
// ---------------------------------------------------------------------------

pub struct CommandRouter {
    /// Current INS being chained.
    chain_ins: u8,
    /// Bytes accumulated in the chaining buffer.
    chain_pos: usize,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain_ins: 0,
            chain_pos: 0,
        }
    }

    /// Dispatch an incoming APDU.
    ///
    /// Returns a `Response` pointing into a static buffer.  If the
    /// response has SW1=0x61, the caller must handle GET_RESPONSE
    /// follow-ups to drain the remaining data.
    ///
    /// # Safety
    /// Uses static mut buffers.
    pub unsafe fn dispatch(&mut self, apdu: &[u8]) -> Response {
        if apdu.len() < 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];

        if cla != APDU_CLA {
            return self.sw_response(SW_CLA_NOT_SUPPORTED);
        }

        // GET_RESPONSE: serve next chunk of a pending large response
        if ins == INS_GET_RESPONSE {
            return self.get_response();
        }

        // Extract Lc and data
        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained commands (single APDU, no P1 chaining)
        match ins {
            INS_GET_APP_CONF => return self.cmd_get_app_conf(),
            INS_GET_PUBLIC => return self.cmd_get_public(p2, data, lc),
            INS_GET_PIN_REMAINING => return self.cmd_get_pin_remaining(),
            INS_UNLOCK => return self.cmd_unlock(),
            _ => {}
        }

        // Chained commands: SIGN_ETH_TX, SIGN_ETH_MSG, SIGN_EIP712
        match p1 {
            P1_FIRST => {
                // Start new chain
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
                // If Lc < APDU_MAX_DATA, this is the only chunk — execute now
                if lc < APDU_MAX_DATA {
                    return self.execute_chain(ins);
                }
                self.sw_response(SW_OK)
            }
            P1_MORE => {
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
                // Last chunk if Lc < APDU_MAX_DATA
                if lc < APDU_MAX_DATA {
                    return self.execute_chain(ins);
                }
                self.sw_response(SW_OK)
            }
            _ => self.sw_response(SW_WRONG_DATA),
        }
    }

    /// Execute a fully-accumulated chained command.
    unsafe fn execute_chain(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_SIGN_ETH_TX => self.cmd_sign_eth_tx(&CHAIN_BUF[..len], len),
            INS_SIGN_ETH_MSG => self.cmd_sign_eth_msg(&CHAIN_BUF[..len], len),
            INS_SIGN_EIP712 => self.cmd_sign_eip712(&CHAIN_BUF[..len], len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // -----------------------------------------------------------------------
    // GET_RESPONSE — drain pending large response
    // -----------------------------------------------------------------------

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_POS >= PENDING_LEN {
            PENDING_PTR = core::ptr::null();
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        let remaining = PENDING_LEN - PENDING_POS;
        let chunk = core::cmp::min(remaining, APDU_MAX_RESP);
        let is_last = (PENDING_POS + chunk) >= PENDING_LEN;

        // Build response: data chunk + SW
        // We copy into RESP_BUF for short responses, or build inline
        // for the last chunk. Since chunks are ≤253 bytes, RESP_BUF (256) suffices.
        let src = core::slice::from_raw_parts(PENDING_PTR.add(PENDING_POS), chunk);
        RESP_BUF[..chunk].copy_from_slice(src);
        PENDING_POS += chunk;

        if is_last {
            PENDING_PTR = core::ptr::null();
            RESP_BUF[chunk] = (SW_OK >> 8) as u8;
            RESP_BUF[chunk + 1] = (SW_OK & 0xFF) as u8;
            Response { ptr: RESP_BUF.as_ptr(), len: chunk + 2 }
        } else {
            let still_remaining = PENDING_LEN - PENDING_POS;
            RESP_BUF[chunk] = SW_MORE_DATA;
            RESP_BUF[chunk + 1] = if still_remaining > 255 { 0xFF } else { still_remaining as u8 };
            Response { ptr: RESP_BUF.as_ptr(), len: chunk + 2 }
        }
    }

    // -----------------------------------------------------------------------
    // GET_APP_CONF (0x06) — Keycard Shell compatible
    // -----------------------------------------------------------------------

    unsafe fn cmd_get_app_conf(&self) -> Response {
        // Response: FW version (3) + DB version (4) + UID (16) + pubkey (32) + SW (2)
        let mut p = 0usize;

        // Firmware version
        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;

        // Database version (YYYYMMDD as u32 BE) — use build date placeholder
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;

        // Device UID (16 bytes) — read from STM32U585 UID registers or use zeros
        // On real hardware this would be: 0x0BFA0590, 0x0BFA0594, 0x0BFA0598
        RESP_BUF[p..p + 16].fill(0);
        p += 16;

        // Public key — SLH-DSA verifying key (32 bytes)
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status == NscStatus::Ok as u32 {
            RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        }
        p += VERIFYING_KEY_LEN;

        // SW
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    // -----------------------------------------------------------------------
    // GET_PUBLIC (0x02) — Keycard Shell compatible response format
    // -----------------------------------------------------------------------

    unsafe fn cmd_get_public(&self, p2: u8, data: &[u8], lc: usize) -> Response {
        // Parse BIP32 path (accept but ignore — SLH-DSA uses single key)
        if lc < 1 {
            return self.sw_response(SW_WRONG_DATA);
        }
        let _path_len = data[0] as usize;
        // We don't validate path elements — SLH-DSA doesn't use HD derivation.

        // Get the SLH-DSA verifying key
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // Build Keycard Shell compatible response:
        // [fingerprint_len(1)][fingerprint(4)][pubkey_len(1)][pubkey(32)][chaincode_len(1)][chaincode?(32)] + SW
        let mut p = 0usize;

        // Fingerprint: first 4 bytes of pubkey (simplified — real wallets
        // compute hash160 of the compressed key, but SLH-DSA keys don't
        // have the same structure as secp256k1)
        RESP_BUF[p] = 4; // fingerprint length
        p += 1;
        RESP_BUF[p..p + 4].copy_from_slice(&pubkey[..4]);
        p += 4;

        // Public key: SLH-DSA verifying key (32 bytes)
        RESP_BUF[p] = VERIFYING_KEY_LEN as u8;
        p += 1;
        RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        p += VERIFYING_KEY_LEN;

        // Chain code (P2=0x01 for extended, 0x00 for normal)
        if p2 == 0x01 {
            RESP_BUF[p] = 32; // chain code length
            p += 1;
            // SLH-DSA doesn't have chain codes; provide zero-filled
            RESP_BUF[p..p + 32].fill(0);
            p += 32;
        } else {
            RESP_BUF[p] = 0; // no chain code
            p += 1;
        }

        // SW
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    // -----------------------------------------------------------------------
    // SIGN_ETH_TX (0x04) — sign EIP-1559 transaction
    // -----------------------------------------------------------------------

    unsafe fn cmd_sign_eth_tx(&self, data: &[u8], len: usize) -> Response {
        if len < 5 {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Parse BIP32 path
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Extract transaction data (everything after the BIP32 path)
        let tx_data = &data[path_bytes..];
        let tx_len = len - path_bytes;

        if tx_len == 0 || tx_len > 4096 {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        // Build the sign payload in the format the NSC gateway expects:
        // [has_bundle:u8=0][tx_len:u32 LE][tx_bytes]
        let mut p = 0usize;
        SIGN_PAYLOAD_BUF[p] = 0u8; // has_bundle = false
        p += 1;
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        p += 4;
        SIGN_PAYLOAD_BUF[p..p + tx_len].copy_from_slice(tx_data);
        p += tx_len;

        let status = nsc_api::sign_raw(&SIGN_PAYLOAD_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result(status)
    }

    // -----------------------------------------------------------------------
    // SIGN_ETH_MSG (0x08) — sign Ethereum message (personal_sign)
    // -----------------------------------------------------------------------

    unsafe fn cmd_sign_eth_msg(&self, data: &[u8], len: usize) -> Response {
        if len < 5 {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Parse BIP32 path
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Message length (4 bytes BE) + message
        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;

        // Route to CMD_SIGN with the message data as the payload
        if msg_len > SIGN_PAYLOAD_BUF_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        // For now, pass through to the generic sign path.
        // The secure world handles message hashing.
        let mut p = 0usize;
        SIGN_PAYLOAD_BUF[p] = 0u8;
        p += 1;
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        p += 4;
        SIGN_PAYLOAD_BUF[p..p + msg_len].copy_from_slice(msg_data);
        p += msg_len;

        let status = nsc_api::sign_raw(&SIGN_PAYLOAD_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result(status)
    }

    // -----------------------------------------------------------------------
    // SIGN_EIP712 (0x0C) — sign EIP-712 typed data
    // -----------------------------------------------------------------------

    unsafe fn cmd_sign_eip712(&self, data: &[u8], len: usize) -> Response {
        if len < 5 {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Parse BIP32 path
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;

        if msg_len > CLEAR_SIGN_BUF_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        CLEAR_SIGN_BUF[..msg_len].copy_from_slice(msg_data);
        let status = nsc_api::clear_sign_msg(&CLEAR_SIGN_BUF[..msg_len], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result(status)
    }

    // -----------------------------------------------------------------------
    // PQSigner extensions
    // -----------------------------------------------------------------------

    unsafe fn cmd_get_pin_remaining(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        RESP_BUF[0] = remaining as u8;
        RESP_BUF[1] = (SW_OK >> 8) as u8;
        RESP_BUF[2] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 3 }
    }

    unsafe fn cmd_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a chunked response for a signing result.
    /// If the signature fits in one APDU (≤253 bytes), return it directly.
    /// Otherwise, return the first chunk with SW=0x61XX and store the rest
    /// for GET_RESPONSE.
    unsafe fn sign_result(&self, status: u32) -> Response {
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        // Append SW_OK after the signature
        SIG_BUF[SIGNATURE_LEN] = (SW_OK >> 8) as u8;
        SIG_BUF[SIGNATURE_LEN + 1] = (SW_OK & 0xFF) as u8;

        let total_data = SIGNATURE_LEN; // data bytes (excluding SW)

        if total_data <= APDU_MAX_RESP {
            // Fits in one APDU
            Response {
                ptr: SIG_BUF.as_ptr(),
                len: SIGNATURE_LEN + 2,
            }
        } else {
            // First chunk: APDU_MAX_RESP bytes of data + SW 0x61XX
            let first_chunk = APDU_MAX_RESP;
            let remaining = total_data - first_chunk;

            // Store pending state for GET_RESPONSE
            PENDING_PTR = SIG_BUF.as_ptr().add(first_chunk);
            PENDING_LEN = remaining;
            PENDING_POS = 0;

            // Build first response: first 253 bytes + SW=0x61FF
            // We can't use RESP_BUF (too small for 253 bytes + 2 SW).
            // Instead, we write SW directly after the first chunk in SIG_BUF.
            // But SIG_BUF contains the signature, so we'd overwrite data.
            // Solution: use a separate first-response buffer.
            static mut FIRST_RESP: [u8; APDU_MAX_RESP + 2] = [0u8; APDU_MAX_RESP + 2];
            core::ptr::copy_nonoverlapping(
                SIG_BUF.as_ptr(),
                FIRST_RESP.as_mut_ptr(),
                first_chunk,
            );
            FIRST_RESP[first_chunk] = SW_MORE_DATA;
            FIRST_RESP[first_chunk + 1] = if remaining > 255 { 0xFF } else { remaining as u8 };

            Response {
                ptr: FIRST_RESP.as_ptr(),
                len: first_chunk + 2,
            }
        }
    }

    unsafe fn sw_response(&self, sw: u16) -> Response {
        RESP_BUF[0] = (sw >> 8) as u8;
        RESP_BUF[1] = (sw & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 2 }
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
            NscStatus::IdleWipe => SW_CONDITIONS_NOT_SATISFIED,
            NscStatus::InternalError => SW_INTERNAL_ERROR,
        };
        self.sw_response(sw)
    }
}
