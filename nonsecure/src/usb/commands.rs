//! APDU command router — dual protocol support.
//!
//! CLA 0xE0 → v1 (Keycard Shell compatible, legacy)
//! CLA 0xF0 → v2 (PQSigner native protocol)
//!
//! The v2 protocol drops Keycard Shell compatibility in favor of
//! PQSigner-native commands that expose every device capability:
//! per-chain key derivation, bootstrap signing, ZK clear-signing,
//! EIP-191 message signing, CREATE2 address verification, and
//! structured PQSignatureWrapper responses.

use sphincs_tz_shared::*;
use crate::nsc_api;

// ---------------------------------------------------------------------------
// Static buffers
// ---------------------------------------------------------------------------

/// Maximum accumulated command data (across chained APDUs).
const CHAIN_BUF_LEN: usize = 8192;

/// Signature buffer — sized for the v2 PQSignatureWrapper + SW bytes.
static mut SIG_BUF: [u8; WRAPPER_TOTAL_LEN + 2] = [0u8; WRAPPER_TOTAL_LEN + 2];

/// Sign payload assembly buffer (must fit full UserOp wire format).
const SIGN_PAYLOAD_BUF_LEN: usize = USEROP_PREFIX_LEN + 4096 + 4 + 1120 + 64;
static mut SIGN_PAYLOAD_BUF: [u8; SIGN_PAYLOAD_BUF_LEN] = [0u8; SIGN_PAYLOAD_BUF_LEN];

/// Clear-sign payload buffer.
const CLEAR_SIGN_BUF_LEN: usize = ZK_HEADER_LEN + 4096 + 4 + 2048;
static mut CLEAR_SIGN_BUF: [u8; CLEAR_SIGN_BUF_LEN] = [0u8; CLEAR_SIGN_BUF_LEN];

/// EIP-712 clear-sign payload buffer.
const EIP712_BUF_LEN: usize = EIP712_HEADER_LEN + 4 + 2048;
static mut EIP712_BUF: [u8; EIP712_BUF_LEN] = [0u8; EIP712_BUF_LEN];

/// Short response buffer (for non-signature responses).
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

const FW_VERSION: [u8; 3] = [0x02, 0x00, 0x00];

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
    /// CLA of current chaining session (0xE0 or 0xF0).
    chain_cla: u8,
}

impl CommandRouter {
    pub fn new() -> Self {
        Self {
            chain_ins: 0,
            chain_pos: 0,
            chain_cla: 0,
        }
    }

    pub unsafe fn dispatch(&mut self, apdu: &[u8]) -> Response {
        if apdu.len() < 4 {
            return self.sw_response(SW_WRONG_LENGTH);
        }

        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let _p2 = apdu[3];

        // GET_RESPONSE is CLA-agnostic (shared between v1 and v2)
        if ins == INS_V2_GET_RESPONSE {
            return self.get_response();
        }

        match cla {
            APDU_CLA => self.dispatch_v1(apdu, ins, p1),
            APDU_CLA_V2 => self.dispatch_v2(apdu, ins, p1),
            _ => self.sw_response(SW_CLA_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v1 protocol (CLA 0xE0) — Keycard Shell compatible (legacy)
    // ===================================================================

    unsafe fn dispatch_v1(&mut self, apdu: &[u8], ins: u8, p1: u8) -> Response {
        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained v1 commands
        match ins {
            INS_GET_APP_CONF => return self.cmd_v1_get_app_conf(),
            INS_GET_PUBLIC => return self.cmd_v1_get_public(apdu[3], data, lc),
            INS_GET_PIN_REMAINING => return self.cmd_v1_get_pin_remaining(),
            INS_UNLOCK => return self.cmd_v1_unlock(),
            _ => {}
        }

        // Chained v1 commands
        match p1 {
            P1_FIRST => {
                self.chain_ins = ins;
                self.chain_cla = APDU_CLA;
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
                    return self.execute_chain_v1(ins);
                }
                self.sw_response(SW_OK)
            }
            P1_MORE => {
                if ins != self.chain_ins || self.chain_cla != APDU_CLA {
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
                    return self.execute_chain_v1(ins);
                }
                self.sw_response(SW_OK)
            }
            _ => self.sw_response(SW_WRONG_DATA),
        }
    }

    unsafe fn execute_chain_v1(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_SIGN_ETH_TX => self.cmd_v1_sign_eth_tx(&CHAIN_BUF[..len], len),
            INS_SIGN_ETH_MSG => self.cmd_v1_sign_eth_msg(&CHAIN_BUF[..len], len),
            INS_SIGN_EIP712 => self.cmd_v1_sign_eip712(&CHAIN_BUF[..len], len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v2 protocol (CLA 0xF0) — PQSigner native
    // ===================================================================

    unsafe fn dispatch_v2(&mut self, apdu: &[u8], ins: u8, p1: u8) -> Response {
        let (lc, data) = if apdu.len() > 4 {
            let lc = apdu[4] as usize;
            if apdu.len() < 5 + lc {
                return self.sw_response(SW_WRONG_LENGTH);
            }
            (lc, &apdu[5..5 + lc])
        } else {
            (0, &[] as &[u8])
        };

        // Non-chained v2 commands (single APDU, no P1 chaining)
        match ins {
            INS_V2_GET_DEVICE_INFO => return self.cmd_v2_get_device_info(),
            INS_V2_GET_STATUS => return self.cmd_v2_get_status(),
            INS_V2_UNLOCK => return self.cmd_v2_unlock(),
            INS_V2_LOCK => return self.cmd_v2_lock(),
            INS_V2_GET_BOOTSTRAP_VK => return self.cmd_v2_get_bootstrap_vk(),
            INS_V2_GET_MAIN_VK => return self.cmd_v2_get_main_vk(data, lc),
            INS_V2_GET_WALLET_ADDRESS => return self.cmd_v2_get_wallet_address(data, lc),
            _ => {}
        }

        // Chained v2 commands (P1=0x00 last/only, P1=0x80 more)
        let is_more = (p1 & 0x80) != 0;
        if !is_more {
            // First or only block
            self.chain_ins = ins;
            self.chain_cla = APDU_CLA_V2;
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
                return self.execute_chain_v2(ins);
            }
            self.sw_response(SW_OK)
        } else {
            // Continuation block
            if ins != self.chain_ins || self.chain_cla != APDU_CLA_V2 {
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
                return self.execute_chain_v2(ins);
            }
            self.sw_response(SW_OK)
        }
    }

    unsafe fn execute_chain_v2(&mut self, ins: u8) -> Response {
        let len = self.chain_pos;
        self.chain_ins = 0;
        self.chain_pos = 0;

        match ins {
            INS_V2_SIGN_USEROP => self.cmd_v2_sign_userop(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_CLEAR_USEROP => self.cmd_v2_sign_clear_userop(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_MESSAGE => self.cmd_v2_sign_message(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_EIP712 => self.cmd_v2_sign_eip712(&CHAIN_BUF[..len], len),
            INS_V2_SIGN_BOOTSTRAP => self.cmd_v2_sign_bootstrap(&CHAIN_BUF[..len], len),
            _ => self.sw_response(SW_INS_NOT_SUPPORTED),
        }
    }

    // ===================================================================
    // v2 command handlers
    // ===================================================================

    // -- 0x01 GET_DEVICE_INFO --

    unsafe fn cmd_v2_get_device_info(&self) -> Response {
        let mut p = 0usize;

        // protocol_version u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        p += 2;

        // fw_major, fw_minor, fw_patch
        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;

        // device_uid (16 bytes)
        RESP_BUF[p..p + 16].fill(0);
        p += 16;

        // capabilities u32 BE
        let caps: u32 = (1 << 0)  // UserOp signing
            | (1 << 1)            // ZK clear-sign
            | (1 << 2)            // EIP-712
            | (1 << 3)            // Personal message signing
            | (1 << 4)            // Bootstrap signer
            | (1 << 5)            // Per-chain main key derivation
            | (1 << 7);           // Address verification
        RESP_BUF[p..p + 4].copy_from_slice(&caps.to_be_bytes());
        p += 4;

        // sig_param_set u8 (0 = SHA2-128f)
        RESP_BUF[p] = 0;
        p += 1;

        // sig_size u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        p += 2;

        // erc20_db_version u32 BE
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;

        // vk_db_version u32 BE
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;

        // ep_version u16 BE (EntryPoint v0.6)
        RESP_BUF[p..p + 2].copy_from_slice(&0x0006u16.to_be_bytes());
        p += 2;

        // wrapper_overhead u16 BE
        RESP_BUF[p..p + 2].copy_from_slice(&(WRAPPER_HEADER_LEN as u16).to_be_bytes());
        p += 2;

        // SW
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;

        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    // -- 0x02 GET_STATUS --

    unsafe fn cmd_v2_get_status(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        let unlocked = nsc_api::is_unlocked();

        let provisioned: u8 = if remaining <= MAX_ATTEMPTS as u32 { 1 } else { 0 };

        RESP_BUF[0] = provisioned;
        RESP_BUF[1] = if unlocked { 0 } else { 1 }; // locked = !unlocked
        RESP_BUF[2] = remaining as u8;
        RESP_BUF[3] = (SW_OK >> 8) as u8;
        RESP_BUF[4] = (SW_OK & 0xFF) as u8;

        Response { ptr: RESP_BUF.as_ptr(), len: 5 }
    }

    // -- 0x10 UNLOCK --

    unsafe fn cmd_v2_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    // -- 0x11 LOCK --

    unsafe fn cmd_v2_lock(&self) -> Response {
        nsc_api::lock();
        self.sw_response(SW_OK)
    }

    // -- 0x20 GET_BOOTSTRAP_VK --

    unsafe fn cmd_v2_get_bootstrap_vk(&self) -> Response {
        let mut vk = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_bootstrap_pubkey(&mut vk);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..VERIFYING_KEY_LEN].copy_from_slice(&vk);
        RESP_BUF[VERIFYING_KEY_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[VERIFYING_KEY_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: VERIFYING_KEY_LEN + 2 }
    }

    // -- 0x21 GET_MAIN_VK --

    unsafe fn cmd_v2_get_main_vk(&self, data: &[u8], lc: usize) -> Response {
        if lc != MAIN_PUBKEY_PAYLOAD_LEN {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let chain_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let key_index = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut vk = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_main_pubkey(chain_id, key_index, &mut vk);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..VERIFYING_KEY_LEN].copy_from_slice(&vk);
        RESP_BUF[VERIFYING_KEY_LEN] = (SW_OK >> 8) as u8;
        RESP_BUF[VERIFYING_KEY_LEN + 1] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: VERIFYING_KEY_LEN + 2 }
    }

    // -- 0x60 GET_WALLET_ADDRESS --

    unsafe fn cmd_v2_get_wallet_address(&self, data: &[u8], lc: usize) -> Response {
        if lc != 60 {
            return self.sw_response(SW_WRONG_LENGTH);
        }
        let mut address = [0u8; 20];
        let status = nsc_api::get_wallet_address(data, &mut address);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }

        RESP_BUF[..20].copy_from_slice(&address);
        RESP_BUF[20] = (SW_OK >> 8) as u8;
        RESP_BUF[21] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 22 }
    }

    // -- 0x30 SIGN_USEROP --

    unsafe fn cmd_v2_sign_userop(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + AA header(304) + tx_len(2) + tx + bundle_len(2) + bundle
        // We need to translate this to the v1 NSC wire format that cmd_sign_userop expects.
        if len < USEROP_V2_HEADER_LEN + 2 {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Extract key_index and ots_index (for the response wrapper — currently
        // passed through but the NSC command doesn't use them yet).
        // The NSC signing path will use the wrapper variant once fully wired.
        // For now, translate to v1 wire format and use the legacy NSC path.
        let _key_index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _ots_index = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // Translate v2 → v1 NSC wire format:
        // v2: [key_index(4)][ots_index(4)][sender(20)][entry_point(20)][chain_id(8)][...u256 fields...][init_code_hash(32)][paymaster_hash(32)][tx_len u16 BE][tx][bundle_len u16 BE][bundle]
        // v1: [has_bundle(1)][sender(20)][entry_point(20)][chain_id(8)][...u256 fields...][init_code_hash(32)][paymaster_hash(32)][tx_len u32 LE][tx][bundle_len u32 LE][bundle]

        let aa_start = 8; // skip key_index + ots_index
        let tx_len_off = USEROP_V2_HEADER_LEN;
        if tx_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let tx_len = u16::from_be_bytes([data[tx_len_off], data[tx_len_off + 1]]) as usize;
        let tx_start = tx_len_off + 2;
        let tx_end = tx_start + tx_len;
        if tx_end > len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Check for optional bundle
        let (has_bundle, bundle_len, bundle_start) = if tx_end + 2 <= len {
            let bl = u16::from_be_bytes([data[tx_end], data[tx_end + 1]]) as usize;
            if bl > 0 && tx_end + 2 + bl <= len {
                (true, bl, tx_end + 2)
            } else {
                (false, 0, 0)
            }
        } else {
            (false, 0, 0)
        };

        // Build v1 NSC payload in SIGN_PAYLOAD_BUF
        let mut p = 0usize;
        SIGN_PAYLOAD_BUF[p] = if has_bundle { 1 } else { 0 };
        p += 1;
        // Copy AA fields (sender through paymaster_hash) — starts at data[8]
        let aa_len = USEROP_V2_HEADER_LEN - 8; // 304 bytes
        SIGN_PAYLOAD_BUF[p..p + aa_len].copy_from_slice(&data[aa_start..aa_start + aa_len]);
        p += aa_len;
        // tx_len as u32 LE
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        p += 4;
        // tx data
        SIGN_PAYLOAD_BUF[p..p + tx_len].copy_from_slice(&data[tx_start..tx_end]);
        p += tx_len;
        // Optional bundle
        if has_bundle {
            SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(bundle_len as u32).to_le_bytes());
            p += 4;
            SIGN_PAYLOAD_BUF[p..p + bundle_len].copy_from_slice(&data[bundle_start..bundle_start + bundle_len]);
            p += bundle_len;
        }

        let status = nsc_api::sign_userop(
            &SIGN_PAYLOAD_BUF[..p],
            &mut SIG_BUF[..SIGNATURE_LEN],
        );
        self.sign_result_v1(status)
    }

    // -- 0x31 SIGN_CLEAR_USEROP --

    unsafe fn cmd_v2_sign_clear_userop(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + proof(384) + calldata(164) + readable(64) +
        //          AA header(304) + tx_len(2) + tx + vk_bundle_len(2) + vk_bundle
        let zk_header_start = 8; // after key_index + ots_index
        let min_len = 8 + ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN + (USEROP_V2_HEADER_LEN - 8) + 2;
        if len < min_len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Translate to v1 clear-sign NSC wire format:
        // v1: proof(384) + calldata(164) + readable(64) + [has_bundle(1)][AA header][tx_len u32 LE][tx][bundle_len u32 LE][vk_bundle]
        let mut p = 0usize;

        // Copy ZK header (proof + calldata + readable)
        let zk_len = ZK_PROOF_LEN + ZK_MAX_CALLDATA + ZK_STRING_LEN;
        CLEAR_SIGN_BUF[p..p + zk_len].copy_from_slice(&data[zk_header_start..zk_header_start + zk_len]);
        p += zk_len;

        // AA header: has_bundle = 0 (VK bundle goes at the end in v1 format)
        let aa_v2_start = zk_header_start + zk_len;
        CLEAR_SIGN_BUF[p] = 0; // has_bundle
        p += 1;
        let aa_len = USEROP_V2_HEADER_LEN - 8;
        CLEAR_SIGN_BUF[p..p + aa_len].copy_from_slice(&data[aa_v2_start..aa_v2_start + aa_len]);
        p += aa_len;

        // tx_len (v2: u16 BE → v1: u32 LE)
        let tx_len_off = aa_v2_start + aa_len;
        if tx_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let tx_len = u16::from_be_bytes([data[tx_len_off], data[tx_len_off + 1]]) as usize;
        CLEAR_SIGN_BUF[p..p + 4].copy_from_slice(&(tx_len as u32).to_le_bytes());
        p += 4;

        // tx data
        let tx_start = tx_len_off + 2;
        let tx_end = tx_start + tx_len;
        if tx_end > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        CLEAR_SIGN_BUF[p..p + tx_len].copy_from_slice(&data[tx_start..tx_end]);
        p += tx_len;

        // VK bundle: v2 has vk_bundle_len(2) + vk_bundle; v1 has bundle_len(4) + bundle
        if tx_end + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let vk_len = u16::from_be_bytes([data[tx_end], data[tx_end + 1]]) as usize;
        let vk_start = tx_end + 2;
        if vk_start + vk_len > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        CLEAR_SIGN_BUF[p..p + 4].copy_from_slice(&(vk_len as u32).to_le_bytes());
        p += 4;
        CLEAR_SIGN_BUF[p..p + vk_len].copy_from_slice(&data[vk_start..vk_start + vk_len]);
        p += vk_len;

        let status = nsc_api::clear_sign(&CLEAR_SIGN_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // -- 0x40 SIGN_MESSAGE --

    unsafe fn cmd_v2_sign_message(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + chain_id(8) + msg_len(2) + msg
        if len < 18 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let status = nsc_api::sign_message(data, &mut SIG_BUF[..WRAPPER_TOTAL_LEN]);
        self.sign_result_wrapped(status)
    }

    // -- 0x41 SIGN_EIP712 --

    unsafe fn cmd_v2_sign_eip712(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: key_index(4) + ots_index(4) + proof(384) + canonical(204) + readable(128) +
        //          vk_bundle_len(2) + vk_bundle
        let min_len = 8 + EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN + 2;
        if len < min_len {
            return self.sw_response(SW_WRONG_DATA);
        }

        // Translate to v1 NSC wire format: proof(384) + canonical(204) + readable(128) + bundle_len(4) + vk_bundle
        // (skip key_index + ots_index which aren't in the v1 format)
        let mut p = 0usize;
        let zk_start = 8;
        let zk_len = EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN;
        EIP712_BUF[p..p + zk_len].copy_from_slice(&data[zk_start..zk_start + zk_len]);
        p += zk_len;

        // VK bundle: v2 u16 BE → v1 u32 LE
        let vk_len_off = zk_start + zk_len;
        if vk_len_off + 2 > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        let vk_len = u16::from_be_bytes([data[vk_len_off], data[vk_len_off + 1]]) as usize;
        let vk_start = vk_len_off + 2;
        if vk_start + vk_len > len {
            return self.sw_response(SW_WRONG_DATA);
        }
        EIP712_BUF[p..p + 4].copy_from_slice(&(vk_len as u32).to_le_bytes());
        p += 4;
        EIP712_BUF[p..p + vk_len].copy_from_slice(&data[vk_start..vk_start + vk_len]);
        p += vk_len;

        let status = nsc_api::clear_sign_msg(&EIP712_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // -- 0x50 SIGN_BOOTSTRAP --

    unsafe fn cmd_v2_sign_bootstrap(&self, data: &[u8], len: usize) -> Response {
        // v2 wire: ots_index(4) + context_tag(1) + msg_hash(32) = 37 bytes
        if len != 37 {
            return self.sw_response(SW_WRONG_DATA);
        }

        let _ots_index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let _context_tag = data[4];
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&data[5..37]);

        let status = nsc_api::sign_bootstrap(&msg_hash, &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    // ===================================================================
    // v1 command handlers (unchanged logic from original)
    // ===================================================================

    unsafe fn cmd_v1_get_app_conf(&self) -> Response {
        let mut p = 0usize;
        RESP_BUF[p..p + 3].copy_from_slice(&FW_VERSION);
        p += 3;
        RESP_BUF[p..p + 4].copy_from_slice(&0x20260408u32.to_be_bytes());
        p += 4;
        RESP_BUF[p..p + 16].fill(0);
        p += 16;
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status == NscStatus::Ok as u32 {
            RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        }
        p += VERIFYING_KEY_LEN;
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;
        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    unsafe fn cmd_v1_get_public(&self, p2: u8, data: &[u8], lc: usize) -> Response {
        if lc < 1 { return self.sw_response(SW_WRONG_DATA); }
        let mut pubkey = [0u8; VERIFYING_KEY_LEN];
        let status = nsc_api::get_pubkey(&mut pubkey);
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        let mut p = 0usize;
        RESP_BUF[p] = 4;
        p += 1;
        RESP_BUF[p..p + 4].copy_from_slice(&pubkey[..4]);
        p += 4;
        RESP_BUF[p] = VERIFYING_KEY_LEN as u8;
        p += 1;
        RESP_BUF[p..p + VERIFYING_KEY_LEN].copy_from_slice(&pubkey);
        p += VERIFYING_KEY_LEN;
        if p2 == 0x01 {
            RESP_BUF[p] = 32;
            p += 1;
            RESP_BUF[p..p + 32].fill(0);
            p += 32;
        } else {
            RESP_BUF[p] = 0;
            p += 1;
        }
        RESP_BUF[p] = (SW_OK >> 8) as u8;
        RESP_BUF[p + 1] = (SW_OK & 0xFF) as u8;
        p += 2;
        Response { ptr: RESP_BUF.as_ptr(), len: p }
    }

    unsafe fn cmd_v1_sign_eth_tx(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes { return self.sw_response(SW_WRONG_DATA); }
        let tx_data = &data[path_bytes..];
        let tx_len = len - path_bytes;
        if tx_len == 0 || tx_len > 4096 { return self.sw_response(SW_WRONG_LENGTH); }
        let chain_id = match crate::aa::extract_chain_id(tx_data) {
            Some(id) => id,
            None => return self.sw_response(SW_WRONG_DATA),
        };

        static ENTRYPOINT_V06: [u8; 20] = [
            0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3,
            0x0c, 0x7c, 0xf5, 0x7e, 0x57, 0x8a, 0x02, 0x6d, 0x27, 0x89,
        ];
        let zero20 = [0u8; 20];
        let zero32 = [0u8; 32];
        let mut nonce = [0u8; 32]; nonce[31] = 1;
        let mut call_gas = [0u8; 32]; call_gas[29] = 0x01; call_gas[30] = 0x86; call_gas[31] = 0xa0;
        let mut ver_gas = [0u8; 32]; ver_gas[29] = 0x03; ver_gas[30] = 0x0d; ver_gas[31] = 0x40;
        let mut pre_gas = [0u8; 32]; pre_gas[30] = 0x52; pre_gas[31] = 0x08;
        let mut max_fee = [0u8; 32];
        max_fee[24..32].copy_from_slice(&50_000_000_000u64.to_be_bytes());
        let mut max_prio = [0u8; 32];
        max_prio[24..32].copy_from_slice(&2_000_000_000u64.to_be_bytes());

        let wrap = crate::aa::UserOpWrapper {
            sender: &zero20, entry_point: &ENTRYPOINT_V06, chain_id,
            nonce: &nonce, call_gas_limit: &call_gas, verification_gas_limit: &ver_gas,
            pre_verification_gas: &pre_gas, max_fee_per_gas: &max_fee,
            max_priority_fee_per_gas: &max_prio,
            init_code_hash: &crate::aa::KECCAK_EMPTY,
            paymaster_and_data_hash: &crate::aa::KECCAK_EMPTY,
        };
        let payload_len = crate::aa::build_userop_payload(&wrap, tx_data, &mut SIGN_PAYLOAD_BUF);
        let status = nsc_api::sign_userop(&SIGN_PAYLOAD_BUF[..payload_len], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_sign_eth_msg(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 { return self.sw_response(SW_WRONG_DATA); }
        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;
        if msg_len > SIGN_PAYLOAD_BUF_LEN { return self.sw_response(SW_WRONG_LENGTH); }

        let mut p = 0usize;
        SIGN_PAYLOAD_BUF[p] = 0u8;
        p += 1;
        SIGN_PAYLOAD_BUF[p..p + 4].copy_from_slice(&(msg_len as u32).to_le_bytes());
        p += 4;
        SIGN_PAYLOAD_BUF[p..p + msg_len].copy_from_slice(msg_data);
        p += msg_len;
        let status = nsc_api::sign_userop(&SIGN_PAYLOAD_BUF[..p], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_sign_eip712(&self, data: &[u8], len: usize) -> Response {
        if len < 5 { return self.sw_response(SW_WRONG_DATA); }
        let path_elements = data[0] as usize;
        let path_bytes = 1 + path_elements * 4;
        if len < path_bytes + 4 { return self.sw_response(SW_WRONG_DATA); }
        let msg_data = &data[path_bytes..];
        let msg_len = len - path_bytes;
        if msg_len > CLEAR_SIGN_BUF_LEN { return self.sw_response(SW_WRONG_LENGTH); }
        CLEAR_SIGN_BUF[..msg_len].copy_from_slice(msg_data);
        let status = nsc_api::clear_sign_msg(&CLEAR_SIGN_BUF[..msg_len], &mut SIG_BUF[..SIGNATURE_LEN]);
        self.sign_result_v1(status)
    }

    unsafe fn cmd_v1_get_pin_remaining(&self) -> Response {
        let remaining = nsc_api::get_remaining_attempts();
        RESP_BUF[0] = remaining as u8;
        RESP_BUF[1] = (SW_OK >> 8) as u8;
        RESP_BUF[2] = (SW_OK & 0xFF) as u8;
        Response { ptr: RESP_BUF.as_ptr(), len: 3 }
    }

    unsafe fn cmd_v1_unlock(&self) -> Response {
        let status = nsc_api::request_unlock();
        self.nsc_status_to_response(status)
    }

    // ===================================================================
    // GET_RESPONSE — drain pending large response (shared v1/v2)
    // ===================================================================

    unsafe fn get_response(&self) -> Response {
        if PENDING_PTR.is_null() || PENDING_POS >= PENDING_LEN {
            PENDING_PTR = core::ptr::null();
            return self.sw_response(SW_CONDITIONS_NOT_SATISFIED);
        }

        let remaining = PENDING_LEN - PENDING_POS;
        let chunk = core::cmp::min(remaining, APDU_MAX_RESP);
        let is_last = (PENDING_POS + chunk) >= PENDING_LEN;

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

    // ===================================================================
    // Helpers
    // ===================================================================

    /// Build chunked response for a v1 signing result (raw SIGNATURE_LEN bytes).
    unsafe fn sign_result_v1(&self, status: u32) -> Response {
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(SIGNATURE_LEN)
    }

    /// Build chunked response for a v2 signing result (WRAPPER_TOTAL_LEN bytes).
    unsafe fn sign_result_wrapped(&self, status: u32) -> Response {
        if status != NscStatus::Ok as u32 {
            return self.nsc_status_to_response(status);
        }
        self.setup_chunked_response(WRAPPER_TOTAL_LEN)
    }

    /// Set up chunked GET_RESPONSE state for `total_data` bytes in SIG_BUF.
    unsafe fn setup_chunked_response(&self, total_data: usize) -> Response {
        // Append SW_OK after the data
        SIG_BUF[total_data] = (SW_OK >> 8) as u8;
        SIG_BUF[total_data + 1] = (SW_OK & 0xFF) as u8;

        if total_data <= APDU_MAX_RESP {
            Response {
                ptr: SIG_BUF.as_ptr(),
                len: total_data + 2,
            }
        } else {
            let first_chunk = APDU_MAX_RESP;
            let remaining = total_data - first_chunk;

            PENDING_PTR = SIG_BUF.as_ptr().add(first_chunk);
            PENDING_LEN = remaining;
            PENDING_POS = 0;

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
            NscStatus::IdleWipe => SW_REFERENCED_DATA_INVALIDATED,
            NscStatus::InternalError => SW_INTERNAL_ERROR,
        };
        self.sw_response(sw)
    }
}
