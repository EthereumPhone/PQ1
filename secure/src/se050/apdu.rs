//! SE050 APDU encoding/decoding and command wrappers.
//!
//! Implements the GP (GlobalPlatform) SELECT and SE05x-specific commands
//! needed by the `SecureElement` trait: binary read/write/delete, HMAC
//! key management, and MAC operations.
//!
//! APDU format follows ISO 7816-4: CLA | INS | P1 | P2 | [Lc | Data] | [Le].
//! SE05x parameters are TLV-encoded in the data field.

use super::t1oi2c::{T1Error, T1State};

/// SE050 APDU errors.
#[derive(Debug)]
pub enum ApduError {
    Transport(T1Error),
    /// SE050 returned an error status word.
    Status(u16),
    /// Response too short (missing SW).
    Short,
    /// TLV encoding overflow.
    Overflow,
}

impl From<T1Error> for ApduError {
    fn from(e: T1Error) -> Self {
        ApduError::Transport(e)
    }
}

// ---------------------------------------------------------------------------
// SE050 applet AID and GP SELECT
// ---------------------------------------------------------------------------

/// SE050 applet AID (from NXP documentation).
const SE050_APPLET_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// SE05x instruction codes
// ---------------------------------------------------------------------------
const INS_WRITE: u8 = 0x01;
const INS_READ: u8 = 0x02;
const INS_CRYPTO: u8 = 0x03;
const INS_MGMT: u8 = 0x04;
const INS_PROCESS: u8 = 0x05;

// P1 values (from kSE05x_P1_* in se05x_types.h)
const P1_DEFAULT: u8 = 0x00;
const P1_BINARY: u8 = 0x06; // Binary file object
const P1_HMAC: u8 = 0x05; // HMAC key
const P1_USERID: u8 = 0x07; // UserID authentication object
const P1_MAC: u8 = 0x0D; // MAC operation

// P2 values (from kSE05x_P2_* in se05x_types.h)
const P2_DEFAULT: u8 = 0x00;
const P2_GENERATE: u8 = 0x03;
const P2_ONESHOT: u8 = 0x0E;
const P2_GENERATE_ONESHOT: u8 = 0x45; // MAC one-shot generate
const P2_CREATE_SESSION: u8 = 0x1B;
const P2_CLOSE_SESSION: u8 = 0x1C;
const P2_EXIST: u8 = 0x27;
const P2_DELETE_OBJECT: u8 = 0x28;
const P2_VERIFY_SESSION_USERID: u8 = 0x2C;

// TLV tags (SE05x specific)
const TAG_SESSION_ID: u8 = 0x10;
/// Object access policy (kSE05x_TAG_POLICY).
const TAG_POLICY: u8 = 0x11;
const TAG_MAX_ATTEMPTS: u8 = 0x12;
const TAG_OBJECT_ID: u8 = 0x41;
const TAG_OBJECT_TYPE: u8 = 0x43;
const TAG_AUTH_TYPE: u8 = 0x44;
const TAG_DATA: u8 = 0x45;
const TAG_VALUE: u8 = 0x45;
const TAG_RESULT: u8 = 0x45;
const TAG_1: u8 = 0x41;
const TAG_2: u8 = 0x42;
const TAG_3: u8 = 0x43;
const TAG_4: u8 = 0x44;
const TAG_5: u8 = 0x45;
const TAG_6: u8 = 0x46;
const TAG_7: u8 = 0x47;

// HMAC-SHA256 algorithm identifier (kSE05x_MACAlgo_HMAC_SHA256)
const HMAC_SHA256: u8 = 0x19;

// Object types
const OBJ_HMAC_KEY: u8 = 0x14;

// Success status word
const SW_OK: u16 = 0x9000;

// ---------------------------------------------------------------------------
// TLV encoding helpers
// ---------------------------------------------------------------------------

/// Encode a TLV (tag, length, value) into `buf` at `offset`.
/// Returns the new offset after the TLV.
fn tlv_put(buf: &mut [u8], offset: usize, tag: u8, value: &[u8]) -> usize {
    let mut o = offset;
    buf[o] = tag;
    o += 1;

    let len = value.len();
    if len < 0x80 {
        buf[o] = len as u8;
        o += 1;
    } else if len < 0x100 {
        buf[o] = 0x81;
        buf[o + 1] = len as u8;
        o += 2;
    } else {
        buf[o] = 0x82;
        buf[o + 1] = (len >> 8) as u8;
        buf[o + 2] = (len & 0xFF) as u8;
        o += 3;
    }

    buf[o..o + len].copy_from_slice(value);
    o + len
}

/// Encode a 4-byte object ID as TLV.
fn tlv_put_obj_id(buf: &mut [u8], offset: usize, tag: u8, id: u32) -> usize {
    tlv_put(buf, offset, tag, &id.to_be_bytes())
}

/// Encode a 1-byte value as TLV.
fn tlv_put_u8(buf: &mut [u8], offset: usize, tag: u8, val: u8) -> usize {
    tlv_put(buf, offset, tag, &[val])
}

/// Parse the first TLV from `data`, returning (tag, value, rest).
fn tlv_parse(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (len, hdr) = if data[1] < 0x80 {
        (data[1] as usize, 2)
    } else if data[1] == 0x81 && data.len() >= 3 {
        (data[2] as usize, 3)
    } else if data[1] == 0x82 && data.len() >= 4 {
        (((data[2] as usize) << 8) | data[3] as usize, 4)
    } else {
        return None;
    };

    if data.len() < hdr + len {
        return None;
    }
    Some((tag, &data[hdr..hdr + len], &data[hdr + len..]))
}

// ---------------------------------------------------------------------------
// APDU transceive
// ---------------------------------------------------------------------------

/// Maximum APDU buffer size (command or response).
const MAX_APDU: usize = 1024;

/// SCP03 session reference for MAC wrapping.
/// When `Some`, APDUs are wrapped with C-MAC before sending.
pub static mut SCP03_SESSION: Option<*mut super::scp03::Scp03Session> = None;

/// Send an APDU and return the response data (without SW).
/// If an SCP03 session is active, the APDU is MAC-wrapped before sending.
pub unsafe fn send_apdu(
    t1: &mut T1State,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, ApduError> {
    // Wrap with SCP03 MAC if session is active.
    //
    // ISO 7816-4 Case 4 APDUs have a trailing Le byte after the data
    // (CLA INS P1 P2 Lc Data Le). Le must NOT be included in the MAC
    // computation — strip it before wrapping and re-append after the MAC.
    //
    // Extended-length APDUs use a 3-byte Lc: [0x00, hi, lo] starting at
    // byte 4. Detect this to correctly locate data and Le.
    let (final_apdu, final_len) = if let Some(session_ptr) = SCP03_SESSION {
        let session = &mut *session_ptr;
        if session.active {
            // Determine Lc encoding and data boundaries
            let (hdr_len, lc_val) = if apdu.len() >= 7 && apdu[4] == 0x00 {
                // Extended Lc: [CLA INS P1 P2 0x00 Lc_hi Lc_lo Data...]
                let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
                (7, lc)
            } else if apdu.len() >= 5 {
                // Short Lc: [CLA INS P1 P2 Lc Data...]
                (5, apdu[4] as usize)
            } else {
                (apdu.len(), 0)
            };

            // Detect Le: present if APDU is longer than header + data
            let has_le = apdu.len() > hdr_len + lc_val;
            let apdu_no_le = if has_le { &apdu[..apdu.len() - 1] } else { apdu };

            let mut wrapped = [0u8; MAX_APDU];
            let mut wlen = super::scp03::wrap_apdu(session, apdu_no_le, &mut wrapped);

            // Re-append Le after the MAC
            if has_le {
                wrapped[wlen] = 0x00;
                wlen += 1;
            }
            (wrapped, wlen)
        } else {
            let mut buf = [0u8; MAX_APDU];
            buf[..apdu.len()].copy_from_slice(apdu);
            (buf, apdu.len())
        }
    } else {
        let mut buf = [0u8; MAX_APDU];
        buf[..apdu.len()].copy_from_slice(apdu);
        (buf, apdu.len())
    };

    #[cfg(feature = "debug-log")]
    {
        if final_len >= 5 {
            let obj_id = if final_len >= 11 && final_apdu[5] == 0x41 && final_apdu[6] == 0x04 {
                u32::from_be_bytes([final_apdu[7], final_apdu[8], final_apdu[9], final_apdu[10]])
            } else { 0 };
            cortex_m_semihosting::hprintln!(
                "[SE050] TX INS={:02x} P1={:02x} P2={:02x} Lc={:02x} obj=0x{:08x} len={}",
                final_apdu[1], final_apdu[2], final_apdu[3], final_apdu[4], obj_id, final_len
            );
        }
    }

    let mut raw_resp = [0u8; MAX_APDU];
    let n = t1.transceive(&final_apdu[..final_len], &mut raw_resp)?;

    if n < 2 {
        return Err(ApduError::Short);
    }

    let sw = ((raw_resp[n - 2] as u16) << 8) | (raw_resp[n - 1] as u16);

    #[cfg(feature = "debug-log")]
    cortex_m_semihosting::hprintln!("[SE050] RX SW=0x{:04x} (len={})", sw, n);

    if sw != SW_OK {
        return Err(ApduError::Status(sw));
    }

    let data_len = n - 2;
    if data_len > resp_buf.len() {
        return Err(ApduError::Overflow);
    }
    resp_buf[..data_len].copy_from_slice(&raw_resp[..data_len]);
    Ok(data_len)
}

// ---------------------------------------------------------------------------
// High-level SE050 commands
// ---------------------------------------------------------------------------

/// GP SELECT — select the SE050 applet.
pub unsafe fn select_applet(t1: &mut T1State) -> Result<(), ApduError> {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x00; // CLA
    apdu[1] = 0xA4; // INS = SELECT
    apdu[2] = 0x04; // P1 = select by name
    apdu[3] = 0x00; // P2
    apdu[4] = SE050_APPLET_AID.len() as u8; // Lc
    apdu[5..5 + SE050_APPLET_AID.len()].copy_from_slice(SE050_APPLET_AID);
    let total = 5 + SE050_APPLET_AID.len();

    let mut resp = [0u8; 256];
    let _ = send_apdu(t1, &apdu[..total], &mut resp)?;
    Ok(())
}

/// Write a binary file object on the SE050.
/// If the object already exists it is overwritten.
pub unsafe fn write_binary(
    t1: &mut T1State,
    object_id: u32,
    data: &[u8],
) -> Result<(), ApduError> {
    let mut apdu = [0u8; MAX_APDU];
    apdu[0] = 0x80; // CLA
    apdu[1] = INS_WRITE; // INS
    apdu[2] = P1_BINARY; // P1 = binary
    apdu[3] = P2_DEFAULT; // P2

    // TLV payload: [TAG_POLICY] + TAG_1(objectID) + TAG_3(fileLength) + TAG_4(data).
    // TAG_POLICY can only be set on CREATE (not update). Including it on
    // an existing object causes 0x6A80. So we check first.
    let mut o = 7; // skip CLA+INS+P1+P2+Lc(3 bytes for extended)

    if !check_object_exists(t1, object_id).unwrap_or(true) {
        // New object: set policy requiring Platform SCP for all access.
        // NXP policy format: [entry_len(1)] [ar_header(4)] [auth_obj_id(4)]
        let policy: [u8; 9] = [
            0x08,                      // entry length: 8 bytes follow
            0x00, 0x3C, 0x00, 0x00,    // READ + WRITE + GEN + DELETE
            0x00, 0x00, 0x00, 0x00,    // no auth required (diagnostic)
        ];
        o = tlv_put(&mut apdu, o, TAG_POLICY, &policy);
    }
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);
    // TAG_3: 2-byte file length (max allocation size)
    let file_len = data.len() as u16;
    o = tlv_put(&mut apdu, o, TAG_3, &file_len.to_be_bytes());
    o = tlv_put(&mut apdu, o, TAG_4, data);

    // Encode Lc (extended length if needed)
    let lc = o - 7;
    if lc < 256 {
        // Shift payload right by 2 to make room for short Lc
        // Actually, let's use a simpler approach: rebuild with correct Lc position
        let mut cmd = [0u8; MAX_APDU];
        cmd[0] = 0x80;
        cmd[1] = INS_WRITE;
        cmd[2] = P1_BINARY;
        cmd[3] = P2_DEFAULT;
        cmd[4] = lc as u8;
        cmd[5..5 + lc].copy_from_slice(&apdu[7..7 + lc]);

        let mut resp = [0u8; 64];
        let _ = send_apdu(t1, &cmd[..5 + lc], &mut resp)?;
    } else {
        // Extended Lc: 0x00 followed by 2-byte length
        let mut cmd = [0u8; MAX_APDU];
        cmd[0] = 0x80;
        cmd[1] = INS_WRITE;
        cmd[2] = P1_BINARY;
        cmd[3] = P2_DEFAULT;
        cmd[4] = 0x00;
        cmd[5] = (lc >> 8) as u8;
        cmd[6] = (lc & 0xFF) as u8;
        cmd[7..7 + lc].copy_from_slice(&apdu[7..7 + lc]);

        let mut resp = [0u8; 64];
        let _ = send_apdu(t1, &cmd[..7 + lc], &mut resp)?;
    }

    Ok(())
}

/// Read a binary/object from the SE050.
/// Returns the number of bytes read into `buf`.
pub unsafe fn read_object(
    t1: &mut T1State,
    object_id: u32,
    buf: &mut [u8],
) -> Result<usize, ApduError> {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x80;
    apdu[1] = INS_READ;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);
    // TAG_2 (offset=0) + TAG_3 (length=0x7FFF = max) — required for
    // binary files on the SE050-E GP 1.0 variant. Using 0x7FFF reads
    // the entire file; the SE050 returns only what's stored.
    o = tlv_put(&mut apdu, o, TAG_2, &[0x00, 0x00]); // offset = 0
    o = tlv_put(&mut apdu, o, TAG_3, &[0x7F, 0xFF]); // length = max
    let lc = o - 5;
    apdu[4] = lc as u8;
    apdu[o] = 0x00; // Le: expect response data
    o += 1;

    let mut resp = [0u8; MAX_APDU];
    let n = send_apdu(t1, &apdu[..o], &mut resp)?;

    // Response contains TLV with the data
    if let Some((_tag, value, _rest)) = tlv_parse(&resp[..n]) {
        if value.len() > buf.len() {
            return Err(ApduError::Overflow);
        }
        buf[..value.len()].copy_from_slice(value);
        Ok(value.len())
    } else if n > 0 && n <= buf.len() {
        // Some responses are raw data without TLV wrapping
        buf[..n].copy_from_slice(&resp[..n]);
        Ok(n)
    } else {
        Ok(0)
    }
}

/// Delete a secure object from the SE050.
pub unsafe fn delete_object(t1: &mut T1State, object_id: u32) -> Result<(), ApduError> {
    let mut apdu = [0u8; 32];
    apdu[0] = 0x80;
    apdu[1] = INS_MGMT;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_DELETE_OBJECT;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);
    let lc = o - 5;
    apdu[4] = lc as u8;

    let mut resp = [0u8; 64];
    // 0x6985 (conditions not satisfied) means object doesn't exist — acceptable
    match send_apdu(t1, &apdu[..o], &mut resp) {
        Ok(_) => Ok(()),
        Err(ApduError::Status(0x6985)) => Ok(()), // already gone
        Err(e) => Err(e),
    }
}

/// Check if an object exists on the SE050.
pub unsafe fn check_object_exists(t1: &mut T1State, object_id: u32) -> Result<bool, ApduError> {
    let mut apdu = [0u8; 32];
    apdu[0] = 0x80;
    apdu[1] = INS_MGMT;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_EXIST;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);
    let lc = o - 5;
    apdu[4] = lc as u8;
    apdu[o] = 0x00; // Le
    o += 1;

    let mut resp = [0u8; 64];
    match send_apdu(t1, &apdu[..o], &mut resp) {
        Ok(n) => {
            // Response TLV TAG_1 contains 0x01 (exists) or 0x02 (not found)
            if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
                Ok(!val.is_empty() && val[0] == 0x01)
            } else {
                Ok(true) // SW=9000 implies exists
            }
        }
        Err(ApduError::Status(0x6985)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Write an HMAC-SHA256 key object to the SE050.
pub unsafe fn write_hmac_key(
    t1: &mut T1State,
    object_id: u32,
    key_data: &[u8; 32],
) -> Result<(), ApduError> {
    let mut apdu = [0u8; 128];
    apdu[0] = 0x80;
    apdu[1] = INS_WRITE;
    apdu[2] = P1_HMAC;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);
    o = tlv_put(&mut apdu, o, TAG_3, key_data); // key value
    let lc = o - 5;
    apdu[4] = lc as u8;

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, &apdu[..o], &mut resp)?;
    Ok(())
}

/// Perform HMAC-SHA256 one-shot MAC on the SE050.
/// Uses the key at `key_object_id` to MAC `data`, returns 32-byte result.
pub unsafe fn mac_oneshot(
    t1: &mut T1State,
    key_object_id: u32,
    data: &[u8],
    result: &mut [u8; 32],
) -> Result<(), ApduError> {
    let mut apdu = [0u8; 256];
    apdu[0] = 0x80;
    apdu[1] = INS_CRYPTO;
    apdu[2] = P1_MAC;
    apdu[3] = P2_GENERATE_ONESHOT;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, key_object_id);
    o = tlv_put_u8(&mut apdu, o, TAG_2, HMAC_SHA256); // algorithm
    o = tlv_put(&mut apdu, o, TAG_3, data); // data to MAC
    let lc = o - 5;
    apdu[4] = lc as u8;
    apdu[o] = 0x00; // Le: expect MAC result
    o += 1;

    let mut resp = [0u8; 128];
    let n = send_apdu(t1, &apdu[..o], &mut resp)?;

    // Parse HMAC result from response TLV
    if let Some((_tag, value, _)) = tlv_parse(&resp[..n]) {
        if value.len() >= 32 {
            result.copy_from_slice(&value[..32]);
            return Ok(());
        }
    }
    // Fallback: raw bytes
    if n >= 32 {
        result.copy_from_slice(&resp[..32]);
        Ok(())
    } else {
        Err(ApduError::Short)
    }
}

// ---------------------------------------------------------------------------
// SE050 UserID authentication commands
// ---------------------------------------------------------------------------

/// Write a UserID authentication object on the SE050.
///
/// The UserID object holds a PIN/password that the SE050 verifies internally.
/// Objects with a policy referencing this UserID require a verified session
/// before they can be read/written.
///
/// INS = 0x01 (WRITE), P1 = 0x07 (UserID)
///
/// TLV payload:
///   TAG_POLICY(0x11) = entry_len(1) ‖ ar_header(4) ‖ auth_obj_id(4)
///   TAG_MAX_ATTEMPTS(0x12) = max_attempts (2 bytes BE)
///   TAG_1(0x41) = object_id (4 bytes)
///   TAG_2(0x42) = PIN value
/// INS_AUTH_OBJECT flag — OR'd into INS_WRITE for auth object creation.
const INS_AUTH_OBJECT: u8 = 0x40;

pub unsafe fn write_user_id(
    t1: &mut T1State,
    object_id: u32,
    pin: &[u8],
    max_attempts: u16,
) -> Result<(), ApduError> {
    let mut apdu = [0u8; 128];
    apdu[0] = 0x80;
    apdu[1] = INS_WRITE | INS_AUTH_OBJECT; // 0x41 — required for auth objects
    apdu[2] = P1_USERID;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;

    // No policy on the UserID object itself (NXP passes NULL).

    // Max attempts before lockout (2-byte big-endian, 0 = no limit)
    if max_attempts > 0 {
        o = tlv_put(&mut apdu, o, TAG_MAX_ATTEMPTS, &max_attempts.to_be_bytes());
    }

    // Object ID
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);

    // PIN value
    o = tlv_put(&mut apdu, o, TAG_2, pin);

    let lc = o - 5;
    apdu[4] = lc as u8;

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, &apdu[..o], &mut resp)?;
    Ok(())
}

/// Write a binary file object with a policy requiring UserID authentication.
///
/// Objects written with this function can only be read after creating a
/// session authenticated against the specified `auth_obj_id` (UserID object).
pub unsafe fn write_binary_with_policy(
    t1: &mut T1State,
    object_id: u32,
    data: &[u8],
    auth_obj_id: u32,
) -> Result<(), ApduError> {
    let mut apdu = [0u8; MAX_APDU];
    apdu[0] = 0x80;
    apdu[1] = INS_WRITE;
    apdu[2] = P1_BINARY;
    apdu[3] = P2_DEFAULT;

    // Build TLV payload at offset 7 (extended Lc position),
    // we'll fix up the Lc encoding after.
    let mut o = 7;

    // Policy: NXP format is [entry_len] [auth_obj_id(4)] [ar_header(4)]
    // Note: auth_obj_id comes BEFORE ar_header in the SE050 policy buffer.
    let auth_bytes = auth_obj_id.to_be_bytes();
    let policy: [u8; 9] = [
        0x08,                      // entry length: 8 bytes follow
        auth_bytes[0], auth_bytes[1], auth_bytes[2], auth_bytes[3],
        0x00, 0x36, 0x00, 0x00,    // READ + WRITE + DELETE + REQUIRE_SM
    ];
    o = tlv_put(&mut apdu, o, TAG_POLICY, &policy);

    // Object ID
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, object_id);

    // File length (max allocation)
    let file_len = data.len() as u16;
    o = tlv_put(&mut apdu, o, TAG_3, &file_len.to_be_bytes());

    // Data
    o = tlv_put(&mut apdu, o, TAG_4, data);

    // Encode Lc
    let lc = o - 7;
    if lc < 256 {
        let mut cmd = [0u8; MAX_APDU];
        cmd[0] = 0x80;
        cmd[1] = INS_WRITE;
        cmd[2] = P1_BINARY;
        cmd[3] = P2_DEFAULT;
        cmd[4] = lc as u8;
        cmd[5..5 + lc].copy_from_slice(&apdu[7..7 + lc]);

        let mut resp = [0u8; 64];
        let _ = send_apdu(t1, &cmd[..5 + lc], &mut resp)?;
    } else {
        let mut cmd = [0u8; MAX_APDU];
        cmd[0] = 0x80;
        cmd[1] = INS_WRITE;
        cmd[2] = P1_BINARY;
        cmd[3] = P2_DEFAULT;
        cmd[4] = 0x00;
        cmd[5] = (lc >> 8) as u8;
        cmd[6] = (lc & 0xFF) as u8;
        cmd[7..7 + lc].copy_from_slice(&apdu[7..7 + lc]);

        let mut resp = [0u8; 64];
        let _ = send_apdu(t1, &cmd[..7 + lc], &mut resp)?;
    }

    Ok(())
}

/// Create a session authenticated against a UserID object.
///
/// Returns a 4-byte session ID that must be passed to subsequent commands
/// (via TAG_SESSION_ID) to benefit from the UserID's authorization.
///
/// INS = 0x04 (MGMT), P2 = 0x1B (CreateSession)
pub unsafe fn create_session(
    t1: &mut T1State,
    auth_obj_id: u32,
) -> Result<[u8; 8], ApduError> {
    let mut apdu = [0u8; 32];
    apdu[0] = 0x80;
    apdu[1] = INS_MGMT;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_CREATE_SESSION;

    let mut o = 5;
    o = tlv_put_obj_id(&mut apdu, o, TAG_1, auth_obj_id);
    let lc = o - 5;
    apdu[4] = lc as u8;
    apdu[o] = 0x00; // Le
    o += 1;

    let mut resp = [0u8; 64];
    let n = send_apdu(t1, &apdu[..o], &mut resp)?;

    // Response: TAG_1(session_id, 8 bytes)
    let mut session_id = [0u8; 8];
    if let Some((_, value, _)) = tlv_parse(&resp[..n]) {
        if value.len() >= 8 {
            session_id.copy_from_slice(&value[..8]);
            return Ok(session_id);
        }
    }
    if n >= 8 {
        session_id.copy_from_slice(&resp[..8]);
        Ok(session_id)
    } else {
        Err(ApduError::Short)
    }
}

/// Verify a session against a UserID object by providing the PIN.
///
/// The SE050 requires this to be wrapped in an INS_PROCESS envelope:
///   Outer APDU: CLA=0x80, INS=0x05 (PROCESS), P1=0x00, P2=0x00
///   Payload: TAG_SESSION_ID(8) + TAG_1(inner command)
///
/// The inner command is: INS_MGMT, P1=0x00, P2=0x2C + TAG_1(PIN)
pub unsafe fn verify_session_user_id(
    t1: &mut T1State,
    session_id: &[u8; 8],
    pin: &[u8],
) -> Result<(), ApduError> {
    // Build the inner command TLV: header(4) + Lc(1) + TAG_1(PIN)
    let mut inner = [0u8; 64];
    // Inner header: CLA INS P1 P2
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_VERIFY_SESSION_USERID;
    // Inner payload: TAG_1(PIN)
    let mut io = 5;
    io = tlv_put(&mut inner, io, TAG_1, pin);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;
    let inner_len = io; // total inner command length

    // Build the outer PROCESS APDU
    let mut apdu = [0u8; 128];
    apdu[0] = 0x80;
    apdu[1] = INS_PROCESS;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;
    // TAG_SESSION_ID with the 8-byte session handle
    o = tlv_put(&mut apdu, o, TAG_SESSION_ID, session_id);
    // TAG_1 with the inner command
    o = tlv_put(&mut apdu, o, TAG_1, &inner[..inner_len]);
    let lc = o - 5;
    apdu[4] = lc as u8;

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, &apdu[..o], &mut resp)?;
    Ok(())
}

/// Read a binary object using a session authenticated via UserID.
///
/// All session-based commands use INS_PROCESS (0x05) wrapping.
/// The inner read command does NOT include Le — Le goes on the outer.
pub unsafe fn read_object_authed(
    t1: &mut T1State,
    session_id: &[u8; 8],
    object_id: u32,
    buf: &mut [u8],
) -> Result<usize, ApduError> {
    // Build inner read command.
    // For commands expecting response data (hasle=1), the NXP code uses
    // extended Lc (3 bytes: 0x00 || hi || lo) even for short payloads.
    let mut inner = [0u8; 64];
    inner[0] = 0x80;
    inner[1] = INS_READ;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_DEFAULT;

    let mut io = 5; // short Lc
    io = tlv_put_obj_id(&mut inner, io, TAG_1, object_id);
    // Omit TAG_2 (offset) and TAG_3 (length) — read entire object
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;
    // Le INSIDE the inner command
    inner[io] = 0x00;
    io += 1;
    let inner_len = io;

    // Build outer PROCESS APDU
    let mut apdu = [0u8; 128];
    apdu[0] = 0x80;
    apdu[1] = INS_PROCESS;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;
    o = tlv_put(&mut apdu, o, TAG_SESSION_ID, session_id);
    o = tlv_put(&mut apdu, o, TAG_1, &inner[..inner_len]);
    let lc = o - 5;
    apdu[4] = lc as u8;
    apdu[o] = 0x00; // Le
    o += 1;

    let mut resp = [0u8; MAX_APDU];
    let n = send_apdu(t1, &apdu[..o], &mut resp)?;

    // Response contains TLV with the data
    if let Some((_tag, value, _rest)) = tlv_parse(&resp[..n]) {
        if value.len() > buf.len() {
            return Err(ApduError::Overflow);
        }
        buf[..value.len()].copy_from_slice(value);
        Ok(value.len())
    } else if n > 0 && n <= buf.len() {
        buf[..n].copy_from_slice(&resp[..n]);
        Ok(n)
    } else {
        Ok(0)
    }
}

/// Close a session on the SE050.
///
/// Wrapped in INS_PROCESS like all session commands.
pub unsafe fn close_session(
    t1: &mut T1State,
    session_id: &[u8; 8],
) -> Result<(), ApduError> {
    // Inner close command: just CLA INS P1 P2 (no payload)
    let inner: [u8; 4] = [0x80, INS_MGMT, P1_DEFAULT, P2_CLOSE_SESSION];

    let mut apdu = [0u8; 64];
    apdu[0] = 0x80;
    apdu[1] = INS_PROCESS;
    apdu[2] = P1_DEFAULT;
    apdu[3] = P2_DEFAULT;

    let mut o = 5;
    o = tlv_put(&mut apdu, o, TAG_SESSION_ID, session_id);
    o = tlv_put(&mut apdu, o, TAG_1, &inner);
    let lc = o - 5;
    apdu[4] = lc as u8;

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, &apdu[..o], &mut resp)?;
    Ok(())
}
