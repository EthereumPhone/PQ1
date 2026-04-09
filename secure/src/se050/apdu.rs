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
const P1_MAC: u8 = 0x0D; // MAC operation

// P2 values (from kSE05x_P2_* in se05x_types.h)
const P2_DEFAULT: u8 = 0x00;
const P2_GENERATE: u8 = 0x03;
const P2_ONESHOT: u8 = 0x0E;
const P2_GENERATE_ONESHOT: u8 = 0x45; // MAC one-shot generate
const P2_EXIST: u8 = 0x27;
const P2_DELETE_OBJECT: u8 = 0x28;

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

/// Send an APDU and return the response data (without SW).
/// Checks the status word and returns `ApduError::Status` on failure.
pub unsafe fn send_apdu(
    t1: &mut T1State,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, ApduError> {
    #[cfg(feature = "debug-log")]
    {
        if apdu.len() >= 5 {
            // Extract object ID from first TLV (TAG_1 at offset 5) if present
            let obj_id = if apdu.len() >= 11 && apdu[5] == 0x41 && apdu[6] == 0x04 {
                u32::from_be_bytes([apdu[7], apdu[8], apdu[9], apdu[10]])
            } else { 0 };
            cortex_m_semihosting::hprintln!(
                "[SE050] TX INS={:02x} P1={:02x} P2={:02x} Lc={:02x} obj=0x{:08x} len={}",
                apdu[1], apdu[2], apdu[3], apdu[4], obj_id, apdu.len()
            );
        }
    }

    let mut raw_resp = [0u8; MAX_APDU];
    let n = t1.transceive(apdu, &mut raw_resp)?;

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

    // TLV payload: TAG_1(objectID) + TAG_3(fileLength) + TAG_4(data).
    // TAG_3 is REQUIRED when creating a new binary file object.
    // No explicit policy — use SE050 default (allow all without auth).
    let mut o = 7; // skip CLA+INS+P1+P2+Lc(3 bytes for extended)
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
