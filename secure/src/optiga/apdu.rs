//! OPTIGA Trust M APDU command builders and TLV encoding.
//!
//! OPTIGA uses a custom (non-ISO-7816) APDU format:
//!   Command:  `CMD(1) | Param(1) | Len(2 BE) | TLV InData...`
//!   Response: `Status(1) | Len(2 BE) | TLV OutData...`
//!
//! TLV encoding: `Tag(1) | Length(2 BE) | Value(N)`

use super::ifx_i2c::IfxState;
use super::shield::ShieldedConnection;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum OptigaError {
    /// I2C bus error.
    I2c,
    /// IFX I2C protocol error.
    Transport,
    /// CRC mismatch.
    Crc,
    /// Shielded connection error.
    Shield,
    /// OPTIGA returned non-zero status byte.
    Status(u8),
    /// PIN verification failed (wrong PIN).
    PinIncorrect,
    /// PIN locked (max attempts exceeded).
    PinLocked,
    /// Device not provisioned.
    NotProvisioned,
    /// Buffer overflow.
    BufferOverflow,
}

impl From<super::ifx_i2c::IfxError> for OptigaError {
    fn from(e: super::ifx_i2c::IfxError) -> Self {
        match e {
            super::ifx_i2c::IfxError::Crc => OptigaError::Crc,
            _ => OptigaError::Transport,
        }
    }
}

// ---------------------------------------------------------------------------
// Command bytes
// ---------------------------------------------------------------------------

const CMD_OPEN_APPLICATION: u8 = 0x70;
const CMD_GET_DATA_OBJECT: u8 = 0x01;
const CMD_SET_DATA_OBJECT: u8 = 0x02;
const CMD_GET_RANDOM: u8 = 0x0C;

/// OpenApplication AID for OPTIGA Trust M.
const OPTIGA_AID: [u8; 16] = [
    0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E,
    0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
];

// ---------------------------------------------------------------------------
// APDU parameters
// ---------------------------------------------------------------------------

/// GetDataObject / SetDataObject: read/write data.
const PARAM_DATA: u8 = 0x00;
/// GetDataObject / SetDataObject: read/write metadata.
const PARAM_METADATA: u8 = 0x01;
/// SetDataObject: erase and write.
const PARAM_ERASE_WRITE: u8 = 0x40;

// ---------------------------------------------------------------------------
// TLV tag constants
// ---------------------------------------------------------------------------

/// Tag for OID reference (2 bytes, big-endian).
const TAG_OID: u8 = 0x01;
/// Tag for offset within data object (2 bytes, big-endian).
const TAG_OFFSET: u8 = 0x02;
/// Tag for read length (2 bytes, big-endian).
const TAG_LENGTH: u8 = 0x03;
/// Tag for data payload (variable length).
const TAG_DATA: u8 = 0x03;

// ---------------------------------------------------------------------------
// OID assignments for PQSigner
// ---------------------------------------------------------------------------

/// Platform Binding Secret (shielded connection root of trust).
pub const OID_PBS: u16 = 0xE140;
/// Authorization reference — stores PIN-derived HMAC secret.
pub const OID_AUTH_REF: u16 = 0xF1D0;
/// Entropy half (32 bytes) — XOR-split of BIP-39 entropy.
pub const OID_ENTROPY: u16 = 0xF1D1;
/// Default verifying key (32 bytes).
pub const OID_VK: u16 = 0xF1D2;
/// Bootstrap verifying key (32 bytes).
pub const OID_BOOTSTRAP_VK: u16 = 0xF1D3;
/// Master secret (32 bytes) — for dual-SE cross-verification.
pub const OID_MASTER_SECRET: u16 = 0xF1D4;
/// PIN attempt counter (firmware-managed, shielded-connection-gated).
pub const OID_COUNTER: u16 = 0xF1D5;

// ---------------------------------------------------------------------------
// Metadata constants
// ---------------------------------------------------------------------------

/// Metadata root tag.
const META_ROOT: u8 = 0x20;
/// Life Cycle State of object.
const META_LCSO: u8 = 0xC0;
/// Change (write) access condition.
const META_CHANGE: u8 = 0xD0;
/// Read access condition.
const META_READ: u8 = 0xD1;
/// Execute access condition.
const META_EXECUTE: u8 = 0xD3;
/// Data type tag.
const META_DATA_TYPE: u8 = 0xF0;

/// Access condition: always allowed.
const AC_ALW: u8 = 0x00;
/// Access condition: never allowed.
const AC_NEV: u8 = 0xFF;
/// Access condition: logical AND operator.
const AC_AND: u8 = 0xFD;

/// Life cycle state: Operational (metadata locked, access conditions enforced).
const LCS_OPERATIONAL: u8 = 0x07;

/// Data type: authorization reference (AUTHREF).
const DTYPE_AUTHREF: u8 = 0x03;

// ---------------------------------------------------------------------------
// OPTIGA status codes
// ---------------------------------------------------------------------------

/// Read error code from OID 0xF1C2.
const OPTIGA_STATUS_SUCCESS: u8 = 0x00;
/// Invalid password / authorization failure.
const OPTIGA_ERR_INVALID_PASSWORD: u8 = 0x02;
/// Access conditions not satisfied.
const OPTIGA_ERR_ACCESS_DENIED: u8 = 0x07;
/// Counter threshold exceeded.
const OPTIGA_ERR_COUNTER_EXCEEDED: u8 = 0x0E;
/// Authorization failure.
const OPTIGA_ERR_AUTH_FAILURE: u8 = 0x2F;

// ---------------------------------------------------------------------------
// APDU buffer builder
// ---------------------------------------------------------------------------

/// Stack-allocated APDU builder.
///
/// Usage:
/// ```ignore
/// let mut ab = ApduBuf::new(CMD_GET_DATA_OBJECT, PARAM_DATA);
/// ab.tlv_u16(TAG_OID, 0xE0C2);
/// ab.tlv_u16(TAG_OFFSET, 0x0000);
/// ab.tlv_u16(TAG_LENGTH, 0x0020);
/// let apdu = ab.finish();
/// ```
pub struct ApduBuf {
    buf: [u8; 512],
    /// Current write cursor (starts after the 4-byte header).
    cursor: usize,
}

impl ApduBuf {
    /// Create a new APDU with the given command and parameter.
    /// The length field at bytes [2..4] is patched by `finish()`.
    pub fn new(cmd: u8, param: u8) -> Self {
        let mut s = Self {
            buf: [0u8; 512],
            cursor: 4,
        };
        s.buf[0] = cmd;
        s.buf[1] = param;
        s
    }

    /// Append a TLV with a 2-byte big-endian value.
    pub fn tlv_u16(&mut self, tag: u8, val: u16) -> &mut Self {
        self.buf[self.cursor] = tag;
        self.buf[self.cursor + 1] = 0x00;
        self.buf[self.cursor + 2] = 0x02;
        self.buf[self.cursor + 3] = (val >> 8) as u8;
        self.buf[self.cursor + 4] = val as u8;
        self.cursor += 5;
        self
    }

    /// Append a TLV with arbitrary data.
    pub fn tlv(&mut self, tag: u8, data: &[u8]) -> &mut Self {
        self.buf[self.cursor] = tag;
        let len = data.len() as u16;
        self.buf[self.cursor + 1] = (len >> 8) as u8;
        self.buf[self.cursor + 2] = len as u8;
        self.buf[self.cursor + 3..self.cursor + 3 + data.len()].copy_from_slice(data);
        self.cursor += 3 + data.len();
        self
    }

    /// Finalize: patch the InData length field and return the complete APDU.
    pub fn finish(&mut self) -> &[u8] {
        let data_len = (self.cursor - 4) as u16;
        self.buf[2] = (data_len >> 8) as u8;
        self.buf[3] = data_len as u8;
        &self.buf[..self.cursor]
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Parse an OPTIGA response. Returns the status byte and payload slice.
///
/// Response format: `Status(1) | Len(2 BE) | OutData...`
fn parse_response(resp: &[u8], len: usize) -> Result<&[u8], OptigaError> {
    if len < 3 {
        return Err(OptigaError::Transport);
    }
    let status = resp[0];
    let data_len = ((resp[1] as usize) << 8) | resp[2] as usize;

    if status != OPTIGA_STATUS_SUCCESS {
        return Err(match status {
            OPTIGA_ERR_INVALID_PASSWORD | OPTIGA_ERR_AUTH_FAILURE => OptigaError::PinIncorrect,
            OPTIGA_ERR_ACCESS_DENIED => OptigaError::PinIncorrect,
            OPTIGA_ERR_COUNTER_EXCEEDED => OptigaError::PinLocked,
            _ => OptigaError::Status(status),
        });
    }

    if 3 + data_len > len {
        return Err(OptigaError::Transport);
    }
    Ok(&resp[3..3 + data_len])
}

// ---------------------------------------------------------------------------
// Core command helper
// ---------------------------------------------------------------------------

/// Send an APDU (optionally through the shielded connection) and parse response.
///
/// If `shield` is active, the APDU is encrypted before transmission and the
/// response is decrypted. The caller receives plaintext in both cases.
///
/// Returns the response payload (status byte already checked).
unsafe fn send_command(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, OptigaError> {
    let resp_len = if shield.active {
        // Encrypt APDU
        let mut enc_buf = [0u8; 600];
        let enc_len = shield.wrap_command(apdu, &mut enc_buf)
            .map_err(|_| OptigaError::Shield)?;

        // Transceive encrypted
        let mut enc_resp = [0u8; 600];
        let n = ifx.transceive(&enc_buf[..enc_len], &mut enc_resp)?;

        // Decrypt response
        let dec_len = shield.unwrap_response(&enc_resp[..n], resp_buf)
            .map_err(|_| OptigaError::Shield)?;
        dec_len
    } else {
        ifx.transceive(apdu, resp_buf)?
    };

    Ok(resp_len)
}

// ---------------------------------------------------------------------------
// Public APDU commands
// ---------------------------------------------------------------------------

/// Open the OPTIGA application. Must be called after every reset.
pub unsafe fn open_application(ifx: &mut IfxState) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_OPEN_APPLICATION, 0x00);
    ab.tlv(0x06, &OPTIGA_AID);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = ifx.transceive(apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// Read data from a data object (OID).
///
/// Returns the number of bytes read into `out`.
pub unsafe fn get_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    offset: u16,
    length: u16,
    out: &mut [u8],
) -> Result<usize, OptigaError> {
    let mut ab = ApduBuf::new(CMD_GET_DATA_OBJECT, PARAM_DATA);
    ab.tlv_u16(TAG_OID, oid);
    ab.tlv_u16(TAG_OFFSET, offset);
    ab.tlv_u16(TAG_LENGTH, length);
    let apdu = ab.finish();

    let mut resp = [0u8; 256];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let payload = parse_response(&resp, n)?;

    if payload.len() > out.len() {
        return Err(OptigaError::BufferOverflow);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(payload.len())
}

/// Read metadata from a data object.
pub unsafe fn get_metadata(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    out: &mut [u8],
) -> Result<usize, OptigaError> {
    let mut ab = ApduBuf::new(CMD_GET_DATA_OBJECT, PARAM_METADATA);
    ab.tlv_u16(TAG_OID, oid);
    let apdu = ab.finish();

    let mut resp = [0u8; 256];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let payload = parse_response(&resp, n)?;

    if payload.len() > out.len() {
        return Err(OptigaError::BufferOverflow);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(payload.len())
}

/// Write data to a data object (erase + write).
pub unsafe fn set_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    data: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_ERASE_WRITE);
    ab.tlv_u16(TAG_OID, oid);
    ab.tlv_u16(TAG_OFFSET, 0x0000);
    ab.tlv(TAG_DATA, data);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// Write data to a data object (write only, no erase).
pub unsafe fn write_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    data: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_DATA);
    ab.tlv_u16(TAG_OID, oid);
    ab.tlv_u16(TAG_OFFSET, 0x0000);
    ab.tlv(TAG_DATA, data);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// Write metadata to a data object.
pub unsafe fn set_metadata(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    metadata: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_METADATA);
    ab.tlv_u16(TAG_OID, oid);
    ab.tlv(TAG_DATA, metadata);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// Generate random bytes from OPTIGA Trust M TRNG.
pub unsafe fn get_random(
    ifx: &mut IfxState,
    out: &mut [u8],
    length: u16,
) -> Result<usize, OptigaError> {
    let mut ab = ApduBuf::new(CMD_GET_RANDOM, 0x00);
    ab.tlv_u16(0x02, length);
    let apdu = ab.finish();

    let mut resp = [0u8; 256];
    let n = ifx.transceive(apdu, &mut resp)?;
    let payload = parse_response(&resp, n)?;

    let copy_len = payload.len().min(out.len());
    out[..copy_len].copy_from_slice(&payload[..copy_len]);
    Ok(copy_len)
}

// ---------------------------------------------------------------------------
// Metadata builders
// ---------------------------------------------------------------------------

/// Build metadata TLV for a protected data object.
///
/// Access conditions:
/// - Change: Auto(auth_oid)
/// - Read: Auto(auth_oid) [+ Conf(0xE140) if `require_shielded`]
///
/// Returns `(buf, len)` — the caller writes this to the OID's metadata.
pub fn build_metadata_protected(auth_oid: u16, require_shielded: bool) -> ([u8; 48], usize) {
    let mut buf = [0u8; 48];
    let mut c: usize = 0;

    // Root tag placeholder — we'll patch the length at the end
    buf[c] = META_ROOT;
    c += 1;
    let root_len_pos = c;
    c += 1; // reserve for root length

    // Change: Auto(auth_oid)
    buf[c] = META_CHANGE;
    c += 1;
    buf[c] = 0x03; // length of Auto condition (type + 2-byte OID)
    c += 1;
    buf[c] = 0x21; // Auto condition identifier
    c += 1;
    buf[c] = (auth_oid >> 8) as u8;
    c += 1;
    buf[c] = auth_oid as u8;
    c += 1;

    // Read condition
    if require_shielded {
        // Read: Auto(auth_oid) AND Conf(0xE140)
        // Encoding: AND(Auto(auth_oid), Conf(0xE140))
        // = [AND_op] [Auto] [OID_hi] [OID_lo] [Conf] [0xE1] [0x40]
        buf[c] = META_READ;
        c += 1;
        buf[c] = 0x07; // length
        c += 1;
        buf[c] = AC_AND;
        c += 1;
        buf[c] = 0x21; // Auto
        c += 1;
        buf[c] = (auth_oid >> 8) as u8;
        c += 1;
        buf[c] = auth_oid as u8;
        c += 1;
        buf[c] = 0x23; // Conf
        c += 1;
        buf[c] = (OID_PBS >> 8) as u8;
        c += 1;
        buf[c] = OID_PBS as u8;
        c += 1;
    } else {
        // Read: Auto(auth_oid)
        buf[c] = META_READ;
        c += 1;
        buf[c] = 0x03;
        c += 1;
        buf[c] = 0x21;
        c += 1;
        buf[c] = (auth_oid >> 8) as u8;
        c += 1;
        buf[c] = auth_oid as u8;
        c += 1;
    }

    // Execute: NEV
    buf[c] = META_EXECUTE;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_NEV;
    c += 1;

    // Patch root length
    buf[root_len_pos] = (c - 2) as u8;

    (buf, c)
}

/// Build metadata TLV for the authorization reference OID (0xF1D0).
///
/// - Change: NEV (cannot be overwritten after provisioning)
/// - Read: NEV (secret is never read back)
/// - Data type: AUTHREF
pub fn build_metadata_auth_ref() -> ([u8; 24], usize) {
    let mut buf = [0u8; 24];
    let mut c: usize = 0;

    buf[c] = META_ROOT;
    c += 1;
    let root_len_pos = c;
    c += 1;

    // Change: NEV
    buf[c] = META_CHANGE;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_NEV;
    c += 1;

    // Read: NEV
    buf[c] = META_READ;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_NEV;
    c += 1;

    // Execute: NEV
    buf[c] = META_EXECUTE;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_NEV;
    c += 1;

    // Data type: AUTHREF
    buf[c] = META_DATA_TYPE;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = DTYPE_AUTHREF;
    c += 1;

    buf[root_len_pos] = (c - 2) as u8;
    (buf, c)
}

/// Build metadata TLV for the attempt counter (0xF1D5).
///
/// - Change: Conf(0xE140) (requires shielded connection)
/// - Read: ALW
pub fn build_metadata_counter() -> ([u8; 24], usize) {
    let mut buf = [0u8; 24];
    let mut c: usize = 0;

    buf[c] = META_ROOT;
    c += 1;
    let root_len_pos = c;
    c += 1;

    // Change: Conf(0xE140) — shielded connection required for writes
    buf[c] = META_CHANGE;
    c += 1;
    buf[c] = 0x03;
    c += 1;
    buf[c] = 0x23; // Conf
    c += 1;
    buf[c] = (OID_PBS >> 8) as u8;
    c += 1;
    buf[c] = OID_PBS as u8;
    c += 1;

    // Read: ALW
    buf[c] = META_READ;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_ALW;
    c += 1;

    // Execute: NEV
    buf[c] = META_EXECUTE;
    c += 1;
    buf[c] = 0x01;
    c += 1;
    buf[c] = AC_NEV;
    c += 1;

    buf[root_len_pos] = (c - 2) as u8;
    (buf, c)
}

/// Build metadata TLV to set LcsO to Operational (irreversible lock).
pub fn build_metadata_lock() -> ([u8; 5], usize) {
    let buf: [u8; 5] = [
        META_ROOT,
        0x03,                // root length
        META_LCSO,
        0x01,                // LcsO length
        LCS_OPERATIONAL,     // 0x07
    ];
    (buf, 5)
}

/// Check if metadata indicates the object is in Operational lifecycle.
///
/// Searches the metadata TLV for tag 0xC0 (LcsO) and checks if its
/// value is 0x07 (Operational).
pub fn is_metadata_operational(metadata: &[u8], len: usize) -> bool {
    if len < 4 || metadata[0] != META_ROOT {
        return false;
    }
    let root_len = metadata[1] as usize;
    if 2 + root_len > len {
        return false;
    }

    // Walk the TLV entries inside the root
    let mut pos = 2;
    while pos + 2 <= 2 + root_len {
        let tag = metadata[pos];
        let tlen = metadata[pos + 1] as usize;
        if pos + 2 + tlen > 2 + root_len {
            break;
        }
        if tag == META_LCSO && tlen == 1 {
            return metadata[pos + 2] == LCS_OPERATIONAL;
        }
        pos += 2 + tlen;
    }
    false
}
