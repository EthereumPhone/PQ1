//! OPTIGA Trust M APDU command builders.
//!
//! Wire format (per Infineon Solution Reference Manual and reference C driver):
//!
//!   Command:  `CMD(1) | Param(1) | InLen(2 BE) | InData(...)`
//!   Response: `Status(1) | OutLen(2 BE) | OutData(...)`
//!
//! CMD bytes always carry the `CLEAR_LAST_ERROR` flag (0x80) — the chip uses
//! the low 7 bits to select the operation. E.g. GetDataObject is sent as
//! `0x81`, not `0x01`.
//!
//! InData is **positional** for the primitives we use (not TLV). GetDataObject
//! InData is `OID(2) | Offset(2) | Length(2)`; SetDataObject InData is
//! `OID(2) | Offset(2) | DataBytes(N)`. Each of these fields is written raw.

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
    /// PIN/HMAC verification failed.
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
// Command bytes (raw nibble | CLEAR_LAST_ERROR flag 0x80)
// ---------------------------------------------------------------------------

const CMD_CLEAR_LAST_ERROR: u8 = 0x80;

const CMD_OPEN_APPLICATION:  u8 = 0x70 | CMD_CLEAR_LAST_ERROR;  // 0xF0
const CMD_CLOSE_APPLICATION: u8 = 0x71 | CMD_CLEAR_LAST_ERROR;  // 0xF1
const CMD_GET_DATA_OBJECT:   u8 = 0x01 | CMD_CLEAR_LAST_ERROR;  // 0x81
const CMD_SET_DATA_OBJECT:   u8 = 0x02 | CMD_CLEAR_LAST_ERROR;  // 0x82
const CMD_GET_RANDOM:        u8 = 0x0C | CMD_CLEAR_LAST_ERROR;  // 0x8C
const CMD_DECRYPT_SYM:       u8 = 0x15 | CMD_CLEAR_LAST_ERROR;  // 0x95

/// OPTIGA Trust M unique application identifier ("GenAuthAppl" sealed in the AID).
const OPTIGA_AID: [u8; 16] = [
    0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E,
    0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
];

// ---------------------------------------------------------------------------
// APDU parameters
// ---------------------------------------------------------------------------

/// GetDataObject / SetDataObject: operate on data payload.
const PARAM_DATA:        u8 = 0x00;
/// GetDataObject / SetDataObject: operate on metadata tree.
const PARAM_METADATA:    u8 = 0x01;
/// SetDataObject: erase the full object then write from offset 0.
const PARAM_ERASE_WRITE: u8 = 0x40;
/// DecryptSym operation mode: HMAC verify against an auth-ref secret.
const PARAM_HMAC_MODE:   u8 = 0x02;

/// DecryptSym sequence byte: single-shot message (START + FINAL).
const SYM_SEQ_START_FINAL: u8 = 0x01;

/// DecryptSym verification-data tag (wraps the HMAC digest).
const TAG_VERIFICATION_DATA: u8 = 0x43;

/// Session OID used to hold Auto-Ref authorization state during an unlock.
///
/// The chip has four session slots at 0xE100..0xE103; we reserve 0xE100 for
/// PQSigner. Session state is per-application and resets on reset/CloseApp.
pub const OID_SESSION: u16 = 0xE100;

// ---------------------------------------------------------------------------
// OID assignments for PQSigner
// ---------------------------------------------------------------------------

/// Platform Binding Secret (shielded-connection root of trust).
pub const OID_PBS:           u16 = 0xE140;
/// Authorization reference object (holds the PIN-derived HMAC secret).
pub const OID_AUTH_REF:      u16 = 0xF1D0;
/// Entropy half (32 B) — one leg of the XOR-split BIP-39 seed.
pub const OID_ENTROPY:       u16 = 0xF1D1;
/// Default verifying key (32 B).
pub const OID_VK:            u16 = 0xF1D2;
/// Bootstrap verifying key (32 B).
pub const OID_BOOTSTRAP_VK:  u16 = 0xF1D3;
/// Master secret (32 B) — used for dual-SE cross-verification.
pub const OID_MASTER_SECRET: u16 = 0xF1D4;
/// PIN attempt counter (1 B, firmware-managed, shielded-only writes).
pub const OID_COUNTER:       u16 = 0xF1D5;

// ---------------------------------------------------------------------------
// Metadata tags and access-condition identifiers
// ---------------------------------------------------------------------------

/// Root metadata tag. All metadata TLV trees begin with `0x20 | total_len`.
const META_ROOT:      u8 = 0x20;
/// Lifecycle state of object (LcsO).
const META_LCSO:      u8 = 0xC0;
/// Change (write) access condition.
const META_CHANGE:    u8 = 0xD0;
/// Read access condition.
const META_READ:      u8 = 0xD1;
/// Execute access condition.
const META_EXECUTE:   u8 = 0xD3;
/// Data object type (tag is 0xE8, NOT 0xF0).
const META_DATA_TYPE: u8 = 0xE8;

/// Access condition: always allowed.
const AC_ALW: u8 = 0x00;
/// Access condition: never allowed.
const AC_NEV: u8 = 0xFF;
/// Boolean AND operator (infix in a compound access condition).
const AC_AND: u8 = 0xFD;
/// Boolean OR operator.
const AC_OR:  u8 = 0xFE;

/// Access condition operand: Auto-Ref — requires HMAC verify against `<OID>`.
///
/// Wire format: `0x23 OID_HI OID_LO` (3 bytes).
const AC_OP_AUTO_REF: u8 = 0x23;
/// Access condition operand: Conf — requires the shielded connection.
///
/// Wire format: `0x20 OID_HI OID_LO` (3 bytes, OID references the PBS).
const AC_OP_CONF:     u8 = 0x20;

/// LcsO values (the reachable ones; Termination is one-way).
const LCS_OPERATIONAL: u8 = 0x07;

/// Data types (tag 0xE8).
const DTYPE_BSTR:    u8 = 0x00;
const DTYPE_PBS:     u8 = 0x22;
const DTYPE_AUTHREF: u8 = 0x31;

// ---------------------------------------------------------------------------
// OPTIGA status codes (low byte of response status)
// ---------------------------------------------------------------------------

const OPTIGA_STATUS_SUCCESS:        u8 = 0x00;
const OPTIGA_ERR_INVALID_PASSWORD:  u8 = 0x02;
const OPTIGA_ERR_ACCESS_DENIED:     u8 = 0x07;
const OPTIGA_ERR_COUNTER_EXCEEDED:  u8 = 0x0E;
const OPTIGA_ERR_AUTH_FAILURE:      u8 = 0x2F;

// ---------------------------------------------------------------------------
// APDU builder
// ---------------------------------------------------------------------------

/// Stack-allocated APDU builder.
///
/// All InData is positional — callers write raw bytes with `write_u16()` /
/// `write()`, no TLV envelope unless the specific command uses tagged sub-fields.
pub struct ApduBuf {
    buf: [u8; 768],
    cursor: usize,
}

impl ApduBuf {
    /// Reserve the 4-byte header and return a builder.
    pub fn new(cmd: u8, param: u8) -> Self {
        let mut s = Self { buf: [0u8; 768], cursor: 4 };
        s.buf[0] = cmd;
        s.buf[1] = param;
        s
    }

    /// Append a 16-bit big-endian field.
    pub fn write_u16(&mut self, v: u16) -> &mut Self {
        self.buf[self.cursor] = (v >> 8) as u8;
        self.buf[self.cursor + 1] = v as u8;
        self.cursor += 2;
        self
    }

    /// Append a single byte.
    pub fn write_u8(&mut self, v: u8) -> &mut Self {
        self.buf[self.cursor] = v;
        self.cursor += 1;
        self
    }

    /// Append raw bytes.
    pub fn write(&mut self, data: &[u8]) -> &mut Self {
        self.buf[self.cursor..self.cursor + data.len()].copy_from_slice(data);
        self.cursor += data.len();
        self
    }

    /// Append a tagged TLV entry (`TAG(1) | LEN(2 BE) | DATA(N)`). Used inside
    /// DecryptSym payloads — standalone primitives don't need it.
    pub fn write_tlv(&mut self, tag: u8, data: &[u8]) -> &mut Self {
        self.buf[self.cursor] = tag;
        let len = data.len() as u16;
        self.buf[self.cursor + 1] = (len >> 8) as u8;
        self.buf[self.cursor + 2] = len as u8;
        self.buf[self.cursor + 3..self.cursor + 3 + data.len()].copy_from_slice(data);
        self.cursor += 3 + data.len();
        self
    }

    /// Patch the InLen field and return the final APDU slice.
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

/// Parse an OPTIGA response. Returns the payload slice (status byte verified).
///
/// Response format: `Status(1) | OutLen(2 BE) | OutData(...)`
fn parse_response(resp: &[u8], len: usize) -> Result<&[u8], OptigaError> {
    if len < 3 {
        return Err(OptigaError::Transport);
    }
    let status = resp[0];
    let data_len = ((resp[1] as usize) << 8) | resp[2] as usize;

    if status != OPTIGA_STATUS_SUCCESS {
        return Err(match status {
            OPTIGA_ERR_INVALID_PASSWORD
            | OPTIGA_ERR_AUTH_FAILURE
            | OPTIGA_ERR_ACCESS_DENIED => OptigaError::PinIncorrect,
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
// Core send helper (transparently wraps in shielded connection when active)
// ---------------------------------------------------------------------------

unsafe fn send_command(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, OptigaError> {
    if shield.active {
        let mut enc_buf = [0u8; 900];
        let enc_len = shield.wrap_command(apdu, &mut enc_buf)
            .map_err(|_| OptigaError::Shield)?;

        let mut enc_resp = [0u8; 900];
        let n = ifx.transceive(&enc_buf[..enc_len], &mut enc_resp)?;

        let dec_len = shield.unwrap_response(&enc_resp[..n], resp_buf)
            .map_err(|_| OptigaError::Shield)?;
        Ok(dec_len)
    } else {
        Ok(ifx.transceive(apdu, resp_buf)?)
    }
}

// ---------------------------------------------------------------------------
// Public APDU commands
// ---------------------------------------------------------------------------

/// `OpenApplication` — required once after every reset. Sends the bare 16-byte
/// AID as InData (no TLV envelope).
pub unsafe fn open_application(ifx: &mut IfxState) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_OPEN_APPLICATION, 0x00);
    ab.write(&OPTIGA_AID);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = ifx.transceive(apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// `GetRandom` — generate `length` random bytes from the chip's TRNG.
///
/// InData: `Length(2 BE)` (positional, no tag).
pub unsafe fn get_random(
    ifx: &mut IfxState,
    out: &mut [u8],
) -> Result<usize, OptigaError> {
    let length = out.len() as u16;
    let mut ab = ApduBuf::new(CMD_GET_RANDOM, 0x00);
    ab.write_u16(length);
    let apdu = ab.finish();

    let mut resp = [0u8; 512];
    let n = ifx.transceive(apdu, &mut resp)?;
    let payload = parse_response(&resp, n)?;

    let copy_len = payload.len().min(out.len());
    out[..copy_len].copy_from_slice(&payload[..copy_len]);
    Ok(copy_len)
}

/// `GetDataObject` — read `length` bytes from `oid` starting at `offset`.
///
/// InData: `OID(2) | Offset(2) | Length(2)` (all positional, no TLV).
pub unsafe fn get_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    offset: u16,
    length: u16,
    out: &mut [u8],
) -> Result<usize, OptigaError> {
    let mut ab = ApduBuf::new(CMD_GET_DATA_OBJECT, PARAM_DATA);
    ab.write_u16(oid);
    ab.write_u16(offset);
    ab.write_u16(length);
    let apdu = ab.finish();

    let mut resp = [0u8; 512];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let payload = parse_response(&resp, n)?;

    if payload.len() > out.len() {
        return Err(OptigaError::BufferOverflow);
    }
    out[..payload.len()].copy_from_slice(payload);
    Ok(payload.len())
}

/// `GetDataObject` in metadata mode — read the full metadata TLV tree of `oid`.
///
/// InData: `OID(2)` only (positional).
pub unsafe fn get_metadata(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    out: &mut [u8],
) -> Result<usize, OptigaError> {
    let mut ab = ApduBuf::new(CMD_GET_DATA_OBJECT, PARAM_METADATA);
    ab.write_u16(oid);
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

/// `SetDataObject` with erase-and-write — overwrite `oid` from offset 0.
///
/// InData: `OID(2) | Offset(2) | Data(N)` (positional).
pub unsafe fn set_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    data: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_ERASE_WRITE);
    ab.write_u16(oid);
    ab.write_u16(0x0000);
    ab.write(data);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// `SetDataObject` write-only — update `oid` in place without erasing first.
pub unsafe fn write_data_object(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    data: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_DATA);
    ab.write_u16(oid);
    ab.write_u16(0x0000);
    ab.write(data);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// `SetDataObject` in metadata mode — install/update the metadata TLV tree.
///
/// InData: `OID(2) | Offset(2) | MetadataBytes(N)`.
pub unsafe fn set_metadata(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    oid: u16,
    metadata: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_SET_DATA_OBJECT, PARAM_METADATA);
    ab.write_u16(oid);
    ab.write_u16(0x0000);
    ab.write(metadata);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

/// `DecryptSym` in HMAC-verify mode — present a precomputed HMAC over
/// `input_data` and ask the chip to compare against the secret at
/// `secret_oid`. On success, the `session_oid` session is marked as having
/// verified `secret_oid`, and subsequent reads of OIDs with `Auto(secret_oid)`
/// access conditions succeed within that session.
///
/// InData layout (positional + one trailing TLV):
///
/// ```text
///   secret_oid(2) | seq(1) | length(2) | session_oid(2) | input_data(N)
///   | 0x43 | tlv_len(2) | hmac(32)
/// ```
///
/// Where `length = N + 2` (the +2 accounts for the inlined `session_oid`).
pub unsafe fn hmac_verify(
    ifx: &mut IfxState,
    shield: &mut ShieldedConnection,
    secret_oid: u16,
    session_oid: u16,
    input_data: &[u8],
    hmac: &[u8],
) -> Result<(), OptigaError> {
    let mut ab = ApduBuf::new(CMD_DECRYPT_SYM, PARAM_HMAC_MODE);
    ab.write_u16(secret_oid);
    ab.write_u8(SYM_SEQ_START_FINAL);
    ab.write_u16((input_data.len() as u16) + 2);
    ab.write_u16(session_oid);
    ab.write(input_data);
    ab.write_tlv(TAG_VERIFICATION_DATA, hmac);
    let apdu = ab.finish();

    let mut resp = [0u8; 64];
    let n = send_command(ifx, shield, apdu, &mut resp)?;
    let _ = parse_response(&resp, n)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Metadata builders
// ---------------------------------------------------------------------------

/// Inner buffer type for metadata builders. 64 bytes is plenty — the largest
/// metadata tree we produce is ~30 bytes.
type MetaBuf = [u8; 64];

fn push_lcso_op(buf: &mut MetaBuf, c: &mut usize, state: u8) {
    buf[*c] = META_LCSO;
    buf[*c + 1] = 0x01;
    buf[*c + 2] = state;
    *c += 3;
}

fn push_ac_simple(buf: &mut MetaBuf, c: &mut usize, tag: u8, cond: u8) {
    buf[*c] = tag;
    buf[*c + 1] = 0x01;
    buf[*c + 2] = cond;
    *c += 3;
}

fn push_ac_auto_or_conf(
    buf: &mut MetaBuf,
    c: &mut usize,
    tag: u8,
    auth_oid: u16,
    op: u8,
) {
    buf[*c] = tag;
    buf[*c + 1] = 0x07;
    buf[*c + 2] = AC_OP_AUTO_REF;
    buf[*c + 3] = (auth_oid >> 8) as u8;
    buf[*c + 4] = auth_oid as u8;
    buf[*c + 5] = op;
    buf[*c + 6] = AC_OP_CONF;
    buf[*c + 7] = (OID_PBS >> 8) as u8;
    buf[*c + 8] = OID_PBS as u8;
    *c += 9;
}

fn push_ac_auto(buf: &mut MetaBuf, c: &mut usize, tag: u8, auth_oid: u16) {
    buf[*c] = tag;
    buf[*c + 1] = 0x03;
    buf[*c + 2] = AC_OP_AUTO_REF;
    buf[*c + 3] = (auth_oid >> 8) as u8;
    buf[*c + 4] = auth_oid as u8;
    *c += 5;
}

fn push_ac_conf(buf: &mut MetaBuf, c: &mut usize, tag: u8) {
    buf[*c] = tag;
    buf[*c + 1] = 0x03;
    buf[*c + 2] = AC_OP_CONF;
    buf[*c + 3] = (OID_PBS >> 8) as u8;
    buf[*c + 4] = OID_PBS as u8;
    *c += 5;
}

fn push_data_type(buf: &mut MetaBuf, c: &mut usize, ty: u8) {
    buf[*c] = META_DATA_TYPE;
    buf[*c + 1] = 0x01;
    buf[*c + 2] = ty;
    *c += 3;
}

fn wrap_meta(buf: MetaBuf, inner_len: usize) -> (MetaBuf, usize) {
    let mut out = [0u8; 64];
    out[0] = META_ROOT;
    out[1] = inner_len as u8;
    out[2..2 + inner_len].copy_from_slice(&buf[..inner_len]);
    (out, 2 + inner_len)
}

/// Metadata for a protected user OID (entropy, VK, master_secret, etc).
///
/// - **Change**: `Auto(auth_oid) OR Conf(0xE140)` — PIN auth unlocks normal
///   writes; shielded connection provides the admin-recovery path.
/// - **Read**: `Auto(auth_oid) AND Conf(0xE140)` for `require_shielded=true`
///   (entropy + master_secret); just `Auto(auth_oid)` otherwise (VK objects
///   that need to be readable by the NSC gateway before unlock).
/// - **Execute**: Never.
pub fn build_metadata_protected(
    auth_oid: u16,
    require_shielded: bool,
) -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;

    push_ac_auto_or_conf(&mut inner, &mut c, META_CHANGE, auth_oid, AC_OR);

    if require_shielded {
        push_ac_auto_or_conf(&mut inner, &mut c, META_READ, auth_oid, AC_AND);
    } else {
        push_ac_auto(&mut inner, &mut c, META_READ, auth_oid);
    }

    push_ac_simple(&mut inner, &mut c, META_EXECUTE, AC_NEV);

    wrap_meta(inner, c)
}

/// Metadata for the authorization-reference OID (0xF1D0).
///
/// - **Change**: `Conf(0xE140)` — only the shielded connection (i.e. the
///   admin path from MCU) can rewrite the secret. This enables
///   factory-reset-with-new-PIN without bricking the chip.
/// - **Read**: Never.
/// - **Execute**: Always — required for the HMAC challenge-response protocol.
/// - **Data type**: AUTHREF (0x31).
pub fn build_metadata_auth_ref() -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;

    push_ac_conf(&mut inner, &mut c, META_CHANGE);
    push_ac_simple(&mut inner, &mut c, META_READ, AC_NEV);
    push_ac_simple(&mut inner, &mut c, META_EXECUTE, AC_ALW);
    push_data_type(&mut inner, &mut c, DTYPE_AUTHREF);

    wrap_meta(inner, c)
}

/// Metadata for the PIN attempt counter (0xF1D5).
///
/// - **Change**: `Conf(0xE140)` — only the shielded connection can update.
/// - **Read**: Always (the value is non-secret).
/// - **Execute**: Never.
pub fn build_metadata_counter() -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;

    push_ac_conf(&mut inner, &mut c, META_CHANGE);
    push_ac_simple(&mut inner, &mut c, META_READ, AC_ALW);
    push_ac_simple(&mut inner, &mut c, META_EXECUTE, AC_NEV);

    wrap_meta(inner, c)
}

/// Metadata that raises LcsO to Operational (irreversible).
pub fn build_metadata_lock() -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;
    push_lcso_op(&mut inner, &mut c, LCS_OPERATIONAL);
    wrap_meta(inner, c)
}

/// Metadata for the Platform Binding Secret OID (0xE140).
///
/// Follows Infineon's `example_pair_host_and_optiga_using_pre_shared_secret`
/// pattern verbatim, with LcsO bumped to Operational so the metadata itself
/// becomes immutable:
///
/// - **Change**: `LcsO < Operational OR Conf(0xE140)` — the LcsO path is
///   one-shot (satisfied only during Creation), the `Conf` path keeps the
///   PBS rotatable *via the existing shielded connection* so we can recover
///   from compromise or rotate keys in a future firmware.
/// - **Read**: `LcsO < Operational` — unreadable after first boot.
/// - **Execute**: Always (the shielded connection engine must be able to use
///   the secret).
/// - **Data type**: Platform Binding Secret (0x22).
/// - **LcsO**: Operational (irreversible).
pub fn build_metadata_pbs_final() -> (MetaBuf, usize) {
    let mut inner = [0u8; 64];
    let mut c = 0usize;

    push_lcso_op(&mut inner, &mut c, LCS_OPERATIONAL);

    // Change: LcsO < Operational OR Conf(0xE140) — 7-byte expression.
    inner[c] = META_CHANGE;
    inner[c + 1] = 0x07;
    inner[c + 2] = 0xE1; // LcsO compare tag
    inner[c + 3] = 0xFC; // "<" comparator
    inner[c + 4] = LCS_OPERATIONAL;
    inner[c + 5] = AC_OR;
    inner[c + 6] = AC_OP_CONF;
    inner[c + 7] = (OID_PBS >> 8) as u8;
    inner[c + 8] = OID_PBS as u8;
    c += 9;

    // Read: LcsO < Operational — 3-byte expression (no shield fallback).
    inner[c] = META_READ;
    inner[c + 1] = 0x03;
    inner[c + 2] = 0xE1;
    inner[c + 3] = 0xFC;
    inner[c + 4] = LCS_OPERATIONAL;
    c += 5;

    push_ac_simple(&mut inner, &mut c, META_EXECUTE, AC_ALW);
    push_data_type(&mut inner, &mut c, DTYPE_PBS);

    wrap_meta(inner, c)
}

// ---------------------------------------------------------------------------
// Metadata parsing helpers
// ---------------------------------------------------------------------------

/// Walk a metadata TLV tree looking for `tag`. Returns the value slice.
fn find_metadata_tag<'a>(metadata: &'a [u8], len: usize, tag: u8) -> Option<&'a [u8]> {
    if len < 2 || metadata[0] != META_ROOT {
        return None;
    }
    let root_len = metadata[1] as usize;
    if 2 + root_len > len {
        return None;
    }
    let mut pos = 2;
    while pos + 2 <= 2 + root_len {
        let t = metadata[pos];
        let tlen = metadata[pos + 1] as usize;
        if pos + 2 + tlen > 2 + root_len {
            return None;
        }
        if t == tag {
            return Some(&metadata[pos + 2..pos + 2 + tlen]);
        }
        pos += 2 + tlen;
    }
    None
}

/// Returns true if the metadata indicates LcsO = Operational.
pub fn is_metadata_operational(metadata: &[u8], len: usize) -> bool {
    match find_metadata_tag(metadata, len, META_LCSO) {
        Some(v) if v.len() == 1 => v[0] == LCS_OPERATIONAL,
        _ => false,
    }
}
