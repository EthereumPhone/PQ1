//! SE050 APDU encoding and command wrappers.
//!
//! Implements the minimal set of SE05x commands needed for UserID-based
//! PIN authentication and binary object storage:
//!
//!   SELECT, CheckExists, WriteUserID, WriteBinaryGated,
//!   CreateSession, VerifySession, ReadAuthed, CloseSession.
//!
//! APDU format: ISO 7816-4 (CLA | INS | P1 | P2 | [Lc | Data] | [Le]).
//! SE05x payload fields are TLV-encoded.

use super::scp03::Scp03Session;
use super::t1oi2c::{T1Error, T1State};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// SE050 operation errors.
#[derive(Debug)]
pub enum Se050Error {
    /// I2C bus failure.
    I2c,
    /// T1oI2C framing, CRC, or timeout error.
    Transport,
    /// SCP03 handshake or cryptogram mismatch.
    Scp03,
    /// SE050 returned a non-0x9000 status word.
    Status(u16),
    /// PIN verification failed (SE050 decremented attempt counter).
    PinIncorrect,
    /// Device not provisioned (UserID object missing).
    NotProvisioned,
    /// Response data exceeds caller buffer.
    BufferOverflow,
}

impl From<T1Error> for Se050Error {
    fn from(_: T1Error) -> Self {
        Se050Error::Transport
    }
}

// ---------------------------------------------------------------------------
// SE050 constants
// ---------------------------------------------------------------------------

/// SE050 applet AID (from NXP documentation).
const SE050_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
];

// Instruction codes
const INS_WRITE: u8 = 0x01;
const INS_READ: u8 = 0x02;
const INS_MGMT: u8 = 0x04;
const INS_PROCESS: u8 = 0x05;
/// OR'd into INS_WRITE for authentication object creation (UserID, keys).
const INS_AUTH_OBJECT: u8 = 0x40;

// P1 values
const P1_DEFAULT: u8 = 0x00;
const P1_BINARY: u8 = 0x06;
const P1_USERID: u8 = 0x07;

// P2 values
const P2_DEFAULT: u8 = 0x00;
const P2_CREATE_SESSION: u8 = 0x1B;
const P2_EXIST: u8 = 0x27;
const P2_VERIFY_SESSION_USERID: u8 = 0x2C;

// TLV tags
const TAG_SESSION_ID: u8 = 0x10;
const TAG_POLICY: u8 = 0x11;
const TAG_MAX_ATTEMPTS: u8 = 0x12;
const TAG_1: u8 = 0x41;
const TAG_2: u8 = 0x42;
const TAG_3: u8 = 0x43;
const TAG_4: u8 = 0x44;

const SW_OK: u16 = 0x9000;

// ---------------------------------------------------------------------------
// TLV encoding helpers
// ---------------------------------------------------------------------------

/// Encode a TLV into `buf` at `offset`. Returns the new offset.
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

/// Encode a 4-byte big-endian object ID as TLV.
fn tlv_put_u32(buf: &mut [u8], offset: usize, tag: u8, val: u32) -> usize {
    tlv_put(buf, offset, tag, &val.to_be_bytes())
}

/// Parse the first TLV from `data`. Returns `(tag, value, rest)`.
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
// APDU buffer builder
// ---------------------------------------------------------------------------

/// Maximum APDU buffer size.
const MAX_APDU: usize = 1024;

/// Builds an ISO 7816-4 APDU incrementally.
///
/// Usage: `ApduBuf::new(cla, ins, p1, p2)`, then `.tlv(...)` calls to
/// append payload TLVs, then `.finish()` to encode Lc and return the
/// complete APDU bytes.
struct ApduBuf {
    buf: [u8; MAX_APDU],
    /// Write cursor — starts at 7 to reserve space for the header and
    /// a 3-byte extended Lc. `finish()` fixes up the actual Lc encoding.
    cursor: usize,
}

impl ApduBuf {
    /// Start a new APDU with the given header bytes.
    fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        let mut buf = [0u8; MAX_APDU];
        buf[0] = cla;
        buf[1] = ins;
        buf[2] = p1;
        buf[3] = p2;
        // Cursor starts at offset 7 (past header + 3-byte extended Lc slot).
        // finish() will compact to short Lc if the payload is small.
        Self { buf, cursor: 7 }
    }

    /// Append a TLV to the payload.
    fn tlv(&mut self, tag: u8, value: &[u8]) -> &mut Self {
        self.cursor = tlv_put(&mut self.buf, self.cursor, tag, value);
        self
    }

    /// Append a TLV with a 4-byte big-endian value.
    fn tlv_u32(&mut self, tag: u8, val: u32) -> &mut Self {
        self.cursor = tlv_put_u32(&mut self.buf, self.cursor, tag, val);
        self
    }

    /// Finalize the APDU: encode Lc and return the complete byte slice.
    /// If `with_le` is true, appends Le=0x00 for commands expecting response data.
    fn finish(&mut self, with_le: bool) -> &[u8] {
        let payload_len = self.cursor - 7;

        if payload_len == 0 && !with_le {
            // Case 1: no payload, no Le — just the 4-byte header
            return &self.buf[..4];
        }

        if payload_len == 0 && with_le {
            // Case 2: no payload, Le only
            self.buf[4] = 0x00;
            return &self.buf[..5];
        }

        // Payload present: encode Lc
        let start;
        if payload_len < 256 {
            // Short Lc: shift payload from offset 7 to offset 5
            self.buf[4] = payload_len as u8;
            // Copy payload left by 2 bytes
            for i in 0..payload_len {
                self.buf[5 + i] = self.buf[7 + i];
            }
            start = 0;
            let mut end = 5 + payload_len;
            if with_le {
                self.buf[end] = 0x00;
                end += 1;
            }
            return &self.buf[start..end];
        }

        // Extended Lc: 0x00 || hi || lo
        self.buf[4] = 0x00;
        self.buf[5] = (payload_len >> 8) as u8;
        self.buf[6] = (payload_len & 0xFF) as u8;
        // Payload is already at offset 7
        let mut end = 7 + payload_len;
        if with_le {
            self.buf[end] = 0x00;
            end += 1;
        }
        &self.buf[..end]
    }
}

// ---------------------------------------------------------------------------
// APDU transceive
// ---------------------------------------------------------------------------

/// Send an APDU and return the response data (without SW).
///
/// If an SCP03 session is active, the APDU is MAC'd and encrypted before
/// sending. The Le byte is stripped before MAC computation and re-appended
/// afterward (ISO 7816-4 Case 4).
pub unsafe fn send_apdu(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, Se050Error> {
    let (tx_buf, tx_len) = if scp03.active {
        // Detect Lc and Le for proper SCP03 wrapping
        let (hdr_len, lc_val) = if apdu.len() >= 7 && apdu[4] == 0x00 {
            (7usize, ((apdu[5] as usize) << 8) | (apdu[6] as usize))
        } else if apdu.len() >= 5 {
            (5usize, apdu[4] as usize)
        } else {
            (apdu.len(), 0)
        };

        let has_le = apdu.len() > hdr_len + lc_val;
        let apdu_no_le = if has_le { &apdu[..apdu.len() - 1] } else { apdu };

        let mut wrapped = [0u8; MAX_APDU];
        let mut wlen = super::scp03::wrap_apdu(scp03, apdu_no_le, &mut wrapped);

        if has_le {
            wrapped[wlen] = 0x00;
            wlen += 1;
        }
        (wrapped, wlen)
    } else {
        let mut buf = [0u8; MAX_APDU];
        buf[..apdu.len()].copy_from_slice(apdu);
        (buf, apdu.len())
    };

    #[cfg(feature = "debug-log")]
    {
        if tx_len >= 5 {
            // Log the raw (post-SCP03) APDU header + first few bytes
            cortex_m_semihosting::hprintln!(
                "[SE050] TX CLA={:02x} INS={:02x} P1={:02x} P2={:02x} Lc={:02x} len={}",
                tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3], tx_buf[4], tx_len
            );
        }
    }

    let mut raw_resp = [0u8; MAX_APDU];
    let n = t1.transceive(&tx_buf[..tx_len], &mut raw_resp)
        .map_err(|_| Se050Error::Transport)?;

    if n < 2 {
        return Err(Se050Error::Transport);
    }

    let sw = ((raw_resp[n - 2] as u16) << 8) | (raw_resp[n - 1] as u16);

    #[cfg(feature = "debug-log")]
    cortex_m_semihosting::hprintln!("[SE050] RX SW=0x{:04x} len={}", sw, n);

    if sw != SW_OK {
        return Err(Se050Error::Status(sw));
    }

    let data_len = n - 2;
    if data_len > resp_buf.len() {
        return Err(Se050Error::BufferOverflow);
    }
    resp_buf[..data_len].copy_from_slice(&raw_resp[..data_len]);
    Ok(data_len)
}

// ---------------------------------------------------------------------------
// SE050 commands
// ---------------------------------------------------------------------------

/// GP SELECT — activate the SE050 applet.
///
/// Sent WITHOUT SCP03 wrapping (the session isn't established yet).
/// Uses raw data (not TLV) per ISO 7816-4 SELECT BY NAME.
pub unsafe fn select_applet(t1: &mut T1State) -> Result<(), Se050Error> {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x00; // CLA
    apdu[1] = 0xA4; // INS = SELECT
    apdu[2] = 0x04; // P1 = select by name
    apdu[3] = 0x00; // P2
    apdu[4] = SE050_AID.len() as u8; // Lc
    apdu[5..5 + SE050_AID.len()].copy_from_slice(SE050_AID);
    let total = 5 + SE050_AID.len();

    let mut resp = [0u8; 256];
    let n = t1.transceive(&apdu[..total], &mut resp).map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    if sw != SW_OK {
        return Err(Se050Error::Status(sw));
    }
    Ok(())
}

/// Check if an object exists on the SE050.
pub unsafe fn check_exists(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
) -> Result<bool, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_EXIST);
    let cmd = apdu.tlv_u32(TAG_1, obj_id).finish(true);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(n) => {
            #[cfg(feature = "debug-log")]
            {
                if n >= 3 {
                    cortex_m_semihosting::hprintln!(
                        "[SE050] check_exists resp: {:02x} {:02x} {:02x} (n={})",
                        resp[0], resp[1], resp[2], n
                    );
                }
            }
            if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
                Ok(!val.is_empty() && val[0] == 0x01)
            } else {
                Ok(false) // can't parse → assume not found
            }
        }
        Err(Se050Error::Status(0x6985)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Create a UserID authentication object with a PIN.
///
/// The SE050 verifies PINs internally and enforces an attempt counter.
/// After `max_attempts` failures the UserID locks permanently.
///
/// HW lesson #1: INS must be 0x41 (WRITE | AUTH_OBJECT), not 0x01.
/// HW lesson #4: UserID objects cannot be deleted after creation.
pub unsafe fn write_userid(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    pin: &[u8],
    max_attempts: u16,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE | INS_AUTH_OBJECT, P1_USERID, P2_DEFAULT);

    if max_attempts > 0 {
        apdu.tlv(TAG_MAX_ATTEMPTS, &max_attempts.to_be_bytes());
    }
    apdu.tlv_u32(TAG_1, obj_id);
    apdu.tlv(TAG_2, pin);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Write a binary object with a policy requiring UserID authentication.
///
/// Objects created with this function can only be read after verifying the
/// PIN via an authenticated session.
///
/// HW lesson #2: In the policy TLV, auth_obj_id(4) comes BEFORE ar_header(4).
pub unsafe fn write_binary_gated(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    data: &[u8],
    auth_obj_id: u32,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE, P1_BINARY, P2_DEFAULT);

    // Policy TLV: auth_obj_id(4, BE) THEN ar_header(4, BE).
    // AR = READ(0x0020_0000) | WRITE(0x0010_0000) | DELETE(0x0004_0000) | REQUIRE_SM(0x0002_0000)
    //    = 0x0036_0000
    let auth_bytes = auth_obj_id.to_be_bytes();
    let policy: [u8; 9] = [
        0x08, // entry_len: 8 bytes follow
        auth_bytes[0], auth_bytes[1], auth_bytes[2], auth_bytes[3],
        0x00, 0x36, 0x00, 0x00,
    ];
    apdu.tlv(TAG_POLICY, &policy);
    apdu.tlv_u32(TAG_1, obj_id);

    // TAG_3: file length (max allocation size)
    let file_len = data.len() as u16;
    apdu.tlv(TAG_3, &file_len.to_be_bytes());

    apdu.tlv(TAG_4, data);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Create a session authenticated against a UserID object.
///
/// Returns an 8-byte session ID (HW lesson #3).
pub unsafe fn create_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    auth_obj_id: u32,
) -> Result<[u8; 8], Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_CREATE_SESSION);
    let cmd = apdu.tlv_u32(TAG_1, auth_obj_id).finish(true);

    let mut resp = [0u8; 64];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;

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
        Err(Se050Error::Transport)
    }
}

/// Verify a PIN against a UserID via an authenticated session.
///
/// The SE050 performs the PIN comparison internally. On failure it
/// decrements its hardware attempt counter.
///
/// All session commands use INS_PROCESS (0x05) wrapping:
///   outer: TAG_SESSION_ID(8) + TAG_1(inner_command)
pub unsafe fn verify_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    pin: &[u8],
) -> Result<(), Se050Error> {
    // Build inner command: MGMT / VerifySessionUserID / TAG_1(PIN)
    let mut inner = [0u8; 64];
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_VERIFY_SESSION_USERID;
    let mut io = 5;
    io = tlv_put(&mut inner, io, TAG_1, pin);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;

    // Build outer PROCESS APDU
    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(_) => Ok(()),
        Err(Se050Error::Status(sw)) if sw == 0x6985 || (sw & 0xFF00) == 0x6300 => {
            Err(Se050Error::PinIncorrect)
        }
        Err(e) => Err(e),
    }
}

/// Read a UserID-gated binary object through an authenticated session.
///
/// HW lesson #5: Do NOT include TAG_2 (offset) or TAG_3 (length) inside
/// an INS_PROCESS wrapper — they cause SW=0x6985. Use only TAG_1 (object ID).
pub unsafe fn read_authed(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    obj_id: u32,
    buf: &mut [u8],
) -> Result<usize, Se050Error> {
    // Inner read command: READ / TAG_1(object_id) / Le=0x00
    let mut inner = [0u8; 32];
    inner[0] = 0x80;
    inner[1] = INS_READ;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_DEFAULT;
    let mut io = 5;
    io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;
    inner[io] = 0x00; // Le inside inner command
    io += 1;

    // Outer PROCESS APDU
    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; MAX_APDU];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;

    // Response contains TLV-wrapped data
    if let Some((_, value, _)) = tlv_parse(&resp[..n]) {
        if value.len() > buf.len() {
            return Err(Se050Error::BufferOverflow);
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

/// Delete a single secure object from the SE050.
///
/// Returns Ok even if the object doesn't exist (SW=0x6985).
/// UserID auth objects may return SW=0x6986 (not allowed) — that is
/// also treated as Ok since we can't do anything about it.
pub unsafe fn delete_object(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, 0x28); // P2=DELETE_OBJECT
    let cmd = apdu.tlv_u32(TAG_1, obj_id).finish(false);

    let mut resp = [0u8; 64];
    match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(_) => Ok(()),
        Err(Se050Error::Status(0x6985)) => Ok(()), // doesn't exist
        Err(Se050Error::Status(0x6986)) => Ok(()), // not allowed (UserID)
        Err(e) => Err(e),
    }
}

/// Request a platform-level factory reset via SetPlatformSCPRequest.
///
/// This resets the SE050 to factory defaults, wiping ALL objects including
/// UserID auth objects that cannot be individually deleted.
/// Uses the platform SCP resource ID 0x7FFF0207 (HW lesson #8).
pub unsafe fn platform_factory_reset(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
) -> Result<(), Se050Error> {
    const PLATFORM_SCP_OBJ: u32 = 0x7FFF_0207;
    const P2_SCP: u8 = 0x35;  // kSE05x_P2_SCP
    const FACTORY_RESET_REQ: u8 = 0x02;

    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_SCP);
    apdu.tlv_u32(TAG_1, PLATFORM_SCP_OBJ);
    apdu.tlv(TAG_2, &[FACTORY_RESET_REQ]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Close a session on the SE050.
pub unsafe fn close_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
) -> Result<(), Se050Error> {
    // Inner close: MGMT / CloseSession (no payload)
    let inner: [u8; 4] = [0x80, INS_MGMT, P1_DEFAULT, 0x1C];

    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    let _ = send_apdu(t1, scp03, cmd, &mut resp);
    Ok(())
}
