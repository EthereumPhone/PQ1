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
    /// T1oI2C framing, CRC, or timeout error.
    ///
    /// **Inconclusive** — see [`Se050Error::is_inconclusive`]. The SE may never
    /// have seen the command, or may have executed it and lost the reply. This
    /// is not evidence about any credential or object.
    Transport,
    /// SCP03 handshake or cryptogram mismatch.
    Scp03,
    /// SE050 returned a non-0x9000 status word.
    Status(u16),
    /// PIN verification failed (SE050 decremented attempt counter).
    PinIncorrect,
    /// UserID authentication object is silicon-locked — the chip-side
    /// `auth_attempts == max_attempts` and the policy now denies any
    /// further use of the credential. Mapped from `SW_COMMAND_NOT_
    /// ALLOWED = 0x6986` per `plug-and-trust/hostlib/hostLib/inc/
    /// se05x_enums.h:84` (`kSE05x_SW12_COMMAND_NOT_ALLOWED`, "Command
    /// not allowed — access denied based on object policy"), AN12413
    /// §4.3.1 Table 15.
    ///
    /// **Where the lock surfaces (silicon, 2026-05-28).** On
    /// B-U585I-IOT02A the lockout is enforced at `create_session`
    /// (SW=0x6986) — the chip refuses to even open a session against a
    /// locked UserID, BEFORE any VERIFY runs. `create_session` and
    /// `verify_session` both translate 0x6986 to this variant so either
    /// manifestation maps cleanly. Cleanly observed in the 2026-05-28
    /// destructive run (tests 14 `pin_counter_persists_across_reinit`
    /// + 17 `userid_silicon_lockout`) once the driver `reinit()`s after
    /// every failed verify — see the corrected analysis in
    /// `docs/secure-elements/se050-silicon-findings.md` §4a.
    ///
    /// **NOT 0x6982.** An earlier draft mapped SW=0x6982 here too,
    /// believing it was the lockout code. It is not — 0x6982 is the
    /// Finding-A3 session-pending TRANSIENT (any non-session APDU
    /// after a failed verify/close cycle returns it until `reinit()`),
    /// which is RECOVERABLE and must never trigger a wipe. Mapping it
    /// to `AuthMethodBlocked → PinLocked → trigger_lockout_wipe` would
    /// be a false-positive device wipe. 0x6982 therefore stays a raw
    /// `Status(0x6982)` → `InternalError` (transient, no wipe).
    ///
    /// Distinct from `PinIncorrect` because the chip won't accept any
    /// more attempts — the only recovery is `factory_reset_admin` + a
    /// fresh `UserID` re-provision (which after S-6 requires bumping
    /// the OID range; see USERID_OBJ comment in mod.rs).
    AuthMethodBlocked,
    /// Device not provisioned (UserID object missing).
    NotProvisioned,
    /// Response data exceeds caller buffer.
    BufferOverflow,
    /// Caller supplied an out-of-range argument (e.g. `GetRandom`
    /// length outside the SE050's accepted [1, 256] range).
    InvalidParam,
}

impl Se050Error {
    /// Does this error mean **"I don't know"** rather than an answer the SE
    /// actually gave?
    ///
    /// **Why this exists (work-todo D1).** A probe that cannot say "I don't
    /// know" says "no" — and at every rotation site in this driver, "no" means
    /// *mutate*. `Transport` is a T=1' framing / CRC / timeout fault: the SE may
    /// never have seen the command, or may have executed it and lost the reply.
    /// It is not evidence about a credential, an object's existence, or a
    /// lifecycle state, and it must never be allowed to drive a write.
    ///
    /// Everything else is authoritative *because the SE spoke*: `Scp03` is a
    /// cryptogram/MAC mismatch (the card answered and the answer did not
    /// verify), `Status`/`PinIncorrect`/`AuthMethodBlocked`/`NotProvisioned`
    /// are verdicts it returned, and `BufferOverflow`/`InvalidParam` are our
    /// own bugs, not the card's state.
    ///
    /// Callers on a *read-only* path may still treat an inconclusive result as
    /// a plain failure. Callers whose next step is an **irreversible or
    /// destructive** mutation (PUT KEY, delete-and-recreate, an E140 rewrite)
    /// MUST fail closed on it. The first-boot ceremony is journal-resumable, so
    /// failing closed *is* the retry: the next boot re-enters the step with a
    /// fresh link.
    #[must_use]
    pub const fn is_inconclusive(&self) -> bool {
        matches!(self, Se050Error::Transport)
    }
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
/// NXP AN12413 §5.13.1 — `Se05x_API_GetRandom`. Header is
/// `(CLA=0x80, INS=INS_MGMT, P1=P1_DEFAULT, P2=P2_RANDOM)`; body is
/// `TLV(TAG_1, length:u16)`; response is `TLV(TAG_1, random_bytes)`.
const P2_RANDOM: u8 = 0x49;
/// GetVersion (extended) — returns 37-byte VersionInfo. AN12413 §4.x;
/// `kSE05x_P2_VERSION_EXT = 0x21` in NXP plug-and-trust `se05x_enums.h`.
const P2_VERSION_EXT: u8 = 0x21;
/// SetPlatformSCPRequest (AN12413 §4.6.2; `kSE05x_P2_SCP = 0x52`).
#[cfg(any(
    feature = "se050-platform-scp-required",
    feature = "se050-platform-scp-tool",
    feature = "se050-stress"
))]
const P2_SCP: u8 = 0x52;

/// `RESERVED_ID_PLATFORM_SCP` (AN12413 §3.2.5.7): the credential a session
/// must be opened with for `SetPlatformSCPRequest`. Absent on a factory E2
/// (EVT-3D21 inventory, 2026-10-19), so the firmware creates it (#989). The
/// wipe sweep skips the whole `0x7FFF*` range, so it is a device-level object
/// that survives wallet wipes.
pub const PLATFORM_SCP_OBJ: u32 = 0x7FFF_0207;

/// The `PlatformSCPRequest` byte (AN12413 Table 48). A production image can
/// only name `Required`: there is no path that turns the requirement off.
#[cfg(any(
    feature = "se050-platform-scp-required",
    feature = "se050-platform-scp-tool",
    feature = "se050-stress"
))]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformScpRequest {
    /// `SCP_REQUIRED`: every applet APDU not under full C+R MAC+ENC platform
    /// SCP03 is refused.
    Required = 0x01,
    /// `SCP_NOT_REQUIRED` (the default). Bench tool / stress only.
    #[cfg(any(feature = "se050-platform-scp-tool", feature = "se050-stress"))]
    NotRequired = 0x02,
}

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
// TLV encoding helpers — re-exported from the always-on `iso7816`
// module so a single source of truth (and a single proptest harness)
// covers both the production path here and any future SE driver.
// ---------------------------------------------------------------------------
use crate::iso7816::{tlv_parse, tlv_put, tlv_put_u32};

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

impl Drop for ApduBuf {
    /// LCR-F4: an APDU under construction can hold plaintext PIN,
    /// provisioned-object, or key material before it is SCP03-wrapped and
    /// sent. Wipe the whole buffer on EVERY scope exit (success or error) so
    /// those bytes don't outlive the operation on the secure stack. `ApduBuf`
    /// is only ever a local (created → `.tlv()` → `.finish()` borrow), so the
    /// drop always runs at the constructing function's scope end.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buf.zeroize();
    }
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
/// Requires a live SCP03 session and fails CLOSED (`Se050Error::Scp03`)
/// without one — an application APDU is never sent in cleartext
/// (invariant #3; idle-relock fix 2026-07-02). The only legitimate
/// pre-session exchanges (SELECT, INITIALIZE UPDATE, EXTERNAL
/// AUTHENTICATE) drive `t1.transceive` directly and never come through
/// here, so an inactive session at this point is a state bug (e.g. the
/// lock-path zeroize ran and `Se050::init()` has not re-established
/// yet), not a cleartext phase. The old fallback pushed the APDU out
/// unwrapped as CLA=0x80: the chip refuses that with 0x6982/0x6985
/// while its own session survives — and had the chip-side session been
/// gone too, `verify_session` would have carried the PIN in plaintext
/// on the I2C bus.
///
/// The APDU is MAC'd and encrypted before sending (`scp03::wrap_apdu`),
/// the wire response is MAC-verified and decrypted
/// (`scp03::unwrap_response`), and the SW is parsed from the resulting
/// plaintext. The Le byte is stripped before MAC computation and
/// re-appended afterward (ISO 7816-4 Case 4).
///
/// S-5 fix: previously the response was read straight off the wire (SW
/// + TLV from the ciphertext / un-MAC'd body), which silently broke if
/// the SE happened to respond in cleartext (level 0x03 — what the
/// driver used to negotiate). At level 0x33 every response is wrapped
/// and the `unwrap_response` call below is mandatory.
pub unsafe fn send_apdu(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    apdu: &[u8],
    resp_buf: &mut [u8],
) -> Result<usize, Se050Error> {
    if !scp03.active {
        #[cfg(feature = "debug-log")]
        secure_log!("[SE050] send_apdu REFUSED: no SCP03 session (init/reinit required)");
        return Err(Se050Error::Scp03);
    }

    let (tx_buf, tx_len) = {
        // Detect Lc and Le for proper SCP03 wrapping
        let (hdr_len, lc_val) = if apdu.len() >= 7 && apdu[4] == 0x00 {
            (7usize, ((apdu[5] as usize) << 8) | (apdu[6] as usize))
        } else if apdu.len() >= 5 {
            (5usize, apdu[4] as usize)
        } else {
            (apdu.len(), 0)
        };

        let has_le = apdu.len() > hdr_len + lc_val;
        let apdu_no_le = if has_le {
            &apdu[..apdu.len() - 1]
        } else {
            apdu
        };

        let mut wrapped = [0u8; MAX_APDU];
        // #991: `wrap_apdu` refuses (no session, malformed framing, too long)
        // rather than ever handing back the APDU unwrapped.
        let mut wlen = super::scp03::wrap_apdu(scp03, apdu_no_le, &mut wrapped)?;

        // S-7c fix — extended-Lc commands take a 2-byte Le per ISO 7816-4
        // (and per NXP plug-and-trust `se05x_tlv.c:1055-1059`). wrap_apdu
        // emits extended Lc when its input was extended or when padding +
        // the 8-byte C-MAC push the body to 256 bytes or more; small
        // commands stay short-Lc, so the Le form follows what it chose.
        if has_le {
            if wlen + 2 > wrapped.len() {
                return Err(Se050Error::BufferOverflow);
            }
            let wrapped_extended = wlen >= 7 && wrapped[4] == 0x00;
            if wrapped_extended {
                wrapped[wlen] = 0x00;
                wrapped[wlen + 1] = 0x00;
                wlen += 2;
            } else {
                wrapped[wlen] = 0x00;
                wlen += 1;
            }
        }
        (wrapped, wlen)
    };

    #[cfg(feature = "debug-log")]
    {
        if tx_len >= 5 {
            // Log the raw (post-SCP03) APDU header + first few bytes
            secure_log!(
                "[SE050] TX CLA={:02x} INS={:02x} P1={:02x} P2={:02x} Lc={:02x} len={}",
                tx_buf[0],
                tx_buf[1],
                tx_buf[2],
                tx_buf[3],
                tx_buf[4],
                tx_len
            );
        }
    }

    let mut raw_resp = [0u8; MAX_APDU];
    let n = t1
        .transceive(&tx_buf[..tx_len], &mut raw_resp)
        .map_err(|_| Se050Error::Transport)?;

    if n < 2 {
        return Err(Se050Error::Transport);
    }

    // S-5 fix — unwrap (R-MAC verify + R-ENC decrypt) when SCP03 is up.
    // The unwrapped buffer is `plaintext_body || SW1 SW2`; reading SW
    // off `raw_resp[n-2..]` (the old code) would have used SW from the
    // ciphertext at level 0x33, which is identically the on-wire SW
    // because GP Amd D leaves SW outside the R-ENC envelope — but the
    // body bytes are encrypted, so the old code's TLV parse upstream
    // was reading ciphertext as if it were plaintext.  At level 0x03
    // (pre-S-5) the body was cleartext but unauthenticated.  Either
    // way, unwrap_response is now the only correct path.
    let mut unwrapped = [0u8; MAX_APDU];
    let m = super::scp03::unwrap_response(scp03, &raw_resp[..n], &mut unwrapped)?;
    let (resp_slice, resp_len) = (&unwrapped[..m], m);

    let sw = ((resp_slice[resp_len - 2] as u16) << 8) | (resp_slice[resp_len - 1] as u16);

    #[cfg(feature = "debug-log")]
    secure_log!("[SE050] RX SW=0x{:04x} len={}", sw, resp_len);

    if sw != SW_OK {
        return Err(Se050Error::Status(sw));
    }

    let data_len = resp_len - 2;
    if data_len > resp_buf.len() {
        return Err(Se050Error::BufferOverflow);
    }
    // Receipt-bound copy (wave-18 GPT-5.6 follow-up): a skipped or shortened
    // plain memcpy here would leave STALE bytes from a previous response in
    // `resp_buf` behind an `Ok`, and the downstream exact-copy receipts
    // faithfully certify the stale staging buffer. `rng_exact::copy_exact`
    // binds the copy with pointer publications, volatile progress, and two
    // independent read-back relations; on any failure it wipes the
    // destination slice and we fail closed as a transport fault.
    if crate::rng_exact::copy_exact(&resp_slice[..data_len], &mut resp_buf[..data_len]).is_err() {
        return Err(Se050Error::Transport);
    }
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
    let n = t1
        .transceive(&apdu[..total], &mut resp)
        .map_err(|_| Se050Error::Transport)?;
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
                    secure_log!(
                        "[SE050] check_exists resp: {:02x} {:02x} {:02x} (n={})",
                        resp[0],
                        resp[1],
                        resp[2],
                        n
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

// Policy ar_header bit values (per se05x_const.h, POLICY_OBJ_ALLOW_*).
const AR_ALLOW_READ: u32 = 0x0020_0000;
const AR_ALLOW_WRITE: u32 = 0x0010_0000;
const AR_ALLOW_DELETE: u32 = 0x0004_0000;
const AR_REQUIRE_SM: u32 = 0x0002_0000;

/// Build a TAG_POLICY value with one or two entries.
///
/// Layout per entry (9 bytes):
///   `[entry_len=0x08] [auth_obj_id:4 BE] [ar_header:4 BE]`
///
/// SE05x policy semantics: entries are OR'd — if ANY entry's auth_obj_id
/// is satisfied by the current session AND that entry's ar_header allows
/// the requested operation, the operation succeeds. This lets us grant
/// "normal use under UserID" + "admin delete under a secondary auth
/// object" on the same secure object.
fn build_policy(primary_auth: u32, primary_ar: u32, admin_auth: Option<u32>) -> ([u8; 18], usize) {
    let mut out = [0u8; 18];
    let mut len = 0;

    let a = primary_auth.to_be_bytes();
    let ar = primary_ar.to_be_bytes();
    out[0] = 0x08;
    out[1..5].copy_from_slice(&a);
    out[5..9].copy_from_slice(&ar);
    len += 9;

    if let Some(admin) = admin_auth {
        let a2 = admin.to_be_bytes();
        // Admin entry: ALLOW_DELETE only (never ALLOW_READ) + REQUIRE_SM.
        let ar2 = (AR_ALLOW_DELETE | AR_REQUIRE_SM).to_be_bytes();
        out[9] = 0x08;
        out[10..14].copy_from_slice(&a2);
        out[14..18].copy_from_slice(&ar2);
        len += 9;
    }

    (out, len)
}

/// The value a UserID object holds, and that is presented to open it.
///
/// The chip stores this value exactly as given, so what may be put here is
/// restricted by type (#855: the user UserID used to hold the raw PIN, and
/// reading the chip gave it away). There are three things it can be, and a
/// PIN typed in at runtime is none of them: it is not a credential type, it
/// is not sixteen bytes, and it does not live for `'static`.
#[derive(Clone, Copy)]
pub enum UserIdValue<'a> {
    /// The user's or the decoy's die-bound credential, from
    /// `pin_credential::derive_set` by way of `pin_gate`.
    Credential(&'a crate::pin_credential::Se050PinCredential),
    /// A 16-byte device secret from `hw::secret_keys` (the admin and
    /// transport UserIDs), or a 16-byte test stand-in for one.
    DeviceSecret(&'a [u8; 16]),
    /// A compile-time constant: the policy self-test canary, bench test
    /// objects, and the known test PINs the bench clean-up tries against a
    /// chip provisioned by pre-#855 firmware.
    Fixed(&'static [u8]),
    /// The on-silicon stress harness only, which generates its values at
    /// run time. Not compiled into any other build.
    #[cfg(feature = "se050-stress")]
    Bench(&'a [u8]),
}

impl UserIdValue<'_> {
    /// The bytes that go on the wire, inside SCP03.
    fn bytes(&self) -> &[u8] {
        match self {
            UserIdValue::Credential(c) => c.expose_for_se050(),
            UserIdValue::DeviceSecret(s) => &s[..],
            UserIdValue::Fixed(f) => f,
            #[cfg(feature = "se050-stress")]
            UserIdValue::Bench(b) => b,
        }
    }
}

/// Create a UserID authentication object holding `userid_value`, with a
/// policy allowing self-delete plus optional admin-delete.
///
/// The SE050 verifies PINs internally and enforces an attempt counter.
/// After `max_attempts` failures the UserID locks permanently.
///
/// `max_attempts` must be in `1..=255`. Per AN12413 §4.7.1.5 Table 98 the
/// SE050 treats `max_attempts = 0` as "UNLIMITED" — a silent footgun
/// (caller may intend "lock immediately") that this function rejects with
/// `Se050Error::InvalidParam`.  Callers that genuinely want unlimited
/// attempts (admin / duress UserIDs whose lockout is enforced on the MCU
/// side) MUST use [`write_userid_unlimited`] explicitly.  The same table
/// also caps PINs at 255 attempts; values >= 256 are rejected.  (S-7a
/// fix — docs/security/security-review-2026-05.md §C-9.)
///
/// Policy entries:
///   1. `auth_obj_id = <self>`, `ar = ALLOW_WRITE | ALLOW_DELETE | REQUIRE_SM`
///      (session verified against this PIN can rotate PIN and self-delete)
///   2. If `admin_auth_obj_id` is provided:
///      `auth_obj_id = <admin>`, `ar = ALLOW_DELETE | REQUIRE_SM`
///      (a session authenticated against the admin UserID can delete THIS
///       UserID without knowing its PIN). **S-6 caveat:** passing
///       `Some(admin)` for a *user* UserID opens the substitution attack
///       (admin deletes UserID, recreates with attacker PIN, satisfies
///       any data object's `[UserID → ALLOW_READ]` policy).  Production
///       code passes `None` for the user UserID and `Some(admin)` only
///       for data objects via `write_binary_gated`.
///
/// HW lesson #1: INS must be 0x41 (WRITE | AUTH_OBJECT), not 0x01.
pub unsafe fn write_userid(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    userid_value: UserIdValue<'_>,
    max_attempts: u16,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    // S-7a — reject the silent-unlimited footgun + the PIN-objects cap.
    if max_attempts == 0 || max_attempts >= 256 {
        return Err(Se050Error::InvalidParam);
    }

    let mut apdu = ApduBuf::new(0x80, INS_WRITE | INS_AUTH_OBJECT, P1_USERID, P2_DEFAULT);

    let primary_ar = AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;
    let (policy_buf, policy_len) = build_policy(obj_id, primary_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);

    apdu.tlv(TAG_MAX_ATTEMPTS, &max_attempts.to_be_bytes());
    apdu.tlv_u32(TAG_1, obj_id);
    apdu.tlv(TAG_2, userid_value.bytes());
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Create a UserID authentication object with UNLIMITED PIN attempts —
/// `TAG_MAX_ATTEMPTS` is omitted from the APDU, which AN12413 §4.7.1.5
/// Table 98 specifies as the "unlimited" encoding.
///
/// Use this ONLY where the lockout is enforced by some external
/// mechanism that compensates for the SE not bounding the attempt
/// count.  In this firmware that's:
///
/// - **`ADMIN_WIPE_OBJ`** — PIN is 16 bytes of hardware-root-derived
///   entropy (`hw::secret_keys::se050_admin_pin()`), brute force
///   infeasible at any timing budget; SE-side lockout would only ever
///   accidentally trigger on a hardware fault.
/// - **`DURESS_USERID_OBJ`** — the MCU page-124 attempt counter gates
///   lockout; an SE-side limit here would let a wrong duress PIN burn
///   real-PIN attempts on the same chip.
/// - **E2E test admin UserIDs (`TEST_ADMIN`)** — under
///   `e2e-test`/`se050-reset-e2e` feature gates; intentional.
///
/// This is the S-7a-compliant explicit form.  Most callers should use
/// [`write_userid`] which enforces `max_attempts ∈ 1..=255`.
pub unsafe fn write_userid_unlimited(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    userid_value: UserIdValue<'_>,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE | INS_AUTH_OBJECT, P1_USERID, P2_DEFAULT);

    let primary_ar = AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM;
    let (policy_buf, policy_len) = build_policy(obj_id, primary_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);

    // TAG_MAX_ATTEMPTS omitted → SE050 treats as "unlimited" per
    // AN12413 §4.7.1.5 (mirrors NXP plug-and-trust
    // `se05x_tlv.c:351-358 tlvSet_MaxAttemps`, which also omits the
    // TLV when its argument is 0).
    apdu.tlv_u32(TAG_1, obj_id);
    apdu.tlv(TAG_2, userid_value.bytes());
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Write a binary object gated by UserID authentication, with optional
/// admin-delete entry.
///
/// Policy entries:
///   1. `auth_obj_id = <user>`, `ar = READ | WRITE | DELETE | REQUIRE_SM`
///   2. If `admin_auth_obj_id` is provided:
///      `auth_obj_id = <admin>`, `ar = DELETE | REQUIRE_SM`
///      (admin can wipe but not read — preserves hardware-enforced PIN gating
///       on entropy while giving the PIN-lockout path a way to clean up)
///
/// HW lesson #2: In each policy entry, auth_obj_id(4) comes BEFORE ar_header(4).
pub unsafe fn write_binary_gated(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    data: &[u8],
    auth_obj_id: u32,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    write_binary_with_user_ar(
        t1,
        scp03,
        obj_id,
        data,
        auth_obj_id,
        AR_ALLOW_READ | AR_ALLOW_WRITE | AR_ALLOW_DELETE | AR_REQUIRE_SM,
        admin_auth_obj_id,
    )
}

/// Like [`write_binary_gated`] but **WRITE-ONCE**: the user policy entry
/// omits `ALLOW_WRITE`, so a PIN-verified session can READ the object but
/// can never **overwrite it in place**. Used for the XOR-split SE share
/// (`ENTROPY_OBJ` / half_E) and the verifying keys, where an in-place
/// re-seed under a live PIN session would silently desync the dual-SE
/// entropy split against the fresh half_O on OPTIGA. Admin-delete is
/// preserved (via `admin_auth_obj_id`) so the factory-reset/re-provision
/// path still reclaims the object.
///
/// Scope note: the user entry intentionally KEEPS `ALLOW_DELETE`, so a
/// PIN session can still delete-then-recreate (a re-seed by another name)
/// — this is by design (admin re-provision relies on delete-then-write)
/// and grants no capability a PIN holder lacks: that session already has
/// `ALLOW_READ` on the share, and the firmware exposes no runtime gateway
/// command that deletes+recreates a secret object (deletes happen only on
/// the admin-authed provisioning/wipe paths). What this closes is the
/// silent *in-place* overwrite, which needs no delete and leaves no trace.
///
/// **SE050 create-vs-update semantics.** The policy governs *subsequent*
/// writes; the creating `WriteBinary` (object does not yet exist) is
/// authorized by the SCP03 session, so creation succeeds even though the
/// policy lacks `ALLOW_WRITE`. plug-and-trust builds write-less policies
/// (`fsl_sss_se05x_policy.c` sets `POLICY_OBJ_ALLOW_WRITE` only
/// conditionally), confirming this is an intended configuration — but it
/// is **bench-validation-pending** on real silicon: provision, confirm
/// the PIN-gated READ still works, then confirm a second `WriteBinary` to
/// the same OID is refused (expect SW=0x6985 "conditions not satisfied").
pub unsafe fn write_binary_write_once(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    data: &[u8],
    auth_obj_id: u32,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    write_binary_with_user_ar(
        t1,
        scp03,
        obj_id,
        data,
        auth_obj_id,
        // No ALLOW_WRITE → write-once. READ kept for seed reconstruction,
        // DELETE kept for self/admin teardown, REQUIRE_SM as always.
        AR_ALLOW_READ | AR_ALLOW_DELETE | AR_REQUIRE_SM,
        admin_auth_obj_id,
    )
}

/// Core of [`write_binary_gated`] / [`write_binary_write_once`]: write a
/// binary object whose *user* policy entry carries the supplied `user_ar`.
/// The admin entry (when `admin_auth_obj_id` is `Some`) is always
/// `DELETE | REQUIRE_SM` per [`build_policy`].
unsafe fn write_binary_with_user_ar(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    data: &[u8],
    auth_obj_id: u32,
    user_ar: u32,
    admin_auth_obj_id: Option<u32>,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_WRITE, P1_BINARY, P2_DEFAULT);

    let (policy_buf, policy_len) = build_policy(auth_obj_id, user_ar, admin_auth_obj_id);
    apdu.tlv(TAG_POLICY, &policy_buf[..policy_len]);
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
///
/// **Silicon lockout path (2026-05-28).** When a UserID has exhausted
/// its `auth_attempts` budget, B-U585I-IOT02A refuses session creation
/// itself — `CreateSession` returns SW=0x6986 BEFORE any VERIFY can
/// run. Both `userid_silicon_lockout` and `pin_counter_persists_across_
/// reinit` stress tests show this cleanly once the A3 session-pending
/// artifact is cleared by an intervening `reinit()` (raw evidence in
/// the 2026-05-28 destructive run, tests 14 + 17). The prior assumption
/// — that lockout surfaces at `verify_session` with SW=0x6982 — was an
/// artifact of the chip being session-pending (Finding A3): with the
/// driver now `reinit()`ing after each failed verify, the TRUE lockout
/// code (0x6986 at session creation) is exposed. We translate it to
/// `Se050Error::AuthMethodBlocked` here so the unlock dispatch
/// (`classify_se050_unlock_error`) maps it to `UnlockError::PinLocked`
/// → `trigger_lockout_wipe`, exactly as the §25 Gap 4 contract
/// intends. Without this arm a locked UserID would mis-classify as
/// `InternalError` (no wipe).
pub unsafe fn create_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    auth_obj_id: u32,
) -> Result<[u8; 8], Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_CREATE_SESSION);
    let cmd = apdu.tlv_u32(TAG_1, auth_obj_id).finish(true);

    let mut resp = [0u8; 64];
    let n = match send_apdu(t1, scp03, cmd, &mut resp) {
        Ok(n) => n,
        // Locked-UserID path: 0x6986 (policy denial) on CreateSession.
        // See the doc above + `verify_session`'s matching arm.
        Err(Se050Error::Status(0x6986)) => return Err(Se050Error::AuthMethodBlocked),
        Err(e) => return Err(e),
    };

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

/// Present `userid_value` to a UserID via an authenticated session.
///
/// The SE050 performs the comparison internally. On failure it decrements
/// its hardware attempt counter. `userid_value` is the value the object
/// holds (see [`UserIdValue`]) — since #855 never a PIN.
///
/// All session commands use INS_PROCESS (0x05) wrapping:
///   outer: TAG_SESSION_ID(8) + TAG_1(inner_command)
pub unsafe fn verify_session(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    userid_value: UserIdValue<'_>,
) -> Result<(), Se050Error> {
    // Build inner command: MGMT / VerifySessionUserID / TAG_1(PIN)
    let mut inner = [0u8; 64];
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = P2_VERIFY_SESSION_USERID;
    let mut io = 5;
    io = tlv_put(&mut inner, io, TAG_1, userid_value.bytes());
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
        // Wrong-PIN path: 0x6985 (`SM_ERR_CONDITIONS_NOT_SATISFIED`)
        // or 0x63Cx (counter remaining nibble; documented as
        // "Authentication failed, attempts left = x" in NXP's
        // A71CL HAL header which SE050 inherits via ISO 7816-4).
        Err(Se050Error::Status(sw)) if sw == 0x6985 || (sw & 0xFF00) == 0x6300 => {
            Err(Se050Error::PinIncorrect)
        }
        // UserID silicon-lock path: §25 Gap 4. AN12413 §4.3.1 Table 15
        // lists 0x6986 (`SM_ERR_COMMAND_NOT_ALLOWED`, "Command not
        // allowed — access denied based on object policy") as the
        // policy-denial code. On B-U585I-IOT02A the lockout actually
        // surfaces one step earlier — at `create_session` (SW=0x6986,
        // mapped there too) — but we keep this arm because a chip that
        // admits the session and rejects the VERIFY would land here.
        //
        // NOTE: SW=0x6982 is deliberately NOT mapped to
        // `AuthMethodBlocked`. The 2026-05-28 silicon run initially
        // suggested 0x6982 was the lockout code, but that was the
        // Finding-A3 session-pending TRANSIENT (recoverable via
        // `reinit()`), not a permanent lock — see
        // `docs/secure-elements/se050-silicon-findings.md` §4. Mapping a recoverable
        // transient to `AuthMethodBlocked` → `PinLocked` →
        // `trigger_lockout_wipe` would risk a false-positive wipe, so
        // 0x6982 propagates as `Status(0x6982)` (→ `InternalError`,
        // treated as transient, no wipe).
        Err(Se050Error::Status(sw)) if sw == 0x6986 => Err(Se050Error::AuthMethodBlocked),
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

/// Update a binary object's DATA through an authenticated session
/// (INS_PROCESS-wrapped `WriteBinary`, data-only: object-id + data tags
/// only, no offset/length tags per HW lesson #5, no policy tag since the
/// policy is immutable post-create). This is the pure data-UPDATE path an attacker
/// would use to re-seed an object — it succeeds only if the session's auth
/// object holds `ALLOW_WRITE` in the object policy. Used by the write-once
/// silicon validation to prove that dropping `ALLOW_WRITE` (half_E) is what
/// refuses the update. Not used by production firmware (which only ever
/// CREATEs these objects).
pub unsafe fn write_authed(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    obj_id: u32,
    data: &[u8],
) -> Result<(), Se050Error> {
    // Inner command: WRITE / P1_BINARY / TAG_1(obj_id) + TAG_4(data).
    let mut inner = [0u8; 96];
    inner[0] = 0x80;
    inner[1] = INS_WRITE;
    inner[2] = P1_BINARY;
    inner[3] = P2_DEFAULT;
    let mut io = 5;
    io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);
    io = tlv_put(&mut inner, io, TAG_4, data);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;

    // Outer PROCESS APDU: TAG_SESSION_ID(8) + TAG_1(inner_command).
    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp)?;
    Ok(())
}

/// Read the SE050 EXTENDED applet version — 37-byte VersionInfo
/// (major.minor.patch + applet feature config + secure-box version).
/// Anti-substitution identity check: the OEF / variant marker in this
/// response pins the chip to the ordered part (SE050E2 / OEF 0xA921 on
/// the OM-SE050ARD-E dev board). `CLA=0x80 INS=INS_MGMT P1=P1_DEFAULT
/// P2=P2_VERSION_EXT`, Case 2 (no command body, Le=0). The response is
/// `TAG_1`-wrapped; the raw-bytes fallback handles stacks that don't wrap.
pub unsafe fn get_version_ext(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    out: &mut [u8],
) -> Result<usize, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_VERSION_EXT);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 64];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    if let Some((_, value, _)) = tlv_parse(&resp[..n]) {
        let len = value.len().min(out.len());
        out[..len].copy_from_slice(&value[..len]);
        Ok(len)
    } else {
        let len = n.min(out.len());
        out[..len].copy_from_slice(&resp[..len]);
        Ok(len)
    }
}

/// Delete a single secure object from the SE050.
///
/// Returns `Ok` if the object doesn't exist (SW=0x6985 — empirically the
/// chip's "no such OID" response; not formally documented in AN12413
/// Table 125 page 71, which only enumerates `SW_NO_ERROR`, but
/// consistent across observed traffic and what NXP's own
/// `iterative_delete_all` accepts).
///
/// **S-7b fix:** SW=0x6986 (`kSE05x_SW12_COMMAND_NOT_ALLOWED` per NXP
/// plug-and-trust `se05x_enums.h:84`) means "access denied based on
/// object policy" — the object exists but the current session lacks
/// `ALLOW_DELETE` for it.  Pre-S-7b this was silently mapped to `Ok`,
/// masking real policy-denial bugs (e.g. an unauthenticated sweep
/// silently "succeeding" on objects that still exist on chip).  Now
/// it propagates as `Se050Error::Status(0x6986)`, so the caller (
/// `iterative_delete_all`, `admin_factory_reset`, etc.) sees the
/// distinction between "already gone" and "needs different auth".
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
        Err(Se050Error::Status(0x6985)) => Ok(()), // doesn't exist — idempotent
        // S-7b: 0x6986 is policy-denied → caller distinguishes "missing"
        // from "wrong auth".  Falls through to the generic Err arm.
        Err(e) => Err(e),
    }
}

/// Delete a UserID-gated secure object through an authenticated session.
///
/// Wraps the `DELETE_OBJECT` APDU inside an INS_PROCESS envelope with
/// `TAG_SESSION_ID` at the outer level (matching `read_authed` /
/// `verify_session`). Earlier ad-hoc implementations that sent
/// `INS=0x04 P2=0x28` with a top-level TAG_SESSION_ID were silently
/// ignoring the session and applying plain-SCP03 privileges → 0x6985/6986.
pub unsafe fn delete_object_authed(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    obj_id: u32,
) -> Result<(), Se050Error> {
    // Inner delete command: MGMT / DELETE_OBJECT / TAG_1(obj_id)
    let mut inner = [0u8; 32];
    inner[0] = 0x80;
    inner[1] = INS_MGMT;
    inner[2] = P1_DEFAULT;
    inner[3] = 0x28; // P2 = DELETE_OBJECT
    let mut io = 5;
    io = tlv_put_u32(&mut inner, io, TAG_1, obj_id);
    let inner_lc = io - 5;
    inner[4] = inner_lc as u8;

    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner[..io]);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp).map(|_| ())
}

/// `SetPlatformSCPRequest` inside a session opened with
/// [`PLATFORM_SCP_OBJ`] (#989, AN12413 §4.6.2): a persistent applet state.
///
/// Framing as [`delete_object_authed`]: the outer `INS_PROCESS` carries
/// `TAG_SESSION_ID` and is SCP03-wrapped by `send_apdu`; the inner command is
/// `80 04 00 52 03 41 01 <req>` (Case 3, no Le), as plug-and-trust's
/// `Se05x_API_SetPlatformSCPRequest` sends it over a UserID session. The
/// applet refuses it from any session not authenticated with
/// `RESERVED_ID_PLATFORM_SCP`.
#[cfg(any(
    feature = "se050-platform-scp-required",
    feature = "se050-platform-scp-tool",
    feature = "se050-stress"
))]
pub unsafe fn set_platform_scp_request(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: &[u8; 8],
    req: PlatformScpRequest,
) -> Result<(), Se050Error> {
    let inner: [u8; 8] = [0x80, INS_MGMT, P1_DEFAULT, P2_SCP, 0x03, TAG_1, 0x01, req as u8];

    let mut apdu = ApduBuf::new(0x80, INS_PROCESS, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv(TAG_SESSION_ID, session_id);
    apdu.tlv(TAG_1, &inner);
    let cmd = apdu.finish(false);

    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp).map(|_| ())
}

/// The same command with NO session (platform SCP03 only). Stress-only: the
/// negative test that the applet refuses it outside a
/// `RESERVED_ID_PLATFORM_SCP` session. Only `NotRequired` can be sent, so the
/// test is a no-op even if the chip wrongly accepted it.
#[cfg(feature = "se050-stress")]
pub unsafe fn set_platform_scp_request_no_session_stress(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
) -> Result<(), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_SCP);
    let cmd = apdu.tlv(TAG_1, &[PlatformScpRequest::NotRequired as u8]).finish(false);
    let mut resp = [0u8; 64];
    send_apdu(t1, scp03, cmd, &mut resp).map(|_| ())
}

/// The one plain applet APDU a production image sends (#989): a fixed
/// `CheckObjectExists(UNIQUE_ID 0x7FFF0206)`, after a fresh link bring-up and
/// before SCP03, to measure the platform-SCP requirement. The answer is
/// public (the unique-ID object exists on every SE050). Takes no caller bytes.
/// Returns the SW and up to 3 body bytes (`41 01 01` = exists).
#[cfg(any(
    feature = "se050-platform-scp-required",
    feature = "se050-platform-scp-tool",
    feature = "se050-probe",
    feature = "se050-stress"
))]
pub unsafe fn platform_scp_plain_probe(
    t1: &mut T1State,
) -> Result<(u16, [u8; 3], usize), Se050Error> {
    let apdu: [u8; 12] = [
        0x80, INS_MGMT, P1_DEFAULT, P2_EXIST, 0x06, TAG_1, 0x04, 0x7F, 0xFF, 0x02, 0x06, 0x00,
    ];
    let mut resp = [0u8; 16];
    let n = t1
        .transceive(&apdu, &mut resp)
        .map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    let mut body = [0u8; 3];
    let body_len = (n - 2).min(3);
    body[..body_len].copy_from_slice(&resp[..body_len]);
    Ok((sw, body, body_len))
}

/// What the 6B.23 stress test may send in plaintext to probe a carve-out
/// object's policy (#989). Stress-only; the OID must sit in the stress
/// carve-out (`0x7B5E_*`), checked at run time, so it cannot touch a
/// production object.
#[cfg(feature = "se050-stress")]
pub enum PlainMutateCmd<'a> {
    /// `WriteBinary(oid, offset 0, data)`.
    Write(u32, &'a [u8]),
    /// `DeleteSecureObject(oid)`.
    Delete(u32),
}

/// Send one [`PlainMutateCmd`] without SCP03. Returns the SW.
#[cfg(feature = "se050-stress")]
pub unsafe fn plain_mutate_stress(t1: &mut T1State, cmd: PlainMutateCmd<'_>) -> Result<u16, Se050Error> {
    let oid = match cmd {
        PlainMutateCmd::Write(oid, _) | PlainMutateCmd::Delete(oid) => oid,
    };
    if oid & 0xFFFF_0000 != 0x7B5E_0000 {
        return Err(Se050Error::InvalidParam);
    }
    let mut apdu = match cmd {
        PlainMutateCmd::Write(oid, data) => {
            let mut a = ApduBuf::new(0x80, INS_WRITE, P1_BINARY, P2_DEFAULT);
            a.tlv_u32(TAG_1, oid);
            a.tlv(TAG_2, &[0x00, 0x00]);
            a.tlv(TAG_4, data);
            a
        }
        PlainMutateCmd::Delete(oid) => {
            let mut a = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, 0x28);
            a.tlv_u32(TAG_1, oid);
            a
        }
    };
    let cmd = apdu.finish(false);
    let mut resp = [0u8; 64];
    let n = t1.transceive(cmd, &mut resp).map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    Ok(((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16))
}

/// P2 for ReadIDList (kSE05x_P2_LIST).
const P2_LIST: u8 = 0x25;

/// ReadIDList response TAG_1, `kSE05x_MoreIndicator_*` (NXP `se05x_enums.h`):
/// `0x01` is NO_MORE and `0x02` is MORE. Not a boolean. NXP's ReadIDList
/// prose (`se05x_APDU_apis.h`) says the applet signals more "by setting
/// TLV[TAG_1] to 0x01"; the enum, NXP's own DeleteAll loop
/// (`while (pmore == kSE05x_MoreIndicator_MORE)`) and silicon disagree — on
/// EVT-3D21 (2026-10-19) a complete 20-object list and an empty page past
/// its end both return `0x01`, and an empty page cannot mean "more".
pub const MORE_INDICATOR_NO_MORE: u8 = 0x01;
/// See [`MORE_INDICATOR_NO_MORE`].
pub const MORE_INDICATOR_MORE: u8 = 0x02;

/// P2 for ReadObjectAttributes (kSE05x_P2_ATTRIBUTES) — diagnostic.
const P2_ATTRIBUTES: u8 = 0x3B;

/// Read the on-chip policy attributes of a secure object. Useful for
/// debugging "why is delete refused?" questions — the response contains
/// the TAG_POLICY the object was created with.
pub unsafe fn read_object_attributes(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    buf: &mut [u8],
) -> Result<usize, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_ATTRIBUTES);
    apdu.tlv_u32(TAG_1, obj_id);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 256];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
        let take = val.len().min(buf.len());
        buf[..take].copy_from_slice(&val[..take]);
        return Ok(take);
    }
    let take = n.min(buf.len());
    buf[..take].copy_from_slice(&resp[..take]);
    Ok(take)
}

// ===========================================================================
// §6B read-only probe helpers (`se050-probe`, bench-only).
//
// Typed read-class commands used only by `se050::probe`. They live here, not
// in the probe module, because they legitimately go through `send_apdu`
// (SCP03) or `t1.transceive` (plain) — names the probe's read-only
// `source_invariants` pin forbids inside the probe files. Each one is
// read-class (GetVersion, ReadIDList, ReadType, ReadSize, GetFreeMemory, a
// plain object read) and never creates, writes, deletes or authenticates an
// object. AN12413 §4 / NXP `se05x_enums.h` P2 codes.
// ===========================================================================

/// `kSE05x_P2_SIZE`.
#[cfg(feature = "se050-probe")]
const P2_SIZE: u8 = 0x07;
/// `kSE05x_P2_MEMORY` — GetFreeMemory.
#[cfg(feature = "se050-probe")]
const P2_MEMORY: u8 = 0x22;
/// `kSE05x_P2_TYPE`.
#[cfg(feature = "se050-probe")]
const P2_TYPE: u8 = 0x26;

/// Memory kinds for `get_free_memory_probe` (`kSE05x_MemoryType_*`).
#[cfg(feature = "se050-probe")]
pub const MEM_PERSISTENT: u8 = 0x01;
#[cfg(feature = "se050-probe")]
pub const MEM_TRANSIENT_RESET: u8 = 0x02;
#[cfg(feature = "se050-probe")]
pub const MEM_TRANSIENT_DESELECT: u8 = 0x03;

/// The reserved applet object that holds the 18-byte device unique ID
/// (`kSE05x_AppletResID_UNIQUE_ID`).
#[cfg(any(feature = "se050-probe", feature = "se050-platform-scp-tool"))]
pub const UNIQUE_ID_OBJ: u32 = 0x7FFF_0206;

/// One page of `ReadIDList` over SCP03. Writes up to `ids.len()` object IDs
/// into `ids` and returns `(more, listed, copied)`: `more` is the raw
/// `MORE_INDICATOR_*` byte, `listed` is how many IDs
/// the chip put on this page, `copied` how many fit in `ids`. A page with
/// `copied < listed` was truncated and the caller must say so. `offset` is a
/// 0-based index into the object list, NOT a byte offset: start at 0 and add
/// each page's `listed` (NXP `se05x_APDU_apis.h`, `Se05x_API_ReadIDList`).
/// Read-only (INS_READ / P2_LIST).
#[cfg(feature = "se050-probe")]
pub unsafe fn read_id_list_probe(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    offset: u16,
    ids: &mut [u32],
) -> Result<(u8, usize, usize), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_LIST);
    apdu.tlv(TAG_1, &offset.to_be_bytes());
    apdu.tlv(TAG_2, &[0xFF]);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 1024];
    let resp_len = send_apdu(t1, scp03, cmd, &mut resp)?;

    // TAG_1(more:1) + TAG_2(id_list: N*4), BER lengths (0x81/0x82 prefixes).
    let mut more = 0u8;
    let mut list_start = 0usize;
    let mut list_len = 0usize;
    let mut idx = 0usize;
    while idx + 1 < resp_len {
        let tag = resp[idx];
        idx += 1;
        let len_byte = resp[idx];
        idx += 1;
        let len: usize = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x81 && idx < resp_len {
            let l = resp[idx] as usize;
            idx += 1;
            l
        } else if len_byte == 0x82 && idx + 1 < resp_len {
            let l = ((resp[idx] as usize) << 8) | (resp[idx + 1] as usize);
            idx += 2;
            l
        } else {
            break;
        };
        if tag == TAG_1 && len == 1 && idx < resp_len {
            more = resp[idx];
        } else if tag == TAG_2 {
            list_start = idx;
            list_len = len;
        }
        idx = idx.saturating_add(len);
    }

    let list_end = list_start.saturating_add(list_len).min(resp_len);
    let listed = list_end.saturating_sub(list_start) / 4;
    let mut n = 0usize;
    let mut i = list_start;
    while i + 3 < list_end && n < ids.len() {
        ids[n] = ((resp[i] as u32) << 24)
            | ((resp[i + 1] as u32) << 16)
            | ((resp[i + 2] as u32) << 8)
            | (resp[i + 3] as u32);
        n += 1;
        i += 4;
    }
    Ok((more, listed, n))
}

/// `ReadType` of an object (INS_READ / P2_TYPE). Copies the raw response
/// (object type byte + transient indicator) into `out`.
#[cfg(feature = "se050-probe")]
pub unsafe fn read_object_type_probe(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    out: &mut [u8],
) -> Result<usize, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_TYPE);
    apdu.tlv_u32(TAG_1, obj_id);
    let cmd = apdu.finish(true);
    let mut resp = [0u8; 64];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
        let take = val.len().min(out.len());
        out[..take].copy_from_slice(&val[..take]);
        return Ok(take);
    }
    let take = n.min(out.len());
    out[..take].copy_from_slice(&resp[..take]);
    Ok(take)
}

/// `ReadSize` of an object (INS_READ / P2_SIZE). Returns the u16 size.
#[cfg(feature = "se050-probe")]
pub unsafe fn read_object_size_probe(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
) -> Result<u16, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_SIZE);
    apdu.tlv_u32(TAG_1, obj_id);
    let cmd = apdu.finish(true);
    let mut resp = [0u8; 64];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    let val = tlv_parse(&resp[..n]).map(|(_, v, _)| v).unwrap_or(&resp[..n]);
    if val.len() >= 2 {
        Ok(((val[val.len() - 2] as u16) << 8) | (val[val.len() - 1] as u16))
    } else if val.len() == 1 {
        Ok(val[0] as u16)
    } else {
        Ok(0)
    }
}

/// `GetFreeMemory` (INS_MGMT / P2_MEMORY). `mem_type` is one of the
/// `MEM_*` kinds. Returns the u16 free-byte count. Read-only.
#[cfg(feature = "se050-probe")]
pub unsafe fn get_free_memory_probe(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    mem_type: u8,
) -> Result<u16, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_MEMORY);
    apdu.tlv(TAG_1, &[mem_type]);
    let cmd = apdu.finish(true);
    let mut resp = [0u8; 64];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    let val = tlv_parse(&resp[..n]).map(|(_, v, _)| v).unwrap_or(&resp[..n]);
    if val.len() >= 2 {
        Ok(((val[0] as u16) << 8) | (val[1] as u16))
    } else {
        Ok(0)
    }
}

/// Read an object over platform SCP03 with no UserID session (INS_READ /
/// P2_DEFAULT, Le). Copies the data into `out`. The probe uses it for the
/// unique-ID object (6B.2). Read-only.
#[cfg(any(feature = "se050-probe", feature = "se050-platform-scp-tool"))]
pub unsafe fn read_object_scp03_probe(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    obj_id: u32,
    out: &mut [u8],
) -> Result<usize, Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_DEFAULT);
    apdu.tlv_u32(TAG_1, obj_id);
    let cmd = apdu.finish(true);
    let mut resp = [0u8; 256];
    let n = send_apdu(t1, scp03, cmd, &mut resp)?;
    if let Some((_, val, _)) = tlv_parse(&resp[..n]) {
        let take = val.len().min(out.len());
        out[..take].copy_from_slice(&val[..take]);
        return Ok(take);
    }
    let take = n.min(out.len());
    out[..take].copy_from_slice(&resp[..take]);
    Ok(take)
}

/// The only commands [`plain_readclass_probe`] can send. Each variant maps to
/// one fixed read-class header inside the helper; no variant writes, deletes
/// or authenticates. (A raw `ins/p1/p2` interface would not be read-only:
/// `INS_MGMT` also carries DeleteAll, and the probe file's name-based pin
/// cannot see header bytes.)
#[cfg(any(feature = "se050-probe", feature = "se050-stress"))]
#[derive(Clone, Copy)]
pub enum PlainReadCmd {
    /// GetVersionExt (INS_MGMT / P2_VERSION_EXT), Case 2.
    GetVersionExt,
    /// GetRandom of `n` bytes (INS_MGMT / P2_RANDOM).
    GetRandom(u16),
    /// ReadIDList from index 0, all types (INS_READ / P2_LIST).
    ReadIdList,
    /// CheckObjectExists (INS_MGMT / P2_EXIST).
    CheckExists(u32),
    /// Read of one object (INS_READ / P2_DEFAULT).
    Read(u32),
}

/// Send one read-class APDU **without SCP03** (plaintext on the wire), for the
/// §6B.6 "is platform SCP mandatory?" matrix. Drives `t1.transceive` directly,
/// so it never goes through the `send_apdu` SCP03 guard. Returns the raw SW and
/// copies any response data (minus SW) into `out`.
///
/// Read-class only by construction: the header and body come from
/// [`PlainReadCmd`], so a caller cannot name a write, delete or auth command.
#[cfg(any(feature = "se050-probe", feature = "se050-stress"))]
pub unsafe fn plain_readclass_probe(
    t1: &mut T1State,
    cmd: PlainReadCmd,
    out: &mut [u8],
) -> Result<(u16, usize), Se050Error> {
    let mut body_buf = [0u8; 7];
    let (ins, p2, body_len) = match cmd {
        PlainReadCmd::GetVersionExt => (INS_MGMT, P2_VERSION_EXT, 0),
        PlainReadCmd::GetRandom(n) => {
            body_buf[..2].copy_from_slice(&[TAG_1, 0x02]);
            body_buf[2..4].copy_from_slice(&n.to_be_bytes());
            (INS_MGMT, P2_RANDOM, 4)
        }
        PlainReadCmd::ReadIdList => {
            body_buf.copy_from_slice(&[TAG_1, 0x02, 0x00, 0x00, TAG_2, 0x01, 0xFF]);
            (INS_READ, P2_LIST, 7)
        }
        PlainReadCmd::CheckExists(obj_id) => {
            body_buf[..2].copy_from_slice(&[TAG_1, 0x04]);
            body_buf[2..6].copy_from_slice(&obj_id.to_be_bytes());
            (INS_MGMT, P2_EXIST, 6)
        }
        PlainReadCmd::Read(obj_id) => {
            body_buf[..2].copy_from_slice(&[TAG_1, 0x04]);
            body_buf[2..6].copy_from_slice(&obj_id.to_be_bytes());
            (INS_READ, P2_DEFAULT, 6)
        }
    };
    let body = &body_buf[..body_len];

    let mut apdu = [0u8; 16];
    apdu[0] = 0x80;
    apdu[1] = ins;
    apdu[2] = P1_DEFAULT;
    apdu[3] = p2;
    let total;
    if body.is_empty() {
        apdu[4] = 0x00; // Le only (Case 2)
        total = 5;
    } else {
        apdu[4] = body.len() as u8;
        apdu[5..5 + body.len()].copy_from_slice(body);
        apdu[5 + body.len()] = 0x00; // Le
        total = 6 + body.len();
    }
    let mut resp = [0u8; 256];
    let n = t1
        .transceive(&apdu[..total], &mut resp)
        .map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    let data_len = (n - 2).min(out.len());
    out[..data_len].copy_from_slice(&resp[..data_len]);
    Ok((sw, data_len))
}

/// The applet SELECT, for the §6B.6 pre-session leg: the same fixed
/// `SELECT BY NAME (SE050_AID)` [`select_applet`] sends, but returning the SW
/// and the response data instead of failing on a non-`9000` SW, so the probe
/// can record what a keyless bus party gets back. Takes no header or AID from
/// the caller. SELECT is plain by design (it precedes SCP03 in every
/// session), so this exposes nothing `select_applet` does not.
#[cfg(any(feature = "se050-probe", feature = "se050-stress", feature = "se050-platform-scp-tool"))]
pub unsafe fn select_applet_probe(
    t1: &mut T1State,
    out: &mut [u8],
) -> Result<(u16, usize), Se050Error> {
    let mut apdu = [0u8; 64];
    apdu[0] = 0x00; // CLA
    apdu[1] = 0xA4; // INS = SELECT
    apdu[2] = 0x04; // P1 = select by name
    apdu[3] = 0x00; // P2
    apdu[4] = SE050_AID.len() as u8; // Lc
    apdu[5..5 + SE050_AID.len()].copy_from_slice(SE050_AID);
    let total = 5 + SE050_AID.len();

    let mut resp = [0u8; 256];
    let n = t1
        .transceive(&apdu[..total], &mut resp)
        .map_err(|_| Se050Error::Transport)?;
    if n < 2 {
        return Err(Se050Error::Transport);
    }
    let sw = ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16);
    let data_len = (n - 2).min(out.len());
    out[..data_len].copy_from_slice(&resp[..data_len]);
    Ok((sw, data_len))
}

/// Iteratively delete every user-created object on the SE050, mirroring
/// the NXP SDK's `Se05x_API_DeleteAll_Iterative`.
///
/// Two-pass: first tries plain SCP03 delete (handles default-policy
/// objects), then if `auth_obj_id`/`userid_value` are provided, creates a UserID
/// session and retries through `delete_object_authed`. Self-deletes
/// the UserID object at the end.
///
/// Skips reserved ranges (0x7FFFxxxx applet-reserved, 0x7DA0xxxx demo
/// auth, 0xF000_0000+ IoT Hub trust-provisioned).
///
/// Returns `(deleted, remaining_failed, auth_ok)`. `auth_ok` is true when
/// the unauthenticated pass cleaned everything OR the PIN authenticated
/// against the UserID; false when auth was attempted (or required) and
/// did not succeed. Lets the caller distinguish "wrong PIN" from
/// "objects survived authenticated delete (policy-blocked)".
pub unsafe fn iterative_delete_all(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    auth_obj_id: Option<u32>,
    userid_value: Option<UserIdValue<'_>>,
) -> Result<(u16, u16, bool), Se050Error> {
    #[cfg(feature = "debug-log")]
    secure_log!("[SE050][erase] Pass 1: unauthenticated");

    let (mut deleted, mut failed) = sweep(t1, scp03, None)?;

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[SE050][erase] Pass 1 done: {} deleted, {} left",
        deleted,
        failed
    );

    if failed == 0 {
        return Ok((deleted, 0, true));
    }

    let (uid, value_bytes) = match (auth_obj_id, userid_value) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok((deleted, failed, false)),
    };

    if !check_exists(t1, scp03, uid).unwrap_or(false) {
        return Ok((deleted, failed, false));
    }

    let session_id = match create_session(t1, scp03, uid) {
        Ok(s) => s,
        Err(_) => return Ok((deleted, failed, false)),
    };

    if verify_session(t1, scp03, &session_id, value_bytes).is_err() {
        let _ = close_session(t1, scp03, &session_id);
        return Ok((deleted, failed, false));
    }

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[SE050][erase] Pass 2: authenticated (UserID=0x{:08x})",
        uid
    );

    let (auth_del, auth_fail) = sweep(t1, scp03, Some(&session_id))?;
    deleted += auth_del;
    failed = auth_fail;

    // Self-delete the UserID. Requires the UserID to have been created
    // with the self-deletable policy (see `write_userid`). Older UserIDs
    // without the policy stay put.
    if delete_object_authed(t1, scp03, &session_id, uid).is_ok()
        && !check_exists(t1, scp03, uid).unwrap_or(true)
    {
        deleted += 1;
    }

    let _ = close_session(t1, scp03, &session_id);
    Ok((deleted, failed, true))
}

/// Hard cap on ReadIDList pages per sweep cycle. The SE050 holds at most a few
/// hundred objects and an honest chip terminates the page walk with
/// `MORE_INDICATOR_NO_MORE` after a handful of pages (each page carries up to
/// ~256 4-byte IDs), so 64 is unreachable on real hardware. Without it the
/// inner loop's only exit is the chip-controlled `more`/`list_byte_len`
/// fields, so a glitching or hostile SE could hold `MORE_INDICATOR_MORE`
/// forever and hang the wipe. Same uncapped-
/// peripheral-loop class already bounded in `t1oi2c` (`MAX_RESP_FRAMES`) and
/// `ifx_i2c` (`MAX_RX_FRAMES`).
const MAX_LIST_PAGES: usize = 64;

unsafe fn sweep(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    session_id: Option<&[u8; 8]>,
) -> Result<(u16, u16), Se050Error> {
    let mut total_deleted = 0u16;
    let mut last_failed = 0u16;

    for _ in 0..10 {
        let mut cycle_deleted = 0u16;
        let mut cycle_failed = 0u16;
        let mut output_offset: u16 = 0;

        for _ in 0..MAX_LIST_PAGES {
            let (more, list_byte_len, d, f) =
                delete_id_list_page(t1, scp03, output_offset, session_id)?;
            // Saturating: `d`/`f` are diagnostic counts; on a hostile SE they
            // could otherwise overflow the u16 accumulator (~256 IDs/page ×
            // MAX_LIST_PAGES) and panic under `overflow-checks = true`.
            cycle_deleted = cycle_deleted.saturating_add(d);
            cycle_failed = cycle_failed.saturating_add(f);
            // TAG_1 is a 0-based index into the object list, so advance by
            // the number of IDs on this page, not their byte length (NXP
            // `se05x_APDU_apis.h`, `Se05x_API_ReadIDList`; confirmed on
            // silicon by probe row 6B.3b; NXP's own
            // `Se05x_API_DeleteAll_Iterative` sample passes bytes, against its
            // doc). Deletions inside the page shift later IDs down, so this
            // page walk can still skip some; the outer cycle restarts at 0 and
            // only stops after a cycle that deleted nothing, i.e. shifted
            // nothing, which with index paging and an honest MORE indicator
            // has seen every object. That holds only for an exit through
            // "a cycle deleted nothing": if the 10-cycle or MAX_LIST_PAGES cap
            // ends the walk, objects never attempted appear in neither
            // `deleted` nor `failed`.
            output_offset = output_offset.saturating_add((list_byte_len / 4) as u16);
            // Page on only while the chip says MORE (0x02). This read
            // `more != 0x01` until 2026-10-19, i.e. it paged on NO_MORE (one
            // wasted, empty request) and stopped on MORE: a list longer than
            // one page was never walked past page 1, so a cycle whose first
            // page held only skipped objects deleted nothing and ended the
            // wipe with deletable objects left on later pages.
            if more != MORE_INDICATOR_MORE || list_byte_len == 0 {
                break;
            }
        }

        total_deleted = total_deleted.saturating_add(cycle_deleted);
        last_failed = cycle_failed;
        if cycle_deleted == 0 {
            break;
        }
    }

    Ok((total_deleted, last_failed))
}

unsafe fn delete_id_list_page(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    output_offset: u16,
    session_id: Option<&[u8; 8]>,
) -> Result<(u8, usize, u16, u16), Se050Error> {
    let mut apdu = ApduBuf::new(0x80, INS_READ, P1_DEFAULT, P2_LIST);
    apdu.tlv(TAG_1, &output_offset.to_be_bytes());
    apdu.tlv(TAG_2, &[0xFF]);
    let cmd = apdu.finish(true);

    let mut resp = [0u8; 1024];
    let resp_len = send_apdu(t1, scp03, cmd, &mut resp)?;
    if resp_len < 3 {
        return Ok((0x00, 0, 0, 0));
    }

    // BER-TLV: TAG_1(more_indicator, 1B) + TAG_2(id_list, N*4 bytes).
    // ID list can exceed 127 bytes so 0x82-prefixed lengths are required.
    let mut more = 0u8;
    let mut list_start = 0usize;
    let mut list_len = 0usize;

    let mut idx = 0;
    while idx + 1 < resp_len {
        let tag = resp[idx];
        idx += 1;
        let len_byte = resp[idx];
        idx += 1;
        let len: usize = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x81 && idx < resp_len {
            let l = resp[idx] as usize;
            idx += 1;
            l
        } else if len_byte == 0x82 && idx + 1 < resp_len {
            let l = ((resp[idx] as usize) << 8) | (resp[idx + 1] as usize);
            idx += 2;
            l
        } else {
            break;
        };
        if tag == TAG_1 && len == 1 && idx < resp_len {
            more = resp[idx];
        } else if tag == TAG_2 {
            list_start = idx;
            list_len = len;
        }
        idx = idx.saturating_add(len);
    }

    let mut deleted = 0u16;
    let mut failed = 0u16;
    let list_end = list_start.saturating_add(list_len).min(resp_len);
    let mut i = list_start;
    while i + 3 < list_end {
        let id = ((resp[i] as u32) << 24)
            | ((resp[i + 1] as u32) << 16)
            | ((resp[i + 2] as u32) << 8)
            | (resp[i + 3] as u32);
        i += 4;

        if id == 0
            || (id & 0xFFFF_0000) == 0x7FFF_0000
            || (id & 0xFFF0_0000) == 0x7DA0_0000
            || id >= 0xF000_0000
        {
            continue;
        }

        let result = match session_id {
            Some(sid) => delete_object_authed(t1, scp03, sid, id),
            None => delete_object(t1, scp03, id),
        };

        match result {
            Ok(()) => {
                if check_exists(t1, scp03, id).unwrap_or(false) {
                    failed += 1;
                } else {
                    deleted += 1;
                    #[cfg(feature = "debug-log")]
                    secure_log!("[SE050][erase]   0x{:08x} deleted", id);
                }
            }
            Err(_e) => {
                failed += 1;
                #[cfg(feature = "debug-log")]
                secure_log!("[SE050][erase]   0x{:08x} FAILED: {:?}", id, _e);
            }
        }
    }

    Ok((more, list_len, deleted, failed))
}

/// Per-`GetRandom`-APDU request ceiling over the SCP03 secure channel.
///
/// **Silicon limit (B-U585I-IOT02A, 2026-05-28).** A single `GetRandom`
/// over SCP03 succeeds up to **224 bytes** and is rejected with
/// SW=0x6985 at **240 bytes** (empirically bracketed by the
/// `get_random_size_boundary` stress probe: 16/32/48/64/96/128/160/
/// 192/224 OK, 240/256 FAIL). The cause is the encrypted response
/// frame: `TLV(TAG_1,N) + SW`, R-ENC-padded to a 16-byte multiple plus
/// the 8-byte R-MAC, must fit the SE050's ~256-byte secure-response
/// frame — which 224 does (≈248 B on the wire) and 240 does not
/// (≈264 B). The NXP plug-and-trust SDK has the same caveat as a TODO
/// (`fsl_sss_se05x_apis.c` — "Replace 512 with max rsp buffer size
/// based on with/without SCP") and resolves it by chunking; we do the
/// same. 128 is chosen as a clean, comfortably-safe chunk below 224.
const GET_RANDOM_MAX_CHUNK: usize = 128;

/// Advance the sole SE050 response cursor only after an exact authenticated
/// response copy.  A stale loop offset cannot be promoted because both passes
/// bind it to the canonical volatile completion record and to the exact
/// `min(128, remaining)` response shape.
#[inline(never)]
fn publish_verified_get_random_progress_into(
    completed_bytes: &mut usize,
    current: usize,
    copied: usize,
    total: usize,
    progress_receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::FAIL_SENTINEL);
    }

    let completed_a = unsafe { core::ptr::read_volatile(completed_bytes) };
    let current_a = unsafe { core::ptr::read_volatile(&current) };
    let copied_a = unsafe { core::ptr::read_volatile(&copied) };
    let total_a = unsafe { core::ptr::read_volatile(&total) };
    if completed_a != current_a || current_a >= total_a {
        return;
    }
    let expected_a = core::cmp::min(GET_RANDOM_MAX_CHUNK, total_a - current_a);
    if copied_a != expected_a {
        return;
    }
    let next_a = match current_a.checked_add(copied_a) {
        Some(next) if next <= total_a => next,
        _ => return,
    };

    crate::fi::wait_random();

    let completed_b = unsafe { core::ptr::read_volatile(completed_bytes) };
    let current_b = unsafe { core::ptr::read_volatile(&current) };
    let copied_b = unsafe { core::ptr::read_volatile(&copied) };
    let total_b = unsafe { core::ptr::read_volatile(&total) };
    if completed_b != current_b || current_b >= total_b {
        return;
    }
    let expected_b = core::cmp::min(GET_RANDOM_MAX_CHUNK, total_b - current_b);
    if copied_b != expected_b {
        return;
    }
    let next_b = match current_b.checked_add(copied_b) {
        Some(next) if next <= total_b => next,
        _ => return,
    };
    if next_b != next_a {
        return;
    }

    unsafe {
        core::ptr::write_volatile(completed_bytes, next_a);
        core::ptr::write_volatile(completed_bytes, next_b);
    }
    if unsafe { core::ptr::read_volatile(completed_bytes) } != next_a {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(completed_bytes) } != next_b {
        return;
    }
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::OK_SENTINEL);
    }
}

/// `Se05x_API_GetRandom` (NXP AN12413 §5.13.1) — fill `out` with bytes
/// from the SE050 hardware TRNG over the established SCP03 channel.
///
/// Requests larger than [`GET_RANDOM_MAX_CHUNK`] are split across
/// multiple `GetRandom` APDUs (the SE050 rejects an oversized single
/// request over SCP03 — see that constant). This mirrors the NXP SDK's
/// `sss_se05x_rng_get_random` chunking loop, so any `out.len()` is
/// accepted. Each APDU's response is `TLV(TAG_1, random_bytes)`.
///
/// The XOR-mix layer (`hw::rng_strong`) is what makes this strong:
/// even if the SE050 TRNG is biased / compromised, the XOR with the
/// STM32 TRNG and OPTIGA TRNG preserves entropy from the remaining
/// sources. We never trust a single SE-TRNG output blindly.
pub unsafe fn get_random(
    t1: &mut T1State,
    scp03: &mut Scp03Session,
    out: &mut [u8],
) -> Result<usize, Se050Error> {
    if out.is_empty() {
        return Err(Se050Error::InvalidParam);
    }

    let mut completed_bytes = usize::MAX;
    let mut progress_init_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut progress_init_receipt, crate::fi::FAIL_SENTINEL);
    }
    crate::rng_exact::initialize_exact_progress_into(
        &mut completed_bytes,
        &mut progress_init_receipt,
    );
    if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
        out.fill(0);
        crate::fi::zeroize_barrier();
        return Err(Se050Error::Transport);
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
        out.fill(0);
        crate::fi::zeroize_barrier();
        return Err(Se050Error::Transport);
    }
    loop {
        let filled = unsafe { core::ptr::read_volatile(&completed_bytes) };
        if filled >= out.len() {
            break;
        }
        let chunk = (out.len() - filled).min(GET_RANDOM_MAX_CHUNK);

        let mut apdu = ApduBuf::new(0x80, INS_MGMT, P1_DEFAULT, P2_RANDOM);
        let size = chunk as u16;
        apdu.tlv(TAG_1, &size.to_be_bytes());
        let cmd = apdu.finish(true);

        let mut resp = [0u8; 320];
        let n = send_apdu(t1, scp03, cmd, &mut resp)?;
        let (tag, value, rest) = tlv_parse(&resp[..n]).ok_or(Se050Error::Transport)?;
        // A caller-owned receipt remains failed if this verifier call is
        // omitted. The out-of-line verifier observes both predicates twice,
        // so skipping one optimized tag/trailing-data rejection cannot accept
        // a substituted hardware-RNG response.
        let mut frame_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut frame_receipt, crate::fi::FAIL_SENTINEL);
        }
        crate::rng_exact::verify_exact_pair_into(
            tag as usize,
            TAG_1 as usize,
            rest.len(),
            0,
            &mut frame_receipt,
        );
        if unsafe { core::ptr::read_volatile(&frame_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&frame_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        // Bind the parser's value pointer to the authenticated response
        // buffer independently of the parser result register. With an exact
        // value length and empty `rest`, the value must occupy the final
        // `chunk` bytes of `resp[..n]`. A stale command-buffer pointer can be
        // valid and non-overlapping, but it cannot satisfy this provenance.
        let expected_value_offset = match n.checked_sub(chunk) {
            Some(offset) => offset,
            None => {
                out.fill(0);
                crate::fi::zeroize_barrier();
                return Err(Se050Error::Transport);
            }
        };
        let expected_value_pointer = unsafe { resp.as_ptr().add(expected_value_offset) };
        let mut published_expected_source = core::ptr::null();
        let mut source_publication_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            expected_value_pointer,
            &mut published_expected_source,
            &mut source_publication_receipt,
        );
        if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }

        // GetRandom has an exact response contract. A short response would
        // leave stale caller bytes; an overlong authenticated TLV indicates
        // command/response desynchronization and must not be truncated.
        let mut copy_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut copy_receipt, crate::fi::FAIL_SENTINEL);
        }
        let mut published_destination = core::ptr::null();
        let mut destination_publication_receipt = crate::fi::FAIL_SENTINEL;
        crate::rng_exact::publish_region_pointer_into(
            unsafe { out.as_ptr().add(filled) },
            &mut published_destination,
            &mut destination_publication_receipt,
        );
        if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
            != crate::fi::OK_SENTINEL
        {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::rng_exact::copy_exact_into(
            value.as_ptr(),
            core::ptr::addr_of!(published_expected_source),
            value.len(),
            out.as_mut_ptr(),
            filled,
            core::ptr::addr_of!(published_destination),
            chunk,
            &mut copy_receipt,
        );
        if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }

        let mut progress_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut progress_receipt, crate::fi::FAIL_SENTINEL);
        }
        publish_verified_get_random_progress_into(
            &mut completed_bytes,
            filled,
            chunk,
            out.len(),
            &mut progress_receipt,
        );
        if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
            out.fill(0);
            crate::fi::zeroize_barrier();
            return Err(Se050Error::Transport);
        }
    }

    let mut completion_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut completion_receipt, crate::fi::FAIL_SENTINEL);
    }
    crate::rng_exact::verify_exact_progress_into(
        &completed_bytes,
        out.len(),
        &mut completion_receipt,
    );
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        out.fill(0);
        crate::fi::zeroize_barrier();
        return Err(Se050Error::Transport);
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
        out.fill(0);
        crate::fi::zeroize_barrier();
        return Err(Se050Error::Transport);
    }
    Ok(out.len())
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
