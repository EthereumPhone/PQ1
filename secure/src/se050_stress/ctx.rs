//! `StressCtx` — the API stress tests are written against.
//!
//! Wraps the live `Se050` driver with helpers for:
//! - Computing scratch OIDs in this test's reserved sub-range.
//! - Writing/reading/deleting scratch data objects (admin-gated, so
//!   they're reclaimable on test failure).
//! - Provisioning test UserIDs and opening user / admin sessions.
//! - Asserting equality, status words, and conditions in a way that
//!   produces structured `StressError` values the runner can log.
//! - Iteration tracking so "fails on iter 47/256" is recoverable.
//! - Typed wrappers around the unsafe `apdu::*` helpers so tests stay
//!   readable and the split-borrow on `Se050.{t1,scp03}` is funneled
//!   through one place.
//!
//! **Adding a helper is a forward-compatible change.** Existing tests
//! ignore methods they don't call; new methods slot in here.

use crate::se050::Se050;
use crate::se050::apdu::{self, Se050Error};
use crate::se050::scp03::Scp03Session;
use crate::se050::t1oi2c::T1State;

use super::oid;
use super::{StressError, StressResult};

pub type SessionId = [u8; 8];

/// Two-entry policy selector for `provision_test_userid`.
///
/// `WithAdminDelete` — gate the UserID with the standard two-entry
/// policy (self + stress-admin DELETE). Lets the runner clean up a
/// crashed test via admin auth.
///
/// `WithoutAdminEntry` — emit ONLY the self-policy entry (no admin
/// fallback). Used by `audit::userid_no_admin_delete` to prove the
/// S-6 fix: a UserID created without an admin entry cannot be
/// admin-deleted.
#[derive(Clone, Copy)]
pub enum AdminPolicy {
    WithAdminDelete,
    WithoutAdminEntry,
}

pub struct StressCtx<'a> {
    se: &'a mut Se050,
    test_id: u16,
    iter: u32,
}

impl<'a> StressCtx<'a> {
    pub fn new(se: &'a mut Se050, test_id: u16) -> Self {
        Self { se, test_id, iter: 0 }
    }

    // -------- OID layout --------

    /// OID for slot `slot` of this test's sub-range
    /// (= `0x7B5E_<test_id><slot>`).
    #[inline]
    pub fn oid(&self, slot: u8) -> u32 {
        oid::scratch_oid(self.test_id, slot)
    }

    // -------- Scratch object I/O (admin-gated for clean teardown) --------

    /// Write a binary object at `target`, gated solely by stress-admin
    /// auth. Reads/writes go through the admin session in
    /// `read_scratch` / `delete_scratch`, so the runner always has a
    /// path to clean up even if a test panics.
    pub fn write_scratch(&mut self, target: u32, data: &[u8]) -> StressResult {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_binary_gated(
                t1, scp03, target, data, oid::STRESS_ADMIN_USERID, None,
            )?;
        }
        Ok(())
    }

    /// Read a previously-written scratch object via admin auth.
    /// Returns the number of bytes written into `out`.
    pub fn read_scratch(&mut self, target: u32, out: &mut [u8]) -> Result<usize, StressError> {
        let pin = self.admin_pin()?;
        unsafe {
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, oid::STRESS_ADMIN_USERID)?
            };
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if let Err(e) = apdu::verify_session(t1, scp03, &sid, apdu::UserIdValue::Bench(&pin)) {
                    let _ = apdu::close_session(t1, scp03, &sid);
                    return Err(e.into());
                }
            }
            let n = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::read_authed(t1, scp03, &sid, target, out)?
            };
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, &sid);
            Ok(n)
        }
    }

    /// Delete a scratch object via admin auth. Idempotent (missing OID
    /// is a no-op).
    ///
    /// **A3 robustness (2026-05-28).** A leftover at `target` may be a
    /// UserID with no admin-delete policy entry (stranded by a prior
    /// `WithoutAdminEntry` provisioning that crashed before its own
    /// user-PIN self-delete). In that case `delete_object_authed`
    /// returns SW=0x6986 and the subsequent close leaves the chip in
    /// the Finding-A3 session-pending state, which would poison the
    /// caller's next op. We swallow the admin-delete error for
    /// idempotency BUT `reinit()` afterwards so the chip is clean.
    ///
    /// Note: such a no-admin UserID is NOT removable by this helper —
    /// a transport `write_userid` UPDATE is *refused and preserves* the
    /// object (Finding A2 is retracted; there is no destroy-on-failed-
    /// UPDATE — see `docs/secure-elements/se050-silicon-findings.md` §3). The only
    /// cures are the UserID's own user-PIN self-delete or a carve-out
    /// OID-range bump; `oid::STRESS_BASE` was bumped `0x7B5F → 0x7B5E`
    /// for exactly this reason. `delete_scratch` therefore only
    /// guarantees the chip is left in a clean (non-pending) state, not
    /// that an un-admin-deletable leftover is gone.
    pub fn delete_scratch(&mut self, target: u32) -> StressResult {
        let pin = self.admin_pin()?;
        let mut needs_reinit = false;
        unsafe {
            let present = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::check_exists(t1, scp03, target).unwrap_or(false)
            };
            if !present {
                return Ok(());
            }
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, oid::STRESS_ADMIN_USERID)?
            };
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if apdu::verify_session(t1, scp03, &sid, apdu::UserIdValue::Bench(&pin)).is_err() {
                    let _ = apdu::close_session(t1, scp03, &sid);
                    // Verify failure on the admin session itself leaves
                    // the chip session-pending — flush it.
                    let _ = self.se.reinit();
                    return Ok(());
                }
            }
            {
                let (t1, scp03) = self.se.t1_scp03_mut();
                if apdu::delete_object_authed(t1, scp03, &sid, target).is_err() {
                    // Most likely a no-admin-policy UserID (0x6986).
                    // The failed delete + close leaves session-pending.
                    needs_reinit = true;
                }
            }
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, &sid);
        }
        if needs_reinit {
            let _ = self.se.reinit();
        }
        Ok(())
    }

    // -------- UserID provisioning + sessions --------

    /// Provision a test UserID. `max_attempts ∈ 1..=255`. `policy`
    /// chooses whether to attach the stress-admin delete entry.
    pub fn provision_test_userid(
        &mut self,
        target: u32,
        pin: &[u8],
        max_attempts: u16,
        policy: AdminPolicy,
    ) -> StressResult {
        let admin_entry = match policy {
            AdminPolicy::WithAdminDelete => Some(oid::STRESS_ADMIN_USERID),
            AdminPolicy::WithoutAdminEntry => None,
        };
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_userid(t1, scp03, target, apdu::UserIdValue::Bench(pin), max_attempts, admin_entry)?;
        }
        Ok(())
    }

    /// Open + verify a session against `userid_oid`.
    ///
    /// **Finding A3 mitigation (2026-05-28).** After any failed verify
    /// (`PinIncorrect`, `AuthMethodBlocked`, or any `Status(sw)`), the
    /// chip can be left in a "session-pending" state: subsequent
    /// non-session APDUs (`check_exists`, `read_object_attributes`,
    /// even a fresh `create_session`) return SW=0x6982 until a
    /// successful close — or, observed reliably on B-U585I-IOT02A, a
    /// full SCP03 re-init. To keep the chip clean for the next probe,
    /// this helper calls `Se050::reinit()` whenever the verify leg
    /// fails, *after* the best-effort close. Cost is ~one SCP03
    /// handshake (~100-300 ms on silicon, ~ms on QEMU). See
    /// `docs/secure-elements/se050-silicon-findings.md` §4 (raw evidence
    /// `b88gzpjod.output:1275-1281`).
    pub fn open_user_session(
        &mut self,
        userid_oid: u32,
        pin: &[u8],
    ) -> Result<SessionId, StressError> {
        unsafe {
            let sid = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::create_session(t1, scp03, userid_oid)?
            };
            let verify_err = {
                let (t1, scp03) = self.se.t1_scp03_mut();
                apdu::verify_session(t1, scp03, &sid, apdu::UserIdValue::Bench(pin)).err()
            };
            if let Some(e) = verify_err {
                {
                    let (t1, scp03) = self.se.t1_scp03_mut();
                    let _ = apdu::close_session(t1, scp03, &sid);
                }
                // A3 mitigation: flush the chip's session-pending
                // state so the caller's next non-session APDU isn't
                // poisoned by 0x6982.
                let _ = self.se.reinit();
                return Err(e.into());
            }
            Ok(sid)
        }
    }

    /// Open + verify a session against the stress-admin UserID.
    pub fn open_admin_session(&mut self) -> Result<SessionId, StressError> {
        let pin = self.admin_pin()?;
        self.open_user_session(oid::STRESS_ADMIN_USERID, &pin)
    }

    /// Close a session (idempotent — SE050 just no-ops on stale IDs).
    pub fn close_session(&mut self, sid: &SessionId) {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            let _ = apdu::close_session(t1, scp03, sid);
        }
    }

    // -------- Typed APDU wrappers for tests --------

    /// `check_exists` on an arbitrary OID, no auth.
    pub fn check_exists(&mut self, target: u32) -> Result<bool, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::check_exists(t1, scp03, target)
        }
    }

    /// Delete an object through an existing authenticated session.
    pub fn delete_authed(&mut self, sid: &SessionId, target: u32) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::delete_object_authed(t1, scp03, sid, target)
        }
    }

    // -------- Assertion helpers --------

    pub fn assert_true(&self, what: &'static str, cond: bool) -> StressResult {
        if cond {
            Ok(())
        } else {
            Err(StressError::Assertion { what, iter: self.iter })
        }
    }

    pub fn assert_eq(
        &self,
        what: &'static str,
        got: &[u8],
        expected: &[u8],
    ) -> StressResult {
        if got.len() != expected.len() {
            return Err(StressError::Assertion { what, iter: self.iter });
        }
        for (g, e) in got.iter().zip(expected.iter()) {
            if g != e {
                return Err(StressError::Mismatch {
                    what,
                    expected: *e,
                    got: *g,
                });
            }
        }
        Ok(())
    }

    pub fn assert_ne(
        &self,
        what: &'static str,
        a: &[u8],
        b: &[u8],
    ) -> StressResult {
        if a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y) {
            return Err(StressError::Assertion { what, iter: self.iter });
        }
        Ok(())
    }

    pub fn assert_sw_eq(
        &self,
        what: &'static str,
        sw: u16,
        expected: u16,
    ) -> StressResult {
        if sw == expected {
            Ok(())
        } else {
            Err(StressError::UnexpectedSw { what, sw })
        }
    }

    // -------- Iteration tracking --------

    pub fn set_iter(&mut self, n: u32) {
        self.iter = n;
    }

    pub fn iter(&self) -> u32 {
        self.iter
    }

    // -------- Low-level escape hatches --------

    /// Split-borrow accessor: `(t1, scp03)`. Use when a test needs to
    /// call `apdu::*` helpers directly that aren't covered by the
    /// typed wrappers above. The pair lives for the duration of the
    /// returned lifetime; pass both to a single APDU call, drop them,
    /// then re-acquire if more APDUs are needed.
    pub fn t1_scp03(&mut self) -> (&mut T1State, &mut Scp03Session) {
        self.se.t1_scp03_mut()
    }

    /// Snapshot of SCP03 session keys / counter for tests that just
    /// want to inspect handshake outputs without holding a borrow.
    /// Cheap: `s_enc` / `s_mac` / `s_rmac` are 16 bytes each.
    pub fn scp03_snapshot(&mut self) -> Scp03Snapshot {
        let (_, scp03) = self.se.t1_scp03_mut();
        Scp03Snapshot {
            s_enc: scp03.s_enc,
            s_mac: scp03.s_mac,
            s_rmac: scp03.s_rmac,
            mcv: scp03.mcv,
            counter: scp03.counter,
            active: scp03.active,
        }
    }

    /// Send a raw APDU through the SCP03 wrap path. Returns the
    /// unwrapped response body length (SW is stripped — non-9000 SWs
    /// surface as `Se050Error::Status(sw)`).
    pub fn raw_apdu(
        &mut self,
        apdu_bytes: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::send_apdu(t1, scp03, apdu_bytes, resp_buf)
        }
    }

    /// Mutable access to the underlying SE050 — for tests that want to
    /// call `se.random(...)`, `se.reinit(...)`, `se.pin_attempt_count_
    /// raw(...)`, etc.
    pub fn se(&mut self) -> &mut Se050 {
        self.se
    }

    // -------- Adversarial / silicon-assumption probes --------
    //
    // Helpers below are the surface used by the audit / PIN-counter
    // stress tests to probe what the chip actually does — admin-auth
    // read of user-gated objects, substitution writes at deleted OIDs,
    // attribute reads on arbitrary OIDs, transport-level write attempts
    // on existing UserIDs, raw unauth ReadBinary. Every one of them
    // returns the raw `Se050Error` (or a typed parse) so the caller can
    // distinguish "SW=0x6986 policy-denied" (good) from "SW=0x9000 with
    // bytes" (bad) — `delete_scratch` / `read_scratch` deliberately
    // swallow errors for idempotency, which is the wrong shape here.

    /// Provision a test UserID with the SE-side attempt counter
    /// **disabled** (`max_attempts` TLV omitted → AN12413 §4.7.1.5
    /// "unlimited"). Used by the substitution-attack rehearsal so the
    /// repeated user/admin auth swings don't accidentally drive the test
    /// UserID into lockout mid-probe.
    pub fn provision_test_userid_unlimited(
        &mut self,
        target: u32,
        pin: &[u8],
        policy: AdminPolicy,
    ) -> StressResult {
        let admin_entry = match policy {
            AdminPolicy::WithAdminDelete => Some(oid::STRESS_ADMIN_USERID),
            AdminPolicy::WithoutAdminEntry => None,
        };
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_userid_unlimited(t1, scp03, target, apdu::UserIdValue::Bench(pin), admin_entry)?;
        }
        Ok(())
    }

    /// Write a binary data object whose primary policy auth is an
    /// arbitrary UserID (NOT the stress-admin). Used by audit tests
    /// that need to gate a sentinel on a *user* credential and then
    /// probe whether an admin session can still read it.
    pub fn write_user_gated_data(
        &mut self,
        target: u32,
        data: &[u8],
        user_userid: u32,
        admin_userid: Option<u32>,
    ) -> StressResult {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_binary_gated(t1, scp03, target, data, user_userid, admin_userid)?;
        }
        Ok(())
    }

    /// Fallible variant of `write_user_gated_data` — returns the raw
    /// driver error instead of converting to `StressError`. Used by
    /// the substitution-attack rehearsal which needs to distinguish
    /// "chip refused to write at the deleted OID" from generic test
    /// failure.
    pub fn try_write_user_gated_data(
        &mut self,
        target: u32,
        data: &[u8],
        user_userid: u32,
        admin_userid: Option<u32>,
    ) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_binary_gated(t1, scp03, target, data, user_userid, admin_userid)
        }
    }

    /// WRITE-ONCE variant of [`try_write_user_gated_data`] — calls
    /// `write_binary_write_once`, whose user policy entry omits
    /// `ALLOW_WRITE`. Used by the half_E write-once silicon validation:
    /// the CREATE must succeed even though the policy lacks `ALLOW_WRITE`
    /// (the creating WriteBinary is session-authorized), and a second
    /// write to the same OID must be refused.
    pub fn try_write_user_gated_data_write_once(
        &mut self,
        target: u32,
        data: &[u8],
        user_userid: u32,
        admin_userid: Option<u32>,
    ) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_binary_write_once(t1, scp03, target, data, user_userid, admin_userid)
        }
    }

    /// Read a UserID-gated data object through a caller-owned session.
    /// Distinct from `read_scratch` (which opens / verifies / closes a
    /// stress-admin session internally) — required for tests that need
    /// the read to flow through a *specific* session (admin or user) so
    /// the chip's policy check is exercised against that exact auth.
    pub fn read_authed_at(
        &mut self,
        sid: &SessionId,
        target: u32,
        out: &mut [u8],
    ) -> Result<usize, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::read_authed(t1, scp03, sid, target, out)
        }
    }

    /// Session-authed DATA update (INS_PROCESS-wrapped `WriteBinary`,
    /// data-only). Returns the raw driver result so the write-once test
    /// can distinguish "accepted" (the `ALLOW_WRITE` control) from
    /// "refused" (the no-`ALLOW_WRITE` write-once object).
    pub fn try_write_authed(
        &mut self,
        sid: &SessionId,
        target: u32,
        data: &[u8],
    ) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_authed(t1, scp03, sid, target, data)
        }
    }

    /// Read the SE050 extended applet version (anti-substitution identity).
    pub fn get_version_ext(&mut self, out: &mut [u8]) -> Result<usize, Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::get_version_ext(t1, scp03, out)
        }
    }

    /// Send a top-level `INS_WRITE | INS_AUTH_OBJECT` `WriteUserID` APDU
    /// at `target`, *outside* any UserID session (transport-SCP03 only).
    /// On an empty OID the chip CREATEs; on an existing one the chip
    /// must check the existing object's policy for `ALLOW_WRITE` —
    /// transport SCP03 alone does NOT satisfy that, so a successful
    /// return here on an existing target means the silicon is letting
    /// pure-SCP03 callers rotate any PIN at will (catastrophic).
    pub fn try_write_userid_transport(
        &mut self,
        target: u32,
        pin: &[u8],
        max_attempts: u16,
        admin: Option<u32>,
    ) -> Result<(), Se050Error> {
        unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::write_userid(t1, scp03, target, apdu::UserIdValue::Bench(pin), max_attempts, admin)
        }
    }

    /// Parse `ReadObjectAttributes` for the UserID at `target` and
    /// return `(auth_attempts, max_attempts)`. Reads attributes don't
    /// burn a wrong-PIN attempt (policy-gate-independent per AN12413
    /// §4.2) — that load-bearing claim is itself one of the PIN-counter
    /// tests in `tests/userid.rs::attribute_read_does_not_burn`.
    ///
    /// Returns `None` if the object is missing, the response is
    /// malformed, or `auth_attr != SET`. Mirrors
    /// `Se050::pin_attempt_count_raw` but for arbitrary OIDs.
    pub fn read_userid_attempts(&mut self, target: u32) -> Option<(u16, u16)> {
        let mut buf = [0u8; 64];
        let n = unsafe {
            let (t1, scp03) = self.se.t1_scp03_mut();
            apdu::read_object_attributes(t1, scp03, target, &mut buf).ok()?
        };
        if n < 14 || buf[5] != 0x01 {
            return None;
        }
        let auth_attempts = u16::from_be_bytes([buf[6], buf[7]]);
        let max_attempts = u16::from_be_bytes([buf[12], buf[13]]);
        Some((auth_attempts, max_attempts))
    }

    /// Send a top-level `ReadBinary` (no `INS_PROCESS` wrap, no UserID
    /// session) at `target`. The chip must refuse if the object's
    /// policy requires `ALLOW_READ` via UserID auth — transport SCP03
    /// alone is not a session and does not satisfy a UserID-auth entry.
    /// Returns `Ok(n)` with `n` decoded payload bytes on a 0x9000
    /// response (catastrophic — secret leaked); `Err(Status(sw))` is
    /// the expected refusal path.
    pub fn try_unauth_read(&mut self, target: u32, out: &mut [u8]) -> Result<usize, Se050Error> {
        let mut apdu_buf = [0u8; 16];
        apdu_buf[0] = 0x80; // CLA
        apdu_buf[1] = 0x02; // INS = READ
        apdu_buf[2] = 0x00; // P1
        apdu_buf[3] = 0x00; // P2
        apdu_buf[4] = 0x06; // Lc = TAG(1) + LEN(1) + OID(4)
        apdu_buf[5] = 0x41; // TAG_1
        apdu_buf[6] = 0x04;
        apdu_buf[7..11].copy_from_slice(&target.to_be_bytes());
        apdu_buf[11] = 0x00; // Le

        let mut resp = [0u8; 128];
        let n = self.raw_apdu(&apdu_buf[..12], &mut resp)?;
        // 0x9000 path: data is in `resp[..n]`. Could be TLV-wrapped or
        // raw bytes depending on whether the chip honoured the read.
        // Either way, if we got here on a user-gated OID, the
        // confidentiality invariant is broken.
        let take = n.min(out.len());
        out[..take].copy_from_slice(&resp[..take]);
        Ok(take)
    }

    /// Burn `n` wrong-PIN attempts against `target`, asserting each
    /// returns `PinIncorrect` (counter still has room) — useful prelude
    /// for "what does the counter look like after N wrong" tests.
    pub fn burn_wrong_pin(&mut self, target: u32, wrong: &[u8], n: usize) -> StressResult {
        for i in 0..n {
            self.set_iter(i as u32);
            match self.open_user_session(target, wrong) {
                Err(StressError::Driver(Se050Error::PinIncorrect)) => { /* expected */ }
                Err(StressError::Driver(Se050Error::AuthMethodBlocked)) => {
                    return Err(StressError::Assertion {
                        what: "lockout fired earlier than expected",
                        iter: i as u32,
                    });
                }
                Ok(sid) => {
                    self.close_session(&sid);
                    return Err(StressError::Assertion {
                        what: "wrong-PIN attempt opened a session",
                        iter: i as u32,
                    });
                }
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    // -------- Private helpers --------

    fn admin_pin(&self) -> Result<[u8; 16], StressError> {
        crate::hw::secret_keys::se050_admin_pin().map_err(|_| StressError::Assertion {
            what: "se050_admin_pin unavailable",
            iter: self.iter,
        })
    }
}

/// Read-only snapshot of `Scp03Session` state — useful for tests that
/// compare derived session keys across handshakes without keeping a
/// mutable borrow on the chip handle.
#[derive(Debug)]
pub struct Scp03Snapshot {
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mcv: [u8; 16],
    pub counter: [u8; 16],
    pub active: bool,
}
