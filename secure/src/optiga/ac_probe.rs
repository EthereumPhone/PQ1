//! #116 / OP17-1 silicon probe (`optiga-ac-probe`, bench-only, terminal).
//!
//! Proves on real OPTIGA silicon that the secret-OID Read AC
//! `Auto(auth) AND Conf(E140)` built by [`apdu::build_metadata_protected`]
//! is (1) stored byte-exact, (2) refuses a shielded read with no auth,
//! (3) serves a shielded read after auth, and (4) with NO shielded session
//! at all (the desoldered-chip / no-PBS case), after a plaintext PIN-style
//! auth, refuses a plaintext read with a chip `Status` answer — the #116
//! attack. A control object carrying the pre-#116 weak AC (`Auto` only) is
//! served in that same plaintext auth state, so the refusal in (4) is
//! attributable to the `Conf(E140)` arm, not to a lost auto-state or a
//! transport fault (a non-`Status` error is reported as inconclusive).
//!
//! Non-destructive to the wallet: touches ONLY spare OIDs
//! F1D5 (throwaway AuthRef, Execute=ALW → no LUC/E120 involvement),
//! F1D7 (test data, strict AC) and F1E0 (control data, weak AC). Never
//! locks; every object stays at LcsO=Creation. Cleanup relaxes F1D7/F1E0
//! and zeroes them, and overwrites F1D5 with fresh TRNG bytes nobody keeps.
//! Refuses to start if any of the three is already Operational.

use super::apdu::{self, OptigaError};
use super::OptigaTrustM;
use zeroize::Zeroize;

const PROBE_AUTHREF: u16 = 0xF1D5;
const PROBE_STRICT: u16 = 0xF1D7;
const PROBE_CONTROL: u16 = 0xF1E0;

const STRICT_PATTERN: [u8; 32] = [0xA5; 32];
const CONTROL_PATTERN: [u8; 32] = [0x5A; 32];

/// Pre-#116 weak secret-OID AC, re-targeted at the throwaway F1D5:
/// Change = Auto(F1D5) OR Conf(E140), Read = Auto(F1D5) ONLY, Exec = NEV.
/// Literal bytes on purpose — firmware can no longer build this shape.
const CONTROL_WEAK_META: [u8; 19] = [
    0x20, 0x11, 0xD0, 0x07, 0x23, 0xF1, 0xD5, 0xFE, 0x20, 0xE1, 0x40, 0xD1, 0x03, 0x23, 0xF1,
    0xD5, 0xD3, 0x01, 0xFF,
];

/// What the probe saw. `read_ac` is the stored Read-AC value of F1D7
/// (expected `23 F1 D5 FD 20 E1 40`), for display.
pub struct AcProbeReport {
    pub read_ac: [u8; 16],
    pub read_ac_len: usize,
    /// The chip's answer to the plaintext read of the strict object
    /// (always a `Status(_)` on PASS — the AC refusal itself).
    pub neg_b: Option<OptigaError>,
}

/// Failing step + the driver error, if any.
pub struct AcProbeFail {
    pub step: &'static str,
    pub err: Option<OptigaError>,
    pub read_ac: [u8; 16],
    pub read_ac_len: usize,
}

impl OptigaTrustM {
    /// Run the probe. See the module docs.
    ///
    /// # Safety
    /// Drives the OPTIGA APDU stack; caller holds `&mut self` and must not
    /// run any other OPTIGA flow concurrently.
    pub(crate) unsafe fn ac_probe(&mut self) -> Result<AcProbeReport, AcProbeFail> {
        let mut read_ac = [0u8; 16];
        let mut read_ac_len = 0usize;
        let mut neg_b = None;
        let r = self.ac_probe_body(&mut read_ac, &mut read_ac_len, &mut neg_b);
        // Cleanup runs on every outcome; its own failure is reported only
        // if the body passed (a body failure is the more useful message).
        let c = self.ac_probe_cleanup();
        match (r, c) {
            (Err((step, err)), _) | (Ok(()), Err((step, err))) => {
                Err(AcProbeFail { step, err, read_ac, read_ac_len })
            }
            (Ok(()), Ok(())) => Ok(AcProbeReport { read_ac, read_ac_len, neg_b }),
        }
    }

    unsafe fn ac_probe_fresh_session(&mut self) -> Result<(), (&'static str, Option<OptigaError>)> {
        self.hard_reset_and_reinit().map_err(|e| ("reset", Some(e)))?;
        self.ensure_shield().map_err(|e| ("shield", Some(e)))
    }

    /// PIN-style HMAC auth against the throwaway F1D5 (non-LUC Infineon
    /// 64-B shape). Runs over whatever transport is current: shielded if
    /// the session is up, plaintext otherwise.
    unsafe fn ac_probe_auth(&mut self, secret: &[u8; 32]) -> Result<(), (&'static str, Option<OptigaError>)> {
        let mut host_nonce = [0u8; 16];
        let mut host_tag = [0u8; 16];
        crate::rng::fill(&mut host_nonce).map_err(|_| ("rng", None))?;
        crate::rng::fill(&mut host_tag).map_err(|_| ("rng", None))?;
        let mut chip_random = [0u8; 32];
        apdu::generate_auth_code(
            &mut self.ifx, &mut self.shield, apdu::OID_SESSION, &host_nonce, &mut chip_random,
        )
        .map_err(|e| ("auth-code", Some(e)))?;
        let mut input = [0u8; 64];
        input[..16].copy_from_slice(&host_nonce);
        input[16..48].copy_from_slice(&chip_random);
        input[48..].copy_from_slice(&host_tag);
        let mut mac = Self::hmac_sha256(secret, &input);
        let v = apdu::hmac_verify(
            &mut self.ifx, &mut self.shield, PROBE_AUTHREF, apdu::OID_SESSION, &input, &mac,
        );
        mac.zeroize();
        input.zeroize();
        v.map_err(|e| ("auth-verify", Some(e)))
    }

    unsafe fn ac_probe_body(
        &mut self,
        read_ac: &mut [u8; 16],
        read_ac_len: &mut usize,
        neg_b: &mut Option<OptigaError>,
    ) -> Result<(), (&'static str, Option<OptigaError>)> {
        secure_log!("[AC-PROBE] start (spares F1D5/F1D7/F1E0 only)");
        self.init().map_err(|e| ("init", Some(e)))?;
        self.ensure_shield().map_err(|e| ("shield", Some(e)))?;

        // 0. Refuse to touch a spare that is already frozen.
        for oid in [PROBE_AUTHREF, PROBE_STRICT, PROBE_CONTROL] {
            let mut m = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, oid, &mut m)
                .map_err(|e| ("pre-meta", Some(e)))?;
            secure_log!("[AC-PROBE] pre 0x{:04x} meta={:02x?}", oid, &m[..n.min(48)]);
            if apdu::is_metadata_operational(&m, n) {
                return Err(("spare-locked", None));
            }
        }

        // 1. Throwaway AuthRef F1D5 = fresh TRNG secret (kept in RAM only).
        let mut secret = [0u8; 32];
        crate::rng::fill(&mut secret).map_err(|_| ("rng", None))?;
        let r = (|| -> Result<(), (&'static str, Option<OptigaError>)> {
            apdu::set_data_object(&mut self.ifx, &mut self.shield, PROBE_AUTHREF, &secret)
                .map_err(|e| ("authref-data", Some(e)))?;
            let (m, ml) = apdu::build_metadata_auth_ref();
            apdu::set_metadata(&mut self.ifx, &mut self.shield, PROBE_AUTHREF, &m[..ml])
                .map_err(|e| ("authref-meta", Some(e)))?;
            self.ac_probe_fresh_session()?;

            // 2. Strict object F1D7 with the production builder.
            apdu::set_data_object(&mut self.ifx, &mut self.shield, PROBE_STRICT, &STRICT_PATTERN)
                .map_err(|e| ("strict-data", Some(e)))?;
            let (m, ml) = apdu::build_metadata_protected(PROBE_AUTHREF);
            apdu::set_metadata(&mut self.ifx, &mut self.shield, PROBE_STRICT, &m[..ml])
                .map_err(|e| ("strict-meta", Some(e)))?;
            let mut st = [0u8; 128];
            let n = apdu::get_metadata(&mut self.ifx, &mut self.shield, PROBE_STRICT, &mut st)
                .map_err(|e| ("strict-readback", Some(e)))?;
            secure_log!("[AC-PROBE] F1D7 stored meta={:02x?}", &st[..n.min(48)]);
            if let Some(v) = find_read_tag(&st, n) {
                let k = v.len().min(read_ac.len());
                read_ac[..k].copy_from_slice(&v[..k]);
                *read_ac_len = k;
            }
            if !apdu::secret_oid_metadata_ok(&st, n, &m[..ml], ml) {
                return Err(("stored-mismatch", None));
            }
            self.ac_probe_fresh_session()?;

            // 3. Control object F1E0 with the pre-#116 weak AC.
            apdu::set_data_object(&mut self.ifx, &mut self.shield, PROBE_CONTROL, &CONTROL_PATTERN)
                .map_err(|e| ("control-data", Some(e)))?;
            apdu::set_metadata(&mut self.ifx, &mut self.shield, PROBE_CONTROL, &CONTROL_WEAK_META)
                .map_err(|e| ("control-meta", Some(e)))?;
            self.ac_probe_fresh_session()?;

            // 4. Negative A: shielded read, NO auth → must be refused.
            let mut buf = [0u8; 32];
            if apdu::get_data_object(&mut self.ifx, &mut self.shield, PROBE_STRICT, 0, 32, &mut buf)
                .is_ok()
            {
                return Err(("negA-read-noauth", None));
            }
            secure_log!("[AC-PROBE] negA OK: shielded read without auth refused");
            self.ac_probe_fresh_session()?;

            // 5. Auth against F1D5 over the shielded session.
            self.ac_probe_auth(&secret)?;

            // 6. Positive: shielded read after auth → the pattern.
            buf = [0u8; 32];
            apdu::get_data_object(&mut self.ifx, &mut self.shield, PROBE_STRICT, 0, 32, &mut buf)
                .map_err(|e| ("pos-read", Some(e)))?;
            if buf != STRICT_PATTERN {
                return Err(("pos-wrong-data", None));
            }
            secure_log!("[AC-PROBE] pos OK: shielded read after auth served");

            // 7. Negative B — the #116 attack shape: NO shielded session
            //    at all (desoldered chip / no PBS), PIN auth done in
            //    plaintext, then a plaintext GetData. A plaintext frame
            //    sent INSIDE an established PRL session is dropped at the
            //    link layer (first EVT run 2026-10-13: Transport), which
            //    says nothing about the AC — so the session is torn down
            //    by RST and never re-established here.
            self.hard_reset_and_reinit().map_err(|e| ("reset", Some(e)))?;
            if self.shield.active {
                return Err(("negB-shield-up", None));
            }
            self.ac_probe_auth(&secret)
                .map_err(|(s, e)| (if s == "auth-verify" { "negB-plain-auth" } else { s }, e))?;
            //    Control first: weak-AC object, same plaintext auth state.
            //    Must be served — reproduces the pre-#116 leak and proves
            //    the plaintext path + auto-state are live.
            let mut cbuf = [0u8; 32];
            match apdu::get_data_object(&mut self.ifx, &mut self.shield, PROBE_CONTROL, 0, 32, &mut cbuf) {
                Ok(_) if cbuf == CONTROL_PATTERN => {}
                Ok(_) => return Err(("control-wrong", None)),
                Err(e) => return Err(("control-read", Some(e))),
            }
            //    Strict object: must be refused BY THE CHIP (a Status
            //    answer). A transport-level error is inconclusive → FAIL.
            buf = [0u8; 32];
            match apdu::get_data_object(&mut self.ifx, &mut self.shield, PROBE_STRICT, 0, 32, &mut buf) {
                Ok(_) => return Err(("negB-plain-read", None)),
                Err(e @ OptigaError::Status(_)) => *neg_b = Some(e),
                Err(e) => return Err(("negB-inconclusive", Some(e))),
            }
            secure_log!("[AC-PROBE] negB OK: plaintext read refused by chip ({:?}); weak-AC control served (old shape leaks)", *neg_b);
            Ok(())
        })();
        secret.zeroize();
        r
    }

    /// Relax + zero F1D7 / F1E0, scramble F1D5. Best-effort ordering, but
    /// every step's error is surfaced.
    unsafe fn ac_probe_cleanup(&mut self) -> Result<(), (&'static str, Option<OptigaError>)> {
        let zero = [0u8; 32];
        let (relaxed, rl) = apdu::build_metadata_relaxed();
        for oid in [PROBE_STRICT, PROBE_CONTROL] {
            self.ac_probe_fresh_session()?;
            apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &relaxed[..rl])
                .map_err(|e| ("cleanup-meta", Some(e)))?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, &zero)
                .map_err(|e| ("cleanup-data", Some(e)))?;
        }
        self.ac_probe_fresh_session()?;
        let mut junk = [0u8; 32];
        crate::rng::fill(&mut junk).map_err(|_| ("rng", None))?;
        let r = apdu::set_data_object(&mut self.ifx, &mut self.shield, PROBE_AUTHREF, &junk)
            .map_err(|e| ("cleanup-authref", Some(e)));
        junk.zeroize();
        r?;
        self.ac_probe_fresh_session()?;
        secure_log!("[AC-PROBE] cleanup done");
        Ok(())
    }
}

/// Value of the Read (0xD1) tag in a metadata TLV, if present.
fn find_read_tag(m: &[u8], n: usize) -> Option<&[u8]> {
    if n < 2 || m[0] != 0x20 {
        return None;
    }
    let end = (2 + m[1] as usize).min(n);
    let mut p = 2;
    while p + 2 <= end {
        let (t, l) = (m[p], m[p + 1] as usize);
        if p + 2 + l > end {
            return None;
        }
        if t == 0xD1 {
            return Some(&m[p + 2..p + 2 + l]);
        }
        p += 2 + l;
    }
    None
}
