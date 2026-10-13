//! SE050 object-ID carve-out for the stress harness.
//!
//! Layout — every OID the harness ever touches is in `0x7B5E_*`:
//!
//! ```text
//!   0x7B5E_00A0  STRESS_ADMIN_USERID  unlimited attempts, HW-root PIN
//!   0x7B5E_NN00..0x7B5E_NNFF   test #NN (1..=255) — 256 OIDs
//! ```
//!
//! That's well above existing per-test e2e ranges
//! (`0x7B07_*`, `0x7B09_*`, `0x7B0A_*`, `0x7B0B_*`) and decisively above
//! the v6 production range (`0x7B10_*`), so a stress run never collides
//! with real provisioning.
//!
//! **Generation bump (2026-05-28): `0x7B5F_*` → `0x7B5E_*`.** The
//! previous base (`0x7B5F_*`) accumulated stranded no-admin-delete
//! UserIDs across runs — a UserID provisioned with `WithoutAdminEntry`
//! (or by an older firmware whose OID layout differed) that crashed
//! before its own user-PIN self-delete CANNOT be removed afterwards:
//! admin-delete returns 0x6986 (no admin entry in its policy), and a
//! transport `write_userid` UPDATE is *refused and preserves* the
//! object (Finding A2 is RETRACTED — there is no destroy-on-failed-
//! UPDATE; see `docs/secure-elements/se050-silicon-findings.md` §3). On the 2026-05-28
//! run a stranded UserID at `0x7B5F_0801` made `pin_attribute_read_-
//! refused_on_user_userid` fail at provisioning. Bumping the whole
//! carve-out to `0x7B5E_*` abandons the stranded `0x7B5F_*` generation
//! and gives every test + the admin UserID a clean slate — the same
//! "bump the OID range to re-provision" pattern production uses after a
//! chip strands a UserID (CLAUDE.md S-6). The abandoned `0x7B5F_*`
//! objects are a harmless NVM leak on the throwaway stress chip. Bump
//! again (`…5D`, `…5C`, …) if a future run strands the current
//! generation.

use crate::se050::Se050;
use crate::se050::apdu;

/// Base address of the stress carve-out range. Helper functions
/// elsewhere assume `STRESS_BASE & 0xFFFF_0000 == 0x7B5E_0000`.
pub const STRESS_BASE: u32 = 0x7B5E_0000;

/// Upper bound on slot probing within any single test's 256-slot sub-
/// range. Tests in this catalog use slots `0x01..=0x02` exclusively (a
/// "user" OID and a "data" OID); 8 is a comfortable buffer for future
/// additions. Bounding the per-test sweep this way keeps cleanup fast
/// on real silicon — at ~400 ms per SCP03-wrapped APDU (the round-trip
/// cost with `debug-log` enabled on this hardware), scanning all 256
/// slots blows past the probe-rs 600 s timeout before any test even
/// runs. If a future test ever needs slot ≥ 8, bump this constant.
const STRESS_SWEEP_SLOTS: u8 = 8;

/// Stress-admin UserID. Unlimited attempts, PIN derived from
/// `hw::secret_keys::se050_admin_pin()` (BHK-rooted in the shipping
/// configuration, otherwise OTP/DHUK-rooted — every variant is per-
/// device deterministic so the same firmware re-derives the same PIN
/// across reboots and reflashes). Holds admin-delete authority over
/// every OID in `0x7B5E_*`, so the runner can always clean up after a
/// crashed test.
pub const STRESS_ADMIN_USERID: u32 = STRESS_BASE | 0x00A0;

/// Compute the OID for slot `slot` of test `test_id`.
/// `test_id ∈ 1..=255`, `slot ∈ 0..=255`. Test 0 is reserved (used for
/// the admin UserID's own sub-range).
#[inline]
pub const fn scratch_oid(test_id: u16, slot: u8) -> u32 {
    STRESS_BASE | (((test_id as u32) & 0xFF) << 8) | (slot as u32)
}

/// `(low, high_inclusive)` OID bounds for a single test's sub-range.
#[inline]
pub const fn scratch_range(test_id: u16) -> (u32, u32) {
    let lo = STRESS_BASE | (((test_id as u32) & 0xFF) << 8);
    (lo, lo | 0xFF)
}

/// Result of an admin sweep — how many OIDs were cleared vs. left
/// behind. Failures are best-effort; the runner logs them and proceeds.
pub struct SweepReport {
    pub cleared: u16,
    pub failed: u16,
}

/// Top-of-run sweep: clears every OID in `0x7B5E_*` that the stress-
/// admin session can reach. Provisions the stress-admin UserID first if
/// it doesn't yet exist (idempotent). Best-effort — on failure the
/// runner still tries the test, since per-test setup also tries to
/// clean its own range.
pub fn admin_sweep_all(se: &mut Se050) -> SweepReport {
    let mut rep = SweepReport { cleared: 0, failed: 0 };
    let pin = match crate::hw::secret_keys::se050_admin_pin() {
        Ok(p) => p,
        Err(_) => {
            secure_log!("[S][stress] sweep: se050_admin_pin unavailable");
            return rep;
        }
    };

    unsafe {
        // Idempotent provisioning of the stress admin. If the OID
        // already exists, skip provisioning.
        {
            let (t1, scp03) = se.t1_scp03_mut();
            let exists = apdu::check_exists(t1, scp03, STRESS_ADMIN_USERID)
                .unwrap_or(false);
            if !exists {
                if let Err(e) = apdu::write_userid_unlimited(
                    t1, scp03, STRESS_ADMIN_USERID, apdu::UserIdValue::Bench(&pin), None,
                ) {
                    secure_log!("[S][stress] sweep: provision STRESS_ADMIN failed: {:?}", e);
                    return rep;
                }
            }
        }

        // Open admin session.
        let sid = {
            let (t1, scp03) = se.t1_scp03_mut();
            match apdu::create_session(t1, scp03, STRESS_ADMIN_USERID) {
                Ok(s) => s,
                Err(e) => {
                    secure_log!("[S][stress] sweep: create_session failed: {:?}", e);
                    return rep;
                }
            }
        };
        {
            let (t1, scp03) = se.t1_scp03_mut();
            if let Err(e) = apdu::verify_session(t1, scp03, &sid, apdu::UserIdValue::Bench(&pin)) {
                secure_log!("[S][stress] sweep: verify_session failed: {:?}", e);
                let _ = apdu::close_session(t1, scp03, &sid);
                return rep;
            }
        }

        // Top-of-run sweep DISABLED for performance — at ~400 ms per
        // SCP03-wrapped APDU on real silicon (with `debug-log`), even
        // a bounded 64 × 8 = 512-OID scan blows past the probe-rs
        // 600 s timeout before any test runs.
        //
        // The harness still gets cleanup from two layers:
        //   1. Per-test teardown (`admin_sweep_test_range`) clears the
        //      current test's 0..8 slots after every test, PASS or FAIL.
        //   2. Each test's own first action is a `delete_scratch(target)`
        //      that idempotently clears its OID(s) before provisioning —
        //      so residue from a crashed prior run is reclaimed when
        //      the same test_id runs again next time.
        //
        // The one residual case top-of-run sweep used to catch: a test
        // crashed AND the catalog reorders so a different test_id
        // touches the polluted slots. Worst case: those OIDs stay
        // occupied (≤150 B each) inside the `0x7B5E_*` carve-out,
        // invisible to production. Operationally acceptable.

        let (t1, scp03) = se.t1_scp03_mut();
        let _ = apdu::close_session(t1, scp03, &sid);
    }
    rep
}

/// Per-test sweep: clear just one test's 256-OID sub-range. Called
/// after each test (PASS or FAIL) so the next test starts clean.
pub fn admin_sweep_test_range(se: &mut Se050, test_id: u16) -> SweepReport {
    let mut rep = SweepReport { cleared: 0, failed: 0 };
    let pin = match crate::hw::secret_keys::se050_admin_pin() {
        Ok(p) => p,
        Err(_) => return rep,
    };

    unsafe {
        let lo = STRESS_BASE | ((test_id as u32) << 8);

        // Quick scan: only probe the slots the catalog actually uses
        // (`0..STRESS_SWEEP_SLOTS`, currently 8). Scanning the full
        // 256-slot sub-range here would dominate the runner's wall
        // clock — see the `STRESS_SWEEP_SLOTS` doc.
        let mut any = false;
        for slot in 0u8..STRESS_SWEEP_SLOTS {
            let oid = lo | (slot as u32);
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::check_exists(t1, scp03, oid).unwrap_or(false) {
                any = true;
                break;
            }
        }
        if !any {
            return rep;
        }

        let sid = {
            let (t1, scp03) = se.t1_scp03_mut();
            match apdu::create_session(t1, scp03, STRESS_ADMIN_USERID) {
                Ok(s) => s,
                Err(_) => return rep,
            }
        };
        {
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::verify_session(t1, scp03, &sid, apdu::UserIdValue::Bench(&pin)).is_err() {
                let _ = apdu::close_session(t1, scp03, &sid);
                return rep;
            }
        }

        for slot in 0u8..STRESS_SWEEP_SLOTS {
            let oid = lo | (slot as u32);
            let (t1, scp03) = se.t1_scp03_mut();
            if apdu::check_exists(t1, scp03, oid).unwrap_or(false) {
                match apdu::delete_object_authed(t1, scp03, &sid, oid) {
                    Ok(()) => rep.cleared += 1,
                    Err(_) => rep.failed += 1,
                }
            }
        }
        let (t1, scp03) = se.t1_scp03_mut();
        let _ = apdu::close_session(t1, scp03, &sid);
    }
    rep
}
