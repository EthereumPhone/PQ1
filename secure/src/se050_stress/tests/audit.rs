//! Silicon verification of recently-landed ship-blocker fixes.
//!
//! S-5 (2026-05-28): SCP03 elevated to `P1=0x33`; `unwrap_response`
//! wired into `send_apdu`. Logic-analyzer verification on a real
//! B-U585I-IOT02A still pending per CLAUDE.md — these tests prove the
//! Rust side works end-to-end, leaving the bus capture as the only
//! remaining closure step.
//!
//! S-6 (2026-05-28): user UserID's admin-delete policy entry removed.
//! Admin can DoS-wipe data objects but can no longer substitute the
//! user PIN by deleting + recreating the UserID at the same OID.
//!
//! Each test in this file directly probes one of those guarantees.
//! A FAIL here is a hard signal that the fix doesn't hold on this
//! silicon — investigate before shipping.

use crate::stress_test;
use crate::se050::apdu::Se050Error;
use crate::se050_stress::oid::STRESS_ADMIN_USERID;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};
use crate::se050_stress::ctx::AdminPolicy;

// ---------------------------------------------------------------------------
// 3. scp03_response_encryption_verify (S-5 closure)
// ---------------------------------------------------------------------------

/// Writes a 32-byte sentinel pattern, reads it back through the
/// authenticated session, and asserts byte-for-byte round-trip equality.
///
/// At SCP03 `P1=0x33` (the new post-S-5 level) the response is encrypted
/// + R-MAC-authenticated; `unwrap_response` is responsible for
/// decrypting and verifying. If `unwrap_response` is broken — wrong
/// IV, wrong key derivation, off-by-one R-MAC length — the read either
/// returns garbage (`assert_eq` fails) or `Se050Error::Scp03`.
///
/// Sentinel pattern is `[0xDE; 32]`: maximally distinguishable from
/// natural TLV / SW bytes in a wire capture, so a logic analyzer can
/// confirm the on-bus response is NOT a 32-byte run of 0xDE (which
/// would imply ciphertext bypass).
fn scp03_response_encryption_verify(ctx: &mut StressCtx) -> StressResult {
    const SENTINEL: [u8; 32] = [0xDE; 32];
    let target = ctx.oid(0x01);

    // Clean slate.
    ctx.delete_scratch(target)?;

    ctx.write_scratch(target, &SENTINEL)?;

    let mut got = [0u8; 64];
    let n = ctx.read_scratch(target, &mut got)?;
    if n != SENTINEL.len() {
        secure_log!(
            "[S][stress][audit-s5] read returned {} bytes (want {})",
            n, SENTINEL.len(),
        );
        return Err(StressError::Assertion {
            what: "S-5 round-trip length mismatch",
            iter: 0,
        });
    }
    ctx.assert_eq("S-5 SCP03 payload round-trip", &got[..n], &SENTINEL)?;

    secure_log!(
        "[S][stress][audit-s5] 32-B 0xDE round-trip OK at P1=0x33 — unwrap_response verified",
    );
    Ok(())
}
stress_test!(SCP03_RESPONSE_ENCRYPTION_VERIFY, "scp03_response_encryption_verify", Tier::Safe, scp03_response_encryption_verify);

// ---------------------------------------------------------------------------
// 7. userid_no_admin_delete (S-6 closure)
// ---------------------------------------------------------------------------

/// Provision a UserID with `AdminPolicy::WithoutAdminEntry`, then
/// attempt to delete it under stress-admin auth. The expectation is
/// that the SE050 refuses (`Se050Error::Status(non-9000)`).
///
/// Why this matters: pre-S-6, every UserID carried a two-entry policy
/// including admin DELETE. That made the substitution attack possible:
/// admin → delete UserID → recreate at same OID with attacker PIN →
/// the gated data objects' policy is now satisfied by the new PIN,
/// letting the attacker exfiltrate `half_E`. Post-S-6, omitting the
/// admin entry makes the UserID immutable from admin's perspective —
/// only the user PIN itself can self-delete it.
///
/// This test FALSIFIES (or VERIFIES) that on silicon. PASS = admin
/// delete refused, AND user self-delete still succeeds (so the
/// invariant is "admin can't substitute" not "no one can delete").
fn userid_no_admin_delete(ctx: &mut StressCtx) -> StressResult {
    let target = ctx.oid(0x01);
    let user_pin: [u8; 8] = *b"audit_s6";

    // Pre-clean (best-effort — admin can delete a USER-self-policy-only
    // UserID only via this test's own self-delete path, so the prior
    // run's residue requires admin-aware sweep).
    ctx.delete_scratch(target)?;

    // Step 1: provision UserID WITHOUT the admin entry. This is the
    // critical S-6 configuration.
    ctx.provision_test_userid(
        target,
        &user_pin,
        5,
        AdminPolicy::WithoutAdminEntry,
    )?;

    // Step 2: admin attempt to delete must FAIL. Use the raw admin
    // session because `delete_scratch` swallows the error to stay
    // idempotent — for the audit we want the error visible.
    let sid = ctx.open_admin_session()?;
    let delete_result = ctx.delete_authed(&sid, target);
    ctx.close_session(&sid);

    match delete_result {
        Ok(()) => {
            // Bad — admin deleted a UserID it shouldn't be able to.
            // S-6 is NOT enforced on this silicon.
            secure_log!(
                "[S][stress][audit-s6] FAIL: admin deleted UserID with no admin policy entry",
            );
            return Err(StressError::Assertion {
                what: "S-6 broken: admin deleted no-admin-policy UserID",
                iter: 0,
            });
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-s6] admin delete refused with SW=0x{:04x} (expected non-9000)",
                sw,
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-s6] admin delete refused with driver error: {:?}",
                e,
            );
        }
    }

    // A3 mitigation (2026-05-28): the failed delete_authed +
    // immediately-following close_session sequence can leave the chip
    // in a "session-pending" state where the very next non-session
    // APDU (`check_exists` below) returns SW=0x6982 regardless of the
    // OID's actual state. `reinit()` (T=1' reset + fresh SCP03) flushes
    // that state so step 3's existence check probes the real chip.
    // See `docs/secure-elements/se050-silicon-findings.md` §4.
    ctx.se().reinit()?;

    // Step 3: confirm the UserID is still on-chip.
    let still_there = ctx.check_exists(target).unwrap_or(false);
    ctx.assert_true(
        "UserID must survive admin delete attempt",
        still_there,
    )?;

    // Step 4: user self-delete still works (proves the UserID isn't
    // structurally immortal — only admin is locked out).
    let sid = ctx.open_user_session(target, &user_pin)?;
    let self_delete = ctx.delete_authed(&sid, target);
    ctx.close_session(&sid);

    if let Err(e) = self_delete {
        secure_log!(
            "[S][stress][audit-s6] user self-delete FAILED: {:?} (S-6 fix may have over-restricted)",
            e,
        );
        return Err(e.into());
    }

    secure_log!(
        "[S][stress][audit-s6] S-6 confirmed: admin REFUSED, user self-delete OK",
    );
    Ok(())
}
stress_test!(USERID_NO_ADMIN_DELETE, "userid_no_admin_delete", Tier::Destructive, userid_no_admin_delete);

// ---------------------------------------------------------------------------
// 9. audit_admin_passive_read_refused
// ---------------------------------------------------------------------------

/// Provision a sentinel under USER-PIN gating with the standard two-
/// entry policy (user → READ|WRITE|DELETE, admin → DELETE only). Open
/// an admin session. Attempt to READ. The chip MUST refuse — admin
/// holds DELETE authority but not READ authority over user-PIN-gated
/// data.
///
/// This is the central "desolder + extracted BHK" confidentiality
/// claim: even with full admin auth (which an attacker who recovered
/// `se050_admin_pin()` can mount), the silicon refuses to release the
/// user-gated bytes. A FAIL here is a confidentiality breach — every
/// shipped device leaks `half_E` to anyone holding admin auth, full
/// stop.
///
/// Mirrors `Se050::run_admin_extract_attempt` (`mod.rs:953-1158`,
/// gated behind `se050-admin-extract-attempt-e2e`) but as a first-
/// class stress test that runs under the routine
/// `make se050-stress-destructive` suite — so the assertion is
/// exercised on every chip-validation pass, not only when an opt-in
/// e2e harness is plumbed up.
///
/// PASS = admin read returns `Se050Error::Status(non-9000)` or a
/// driver error.  FAIL = admin read returns 0x9000 (the chip released
/// data through admin auth).
fn audit_admin_passive_read_refused(ctx: &mut StressCtx) -> StressResult {
    let user_oid = ctx.oid(0x01);
    let data_oid = ctx.oid(0x02);
    let user_pin: [u8; 8] = *b"a1userpn";
    // 32-byte sentinel — distinct from 0xDE (S-5 test) so a wire capture
    // disambiguates which test is currently running.
    const SENTINEL: [u8; 32] = [
        0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
        0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
        0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
        0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1, 0xA1,
    ];

    ctx.delete_scratch(data_oid)?;
    ctx.delete_scratch(user_oid)?;

    ctx.provision_test_userid(user_oid, &user_pin, 5, AdminPolicy::WithAdminDelete)?;
    ctx.write_user_gated_data(data_oid, &SENTINEL, user_oid, Some(STRESS_ADMIN_USERID))?;

    // Sanity: USER auth MUST be able to read the sentinel — if this
    // fails, the test setup is wrong and we cannot draw conclusions
    // from the attack step.
    let user_sid = ctx.open_user_session(user_oid, &user_pin)?;
    let mut sanity_buf = [0u8; 64];
    let n = ctx.read_authed_at(&user_sid, data_oid, &mut sanity_buf)?;
    ctx.close_session(&user_sid);
    ctx.assert_eq("user-auth sanity read returns sentinel", &sanity_buf[..n], &SENTINEL)?;

    // ATTACK: admin-authed READ. Must be refused.
    let admin_sid = ctx.open_admin_session()?;
    let mut attack_buf = [0u8; 64];
    let attack_result = ctx.read_authed_at(&admin_sid, data_oid, &mut attack_buf);
    ctx.close_session(&admin_sid);

    match attack_result {
        Ok(m) => {
            let leaked = m == SENTINEL.len()
                && attack_buf[..m].iter().zip(SENTINEL.iter()).all(|(a, b)| a == b);
            secure_log!(
                "[S][stress][audit-a1] SECURITY FAILURE — admin-auth read returned {} bytes (leaked_sentinel={})",
                m, leaked,
            );
            Err(StressError::Assertion {
                what: "admin-auth read returned data — confidentiality breach (S-5/desolder claim violated)",
                iter: 0,
            })
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-a1] admin-auth read REFUSED with SW=0x{:04x} — confidentiality holds",
                sw,
            );
            Ok(())
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a1] admin-auth read REFUSED with driver error: {:?} — confidentiality holds",
                e,
            );
            Ok(())
        }
    }
}
stress_test!(AUDIT_ADMIN_PASSIVE_READ_REFUSED, "audit_admin_passive_read_refused", Tier::Destructive, audit_admin_passive_read_refused);

// ---------------------------------------------------------------------------
// 9b. audit_write_once_enforced — half_E write-once policy on real silicon
// ---------------------------------------------------------------------------

/// Validates the 2026-06-02 half_E write-once fix (`write_binary_write_once`,
/// whose user policy drops `ALLOW_WRITE`) against real silicon. Two claims
/// no emulator can settle:
///
/// 1. **Create-without-`ALLOW_WRITE` SUCCEEDS** — the brick-risk check.
///    The creating `WriteBinary` is authorized by the SCP03 session, not
///    the (not-yet-existent) object policy, so an object whose policy omits
///    `ALLOW_WRITE` is still creatable. If silicon instead REJECTED the
///    create, production provisioning would brick for *every* user (worse
///    than the desync the fix prevents) — so this is the load-bearing one.
/// 2. **In-place overwrite is REFUSED** — the write-once guarantee. A
///    second `WriteBinary` to the existing OID must fail (expect SW=0x6985
///    "conditions not satisfied"), and the original payload must survive
///    intact (a live PIN session can't silently re-seed half_E).
fn audit_write_once_enforced(ctx: &mut StressCtx) -> StressResult {
    let user_oid = ctx.oid(0x01);
    let wo_oid = ctx.oid(0x02); // write-once: policy WITHOUT ALLOW_WRITE
    let rw_oid = ctx.oid(0x03); // control: policy WITH ALLOW_WRITE
    let user_pin: [u8; 8] = *b"w1userpn";
    // half_E-shaped (32 B) first share + an attempted re-seed.
    const V1: [u8; 32] = [0x91; 32];
    const V2: [u8; 32] = [0x92; 32];

    ctx.delete_scratch(wo_oid)?;
    ctx.delete_scratch(rw_oid)?;
    ctx.delete_scratch(user_oid)?;

    ctx.provision_test_userid(user_oid, &user_pin, 5, AdminPolicy::WithAdminDelete)?;

    // 1. CREATE the write-once object (policy omits ALLOW_WRITE). MUST
    //    succeed — the creating WriteBinary is session-authorized, not
    //    policy-gated. If it failed, production provisioning would brick
    //    for every user (the load-bearing check).
    ctx.try_write_user_gated_data_write_once(wo_oid, &V1, user_oid, Some(STRESS_ADMIN_USERID))
        .map_err(|e| {
            secure_log!(
                "[S][stress][audit-wo] BRICK RISK — create of policy-without-ALLOW_WRITE object FAILED: {:?}",
                e,
            );
            StressError::Assertion {
                what: "SE050 refused to CREATE a write-once (no-ALLOW_WRITE) object — would brick provisioning",
                iter: 0,
            }
        })?;
    secure_log!("[S][stress][audit-wo] create-without-ALLOW_WRITE SUCCEEDED — no provisioning brick");

    // Control object WITH ALLOW_WRITE (default write_binary_gated policy).
    // Same user gating, same data — only the ALLOW_WRITE bit differs.
    ctx.write_user_gated_data(rw_oid, &V1, user_oid, Some(STRESS_ADMIN_USERID))?;

    // Sanity: USER auth reads the write-once share (seed-reconstruction path).
    let sid = ctx.open_user_session(user_oid, &user_pin)?;
    let mut buf = [0u8; 64];
    let n = ctx.read_authed_at(&sid, wo_oid, &mut buf)?;
    ctx.assert_eq("write-once read-back returns V1", &buf[..n], &V1)?;

    // 2a. CONTROL — a session-authed DATA update (the attacker's re-seed
    //     path) on the ALLOW_WRITE object MUST succeed. This proves the
    //     write_authed APDU is well-formed AND a user session can update
    //     an object whose policy grants WRITE — so the refusal at 2b can
    //     ONLY be the missing ALLOW_WRITE, not a malformed command.
    let ctrl = ctx.try_write_authed(&sid, rw_oid, &V2);
    if let Err(e) = &ctrl {
        secure_log!(
            "[S][stress][audit-wo] CONTROL update of ALLOW_WRITE object FAILED: {:?} (APDU format suspect — verdict inconclusive)",
            e,
        );
    }
    ctx.assert_true("control: ALLOW_WRITE object accepts session data update", ctrl.is_ok())?;
    let m = ctx.read_authed_at(&sid, rw_oid, &mut buf)?;
    ctx.assert_eq("control object mutated to V2", &buf[..m], &V2)?;

    // 2b. WRITE-ONCE — the IDENTICAL session-authed data update on the
    //     no-ALLOW_WRITE object MUST be refused.
    let attack = ctx.try_write_authed(&sid, wo_oid, &V2);
    match attack {
        Ok(()) => {
            secure_log!(
                "[S][stress][audit-wo] SECURITY FAILURE — write-once object ACCEPTED a session data update (ALLOW_WRITE gate ineffective)"
            );
            ctx.close_session(&sid);
            return Err(StressError::Assertion {
                what: "write-once object updated via session — half_E re-seedable by a PIN session",
                iter: 0,
            });
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-wo] write-once data update REFUSED with SW=0x{:04x} — ALLOW_WRITE gate holds",
                sw,
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-wo] write-once data update REFUSED with driver error: {:?} — ALLOW_WRITE gate holds",
                e,
            );
        }
    }

    // 3. The write-once share MUST survive the refused update intact (V1).
    //    The policy-denied write (0x6986) invalidates the SE050 session (a
    //    later read on it returns 0x6a80), so recover via reinit + a fresh
    //    session before the survival read — this also makes it the stronger
    //    check: the share is unchanged across a simulated power cycle.
    ctx.close_session(&sid);
    ctx.se().reinit()?;
    let sid2 = ctx.open_user_session(user_oid, &user_pin)?;
    let s = ctx.read_authed_at(&sid2, wo_oid, &mut buf)?;
    ctx.close_session(&sid2);
    ctx.assert_eq("write-once payload survives refused update", &buf[..s], &V1)?;

    secure_log!(
        "[S][stress][audit-wo] PASS: create ok (no brick); control accepts update; write-once refuses + survives"
    );
    Ok(())
}
stress_test!(AUDIT_WRITE_ONCE_ENFORCED, "audit_write_once_enforced", Tier::Destructive, audit_write_once_enforced);

// ---------------------------------------------------------------------------
// 9c. audit_se050_version_identity — anti-substitution OEF/variant check
// ---------------------------------------------------------------------------

/// Anti-substitution variant check (work-todo #651). Reads the SE050
/// EXTENDED applet VersionInfo and pins the **AppletConfig** — the variant
/// feature fingerprint that is fixed by the ordered OEF, so a substituted
/// different-variant part (e.g. SE050F, which adds FIPS + forces SCP) reports
/// a different value. Non-breaking: an unauthenticated identity read, no
/// state change.
///
/// **Finding (2026-06-02 silicon):** the OEF id is an ORDERING identifier and
/// is NOT present anywhere in the GetVersion response — so the runtime check
/// pins AppletConfig, not the OEF. The OM-SE050ARD-E bench part (SE050E2, OEF
/// `0xA921`) reports applet `v7.2.0`, `AppletConfig=0x3F9F`,
/// `SecureBox=0xFFFF`. 7-byte VersionInfo layout per AN12413:
/// `[major][minor][patch][AppletConfig:2 BE][SecureBox:2 BE]`.
///
/// **Production part = SE050C2HQ1/Z01SDZ (OEF `0xA201`, applet 3.x).** Its
/// AppletConfig is a different, not-yet-captured fingerprint (see
/// `ACCEPTED_APPLET_CONFIGS` below); the GetVersion SELECT/APDU shape is
/// generation-identical, so only the expected value differs.
fn audit_se050_version_identity(ctx: &mut StressCtx) -> StressResult {
    // Anti-substitution AppletConfig fingerprints — the variant feature bitmap
    // (AN12413 §4.3.23 Table 40), silicon-captured per part (NXP does not
    // publish it, and it is NOT the OEF id). A substituted different-variant
    // part reports a value not in this list and fails the gate below.
    //
    //   SE050E2 (OM-SE050ARD-E bench): 0x3F9F, captured 2026-06-02.
    //   SE050C2 (SE050C2HQ1/Z01SDZ, the finalized production part): NOT YET
    //     CAPTURED — the C2's feature set differs from the E2's (no
    //     Curve448/GMAC/CCM-GCM), so its fingerprint differs too. On the first
    //     C2 bring-up read the `AppletConfig=0x....` value logged below and add
    //     it here; until then a C2 run fails this gate LOUDLY with its observed
    //     value in the log (the intended capture workflow).
    const ACCEPTED_APPLET_CONFIGS: &[u16] = &[
        0x3F9F, // SE050E2 (bench)
        // TODO(C2-silicon): 0x____, // SE050C2 (SE050C2HQ1/Z01SDZ) — capture + pin
    ];

    let mut buf = [0u8; 48];
    let n = ctx.get_version_ext(&mut buf)?;
    ctx.assert_true("GetVersion returned >=7 bytes", n >= 7)?;

    let applet_config = ((buf[3] as u16) << 8) | buf[4] as u16;
    secure_log!(
        "[S][stress][audit-ver] applet v{}.{}.{} AppletConfig=0x{:04x} SecureBox=0x{:02x}{:02x}",
        buf[0], buf[1], buf[2], applet_config, buf[5], buf[6]
    );

    // Log the remaining ext bytes in 4-byte windows (no_std — no slice fmt).
    let mut j = 7;
    while j < n {
        let b0 = buf[j];
        let b1 = if j + 1 < n { buf[j + 1] } else { 0 };
        let b2 = if j + 2 < n { buf[j + 2] } else { 0 };
        let b3 = if j + 3 < n { buf[j + 3] } else { 0 };
        secure_log!(
            "[S][stress][audit-ver] vinfo[{}..]: {:02x} {:02x} {:02x} {:02x}",
            j, b0, b1, b2, b3
        );
        j += 4;
    }

    // Anti-substitution: accept only a pinned known-good fingerprint. Once the
    // SE050C2 value is captured and added above, this confirms the production
    // C2; until then only the E2 bench value passes.
    ctx.assert_true(
        "AppletConfig matches a pinned SE050E2/SE050C2 fingerprint (anti-substitution)",
        ACCEPTED_APPLET_CONFIGS.contains(&applet_config),
    )?;
    secure_log!(
        "[S][stress][audit-ver] PASS: known SE050 variant (AppletConfig 0x{:04x})",
        applet_config
    );
    Ok(())
}
stress_test!(AUDIT_SE050_VERSION_IDENTITY, "audit_se050_version_identity", Tier::Safe, audit_se050_version_identity);

// ---------------------------------------------------------------------------
// 10. audit_unauth_read_refused
// ---------------------------------------------------------------------------

/// Provision a sentinel under USER-PIN gating, then send a top-level
/// `INS_READ` APDU (no `INS_PROCESS` wrap, no UserID session) over the
/// established SCP03 transport. The chip MUST refuse — the object's
/// policy demands `ALLOW_READ` granted via a session authenticated
/// against the user UserID, and transport SCP03 alone does NOT satisfy
/// a session-auth policy entry.
///
/// This probes the silicon's default-deny behavior, distinct from
/// `audit_admin_passive_read_refused` (which tests "wrong session
/// auth"): this test asks "what about NO session auth at all". A bug
/// where the chip treated transport SCP03 as an anonymous session that
/// satisfied any UserID auth entry would leak every gated object.
///
/// PASS = `Err(Se050Error::Status(non-9000))` or driver error.
/// FAIL = read returned bytes that match the sentinel.
fn audit_unauth_read_refused(ctx: &mut StressCtx) -> StressResult {
    let user_oid = ctx.oid(0x01);
    let data_oid = ctx.oid(0x02);
    let user_pin: [u8; 8] = *b"a3userpn";
    const SENTINEL: [u8; 32] = [
        0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
        0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
        0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
        0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
    ];

    ctx.delete_scratch(data_oid)?;
    ctx.delete_scratch(user_oid)?;

    ctx.provision_test_userid(user_oid, &user_pin, 5, AdminPolicy::WithAdminDelete)?;
    ctx.write_user_gated_data(data_oid, &SENTINEL, user_oid, Some(STRESS_ADMIN_USERID))?;

    // Attack: top-level ReadBinary, no INS_PROCESS, no session.
    let mut buf = [0u8; 64];
    match ctx.try_unauth_read(data_oid, &mut buf) {
        Ok(m) => {
            // Possible TLV envelope around the data; the apdu layer
            // strips SW1/SW2 in `send_apdu`, but TLV wrappers from
            // INS_READ can still be present. Search for the sentinel
            // pattern in the returned bytes — finding it = leak.
            let contains_sentinel = buf[..m]
                .windows(SENTINEL.len())
                .any(|w| w.iter().zip(SENTINEL.iter()).all(|(a, b)| a == b));
            secure_log!(
                "[S][stress][audit-a3] SECURITY FAILURE — unauth top-level READ returned {} bytes (sentinel_present={})",
                m, contains_sentinel,
            );
            Err(StressError::Assertion {
                what: "unauth ReadBinary returned data — transport SCP03 alone bypassed policy gate",
                iter: 0,
            })
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-a3] unauth READ REFUSED with SW=0x{:04x} — policy gate holds",
                sw,
            );
            Ok(())
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a3] unauth READ REFUSED with driver error: {:?} — policy gate holds",
                e,
            );
            Ok(())
        }
    }
}
stress_test!(AUDIT_UNAUTH_READ_REFUSED, "audit_unauth_read_refused", Tier::Safe, audit_unauth_read_refused);

// ---------------------------------------------------------------------------
// 11. audit_admin_cannot_rotate_user_pin
// ---------------------------------------------------------------------------

/// S-6 closes admin DELETE of a user UserID with no admin policy entry.
/// This test probes the adjacent attack vector: in-place UPDATE of an
/// existing user UserID. If a transport-SCP03 caller could send
/// `INS_WRITE | INS_AUTH_OBJECT` at the user OID and silently swap the
/// PIN, the substitution-attack chain reopens via a different APDU than
/// DELETE+CREATE.
///
/// Per AN12413 §4.7, UPDATE of an existing AUTH_OBJECT must check the
/// existing policy for `ALLOW_WRITE` granted to the current session's
/// auth. Our user policy grants `ALLOW_WRITE` only to the user's own
/// auth entry; admin's entry has only `ALLOW_DELETE`. Transport SCP03
/// has no UserID session at all. So both the "no session" and "admin
/// session" cases MUST be refused, leaving the original UserID intact.
///
/// **Finding A2 RETRACTED (2026-05-28, second silicon run).** An
/// earlier draft of this test claimed the failed UPDATE *destroys* the
/// UserID ("delete-then-create that aborts after the delete" — a DoS).
/// That was WRONG: it was an artifact of Finding A3. In run 1 the
/// post-attack `check_exists` returned SW=0x6982 — which we misread as
/// "object gone" — but 0x6982 was the chip's session-pending TRANSIENT
/// left by the refused write, NOT a deletion. Run 2 inserts a
/// `reinit()` after the attack (clearing the A3 transient) and the
/// follow-up `check_exists` returns 0x9000 PRESENT: the UserID
/// **survives** the refused UPDATE fully intact, and the original
/// `user_pin` still authenticates. So the chip behaves correctly —
/// the transport/admin-context UPDATE is cleanly refused (SW=0x6985)
/// AND the original credential is preserved. No DoS, no substitution.
/// See `docs/secure-elements/se050-silicon-findings.md` §3.
///
/// Sequence per attack:
///   1. Provision USERID with `user_pin`; sanity-check `user_pin` works.
///   2. ATTACK: transport-level `write_userid(user_oid, attacker_pin,…)`
///      → must be refused (Err).
///   3. `reinit()` to clear the A3 session-pending transient the
///      refused write leaves behind.
///   4. Assert the UserID SURVIVES (`check_exists` → true).
///   5. Assert `user_pin` STILL opens a session (credential intact).
///   6. Assert `attacker_pin` does NOT open a session (no substitution).
///
/// PASS = refused + UserID survives + user_pin works + attacker_pin
/// rejected, under both transport-only (A) and admin-session-context
/// (B) attack contexts.
/// FAIL = (a) attack returns Ok, (b) UserID vanished, (c) user_pin
/// stops working, or (d) attacker_pin opens a session.
fn audit_admin_cannot_rotate_user_pin(ctx: &mut StressCtx) -> StressResult {
    let user_oid = ctx.oid(0x01);
    let user_pin:  [u8; 8] = *b"a4userpn";
    let attacker_pin: [u8; 8] = *b"eviltest";

    // -------- ATTACK A: transport-level WriteUserID (no session) --------

    ctx.delete_scratch(user_oid)?;
    ctx.provision_test_userid(user_oid, &user_pin, 5, AdminPolicy::WithAdminDelete)?;

    // Sanity: user PIN works on the freshly-provisioned UserID.
    let sid = ctx.open_user_session(user_oid, &user_pin)?;
    ctx.close_session(&sid);

    run_rotate_attack(ctx, user_oid, &user_pin, &attacker_pin, "A", None)?;

    // -------- ATTACK B: same APDU, admin session open in parallel --------

    let admin_sid = ctx.open_admin_session()?;
    run_rotate_attack(ctx, user_oid, &user_pin, &attacker_pin, "B", Some(admin_sid))?;

    secure_log!(
        "[S][stress][audit-a4] PASS: WriteUserID UPDATE refused under both transport and \
         admin-session contexts — UserID survives intact, user PIN still works, attacker \
         PIN never installs. Substitution chain stays closed (A2 retracted: no DoS).",
    );
    Ok(())
}

/// One rotate-attack pass: fire the transport `write_userid` UPDATE,
/// assert refusal, reinit to clear the A3 transient, then assert the
/// UserID + original PIN survive and the attacker PIN does not work.
/// `admin_sid`, if `Some`, is an open admin session held in parallel
/// (the worst-case context for attack B) and is closed before the
/// post-attack reinit.
fn run_rotate_attack(
    ctx: &mut StressCtx,
    user_oid: u32,
    user_pin: &[u8],
    attacker_pin: &[u8],
    label: &str,
    admin_sid: Option<crate::se050_stress::ctx::SessionId>,
) -> StressResult {
    let attack = ctx.try_write_userid_transport(user_oid, attacker_pin, 5, Some(STRESS_ADMIN_USERID));

    // Close the parallel admin session (attack B) before any reinit.
    if let Some(sid) = admin_sid {
        ctx.close_session(&sid);
    }

    match attack {
        Ok(()) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} SECURITY FAILURE — WriteUserID UPDATE succeeded on existing user OID",
                label,
            );
            return Err(StressError::Assertion {
                what: "WriteUserID UPDATE returned Ok on an existing user OID",
                iter: 0,
            });
        }
        Err(Se050Error::Status(sw)) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} refused with SW=0x{:04x} (expected)",
                label, sw,
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} refused with driver error: {:?}",
                label, e,
            );
        }
    }

    // A3 recovery: the refused write leaves the chip session-pending.
    // Flush it so the survival probes below read the REAL chip state
    // rather than the 0x6982 transient (which run 1 misread as
    // "destroyed", the false A2 finding).
    let _ = ctx.se().reinit();

    // The UserID must SURVIVE the refused UPDATE (A2 retracted).
    match ctx.check_exists(user_oid) {
        Ok(true) => {
            secure_log!(
                "[S][stress][audit-a4] attack {}: UserID survives the refused UPDATE (correct)",
                label,
            );
        }
        Ok(false) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} FAILURE — UserID vanished after refused UPDATE",
                label,
            );
            return Err(StressError::Assertion {
                what: "UserID destroyed by a refused WriteUserID UPDATE",
                iter: 0,
            });
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} check_exists err {:?} after reinit",
                label, e,
            );
            return Err(e.into());
        }
    }

    // The original user PIN must STILL work (credential intact).
    match ctx.open_user_session(user_oid, user_pin) {
        Ok(sid) => {
            ctx.close_session(&sid);
            secure_log!(
                "[S][stress][audit-a4] attack {}: original user PIN still authenticates (correct)",
                label,
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a4] attack {} FAILURE — original user PIN stopped working: {:?}",
                label, e,
            );
            return Err(e);
        }
    }

    // The attacker PIN must NOT open a session (no substitution).
    match ctx.open_user_session(user_oid, attacker_pin) {
        Ok(sid) => {
            ctx.close_session(&sid);
            secure_log!(
                "[S][stress][audit-a4] attack {} SECURITY FAILURE — attacker PIN opened a session (PIN was rotated)",
                label,
            );
            Err(StressError::Assertion {
                what: "attacker PIN opens session — UPDATE silently installed the new PIN",
                iter: 0,
            })
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a4] attack {}: attacker PIN rejected ({:?}) — no substitution",
                label, e,
            );
            Ok(())
        }
    }
}
stress_test!(AUDIT_ADMIN_CANNOT_ROTATE_USER_PIN, "audit_admin_cannot_rotate_user_pin", Tier::Destructive, audit_admin_cannot_rotate_user_pin);

// ---------------------------------------------------------------------------
// 12. audit_data_substitution_chip_level
// ---------------------------------------------------------------------------

/// **Scope: SE050 chip layer ONLY.** This test asserts what the silicon
/// itself does. The *system*-level protection that absorbs this chip
/// behavior is a separate concern (see "Why this is not the system's
/// final defense" below) and out of scope here.
///
/// **What the test proves on silicon.** SE050 has no CREATE-ACL on
/// freed OIDs: after admin DELETEs a user-gated data object, the OID
/// becomes a blank slot that any caller holding the SCP03 transport
/// session can re-populate with arbitrary `(payload, policy)`. The
/// chip does NOT remember "this OID used to be owned by entity X" —
/// it forgets the object completely and treats the next write as a
/// fresh creation. The next user PIN session reading the OID
/// therefore gets back ATTACKER bytes through the ORIGINAL UserID
/// session, exactly as if the user had stored those bytes themselves.
///
/// Sequence:
///   1. Provision USER UserID + DATA gated by user (admin-delete entry).
///   2. Sanity: user-auth read returns ORIGINAL.
///   3. Admin DELETE on DATA → MUST succeed (`ALLOW_DELETE` policy).
///   4. Transport-SCP03 (no UserID session) WriteBinary at the SAME OID
///      with `(ATTACKER payload, user_userid → ALLOW_READ policy)` →
///      MUST succeed (no chip-level CREATE-ACL).
///   5. User-auth READ → MUST return ATTACKER bytes (the chip can't
///      tell who wrote them; policy is satisfied; bytes are released).
///
/// PASS = all three steps succeed as described.
/// FAIL = any step blocked unexpectedly — silicon is more defensive
/// than the chip-layer threat model claims; investigate and update
/// the firmware's defense-in-depth assumptions (one less layer needed
/// upstream).
///
/// **What this test does NOT claim.** This test does NOT show that
/// `half_E` is extractable, that the seed is recoverable, or that the
/// wallet's confidentiality is broken. It claims only that the SE050,
/// at the chip layer, will execute the delete-then-substitute sequence
/// when the caller holds admin auth + SCP03 transport. The systemic
/// outcome depends on the firmware layer above, which is not what this
/// test exercises.
///
/// **Why this is not the system's final defense — pointer for the
/// auditor.** The actual barrier against a substitution-attack
/// payoff lives in `secure/src/dual_se.rs`'s unlock path (`[DUAL] CRITICAL: reconstructed entropy…`): after both
/// halves are read and XORed, the firmware re-derives
/// `kdf("sphincs-master", full_entropy, 0)` and compares against
/// OPTIGA's independently-stored `master_o`. A single-SE substitution
/// (this test's chain on SE050 alone) fails that check and aborts
/// unlock with `CRITICAL: reconstructed entropy doesn't match
/// master!`. A two-SE coordinated substitution (also tampering
/// OPTIGA in lockstep) defeats the check but only *installs* an
/// attacker-chosen seed — the original seed never leaves the device.
/// The remaining detection vector is the 8-word measurement
/// fingerprint on the OLED (CLAUDE.md "Trusted-display clear-
/// signing"), which the user must validate against an out-of-band
/// reference before first funding. None of those upstream defenses
/// are silicon-layer; they belong in a firmware-layer test.
fn audit_data_substitution_chip_level(ctx: &mut StressCtx) -> StressResult {
    let user_oid = ctx.oid(0x01);
    let data_oid = ctx.oid(0x02);
    let user_pin: [u8; 8] = *b"a2userpn";
    const ORIGINAL: [u8; 32] = [
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    const ATTACKER: [u8; 32] = [
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    ];

    ctx.delete_scratch(data_oid)?;
    ctx.delete_scratch(user_oid)?;

    ctx.provision_test_userid(user_oid, &user_pin, 5, AdminPolicy::WithAdminDelete)?;
    ctx.write_user_gated_data(data_oid, &ORIGINAL, user_oid, Some(STRESS_ADMIN_USERID))?;

    // Step 1 (setup sanity).
    let user_sid = ctx.open_user_session(user_oid, &user_pin)?;
    let mut sanity_buf = [0u8; 64];
    let n = ctx.read_authed_at(&user_sid, data_oid, &mut sanity_buf)?;
    ctx.close_session(&user_sid);
    ctx.assert_eq("setup sanity: user reads ORIGINAL", &sanity_buf[..n], &ORIGINAL)?;
    secure_log!("[S][stress][audit-a2] step 1: sanity OK — user reads ORIGINAL ({} B)", n);

    // Step 2: admin DELETE — strict assertion (DoS-wipe path is documented).
    let admin_sid = ctx.open_admin_session()?;
    let del_r = ctx.delete_authed(&admin_sid, data_oid);
    ctx.close_session(&admin_sid);
    if let Err(e) = del_r {
        secure_log!(
            "[S][stress][audit-a2] step 2: admin delete FAILED ({:?}) — DoS-wipe path is broken",
            e,
        );
        return Err(StressError::Assertion {
            what: "admin delete refused on data object — ALLOW_DELETE policy not honoured",
            iter: 0,
        });
    }
    if ctx.check_exists(data_oid).unwrap_or(true) {
        secure_log!("[S][stress][audit-a2] step 2: admin reported delete OK but object still present");
        return Err(StressError::Assertion {
            what: "object survived admin delete (silicon-level inconsistency)",
            iter: 0,
        });
    }
    secure_log!("[S][stress][audit-a2] step 2: admin delete OK — OID freed");

    // Step 3: transport-SCP03 substitution write — strict assertion.
    let subst_r = ctx.try_write_user_gated_data(
        data_oid,
        &ATTACKER,
        user_oid,
        Some(STRESS_ADMIN_USERID),
    );
    match &subst_r {
        Ok(()) => {
            secure_log!(
                "[S][stress][audit-a2] step 3: substitution write OK — chip has no CREATE-ACL on freed OID",
            );
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a2] step 3: substitution write REFUSED ({:?}) — silicon has a CREATE-ACL not in the chip-layer threat model; review upstream defenses (one less layer needed)",
                e,
            );
            return Err(StressError::Assertion {
                what: "substitution write refused — silicon stronger than chip-layer model claims",
                iter: 0,
            });
        }
    }

    // Step 4: user-auth read MUST return ATTACKER bytes.
    let user_sid2 = ctx.open_user_session(user_oid, &user_pin)?;
    let mut read_buf = [0u8; 64];
    let read_r = ctx.read_authed_at(&user_sid2, data_oid, &mut read_buf);
    ctx.close_session(&user_sid2);

    match read_r {
        Ok(m) => {
            let is_attacker = m == ATTACKER.len()
                && read_buf[..m].iter().zip(ATTACKER.iter()).all(|(a, b)| a == b);
            let is_original = m == ORIGINAL.len()
                && read_buf[..m].iter().zip(ORIGINAL.iter()).all(|(a, b)| a == b);
            if is_attacker {
                secure_log!(
                    "[S][stress][audit-a2] step 4: user-auth read returns ATTACKER ({} B) — chip-layer substitution chain complete. Firmware-layer mitigation (dual_se.rs unlock kdf(entropy)==master consistency check) is the systemic backstop.",
                    m,
                );
                Ok(())
            } else if is_original {
                secure_log!(
                    "[S][stress][audit-a2] step 4: read returns ORIGINAL — impossible after a confirmed delete+write; chip is reporting state from a hidden cache or write was silently aborted",
                );
                Err(StressError::Assertion {
                    what: "post-substitution read returned ORIGINAL bytes (silicon anomaly)",
                    iter: 0,
                })
            } else {
                secure_log!(
                    "[S][stress][audit-a2] step 4: read returns {} bytes, neither ATTACKER nor ORIGINAL — chip mutated the substituted payload",
                    m,
                );
                Err(StressError::Assertion {
                    what: "post-substitution read returned neither attacker nor original (silicon anomaly)",
                    iter: 0,
                })
            }
        }
        Err(e) => {
            secure_log!(
                "[S][stress][audit-a2] step 4: user-auth read REFUSED ({:?}) — silicon honoured a residual policy on the freed OID, blocking the substitution at read time. Chip-layer model overstates substitution; update threat model.",
                e,
            );
            Err(StressError::Assertion {
                what: "post-substitution user read refused — silicon enforces residual policy, chip-layer threat model overstated",
                iter: 0,
            })
        }
    }
}
stress_test!(AUDIT_DATA_SUBSTITUTION_CHIP_LEVEL, "audit_data_substitution_chip_level", Tier::Destructive, audit_data_substitution_chip_level);
