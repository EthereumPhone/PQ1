//! #989 silicon tests: the production `half_E` object policy and the
//! platform-SCP credential gate (DVT §6B.23, 6B.5).
//!
//! The SE050E2 ships `SCP_NOT_REQUIRED`, so until the firmware sets
//! `SCP_REQUIRED` the confidentiality of `half_E` against a bus party rests on
//! the object policy alone. `policy_halfe_plain_refused` proves that policy on
//! a PRESENT object — the 2026-10-19 probe's plain `Read(ENTROPY_OBJ)` was
//! vacuous because the object was absent. Run it while the die is still
//! `SCP_NOT_REQUIRED`: under `SCP_REQUIRED` every plain command is refused
//! anyway and the plain leg proves nothing about the policy (the test says so
//! in its log).
//!
//! The two `platform_scp_set_refused_*` tests check that the applet only
//! takes `SetPlatformSCPRequest` from a `RESERVED_ID_PLATFORM_SCP` session.
//! They send `SCP_NOT_REQUIRED`, so they are no-ops on a factory die even if
//! the chip wrongly accepted the command; on a die already at `SCP_REQUIRED`
//! a wrong acceptance would release it — which is exactly the finding.

use crate::se050::apdu::{self, Se050Error};
use crate::se050_stress::ctx::AdminPolicy;
use crate::se050_stress::oid::STRESS_ADMIN_USERID;
use crate::se050_stress::{StressCtx, StressError, StressResult, Tier};
use crate::stress_test;

/// Interface-reset attempts after the power cycle (~50 ms apart), as the
/// probe's pre-session leg.
const RESET_ATTEMPTS: u32 = 20;

/// The plain (no-SCP03) leg: SE rail power cycle (no session survives),
/// T=1 reset, plain SELECT, then plain Read / Write / Delete of `obj`.
/// Returns `(read_sw, read_len, write_sw, delete_sw)`. Leaves the driver
/// re-initialised over SCP03. Fails as INCONCLUSIVE when the chip already
/// refuses every plain command (`SCP_REQUIRED`): the policy is then untested,
/// and a PASS would overclaim.
fn plain_leg(ctx: &mut StressCtx, obj: u32) -> Result<(u16, usize, u16, u16), StressError> {
    let cycled = crate::hw::se_power::power_cycle(100);
    crate::hw::i2c_hw::init();
    if !cycled {
        secure_log!("[S][stress][6B.23] no SE rail enable on this board — plain leg not isolated");
    }
    let r = {
        let (t1, _scp) = ctx.t1_scp03();
        // SAFETY: single-threaded stress runner; plain frames on this
        // driver's own T=1 state, no secret in them.
        unsafe {
            let mut up = false;
            for _ in 0..RESET_ATTEMPTS {
                if t1.interface_reset().is_ok() {
                    up = true;
                    break;
                }
                cortex_m::asm::delay(8_000_000);
            }
            if !up {
                return Err(StressError::Timeout("6B.23 T=1 reset after power cycle"));
            }
            let mut o = [0u8; 64];
            let (sel, _) = apdu::select_applet_probe(t1, &mut o)?;
            if sel != 0x9000 {
                return Err(StressError::UnexpectedSw { what: "6B.23 plain SELECT", sw: sel });
            }
            let (psw, pbody, pn) = apdu::platform_scp_plain_probe(t1)?;
            secure_log!("[S][stress][6B.23] chip platform-SCP probe SW=0x{:04x} body_len={}", psw, pn);
            if psw == 0x9000 && pbody[..pn] == [0x41, 0x01, 0x01] {
                let (rsw, rn) = apdu::plain_readclass_probe(t1, apdu::PlainReadCmd::Read(obj), &mut o)?;
                let wsw = apdu::plain_mutate_stress(t1, apdu::PlainMutateCmd::Write(obj, &[0x00; 32]))?;
                let dsw = apdu::plain_mutate_stress(t1, apdu::PlainMutateCmd::Delete(obj))?;
                Some((rsw, rn, wsw, dsw))
            } else {
                None
            }
        }
    };
    ctx.se().reinit()?;
    r.ok_or(StressError::Assertion {
        what: "6B.23 INCONCLUSIVE: the chip refuses plain commands (SCP_REQUIRED?) — run before `require`",
        iter: 0,
    })
}

/// Remove the 6B.23 carve-out objects through the admin path (the
/// production wipe path), user UserID last.
fn cleanup(ctx: &mut StressCtx, obj: u32, user: u32) -> StressResult {
    if ctx.check_exists(obj)? {
        let sid = ctx.open_admin_session()?;
        let r = ctx.delete_authed(&sid, obj);
        ctx.close_session(&sid);
        ctx.se().reinit()?;
        r?;
    }
    ctx.delete_scratch(user)
}

/// SWs that mean "the applet refused this command on policy / session
/// grounds" (AN12413 §4.3.1: 6982 security status, 6985 conditions, 6986
/// not allowed). A framing refusal (6A80, 6700, 6D00…) is not a pass.
const POLICY_REFUSAL_SWS: [u16; 3] = [0x6982, 0x6985, 0x6986];

// ---------------------------------------------------------------------------
// 6B.23 — the production half_E policy on a present object
// ---------------------------------------------------------------------------

/// A carve-out UserID with the production user policy plus the bench
/// admin-delete entry, and a data object created with
/// `write_binary_write_once` — the exact `half_E` policy
/// (`READ|DELETE|REQUIRE_SM` for the user, `DELETE|REQUIRE_SM` for admin).
///
/// | who                         | read     | write    | delete   |
/// |-----------------------------|----------|----------|----------|
/// | plain bus party (no SCP03)  | refused  | refused  | refused  |
/// | SCP03, no UserID session    | refused  |          |          |
/// | admin session               | refused  |          | allowed  |
/// | user session                | allowed  | refused  |          |
fn policy_halfe_plain_refused(ctx: &mut StressCtx) -> StressResult {
    const V: [u8; 32] = [0x6B; 32];
    let user = ctx.oid(0x01);
    let obj = ctx.oid(0x02);
    let pin: [u8; 8] = *b"6b23user";

    ctx.delete_scratch(obj)?;
    ctx.delete_scratch(user)?;
    ctx.provision_test_userid(user, &pin, 10, AdminPolicy::WithAdminDelete)?;
    ctx.try_write_user_gated_data_write_once(obj, &V, user, Some(STRESS_ADMIN_USERID))?;

    // 1. Plain bus party. On any failure here (including INCONCLUSIVE on a
    // chip at SCP_REQUIRED) remove the carve-out objects before reporting.
    let (rsw, rn, wsw, dsw) = match plain_leg(ctx, obj) {
        Ok(r) => r,
        Err(e) => {
            let _ = ctx.se().reinit();
            let _ = cleanup(ctx, obj, user);
            return Err(e);
        }
    };
    secure_log!(
        "[S][stress][6B.23] plain read SW=0x{:04x} len={} write SW=0x{:04x} delete SW=0x{:04x}",
        rsw, rn, wsw, dsw,
    );
    ctx.assert_true("plain read of the half_E-policy object refused", rsw != 0x9000 && rn == 0)?;
    ctx.assert_true("plain write of the half_E-policy object refused", wsw != 0x9000)?;
    ctx.assert_true("plain delete of the half_E-policy object refused", dsw != 0x9000)?;
    let survived = ctx.check_exists(obj)?;
    ctx.assert_true("object survives the plain leg", survived)?;

    // 2. SCP03, no UserID session.
    let mut buf = [0u8; 64];
    match ctx.try_unauth_read(obj, &mut buf) {
        Ok(n) => {
            secure_log!("[S][stress][6B.23] SECURITY FAILURE — session-less SCP03 read returned {} bytes", n);
            return Err(StressError::Assertion { what: "half_E-policy object readable without a UserID session", iter: 0 });
        }
        Err(e) => {
            secure_log!("[S][stress][6B.23] session-less SCP03 read refused: {:?}", e);
        }
    }

    // 3. Admin session: may delete, may not read.
    {
        let sid = ctx.open_admin_session()?;
        let r = ctx.read_authed_at(&sid, obj, &mut buf);
        ctx.close_session(&sid);
        if let Ok(n) = r {
            secure_log!("[S][stress][6B.23] SECURITY FAILURE — admin session read {} bytes", n);
            return Err(StressError::Assertion { what: "admin session can read the half_E-policy object", iter: 0 });
        }
        ctx.se().reinit()?;
    }

    // 4. User session: reads the intact value, cannot overwrite it.
    {
        let sid = ctx.open_user_session(user, &pin)?;
        let n = ctx.read_authed_at(&sid, obj, &mut buf)?;
        ctx.assert_eq("user session reads the untouched value", &buf[..n], &V)?;
        let w = ctx.try_write_authed(&sid, obj, &[0x00; 32]);
        ctx.close_session(&sid);
        match w {
            Ok(()) => {
                return Err(StressError::Assertion { what: "user session overwrote the write-once object", iter: 0 });
            }
            Err(Se050Error::Status(sw)) => {
                secure_log!("[S][stress][6B.23] user overwrite refused SW=0x{:04x}", sw);
            }
            Err(e) => {
                secure_log!("[S][stress][6B.23] user overwrite refused: {:?}", e);
            }
        }
        ctx.se().reinit()?;
    }

    // 5. Cleanup through the admin path (the production wipe path).
    cleanup(ctx, obj, user)?;
    let gone = !ctx.check_exists(obj)?;
    ctx.assert_true("admin deleted the object", gone)?;
    secure_log!("[S][stress][6B.23] half_E policy matrix holds on a present object");
    Ok(())
}
stress_test!(POLICY_HALFE_PLAIN_REFUSED, "policy_halfe_plain_refused", Tier::Safe, policy_halfe_plain_refused);

// ---------------------------------------------------------------------------
// 6B.5 — SetPlatformSCPRequest only from a RESERVED_ID_PLATFORM_SCP session
// ---------------------------------------------------------------------------

/// `SetPlatformSCPRequest` with no session (platform SCP03 only) must be
/// refused (AN12413 §4.6.2).
fn platform_scp_set_refused_without_session(ctx: &mut StressCtx) -> StressResult {
    let r = {
        let (t1, scp03) = ctx.t1_scp03();
        // SAFETY: single-threaded stress runner; one SCP03 APDU.
        unsafe { apdu::set_platform_scp_request_no_session_stress(t1, scp03) }
    };
    match r {
        Ok(()) => Err(StressError::Assertion {
            what: "SetPlatformSCPRequest accepted without a RESERVED_ID_PLATFORM_SCP session",
            iter: 0,
        }),
        Err(Se050Error::Status(sw)) if POLICY_REFUSAL_SWS.contains(&sw) => {
            secure_log!("[S][stress][6B.5] session-less SetPlatformSCPRequest refused SW=0x{:04x}", sw);
            Ok(())
        }
        Err(Se050Error::Status(sw)) => Err(StressError::UnexpectedSw {
            what: "session-less SetPlatformSCPRequest refused for a non-policy reason (framing?)",
            sw,
        }),
        Err(e) => Err(e.into()),
    }
}
stress_test!(
    PLATFORM_SCP_SET_REFUSED_WITHOUT_SESSION,
    "platform_scp_set_refused_without_session",
    Tier::Safe,
    platform_scp_set_refused_without_session
);

/// The same command from an ordinary (carve-out) UserID session must be
/// refused: only the `0x7FFF0207` credential may change the requirement.
fn platform_scp_set_refused_from_carveout_session(ctx: &mut StressCtx) -> StressResult {
    let user = ctx.oid(0x01);
    let pin: [u8; 8] = *b"6b5user!";
    ctx.delete_scratch(user)?;
    ctx.provision_test_userid_unlimited(user, &pin, AdminPolicy::WithAdminDelete)?;
    let sid = ctx.open_user_session(user, &pin)?;
    let r = {
        let (t1, scp03) = ctx.t1_scp03();
        // SAFETY: single-threaded stress runner; one SCP03 APDU.
        unsafe { apdu::set_platform_scp_request(t1, scp03, &sid, apdu::PlatformScpRequest::NotRequired) }
    };
    ctx.close_session(&sid);
    ctx.se().reinit()?;
    ctx.delete_scratch(user)?;
    match r {
        Ok(()) => Err(StressError::Assertion {
            what: "SetPlatformSCPRequest accepted from an ordinary UserID session",
            iter: 0,
        }),
        Err(Se050Error::Status(sw)) if POLICY_REFUSAL_SWS.contains(&sw) => {
            secure_log!("[S][stress][6B.5] carve-out-session SetPlatformSCPRequest refused SW=0x{:04x}", sw);
            Ok(())
        }
        Err(Se050Error::Status(sw)) => Err(StressError::UnexpectedSw {
            what: "carve-out-session SetPlatformSCPRequest refused for a non-policy reason (framing?)",
            sw,
        }),
        Err(e) => Err(e.into()),
    }
}
stress_test!(
    PLATFORM_SCP_SET_REFUSED_FROM_CARVEOUT_SESSION,
    "platform_scp_set_refused_from_carveout_session",
    Tier::Safe,
    platform_scp_set_refused_from_carveout_session
);
