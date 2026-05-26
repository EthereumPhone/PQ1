//! Reversible firmware anti-rollback test (`fw-rollback-e2e`).
//!
//! Drives the REAL [`crate::fw_update::verify_manifest`] — the exact verify
//! chain the `FW_BEGIN` gateway runs (structural → CRC → digest → vendor-fpr
//! → FI-hardened SPHINCS+C10 signature → rollback floor) — with dev-key-signed
//! v1/v2/v3 manifests against literal test floors. It proves the
//! downgrade-rejection behaviour with **zero irreversible side effects**: no
//! OTP bump, no flash erase, no boot-state write, no reboot, no USB. Reflash
//! to revert. The rollback floor is a *function argument* here, not the OTP
//! counter, which is why nothing is burned.
//!
//! What this deliberately does NOT prove (left to the production OTP-burn
//! hardware tests, which permanently raise the OTP floor and so only run on
//! dedicated units):
//!   - that the gateway `CMD_FW_BEGIN` actually calls `verify_manifest`
//!     (a one-line link, code-review-grade — see `nsc/cmd_fw_begin.rs`),
//!   - that `CMD_FW_COMMIT` actually bumps the OTP rollback floor,
//!   - that the FSBL rejects a below-floor manifest on the next boot.
//!
//! Embeds the DEV vendor signing seed — a *public* constant mirrored from
//! `fsbl/build.rs` (used only when `FSBL_VENDOR_PUBKEY` is unset, i.e. dev /
//! e2e builds). The `fw-rollback-e2e` feature implies `e2e-test` and is fenced
//! out of `mode-production` (see the `compile_error!` in `nsc/mod.rs`), so this
//! signing seed can never link into a shipping image.

use core::ptr::{addr_of, addr_of_mut};

use fw_manifest::{ManifestBuilder, ManifestRef, MANIFEST_SIZE, TRY_ONCE_COMMITTED};
use fw_manifest::VerifyError;
use sphincs_c10::SigningKey;

use crate::fw_update::{vendor_pubkey, verify_manifest};

/// Dev vendor signing seed — MUST stay byte-identical to the dev path in
/// `fsbl/build.rs` (mirrored by `secure/build.rs`) so the signatures we
/// produce here verify against the build's embedded `VENDOR_PK_SEED/ROOT`.
const DEV_SK: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const DEV_PS: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

/// Four 8 KiB manifests = 32 KiB — far too large for the stack. Park them in
/// a `static mut`: the boot path is single-threaded and this buffer is touched
/// only by `run_and_halt`, once, before the device does anything else.
static mut MANIFEST_BUF: [[u8; MANIFEST_SIZE]; 4] = [[0u8; MANIFEST_SIZE]; 4];

/// Build a manifest at `version` and sign it with `sk`.
///
/// When `corrupt_sig` is set, one signature byte is flipped *before*
/// `finalize()` recomputes the CRC — so the manifest's CRC stays valid and
/// only the SPHINCS+C10 signature is wrong. That isolates a `BadSignature`
/// verdict (a post-finalize flip would trip `CrcMismatch` first, since the
/// CRC covers the signature region).
fn build_signed(version: u32, sk: &SigningKey, corrupt_sig: bool) -> [u8; MANIFEST_SIZE] {
    // The rollback + signature checks don't depend on the image bytes (the
    // image re-hash is a COMMIT-time step we deliberately don't exercise);
    // the builder just needs internally consistent, signed-over fields.
    let dummy_secure = [0xAAu8; 32];
    let dummy_nonsecure = [0xBBu8; 32];
    let build_id = [0xCDu8; 32];

    let mut b = ManifestBuilder::new();
    b.init(0) // slot A — informational only
        .fw_version(version)
        .secure_image(&dummy_secure, 1024)
        .nonsecure_image(&dummy_nonsecure, 1024)
        // Use the byte-for-byte fingerprint the build embedded, so it equals
        // what `verify_vendor_fpr` recomputes and compares against.
        .vendor_pubkey_fpr(&vendor_pubkey::VENDOR_PK_FPR)
        .build_id(&build_id)
        .boot_counter_snap(0)
        .try_once(TRY_ONCE_COMMITTED);

    let digest = b.finalize_preimage();
    let mut sig = sk.sign(&digest, None);
    if corrupt_sig {
        sig[0] ^= 0xff;
    }
    b.set_signature(&sig);
    b.finalize()
}

/// Run one assertion: `verify_manifest(MANIFEST_BUF[idx], floor)` must equal
/// `expected`. Logs floor/version/expected/actual; returns the pass bit.
fn check(idx: usize, floor: u32, expected: Result<(), VerifyError>, label: &str) -> bool {
    // SAFETY: single-threaded boot path; `MANIFEST_BUF` is fully initialised
    // by `run_and_halt` before any `check` call. `addr_of!` avoids taking a
    // reference *through* the `static mut` place (the `static_mut_refs` lint).
    let buf: &[u8; MANIFEST_SIZE] = unsafe { &*addr_of!(MANIFEST_BUF[idx]) };
    let m = ManifestRef::new(buf);
    let got = verify_manifest(&m, floor);
    let ok = got == expected;
    secure_log!(
        "[S][fwrb] {} : floor={} expected={:?} got={:?} -> {}",
        label,
        floor,
        expected,
        got,
        if ok { "OK" } else { "MISMATCH" }
    );
    ok
}

/// Entry point: build + sign the manifests, run the anti-rollback assertions,
/// log a single `=== PASS ===` / `=== FAIL ===` summary, then park the CPU.
pub fn run_and_halt() -> ! {
    secure_log!("[S][fwrb] === FW anti-rollback test (reversible; no OTP burn) ===");

    let sk = SigningKey::keygen(DEV_SK, DEV_PS);
    secure_log!("[S][fwrb] dev vendor key ready; signing v1/v2/v3 (SPHINCS+C10, ~1s each)...");

    // idx0=v1, idx1=v2, idx2=v3, idx3=v3 with a corrupted signature.
    let specs: [(u32, bool); 4] = [(1, false), (2, false), (3, false), (3, true)];
    for (i, (ver, corrupt)) in specs.iter().enumerate() {
        let manifest = build_signed(*ver, &sk, *corrupt);
        // SAFETY: single-threaded boot path; sole writer of MANIFEST_BUF.
        unsafe {
            addr_of_mut!(MANIFEST_BUF[i]).write(manifest);
        }
        secure_log!(
            "[S][fwrb] manifest[{}] built: v{}{}",
            i,
            ver,
            if *corrupt { " (BAD SIGNATURE)" } else { "" }
        );
    }

    // floor 0 = fresh device; floor 2 = "v2 has already been committed".
    // verify_rollback requires fw_version > floor (strict), so:
    let mut pass = true;
    pass &= check(0, 0, Ok(()), "v1 @ floor0  fresh install        ");
    pass &= check(1, 0, Ok(()), "v2 @ floor0  update v0->v2        ");
    pass &= check(0, 2, Err(VerifyError::BelowRollback), "v1 @ floor2  DOWNGRADE -> REJECT  ");
    pass &= check(1, 2, Err(VerifyError::BelowRollback), "v2 @ floor2  reinstall -> REJECT  ");
    pass &= check(2, 2, Ok(()), "v3 @ floor2  forward   -> ALLOW   ");
    pass &= check(3, 0, Err(VerifyError::BadSignature), "v3 bad-sig   forged    -> REJECT  ");

    if pass {
        secure_log!("[S][fwrb] === PASS ===");
    } else {
        secure_log!("[S][fwrb] === FAIL ===");
    }

    loop {
        cortex_m::asm::wfe();
    }
}
