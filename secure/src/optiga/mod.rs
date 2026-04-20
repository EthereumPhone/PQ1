//! Infineon OPTIGA Trust M V3 secure element driver.
//!
//! Stores one half of the XOR-split BIP-39 entropy, protected by a
//! hardware-enforced PIN via the OPTIGA authorization-reference mechanism.
//!
//! Communication: I2C1 (PB8/PB9, shared with SE050) → IFX I2C protocol
//! (4-layer stack) → Shielded Connection (AES-128-CCM-8 with TLS-PRF-
//! derived session keys).
//!
//! # PIN scheme — HMAC challenge-response
//!
//! OPTIGA Trust M doesn't have a dedicated "verify PIN" opcode. Instead,
//! PIN gating uses the generic authorization-reference (Auto-Ref)
//! mechanism:
//!
//! 1. During provisioning we write the PIN-derived HMAC secret into the
//!    auth-ref OID (0xF1D0) and mark it with data type 0x31 (AUTHREF),
//!    `Exec = Always`, `Change = Conf(0xE140)`, `Read = Never`.
//! 2. During unlock:
//!    a. `GetRandom` — the chip returns a 32-byte challenge from its TRNG.
//!    b. Host computes `HMAC-SHA256(pin_secret, challenge)`.
//!    c. `DecryptSym` in HMAC-verify mode — the chip recomputes the HMAC
//!       using the stored secret and constant-time-compares. The firmware
//!       never sees the comparison result except as success/failure.
//! 3. On success, the session at 0xE100 is marked as having "verified"
//!    0xF1D0, and subsequent reads of user OIDs gated by `Auto(0xF1D0)`
//!    succeed within that session.
//!
//! # Admin recovery path
//!
//! Every user OID's `Change` access condition is `Auto(0xF1D0) OR Conf(0xE140)`.
//! The PIN path unlocks normal operation; the `Conf` path lets the shielded
//! connection overwrite the data during factory reset, even when the user
//! has forgotten their PIN. This avoids the SE050 "permanent lockout"
//! failure mode we hit earlier.
//!
//! Attempt limiting uses a firmware-managed counter at OID 0xF1D5,
//! protected by `Conf(0xE140)` (shielded connection required for writes,
//! reads are `Always` so firmware can check without authenticating).

pub mod i2c;
pub mod ifx_i2c;
pub mod apdu;
pub mod shield;
#[cfg(feature = "optiga-reset-oids")]
pub mod reset;
#[cfg(feature = "stm32u585")]
pub mod reset_pin;

use apdu::OptigaError;
use ifx_i2c::IfxState;
use shield::ShieldedConnection;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PIN attempts before lockout — shared with the rest of the wallet.
const MAX_ATTEMPTS: u8 = sphincs_tz_shared::MAX_ATTEMPTS;

/// Domain tag for deriving the PIN authorization secret.
const PIN_AUTH_DOMAIN: &[u8] = b"optiga-pin-auth-v1";

/// HMAC challenge length from OPTIGA TRNG during auth.
const AUTH_CHALLENGE_LEN: usize = 32;

/// Counter sentinel written by `factory_reset()` so `is_provisioned()` can
/// distinguish a wiped chip from an in-use one after LcsO has been locked.
const RESET_SENTINEL: u8 = 0xFF;

// ---------------------------------------------------------------------------
// OptigaTrustM driver
// ---------------------------------------------------------------------------

/// OPTIGA Trust M secure element driver.
///
/// Caches the encrypted entropy blob, VK, and bootstrap VK in struct fields
/// after provisioning or unlock, so signing operations don't require
/// re-authenticating against the hardware.
pub struct OptigaTrustM {
    ifx: IfxState,
    shield: ShieldedConnection,
    ready: bool,
    entropy_blob_cache: [u8; crate::crypto::ENTROPY_BLOB_LEN],
    blob_cached: bool,
    vk_cache: [u8; 32],
    vk_cached: bool,
    bootstrap_vk_cache: [u8; 32],
    bootstrap_vk_cached: bool,
    remaining: u8,
}

impl OptigaTrustM {
    pub const fn new() -> Self {
        Self {
            ifx: IfxState::new(),
            shield: ShieldedConnection::new(),
            ready: false,
            entropy_blob_cache: [0; crate::crypto::ENTROPY_BLOB_LEN],
            blob_cached: false,
            vk_cache: [0; 32],
            vk_cached: false,
            bootstrap_vk_cache: [0; 32],
            bootstrap_vk_cached: false,
            remaining: MAX_ATTEMPTS,
        }
    }

    /// Initialize the OPTIGA Trust M: soft reset + OpenApplication.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops.
    pub fn init(&mut self) -> Result<(), OptigaError> {
        if self.ready {
            return Ok(());
        }

        unsafe {
            // Cold-boot settle: the datasheet STARTUP_TIME is worst-case
            // 12 s but typical warm-reset is 15 ms. Wait 50 ms — enough for
            // warm reset, covered by the retry loop for colder starts.
            //
            // Use `cortex_m::asm::delay(N)` instead of a hand-rolled NOP
            // loop. LTO is legally allowed to drop the loop counter around
            // a `for _ in 0..N { nop() }` body (nop has no observable
            // side effect per the Rust abstract machine) and leave an
            // infinite `bl nop; b back` behind. `delay()` is implemented
            // with a volatile counter so it always runs the full count.
            cortex_m::asm::delay(8_000_000);

            // Retry with SHORT delays. The chip goes into sleep mode and
            // NACKs until woken by I2C address detection — each probe wakes
            // it, but if we wait too long between probes it may re-sleep.
            // Docs specify 500 µs retry interval (~80k cycles at 160 MHz).
            // Loop up to 2000 times = ~1 second total — covers sleep + the
            // tail of a cold boot.
            let mut acked = false;
            let mut ack_attempt = 0u32;
            for attempt in 0..2000u32 {
                if i2c::probe().is_ok() || i2c::probe_with_reg().is_ok() {
                    acked = true;
                    ack_attempt = attempt;
                    break;
                }
                cortex_m::asm::delay(80_000);
            }

            if !acked {
                secure_log!("[OPTIGA] Init: chip did not ACK after 2000 retries / ~1 s");
                i2c::scan();
                return Err(OptigaError::I2c);
            }
            secure_log!("[OPTIGA] Init: chip ACK'd at 0x30 after {} retries", ack_attempt);

            secure_log!("[OPTIGA] Init: soft reset...");
            if let Err(e) = self.ifx.soft_reset() {
                secure_log!("[OPTIGA] Init: soft_reset FAILED: {:?}", e);
                return Err(OptigaError::Transport);
            }

            secure_log!("[OPTIGA] Init: OpenApplication...");
            if let Err(e) = apdu::open_application(&mut self.ifx) {
                secure_log!("[OPTIGA] Init: OpenApplication FAILED: {:?}", e);
                return Err(e);
            }

            secure_log!("[OPTIGA] Init complete");
        }

        self.ready = true;
        Ok(())
    }

    /// Pulse the RST line low via PD5 and re-run OpenApplication.
    ///
    /// Needed as a workaround for the 2-writes-per-session throttle on
    /// this specific OPTIGA Trust M dev board: after the chip accepts
    /// two consecutive SetData-family APDUs, all subsequent data APDUs
    /// either time out or return `Status=0xFF`. A real silicon reset
    /// via RST clears the throttle. NV OIDs survive; volatile state
    /// (strict locks, per-session counters) resets.
    #[cfg(feature = "stm32u585")]
    fn hard_reset_and_reinit(&mut self) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA] hard-pulsing RST (PD5) to clear session throttle");
        unsafe {
            reset_pin::init();
            reset_pin::hard_pulse();
        }
        // Hard reset invalidates our IFX DL-layer state. Start fresh.
        self.ifx = ifx_i2c::IfxState::new();
        self.ready = false;
        self.init()
    }

    /// One-shot SetObjectProtected recovery flow, gated by `optiga-reset-oids`.
    ///
    /// Initializes the chip (`OpenApplication`), provisions a Trust Anchor
    /// cert at OID `0xE0E3` if it isn't already there, then iterates the
    /// embedded reset-manifest bundle and sends each one. Logs per-OID
    /// outcome via `secure_log!`.
    ///
    /// Drops the `optiga-reset-oids` feature as soon as the chip is back
    /// in a writable state — the TA cert that authorises these manifests
    /// is a sample key from Infineon's example set, unsafe for production.
    #[cfg(feature = "optiga-reset-oids")]
    pub fn recover_burned_oids(&mut self) -> Result<(), OptigaError> {
        // Before anything else, configure PD5 (= Arduino D5 on the
        // B-U585I-IOT02A) as a GPIO output and drive it high — this
        // is wired to the OPTIGA MTR Express V3 board's RST pin, and
        // driving high explicitly tells the chip it's not in reset.
        #[cfg(feature = "stm32u585")]
        unsafe {
            reset_pin::init();
        }

        self.init()?;

        unsafe {
            secure_log!("[OPTIGA][reset] provisioning Trust Anchor at 0xE0E3");
            if let Err(e) = reset::provision_trust_anchor(&mut self.ifx, &mut self.shield) {
                secure_log!(
                    "[OPTIGA][reset] TA provisioning failed ({:?}); \
                    assuming already provisioned and continuing",
                    e
                );
            } else {
                secure_log!("[OPTIGA][reset] TA cert + metadata written");
            }

            // After the 604-byte TA cert write, the chip wedges — it ACKs
            // subsequent frames at DL layer but never sets RESP_READY in
            // I2C_STATE. A soft-reset-over-I²C doesn't recover it; only
            // a real silicon reset via the RST pin does. We also observe
            // that every successful SetObjectProtected puts the chip back
            // in the same wedged state, so we hard-pulse before EACH
            // manifest, not just once before the loop. The TA cert lives
            // in NV flash and survives the resets.
            let mut success: usize = 0;
            for entry in reset::iter_reset_entries() {
                #[cfg(feature = "stm32u585")]
                if let Err(e) = self.hard_reset_and_reinit() {
                    secure_log!(
                        "[OPTIGA][reset] re-init before OID 0x{:04X} FAILED: {:?}",
                        entry.oid, e
                    );
                    continue;
                }

                match apdu::send_protected_manifest(
                    &mut self.ifx,
                    &mut self.shield,
                    entry.manifest,
                    entry.fragment,
                ) {
                    Ok(()) => {
                        secure_log!("[OPTIGA][reset] OID 0x{:04X} reset OK", entry.oid);
                        success += 1;
                    }
                    Err(e) => {
                        secure_log!(
                            "[OPTIGA][reset] OID 0x{:04X} FAILED: {:?}",
                            entry.oid, e
                        );
                    }
                }
            }
            secure_log!("[OPTIGA][reset] {} OIDs reset", success);
        }

        Ok(())
    }

    /// Load the Platform Binding Secret into the Shielded Connection
    /// state.
    ///
    /// Post-work-todo-#24: the PBS is re-derived from the per-device
    /// OTP master key every boot via
    /// `hw::secret_keys::optiga_pairing_secret`. No flash seal, no
    /// blank-page check, no AES-GCM unseal. First boot triggers the
    /// one-time OTP master burn as a side-effect of the HKDF call.
    ///
    /// Under `optiga-no-shield` this is a no-op — we never attempt
    /// PRL on chips where E140 is unreachable. See
    /// `docs/optiga-brick-postmortem.md` §7.
    #[cfg(feature = "stm32u585")]
    pub fn load_pbs(&mut self) {
        #[cfg(feature = "optiga-no-shield")]
        {
            secure_log!("[OPTIGA] load_pbs skipped (feature optiga-no-shield)");
            return;
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            use zeroize::Zeroize;
            match crate::hw::secret_keys::optiga_pairing_secret() {
                Ok(mut pbs) => {
                    // Fingerprint log: first 8 bytes of the derived PBS.
                    // Stable across rebuilds iff the OTP master + HKDF
                    // label haven't changed. If this line ever differs
                    // between two boots of the same chip, the PBS we're
                    // about to hand to the PRL handshake will not match
                    // what the chip was paired with — STOP before writing
                    // anything to E140, because LcsO=op makes rewrites
                    // impossible. The hardcoded test constant is in
                    // source; printing 8 bytes of its HKDF output leaks
                    // nothing a code reader doesn't already have.
                    secure_log!(
                        "[OPTIGA] PBS fingerprint: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        pbs[0], pbs[1], pbs[2], pbs[3],
                        pbs[4], pbs[5], pbs[6], pbs[7]
                    );
                    self.shield.load_pbs(&pbs);
                    pbs.zeroize();
                    secure_log!("[OPTIGA] PBS derived from OTP master and loaded");
                }
                Err(e) => {
                    // Only reachable if OTP itself failed (RNG failure on
                    // first-boot burn, ReadbackMismatch, etc.). Shielded
                    // Connection will be unavailable; the provisioning
                    // path + PIN flow surface a diagnostic upstream.
                    secure_log!("[OPTIGA] load_pbs FAILED: {:?}", e);
                }
            }
        }
    }

    #[cfg(not(feature = "stm32u585"))]
    pub fn load_pbs(&mut self) {
        secure_log!("[OPTIGA] load_pbs: non-stm32u585 build, no-op");
    }

    /// Ensure the shielded connection is active, establishing it on demand
    /// from the cached PBS.
    ///
    /// Under `optiga-no-shield` this is a no-op — we never attempt the PRL
    /// handshake, every APDU stays plaintext on I2C. Use this mode when
    /// `E140` is unreachable on a specific chip (e.g. the current bricked
    /// test chip), so that non-PRL paths (PIN HMAC verify, entropy
    /// read/write, factory reset of F1Dx) can still be exercised. See
    /// `docs/optiga-brick-postmortem.md` §7.
    fn ensure_shield(&mut self) -> Result<(), OptigaError> {
        #[cfg(feature = "optiga-no-shield")]
        {
            // Mode-of-operation: bus-level I2C encryption is intentionally
            // off. AC'd reads/writes rely on the authenticated-on-chip
            // path instead (PIN HMAC verify → Auto(F1DC) session state).
            return Ok(());
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            if !self.shield.active {
                if !self.shield.pbs_loaded {
                    return Err(OptigaError::Shield);
                }
                // Chip-side pre-condition for PRL handshake: E140 LcsO=op.
                // For chips that were provisioned under an older firmware
                // revision that kept LcsO at Creation, bump it here — no-op
                // if already Operational.
                unsafe {
                    self.ensure_pbs_lcso_operational()?;
                    self.shield.establish(&mut self.ifx)
                        .map_err(|_| OptigaError::Shield)?;
                }
                secure_log!("[OPTIGA/shield] PRL handshake OK — encrypted I2C active");
            }
            Ok(())
        }
    }

    /// PBS provisioning without attempting the shielded-connection
    /// handshake. Writes the 32-byte Platform Binding Secret to OID
    /// 0xE140 and installs the PRL-compatible metadata, but does NOT
    /// call `shield.establish`. Used during bring-up while the PRL
    /// handshake itself is being debugged against real silicon.
    ///
    /// ## Source of the PBS (work-todo #24)
    ///
    /// The PBS is derived on demand from the per-device OTP master key
    /// via `hw::secret_keys::optiga_pairing_secret` (HMAC-SHA256 with
    /// label `"pqsigner/optiga-pbs-v1"`). Two properties matter:
    ///
    /// - **Deterministic across firmware rebuilds.** The PBS is a pure
    ///   function of the OTP master (burned once per physical board)
    ///   and the HKDF label — both stable for the device's lifetime.
    ///   Any firmware reflash reproduces the same 32 bytes. The old
    ///   `rng::fill`-generated PBS + flash-page-126 AES-GCM seal is
    ///   gone (`hw::flash::write_pbs` deleted), along with its
    ///   dependency on `measured_boot::firmware_hash` inside the wrap
    ///   key — that coupling is what bricked bench units on every
    ///   rebuild (see `docs/optiga-brick-postmortem.md`).
    /// - **First boot self-provisions the master.** On a blank MCU the
    ///   inner `ensure_device_master` call inside `optiga_pairing_
    ///   secret` programs 32 TRNG bytes into OTP and locks the region.
    ///   Every subsequent boot is a pure OTP read + one HMAC.
    ///
    /// ## LcsO=Operational bump
    ///
    /// Per SRM §"Platform Binding Secret" the chip requires
    /// `E140.LcsO=op` for the PRL state machine to emit SlaveHello, so
    /// production builds must enable the `optiga-lock-operational`
    /// Cargo feature. Dev builds leave it off so a firmware rebuild
    /// does not produce an unrecoverable chip. See
    /// `docs/optiga-brick-postmortem.md` §3 and §7.
    ///
    /// The bump additionally refuses to proceed unless the OTP master
    /// has actually been burned (`is_device_master_burned`). On a
    /// board where the master is still blank, committing LcsO=op would
    /// lock E140 against a PBS the driver cannot reproduce after the
    /// very next reset — that is the exact class of reliability bug
    /// #24 was written to eliminate.
    fn setup_pbs_no_handshake(&mut self) -> Result<(), OptigaError> {
        // Derive the PBS from the OTP master on real hardware; fall
        // back to a TRNG-filled ephemeral value on pure-host/QEMU
        // builds (which don't exercise real OPTIGA I/O anyway — the
        // driver is `optiga-trust-m`-gated and `stm32u585`-gated
        // peripherals are what deliver APDUs).
        //
        // 64-byte size per OPTIGA Trust M SRM §"Platform Binding Secret".
        #[cfg(feature = "stm32u585")]
        let mut pbs = crate::hw::secret_keys::optiga_pairing_secret()
            .map_err(|e| {
                secure_log!("[OPTIGA/prov] optiga_pairing_secret FAILED: {:?}", e);
                OptigaError::Transport
            })?;
        #[cfg(not(feature = "stm32u585"))]
        let mut pbs = {
            let mut p = [0u8; 64];
            crate::rng::fill(&mut p).map_err(|_| OptigaError::Transport)?;
            p
        };

        unsafe {
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &pbs,
            )?;

            let (meta, meta_len) = apdu::build_metadata_pbs_final();
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &meta[..meta_len],
            )?;

            // LcsO = Operational. Irreversible per SRM §"Life Cycle Status".
            // Gated behind `optiga-lock-operational` so dev builds cannot
            // commit to an irreversible pairing; additionally gated on
            // `is_device_master_burned` so an accidental feature-flip on
            // an unburned board cannot reproduce the brick scenario.
            #[cfg(feature = "optiga-lock-operational")]
            {
                #[cfg(feature = "stm32u585")]
                {
                    if !crate::hw::otp::is_device_master_burned() {
                        secure_log!(
                            "[OPTIGA/prov] REFUSE LcsO=op: OTP master is blank; \
                             the PBS cannot be reproduced across resets, locking \
                             E140 would brick the chip on next boot"
                        );
                        pbs.zeroize();
                        return Err(OptigaError::Transport);
                    }
                }

                let (lock_meta, lock_len) = apdu::build_metadata_lock();
                if let Err(e) = apdu::set_metadata(
                    &mut self.ifx, &mut self.shield,
                    apdu::OID_PBS, &lock_meta[..lock_len],
                ) {
                    secure_log!("[OPTIGA/prov] E140 LcsO→op bump FAILED: {:?}", e);
                    pbs.zeroize();
                    return Err(e);
                }
                secure_log!("[OPTIGA/prov] E140 LcsO bumped to Operational (feature optiga-lock-operational)");
            }
            #[cfg(not(feature = "optiga-lock-operational"))]
            {
                secure_log!("[OPTIGA/prov] E140 LcsO bump SKIPPED (optiga-lock-operational OFF; E140 stays at Creation, rewriteable)");
            }
        }

        self.shield.load_pbs(&pbs);
        pbs.zeroize();

        secure_log!("[OPTIGA] PBS provisioned (handshake deferred)");
        Ok(())
    }

    /// Make sure E140 is at LcsO=Operational. Required before any PRL
    /// handshake attempt: on a chip where previous provisioning left E140
    /// at LcsO=Creation (e.g. earlier firmware revisions of this driver),
    /// the chip refuses to emit SlaveHello.
    ///
    /// Reads metadata first and only writes when needed so we don't burn
    /// an NVM cycle on every boot once the chip is already Operational.
    /// Metadata reads are Change=ALW on the LcsO tag (SRM §"Metadata
    /// associated with data and key objects"), no shielded connection
    /// required.
    unsafe fn ensure_pbs_lcso_operational(&mut self) -> Result<(), OptigaError> {
        let mut meta = [0u8; 64];
        let n = apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PBS, &mut meta,
        )?;
        if apdu::is_metadata_operational(&meta, n) {
            secure_log!("[OPTIGA/shield] E140 already at LcsO=op");
            return Ok(());
        }
        secure_log!("[OPTIGA/shield] E140 LcsO<op; bumping to Operational");
        let (lock_meta, lock_len) = apdu::build_metadata_lock();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_PBS, &lock_meta[..lock_len],
        )?;
        Ok(())
    }

    /// Derive the 32-byte PIN authorization secret from the 8-digit PIN.
    fn derive_pin_secret(pin: &[u8; 8]) -> [u8; 32] {
        crate::crypto::kdf(PIN_AUTH_DOMAIN, pin, 0)
    }

    /// HMAC-SHA256(key, data) — 32-byte output.
    fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        use hmac::Mac;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Check if the device has been provisioned.
    ///
    /// Uses the attempt counter OID (0xF1D5) as a liveness marker since
    /// LcsO can only go up — it stays Operational even after a factory
    /// reset, so a metadata check alone would mis-report a wiped chip as
    /// provisioned. The counter can hold:
    /// - `0x00..=0x0A` — normal provisioned state (usage counter value)
    /// - `0xFF` — factory-reset sentinel set by `factory_reset()`
    /// - read-error — object uninitialized, i.e. fresh chip
    ///
    /// Read access on the counter is `Always`, so no shielded connection or
    /// PIN is required.
    fn check_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        match unsafe { self.read_counter_raw() } {
            Some(v) if v != RESET_SENTINEL => true,
            _ => false,
        }
    }

    /// Close + reopen the OPTIGA application context. Frees the chip's
    /// per-session work buffer between long chains of writes where the
    /// chip otherwise starts returning Status=0xff after a few operations.
    unsafe fn reopen_application(&mut self) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] reopen_application");
        apdu::close_application(&mut self.ifx)?;
        apdu::open_application(&mut self.ifx)
    }

    /// Lock an OID's lifecycle to Operational (irreversible).
    unsafe fn lock_oid(&mut self, oid: u16) -> Result<(), OptigaError> {
        let (lock_meta, lock_len) = apdu::build_metadata_lock();
        apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &lock_meta[..lock_len])
    }

    /// Provision the auth-reference OID: write the PIN-derived secret,
    /// install AC + data-type, lock LcsO.
    ///
    /// Order matters (aligned with `provision_user_oid`, which was the
    /// fix identified in commit d8e54d7 "data-first write"): while the
    /// OID is at LcsO=Creation with default allow-all Change AC, the
    /// data write goes through plaintext. Installing the AUTHREF data-
    /// type metadata *before* the data is written fails on a fresh chip
    /// with Status=0xFF — the chip apparently refuses to apply
    /// `type=AUTHREF` to an empty OID.
    unsafe fn provision_auth_ref(&mut self, pin_secret: &[u8; 32]) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] auth_ref: set_data_object");
        if let Err(e) = apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, pin_secret,
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_data FAILED: {:?}", e);
            return Err(e);
        }

        secure_log!("[OPTIGA/prov] auth_ref: set_metadata");
        let (meta, meta_len) = apdu::build_metadata_auth_ref();
        if let Err(e) = apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &meta[..meta_len],
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_metadata FAILED: {:?}", e);
            return Err(e);
        }

        secure_log!("[OPTIGA/prov] auth_ref: lock_oid");
        if let Err(e) = self.lock_oid(apdu::OID_AUTH_REF) {
            secure_log!("[OPTIGA/prov] auth_ref lock FAILED: {:?}", e);
            return Err(e);
        }
        Ok(())
    }

    /// Provision one user data OID: write payload (while LcsO=Creation
    /// allows it), then install AC, then lock LcsO.
    ///
    /// Order matters: if we install `Change = Auto(F1DC) OR Conf(E140)`
    /// BEFORE writing the data, the chip immediately enforces that AC on
    /// the subsequent write (even in Creation state, in practice) and we
    /// get Status=0xff. Writing the data first, while default "allow-all"
    /// Creation-state ACs apply, succeeds.
    unsafe fn provision_user_oid(
        &mut self,
        oid: u16,
        data: &[u8],
        require_shielded_read: bool,
    ) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data ({} bytes)", oid, data.len());
        if let Err(e) = apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, data) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data FAILED: {:?}", oid, e);
            return Err(e);
        }

        let (meta, meta_len) =
            apdu::build_metadata_protected(apdu::OID_AUTH_REF, require_shielded_read);
        if let Err(e) = apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len]) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_metadata FAILED: {:?}", oid, e);
            return Err(e);
        }
        if let Err(e) = self.lock_oid(oid) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: lock FAILED: {:?}", oid, e);
            return Err(e);
        }
        Ok(())
    }

    /// Provision the attempt counter: write 0, install AC, lock.
    unsafe fn provision_counter(&mut self) -> Result<(), OptigaError> {
        apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, &[0u8],
        )?;

        let (meta, meta_len) = apdu::build_metadata_counter();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, &meta[..meta_len],
        )?;

        self.lock_oid(apdu::OID_COUNTER)
    }

    /// Full-device provisioning.
    ///
    /// Idempotent against a partially-provisioned device: if the PBS is
    /// already in place the shielded connection re-establishes using the
    /// cached copy, and the subsequent data writes go through because the
    /// user OIDs are `Change = Auto(F1D0) OR Conf(0xE140)` — the `Conf` arm
    /// is satisfied by the shielded connection.
    fn store_objects(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        self.init()?;
        secure_log!("[OPTIGA/prov] init OK");

        // 1. PBS (plain write to E140 at LcsO=Creation). Unconditionally
        // runs on every provisioning attempt under `optiga-trust-m`:
        // setup_pbs_no_handshake is idempotent against LcsO=Creation
        // (Change AC defaults to ALW until metadata is installed, and
        // then the `LcsO<op OR Conf(E140)` branch allows the plaintext
        // re-write), so re-running it on a partially-provisioned chip
        // just rewrites the same 64 bytes.
        //
        // Pre-#24 this was gated on `!self.shield.pbs_loaded`, which
        // worked when `load_pbs` only set `pbs_loaded=true` after an
        // unsealed flash read succeeded. Post-#24, `load_pbs` always
        // succeeds (PBS is derived from the OTP master on every boot),
        // so that gate would now skip the chip-side write on every
        // fresh chip — which is exactly the bug surfaced on Phase-A
        // hardware validation of 2026-04-20.
        //
        // Under `optiga-no-shield` the entire PBS setup is skipped —
        // we never use shielded connection, so we never write E140.
        // Keeps a chip with a bricked E140 (LcsO=op with lost PBS)
        // usable for all non-PRL paths. See
        // `docs/optiga-brick-postmortem.md` §7.
        #[cfg(feature = "optiga-no-shield")]
        {
            secure_log!("[OPTIGA/prov] step 1 skipped (feature optiga-no-shield; PRL is disabled)");
        }
        #[cfg(not(feature = "optiga-no-shield"))]
        {
            secure_log!("[OPTIGA/prov] step 1: setup_pbs_no_handshake");
            if let Err(e) = self.setup_pbs_no_handshake() {
                secure_log!("[OPTIGA/prov] setup_pbs FAILED: {:?}", e);
                return Err(e);
            }
            // After PBS write (2 SetData ops) the chip refuses further
            // writes until it is hard-reset. Pulse RST (PD5) to clear
            // the wedge; NV OIDs (including the PBS we just wrote) survive.
            #[cfg(feature = "stm32u585")]
            self.hard_reset_and_reinit()?;
        }

        // 2. Auth reference
        secure_log!("[OPTIGA/prov] step 2: provision_auth_ref");
        {
            let mut pin_secret = Self::derive_pin_secret(pin);
            let result = unsafe { self.provision_auth_ref(&pin_secret) };
            pin_secret.zeroize();
            if let Err(e) = result {
                secure_log!("[OPTIGA/prov] provision_auth_ref FAILED: {:?}", e);
                return Err(e);
            }
            #[cfg(feature = "stm32u585")]
            self.hard_reset_and_reinit()?;
        }

        // 3. User data. While shielded is disabled we drop the Conf(E140)
        // arm from Read AC — entropy/master_secret become Auto(F1D0) only,
        // same protection level as VK. I²C traffic is plaintext for now.
        // Cycle Close/Open between OIDs: on this chip, after ~3 consecutive
        // SetData operations the chip starts returning Status=0xff. The
        // pattern goes away if we release + reacquire the application
        // context, suggesting a per-session work buffer or transient-OID
        // slot gets exhausted otherwise.
        // Each user OID provision = 2 SetData writes (metadata + data),
        // and the chip wedges after 2 writes per session. Hard-pulse RST
        // between every OID so each provision starts in a fresh session.
        // The OpenApplication is done by hard_reset_and_reinit(). The
        // reopen_application() call that used to live here (CloseApp +
        // OpenApp) doesn't help on this chip — CloseApp ACKs but never
        // emits a data response, so we just time out.
        macro_rules! prov_with_reset {
            ($name:literal, $call:expr) => {{
                secure_log!("[OPTIGA/prov] step: {}", $name);
                $call.map_err(|e| {
                    secure_log!("[OPTIGA/prov] {} write FAILED: {:?}", $name, e); e
                })?;
                #[cfg(feature = "stm32u585")]
                self.hard_reset_and_reinit()?;
            }};
        }

        unsafe {
            prov_with_reset!("entropy", self.provision_user_oid(apdu::OID_ENTROPY, entropy, false));
            prov_with_reset!("master_secret", self.provision_user_oid(apdu::OID_MASTER_SECRET, master_secret, false));
            prov_with_reset!("vk", self.provision_user_oid(apdu::OID_VK, vk, false));
            prov_with_reset!("bootstrap_vk", self.provision_user_oid(apdu::OID_BOOTSTRAP_VK, bootstrap_vk, false));
            prov_with_reset!("counter", self.provision_counter());
        }

        secure_log!("[OPTIGA] Provisioning complete (6 OIDs written + locked)");
        Ok(())
    }

    /// Read the 1-byte attempt counter, returning `None` if the object is
    /// uninitialized (fresh chip) or the read fails for any other reason.
    unsafe fn read_counter_raw(&mut self) -> Option<u8> {
        let mut buf = [0u8; 4];
        match apdu::get_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_COUNTER, 0, 1, &mut buf,
        ) {
            Ok(n) if n > 0 => Some(buf[0]),
            _ => None,
        }
    }

    /// Authenticate with PIN and read every protected data object.
    ///
    /// Flow:
    /// 1. Ensure shielded connection
    /// 2. Read + gate on attempt counter
    /// 3. Write counter += 1 (decrement-before-verify pattern)
    /// 4. `GetRandom` for the HMAC challenge
    /// 5. Host computes `HMAC-SHA256(pin_secret, challenge)`
    /// 6. `DecryptSym` in HMAC-verify mode — chip recomputes and compares
    /// 7. On success: read entropy, master_secret, VK, bootstrap_vk
    /// 8. Reset counter to 0
    /// 9. Cache everything, return master_secret
    fn authenticate_and_read(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], OptigaError> {
        secure_log!("[OPTIGA/auth] authenticate_and_read: start");
        self.init()?;
        // CRIT-8 requires every PIN-auth APDU to traverse the shielded
        // connection, including the TRNG challenge fetch. Re-establish
        // (or reuse the existing) session before any further APDU.
        self.ensure_shield()?;

        unsafe {
            let attempts = match self.read_counter_raw() {
                Some(v) if v == RESET_SENTINEL => {
                    secure_log!("[OPTIGA/auth] counter = RESET_SENTINEL → NotProvisioned");
                    return Err(OptigaError::NotProvisioned);
                }
                Some(v) => {
                    secure_log!("[OPTIGA/auth] counter = {}", v);
                    v
                }
                None => {
                    secure_log!("[OPTIGA/auth] counter read returned None → NotProvisioned");
                    return Err(OptigaError::NotProvisioned);
                }
            };
            if attempts >= MAX_ATTEMPTS {
                return Err(OptigaError::PinLocked);
            }

            // 3. Bump counter BEFORE verify (so a power cut can't refund
            //    the attempt). CRIT-6 fix: add a read-back assertion
            //    that the written value actually landed — a glitch or
            //    bus-MITM that produces a nominal-success response for
            //    a failed write would otherwise leave the counter at
            //    `attempts` and allow a re-try. On mismatch we refuse
            //    the whole unlock and zeroize; the counter is advisory
            //    but the firmware-level assertion is not.
            let new_attempts = attempts + 1;
            secure_log!("[OPTIGA/auth] bumping counter to {}", new_attempts);
            if let Err(e) = apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[new_attempts],
            ) {
                secure_log!("[OPTIGA/auth] counter bump FAILED: {:?}", e);
                return Err(e);
            }
            let readback = self.read_counter_raw().ok_or(OptigaError::PinLocked)?;
            if readback != new_attempts {
                secure_log!(
                    "[OPTIGA/auth] counter readback mismatch: wrote {} read {} — PinLocked",
                    new_attempts, readback
                );
                return Err(OptigaError::PinLocked);
            }

            // 4. Get challenge. CRIT-8 fix: route through the shielded
            //    channel AND XOR with host TRNG, so a bus MITM can't
            //    force a fixed challenge and a compromised chip RNG
            //    can't feed us a predictable one.
            secure_log!("[OPTIGA/auth] GetRandom (shielded + host-mixed)");
            let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
            if let Err(e) =
                apdu::get_random_mixed(&mut self.ifx, &mut self.shield, &mut challenge)
            {
                secure_log!("[OPTIGA/auth] GetRandom FAILED: {:?}", e);
                return Err(e);
            }
            secure_log!(
                "[OPTIGA/auth] challenge[0..4]={:02x}{:02x}{:02x}{:02x}",
                challenge[0], challenge[1], challenge[2], challenge[3]
            );

            let mut pin_secret = Self::derive_pin_secret(pin);
            let mut hmac = Self::hmac_sha256(&pin_secret, &challenge);
            pin_secret.zeroize();

            secure_log!("[OPTIGA/auth] hmac_verify via DecryptSym");
            let verify_result = apdu::hmac_verify(
                &mut self.ifx, &mut self.shield,
                apdu::OID_AUTH_REF,
                apdu::OID_SESSION,
                &challenge,
                &hmac,
            );
            hmac.zeroize();
            challenge.zeroize();

            match verify_result {
                Ok(()) => {
                    secure_log!("[OPTIGA/auth] hmac_verify OK");
                }
                Err(e) => {
                    secure_log!("[OPTIGA/auth] hmac_verify FAILED: {:?}", e);
                    return Err(match e {
                        OptigaError::PinIncorrect
                        | OptigaError::Status(_)
                        | OptigaError::PinLocked => OptigaError::PinIncorrect,
                        other => other,
                    });
                }
            }

            // 7. Read protected data now that Auto(F1D0) is authorized
            let mut entropy = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_ENTROPY, 0, 32, &mut entropy,
            )?;

            let mut master_secret = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_MASTER_SECRET, 0, 32, &mut master_secret,
            )?;

            let mut vk = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_VK, 0, 32, &mut vk,
            )?;

            let mut bootstrap_vk = [0u8; 32];
            apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_BOOTSTRAP_VK, 0, 32, &mut bootstrap_vk,
            )?;

            // 8. Reset counter now that we know the PIN was right
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[0u8],
            )?;

            // 9. Cache & return
            let blob = crate::crypto::encrypt_entropy_blob(&entropy, &master_secret);
            self.entropy_blob_cache.copy_from_slice(&blob);
            self.blob_cached = true;

            self.vk_cache.copy_from_slice(&vk);
            self.vk_cached = true;

            self.bootstrap_vk_cache.copy_from_slice(&bootstrap_vk);
            self.bootstrap_vk_cached = true;

            self.remaining = MAX_ATTEMPTS;

            entropy.zeroize();
            vk.zeroize();
            bootstrap_vk.zeroize();

            secure_log!("[OPTIGA] Unlocked: entropy + VKs cached");
            Ok(master_secret)
        }
    }

    /// Admin factory reset — wipes every user-data OID via the shielded
    /// connection path (Conf(0xE140)), so it works even if the PIN is lost.
    ///
    /// Steps:
    /// 1. Ensure shielded connection active.
    /// 2. Overwrite F1D1..F1D4 with zeros (Change is satisfied by Conf).
    /// 3. Overwrite F1D0 (auth ref) with zeros (Change = Conf only).
    /// 4. Reset the attempt counter to 0.
    ///
    /// After this the device reports `is_provisioned()` → false? Not
    /// quite: LcsO is still Operational and metadata is still in place.
    /// The next call to `provision()` will rewrite the data (the
    /// `Auto OR Conf` AC lets it through via Conf) and everything resumes
    /// normally. We deliberately leave LcsO alone — raising it is
    /// irreversible, and that would prevent future rotation.
    pub fn factory_reset(&mut self) -> Result<(), OptigaError> {
        self.init()?;
        // Shielded path is disabled while PRL is being debugged; Change AC
        // for user OIDs is currently Auto(F1D0) only, so factory reset
        // needs a valid PIN session. TODO: re-enable Conf(E140) path once
        // the handshake is green.

        // HIGH-18 fix: arm the shared wipe flag BEFORE starting any
        // destructive OID write. A power loss between two OID wipes
        // would otherwise leave OPTIGA in a half-wiped state where
        // (say) OID_ENTROPY is zeroed but OID_AUTH_REF is intact —
        // the next boot would successfully verify the stale PIN and
        // read zeros for entropy. Recovery on the next boot is
        // gated on `is_wipe_armed()` in main.rs so we just re-run
        // the same reset sequence (the Conf(E140) AC path still
        // works because PBS is intact).
        #[cfg(feature = "stm32u585")]
        unsafe {
            let _ = crate::hw::flash::arm_wipe_flag();
        }

        let blank = [0u8; 32];
        unsafe {
            // Write the sentinel FIRST so a crash mid-wipe still produces a
            // chip that boots as unprovisioned — the wizard on the next
            // boot will overwrite every OID cleanly. If we wrote the
            // sentinel last, a crash would leave stale user data behind a
            // "provisioned"-looking counter, reproducing the SE050 trap.
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[RESET_SENTINEL],
            )?;

            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_AUTH_REF, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_ENTROPY, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_MASTER_SECRET, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_VK, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_BOOTSTRAP_VK, &blank)?;
        }

        self.zeroize_caches_internal();
        self.remaining = MAX_ATTEMPTS;

        secure_log!("[OPTIGA] Factory reset complete");
        Ok(())
    }

    fn zeroize_caches_internal(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
    }
}

// ---------------------------------------------------------------------------
// WalletStore implementation
// ---------------------------------------------------------------------------

use crate::secure_element::{SeError, UnlockError, WalletStore};

impl WalletStore for OptigaTrustM {
    fn is_provisioned(&mut self) -> bool {
        self.check_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        self.store_objects(entropy, master_secret, vk, bootstrap_vk, pin)
            .map_err(|_| SeError::InternalError)?;

        self.vk_cache.copy_from_slice(vk);
        self.vk_cached = true;
        self.bootstrap_vk_cache.copy_from_slice(bootstrap_vk);
        self.bootstrap_vk_cached = true;
        self.remaining = MAX_ATTEMPTS;

        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        self.authenticate_and_read(pin).map_err(|e| match e {
            OptigaError::PinIncorrect => {
                if self.remaining > 0 {
                    self.remaining -= 1;
                }
                UnlockError::PinIncorrect
            }
            OptigaError::PinLocked => UnlockError::PinLocked,
            _ => UnlockError::InternalError,
        })
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached || buf.len() < crate::crypto::ENTROPY_BLOB_LEN {
            return Err(SeError::SlotNotFound);
        }
        buf[..crate::crypto::ENTROPY_BLOB_LEN]
            .copy_from_slice(&self.entropy_blob_cache);
        Ok(crate::crypto::ENTROPY_BLOB_LEN)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.vk_cache);
        Ok(32)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.bootstrap_vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.bootstrap_vk_cache);
        Ok(32)
    }

    fn remaining_attempts(&mut self) -> u8 {
        self.remaining
    }

    fn zeroize_caches(&mut self) {
        self.zeroize_caches_internal();
    }

    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        self.factory_reset().map_err(|_| SeError::InternalError)
    }
}
