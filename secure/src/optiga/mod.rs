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
            // 8M NOPs at 160 MHz ≈ 50 ms.
            for _ in 0..8_000_000u32 {
                cortex_m::asm::nop();
            }

            // Retry with SHORT delays. The chip goes into sleep mode and
            // NACKs until woken by I2C address detection — each probe wakes
            // it, but if we wait too long between probes it may re-sleep.
            // Docs specify 500 µs retry interval (~80k NOPs at 160 MHz).
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
                // ~500 µs delay
                for _ in 0..80_000u32 {
                    cortex_m::asm::nop();
                }
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

    /// Load the Platform Binding Secret from secure flash (page 126).
    ///
    /// Called at boot. If the PBS page is blank (first boot), this is a
    /// no-op — PBS will be generated during `setup_pbs` on first
    /// provisioning.
    ///
    /// Under `optiga-bringup-fresh` the PBS page is erased at boot. This
    /// forces `setup_pbs` to generate a fresh secret, which is what we
    /// want when the chip's OID 0xE140 is still in LcsO=Creation state
    /// (fresh silicon) or when we've re-flashed the MCU but the chip was
    /// never successfully provisioned. Should NEVER be enabled in
    /// production — it orphans any already-provisioned chip from the MCU.
    #[cfg(feature = "stm32u585")]
    pub fn load_pbs(&mut self) {
        #[cfg(feature = "optiga-bringup-fresh")]
        unsafe {
            if !crate::hw::flash::is_pbs_blank() {
                secure_log!("[OPTIGA] optiga-bringup-fresh: erasing stale PBS flash page");
                match crate::hw::flash::erase_pbs_page() {
                    Ok(()) => {
                        let still_dirty = !crate::hw::flash::is_pbs_blank();
                        secure_log!(
                            "[OPTIGA] erase returned Ok, is_pbs_blank post-erase: {}",
                            !still_dirty
                        );
                    }
                    Err(_) => {
                        secure_log!("[OPTIGA] erase_pbs_page returned Err");
                    }
                }
            } else {
                secure_log!("[OPTIGA] optiga-bringup-fresh: PBS page already blank");
            }
        }

        unsafe {
            if crate::hw::flash::is_pbs_blank() {
                secure_log!("[OPTIGA] PBS page blank (first boot)");
                return;
            }
            let mut pbs = [0u8; 32];
            match crate::hw::flash::read_pbs(&mut pbs) {
                Ok(()) => {
                    self.shield.load_pbs(&pbs);
                    pbs.zeroize();
                    secure_log!("[OPTIGA] PBS unsealed from flash page 126");
                }
                Err(e) => {
                    // CRIT-9: either the flash was tampered with, the
                    // chip was swapped under this firmware, or this
                    // firmware revision changed the wrap-key domain.
                    // All three collapse to "treat as unprovisioned
                    // and re-run first-boot provisioning" — the admin
                    // factory-reset path handles the clean-up.
                    pbs.zeroize();
                    secure_log!("[OPTIGA] PBS unseal FAILED: {:?}; treating as blank", e);
                }
            }
        }
    }

    #[cfg(not(feature = "stm32u585"))]
    pub fn load_pbs(&mut self) {
        secure_log!("[OPTIGA] load_pbs: no flash on QEMU");
    }

    /// Generate + provision the Platform Binding Secret, lock it to
    /// Operational, and establish the first shielded connection.
    ///
    /// Only runs when LcsO of 0xE140 is < Operational (i.e. first boot).
    /// On subsequent boots `load_pbs()` restores the secret from flash and
    /// this function is skipped.
    fn setup_pbs(&mut self) -> Result<(), OptigaError> {
        let mut pbs = [0u8; 32];
        crate::rng::fill(&mut pbs).map_err(|_| OptigaError::Transport)?;

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
        }

        self.shield.load_pbs(&pbs);

        #[cfg(feature = "stm32u585")]
        unsafe {
            crate::hw::flash::write_pbs(&pbs)
                .map_err(|_| OptigaError::Transport)?;
            secure_log!("[OPTIGA] PBS written to flash page 126");
        }

        pbs.zeroize();

        unsafe {
            self.shield.establish(&mut self.ifx)
                .map_err(|_| OptigaError::Shield)?;
        }

        secure_log!("[OPTIGA] PBS provisioned, shielded connection active");
        Ok(())
    }

    /// Ensure the shielded connection is active, establishing it on demand
    /// from the cached PBS.
    #[allow(dead_code)] // kept for when the PRL handshake is fixed
    fn ensure_shield(&mut self) -> Result<(), OptigaError> {
        if !self.shield.active {
            if !self.shield.pbs_loaded {
                return Err(OptigaError::Shield);
            }
            unsafe {
                self.shield.establish(&mut self.ifx)
                    .map_err(|_| OptigaError::Shield)?;
            }
        }
        Ok(())
    }

    /// PBS provisioning without attempting the shielded-connection
    /// handshake. Writes PBS to OID 0xE140 + sets its metadata (LcsO,
    /// type=0x22), saves PBS to MCU flash, but does NOT call
    /// `shield.establish`. Used while the PRL handshake is being
    /// debugged against real silicon.
    fn setup_pbs_no_handshake(&mut self) -> Result<(), OptigaError> {
        let mut pbs = [0u8; 32];
        crate::rng::fill(&mut pbs).map_err(|_| OptigaError::Transport)?;

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
        }

        self.shield.load_pbs(&pbs);

        #[cfg(feature = "stm32u585")]
        unsafe {
            crate::hw::flash::write_pbs(&pbs)
                .map_err(|_| OptigaError::Transport)?;
            secure_log!("[OPTIGA] PBS written to flash page 126");
        }

        pbs.zeroize();

        secure_log!("[OPTIGA] PBS provisioned (handshake deferred)");
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

    /// Check if the auth-ref OID already has data_type = 0x31 (AUTHREF).
    /// Used by bringup-fresh to skip re-provisioning across runs when
    /// the secret on-chip is already the one we'd write.
    #[cfg(feature = "optiga-bringup-fresh")]
    unsafe fn auth_ref_is_authref_typed(&mut self) -> bool {
        let mut meta = [0u8; 64];
        match apdu::get_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &mut meta,
        ) {
            Ok(n) => {
                // Walk the TLV tree looking for tag 0xE8 (data type) = 0x31.
                if n < 2 || meta[0] != 0x20 { return false; }
                let root_len = meta[1] as usize;
                if 2 + root_len > n { return false; }
                let mut pos = 2;
                while pos + 2 <= 2 + root_len {
                    let tag = meta[pos];
                    let tlen = meta[pos + 1] as usize;
                    if pos + 2 + tlen > 2 + root_len { break; }
                    if tag == 0xE8 && tlen == 1 && meta[pos + 2] == 0x31 {
                        return true;
                    }
                    pos += 2 + tlen;
                }
                false
            }
            Err(_) => false,
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
    ///
    /// Under `optiga-bringup-fresh` we skip this call so the OIDs stay in
    /// Creation state and can be rewritten on the next test run. Without
    /// this escape hatch each provisioning attempt permanently consumes
    /// one entry from the chip's arbitrary-data-object budget.
    unsafe fn lock_oid(&mut self, _oid: u16) -> Result<(), OptigaError> {
        #[cfg(feature = "optiga-bringup-fresh")]
        {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: lock_oid SKIPPED (bring-up)", _oid);
            return Ok(());
        }
        #[cfg(not(feature = "optiga-bringup-fresh"))]
        {
            let (lock_meta, lock_len) = apdu::build_metadata_lock();
            apdu::set_metadata(&mut self.ifx, &mut self.shield, _oid, &lock_meta[..lock_len])
        }
    }

    /// Provision the auth-reference OID: install AC + data-type, write the
    /// PIN-derived secret, lock LcsO.
    unsafe fn provision_auth_ref(&mut self, pin_secret: &[u8; 32]) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] auth_ref: set_metadata");
        let (meta, meta_len) = apdu::build_metadata_auth_ref();
        if let Err(e) = apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &meta[..meta_len],
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_metadata FAILED: {:?}", e);
            return Err(e);
        }

        secure_log!("[OPTIGA/prov] auth_ref: set_data_object");
        if let Err(e) = apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, pin_secret,
        ) {
            secure_log!("[OPTIGA/prov] auth_ref set_data FAILED: {:?}", e);
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
        _require_shielded_read: bool,
    ) -> Result<(), OptigaError> {
        secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data ({} bytes)", oid, data.len());
        if let Err(e) = apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, data) {
            secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_data FAILED: {:?}", oid, e);
            return Err(e);
        }

        // Bring-up: skip AC install + LcsO lock entirely. Leaves OID in
        // Creation state with default "allow all" access — fine for
        // validating the provisioning / unlock round trip on real silicon
        // but MUST be re-enabled (via build_metadata_protected) before
        // shipping. See project memory for the chip-reset story.
        #[cfg(not(feature = "optiga-bringup-fresh"))]
        {
            let (meta, meta_len) =
                apdu::build_metadata_protected(apdu::OID_AUTH_REF, _require_shielded_read);
            if let Err(e) = apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len]) {
                secure_log!("[OPTIGA/prov] OID 0x{:04x}: set_metadata FAILED: {:?}", oid, e);
                return Err(e);
            }
            if let Err(e) = self.lock_oid(oid) {
                secure_log!("[OPTIGA/prov] OID 0x{:04x}: lock FAILED: {:?}", oid, e);
                return Err(e);
            }
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

        // 1. PBS (plain write; shielded connection disabled until the PRL
        // handshake bring-up issue is resolved — see project memory).
        // Still writes the PBS and metadata so the chip is ready to
        // handshake later. Subsequent APDUs go plaintext via ifx layer.
        if !self.shield.pbs_loaded {
            self.setup_pbs_no_handshake()?;
        }

        // 2. Auth reference
        //
        // Under bringup-fresh, skip if the OID already holds our secret
        // (the PIN-derived secret is deterministic across runs since PIN
        // + KDF domain are fixed, so re-provisioning would just rewrite
        // the same bytes — and the chip refuses the second write because
        // AUTHREF-typed OIDs are effectively write-once). Check by
        // reading the OID's metadata and looking for data_type = 0x31.
        let already_provisioned = {
            #[cfg(feature = "optiga-bringup-fresh")]
            {
                unsafe { self.auth_ref_is_authref_typed() }
            }
            #[cfg(not(feature = "optiga-bringup-fresh"))]
            { false }
        };
        if already_provisioned {
            secure_log!("[OPTIGA/prov] auth_ref already provisioned (bringup, skipping)");
        } else {
            let mut pin_secret = Self::derive_pin_secret(pin);
            let result = unsafe { self.provision_auth_ref(&pin_secret) };
            pin_secret.zeroize();
            result?;
        }

        // 3. User data. While shielded is disabled we drop the Conf(E140)
        // arm from Read AC — entropy/master_secret become Auto(F1D0) only,
        // same protection level as VK. I²C traffic is plaintext for now.
        // Cycle Close/Open between OIDs: on this chip, after ~3 consecutive
        // SetData operations the chip starts returning Status=0xff. The
        // pattern goes away if we release + reacquire the application
        // context, suggesting a per-session work buffer or transient-OID
        // slot gets exhausted otherwise.
        unsafe {
            self.provision_user_oid(apdu::OID_ENTROPY, entropy, false)?;
            self.reopen_application()?;
            self.provision_user_oid(apdu::OID_MASTER_SECRET, master_secret, false)?;
            self.reopen_application()?;
            self.provision_user_oid(apdu::OID_VK, vk, false)?;
            self.reopen_application()?;
            self.provision_user_oid(apdu::OID_BOOTSTRAP_VK, bootstrap_vk, false)?;
            self.reopen_application()?;
            self.provision_counter()?;
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
