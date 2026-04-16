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
    #[cfg(feature = "stm32u585")]
    pub fn load_pbs(&mut self) {
        unsafe {
            if !crate::hw::flash::is_pbs_blank() {
                let mut pbs = [0u8; 32];
                crate::hw::flash::read_pbs(&mut pbs);
                self.shield.load_pbs(&pbs);
                pbs.zeroize();
                secure_log!("[OPTIGA] PBS loaded from flash page 126");
            } else {
                secure_log!("[OPTIGA] PBS page blank (first boot)");
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

    /// Lock an OID's lifecycle to Operational (irreversible).
    ///
    /// Must be called after the AC metadata is in place so the chip knows
    /// which rules to apply post-lock.
    unsafe fn lock_oid(&mut self, oid: u16) -> Result<(), OptigaError> {
        let (lock_meta, lock_len) = apdu::build_metadata_lock();
        apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &lock_meta[..lock_len])
    }

    /// Provision the auth-reference OID: install AC + data-type, write the
    /// PIN-derived secret, lock LcsO.
    unsafe fn provision_auth_ref(&mut self, pin_secret: &[u8; 32]) -> Result<(), OptigaError> {
        // Install AC + data type FIRST so the write lands typed as AUTHREF.
        let (meta, meta_len) = apdu::build_metadata_auth_ref();
        apdu::set_metadata(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, &meta[..meta_len],
        )?;

        apdu::set_data_object(
            &mut self.ifx, &mut self.shield,
            apdu::OID_AUTH_REF, pin_secret,
        )?;

        self.lock_oid(apdu::OID_AUTH_REF)
    }

    /// Provision one user data OID: write payload, install AC, lock.
    unsafe fn provision_user_oid(
        &mut self,
        oid: u16,
        data: &[u8],
        require_shielded_read: bool,
    ) -> Result<(), OptigaError> {
        apdu::set_data_object(&mut self.ifx, &mut self.shield, oid, data)?;

        let (meta, meta_len) =
            apdu::build_metadata_protected(apdu::OID_AUTH_REF, require_shielded_read);
        apdu::set_metadata(&mut self.ifx, &mut self.shield, oid, &meta[..meta_len])?;

        self.lock_oid(oid)
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

        // 1. PBS + shielded connection
        if self.shield.pbs_loaded {
            self.ensure_shield()?;
        } else {
            self.setup_pbs()?;
        }

        // 2. Auth reference
        let mut pin_secret = Self::derive_pin_secret(pin);
        let result = unsafe { self.provision_auth_ref(&pin_secret) };
        pin_secret.zeroize();
        result?;

        // 3. User data (entropy + master_secret need Conf on read; VKs don't)
        unsafe {
            self.provision_user_oid(apdu::OID_ENTROPY, entropy, true)?;
            self.provision_user_oid(apdu::OID_MASTER_SECRET, master_secret, true)?;
            self.provision_user_oid(apdu::OID_VK, vk, false)?;
            self.provision_user_oid(apdu::OID_BOOTSTRAP_VK, bootstrap_vk, false)?;
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
        self.init()?;
        self.ensure_shield()?;

        unsafe {
            // 2. Check counter — missing counter means the device wasn't
            // provisioned, so bail with NotProvisioned rather than looping
            // on PinIncorrect.
            let attempts = match self.read_counter_raw() {
                Some(v) if v == RESET_SENTINEL => return Err(OptigaError::NotProvisioned),
                Some(v) => v,
                None => return Err(OptigaError::NotProvisioned),
            };
            if attempts >= MAX_ATTEMPTS {
                return Err(OptigaError::PinLocked);
            }

            // 3. Bump counter BEFORE verify (so a power cut can't refund the attempt)
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[attempts + 1],
            )?;

            // 4. Get challenge
            let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
            apdu::get_random(&mut self.ifx, &mut challenge)?;

            // 5. Host-side HMAC
            let mut pin_secret = Self::derive_pin_secret(pin);
            let mut hmac = Self::hmac_sha256(&pin_secret, &challenge);
            pin_secret.zeroize();

            // 6. Ask chip to verify
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
                Ok(()) => {}
                Err(OptigaError::PinIncorrect)
                | Err(OptigaError::Status(_))
                | Err(OptigaError::PinLocked) => {
                    // HMAC mismatch — chip rejects. Don't decrement counter
                    // here; we already bumped it in step 3.
                    return Err(OptigaError::PinIncorrect);
                }
                Err(e) => return Err(e),
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
        self.ensure_shield()?;

        let blank = [0u8; 32];
        unsafe {
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_ENTROPY, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_MASTER_SECRET, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_VK, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_BOOTSTRAP_VK, &blank)?;
            apdu::set_data_object(&mut self.ifx, &mut self.shield, apdu::OID_AUTH_REF, &blank)?;
            // RESET_SENTINEL tells is_provisioned() this is a wiped chip.
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[RESET_SENTINEL],
            )?;
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
