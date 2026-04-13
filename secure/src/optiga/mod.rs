//! Infineon OPTIGA Trust M V3 secure element driver.
//!
//! Stores one half of the XOR-split BIP-39 entropy, protected by a
//! hardware-enforced PIN via the OPTIGA authorization reference mechanism.
//!
//! Communication: I2C1 (PB8/PB9, shared with SE050) → IFX I2C protocol
//! (4-layer stack) → optionally wrapped in a Shielded Connection
//! (AES-128-CCM-8 with TLS-PRF-derived session keys).
//!
//! # PIN scheme
//!
//! OPTIGA Trust M uses **authorization references** rather than a dedicated
//! UserID auth object (like SE050). The 8-digit PIN is stretched via
//! HMAC-SHA256 and stored at OID 0xF1D0. Data objects are protected with
//! `Auto(0xF1D0)` access conditions — the OPTIGA hardware verifies the
//! PIN-derived secret and enforces access policy. Firmware never decides
//! if the PIN is correct.
//!
//! Attempt limiting uses a firmware-managed counter at OID 0xF1D5,
//! protected by `Conf(0xE140)` (shielded connection required for writes).

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

/// Maximum PIN attempts before lockout.
const MAX_ATTEMPTS: u8 = sphincs_tz_shared::MAX_ATTEMPTS;

/// Domain tag for deriving the PIN authorization secret.
const PIN_AUTH_DOMAIN: &[u8] = b"optiga-pin-auth-v1";

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
    // Caches populated on provision/unlock, cleared on zeroize.
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

    /// Initialize the OPTIGA Trust M: soft reset, OpenApplication.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops.
    pub fn init(&mut self) -> Result<(), OptigaError> {
        if self.ready {
            return Ok(());
        }

        unsafe {
            // Delay for power stabilization (~5 ms)
            for _ in 0..800_000 {
                cortex_m::asm::nop();
            }

            secure_log!("[OPTIGA] Init: soft reset...");
            self.ifx.soft_reset().map_err(|_| OptigaError::Transport)?;

            secure_log!("[OPTIGA] Init: OpenApplication...");
            apdu::open_application(&mut self.ifx)?;

            secure_log!("[OPTIGA] Init complete");
        }

        self.ready = true;
        Ok(())
    }

    /// Load the Platform Binding Secret from secure flash (page 126).
    ///
    /// Called at boot. If the PBS page is blank (first boot), this is a no-op —
    /// PBS will be provisioned during `store_objects`.
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

    /// Stub for non-STM32U585 builds (QEMU).
    #[cfg(not(feature = "stm32u585"))]
    pub fn load_pbs(&mut self) {
        // On QEMU, PBS is generated during provisioning and lives only in RAM.
        secure_log!("[OPTIGA] load_pbs: no flash on QEMU");
    }

    /// Provision the Platform Binding Secret (first-boot only).
    ///
    /// 1. Generate 32 random bytes from TRNG
    /// 2. Write PBS to OPTIGA OID 0xE140
    /// 3. Lock 0xE140 lifecycle to Operational (irreversible)
    /// 4. Save PBS to secure flash page 126
    /// 5. Establish the shielded connection
    fn setup_pbs(&mut self) -> Result<(), OptigaError> {
        let mut pbs = [0u8; 32];
        crate::rng::fill(&mut pbs).map_err(|_| OptigaError::Transport)?;

        unsafe {
            // Write PBS to OPTIGA (plaintext — shielded connection not yet active)
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &pbs,
            )?;

            // Lock PBS lifecycle to Operational (irreversible)
            let (lock_meta, lock_len) = apdu::build_metadata_lock();
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_PBS, &lock_meta[..lock_len],
            )?;
        }

        // Load PBS into shielded connection state
        self.shield.load_pbs(&pbs);

        // Persist PBS to secure flash
        #[cfg(feature = "stm32u585")]
        unsafe {
            crate::hw::flash::write_pbs(&pbs)
                .map_err(|_| OptigaError::Transport)?;
            secure_log!("[OPTIGA] PBS written to flash page 126");
        }

        pbs.zeroize();

        // Establish the shielded connection
        unsafe {
            self.shield.establish(&mut self.ifx)
                .map_err(|_| OptigaError::Shield)?;
        }

        secure_log!("[OPTIGA] PBS provisioned, shielded connection active");
        Ok(())
    }

    /// Ensure the shielded connection is active. Establishes if needed.
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
    ///
    /// `pin_secret = KDF("optiga-pin-auth-v1", pin, 0)`
    fn derive_pin_secret(pin: &[u8; 8]) -> [u8; 32] {
        crate::crypto::kdf(PIN_AUTH_DOMAIN, pin, 0)
    }

    /// Check if the device has been provisioned.
    ///
    /// Reads metadata of OID 0xF1D1 (entropy) and checks if its lifecycle
    /// state is Operational.
    fn check_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        unsafe {
            let mut meta = [0u8; 64];
            match apdu::get_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_ENTROPY, &mut meta,
            ) {
                Ok(n) => apdu::is_metadata_operational(&meta, n),
                Err(_) => false,
            }
        }
    }

    /// Store entropy, keys, and PIN protection on the OPTIGA Trust M.
    ///
    /// Full provisioning sequence:
    /// 1. Setup PBS (generate, write, lock, persist, establish shielded conn)
    /// 2. Write auth reference (PIN-derived secret) to 0xF1D0
    /// 3. Write data objects (entropy, VK, bootstrap_vk, master_secret)
    /// 4. Initialize attempt counter
    /// 5. Set access condition metadata on all OIDs
    /// 6. Lock all OID lifecycles to Operational
    fn store_objects(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), OptigaError> {
        self.init()?;

        // 1. Provision PBS and establish shielded connection
        self.setup_pbs()?;

        // 2. Derive PIN secret and write auth reference
        let mut pin_secret = Self::derive_pin_secret(pin);

        unsafe {
            // Set auth reference metadata BEFORE writing data (so it's typed correctly)
            let (auth_meta, auth_meta_len) = apdu::build_metadata_auth_ref();
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_AUTH_REF, &auth_meta[..auth_meta_len],
            )?;

            // Write the PIN-derived secret to the auth reference OID
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_AUTH_REF, &pin_secret,
            )?;
        }
        pin_secret.zeroize();

        unsafe {
            // 3. Write data objects (inside shielded connection)
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_ENTROPY, entropy,
            )?;
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_VK, vk,
            )?;
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_BOOTSTRAP_VK, bootstrap_vk,
            )?;
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_MASTER_SECRET, master_secret,
            )?;

            // 4. Initialize attempt counter to 0
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[0x00],
            )?;

            // 5. Set metadata (access conditions) on data OIDs
            // Entropy + master secret: Auto(0xF1D0) + Conf(0xE140)
            let (meta_sec, meta_sec_len) =
                apdu::build_metadata_protected(apdu::OID_AUTH_REF, true);
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_ENTROPY, &meta_sec[..meta_sec_len],
            )?;
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_MASTER_SECRET, &meta_sec[..meta_sec_len],
            )?;

            // VK + bootstrap VK: Auto(0xF1D0) only
            let (meta_vk, meta_vk_len) =
                apdu::build_metadata_protected(apdu::OID_AUTH_REF, false);
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_VK, &meta_vk[..meta_vk_len],
            )?;
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_BOOTSTRAP_VK, &meta_vk[..meta_vk_len],
            )?;

            // Counter: Conf(0xE140) for writes, ALW for reads
            let (meta_ctr, meta_ctr_len) = apdu::build_metadata_counter();
            apdu::set_metadata(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &meta_ctr[..meta_ctr_len],
            )?;

            // 6. Lock all OIDs to Operational (irreversible)
            let (lock_meta, lock_len) = apdu::build_metadata_lock();
            for oid in &[
                apdu::OID_AUTH_REF,
                apdu::OID_ENTROPY,
                apdu::OID_VK,
                apdu::OID_BOOTSTRAP_VK,
                apdu::OID_MASTER_SECRET,
                apdu::OID_COUNTER,
            ] {
                apdu::set_metadata(
                    &mut self.ifx, &mut self.shield,
                    *oid, &lock_meta[..lock_len],
                )?;
            }
        }

        secure_log!("[OPTIGA] Provisioning complete (6 OIDs written + locked)");
        Ok(())
    }

    /// Authenticate with PIN and read protected data objects.
    ///
    /// Flow:
    /// 1. Ensure shielded connection
    /// 2. Read + check attempt counter
    /// 3. Increment counter (decrement-before-auth)
    /// 4. Present PIN-derived secret to OPTIGA auth reference
    /// 5. On success: read entropy, master_secret, VK, bootstrap_vk
    /// 6. Reset attempt counter
    /// 7. Return master_secret
    fn authenticate_and_read(
        &mut self,
        pin: &[u8; 8],
    ) -> Result<[u8; 32], OptigaError> {
        self.init()?;
        self.ensure_shield()?;

        unsafe {
            // 2. Read attempt counter
            let mut counter_buf = [0u8; 4];
            let n = apdu::get_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, 0, 1, &mut counter_buf,
            )?;
            let attempts = if n > 0 { counter_buf[0] } else { 0 };

            if attempts >= MAX_ATTEMPTS {
                return Err(OptigaError::PinLocked);
            }

            // 3. Increment counter (decrement-before-auth pattern)
            let new_count = attempts + 1;
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[new_count],
            )?;

            // 4. Derive PIN secret and verify against auth reference
            let mut pin_secret = Self::derive_pin_secret(pin);

            // Write the candidate to 0xF1D0 — OPTIGA compares internally.
            // If it doesn't match, the Auto(0xF1D0) condition remains unsatisfied
            // and subsequent reads will fail with access denied.
            let auth_result = apdu::write_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_AUTH_REF, &pin_secret,
            );
            pin_secret.zeroize();

            if auth_result.is_err() {
                return Err(OptigaError::PinIncorrect);
            }

            // 5. Read protected data objects
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

            // 6. Reset attempt counter on success
            apdu::set_data_object(
                &mut self.ifx, &mut self.shield,
                apdu::OID_COUNTER, &[0x00],
            )?;

            // 7. Cache data
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

        // Cache VK + bootstrap VK so cmd_get_pubkey works before first unlock.
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
        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
    }
}
