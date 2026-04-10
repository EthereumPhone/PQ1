//! NXP SE050 secure element driver.
//!
//! Stores BIP-39 entropy on the SE050, protected by a hardware-enforced
//! UserID PIN (max 9 attempts before permanent lockout).
//!
//! Communication: I2C1 (PB8 SCL, PB9 SDA) -> T1oI2C -> SE05x APDUs,
//! all wrapped in an SCP03 authenticated/encrypted channel.

pub mod i2c;
pub mod t1oi2c;
pub mod apdu;
pub mod scp03;

use apdu::Se050Error;
use scp03::Scp03Session;
use t1oi2c::T1State;

// ---------------------------------------------------------------------------
// Object IDs on the SE050
// ---------------------------------------------------------------------------

/// UserID authentication object — hardware-enforced PIN.
/// Range v3 (0x7B06xxxx) to avoid stale objects from old firmware.
const USERID_OBJ: u32 = 0x7B06_0000;

/// Raw BIP-39 entropy (32 bytes), policy requires UserID auth.
const ENTROPY_OBJ: u32 = 0x7B06_0001;

/// Verifying key (32 bytes), policy requires UserID auth.
const VK_OBJ: u32 = 0x7B06_0002;

/// Bootstrap verifying key (32 bytes), policy requires UserID auth.
const BOOTSTRAP_VK_OBJ: u32 = 0x7B06_0003;

// ---------------------------------------------------------------------------
// Se050
// ---------------------------------------------------------------------------

/// SE050 secure element driver.
pub struct Se050 {
    t1: T1State,
    scp03: Scp03Session,
    ready: bool,
}

impl Se050 {
    pub const fn new() -> Self {
        Self {
            t1: T1State::new(),
            scp03: Scp03Session::new(),
            ready: false,
        }
    }

    /// Initialize the SE050: T1oI2C reset, applet SELECT, SCP03 establish.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops.
    pub fn init(&mut self) -> Result<(), Se050Error> {
        if self.ready {
            return Ok(());
        }

        unsafe {
            // Power-on delay (~3 ms for SE050 VCC stabilization)
            for _ in 0..500_000 {
                cortex_m::asm::nop();
            }

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Init: interface reset...");

            self.t1.interface_reset().map_err(|_| Se050Error::Transport)?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Init: selecting applet...");

            apdu::select_applet(&mut self.t1)?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Init: establishing SCP03...");

            scp03::establish(&mut self.scp03, &mut self.t1)?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Init complete");
        }

        self.ready = true;
        Ok(())
    }

    /// Factory reset: wipe the SE050 to factory defaults.
    ///
    /// Uses SetPlatformSCPRequest(FACTORY_RESET) which erases ALL objects
    /// including UserID auth objects that can't be individually deleted.
    /// After this the SE050 is blank — needs re-provisioning.
    ///
    /// The SCP03 session is invalidated after reset, so `ready` is cleared.
    pub fn factory_reset(&mut self) -> Result<(), Se050Error> {
        self.init()?;
        unsafe {
            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Platform factory reset...");

            apdu::platform_factory_reset(&mut self.t1, &mut self.scp03)?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] Factory reset complete");
        }
        // SCP03 session is dead after factory reset
        self.ready = false;
        self.scp03 = scp03::Scp03Session::new();
        Ok(())
    }

    /// Check if the device has been provisioned (UserID object exists).
    pub fn is_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        unsafe {
            apdu::check_exists(&mut self.t1, &mut self.scp03, USERID_OBJ)
                .unwrap_or(false)
        }
    }

    /// Provision the SE050 with a PIN-gated entropy, VK, and bootstrap VK.
    ///
    /// Creates a UserID object with the PIN (HW lesson #4: can't be deleted
    /// after creation), then stores three binary objects behind a policy
    /// that requires UserID authentication to read.
    ///
    /// Skips creation of any object that already exists (idempotent).
    pub fn provision(
        &mut self,
        pin: &[u8],
        max_attempts: u16,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
    ) -> Result<(), Se050Error> {
        self.init()?;

        unsafe {
            // UserID: skip if already exists (can't be deleted)
            let userid_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, USERID_OBJ
            ).unwrap_or(false);

            if !userid_exists {
                #[cfg(feature = "debug-log")]
                cortex_m_semihosting::hprintln!("[SE050] Creating UserID...");

                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    USERID_OBJ, pin, max_attempts,
                )?;
            }

            // Binary objects: skip if already exist (reprovisioning requires
            // factory reset due to UserID policy)
            let objs: [(u32, &[u8]); 3] = [
                (ENTROPY_OBJ, entropy),
                (VK_OBJ, vk),
                (BOOTSTRAP_VK_OBJ, bootstrap_vk),
            ];

            for (obj_id, data) in &objs {
                let exists = apdu::check_exists(
                    &mut self.t1, &mut self.scp03, *obj_id
                ).unwrap_or(false);

                if !exists {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[SE050] Writing obj 0x{:08x}...", obj_id);

                    apdu::write_binary_gated(
                        &mut self.t1, &mut self.scp03,
                        *obj_id, data, USERID_OBJ,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Authenticate with PIN and read the stored entropy.
    ///
    /// On success returns the 32-byte entropy. On PIN failure the SE050
    /// hardware decrements its attempt counter internally.
    pub fn unlock(&mut self, pin: &[u8]) -> Result<[u8; 32], Se050Error> {
        self.init()?;

        unsafe {
            // Create session against UserID
            let session_id = apdu::create_session(
                &mut self.t1, &mut self.scp03, USERID_OBJ,
            )?;

            // Verify PIN (SE050 hardware does the comparison)
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &session_id, pin,
            ) {
                let _ = apdu::close_session(
                    &mut self.t1, &mut self.scp03, &session_id,
                );
                return Err(e);
            }

            // Read entropy through the authenticated session
            let mut entropy = [0u8; 32];
            let n = apdu::read_authed(
                &mut self.t1, &mut self.scp03,
                &session_id, ENTROPY_OBJ, &mut entropy,
            );

            // Always close the session
            let _ = apdu::close_session(
                &mut self.t1, &mut self.scp03, &session_id,
            );

            match n {
                Ok(32) => Ok(entropy),
                Ok(_) => Err(Se050Error::Transport), // unexpected length
                Err(e) => Err(e),
            }
        }
    }
}
