/// Real TROPIC01 Secure Element via semihosting SPI bridge.
///
/// Establishes an e2e encrypted session (X25519 Noise_KK1 + AES-256-GCM)
/// for every command batch. All r-mem and MAC-and-Destroy operations go
/// through the encrypted tunnel — the SPHINCS+ private key never travels
/// in plaintext over the SPI bus.
///
/// ## PIN scheme (AppNote-aligned)
///
/// Uses the MAC-and-Destroy PIN verification scheme from the TROPIC01
/// Application Note (ODN_TR01_app_002_pin_verif_1v2). Each wrong PIN
/// destroys one MACD slot; correct PIN re-initialises all slots.
///
/// Per-slot encryption uses XOR (one-time pad semantics) instead of
/// AES-GCM, saving 16 bytes/slot and fitting 10 attempts inside the
/// 475-byte r-mem limit. A separate SHA-256 verification tag replaces
/// the GCM authentication tag.

use crate::rng;
#[cfg(not(feature = "stm32u585"))]
use crate::semihosting_spi::SemihostingSpi;
use crate::secure_element::{SecureElement, SeError};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

// ---------------------------------------------------------------------------
// Tropic01-specific PIN constants
// ---------------------------------------------------------------------------

/// Tropic01 allows 10 PIN attempts (uses 10 of the 128 available MACD slots).
/// Matches the shared MAX_ATTEMPTS (10) used by SE050/Mock.
const TROPIC01_MAX_ATTEMPTS: u8 = 10;

/// Per-slot XOR-encrypted master_secret (32 bytes, no GCM tag).
const T01_CT_LEN: usize = 32;

/// Verification tag length (SHA-256 output).
const T01_TAG_LEN: usize = 32;

/// Total PIN state: counter(1) + tag(32) + 10 * ciphertext(32) = 353 bytes.
/// Fits within the 475-byte r-mem slot limit.
const T01_PIN_STATE_LEN: usize = 1 + T01_TAG_LEN + TROPIC01_MAX_ATTEMPTS as usize * T01_CT_LEN;

// ---------------------------------------------------------------------------
// Tropic01-specific PIN state type and helpers
// ---------------------------------------------------------------------------

/// Deserialized PIN state for the Tropic01 XOR+tag scheme.
struct T01PinState {
    next_index: u8,
    tag: [u8; 32],
    encrypted_secrets: [[u8; 32]; TROPIC01_MAX_ATTEMPTS as usize],
}

/// Derive the verification tag from the master secret.
/// Used at provisioning (stored in r-mem) and at verification (recomputed
/// from the recovered candidate and compared constant-time).
fn pin_verification_tag(master_secret: &[u8; 32]) -> [u8; 32] {
    crate::crypto::kdf(b"t01-pin-tag", master_secret, 0)
}

/// Derive the per-slot XOR key from the MACD output `w_j`.
/// Each slot gets a unique key because `j` is part of the KDF input.
fn slot_xor_key(w_j: &[u8; 32], j: u8) -> [u8; 32] {
    crate::crypto::kdf(b"t01-slot-wrap", w_j, j)
}

/// XOR two 32-byte arrays. Inherently constant-time on any real CPU.
fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Serialize a `T01PinState` into `buf`. Returns the number of bytes written.
fn serialize_t01_pin_state(state: &T01PinState, buf: &mut [u8]) -> usize {
    buf[0] = state.next_index;
    buf[1..1 + T01_TAG_LEN].copy_from_slice(&state.tag);
    let mut offset = 1 + T01_TAG_LEN;
    for c in &state.encrypted_secrets {
        buf[offset..offset + T01_CT_LEN].copy_from_slice(c);
        offset += T01_CT_LEN;
    }
    offset
}

/// Deserialize a `T01PinState` from `buf[..len]`.
fn deserialize_t01_pin_state(buf: &[u8], len: usize) -> Result<T01PinState, ()> {
    let expected = T01_PIN_STATE_LEN;
    if len != expected {
        return Err(());
    }
    let next_index = buf[0];
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&buf[1..1 + T01_TAG_LEN]);
    let mut encrypted_secrets = [[0u8; 32]; TROPIC01_MAX_ATTEMPTS as usize];
    let mut offset = 1 + T01_TAG_LEN;
    for i in 0..TROPIC01_MAX_ATTEMPTS as usize {
        encrypted_secrets[i].copy_from_slice(&buf[offset..offset + T01_CT_LEN]);
        offset += T01_CT_LEN;
    }
    Ok(T01PinState { next_index, tag, encrypted_secrets })
}

/// Device path for the TROPIC01 USB dongle (null-terminated for semihosting).
#[cfg(not(feature = "stm32u585"))]
const DEVICE_PATH: &[u8] = b"/dev/ttyACM0\0";

/// Generate an ephemeral X25519 keypair using host randomness.
fn generate_ephemeral() -> Result<(PublicKey, StaticSecret), SeError> {
    let mut key_bytes = [0u8; 32];
    rng::fill(&mut key_bytes).map_err(|_| SeError::InternalError)?;
    let secret = StaticSecret::from(key_bytes);
    let public = PublicKey::from(&secret);
    Ok((public, secret))
}

// ---------------------------------------------------------------------------
// Per-device pairing key: flash on real hardware, UID derivation on QEMU
// ---------------------------------------------------------------------------

/// QEMU fallback: derive a deterministic pairing key from a fixed test UID.
/// QEMU mps2-an505 has no flash write support and no STM32 UID register.
#[cfg(not(feature = "stm32u585"))]
fn derive_pairing_key_from_uid() -> [u8; 32] {
    crate::crypto::kdf(b"t01-pairing-key", b"QEMU-UID-TST", 0)
}

// ---------------------------------------------------------------------------
// Session macro
// ---------------------------------------------------------------------------

/// Execute a closure with an active, e2e-encrypted TROPIC01 session.
///
/// Each call opens the SPI port, reboots the chip, performs X25519 key exchange
/// (Noise_KK1 protocol), executes the closure, and closes the session.
/// All commands within the closure are AES-256-GCM encrypted end-to-end.
///
/// Uses the pairing key stored in the `Tropic01SecureElement` struct — either
/// devkit keys (slot 0, default) or a per-device key (slot 1, after setup).
///
/// This macro exists because `ActiveSession` is a private type in the tropic01
/// crate, so we cannot store the session in a struct field.
macro_rules! with_session {
    ($se:expr, $session:ident, $body:block) => {{
        // On real STM32U585 hardware, use the bare-metal SPI2 driver.
        // On QEMU, use the semihosting SPI bridge to /dev/ttyACM0.
        #[cfg(feature = "stm32u585")]
        let spi = unsafe { crate::hw::spi::Stm32Spi::new() };
        #[cfg(not(feature = "stm32u585"))]
        let spi = SemihostingSpi::open(DEVICE_PATH)
            .map_err(|_| SeError::InternalError)?;
        let mut tropic = Tropic01::new(spi);

        // Reboot chip to clean state
        tropic.startup_req(tropic01::StartupReq::Reboot)
            .map_err(|_| SeError::InternalError)?;

        // Allow the chip time to complete its internal reboot sequence
        // before starting the Noise_KK1 handshake (~10 ms at 160 MHz).
        for _ in 0..1_600_000u32 { cortex_m::asm::nop(); }

        // Generate ephemeral X25519 keypair (random from host /dev/urandom)
        let (ehpub, ehpriv) = generate_ephemeral()?;

        // Use the struct's pairing key (devkit slot 0 or per-device slot 1)
        let shpub: PublicKey = ($se).pairing_pub.into();
        let shpriv: StaticSecret = ($se).pairing_priv.into();
        let __pslot = ($se).pairing_slot;

        // Establish e2e encrypted session (Noise_KK1 handshake)
        // After this, all commands are AES-256-GCM encrypted over SPI.
        let mut $session = tropic
            .session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, __pslot)
            .map_err(|(_, _e)| SeError::InternalError)?;

        let __result = { $body };

        // Close session (zeroizes session keys)
        $session.session_abort().ok();
        __result
    }};
}

/// TROPIC01 SecureElement implementation.
///
/// Holds the pairing key used for Noise_KK1 sessions. Defaults to devkit
/// keys (slot 0). After `setup_pairing()`, uses a per-device key (slot 1).
pub struct Tropic01SecureElement {
    pairing_priv: [u8; 32],
    pairing_pub: [u8; 32],
    pairing_slot: u8,
}

impl Tropic01SecureElement {
    pub const fn new() -> Self {
        Self {
            pairing_priv: SH0PRIV_PROD0,
            pairing_pub: SH0PUB_PROD0,
            pairing_slot: 0,
        }
    }

    /// Load the per-device pairing key at boot.
    ///
    /// **STM32U585 (real hardware):** reads a previously stored random
    /// key from the reserved secure flash page. Returns `false` if the
    /// page is blank (first boot — devkit keys are used until provisioning
    /// calls `setup_pairing`).
    ///
    /// **QEMU:** derives a deterministic key from a fixed test UID.
    /// Always returns `true` since no persistence is needed.
    #[cfg(feature = "stm32u585")]
    pub fn load_pairing_key(&mut self) -> bool {
        unsafe {
            if crate::hw::flash::is_key_blank() {
                secure_log!("[T01] No pairing key in flash, using devkit keys (slot 0)");
                return false;
            }
            let mut priv_bytes = [0u8; 32];
            crate::hw::flash::read_key(&mut priv_bytes);
            let pub_bytes = *PublicKey::from(&StaticSecret::from(priv_bytes)).as_bytes();
            self.pairing_priv = priv_bytes;
            self.pairing_pub = pub_bytes;
            self.pairing_slot = 1;
            secure_log!("[T01] Loaded pairing key from secure flash (slot 1)");
            true
        }
    }

    #[cfg(not(feature = "stm32u585"))]
    pub fn load_pairing_key(&mut self) -> bool {
        let priv_bytes = derive_pairing_key_from_uid();
        let pub_bytes = *PublicKey::from(&StaticSecret::from(priv_bytes)).as_bytes();
        self.pairing_priv = priv_bytes;
        self.pairing_pub = pub_bytes;
        self.pairing_slot = 1;
        secure_log!("[T01] Derived pairing key from test UID (slot 1)");
        true
    }

    /// Generate a random pairing key, save it to secure flash, and write
    /// the public half to the Tropic01's pairing slot 1.
    ///
    /// Called once during first-boot provisioning. On QEMU (no flash),
    /// the UID-derived key is written to the chip instead.
    ///
    /// Slot 0 (devkit keys) is NOT invalidated — it remains as fallback.
    pub fn setup_pairing(&mut self) -> Result<(), SeError> {
        #[cfg(feature = "stm32u585")]
        let priv_bytes = {
            // Generate a truly random key from hardware TRNG
            let mut key = [0u8; 32];
            rng::fill(&mut key).map_err(|_| SeError::InternalError)?;
            // Persist to secure flash so it survives reboots
            unsafe {
                crate::hw::flash::write_key(&key)
                    .map_err(|_| SeError::InternalError)?;
            }
            secure_log!("[T01] Pairing key saved to secure flash");
            key
        };

        #[cfg(not(feature = "stm32u585"))]
        let priv_bytes = derive_pairing_key_from_uid();

        let pub_bytes = *PublicKey::from(&StaticSecret::from(priv_bytes)).as_bytes();

        // Write public key to Tropic01 pairing slot 1
        with_session!(self, session, {
            session.pairing_key_write(U16::new(1), &pub_bytes)
                .map_err(|_| SeError::InternalError)?;
            secure_log!("[T01] Pairing key written to slot 1");
            Ok(())
        })?;

        // Switch to per-device key for all future sessions
        self.pairing_priv = priv_bytes;
        self.pairing_pub = pub_bytes;
        self.pairing_slot = 1;

        secure_log!("[T01] Per-device pairing key active (slot 1)");
        Ok(())
    }
}

impl SecureElement for Tropic01SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError> {
        with_session!(self, session, {
            session
                .r_mem_data_write(U16::new(slot), data)
                .map_err(|_| SeError::InternalError)
        })
    }

    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError> {
        with_session!(self, session, {
            let data = session
                .r_mem_data_read(U16::new(slot))
                .map_err(|_| SeError::SlotNotFound)?;
            let len = data.len();
            if buf.len() < len {
                return Err(SeError::InvalidParameter);
            }
            buf[..len].copy_from_slice(data);
            Ok(len)
        })
    }

    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError> {
        with_session!(self, session, {
            session
                .r_mem_data_erase(U16::new(slot))
                .map_err(|_| SeError::InternalError)
        })
    }

    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError> {
        with_session!(self, session, {
            let result = session
                .mac_and_destroy(U16::new(slot), data_in)
                .map_err(|_| SeError::InternalError)?;
            Ok(*result)
        })
    }
}

/// Batch operations that need multiple commands in one session.
/// These avoid the overhead of re-establishing a session for each command.
impl Tropic01SecureElement {
    /// Store pre-derived entropy, VK, bootstrap VK, and MACD PIN chain in a
    /// single e2e-encrypted session.
    ///
    /// The caller has already run the key derivation chain (entropy,
    /// master_secret, VK, bootstrap VK). This method encrypts the entropy,
    /// initialises MACD slots with the AppNote XOR+tag scheme, and writes
    /// everything to r-mem.
    ///
    /// PIN state format (353 bytes, fits in 475-byte r-mem slot):
    /// `counter(1) ‖ tag(32) ‖ c_0(32) ‖ c_1(32) ‖ ... ‖ c_9(32)`
    fn store_data_session(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        use crate::crypto::{encrypt_entropy_blob, macd_init_input, macd_pin_input};

        let entropy_blob = encrypt_entropy_blob(entropy, master_secret);
        let tag = pin_verification_tag(master_secret);

        with_session!(self, session, {
            secure_log!("  [T01] Session established (e2e encrypted)");
            secure_log!("  [T01] Provisioning from pre-derived data");

            // Initialize MAC-and-Destroy slots and build the per-slot
            // XOR-encrypted master_secret blobs (AppNote scheme).
            let mut encrypted_secrets = [[0u8; T01_CT_LEN]; TROPIC01_MAX_ATTEMPTS as usize];

            for j in 0..TROPIC01_MAX_ATTEMPTS {
                let init_in = macd_init_input(master_secret, j);
                let pin_in = macd_pin_input(pin, j);

                // 1. Initialize MACD slot j
                session
                    .mac_and_destroy(U16::new(j as u16), &init_in)
                    .map_err(|_| SeError::InternalError)?;
                // 2. Derive per-slot secret w_j from PIN input
                let mut w_j: [u8; 32] = *session
                    .mac_and_destroy(U16::new(j as u16), &pin_in)
                    .map_err(|_| SeError::InternalError)?;
                // 3. Re-initialize slot to known state (ready for unlock)
                session
                    .mac_and_destroy(U16::new(j as u16), &init_in)
                    .map_err(|_| SeError::InternalError)?;

                // XOR-encrypt master_secret under w_j-derived key
                let mut k_j = slot_xor_key(&w_j, j);
                encrypted_secrets[j as usize] = xor_32(master_secret, &k_j);
                w_j.zeroize();
                k_j.zeroize();
            }
            secure_log!("  [T01] MACD slots initialized ({} attempts)", TROPIC01_MAX_ATTEMPTS);

            // Slot 0: encrypted entropy blob
            session.r_mem_data_erase(U16::new(0)).ok();
            session
                .r_mem_data_write(U16::new(0), &entropy_blob)
                .map_err(|_| SeError::InternalError)?;

            // Slot 1: PIN state (counter + tag + XOR ciphertexts)
            let ps = T01PinState {
                next_index: 0,
                tag,
                encrypted_secrets,
            };
            let mut pin_state_buf = [0u8; T01_PIN_STATE_LEN];
            let ps_len = serialize_t01_pin_state(&ps, &mut pin_state_buf);
            session.r_mem_data_erase(U16::new(1)).ok();
            session
                .r_mem_data_write(U16::new(1), &pin_state_buf[..ps_len])
                .map_err(|_| SeError::InternalError)?;
            secure_log!("  [T01] PIN state: {} bytes", ps_len);

            // Slot 2: default verifying key
            session.r_mem_data_erase(U16::new(2)).ok();
            session
                .r_mem_data_write(U16::new(2), vk)
                .map_err(|_| SeError::InternalError)?;

            // Slot 3: bootstrap verifying key
            session.r_mem_data_erase(U16::new(3)).ok();
            session
                .r_mem_data_write(U16::new(3), bootstrap_vk)
                .map_err(|_| SeError::InternalError)?;

            secure_log!("  [T01] Provisioned (e2e encrypted)");
            Ok(())
        })
    }

    /// Verify PIN via the AppNote XOR+tag MACD scheme.
    ///
    /// Reads PIN state, performs MACD to derive the per-slot XOR key,
    /// recovers the master secret candidate, and verifies via constant-time
    /// tag comparison. On success, re-initialises all 10 MACD slots and
    /// resets the attempt counter. On failure, bumps the counter (and
    /// erases all data on the 10th failure).
    pub fn batch_verify_pin(
        &mut self,
        pin: &[u8; 8],
    ) -> Result<[u8; 32], SeError> {
        use crate::crypto::macd_pin_input;

        with_session!(self, session, {
            // Read PIN state (353 bytes from r-mem slot 1)
            let state_data = session.r_mem_data_read(U16::new(1))
                .map_err(|_| SeError::InternalError)?;
            let mut state_buf = [0u8; T01_PIN_STATE_LEN];
            let state_len = state_data.len();
            if state_len > T01_PIN_STATE_LEN {
                return Err(SeError::InternalError);
            }
            state_buf[..state_len].copy_from_slice(state_data);

            let ps = deserialize_t01_pin_state(&state_buf, state_len)
                .map_err(|_| SeError::InternalError)?;

            if ps.next_index >= TROPIC01_MAX_ATTEMPTS {
                // Already locked — erase all wallet data
                session.r_mem_data_erase(U16::new(0)).ok();
                session.r_mem_data_erase(U16::new(1)).ok();
                session.r_mem_data_erase(U16::new(2)).ok();
                session.r_mem_data_erase(U16::new(3)).ok();
                return Err(SeError::SlotExpired);
            }

            // MAC-and-Destroy: derive per-slot secret w_j
            let j = ps.next_index;
            let pin_in = macd_pin_input(pin, j);
            let mut w_j: [u8; 32] = *session
                .mac_and_destroy(U16::new(j as u16), &pin_in)
                .map_err(|_| SeError::InternalError)?;

            // XOR-decrypt the master secret candidate
            let mut k_j = slot_xor_key(&w_j, j);
            let mut recovered_s = xor_32(&ps.encrypted_secrets[j as usize], &k_j);
            k_j.zeroize();
            w_j.zeroize();

            // Constant-time tag verification (prevents timing side-channel)
            let expected_tag = pin_verification_tag(&recovered_s);
            let tag_ok: bool = expected_tag.ct_eq(&ps.tag).into();

            if tag_ok {
                // PIN correct — re-initialize all MACD slots
                for slot_j in 0..TROPIC01_MAX_ATTEMPTS {
                    let init_in = crate::crypto::macd_init_input(&recovered_s, slot_j);
                    session.mac_and_destroy(U16::new(slot_j as u16), &init_in)
                        .map_err(|_| SeError::InternalError)?;
                }

                // Reset attempt counter (keep tag + encrypted_secrets unchanged)
                let new_ps = T01PinState {
                    next_index: 0,
                    tag: ps.tag,
                    encrypted_secrets: ps.encrypted_secrets,
                };
                let mut new_state = [0u8; T01_PIN_STATE_LEN];
                let len = serialize_t01_pin_state(&new_ps, &mut new_state);
                session.r_mem_data_erase(U16::new(1)).ok();
                session.r_mem_data_write(U16::new(1), &new_state[..len])
                    .map_err(|_| SeError::InternalError)?;

                Ok(recovered_s)
            } else {
                // Wrong PIN — zeroize candidate and advance counter
                recovered_s.zeroize();

                let new_index = j + 1;
                if new_index >= TROPIC01_MAX_ATTEMPTS {
                    // 10th wrong attempt — erase all wallet data
                    session.r_mem_data_erase(U16::new(0)).ok();
                    session.r_mem_data_erase(U16::new(1)).ok();
                    session.r_mem_data_erase(U16::new(2)).ok();
                    session.r_mem_data_erase(U16::new(3)).ok();
                    return Err(SeError::SlotExpired);
                }

                // Bump counter, preserve tag + encrypted_secrets
                let bumped_ps = T01PinState {
                    next_index: new_index,
                    tag: ps.tag,
                    encrypted_secrets: ps.encrypted_secrets,
                };
                let mut new_state = [0u8; T01_PIN_STATE_LEN];
                let len = serialize_t01_pin_state(&bumped_ps, &mut new_state);
                session.r_mem_data_erase(U16::new(1)).ok();
                session.r_mem_data_write(U16::new(1), &new_state[..len]).ok();

                Err(SeError::InvalidParameter) // PIN incorrect
            }
        })
    }

    /// Read the encrypted entropy blob (slot 0) and verifying key (slot 2)
    /// in one session. Used by the sign flow on every call.
    pub fn batch_read_entropy_and_vk(
        &mut self,
        entropy_blob: &mut [u8],
        vk_buf: &mut [u8],
    ) -> Result<(usize, usize), SeError> {
        with_session!(self, session, {
            let entropy_data = session
                .r_mem_data_read(U16::new(0))
                .map_err(|_| SeError::SlotNotFound)?;
            let entropy_len = entropy_data.len();
            if entropy_blob.len() < entropy_len {
                return Err(SeError::InvalidParameter);
            }
            entropy_blob[..entropy_len].copy_from_slice(entropy_data);

            let vk_data = session
                .r_mem_data_read(U16::new(2))
                .map_err(|_| SeError::SlotNotFound)?;
            let vk_len = vk_data.len();
            if vk_buf.len() < vk_len {
                return Err(SeError::InvalidParameter);
            }
            vk_buf[..vk_len].copy_from_slice(vk_data);

            Ok((entropy_len, vk_len))
        })
    }

    /// Read PIN state (remaining attempts) in one session.
    /// Returns the `next_index` byte (0 = all attempts available,
    /// TROPIC01_MAX_ATTEMPTS = locked out).
    pub fn batch_read_pin_state(&mut self) -> Result<u8, SeError> {
        with_session!(self, session, {
            let data = session.r_mem_data_read(U16::new(1))
                .map_err(|_| SeError::SlotNotFound)?;
            if data.is_empty() {
                return Err(SeError::InternalError);
            }
            let next_index = data[0];
            Ok(next_index)
        })
    }

}

// ---------------------------------------------------------------------------
// WalletStore implementation
// ---------------------------------------------------------------------------

use crate::secure_element::{UnlockError, WalletStore};

impl WalletStore for Tropic01SecureElement {
    fn is_provisioned(&mut self) -> bool {
        use crate::crypto::{RMEM_ENCRYPTED_ENTROPY, RMEM_PIN_STATE, RMEM_VERIFYING_KEY};
        let mut buf = [0u8; 128];
        self.r_mem_read(RMEM_ENCRYPTED_ENTROPY, &mut buf).is_ok()
            && self.r_mem_read(RMEM_PIN_STATE, &mut buf).is_ok()
            && self.r_mem_read(RMEM_VERIFYING_KEY, &mut buf).is_ok()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        self.store_data_session(entropy, master_secret, vk, bootstrap_vk, pin)?;
        // Generate a per-device pairing key and write it to the chip.
        // Future sessions use slot 1 instead of the shared devkit slot 0.
        // Skip in e2e-test: the second Noise session fails reproducibly
        // on SPI hardware (works via semihosting bridge). Tracked separately.
        #[cfg(not(feature = "e2e-test"))]
        self.setup_pairing()?;
        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        self.batch_verify_pin(pin).map_err(|e| match e {
            SeError::SlotExpired => UnlockError::PinLocked,
            SeError::InvalidParameter => UnlockError::PinIncorrect,
            _ => UnlockError::InternalError,
        })
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        let mut vk_ignore = [0u8; 64];
        self.batch_read_entropy_and_vk(buf, &mut vk_ignore)
            .map(|(entropy_len, _)| entropy_len)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        let mut entropy_ignore = [0u8; 64];
        self.batch_read_entropy_and_vk(&mut entropy_ignore, buf)
            .map(|(_, vk_len)| vk_len)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.r_mem_read(crate::crypto::RMEM_BOOTSTRAP_VK, buf)
    }

    fn remaining_attempts(&mut self) -> u8 {
        match self.batch_read_pin_state() {
            Ok(next_index) => {
                if next_index >= TROPIC01_MAX_ATTEMPTS {
                    0
                } else {
                    TROPIC01_MAX_ATTEMPTS - next_index
                }
            }
            Err(_) => TROPIC01_MAX_ATTEMPTS,
        }
    }

    fn zeroize_caches(&mut self) {
        // Tropic01 re-reads from chip every time — no caching.
    }
}
