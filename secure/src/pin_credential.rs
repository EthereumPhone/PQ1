//! Die-bound PIN credentials and seed-half masks (issue #855).
//!
//! ## The defect this replaces
//!
//! Both secure elements used to receive a value that was the same on every
//! device and needed no secret from the microcontroller:
//!
//! - SE050: the UserID credential was the raw 8-digit PIN.
//! - OPTIGA: the F1D0 authorization secret was one unsalted, unkeyed
//!   `SHA-256("optiga-pin-auth-v1" || PIN || 0)`.
//!
//! Reading the stored credential out of **either** chip therefore gave the
//! PIN — directly from the SE050, or by trying all 10^8 values offline
//! against the OPTIGA hash, with no attempt counter involved. The PIN then
//! opened the other chip on the first try. (Ledger Donjon report, scenarios
//! A, B and C.)
//!
//! ## What is presented instead
//!
//! Every value that depends on the PIN and reaches a chip is one output of a
//! pseudo-random function keyed by the **device hardware key**, which lives
//! in the microcontroller and never in either secure element:
//!
//! ```text
//! out = PRF(device_key, label || salt || PIN)
//! ```
//!
//! - `label` is a fixed 22-byte tag, different for each (chip, wallet,
//!   purpose). Knowing the SE050 credential says nothing about the OPTIGA
//!   credential.
//! - `salt` is 32 random bytes drawn at provisioning and kept in secure
//!   flash. Every wipe destroys it first, so a credential read out of a chip
//!   can no longer be recomputed by the device afterwards (`pin_salt`).
//! - The comparison still happens inside the secure element (invariant #2).
//!   Only the value presented changes.
//!
//! Each chip also stores its seed half XOR a PIN-keyed mask from the same
//! PRF, so the halves read out of **both** chips do not XOR to the seed
//! without the device key and the PIN.
//!
//! ## What this does not do
//!
//! - Code running in the secure world can select the device key and
//!   recompute every value here. That attacker is out of scope for this
//!   module; measured boot, RDP-2 and TrustZone answer it.
//! - The PRF is supplied by the caller. Under `otp-hardcoded-master-key`
//!   the firmware passes a PRF keyed by a compile-time constant, and at
//!   RDP-0 the silicon DHUK is a constant shared by every part. In both
//!   cases the outputs are **not** die-bound. See `hw::secret_keys`.
//!
//! This module is pure: no hardware, no flash, no secure-element traffic.
//! It is compiled into host tests, where the PRF is software AES-CMAC.

// Nothing consumes this on the QEMU / mock-SE builds, which have no
// OPTIGA or SE050 driver.
#![allow(dead_code)]

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// PIN length in bytes (eight digits).
pub const PIN_LEN: usize = 8;
/// Per-provisioning salt length.
pub const SALT_LEN: usize = 32;
/// Every domain label has exactly this length.
pub const LABEL_LEN: usize = 22;
/// Bytes handed to the PRF: `label || salt || PIN`.
pub const PRF_INPUT_LEN: usize = LABEL_LEN + SALT_LEN + PIN_LEN;
/// OPTIGA authorization-reference secret length (F1D0 / F1D8).
pub const OPTIGA_CRED_LEN: usize = 32;
/// SE050 UserID value length (the object accepts 4..=16 bytes).
pub const SE050_CRED_LEN: usize = 16;
/// Seed-half length.
pub const HALF_LEN: usize = 32;

// The firmware PRF (`hw::secret_keys::derive_into`) copies its input into a
// 65-byte scratch buffer and appends one counter byte, so the input may be
// at most 64 bytes.
const _: () = assert!(PRF_INPUT_LEN <= 64, "PRF input overflows the SAES KDF scratch buffer");

/// Which of the two wallets a credential set belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WalletRole {
    /// The real wallet (OPTIGA F1D0, SE050 `USERID_OBJ`).
    Real,
    /// The decoy wallet (OPTIGA F1D8, SE050 `DURESS_USERID_OBJ`).
    Duress,
}

/// The four labels of one wallet role.
struct Labels {
    cred_optiga: &'static [u8; LABEL_LEN],
    cred_se050: &'static [u8; LABEL_LEN],
    mask_optiga: &'static [u8; LABEL_LEN],
    mask_se050: &'static [u8; LABEL_LEN],
}

// `O` is the OPTIGA side (it holds `half_O`), `E` the SE050 side (`half_E`).
//
// All eight labels have the same length and the salt and PIN are fixed
// length, so `label || salt || PIN` is an injective encoding: two different
// (label, salt, PIN) triples never produce the same PRF input.
//
// These are persisted-credential domain tags. Changing one makes every
// provisioned device present a different value to its chip. Bump the `-v1`
// suffix deliberately; never edit in place.
const REAL: Labels = Labels {
    cred_optiga: b"pqsigner/pin-cred-O-v1",
    cred_se050: b"pqsigner/pin-cred-E-v1",
    mask_optiga: b"pqsigner/pin-mask-O-v1",
    mask_se050: b"pqsigner/pin-mask-E-v1",
};
const DURESS: Labels = Labels {
    cred_optiga: b"pqsigner/dur-cred-O-v1",
    cred_se050: b"pqsigner/dur-cred-E-v1",
    mask_optiga: b"pqsigner/dur-mask-O-v1",
    mask_se050: b"pqsigner/dur-mask-E-v1",
};

const fn labels_for(role: WalletRole) -> &'static Labels {
    match role {
        WalletRole::Real => &REAL,
        WalletRole::Duress => &DURESS,
    }
}

/// `true` when every byte of `bytes` equals `value`.
fn all_bytes_are(bytes: &[u8], value: u8) -> bool {
    let mut diff = 0u8;
    for b in bytes {
        diff |= b ^ value;
    }
    diff == 0
}

/// A 16-byte block that reads as erased flash (`0xFF`) or as a destroyed
/// record (`0x00`).
fn block_is_degenerate(block: &[u8]) -> bool {
    all_bytes_are(block, 0x00) || all_bytes_are(block, 0xFF)
}

/// The per-provisioning salt.
///
/// It can only be built from bytes that are usable: neither 16-byte half may
/// be all `0x00` or all `0xFF`. Those two patterns are what a destroyed and
/// an erased flash quad-word read as, so a salt holding one of them would be
/// indistinguishable from "no salt" in `pin_salt`.
pub struct PinSalt([u8; SALT_LEN]);

impl PinSalt {
    /// Wrap `bytes` as a salt, or `None` when they are not usable.
    #[must_use]
    pub fn new(bytes: [u8; SALT_LEN]) -> Option<Self> {
        if block_is_degenerate(&bytes[..16]) || block_is_degenerate(&bytes[16..]) {
            let mut b = bytes;
            b.zeroize();
            return None;
        }
        Some(Self(bytes))
    }

    /// The raw salt bytes, for persisting and for the PRF input.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl Drop for PinSalt {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The value written to OPTIGA F1D0 (or F1D8) and used as the HMAC key when
/// answering the chip's challenge. Not `Clone`, not `Debug`; wiped on drop.
pub struct OptigaPinCredential([u8; OPTIGA_CRED_LEN]);

impl OptigaPinCredential {
    /// The credential bytes, for the OPTIGA driver only.
    #[must_use]
    pub fn expose_for_optiga(&self) -> &[u8; OPTIGA_CRED_LEN] {
        &self.0
    }
}

impl Drop for OptigaPinCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The value written to the SE050 user UserID object (or the decoy one) and
/// presented in `VerifySessionUserID`. Not `Clone`, not `Debug`; wiped on
/// drop.
pub struct Se050PinCredential([u8; SE050_CRED_LEN]);

impl Se050PinCredential {
    /// The credential bytes, for the SE050 driver only.
    #[must_use]
    pub fn expose_for_se050(&self) -> &[u8; SE050_CRED_LEN] {
        &self.0
    }
}

impl Drop for Se050PinCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A PIN-keyed mask for one seed half. Not `Clone`, not `Debug`; wiped on
/// drop.
pub struct HalfMask([u8; HALF_LEN]);

impl HalfMask {
    /// XOR the mask into `half`. Masking and unmasking are the same
    /// operation.
    #[must_use]
    pub fn apply(&self, half: &[u8; HALF_LEN]) -> Zeroizing<[u8; HALF_LEN]> {
        let mut out = Zeroizing::new([0u8; HALF_LEN]);
        for i in 0..HALF_LEN {
            out[i] = half[i] ^ self.0[i];
        }
        out
    }
}

impl Drop for HalfMask {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything one wallet role needs from one PIN.
pub struct PinCredentialSet {
    /// Presented to the OPTIGA.
    pub optiga: OptigaPinCredential,
    /// Presented to the SE050.
    pub se050: Se050PinCredential,
    /// Masks the half stored on the OPTIGA.
    pub mask_optiga: HalfMask,
    /// Masks the half stored on the SE050.
    pub mask_se050: HalfMask,
}

/// Everything PIN-dependent the OPTIGA is given for one wallet: its
/// credential, and its seed half already masked.
///
/// The fields are private and the only constructor is [`chip_images`]. A
/// caller therefore cannot pair a credential with a half that was not masked
/// for that chip, nor hand a chip the other chip's credential.
pub struct OptigaImage {
    credential: OptigaPinCredential,
    stored_half: Zeroizing<[u8; HALF_LEN]>,
}

impl OptigaImage {
    /// The value for F1D0 (or F1D8).
    #[must_use]
    pub fn credential(&self) -> &OptigaPinCredential {
        &self.credential
    }

    /// `half_O XOR mask_O`: what the entropy object holds.
    #[must_use]
    pub fn stored_half(&self) -> &[u8; HALF_LEN] {
        &self.stored_half
    }
}

/// Everything PIN-dependent the SE050 is given for one wallet. Same rules as
/// [`OptigaImage`].
pub struct Se050Image {
    credential: Se050PinCredential,
    stored_half: Zeroizing<[u8; HALF_LEN]>,
}

impl Se050Image {
    /// The value of the user (or duress) UserID object.
    #[must_use]
    pub fn credential(&self) -> &Se050PinCredential {
        &self.credential
    }

    /// `half_E XOR mask_E`: what the entropy object holds.
    #[must_use]
    pub fn stored_half(&self) -> &[u8; HALF_LEN] {
        &self.stored_half
    }
}

/// Decide what each chip stores for a wallet.
///
/// `half_o` and `half_e` are the two XOR halves of the entropy (after the
/// optional ML-KEM seal, when that feature is on: the mask is the outermost
/// layer). Each half is masked with its own PIN-keyed mask and paired with
/// its own chip's credential; the masks are wiped when this returns.
///
/// This is the single place where a credential and a half are assigned to a
/// chip. `DualSecureElement` passes the two images straight to the drivers.
#[must_use]
pub fn chip_images(
    creds: PinCredentialSet,
    half_o: &[u8; HALF_LEN],
    half_e: &[u8; HALF_LEN],
) -> (OptigaImage, Se050Image) {
    let PinCredentialSet { optiga, se050, mask_optiga, mask_se050 } = creds;
    let optiga_image = OptigaImage { credential: optiga, stored_half: mask_optiga.apply(half_o) };
    let se050_image = Se050Image { credential: se050, stored_half: mask_se050.apply(half_e) };
    (optiga_image, se050_image)
}

/// Why a derivation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum DeriveError<E> {
    /// The PRF reported an error.
    Prf(E),
    /// An output was all `0x00` or all `0xFF`, or two outputs that must be
    /// independent started with the same 16 bytes. A healthy PRF does not
    /// do this; a skipped, stuck or stubbed one does.
    DegenerateOutput,
}

/// Run the PRF once for `label` and write the result into `out`.
fn expand<E, F>(
    info: &mut [u8; PRF_INPUT_LEN],
    label: &[u8; LABEL_LEN],
    out: &mut [u8],
    prf: &mut F,
) -> Result<(), DeriveError<E>>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), E>,
{
    info[..LABEL_LEN].copy_from_slice(label);
    prf(&info[..], out).map_err(DeriveError::Prf)?;
    if block_is_degenerate(out) {
        return Err(DeriveError::DegenerateOutput);
    }
    Ok(())
}

/// Derive the credential set of `role` for `pin` under `salt`.
///
/// `prf(info, out)` must fill `out` with a pseudo-random function of `info`
/// under the device key. The firmware passes
/// `hw::secret_keys::derive_into`; host tests pass software AES-CMAC.
///
/// # Errors
/// [`DeriveError::Prf`] when the PRF fails, [`DeriveError::DegenerateOutput`]
/// when its outputs are not plausible PRF outputs. In both cases no
/// credential is returned and every partial output has been wiped.
pub fn derive_set<E, F>(
    role: WalletRole,
    salt: &PinSalt,
    pin: &[u8; PIN_LEN],
    mut prf: F,
) -> Result<PinCredentialSet, DeriveError<E>>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), E>,
{
    let labels = labels_for(role);

    // `label || salt || PIN`. The label slot is rewritten for each output;
    // the whole buffer is wiped when it drops, on every return path.
    let mut info = Zeroizing::new([0u8; PRF_INPUT_LEN]);
    info[LABEL_LEN..LABEL_LEN + SALT_LEN].copy_from_slice(salt.as_bytes());
    info[LABEL_LEN + SALT_LEN..].copy_from_slice(pin);

    // Each output is built in place inside its wiping wrapper, so an early
    // return never leaves a bare copy behind.
    let mut set = PinCredentialSet {
        optiga: OptigaPinCredential([0u8; OPTIGA_CRED_LEN]),
        se050: Se050PinCredential([0u8; SE050_CRED_LEN]),
        mask_optiga: HalfMask([0u8; HALF_LEN]),
        mask_se050: HalfMask([0u8; HALF_LEN]),
    };

    expand(&mut info, labels.cred_optiga, &mut set.optiga.0, &mut prf)?;
    expand(&mut info, labels.cred_se050, &mut set.se050.0, &mut prf)?;
    expand(&mut info, labels.mask_optiga, &mut set.mask_optiga.0, &mut prf)?;
    expand(&mut info, labels.mask_se050, &mut set.mask_se050.0, &mut prf)?;

    // The four outputs must be unrelated. If any two start with the same 16
    // bytes the PRF ignored its label, and the value held by one chip would
    // reveal the value held by the other.
    let heads: [&[u8]; 4] = [
        &set.optiga.0[..16],
        &set.se050.0[..16],
        &set.mask_optiga.0[..16],
        &set.mask_se050.0[..16],
    ];
    let mut collision = 0u8;
    for i in 0..heads.len() {
        for j in (i + 1)..heads.len() {
            collision |= heads[i].ct_eq(heads[j]).unwrap_u8();
        }
    }
    if collision != 0 {
        return Err(DeriveError::DegenerateOutput);
    }

    Ok(set)
}

/// Whether credentials may be derived at the current read-out protection
/// level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MintPolicy {
    /// Production: only at RDP level 2. Below it the silicon DHUK is not
    /// yet the final per-die key (at RDP-0 it is a constant shared by every
    /// part), so a credential minted there is not die-bound.
    RequireRdp2,
    /// Bench and bring-up: any level. The credential is then only as
    /// die-bound as the PRF key the build uses.
    AnyLevel,
}

/// Decide whether derivation is allowed.
///
/// `rdp_is_level2` is the live read-out protection state. Kept as a pure
/// function so the rule is executable on the host.
#[must_use]
pub const fn mint_allowed(policy: MintPolicy, rdp_is_level2: bool) -> bool {
    match policy {
        MintPolicy::RequireRdp2 => rdp_is_level2,
        MintPolicy::AnyLevel => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmac::kdf_cmac_counter_generic;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;

    const PIN: [u8; PIN_LEN] = *b"48151623";
    const OTHER_PIN: [u8; PIN_LEN] = *b"48151624";
    const DEVICE_KEY_A: [u8; 32] = [0xA5; 32];
    const DEVICE_KEY_B: [u8; 32] = [0x3C; 32];

    fn salt(fill: u8) -> PinSalt {
        let mut b = [fill; SALT_LEN];
        b[0] ^= 0x01;
        b[16] ^= 0x02;
        PinSalt::new(b).expect("test salt is usable")
    }

    /// The same construction the firmware uses on the `saes-dhuk` path:
    /// `AES-256-CMAC(key, info || counter)` per 16-byte block, with software
    /// AES standing in for the SAES peripheral.
    fn device_prf(key: [u8; 32]) -> impl FnMut(&[u8], &mut [u8]) -> Result<(), ()> {
        move |info: &[u8], out: &mut [u8]| {
            let cipher = Aes256::new_from_slice(&key).map_err(|_| ())?;
            let mut scratch = [0u8; 65];
            kdf_cmac_counter_generic::<(), _>(
                info,
                &mut scratch,
                |block| {
                    let mut b = aes::Block::clone_from_slice(block);
                    cipher.encrypt_block(&mut b);
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&b);
                    Ok(o)
                },
                out,
            )
            .map_err(|_| ())
        }
    }

    fn set(key: [u8; 32], role: WalletRole, s: &PinSalt, pin: &[u8; 8]) -> PinCredentialSet {
        derive_set(role, s, pin, device_prf(key)).expect("derivation succeeds")
    }

    #[test]
    fn positive_same_inputs_give_the_same_credentials() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let b = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        assert_eq!(a.optiga.expose_for_optiga(), b.optiga.expose_for_optiga());
        assert_eq!(a.se050.expose_for_se050(), b.se050.expose_for_se050());
        assert_eq!(*a.mask_optiga.apply(&[0; 32]), *b.mask_optiga.apply(&[0; 32]));
        assert_eq!(*a.mask_se050.apply(&[0; 32]), *b.mask_se050.apply(&[0; 32]));
    }

    #[test]
    fn negative_credentials_are_bound_to_the_device_key() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let b = set(DEVICE_KEY_B, WalletRole::Real, &s, &PIN);
        assert_ne!(a.optiga.expose_for_optiga(), b.optiga.expose_for_optiga());
        assert_ne!(a.se050.expose_for_se050(), b.se050.expose_for_se050());
        assert_ne!(*a.mask_optiga.apply(&[0; 32]), *b.mask_optiga.apply(&[0; 32]));
        assert_ne!(*a.mask_se050.apply(&[0; 32]), *b.mask_se050.apply(&[0; 32]));
    }

    #[test]
    fn negative_credentials_are_bound_to_the_salt() {
        let a = set(DEVICE_KEY_A, WalletRole::Real, &salt(0x11), &PIN);
        let b = set(DEVICE_KEY_A, WalletRole::Real, &salt(0x22), &PIN);
        assert_ne!(a.optiga.expose_for_optiga(), b.optiga.expose_for_optiga());
        assert_ne!(a.se050.expose_for_se050(), b.se050.expose_for_se050());
        assert_ne!(*a.mask_optiga.apply(&[0; 32]), *b.mask_optiga.apply(&[0; 32]));
        assert_ne!(*a.mask_se050.apply(&[0; 32]), *b.mask_se050.apply(&[0; 32]));
    }

    #[test]
    fn negative_credentials_are_bound_to_the_pin() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let b = set(DEVICE_KEY_A, WalletRole::Real, &s, &OTHER_PIN);
        assert_ne!(a.optiga.expose_for_optiga(), b.optiga.expose_for_optiga());
        assert_ne!(a.se050.expose_for_se050(), b.se050.expose_for_se050());
    }

    /// The property scenario A of the report turns on: what the SE050 holds
    /// must not be what the OPTIGA holds, in whole or in part.
    #[test]
    fn negative_the_two_chips_never_hold_the_same_value() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let o = a.optiga.expose_for_optiga();
        let e = a.se050.expose_for_se050();
        assert_ne!(&o[..16], &e[..]);
        assert_ne!(&o[16..], &e[..]);
    }

    #[test]
    fn negative_real_and_duress_credentials_differ_for_the_same_pin() {
        let s = salt(0x11);
        let real = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let duress = set(DEVICE_KEY_A, WalletRole::Duress, &s, &PIN);
        assert_ne!(real.optiga.expose_for_optiga(), duress.optiga.expose_for_optiga());
        assert_ne!(real.se050.expose_for_se050(), duress.se050.expose_for_se050());
        assert_ne!(
            *real.mask_optiga.apply(&[0; 32]),
            *duress.mask_optiga.apply(&[0; 32])
        );
    }

    #[test]
    fn negative_no_credential_contains_the_pin_or_its_old_hash() {
        use sha2::{Digest, Sha256};
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let o = a.optiga.expose_for_optiga();
        let e = a.se050.expose_for_se050();

        // The pre-fix SE050 credential was the PIN itself.
        assert!(!e.windows(PIN_LEN).any(|w| w == PIN));
        assert!(!o.windows(PIN_LEN).any(|w| w == PIN));

        // The pre-fix OPTIGA credential was this unkeyed hash.
        let mut h = Sha256::new();
        h.update(b"optiga-pin-auth-v1");
        h.update(PIN);
        h.update([0u8]);
        let old: [u8; 32] = h.finalize().into();
        assert_ne!(o, &old);
        assert_ne!(&e[..], &old[..16]);
    }

    #[test]
    fn positive_mask_is_its_own_inverse() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let half = [0x5Au8; HALF_LEN];
        let masked = a.mask_optiga.apply(&half);
        assert_ne!(*masked, half);
        assert_eq!(*a.mask_optiga.apply(&masked), half);
    }

    /// Both chips read out: the stored halves must not XOR to the seed.
    #[test]
    fn negative_xor_of_both_stored_halves_is_not_the_entropy() {
        let s = salt(0x11);
        let a = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let entropy = [0xC3u8; HALF_LEN];
        let half_o = [0x17u8; HALF_LEN];
        let mut half_e = [0u8; HALF_LEN];
        for i in 0..HALF_LEN {
            half_e[i] = entropy[i] ^ half_o[i];
        }
        let stored_o = a.mask_optiga.apply(&half_o);
        let stored_e = a.mask_se050.apply(&half_e);
        let mut joined = [0u8; HALF_LEN];
        for i in 0..HALF_LEN {
            joined[i] = stored_o[i] ^ stored_e[i];
        }
        assert_ne!(joined, entropy);

        // With the right PIN, salt and device key the join works.
        let back_o = a.mask_optiga.apply(&stored_o);
        let back_e = a.mask_se050.apply(&stored_e);
        for i in 0..HALF_LEN {
            assert_eq!(back_o[i] ^ back_e[i], entropy[i]);
        }
    }

    #[test]
    fn negative_wrong_pin_does_not_unmask_the_halves() {
        let s = salt(0x11);
        let right = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let wrong = set(DEVICE_KEY_A, WalletRole::Real, &s, &OTHER_PIN);
        let half = [0x17u8; HALF_LEN];
        let stored = right.mask_optiga.apply(&half);
        assert_ne!(*wrong.mask_optiga.apply(&stored), half);
    }

    #[test]
    fn negative_blank_or_destroyed_salt_is_refused() {
        assert!(PinSalt::new([0x00; SALT_LEN]).is_none());
        assert!(PinSalt::new([0xFF; SALT_LEN]).is_none());

        // One degenerate half is enough: it would read as a blank or a
        // destroyed flash quad-word.
        let mut first_half_blank = [0x42u8; SALT_LEN];
        first_half_blank[..16].fill(0xFF);
        assert!(PinSalt::new(first_half_blank).is_none());

        let mut second_half_zero = [0x42u8; SALT_LEN];
        second_half_zero[16..].fill(0x00);
        assert!(PinSalt::new(second_half_zero).is_none());

        assert!(PinSalt::new([0x42; SALT_LEN]).is_some());
    }

    #[test]
    fn negative_prf_error_is_propagated() {
        let s = salt(0x11);
        let r = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], _: &mut [u8]| Err(7u8));
        assert!(matches!(r, Err(DeriveError::Prf(7))));
    }

    /// A PRF call that was skipped leaves the output at zero.
    #[test]
    fn negative_untouched_output_is_refused() {
        let s = salt(0x11);
        let r = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], _: &mut [u8]| {
            Ok::<(), ()>(())
        });
        assert!(matches!(r, Err(DeriveError::DegenerateOutput)));
    }

    #[test]
    fn negative_all_ones_output_is_refused() {
        let s = salt(0x11);
        let r = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], out: &mut [u8]| {
            out.fill(0xFF);
            Ok::<(), ()>(())
        });
        assert!(matches!(r, Err(DeriveError::DegenerateOutput)));
    }

    /// One bad output among three good ones. The two tests above are also
    /// caught by the cross-output comparison (all four outputs are equal),
    /// so on their own they do not show the per-output check works: the
    /// mutation gate removed that check and they stayed green. Here the
    /// other three outputs are distinct and healthy, so only the per-output
    /// check can refuse.
    #[test]
    fn negative_one_degenerate_output_among_good_ones_is_refused() {
        let s = salt(0x11);
        for bad_call in 0..4u8 {
            for bad_fill in [0x00u8, 0xFF] {
                let mut call = 0u8;
                let r = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], out: &mut [u8]| {
                    if call == bad_call {
                        out.fill(bad_fill);
                    } else {
                        for (i, b) in out.iter_mut().enumerate() {
                            *b = 0x10u8.wrapping_mul(call + 1) ^ (i as u8) ^ 0x5A;
                        }
                    }
                    call += 1;
                    Ok::<(), ()>(())
                });
                assert!(
                    matches!(r, Err(DeriveError::DegenerateOutput)),
                    "output {bad_call} filled with {bad_fill:#04x} was accepted as a credential"
                );
            }
        }

        // Control: the same PRF with no bad call is accepted, so the refusal
        // above comes from the degenerate output and nothing else.
        let mut call = 0u8;
        let ok = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], out: &mut [u8]| {
            for (i, b) in out.iter_mut().enumerate() {
                *b = 0x10u8.wrapping_mul(call + 1) ^ (i as u8) ^ 0x5A;
            }
            call += 1;
            Ok::<(), ()>(())
        });
        assert!(ok.is_ok());
    }

    /// A PRF that ignores its input gives both chips the same value. That is
    /// the pre-fix defect in another form, and it is refused.
    #[test]
    fn negative_label_blind_prf_is_refused() {
        let s = salt(0x11);
        let r = derive_set(WalletRole::Real, &s, &PIN, |_: &[u8], out: &mut [u8]| {
            for (i, b) in out.iter_mut().enumerate() {
                *b = 0x40 ^ (i as u8);
            }
            Ok::<(), ()>(())
        });
        assert!(matches!(r, Err(DeriveError::DegenerateOutput)));
    }

    /// The PRF must be handed exactly `label || salt || PIN`, once per
    /// output, with the documented output lengths.
    #[test]
    fn positive_prf_input_layout_is_label_salt_pin() {
        let s = salt(0x11);
        let mut calls: std::vec::Vec<(std::vec::Vec<u8>, usize)> = std::vec::Vec::new();
        let mut n = 0u8;
        let _ = derive_set(WalletRole::Real, &s, &PIN, |info: &[u8], out: &mut [u8]| {
            calls.push((info.to_vec(), out.len()));
            n += 1;
            out.fill(n);
            out[0] ^= 0x80;
            Ok::<(), ()>(())
        })
        .expect("distinct outputs are accepted");

        let expect = [
            (&b"pqsigner/pin-cred-O-v1"[..], OPTIGA_CRED_LEN),
            (&b"pqsigner/pin-cred-E-v1"[..], SE050_CRED_LEN),
            (&b"pqsigner/pin-mask-O-v1"[..], HALF_LEN),
            (&b"pqsigner/pin-mask-E-v1"[..], HALF_LEN),
        ];
        assert_eq!(calls.len(), expect.len());
        for ((info, out_len), (label, want_len)) in calls.iter().zip(expect.iter()) {
            assert_eq!(info.len(), PRF_INPUT_LEN);
            assert_eq!(&info[..LABEL_LEN], *label);
            assert_eq!(&info[LABEL_LEN..LABEL_LEN + SALT_LEN], s.as_bytes());
            assert_eq!(&info[LABEL_LEN + SALT_LEN..], &PIN);
            assert_eq!(out_len, want_len);
        }
    }

    #[test]
    fn positive_duress_labels_are_used_for_the_duress_role() {
        let s = salt(0x11);
        let mut labels: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
        let mut n = 0u8;
        let _ = derive_set(WalletRole::Duress, &s, &PIN, |info: &[u8], out: &mut [u8]| {
            labels.push(info[..LABEL_LEN].to_vec());
            n += 1;
            out.fill(n);
            out[0] ^= 0x80;
            Ok::<(), ()>(())
        })
        .expect("distinct outputs are accepted");
        assert_eq!(
            labels,
            [
                b"pqsigner/dur-cred-O-v1".to_vec(),
                b"pqsigner/dur-cred-E-v1".to_vec(),
                b"pqsigner/dur-mask-O-v1".to_vec(),
                b"pqsigner/dur-mask-E-v1".to_vec(),
            ]
        );
    }

    #[test]
    fn negative_all_labels_are_distinct() {
        let all: [&[u8; LABEL_LEN]; 8] = [
            REAL.cred_optiga,
            REAL.cred_se050,
            REAL.mask_optiga,
            REAL.mask_se050,
            DURESS.cred_optiga,
            DURESS.cred_se050,
            DURESS.mask_optiga,
            DURESS.mask_se050,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "labels {i} and {j} collide");
            }
        }
    }

    #[test]
    fn positive_mint_policy_table() {
        assert!(mint_allowed(MintPolicy::RequireRdp2, true));
        assert!(!mint_allowed(MintPolicy::RequireRdp2, false));
        assert!(mint_allowed(MintPolicy::AnyLevel, true));
        assert!(mint_allowed(MintPolicy::AnyLevel, false));
    }

    // -------------------------------------------------------------------
    // Single-chip view: the complete set of PIN-dependent bytes each chip
    // is given, as built by the same `chip_images` the firmware calls.
    // -------------------------------------------------------------------

    impl OptigaImage {
        /// Every PIN-dependent byte string in the image. The destructuring
        /// has no `..`, so adding a field without listing it here is a
        /// compile error: the tests below cannot silently miss one.
        fn pin_dependent_fields(&self) -> [&[u8]; 2] {
            let OptigaImage { credential, stored_half } = self;
            [&credential.0[..], &stored_half[..]]
        }
    }

    impl Se050Image {
        fn pin_dependent_fields(&self) -> [&[u8]; 2] {
            let Se050Image { credential, stored_half } = self;
            [&credential.0[..], &stored_half[..]]
        }
    }

    const ENTROPY: [u8; HALF_LEN] = [0xC3; HALF_LEN];
    const HALF_O: [u8; HALF_LEN] = [0x17; HALF_LEN];

    fn half_e() -> [u8; HALF_LEN] {
        let mut h = [0u8; HALF_LEN];
        for i in 0..HALF_LEN {
            h[i] = ENTROPY[i] ^ HALF_O[i];
        }
        h
    }

    fn images(key: [u8; 32], s: &PinSalt, pin: &[u8; PIN_LEN]) -> (OptigaImage, Se050Image) {
        chip_images(set(key, WalletRole::Real, s, pin), &HALF_O, &half_e())
    }

    /// The property the whole fix is: a value a chip holds may depend on the
    /// PIN only together with the device key. If some field depended on the
    /// PIN but not on the key (the reported defect, in any form), it would
    /// be identical under two device keys.
    #[test]
    fn negative_every_pin_dependent_field_of_both_images_is_key_bound() {
        let s = salt(0x11);
        let (oa, ea) = images(DEVICE_KEY_A, &s, &PIN);
        let (ob, eb) = images(DEVICE_KEY_B, &s, &PIN);
        for (i, (a, b)) in oa.pin_dependent_fields().iter().zip(ob.pin_dependent_fields()).enumerate() {
            assert_ne!(*a, b, "OPTIGA field {i} does not depend on the device key");
        }
        for (i, (a, b)) in ea.pin_dependent_fields().iter().zip(eb.pin_dependent_fields()).enumerate() {
            assert_ne!(*a, b, "SE050 field {i} does not depend on the device key");
        }
    }

    /// Same for the salt: a value read out of a chip before a wipe (or a
    /// re-provisioning) is not what the chip is given afterwards.
    #[test]
    fn negative_every_pin_dependent_field_of_both_images_is_salt_bound() {
        let (oa, ea) = images(DEVICE_KEY_A, &salt(0x11), &PIN);
        let (ob, eb) = images(DEVICE_KEY_A, &salt(0x77), &PIN);
        for (a, b) in oa.pin_dependent_fields().iter().zip(ob.pin_dependent_fields()) {
            assert_ne!(*a, b);
        }
        for (a, b) in ea.pin_dependent_fields().iter().zip(eb.pin_dependent_fields()) {
            assert_ne!(*a, b);
        }
    }

    /// No 16-byte stretch of anything the SE050 holds appears in anything
    /// the OPTIGA holds, and the other way round.
    #[test]
    fn negative_the_two_images_share_no_sixteen_byte_window() {
        let (o, e) = images(DEVICE_KEY_A, &salt(0x11), &PIN);
        for of in o.pin_dependent_fields() {
            for ef in e.pin_dependent_fields() {
                for ow in of.windows(16) {
                    for ew in ef.windows(16) {
                        assert_ne!(ow, ew, "the two chips hold a common 16-byte value");
                    }
                }
            }
        }
    }

    /// Each chip gets its own credential and its own half, masked with its
    /// own mask. A swap would compile (the halves have the same type), so
    /// the assignment is checked against the set it was built from.
    #[test]
    fn positive_chip_images_assign_the_right_credential_and_masked_half() {
        let s = salt(0x11);
        let reference = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let (o, e) = images(DEVICE_KEY_A, &s, &PIN);

        assert_eq!(o.credential().expose_for_optiga(), reference.optiga.expose_for_optiga());
        assert_eq!(e.credential().expose_for_se050(), reference.se050.expose_for_se050());
        assert_eq!(*o.stored_half(), *reference.mask_optiga.apply(&HALF_O));
        assert_eq!(*e.stored_half(), *reference.mask_se050.apply(&half_e()));

        // Neither chip is given a bare half, nor the entropy.
        assert_ne!(*o.stored_half(), HALF_O);
        assert_ne!(*e.stored_half(), half_e());
        assert_ne!(*o.stored_half(), ENTROPY);
        assert_ne!(*e.stored_half(), ENTROPY);
    }

    /// Both chips read out: the stored halves do not XOR to the entropy.
    /// With the masks of the right PIN, salt and device key they do.
    #[test]
    fn negative_both_images_together_do_not_give_the_entropy() {
        let s = salt(0x11);
        let (o, e) = images(DEVICE_KEY_A, &s, &PIN);
        let mut joined = [0u8; HALF_LEN];
        for i in 0..HALF_LEN {
            joined[i] = o.stored_half()[i] ^ e.stored_half()[i];
        }
        assert_ne!(joined, ENTROPY);

        let right = set(DEVICE_KEY_A, WalletRole::Real, &s, &PIN);
        let back_o = right.mask_optiga.apply(o.stored_half());
        let back_e = right.mask_se050.apply(e.stored_half());
        for i in 0..HALF_LEN {
            assert_eq!(back_o[i] ^ back_e[i], ENTROPY[i]);
        }

        // A wrong PIN, a wrong salt or another device's key does not.
        for wrong in [
            set(DEVICE_KEY_A, WalletRole::Real, &s, &OTHER_PIN),
            set(DEVICE_KEY_A, WalletRole::Real, &salt(0x77), &PIN),
            set(DEVICE_KEY_B, WalletRole::Real, &s, &PIN),
            set(DEVICE_KEY_A, WalletRole::Duress, &s, &PIN),
        ] {
            let wo = wrong.mask_optiga.apply(o.stored_half());
            let we = wrong.mask_se050.apply(e.stored_half());
            let mut j = [0u8; HALF_LEN];
            for i in 0..HALF_LEN {
                j[i] = wo[i] ^ we[i];
            }
            assert_ne!(j, ENTROPY);
        }
    }

    /// What the pre-#855 firmware gave each chip, rebuilt here as a control.
    /// (OPTIGA: the unkeyed hash and the bare half. SE050: the raw PIN and
    /// the bare half.)
    fn pre_fix_views(pin: &[u8; PIN_LEN]) -> ([std::vec::Vec<u8>; 2], [std::vec::Vec<u8>; 2]) {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"optiga-pin-auth-v1");
        h.update(pin);
        h.update([0u8]);
        let authref: [u8; 32] = h.finalize().into();
        (
            [authref.to_vec(), HALF_O.to_vec()],
            [pin.to_vec(), half_e().to_vec()],
        )
    }

    /// The offline search the report describes, against one chip's fields:
    /// try every candidate PIN through the forms the firmware has used that
    /// need no key. A tripwire for those known forms; it is the key-binding
    /// tests above, not this list, that cover forms nobody has thought of.
    fn offline_search(fields: &[&[u8]]) -> Option<[u8; PIN_LEN]> {
        use sha2::{Digest, Sha256};
        (0..10_000).map(candidate).find(|p| {
            let mut h = Sha256::new();
            h.update(b"optiga-pin-auth-v1");
            h.update(p);
            h.update([0u8]);
            let hashed: [u8; 32] = h.finalize().into();
            fields
                .iter()
                .any(|f| f.windows(PIN_LEN).any(|w| w == p) || f.windows(32).any(|w| w == hashed))
        })
    }

    #[test]
    fn control_offline_search_recovers_the_pin_from_either_pre_fix_chip() {
        let secret_pin = candidate(7319);
        let (optiga, se050) = pre_fix_views(&secret_pin);
        let o: [&[u8]; 2] = [&optiga[0], &optiga[1]];
        let e: [&[u8]; 2] = [&se050[0], &se050[1]];
        assert_eq!(offline_search(&o), Some(secret_pin), "scenario B must work on the old layout");
        assert_eq!(offline_search(&e), Some(secret_pin), "scenario A must work on the old layout");
    }

    #[test]
    fn replay_offline_search_finds_nothing_in_either_image() {
        let secret_pin = candidate(7319);
        let (o, e) = images(DEVICE_KEY_A, &salt(0x11), &secret_pin);
        assert_eq!(offline_search(&o.pin_dependent_fields()), None);
        assert_eq!(offline_search(&e.pin_dependent_fields()), None);
    }

    // -------------------------------------------------------------------
    // Attack replay — the Ledger Donjon report, scenarios A and B, over a
    // PIN space small enough to search exhaustively in a unit test.
    // -------------------------------------------------------------------

    /// Four-digit search space padded to eight bytes: 10^4 candidates.
    fn candidate(n: u32) -> [u8; PIN_LEN] {
        let mut p = *b"0000    ";
        let d = [n / 1000 % 10, n / 100 % 10, n / 10 % 10, n % 10];
        for (i, digit) in d.iter().enumerate() {
            p[i] = b'0' + *digit as u8;
        }
        p
    }

    /// Positive control. The pre-fix OPTIGA credential is recovered by an
    /// offline search that uses nothing but the value read from the chip.
    /// If this stops finding the PIN the replay below proves nothing.
    #[test]
    fn control_pre_fix_optiga_hash_is_searchable_offline() {
        use sha2::{Digest, Sha256};
        let old = |pin: &[u8; PIN_LEN]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"optiga-pin-auth-v1");
            h.update(pin);
            h.update([0u8]);
            h.finalize().into()
        };
        let secret_pin = candidate(7319);
        let dumped = old(&secret_pin);
        let found = (0..10_000).map(candidate).find(|p| old(p) == dumped);
        assert_eq!(found, Some(secret_pin));
    }

    /// Scenario B. The attacker holds the OPTIGA credential and knows the
    /// salt and every label, but not the device key. Trying every PIN under
    /// a key of their own never reproduces the dumped value.
    #[test]
    fn replay_scenario_b_optiga_dump_is_not_searchable_without_the_device_key() {
        let s = salt(0x11);
        let secret_pin = candidate(7319);
        let dumped = set(DEVICE_KEY_A, WalletRole::Real, &s, &secret_pin);
        let dumped_o = *dumped.optiga.expose_for_optiga();

        let hit = (0..10_000).map(candidate).any(|p| {
            *set(DEVICE_KEY_B, WalletRole::Real, &s, &p).optiga.expose_for_optiga() == dumped_o
        });
        assert!(!hit, "a key the attacker chose reproduced the device's credential");

        // Sanity: under the device key the same search does find it, so the
        // loop above is searching the right space.
        let found = (0..10_000).map(candidate).find(|p| {
            *set(DEVICE_KEY_A, WalletRole::Real, &s, p).optiga.expose_for_optiga() == dumped_o
        });
        assert_eq!(found, Some(secret_pin));
    }

    /// Scenario A. The attacker holds everything the SE050 stores. None of
    /// it, nor any prefix of it, is the HMAC key the OPTIGA expects, and the
    /// PIN is not in it to derive that key from.
    #[test]
    fn replay_scenario_a_se050_dump_does_not_open_the_optiga() {
        let s = salt(0x11);
        let secret_pin = candidate(7319);
        let device = set(DEVICE_KEY_A, WalletRole::Real, &s, &secret_pin);
        let dumped_e = *device.se050.expose_for_se050();
        let optiga_key = *device.optiga.expose_for_optiga();

        // The dumped value is not the PIN (pre-fix it was).
        assert!((0..10_000).map(candidate).all(|p| dumped_e[..PIN_LEN] != p));

        // Padding the dumped value any way to 32 bytes is not the OPTIGA key.
        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(&dumped_e);
        assert_ne!(padded, optiga_key);
        padded[16..].copy_from_slice(&dumped_e);
        assert_ne!(padded, optiga_key);

        // Without the device key no PIN guess reproduces the dumped value,
        // so the attacker cannot confirm a PIN offline either.
        let hit = (0..10_000).map(candidate).any(|p| {
            *set(DEVICE_KEY_B, WalletRole::Real, &s, &p).se050.expose_for_se050() == dumped_e
        });
        assert!(!hit);
    }

    /// After a wipe the salt is gone. A credential read out before the wipe
    /// is no longer what the device computes for the same PIN, so the device
    /// cannot be used to test guesses against it.
    #[test]
    fn replay_credential_dumped_before_a_wipe_is_dead_after_it() {
        let secret_pin = candidate(7319);
        let before = set(DEVICE_KEY_A, WalletRole::Real, &salt(0x11), &secret_pin);
        let after = set(DEVICE_KEY_A, WalletRole::Real, &salt(0x77), &secret_pin);
        assert_ne!(before.optiga.expose_for_optiga(), after.optiga.expose_for_optiga());
        assert_ne!(before.se050.expose_for_se050(), after.se050.expose_for_se050());
    }
}
