//! PQSigner firmware-update manifest format.
//!
//! One 8 KB flash page per manifest. The FSBL reads two copies of this
//! structure (manifest A at `0x0C00_8000`, manifest B at `0x0C00_A000`)
//! at every boot, picks the highest-fw-version structurally-valid +
//! signature-valid one (honouring try-once semantics), and branches into
//! the matching slot image.
//!
//! ## What gets signed
//!
//! The vendor's SPHINCS+C10 signature covers exactly three inputs:
//!
//!   * A domain tag (`b"PQFW_V1"`) — stops cross-protocol signature
//!     reuse.
//!   * The 32-bit firmware version (rollback binding).
//!   * The two 32-byte image SHA-256 hashes.
//!
//! Specifically, the signed message is:
//!
//! ```text
//! digest = SHA-256( b"PQFW_V1"
//!                 || fw_version_be_u32
//!                 || secure_hash[32]
//!                 || nonsecure_hash[32] )
//! ```
//!
//! **Everything else in the manifest is unsigned metadata.** An auditor
//! who rebuilds the firmware from source can reconstruct those 75 bytes
//! from `(version, secure.elf, nonsecure.elf)` alone, compute the
//! SHA-256, and verify the vendor signature — no manifest parsing, no
//! `.pqfw` envelope. See `docs/firmware-update.md` for the
//! verify-it-yourself recipe.
//!
//! The manifest fields like `vendor_pubkey_fpr`, `build_id`, `slot`,
//! and `*_len` are retained as informational metadata and as fast
//! sanity checks the device can run before the expensive SPHINCS+C10
//! verify. They are **not** authority-bearing: an attacker who flips
//! them doesn't gain anything, because the signature covers only the
//! signed preimage and any tamper produces either a hash mismatch or
//! a signature failure.
//!
//! ## Post-sign, per-device fields
//!
//! `boot_counter_snap`, `try_once_flag`, and `crc32` are written by
//! the device *after* signing. They can't be part of the vendor
//! signature without making every state transition require the
//! vendor's offline key. They are integrity-protected only by the
//! trailing CRC-32; a torn flash write is caught by FSBL at boot and
//! falls back to the other slot.
//!
//! ## Wire layout
//!
//! ```text
//! offset  size  field                   signed?
//! ──────────────────────────────────────────────
//!     0     4   magic b"PQSF"             no
//!     4     1   manifest_version 0x02     no
//!     5     1   slot (informational)      no
//!     6     2   reserved                  no
//!     8     4   fw_version (u32 BE)       YES
//!    12     4   secure_len                no  (derivable from hash coverage)
//!    16     4   nonsecure_len             no
//!    20    32   secure_hash               YES
//!    52    32   nonsecure_hash            YES
//!    84    32   vendor_pubkey_fpr         no  (fast reject only)
//!   116    32   build_id                  no  (informational)
//!   148    32   manifest_digest         = SHA256(signed_preimage)
//!   180  4008   signature               SPHINCS+C10 over manifest_digest
//!  4188     4   boot_counter_snap       no
//!  4192     1   try_once_flag           no
//!  4193  3995   reserved, 0xFF          no
//!  8188     4   crc32 (IEEE)            no  (integrity only)
//! ```
//!
//! Total: 8192 bytes = one STM32U585 flash page. Every device
//! page-erases a manifest slot before writing a new manifest, so
//! partial writes always appear as 0xFF and get rejected by the magic
//! check.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use sha2::{Digest, Sha256};
pub use sphincs_c10::params::{SIGNATURE_LEN, VERIFYING_KEY_LEN};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Total manifest size in bytes — one STM32U585 flash page.
pub const MANIFEST_SIZE: usize = 8192;

/// Magic bytes at the start of every manifest.
pub const MAGIC: [u8; 4] = *b"PQSF";

/// Current on-wire manifest version.
///
/// v0x02 shrinks the signed preimage to just `DOMAIN_TAG || fw_version ||
/// secure_hash || nonsecure_hash` — 75 bytes total. Every other manifest
/// field (vendor_pubkey_fpr, build_id, slot, lengths) becomes *unsigned
/// metadata* the device can re-verify but that an independent auditor
/// does NOT need to reconstruct to check a release signature. The goal
/// is that a user who rebuilds the firmware from source can verify a
/// release using only the public key + version + the two image hashes,
/// without parsing the manifest or the `.pqfw` envelope.
pub const MANIFEST_VERSION: u8 = 0x02;

/// Domain-separation tag for the signed preimage. Prevents a vendor
/// SPHINCS+C10 signature over any other protocol from being replayed as
/// a firmware release signature (and vice versa).
pub const DOMAIN_TAG: &[u8; 7] = b"PQFW_V1";

/// Length of the unhashed signed preimage: tag + u32 version + two
/// 32-byte image hashes.
pub const SIGNED_PREIMAGE_LEN: usize = DOMAIN_TAG.len() + 4 + 32 + 32;

/// Slot tag — carried in the manifest but **not signed**. FSBL
/// identifies A/B by which flash page the manifest lives in, not by
/// this field. The companion can install the same signed release into
/// either slot.
pub const SLOT_A: u8 = 0x00;
pub const SLOT_B: u8 = 0x01;

/// `try_once_flag` states. Order matters: FSBL uses them to distinguish
/// "fresh from sign" (committed), "mid-commit reboot" (committing, torn),
/// and "FSBL armed it but slot hasn't confirmed alive yet" (tried).
pub const TRY_ONCE_COMMITTED: u8 = 0x00;
pub const TRY_ONCE_COMMITTING: u8 = 0x55;
pub const TRY_ONCE_TRIED: u8 = 0xAA;

// --- Offsets ---

pub const OFF_MAGIC: usize = 0;
pub const OFF_MANIFEST_VERSION: usize = 4;
pub const OFF_SLOT: usize = 5;
pub const OFF_RESERVED_1: usize = 6;
pub const OFF_FW_VERSION: usize = 8;
pub const OFF_SECURE_LEN: usize = 12;
pub const OFF_NONSECURE_LEN: usize = 16;
pub const OFF_SECURE_HASH: usize = 20;
pub const OFF_NONSECURE_HASH: usize = 52;
pub const OFF_VENDOR_FPR: usize = 84;
pub const OFF_BUILD_ID: usize = 116;
pub const OFF_MANIFEST_DIGEST: usize = 148;
pub const OFF_SIGNATURE: usize = 180;
pub const OFF_BOOT_CTR_SNAP: usize = 4188;
pub const OFF_TRY_ONCE: usize = 4192;
pub const OFF_RESERVED_2: usize = 4193;
pub const OFF_CRC32: usize = MANIFEST_SIZE - 4;

// Compile-time sanity. Breaking any of these is a wire-format regression.
const _: () = assert!(SIGNATURE_LEN == 4008);
const _: () = assert!(OFF_SIGNATURE + SIGNATURE_LEN == 4188);
const _: () = assert!(OFF_BOOT_CTR_SNAP + 4 == OFF_TRY_ONCE);
const _: () = assert!(OFF_CRC32 == 8188);
const _: () = assert!(SIGNED_PREIMAGE_LEN == 75);
const _: () = assert!(VERIFYING_KEY_LEN == 32);

// ---------------------------------------------------------------------------
// The signed preimage
// ---------------------------------------------------------------------------
//
// A release signature binds exactly three things:
//
//   1. A domain tag (prevents cross-protocol signature reuse).
//   2. The firmware version (gives per-signature rollback binding —
//      without this, an attacker holding an old signed hash could
//      replay it with a higher version claim).
//   3. The two image hashes (secure + nonsecure).
//
// Everything else in the manifest is UNSIGNED metadata the device can
// re-verify but an auditor does NOT need to inspect. Auditors verify
// a release like this:
//
//   1. `git checkout $commit && make release` → identical ELFs.
//   2. `fwmeasure` each ELF → two 32-byte hashes.
//   3. Concatenate `DOMAIN_TAG || version_be(4) || sh(32) || nh(32)`.
//   4. SHA-256 → 32-byte digest.
//   5. `sphincs_c10::verify(pk_seed, pk_root, digest, signature)`.
//
// No manifest parsing required.

/// Assemble the signed preimage into a fixed-size buffer. Callers pass
/// this to SHA-256 to obtain the 32-byte digest that SPHINCS+C10
/// actually signs/verifies.
pub fn signed_preimage(
    fw_version: u32,
    secure_hash: &[u8; 32],
    nonsecure_hash: &[u8; 32],
) -> [u8; SIGNED_PREIMAGE_LEN] {
    let mut out = [0u8; SIGNED_PREIMAGE_LEN];
    out[..DOMAIN_TAG.len()].copy_from_slice(DOMAIN_TAG);
    let ver_off = DOMAIN_TAG.len();
    out[ver_off..ver_off + 4].copy_from_slice(&fw_version.to_be_bytes());
    let sec_off = ver_off + 4;
    out[sec_off..sec_off + 32].copy_from_slice(secure_hash);
    let ns_off = sec_off + 32;
    out[ns_off..ns_off + 32].copy_from_slice(nonsecure_hash);
    out
}

/// SHA-256(signed_preimage(...)) — the 32-byte hash the vendor's
/// SPHINCS+C10 key actually signs. Separated out so callers that want
/// to feed it to `SigningKey::sign` / `sphincs_c10::verify` can do so
/// without re-doing the SHA-256.
pub fn compute_signed_digest(
    fw_version: u32,
    secure_hash: &[u8; 32],
    nonsecure_hash: &[u8; 32],
) -> [u8; 32] {
    let preimage = signed_preimage(fw_version, secure_hash, nonsecure_hash);
    Sha256::digest(&preimage).into()
}

// ---------------------------------------------------------------------------
// Error / verification status
// ---------------------------------------------------------------------------

/// Result of structural + cryptographic manifest checks. FSBL walks
/// through these in order and rejects as early as possible; the secure-
/// world COMMIT handler re-runs the same checks against a freshly-staged
/// image before flipping the active slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Magic bytes don't match `b"PQSF"` — almost certainly erased flash.
    BadMagic,
    /// `manifest_version` doesn't match what this FSBL understands.
    BadVersion,
    /// `slot` is not 0x00 or 0x01.
    BadSlot,
    /// Trailing CRC-32 doesn't match a freshly-computed one.
    BadCrc,
    /// `manifest_digest` doesn't match SHA-256 of bytes `[0..PREIMAGE_LEN)`.
    BadDigest,
    /// SPHINCS+C10 signature over `manifest_digest` failed to verify.
    BadSignature,
    /// `vendor_pubkey_fpr` doesn't match the FSBL-compiled vendor pubkey.
    WrongVendor,
    /// `fw_version <= rollback_floor` — the manifest is below the OTP
    /// anti-rollback floor and must be rejected.
    BelowRollback,
    /// The secure-image SHA-256 doesn't match `secure_hash`.
    SecureHashMismatch,
    /// The NS-image SHA-256 doesn't match `nonsecure_hash`.
    NonsecureHashMismatch,
}

// ---------------------------------------------------------------------------
// Read-only view
// ---------------------------------------------------------------------------

/// Zero-copy reader over a manifest page. Does NOT allocate and does not
/// validate anything on construction — call the `verify_*` methods
/// explicitly before trusting any field.
pub struct ManifestRef<'a> {
    bytes: &'a [u8; MANIFEST_SIZE],
}

impl<'a> ManifestRef<'a> {
    /// Wrap a `&[u8; 8192]` — cheap, no allocation, no validation.
    pub fn new(bytes: &'a [u8; MANIFEST_SIZE]) -> Self {
        Self { bytes }
    }

    /// Raw backing bytes — used by the secure-world COMMIT handler to
    /// stream the manifest page into flash verbatim.
    pub fn as_bytes(&self) -> &'a [u8; MANIFEST_SIZE] {
        self.bytes
    }

    pub fn magic(&self) -> [u8; 4] {
        let mut m = [0u8; 4];
        m.copy_from_slice(&self.bytes[OFF_MAGIC..OFF_MAGIC + 4]);
        m
    }

    pub fn manifest_version(&self) -> u8 {
        self.bytes[OFF_MANIFEST_VERSION]
    }

    pub fn slot(&self) -> u8 {
        self.bytes[OFF_SLOT]
    }

    pub fn fw_version(&self) -> u32 {
        read_u32_be(self.bytes, OFF_FW_VERSION)
    }

    pub fn secure_len(&self) -> u32 {
        read_u32_be(self.bytes, OFF_SECURE_LEN)
    }

    pub fn nonsecure_len(&self) -> u32 {
        read_u32_be(self.bytes, OFF_NONSECURE_LEN)
    }

    pub fn secure_hash(&self) -> &[u8; 32] {
        slice_as_array_32(&self.bytes[OFF_SECURE_HASH..OFF_SECURE_HASH + 32])
    }

    pub fn nonsecure_hash(&self) -> &[u8; 32] {
        slice_as_array_32(&self.bytes[OFF_NONSECURE_HASH..OFF_NONSECURE_HASH + 32])
    }

    pub fn vendor_pubkey_fpr(&self) -> &[u8; 32] {
        slice_as_array_32(&self.bytes[OFF_VENDOR_FPR..OFF_VENDOR_FPR + 32])
    }

    pub fn build_id(&self) -> &[u8; 32] {
        slice_as_array_32(&self.bytes[OFF_BUILD_ID..OFF_BUILD_ID + 32])
    }

    pub fn manifest_digest(&self) -> &[u8; 32] {
        slice_as_array_32(&self.bytes[OFF_MANIFEST_DIGEST..OFF_MANIFEST_DIGEST + 32])
    }

    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        slice_as_array_sig(&self.bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN])
    }

    pub fn boot_counter_snap(&self) -> u32 {
        read_u32_be(self.bytes, OFF_BOOT_CTR_SNAP)
    }

    pub fn try_once_flag(&self) -> u8 {
        self.bytes[OFF_TRY_ONCE]
    }

    pub fn crc32(&self) -> u32 {
        read_u32_be(self.bytes, OFF_CRC32)
    }

    // -------- verification steps --------

    /// Fast structural checks: magic, version, slot. Cheap — no hashing.
    pub fn verify_structural(&self) -> Result<(), VerifyError> {
        if self.magic() != MAGIC {
            return Err(VerifyError::BadMagic);
        }
        if self.manifest_version() != MANIFEST_VERSION {
            return Err(VerifyError::BadVersion);
        }
        let s = self.slot();
        if s != SLOT_A && s != SLOT_B {
            return Err(VerifyError::BadSlot);
        }
        Ok(())
    }

    /// Re-compute CRC over `[0..OFF_CRC32)` and compare.
    pub fn verify_crc(&self) -> Result<(), VerifyError> {
        let expected = self.crc32();
        let actual = crc32_ieee(&self.bytes[..OFF_CRC32]);
        if expected == actual {
            Ok(())
        } else {
            Err(VerifyError::BadCrc)
        }
    }

    /// Re-compute the signed digest from `fw_version`, `secure_hash`,
    /// and `nonsecure_hash`, and compare against the stored
    /// `manifest_digest`. This is the SHA-256 the vendor actually
    /// signs; recomputing it independently from source (rebuild → hash
    /// ELFs → hash preimage) is exactly what an auditor does.
    pub fn verify_digest(&self) -> Result<(), VerifyError> {
        let actual = compute_signed_digest(
            self.fw_version(),
            self.secure_hash(),
            self.nonsecure_hash(),
        );
        if &actual == self.manifest_digest() {
            Ok(())
        } else {
            Err(VerifyError::BadDigest)
        }
    }

    /// Verify the SPHINCS+C10 signature against the provided vendor
    /// public key. Call **after** `verify_digest()` has passed — this
    /// verifies the sig over the stored digest, which is only
    /// meaningful if the stored digest matches the actual preimage.
    pub fn verify_signature(
        &self,
        vendor_pk_seed: &[u8; sphincs_c10::params::N],
        vendor_pk_root: &[u8; sphincs_c10::params::N],
    ) -> Result<(), VerifyError> {
        if sphincs_c10::verify(
            vendor_pk_seed,
            vendor_pk_root,
            self.manifest_digest(),
            self.signature(),
        ) {
            Ok(())
        } else {
            Err(VerifyError::BadSignature)
        }
    }

    /// Check `vendor_pubkey_fpr == SHA256(pk_seed || pk_root)`. Cheap and
    /// rejects wrong-key signatures before the expensive C10 verify.
    pub fn verify_vendor_fpr(
        &self,
        vendor_pk_seed: &[u8; sphincs_c10::params::N],
        vendor_pk_root: &[u8; sphincs_c10::params::N],
    ) -> Result<(), VerifyError> {
        let mut h = Sha256::new();
        h.update(vendor_pk_seed);
        h.update(vendor_pk_root);
        let expected: [u8; 32] = h.finalize().into();
        if &expected == self.vendor_pubkey_fpr() {
            Ok(())
        } else {
            Err(VerifyError::WrongVendor)
        }
    }

    /// Check `fw_version > rollback_floor`. FSBL calls this with the
    /// floor it read from OTP.
    pub fn verify_rollback(&self, rollback_floor: u32) -> Result<(), VerifyError> {
        if self.fw_version() > rollback_floor {
            Ok(())
        } else {
            Err(VerifyError::BelowRollback)
        }
    }
}

// ---------------------------------------------------------------------------
// Builder (used by fwsign and by tests)
// ---------------------------------------------------------------------------

/// In-memory builder that writes directly into a fixed 8 KB buffer.
/// No heap. Intended for host tools and test harnesses; on-device code
/// never needs to build manifests (it only reads them).
pub struct ManifestBuilder {
    bytes: [u8; MANIFEST_SIZE],
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ManifestBuilder {
    /// Start with an "erased flash" pattern (all 0xFF) so reserved
    /// regions match what `bytes.len() - written_len` empty flash
    /// would look like if we only programmed the meaningful fields.
    pub fn new() -> Self {
        Self {
            bytes: [0xFF; MANIFEST_SIZE],
        }
    }

    /// Initialize the fixed prefix: magic + version + slot + zero reserved.
    pub fn init(&mut self, slot: u8) -> &mut Self {
        self.bytes[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        self.bytes[OFF_MANIFEST_VERSION] = MANIFEST_VERSION;
        self.bytes[OFF_SLOT] = slot;
        self.bytes[OFF_RESERVED_1..OFF_RESERVED_1 + 2].copy_from_slice(&[0x00, 0x00]);
        self
    }

    pub fn fw_version(&mut self, v: u32) -> &mut Self {
        write_u32_be(&mut self.bytes, OFF_FW_VERSION, v);
        self
    }

    pub fn secure_image(&mut self, hash: &[u8; 32], len: u32) -> &mut Self {
        write_u32_be(&mut self.bytes, OFF_SECURE_LEN, len);
        self.bytes[OFF_SECURE_HASH..OFF_SECURE_HASH + 32].copy_from_slice(hash);
        self
    }

    pub fn nonsecure_image(&mut self, hash: &[u8; 32], len: u32) -> &mut Self {
        write_u32_be(&mut self.bytes, OFF_NONSECURE_LEN, len);
        self.bytes[OFF_NONSECURE_HASH..OFF_NONSECURE_HASH + 32].copy_from_slice(hash);
        self
    }

    pub fn vendor_pubkey_fpr(&mut self, fpr: &[u8; 32]) -> &mut Self {
        self.bytes[OFF_VENDOR_FPR..OFF_VENDOR_FPR + 32].copy_from_slice(fpr);
        self
    }

    pub fn build_id(&mut self, id: &[u8; 32]) -> &mut Self {
        self.bytes[OFF_BUILD_ID..OFF_BUILD_ID + 32].copy_from_slice(id);
        self
    }

    pub fn boot_counter_snap(&mut self, c: u32) -> &mut Self {
        write_u32_be(&mut self.bytes, OFF_BOOT_CTR_SNAP, c);
        self
    }

    pub fn try_once(&mut self, flag: u8) -> &mut Self {
        self.bytes[OFF_TRY_ONCE] = flag;
        self
    }

    /// Compute and write `manifest_digest = compute_signed_digest(...)`.
    /// Returns the digest so the caller can pass it directly to
    /// `SigningKey::sign()`. **Must** be called after every mutation to
    /// `fw_version`, `secure_hash`, or `nonsecure_hash`, and before
    /// calling `set_signature`.
    pub fn finalize_preimage(&mut self) -> [u8; 32] {
        // Read the fields we're about to hash back out of the buffer.
        // ManifestRef is the canonical accessor — we build a short-lived
        // one to avoid duplicating the offset arithmetic.
        let digest = {
            let view = ManifestRef::new(&self.bytes);
            compute_signed_digest(
                view.fw_version(),
                view.secure_hash(),
                view.nonsecure_hash(),
            )
        };
        self.bytes[OFF_MANIFEST_DIGEST..OFF_MANIFEST_DIGEST + 32].copy_from_slice(&digest);
        digest
    }

    pub fn set_signature(&mut self, sig: &[u8; SIGNATURE_LEN]) -> &mut Self {
        self.bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(sig);
        self
    }

    /// Finalize: compute CRC-32 over `[0..OFF_CRC32)`, write it in, and
    /// return the completed manifest page bytes. Consumes the builder.
    pub fn finalize(mut self) -> [u8; MANIFEST_SIZE] {
        let crc = crc32_ieee(&self.bytes[..OFF_CRC32]);
        write_u32_be(&mut self.bytes, OFF_CRC32, crc);
        self.bytes
    }
}

// ---------------------------------------------------------------------------
// Helpers — vendor pubkey fingerprint
// ---------------------------------------------------------------------------

/// SHA-256(pk_seed || pk_root). Used as both the `vendor_pubkey_fpr` field
/// in the manifest and as the FSBL-compiled vendor identity.
pub fn vendor_pubkey_fingerprint(
    pk_seed: &[u8; sphincs_c10::params::N],
    pk_root: &[u8; sphincs_c10::params::N],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pk_seed);
    h.update(pk_root);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Big-endian helpers
// ---------------------------------------------------------------------------

fn read_u32_be(bytes: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn write_u32_be(bytes: &mut [u8], off: usize, v: u32) {
    let b = v.to_be_bytes();
    bytes[off..off + 4].copy_from_slice(&b);
}

fn slice_as_array_32(s: &[u8]) -> &[u8; 32] {
    debug_assert_eq!(s.len(), 32);
    // SAFETY: caller (internal only) passes a &[u8] of exactly 32 bytes
    // produced by slicing `[u8; MANIFEST_SIZE]` at fixed offsets.
    unsafe { &*(s.as_ptr() as *const [u8; 32]) }
}

fn slice_as_array_sig(s: &[u8]) -> &[u8; SIGNATURE_LEN] {
    debug_assert_eq!(s.len(), SIGNATURE_LEN);
    // SAFETY: same invariant as slice_as_array_32.
    unsafe { &*(s.as_ptr() as *const [u8; SIGNATURE_LEN]) }
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, poly 0xEDB88320)
// ---------------------------------------------------------------------------

/// Standard IEEE CRC-32 (the "zlib" / Ethernet CRC). Chosen over
/// Castagnoli (CRC-32C) because IEEE is what every tool — objdump, hex
/// editors, standard `crc32` utilities — default to, so auditors can
/// cross-check a manifest page with off-the-shelf tooling. The security
/// properties are identical for our purposes (we only need torn-write
/// detection; integrity against a motivated attacker is handled by the
/// SPHINCS+C10 signature).
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test against `python3 -c 'import zlib; print(hex(zlib.crc32(b"123456789")))'`
    /// which is the standard 0xCBF43926 fixture.
    #[test]
    fn crc32_kat() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn empty_crc32_is_zero() {
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    /// Round-trip: build a manifest with fixed inputs, serialize, parse,
    /// every field matches.
    #[test]
    fn builder_roundtrip() {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A)
            .fw_version(42)
            .secure_image(&[0x11; 32], 0xA000)
            .nonsecure_image(&[0x22; 32], 0xB000)
            .vendor_pubkey_fpr(&[0x33; 32])
            .build_id(&[0x44; 32])
            .boot_counter_snap(7)
            .try_once(TRY_ONCE_COMMITTED);
        let digest = b.finalize_preimage();
        b.set_signature(&[0x55; SIGNATURE_LEN]);
        let bytes = b.finalize();

        let m = ManifestRef::new(&bytes);
        assert_eq!(m.magic(), MAGIC);
        assert_eq!(m.manifest_version(), MANIFEST_VERSION);
        assert_eq!(m.slot(), SLOT_A);
        assert_eq!(m.fw_version(), 42);
        assert_eq!(m.secure_len(), 0xA000);
        assert_eq!(m.nonsecure_len(), 0xB000);
        assert_eq!(m.secure_hash(), &[0x11; 32]);
        assert_eq!(m.nonsecure_hash(), &[0x22; 32]);
        assert_eq!(m.vendor_pubkey_fpr(), &[0x33; 32]);
        assert_eq!(m.build_id(), &[0x44; 32]);
        assert_eq!(m.manifest_digest(), &digest);
        assert_eq!(m.signature(), &[0x55; SIGNATURE_LEN]);
        assert_eq!(m.boot_counter_snap(), 7);
        assert_eq!(m.try_once_flag(), TRY_ONCE_COMMITTED);

        // Structural + CRC + digest must all pass. Signature + vendor +
        // rollback are separate tests (need real keys).
        m.verify_structural().unwrap();
        m.verify_crc().unwrap();
        m.verify_digest().unwrap();
    }

    #[test]
    fn blank_flash_fails_magic() {
        let blank = [0xFF; MANIFEST_SIZE];
        let m = ManifestRef::new(&blank);
        assert!(matches!(
            m.verify_structural(),
            Err(VerifyError::BadMagic)
        ));
    }

    #[test]
    fn tamper_detects_crc() {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A).fw_version(1);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let mut bytes = b.finalize();

        // Flip one byte in the middle.
        bytes[1000] ^= 0x01;

        let m = ManifestRef::new(&bytes);
        assert!(matches!(m.verify_crc(), Err(VerifyError::BadCrc)));
    }

    #[test]
    fn tamper_detects_digest() {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A).fw_version(1);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let mut bytes = b.finalize();

        // Flip inside the signed preimage, then fix the CRC.
        bytes[OFF_FW_VERSION] ^= 0xFF;
        let new_crc = crc32_ieee(&bytes[..OFF_CRC32]);
        write_u32_be(&mut bytes, OFF_CRC32, new_crc);

        let m = ManifestRef::new(&bytes);
        // CRC now valid again, but the preimage no longer matches
        // manifest_digest.
        m.verify_crc().unwrap();
        assert!(matches!(m.verify_digest(), Err(VerifyError::BadDigest)));
    }

    #[test]
    fn vendor_fingerprint() {
        let pk_seed = [0xAA; 16];
        let pk_root = [0xBB; 16];
        let fpr = vendor_pubkey_fingerprint(&pk_seed, &pk_root);
        // Deterministic: same input always produces same fingerprint.
        let fpr2 = vendor_pubkey_fingerprint(&pk_seed, &pk_root);
        assert_eq!(fpr, fpr2);
    }

    #[test]
    fn signed_preimage_layout() {
        // The preimage an independent auditor reconstructs from
        // `(version, secure_elf, nonsecure_elf)` is exactly this:
        let pre = signed_preimage(7, &[0x11; 32], &[0x22; 32]);
        assert_eq!(&pre[..7], DOMAIN_TAG);
        assert_eq!(&pre[7..11], &7u32.to_be_bytes());
        assert_eq!(&pre[11..43], &[0x11; 32]);
        assert_eq!(&pre[43..75], &[0x22; 32]);
    }

    #[test]
    fn digest_is_sha256_of_preimage() {
        // The digest the vendor signs is SHA-256 of the 75-byte preimage.
        // Auditors reproducing a release verify exactly this.
        let version = 42u32;
        let sh = [0xABu8; 32];
        let nh = [0xCDu8; 32];
        let expected: [u8; 32] = Sha256::digest(&signed_preimage(version, &sh, &nh)).into();
        assert_eq!(compute_signed_digest(version, &sh, &nh), expected);
    }

    #[test]
    fn digest_binds_version() {
        // Same image hashes, different version → different digest.
        // This is what prevents replay of an old signature with a
        // higher version claim.
        let sh = [0xAB; 32];
        let nh = [0xCD; 32];
        let d1 = compute_signed_digest(1, &sh, &nh);
        let d2 = compute_signed_digest(2, &sh, &nh);
        assert_ne!(d1, d2);
    }

    // -----------------------------------------------------------------
    // Property-based fuzz harness
    //
    // The manifest is the first thing a malicious USB host can drop
    // on the firmware-update path (`CMD_FW_BEGIN` accumulates 8 KB,
    // hands them straight to the secure world, which calls into the
    // verifiers below). A panic on hostile input here is a direct
    // path from "anyone with a USB cable" to a secure-world DoS, so
    // every verifier must terminate in bounded time without panicking
    // for arbitrary bytes.
    //
    // We do NOT exercise `verify_signature` because SPHINCS+C10 verify
    // is expensive — proptest would never converge. The structural,
    // CRC, digest, vendor-fpr, and rollback paths are all fast and
    // collectively cover every line a manifest reaches before the
    // signature step.
    // -----------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// `ManifestRef::new` never panics regardless of the underlying
        /// 8 KB blob.
        #[test]
        fn manifest_ref_construction_never_panics(
            blob in proptest::collection::vec(any::<u8>(), MANIFEST_SIZE..=MANIFEST_SIZE)
        ) {
            let mut bytes = [0u8; MANIFEST_SIZE];
            bytes.copy_from_slice(&blob);
            let _ = ManifestRef::new(&bytes);
        }

        /// Every accessor + verifier on `ManifestRef` must terminate
        /// without panic for arbitrary 8 KB blobs. This includes the
        /// CRC and digest re-computations — both walk the blob bytes
        /// linearly so any unchecked arithmetic would surface here.
        #[test]
        fn verifier_chain_never_panics(
            blob in proptest::collection::vec(any::<u8>(), MANIFEST_SIZE..=MANIFEST_SIZE)
        ) {
            let mut bytes = [0u8; MANIFEST_SIZE];
            bytes.copy_from_slice(&blob);
            let m = ManifestRef::new(&bytes);

            let _ = m.magic();
            let _ = m.manifest_version();
            let _ = m.slot();
            let _ = m.fw_version();
            let _ = m.secure_len();
            let _ = m.nonsecure_len();
            let _ = m.secure_hash();
            let _ = m.nonsecure_hash();
            let _ = m.vendor_pubkey_fpr();
            let _ = m.build_id();
            let _ = m.manifest_digest();
            let _ = m.signature();
            let _ = m.boot_counter_snap();
            let _ = m.try_once_flag();
            let _ = m.crc32();

            let _ = m.verify_structural();
            let _ = m.verify_crc();
            let _ = m.verify_digest();
            let _ = m.verify_rollback(0);
            let _ = m.verify_rollback(u32::MAX);

            // verify_vendor_fpr does its own SHA-256 over the
            // caller-supplied (pk_seed, pk_root). Random bytes here
            // must never wedge that path.
            let pk_seed = [0u8; sphincs_c10::params::N];
            let pk_root = [0u8; sphincs_c10::params::N];
            let _ = m.verify_vendor_fpr(&pk_seed, &pk_root);
        }

        /// CRC-32 must accept arbitrary input lengths without panic
        /// — used by the manifest verifier with `&bytes[..OFF_CRC32]`,
        /// but we want to assert the more general property too.
        #[test]
        fn crc32_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..=MANIFEST_SIZE)
        ) {
            let _ = crc32_ieee(&data);
        }

        /// `compute_signed_digest` must terminate for arbitrary inputs.
        /// Trivially true (fixed 75-byte preimage), but the proptest
        /// asserts no surprise on the pure-function boundary.
        #[test]
        fn signed_digest_never_panics(
            version in any::<u32>(),
            secure_hash in any::<[u8; 32]>(),
            ns_hash in any::<[u8; 32]>(),
        ) {
            let _ = compute_signed_digest(version, &secure_hash, &ns_hash);
        }

        /// Single-bit flip anywhere in the signed region MUST flip
        /// the CRC — i.e., a malicious host that tampers with any
        /// field after vendor signing must trigger BadCrc on the
        /// device. Validates we don't accidentally CRC over too small
        /// a window.
        #[test]
        fn any_signed_field_flip_breaks_crc(
            mut byte_idx in 0usize..OFF_CRC32,
            bit in 0u8..8,
        ) {
            let mut b = ManifestBuilder::new();
            b.init(SLOT_A)
                .fw_version(1)
                .secure_image(&[0xAB; 32], 0x100)
                .nonsecure_image(&[0xCD; 32], 0x200);
            b.finalize_preimage();
            b.set_signature(&[0x55; SIGNATURE_LEN]);
            let mut bytes = b.finalize();

            // Pin byte_idx out of the trailing reserved region. The
            // reserved range is intentionally 0xFF, and flipping a bit
            // there changes the CRC just like anywhere else, but the
            // test reads more deterministically when we focus on the
            // structural region.
            if byte_idx >= OFF_RESERVED_2 {
                byte_idx %= OFF_RESERVED_2;
            }

            let m_before = ManifestRef::new(&bytes);
            prop_assert!(m_before.verify_crc().is_ok());

            bytes[byte_idx] ^= 1 << bit;

            let m_after = ManifestRef::new(&bytes);
            prop_assert!(m_after.verify_crc().is_err());
        }

        /// A blob whose first 4 bytes are not "PQSF" MUST be rejected
        /// by `verify_structural` no matter what the rest looks like.
        #[test]
        fn bad_magic_always_rejected(
            magic in any::<[u8; 4]>(),
            tail in proptest::collection::vec(any::<u8>(), MANIFEST_SIZE - 4..=MANIFEST_SIZE - 4),
        ) {
            prop_assume!(magic != MAGIC);
            let mut bytes = [0u8; MANIFEST_SIZE];
            bytes[..4].copy_from_slice(&magic);
            bytes[4..].copy_from_slice(&tail);
            let m = ManifestRef::new(&bytes);
            prop_assert_eq!(m.verify_structural(), Err(VerifyError::BadMagic));
        }
    }

    #[test]
    fn manifest_slot_change_does_not_invalidate_digest() {
        // Slot is UNSIGNED metadata. Flipping it produces a CRC
        // mismatch (if you forget to recompute), but the signed
        // digest is unchanged — which is exactly what lets one
        // `.pqfw` bundle install into either A or B.
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A)
            .fw_version(1)
            .secure_image(&[1; 32], 0x100)
            .nonsecure_image(&[2; 32], 0x200);
        let digest_a = b.finalize_preimage();

        let mut b2 = ManifestBuilder::new();
        b2.init(SLOT_B)
            .fw_version(1)
            .secure_image(&[1; 32], 0x100)
            .nonsecure_image(&[2; 32], 0x200);
        let digest_b = b2.finalize_preimage();

        assert_eq!(digest_a, digest_b);
    }
}
