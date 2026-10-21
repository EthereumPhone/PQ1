//! PQSigner firmware release-signing tool.
//!
//! **Production quarantine:** the current subcommands emit and verify legacy
//! manifest v0x02 / `PQFW_V1` artifacts. They remain useful for bench tests,
//! but are not Draft 1.1's proposed V6 interface and must not produce a
//! shipping release. The root `make release` gate fails until the candidate is
//! approved and its V6/backend/resource/release gates are implemented.
//!
//! This is the host-side companion to the on-device FSBL. It produces
//! signed `.pqfw` release bundles that the companion updater app streams
//! to the wallet over USB HID. The tool lives outside the firmware
//! because the vendor root signing key must never touch the device — it
//! lives in an offline, ideally air-gapped, signing machine.
//!
//! ## Subcommands
//!
//! * `keygen`  — generate a new vendor signing key (offline, one-time).
//! * `pubkey`  — export the vendor public key for FSBL embedding.
//! * `sign`    — sign a pair of secure + nonsecure ELFs into a `.pqfw`.
//! * `verify`  — independently verify a `.pqfw` against a pubkey.
//! * `erc7730-release-metadata` — authenticate and extract the P73S/P73K
//!   firmware half of an ERC-7730 compatibility identity.
//! * `inspect` — dump manifest fields from a `.pqfw` (for debugging).
//!
//! The same checks FSBL runs at boot are reachable through `verify`, so
//! CI can use `fwsign verify` as a proxy for "will FSBL accept this?".
//!
//! ## Determinism
//!
//! Every subcommand is fully deterministic given its inputs. `sign` in
//! particular does not hedge the SPHINCS+C10 signature — it calls
//! `sign(hash, None)` so the signature over a given (secure, nonsecure,
//! version, vendor_key, slot) tuple is byte-identical on every run.
//! This lets CI re-sign a release and confirm the bundle bytes match
//! a prior signing run bit-for-bit.

use clap::{Parser, Subcommand};

mod artifact_key;
mod bundle;
mod elf;
mod forced_eligible;
mod keystore;
mod subcommands;

/// PQSigner firmware release-signing tool.
#[derive(Parser, Debug)]
#[command(name = "fwsign", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh vendor signing key, encrypted at rest with a
    /// passphrase. **Run this once, offline, on an air-gapped machine.**
    /// Losing the output file (and the passphrase) means every future
    /// device update requires a device replacement — the FSBL pubkey is
    /// immutable after provisioning.
    Keygen {
        /// Output path for the encrypted key blob. Will refuse to
        /// overwrite an existing file.
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Extract the vendor public key from an encrypted vendor-key blob.
    /// Writes 32 bytes (`pk_seed[16] || pk_root[16]`) to `--out`, which
    /// is the file `FSBL_VENDOR_PUBKEY` points at during FSBL builds.
    Pubkey {
        /// Encrypted vendor-key blob.
        #[arg(long)]
        key: std::path::PathBuf,
        /// Output path for the 32-byte public key.
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Emit the built-in DEV vendor public key (32 bytes,
    /// `pk_seed[16] || pk_root[16]`) derived from the fixed dev seed —
    /// byte-identical to the key `fsbl/build.rs` falls back to when
    /// `FSBL_VENDOR_PUBKEY` is unset. Used by `make dev-pubkey-fixture` so
    /// the *secure* world (which has no `sphincs-c10` build-dep) embeds
    /// the same dev key the FSBL does, letting dev-signed manifests verify.
    /// **Never production.** No passphrase; the seed is in the source tree.
    DevPubkey {
        /// Output path for the 32-byte DEV public key.
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Emit a self-consistent dev-signed bundle (manifest + raw image
    /// bytes) for the over-USB FW-update transport e2e test
    /// (`make fwup-transport-hw`). Generates deterministic raw images
    /// (`[0xAA; secure_len]` / `[0xBB; nonsecure_len]`), signs the
    /// manifest with the built-in DEV key, writes three files to
    /// `<out_dir>/`: manifest.bin, secure.bin, nonsecure.bin.
    /// **Never production.**
    GenTestFixture {
        /// Firmware version (encoded in the signed manifest).
        #[arg(long)]
        version: u32,
        /// Raw secure-image length in bytes (must be a multiple of 16).
        #[arg(long, default_value_t = 240)]
        secure_len: u32,
        /// Raw nonsecure-image length in bytes (must be a multiple of 16).
        #[arg(long, default_value_t = 240)]
        nonsecure_len: u32,
        /// Output directory for `manifest.bin`, `secure.bin`,
        /// `nonsecure.bin`.
        #[arg(long)]
        out_dir: std::path::PathBuf,
    },

    /// LEGACY BENCH ONLY: sign a manifest-v0x02 / PQFW_V1 bundle.
    ///
    /// This format does not bind the slot byte and does not implement the
    /// reviewed rollback backend. It has no production or release authority.
    Sign {
        /// Explicitly acknowledge the quarantined legacy V1 bench format.
        /// Never use a provisioned/production-intended key: every invocation
        /// consumes that physical C10 key's still-unfrozen global budget.
        #[arg(long)]
        legacy_bench_unsafe: bool,

        /// Size-check the images against the DEV-UNIT A/B slot capacities
        /// (`fw_manifest::devunit`, 640 KiB secure / 192 KiB non-secure)
        /// instead of the legacy bench slots. Dev units only; the layout is
        /// not production geometry.
        #[arg(long)]
        devunit_ab: bool,

        /// Encrypted vendor-key blob.
        #[arg(long)]
        key: std::path::PathBuf,

        /// FSBL ELF participating in this artifact set. Its allocated runtime
        /// vendor key must match the secure ELF, reviewed policy, and signing
        /// key. This does not make the legacy bench FSBL production-immutable.
        #[arg(long)]
        fsbl: std::path::PathBuf,

        /// Reviewed 64-hex SHA-256 fingerprint of the key used by these bench
        /// artifacts. This does not grant the legacy format production status.
        #[arg(long)]
        trusted_fingerprint: std::path::PathBuf,

        /// Legacy firmware version encoded in PQFW_V1. The implemented OTP
        /// rollback path is quarantined and must not be treated as a production
        /// security control. The `$XDG_DATA_HOME/fwsign/ledger` is RECORD-ONLY
        /// provenance: `sign` appends to it but does NOT read it back to refuse
        /// a non-increasing version (F11) — enforcing that here would break the
        /// documented reproducible re-sign workflow (re-signing an already-
        /// recorded version must reproduce identical bytes). Treat the ledger
        /// as an audit trail, not a monotonicity guard.
        #[arg(long)]
        version: u32,

        /// Secure-world ELF.
        #[arg(long)]
        secure: std::path::PathBuf,

        /// Non-secure-world ELF.
        #[arg(long)]
        nonsecure: std::path::PathBuf,

        /// Legacy target-slot metadata. PQFW_V1 does NOT sign this byte; this is
        /// one reason the command is bench-only.
        #[arg(long, value_parser = parse_slot)]
        slot: u8,

        /// Build identifier (typically the git commit SHA-256). Opaque
        /// to FSBL but logged + displayed in the companion app for
        /// audit traceability. Hex-encoded, 64 chars.
        #[arg(long)]
        build_id: String,

        /// Legacy V1 metadata override. It has no approved physical OTP
        /// semantics and must not be interpreted as rollback authority.
        #[arg(long)]
        boot_counter_snap: Option<u32>,

        /// Output `.pqfw` bundle path.
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Independently verify a `.pqfw` bundle against a vendor pubkey.
    /// Runs the exact same check chain FSBL runs at boot: structural
    /// → CRC → digest → vendor-fpr → signature → image-hashes.
    Verify {
        /// `.pqfw` bundle path.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Vendor public key (32 bytes, produced by `fwsign pubkey`).
        #[arg(long)]
        pubkey: std::path::PathBuf,
        /// Size-check against the dev-unit A/B slot capacities.
        #[arg(long)]
        devunit_ab: bool,
    },

    /// Authenticate and extract the firmware-release half of ERC-7730
    /// compatibility as compact JSON.
    ///
    /// This verifies the complete C10 manifest/image chain, requires the P73S
    /// and, for non-legacy images, P73K sidecars to equal their unique valid
    /// records in authenticated secure.bin, and enforces exact/minimum
    /// firmware-version policy. It does not inspect a companion P730 catalogue
    /// and therefore is not itself a compatibility verdict, ERC-8176
    /// attestation, anti-rollback proof, or production grant.
    Erc7730ReleaseMetadata {
        /// `.pqfw` bundle path.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Vendor public key (32 bytes, produced by `fwsign pubkey`).
        #[arg(long)]
        pubkey: std::path::PathBuf,
        /// Exact authenticated firmware version expected by this companion
        /// release. Version negotiation is deliberately forbidden.
        #[arg(long)]
        expected_version: u32,
        /// Lowest firmware version this companion release permits. This is a
        /// caller policy check, not proof of the device's OTP rollback floor.
        #[arg(long)]
        minimum_version: u32,
        /// Require the authenticated P73S receipt to carry
        /// `erc8176-verified` provenance. Refuses before writing sidecars.
        /// This remains a catalogue-provenance check, not production,
        /// rollback, installed-device, or shipment authority.
        #[arg(long)]
        require_erc8176_verified: bool,
        /// Optional path for the exact authenticated 256-byte P73S receipt.
        /// Written only after every authentication and version check passes.
        #[arg(long)]
        status_out: Option<std::path::PathBuf>,
        /// Optional path for the exact authenticated variable-length P73K
        /// refused-known set. Requesting it for a legacy image fails closed.
        #[arg(long)]
        forced_eligible_out: Option<std::path::PathBuf>,
    },

    /// Prove from final linked artifacts that FSBL and secure world use the
    /// same reviewed, non-development firmware-update key.
    VerifyArtifactKeys {
        /// FSBL ELF to verify. Passing this check does not make the legacy
        /// bench FSBL production-immutable.
        #[arg(long)]
        fsbl: std::path::PathBuf,
        /// Final secure-world ELF.
        #[arg(long)]
        secure: std::path::PathBuf,
        /// Reviewed 64-hex SHA-256 fingerprint file.
        #[arg(long)]
        trusted_fingerprint: std::path::PathBuf,
    },

    /// **Verify from source only.** Takes a version number and a pair
    /// of source-built ELFs (plus the signature + vendor pubkey), and
    /// confirms the vendor signed this exact build at this exact
    /// version. Does NOT require the `.pqfw` bundle or any manifest
    /// parsing — the signed preimage is reconstructable from just
    /// `(version, secure_elf, nonsecure_elf)`.
    ///
    /// This is the "I built it myself, prove the vendor blessed it"
    /// workflow. The signature here is post-quantum (SPHINCS+C10)
    /// end-to-end; no classical crypto anywhere in the verification
    /// path.
    VerifyRelease {
        /// Firmware version (matches what the vendor published in the
        /// release notes / `release.json`).
        #[arg(long)]
        version: u32,
        /// Secure-world ELF you built from source.
        #[arg(long)]
        secure: std::path::PathBuf,
        /// Non-secure-world ELF you built from source.
        #[arg(long)]
        nonsecure: std::path::PathBuf,
        /// SPHINCS+C10 signature file (4008 bytes). Extract via
        /// `fwsign extract-sig --bundle release.pqfw --out release.sig`,
        /// or pull from whatever channel the vendor publishes.
        #[arg(long)]
        signature: std::path::PathBuf,
        /// Vendor public key (32 bytes).
        #[arg(long)]
        pubkey: std::path::PathBuf,
    },

    /// Extract the 4008-byte SPHINCS+C10 signature from a `.pqfw` so
    /// auditors can pass it to `verify-release` without shipping the
    /// whole bundle.
    ExtractSig {
        /// `.pqfw` bundle path.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Output path for the raw 4008-byte signature.
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Dump manifest fields from a `.pqfw` bundle. Read-only; makes no
    /// cryptographic claims — use `verify` for that.
    Inspect {
        /// `.pqfw` bundle path.
        #[arg(long)]
        bundle: std::path::PathBuf,
    },
}

fn parse_slot(s: &str) -> Result<u8, String> {
    match s.to_ascii_uppercase().as_str() {
        "A" | "0" => Ok(fw_manifest::SLOT_A),
        "B" | "1" => Ok(fw_manifest::SLOT_B),
        other => Err(format!("expected A or B, got {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_slot ----

    #[test]
    fn positive_parse_slot_letter_a_or_zero() {
        assert_eq!(parse_slot("A").unwrap(), fw_manifest::SLOT_A);
        assert_eq!(parse_slot("a").unwrap(), fw_manifest::SLOT_A);
        assert_eq!(parse_slot("0").unwrap(), fw_manifest::SLOT_A);
    }

    #[test]
    fn positive_parse_slot_letter_b_or_one() {
        assert_eq!(parse_slot("B").unwrap(), fw_manifest::SLOT_B);
        assert_eq!(parse_slot("b").unwrap(), fw_manifest::SLOT_B);
        assert_eq!(parse_slot("1").unwrap(), fw_manifest::SLOT_B);
    }

    #[test]
    fn positive_slot_a_and_b_are_distinct() {
        assert_ne!(fw_manifest::SLOT_A, fw_manifest::SLOT_B);
    }

    #[test]
    fn negative_parse_slot_rejects_garbage() {
        // Assumption attacked: silently coercing to A or B.  Signing for
        // the wrong slot would build a bundle the device rejects at
        // staging — annoying but not catastrophic; still, the wire
        // contract says exactly two slots and parse_slot must enforce.
        for bad in ["", "C", "2", "AA", "01", "-1", "256", "0x00", " A"] {
            assert!(parse_slot(bad).is_err(), "must reject {bad:?}");
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen { out } => subcommands::keygen::run(&out),
        Cmd::Pubkey { key, out } => subcommands::pubkey::run(&key, &out),
        Cmd::DevPubkey { out } => subcommands::dev_pubkey::run(&out),
        Cmd::GenTestFixture {
            version,
            secure_len,
            nonsecure_len,
            out_dir,
        } => subcommands::gen_test_fixture::run(version, secure_len, nonsecure_len, &out_dir),
        Cmd::Sign {
            legacy_bench_unsafe,
            devunit_ab,
            key,
            fsbl,
            trusted_fingerprint,
            version,
            secure,
            nonsecure,
            slot,
            build_id,
            boot_counter_snap,
            out,
        } => subcommands::sign::run(subcommands::sign::Args {
            legacy_bench_unsafe,
            devunit_ab,
            key_path: key,
            fsbl_elf: fsbl,
            trusted_fingerprint,
            version,
            secure_elf: secure,
            nonsecure_elf: nonsecure,
            slot,
            build_id_hex: build_id,
            boot_counter_snap,
            out_path: out,
        }),
        Cmd::Verify {
            bundle,
            pubkey,
            devunit_ab,
        } => subcommands::verify::run(&bundle, &pubkey, devunit_ab),
        Cmd::Erc7730ReleaseMetadata {
            bundle,
            pubkey,
            expected_version,
            minimum_version,
            require_erc8176_verified,
            status_out,
            forced_eligible_out,
        } => subcommands::erc7730_release_metadata::run(
            &bundle,
            &pubkey,
            expected_version,
            minimum_version,
            require_erc8176_verified,
            status_out.as_deref(),
            forced_eligible_out.as_deref(),
        ),
        Cmd::VerifyArtifactKeys {
            fsbl,
            secure,
            trusted_fingerprint,
        } => subcommands::verify_artifact_keys::run(&fsbl, &secure, &trusted_fingerprint),
        Cmd::VerifyRelease {
            version,
            secure,
            nonsecure,
            signature,
            pubkey,
        } => subcommands::verify_release::run(version, &secure, &nonsecure, &signature, &pubkey),
        Cmd::ExtractSig { bundle, out } => subcommands::extract_sig::run(&bundle, &out),
        Cmd::Inspect { bundle } => subcommands::inspect::run(&bundle),
    }
}
