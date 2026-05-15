//! PQSigner firmware release-signing tool.
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

mod bundle;
mod elf;
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

    /// Sign a pair of secure + nonsecure ELFs into a `.pqfw` release
    /// bundle.
    Sign {
        /// Encrypted vendor-key blob.
        #[arg(long)]
        key: std::path::PathBuf,

        /// Monotonic firmware version. Must be strictly greater than the
        /// last signed version (tracked in `$XDG_DATA_HOME/fwsign/ledger`)
        /// and also strictly greater than the current OTP rollback
        /// floor on every device that will receive this release.
        #[arg(long)]
        version: u32,

        /// Secure-world ELF.
        #[arg(long)]
        secure: std::path::PathBuf,

        /// Non-secure-world ELF.
        #[arg(long)]
        nonsecure: std::path::PathBuf,

        /// Target slot. One release bundle signs exactly one slot side;
        /// a device applying the update chooses its inactive slot at
        /// staging time and rejects bundles for the wrong slot.
        #[arg(long, value_parser = parse_slot)]
        slot: u8,

        /// Build identifier (typically the git commit SHA-256). Opaque
        /// to FSBL but logged + displayed in the companion app for
        /// audit traceability. Hex-encoded, 64 chars.
        #[arg(long)]
        build_id: String,

        /// Optional: override the OTP rollback floor the manifest
        /// claims. Default is `version - 1`. Only set this if you
        /// intend to compress the rollback floor.
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Keygen { out } => subcommands::keygen::run(&out),
        Cmd::Pubkey { key, out } => subcommands::pubkey::run(&key, &out),
        Cmd::Sign {
            key,
            version,
            secure,
            nonsecure,
            slot,
            build_id,
            boot_counter_snap,
            out,
        } => subcommands::sign::run(subcommands::sign::Args {
            key_path: key,
            version,
            secure_elf: secure,
            nonsecure_elf: nonsecure,
            slot,
            build_id_hex: build_id,
            boot_counter_snap,
            out_path: out,
        }),
        Cmd::Verify { bundle, pubkey } => subcommands::verify::run(&bundle, &pubkey),
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
