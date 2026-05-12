//! Vendor SPHINCS+C10 public key, baked into the secure image at build time.
//!
//! `secure/build.rs` reads `FSBL_VENDOR_PUBKEY` (a 32-byte file holding
//! `pk_seed[16] || pk_root[16]`) and emits this module's contents into
//! OUT_DIR. The FSBL crate runs the same logic — both binaries must
//! produce byte-identical constants so a manifest accepted at BEGIN by
//! the secure firmware is *also* accepted at boot by FSBL.
//!
//! Without this, the secure firmware would have to defer signature
//! verification to FSBL after reset, leaving the OTP rollback-floor
//! bump in `cmd_fw_commit` running on unverified bytes (C-1 in the
//! security review).
//!
//! Dev / e2e builds: when `FSBL_VENDOR_PUBKEY` is unset, build.rs
//! falls back to a fixed-seed development pubkey. This is the same
//! one `fsbl/build.rs` uses by default, so dev FSBLs and dev-signed
//! .pqfw bundles match end-to-end. The build emits a `cargo:warning`
//! so CI can fail closed on accidental production builds without
//! the env var set.

include!(concat!(env!("OUT_DIR"), "/vendor_pubkey_bytes.rs"));
