//! Compiled-in vendor SPHINCS+C10 public key.
//!
//! The contents come from `OUT_DIR/vendor_pubkey_bytes.rs`, generated
//! by `build.rs` from either `FSBL_VENDOR_PUBKEY` (production) or the
//! built-in dev fixture (non-production). Changing this pubkey is
//! equivalent to provisioning a new vendor identity — the device will
//! no longer accept any previously-signed releases.

// Pre-computed fingerprint is an audit log: a human reading the
// generated source file can confirm which pubkey this FSBL will
// accept. The `_FPR` constant isn't referenced at runtime
// (`ManifestRef::verify_vendor_fpr` recomputes SHA-256 from the seed +
// root), but it's kept emitted so `size` + `objdump` on the FSBL
// binary shows the fingerprint directly.
#[allow(dead_code)]
mod bytes {
    include!(concat!(env!("OUT_DIR"), "/vendor_pubkey_bytes.rs"));
}

pub use bytes::{VENDOR_PK_ROOT, VENDOR_PK_SEED};
