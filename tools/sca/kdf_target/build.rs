//! Places `memory.x` where cortex-m-rt's `link.x` can find it, and pre-computes
//! the SPHINCS+C10 pk_root from the fixed SK_SEED/PK_SEED so the runtime
//! `sca_c10_sign` mirror uses `SigningKey::from_parts` (cheap struct fill)
//! instead of `keygen`. Without this we'd burn the first ~2.5 B emulated
//! instructions on keygen before reaching the sign phase — the TVLA samples
//! would all be in keygen, which `sca_c10_keygen` already tests separately.
use std::{env, fs, path::PathBuf};

use sphincs_c10::{SigningKey, params::N};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=memory.x");

    // Pre-compute pk_root from the fixed sk_seed/pk_seed used by `sca_c10_sign`.
    let sk_seed = [0x42u8; 32];
    let pk_seed = [0x77u8; N];
    let sk = SigningKey::keygen(sk_seed, pk_seed);
    let pk_root: [u8; N] = *sk.pk_root();
    fs::write(out.join("pk_root.bin"), &pk_root).expect("write pk_root");

    if env::var("TARGET").unwrap_or_default().contains("thumb") {
        fs::copy("memory.x", out.join("memory.x")).expect("copying memory.x");
        println!("cargo:rustc-link-search={}", out.display());
    }
}
