use std::{env, fs, path::PathBuf};

use sphincs_c10::{SigningKey, params::N};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");

    // Pre-compute pk_root from the fixed sk_seed / pk_seed so the runtime
    // can use `SigningKey::from_parts` instead of `keygen` — saves ~2.5M
    // emulation instructions per fault iteration.
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
