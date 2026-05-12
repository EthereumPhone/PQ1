//! Places `memory.x` where cortex-m-rt's `link.x` can find it (copy to OUT_DIR,
//! add OUT_DIR to the linker search path). ARM-only crate; if someone runs a
//! host `cargo check` against it anyway, just no-op.
use std::{env, fs, path::PathBuf};

fn main() {
    if !env::var("TARGET").unwrap_or_default().contains("thumb") {
        return; // host check — skip linker-script setup
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::copy("memory.x", out.join("memory.x")).expect("copying memory.x");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
