fn main() {
    println!("cargo::rustc-check-cfg=cfg(keccak_asm)");
    // Only compile the assembly for ARM Thumb targets (Cortex-M3/M4/M33).
    // On other targets (x86 for tests, etc.) the crate falls back to the
    // pure-Rust `keccak` crate automatically.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.starts_with("thumbv7m")
        || target.starts_with("thumbv7em")
        || target.starts_with("thumbv8m")
    {
        cc::Build::new()
            .file("asm/keccakp1600.S")
            .flag("-march=armv7-m")
            .flag("-mthumb")
            .compile("keccakp1600");
        println!("cargo:rustc-cfg=keccak_asm");
    }
}
