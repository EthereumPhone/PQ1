use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();

    // When building for the host (cargo test), skip all ARM-specific linker
    // script setup. The unit tests only exercise pure logic (aa, tx) and
    // don't need memory.x or cortex-m-rt's link.x.
    if !target.contains("thumbv") {
        return;
    }

    // Mutually-exclusive UI backend check
    let ui_semihosting = env::var_os("CARGO_FEATURE_UI_SEMIHOSTING").is_some();
    let ui_oled = env::var_os("CARGO_FEATURE_UI_OLED").is_some();
    if ui_semihosting && ui_oled {
        panic!("features `ui-semihosting` and `ui-oled` are mutually exclusive");
    }
    if !ui_semihosting && !ui_oled {
        panic!("must enable exactly one UI backend (`ui-semihosting` or `ui-oled`)");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stm32u585 = env::var_os("CARGO_FEATURE_STM32U585").is_some();

    // Copy the appropriate memory.x for QEMU or real STM32U585
    let mem_x = if stm32u585 { "memory-stm32u585.x" } else { "memory.x" };
    fs::copy(mem_x, out_dir.join("memory.x")).unwrap();
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-stm32u585.x");

    // Find cortex-m-rt's link.x. On QEMU we redirect .gnu.sgstubs to a
    // separate NSC region (QEMU 8.2.2 SG workaround). On real STM32U585
    // the veneers stay in FLASH and the SAU marks them NSC — no patching.
    let link_x = find_link_x(&out_dir);
    let modified = if stm32u585 {
        link_x // no patching needed on real hardware
    } else {
        link_x.replace(
            "} > FLASH\n  /* Place `__veneer_limit`",
            "} > NSC\n  /* Place `__veneer_limit`",
        )
    };
    fs::write(out_dir.join("link.x"), modified).unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=build.rs");
}

fn find_link_x(out_dir: &PathBuf) -> String {
    // cortex-m-rt puts link.x in a sibling build directory
    let target_dir = out_dir
        .ancestors()
        .find(|p| p.file_name().map(|f| f == "build").unwrap_or(false))
        .expect("Could not find build directory");

    for entry in fs::read_dir(target_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("cortex-m-rt-") {
            let link_path = entry.path().join("out").join("link.x");
            if link_path.exists() {
                return fs::read_to_string(&link_path).unwrap();
            }
        }
    }
    panic!("Could not find cortex-m-rt's link.x");
}
