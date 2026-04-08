use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stm32u585 = env::var_os("CARGO_FEATURE_STM32U585").is_some();
    let mem_x = if stm32u585 { "memory-stm32u585.x" } else { "memory.x" };
    std::fs::copy(mem_x, out_dir.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-stm32u585.x");

    // Stale-blob protection. The ERC20 + VK databases are generated
    // by `cargo run -p dbgen` and checked in. The classic failure
    // mode is "edited the JSON, forgot to regenerate" — catch it at
    // build time by sniffing the magic bytes.
    check_db_magic("src/erc20_db.bin", b"ERC2");
    check_db_magic("src/vk_db.bin", b"VKDB");
}

fn check_db_magic(path: &str, expected: &[u8; 4]) {
    println!("cargo:rerun-if-changed={path}");
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("dbgen blob {path} not found: {e} — run `cargo run -p dbgen`"));
    if bytes.len() < 4 {
        panic!("dbgen blob {path} truncated ({} bytes)", bytes.len());
    }
    if &bytes[..4] != expected {
        panic!(
            "dbgen blob {path} bad magic: expected {:?}, got {:?} — run `cargo run -p dbgen`",
            expected,
            &bytes[..4]
        );
    }
}
