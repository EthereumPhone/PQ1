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

    // ERC-7730 e2e trailer for Phase 3 smoke-test. Pre-computed at
    // build time from the e2e catalog blob (matching the firmware-
    // pinned `ERC7730_DESCRIPTORS_ROOT` under `feature = "e2e-test"`).
    // include_bytes!('d via `env!("OUT_DIR") + "/erc7730_e2e_weth_sepolia.bin"` in
    // `e2e_test.rs`.
    if env::var_os("CARGO_FEATURE_E2E_TEST").is_some() {
        let db = "../tools/companion-stub/erc7730_db_e2e.bin";
        println!("cargo:rerun-if-changed={db}");
        let blob = std::fs::read(db).unwrap_or_else(|e| {
            panic!("ERC-7730 e2e catalog {db} not found: {e} — run `cargo run -p dbgen`")
        });
        // WETH on Sepolia. The seed corpus is sorted by (chain_id,
        // contract); chain 11155111 + 0xfff9...c0d is leaf 3.
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        let trailer = build_erc7730_trailer(&blob, 11_155_111u64, &weth_sepolia)
            .expect("build erc7730 e2e trailer");
        std::fs::write(out_dir.join("erc7730_e2e_weth_sepolia.bin"), trailer)
            .expect("write erc7730 e2e trailer");
    }
}

/// Catalog blob → sign-input trailer payload. Mirrors
/// `tools/companion-stub/erc7730_trailer.py` byte-for-byte; the dbgen
/// test `companion_stub_trailer_verifies_against_on_device` validates
/// the Python output, which in turn validates this function's output
/// (the two implementations stay locked through that round-trip).
fn build_erc7730_trailer(
    blob: &[u8],
    chain_id: u64,
    contract: &[u8; 20],
) -> Result<Vec<u8>, String> {
    const HEADER_LEN: usize = 32;
    const ENTRY_LEN: usize = 72;
    if blob.len() < HEADER_LEN {
        return Err("catalog too short".into());
    }
    if &blob[..4] != b"P730" {
        return Err("bad catalog magic".into());
    }
    let entry_cnt = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let ir_pool_off = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
    let proof_depth = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;

    for i in 0..entry_cnt {
        let base = HEADER_LEN + i * ENTRY_LEN;
        let e_chain = u64::from_le_bytes(blob[base..base + 8].try_into().unwrap());
        let e_contract = &blob[base + 8..base + 28];
        if e_chain != chain_id || e_contract != contract {
            continue;
        }
        let ir_off = u32::from_le_bytes(blob[base + 64..base + 68].try_into().unwrap()) as usize;
        let ir_len = u32::from_le_bytes(blob[base + 68..base + 72].try_into().unwrap()) as usize;
        let ir = &blob[ir_pool_off + ir_off..ir_pool_off + ir_off + ir_len];
        let proof_base = proofs_off + i * proof_depth * 32;
        let proof = &blob[proof_base..proof_base + proof_depth * 32];

        let mut out = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len());
        out.extend_from_slice(&(ir.len() as u16).to_be_bytes());
        out.extend_from_slice(ir);
        out.extend_from_slice(&(i as u32).to_be_bytes());
        out.extend_from_slice(&(proof_depth as u32).to_be_bytes());
        out.extend_from_slice(proof);
        return Ok(out);
    }
    Err(format!(
        "no entry for chain={chain_id} contract=0x{}",
        contract.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
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
