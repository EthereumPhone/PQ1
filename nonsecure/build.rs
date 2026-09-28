use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stm32u585 = env::var_os("CARGO_FEATURE_STM32U585").is_some();
    let ui_px_atlas = env::var_os("CARGO_FEATURE_UI_PX_ATLAS").is_some();
    // `ui-px-atlas` swaps in the script that parks the pixel-UI asset
    // container at a fixed slot offset; every other build keeps the plain
    // layout so its image does not grow by the reserved window.
    let mem_x = match (stm32u585, ui_px_atlas) {
        (true, true) => "memory-stm32u585-px.x",
        (true, false) => "memory-stm32u585.x",
        (false, true) => panic!("ui-px-atlas is a hardware (stm32u585) feature; QEMU builds carry no atlas"),
        (false, false) => "memory.x",
    };
    std::fs::copy(mem_x, out_dir.join("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-stm32u585.x");
    println!("cargo:rerun-if-changed=memory-stm32u585-px.x");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UI_PX_ATLAS");
    if ui_px_atlas {
        check_ui_px_atlas();
    }

    // Stale-blob protection. The ERC20 / Names databases live on
    // the HOST (companion app) under `tools/companion-stub/` — they are
    // NOT in the firmware image. They're `include_bytes!`'d only by the
    // `e2e-test` QEMU companion stub (`nonsecure/src/{erc20,names}_db.rs`),
    // so the stale-blob magic check is gated to `e2e-test` and points at
    // the host-side copies. The classic failure mode is "edited the JSON,
    // forgot to regenerate" — catch it at build time by sniffing the
    // magic bytes. Production builds ship no blob, so there is nothing
    // to check.
    if env::var_os("CARGO_FEATURE_E2E_TEST").is_some() {
        // The e2e NS stub bakes the TINY erc20 fixture blob (the full
        // production erc20_db.bin is multi-MB and would overflow NS flash).
        check_db_magic("../tools/companion-stub/erc20_db_e2e.bin", b"ERC2");
        // e2e NS stub bakes the TINY names fixture (full names_db.bin can grow).
        check_db_magic("../tools/companion-stub/names_db_e2e.bin", b"NAMS");
    }

    // ERC-7730 E2E receipts. Build them from the exact checked-in E2E
    // catalogue that matches the firmware-pinned test root; do not duplicate
    // a leaf index, domain separator, or primary type hash in test code.
    if env::var_os("CARGO_FEATURE_E2E_TEST").is_some() {
        let db = "../tools/companion-stub/erc7730_db_e2e.bin";
        println!("cargo:rerun-if-changed={db}");
        let blob = std::fs::read(db).unwrap_or_else(|e| {
            panic!("ERC-7730 e2e catalog {db} not found: {e} — run `cargo run -p dbgen`")
        });
        let weth_mainnet: [u8; 20] = [
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ];
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        let delegation_sepolia: [u8; 20] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x77, 0x30,
        ];
        let flyingtulip_positions_mainnet: [u8; 20] = [
            0xbe, 0x40, 0x50, 0xa7, 0x3a, 0x7f, 0xb3, 0x84, 0xc6, 0x5e, 0x88, 0x5a, 0x15, 0xc3,
            0x34, 0x61, 0xa4, 0xb2, 0x00, 0x55,
        ];
        let nested_parent: [u8; 20] = [0x34; 20];
        let nested_child: [u8; 20] = [0x56; 20];
        let multi_tail: [u8; 20] = [0x78; 20];

        let weth_mainnet_entry = build_erc7730_entry(&blob, 1, &weth_mainnet)
            .expect("build mainnet WETH ERC-7730 E2E entry");
        assert_eq!(weth_mainnet_entry.context_kind, 0x01);
        std::fs::write(
            out_dir.join("erc7730_e2e_weth_mainnet.bin"),
            &weth_mainnet_entry.trailer,
        )
        .expect("write mainnet WETH ERC-7730 E2E trailer");

        let weth_sepolia_entry = build_erc7730_entry(&blob, 11_155_111, &weth_sepolia)
            .expect("build Sepolia WETH ERC-7730 E2E entry");
        assert_eq!(weth_sepolia_entry.context_kind, 0x01);
        std::fs::write(
            out_dir.join("erc7730_e2e_weth_sepolia.bin"),
            &weth_sepolia_entry.trailer,
        )
        .expect("write Sepolia WETH ERC-7730 E2E trailer");

        let delegation = build_erc7730_entry(&blob, 11_155_111, &delegation_sepolia)
            .expect("build typed Delegation ERC-7730 E2E entry");
        assert_eq!(delegation.context_kind, 0x02);
        assert_ne!(delegation.domain_separator, [0u8; 32]);
        assert_ne!(delegation.primary_type_hash, [0u8; 32]);
        let mut typed_fixture = Vec::with_capacity(64 + delegation.trailer.len());
        typed_fixture.extend_from_slice(&delegation.domain_separator);
        typed_fixture.extend_from_slice(&delegation.primary_type_hash);
        typed_fixture.extend_from_slice(&delegation.trailer);
        std::fs::write(
            out_dir.join("erc7730_e2e_delegation_sepolia.bin"),
            typed_fixture,
        )
        .expect("write typed Delegation ERC-7730 E2E fixture");

        let flyingtulip = build_erc7730_entry(&blob, 1, &flyingtulip_positions_mainnet)
            .expect("build mainnet FlyingTulip PositionsManager ERC-7730 E2E entry");
        assert_eq!(flyingtulip.context_kind, 0x01);
        std::fs::write(
            out_dir.join("erc7730_e2e_flyingtulip_positions_mainnet.bin"),
            &flyingtulip.trailer,
        )
        .expect("write mainnet FlyingTulip PositionsManager ERC-7730 E2E trailer");

        let nested = build_erc7730_proof_set(&blob, 31_337, &nested_parent, &nested_child)
            .expect("build synthetic nested-calldata ERC-7730 E2E proof set");
        std::fs::write(out_dir.join("erc7730_e2e_nested_calldata.bin"), nested)
            .expect("write synthetic nested-calldata ERC-7730 E2E proof set");

        let multi_tail = build_erc7730_entry(&blob, 31_337, &multi_tail)
            .expect("build synthetic multi-tail ERC-7730 E2E entry");
        assert_eq!(multi_tail.context_kind, 0x01);
        std::fs::write(
            out_dir.join("erc7730_e2e_multi_tail.bin"),
            &multi_tail.trailer,
        )
        .expect("write synthetic multi-tail ERC-7730 E2E trailer");
    }
}

struct Erc7730CatalogEntry {
    trailer: Vec<u8>,
    context_kind: u8,
    domain_separator: [u8; 32],
    primary_type_hash: [u8; 32],
}

/// Catalog blob → sign-input trailer payload used by the QEMU fixtures.
/// The separate dbgen test `companion_stub_trailer_verifies_against_on_device`
/// proves that the Python helper's output is accepted by the on-device
/// verifier; it does not byte-compare this build-script implementation against
/// Python. The QEMU scenarios exercise the receipts produced here.
fn build_erc7730_entry(
    blob: &[u8],
    chain_id: u64,
    contract: &[u8; 20],
) -> Result<Erc7730CatalogEntry, String> {
    const HEADER_LEN: usize = 32;
    const ENTRY_LEN: usize = 72;
    const IR_HEADER_LEN: usize = 134;
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

    let entries_end = HEADER_LEN
        .checked_add(
            entry_cnt
                .checked_mul(ENTRY_LEN)
                .ok_or("entry table overflow")?,
        )
        .ok_or("entry table overflow")?;
    if entries_end > blob.len() || ir_pool_off < entries_end || proofs_off < ir_pool_off {
        return Err("catalog offsets are inconsistent".into());
    }

    let mut matched = None;
    for i in 0..entry_cnt {
        let base = HEADER_LEN + i * ENTRY_LEN;
        let e_chain = u64::from_le_bytes(blob[base..base + 8].try_into().unwrap());
        let e_contract = &blob[base + 8..base + 28];
        if e_chain != chain_id || e_contract != contract {
            continue;
        }
        if matched.is_some() {
            return Err(format!(
                "ambiguous catalogue entries for chain={chain_id} contract=0x{}",
                contract
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
        }
        let ir_off = u32::from_le_bytes(blob[base + 64..base + 68].try_into().unwrap()) as usize;
        let ir_len = u32::from_le_bytes(blob[base + 68..base + 72].try_into().unwrap()) as usize;
        let ir_start = ir_pool_off
            .checked_add(ir_off)
            .ok_or("IR offset overflow")?;
        let ir_end = ir_start.checked_add(ir_len).ok_or("IR length overflow")?;
        if ir_len < IR_HEADER_LEN || ir_end > proofs_off || ir_end > blob.len() {
            return Err("catalogue IR is truncated or overlaps proofs".into());
        }
        let ir = &blob[ir_start..ir_end];
        if ir[2..10] != chain_id.to_be_bytes() || ir[10..30] != contract[..] {
            return Err("catalogue entry and IR binding disagree".into());
        }
        let proof_stride = proof_depth.checked_mul(32).ok_or("proof length overflow")?;
        let proof_base = proofs_off
            .checked_add(i.checked_mul(proof_stride).ok_or("proof offset overflow")?)
            .ok_or("proof offset overflow")?;
        let proof_end = proof_base
            .checked_add(proof_stride)
            .ok_or("proof length overflow")?;
        let proof = blob
            .get(proof_base..proof_end)
            .ok_or("catalogue proof is truncated")?;

        let mut out = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len());
        out.extend_from_slice(&(ir.len() as u16).to_be_bytes());
        out.extend_from_slice(ir);
        out.extend_from_slice(&(i as u32).to_be_bytes());
        out.extend_from_slice(&(proof_depth as u32).to_be_bytes());
        out.extend_from_slice(proof);
        let context_kind = blob[base + 60];
        if ir[1] != context_kind {
            return Err("catalogue entry and IR context kind disagree".into());
        }
        let mut domain_separator = [0u8; 32];
        domain_separator.copy_from_slice(&ir[62..94]);
        let mut primary_type_hash = [0u8; 32];
        primary_type_hash.copy_from_slice(&blob[base + 28..base + 60]);
        matched = Some(Erc7730CatalogEntry {
            trailer: out,
            context_kind,
            domain_separator,
            primary_type_hash,
        });
    }
    matched.ok_or_else(|| {
        format!(
            "no entry for chain={chain_id} contract=0x{}",
            contract
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    })
}

/// Build the exact two-bundle proof-set envelope from two independently
/// generated catalogue entries. The outer/child order is signing authority,
/// so callers name both roles explicitly rather than passing an unordered
/// collection.
fn build_erc7730_proof_set(
    blob: &[u8],
    chain_id: u64,
    outer_contract: &[u8; 20],
    child_contract: &[u8; 20],
) -> Result<Vec<u8>, String> {
    // Mirrored from `pqsigner-proto`; the QEMU scenario is itself an
    // end-to-end drift check because the secure parser consumes the canonical
    // constants and rejects this generated envelope if they diverge.
    const ERC7730_PROOF_SET_MAGIC: u16 = 0xe773;
    const ERC7730_PROOF_SET_VERSION: u8 = 1;
    const ERC7730_PROOF_SET_COUNT: usize = 2;

    if ERC7730_PROOF_SET_COUNT != 2 {
        return Err("nested E2E fixture requires exactly two proof-set bundles".into());
    }
    let outer = build_erc7730_entry(blob, chain_id, outer_contract)?;
    let child = build_erc7730_entry(blob, chain_id, child_contract)?;
    if outer.context_kind != 0x01 || child.context_kind != 0x01 {
        return Err("nested E2E proof set requires two contract descriptors".into());
    }

    let mut proof_set = Vec::with_capacity(8 + outer.trailer.len() + child.trailer.len());
    proof_set.extend_from_slice(&ERC7730_PROOF_SET_MAGIC.to_be_bytes());
    proof_set.push(ERC7730_PROOF_SET_VERSION);
    proof_set.push(ERC7730_PROOF_SET_COUNT as u8);
    for bundle in [&outer.trailer, &child.trailer] {
        let len = u16::try_from(bundle.len())
            .map_err(|_| "nested E2E legacy bundle exceeds u16 envelope")?;
        proof_set.extend_from_slice(&len.to_be_bytes());
        proof_set.extend_from_slice(bundle);
    }
    Ok(proof_set)
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


/// `assets/ui-px/atlas.pq1a` must be the container `tools/ui_px_assets.py`
/// baked (magic + the byte count recorded in the secure-side manifest); the
/// secure world's `build.rs` separately pins its sha256. A stale or partial
/// bake here would only make every pixel dialog refuse (hash mismatch), but
/// catch it at build time rather than on the glass.
fn check_ui_px_atlas() {
    let path = "assets/ui-px/atlas.pq1a";
    let manifest_path = "../secure/assets/ui-px/manifest.json";
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rerun-if-changed={manifest_path}");
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("UI_PX_ATLAS: {path} unreadable: {e} (run `make ui-px-assets`)"));
    assert!(bytes.starts_with(b"PQ1A"), "UI_PX_ATLAS: {path} has a wrong magic header");
    let manifest = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|e| panic!("UI_PX_ATLAS: {manifest_path} unreadable: {e}"));
    let key = "\"atlas.pq1a\"";
    let entry = manifest.find(key).expect("UI_PX_ATLAS: atlas.pq1a missing from the manifest");
    let tail = &manifest[entry..];
    let b = tail.find("\"bytes\":").expect("bytes field") + 8;
    let digits: String = tail[b..].chars().skip_while(|c| c.is_whitespace()).take_while(|c| c.is_ascii_digit()).collect();
    let want: usize = digits.parse().expect("bytes value");
    assert_eq!(bytes.len(), want, "UI_PX_ATLAS: {path} length differs from the manifest (stale bake?)");
}
