//! Build-time generator (CLI entry point). See `lib.rs` for the
//! reusable library API consumed by integration tests + xtask.
//!
//! Reads:
//!   secure/data/erc20.json
//!   secure/data/vks.json
//!   secure/data/vks/<file>.bin
//!   secure/data/names.json
//!   secure/data/selectors.json
//!   secure/data/selectors-e2e.json
//!   secure/data/erc7730/*.json
//!   secure/data/erc7730/policy.toml
//!
//! Writes (checked into the repo, like the existing
//! tools/export_zk_constants.js outputs):
//!   nonsecure/src/erc20_db.bin
//!   nonsecure/src/vk_db.bin
//!   nonsecure/src/names_db.bin
//!   tools/companion-stub/selectors_db.bin
//!   tools/companion-stub/selectors_db_e2e.bin
//!   tools/companion-stub/erc7730_db.bin
//!   tools/companion-stub/erc7730_db_e2e.bin
//!   secure/src/db_roots.rs
//!   secure/data/vks.review.txt
//!   secure/data/erc7730.review.txt
//!   circuits/generated/erc20_poseidon_tree.json
//!
//! Run manually after editing the JSON sources:
//!
//!   cargo run -p dbgen
//!
//! The runtime parsers live in:
//!   nonsecure/src/erc20_db.rs   (ERC20 metadata)
//!   nonsecure/src/vk_db.rs      (ZK clear-signing VKs)
//!   nonsecure/src/names_db.rs   (address-name lookup)
//!
//! Both crates physically share the on-disk format definition via
//! sphincs_tz_shared::db_format, so any field-layout change here is a
//! single edit in shared/src/db_format.rs.

use std::fs;
use std::path::PathBuf;

use dbgen::{erc20, erc7730, names, selectors, vks};

const REPO_ROOT_CARGO: &str = env!("CARGO_MANIFEST_DIR");

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is .../sphincs_rust/dbgen — go up one.
    PathBuf::from(REPO_ROOT_CARGO)
        .parent()
        .expect("CARGO_MANIFEST_DIR has no parent")
        .to_path_buf()
}

fn main() {
    let root = repo_root();
    println!("dbgen: workspace root = {}", root.display());

    // Source data lives under secure/data/ for historical reasons
    // (the curated JSON is the same regardless of which world hosts
    // the resulting blob).
    let erc20_json = root.join("secure/data/erc20.json");
    let vks_json = root.join("secure/data/vks.json");
    let vks_dir = root.join("secure/data/vks");
    let names_json = root.join("secure/data/names.json");
    let selectors_json = root.join("secure/data/selectors.json");
    let selectors_e2e_json = root.join("secure/data/selectors-e2e.json");
    let erc7730_dir = root.join("secure/data/erc7730");
    let erc7730_policy = erc7730_dir.join("policy.toml");
    let erc7730_e2e_dir = root.join("secure/data/erc7730-e2e");

    // The full DB blobs ship in the NON-SECURE firmware image as
    // rodata. The secure firmware only embeds the Merkle root via
    // the generated `db_roots.rs` file below.
    let erc20_out = root.join("nonsecure/src/erc20_db.bin");
    let vk_out = root.join("nonsecure/src/vk_db.bin");
    let names_out = root.join("nonsecure/src/names_db.bin");
    // The selectors DB blob is the odd one out: it lives on the host
    // (companion app) instead of in NS rodata, so it ships as a
    // separate artifact under tools/companion-stub/. Only the 32-byte
    // SELECTOR_DB_ROOT crosses into the firmware image.
    let selectors_out = root.join("tools/companion-stub/selectors_db.bin");
    // Tiny parallel fixture used by the QEMU e2e test driver.
    // Production builds DO NOT consume this artifact — it's the only
    // way to keep `make e2e` runnable without baking the full
    // host-side blob into NS rodata (which would overflow flash).
    let selectors_e2e_out = root.join("tools/companion-stub/selectors_db_e2e.bin");
    let erc7730_out = root.join("tools/companion-stub/erc7730_db.bin");
    let erc7730_e2e_out = root.join("tools/companion-stub/erc7730_db_e2e.bin");
    let erc7730_review_out = root.join("secure/data/erc7730.review.txt");
    let roots_out = root.join("secure/src/db_roots.rs");
    let review_out = root.join("secure/data/vks.review.txt");
    // The Poseidon-Merkle tree export is consumed by the off-device
    // witness generator that builds CowSwap EIP-712 v3 proofs. It's
    // committed into the repo so `make e2e-hw` remains deterministic
    // without requiring a live dbgen run.
    let poseidon_tree_out = root.join("circuits/generated/erc20_poseidon_tree.json");

    // ----- ERC20 metadata DB -----
    let erc20_res = erc20::build_db(&erc20_json).expect("erc20 db build failed");
    erc20::round_trip_check(&erc20_res.blob, &erc20_json, &erc20_res.root)
        .expect("erc20 round-trip failed");
    fs::write(&erc20_out, &erc20_res.blob).expect("write erc20_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        erc20_out.display(),
        erc20_res.blob.len(),
        hex::encode(erc20_res.root),
    );
    // ERC20 Poseidon-Merkle companion artifact.
    if let Some(parent) = poseidon_tree_out.parent() {
        fs::create_dir_all(parent).expect("create circuits/generated");
    }
    fs::write(&poseidon_tree_out, &erc20_res.poseidon_tree_json)
        .expect("write erc20_poseidon_tree.json");
    println!(
        "dbgen: wrote {} (poseidon root = {})",
        poseidon_tree_out.display(),
        hex::encode(erc20_res.poseidon_root),
    );

    // ----- VK DB -----
    let vk_res = vks::build_db(&vks_json, &vks_dir).expect("vk db build failed");
    vks::round_trip_check(&vk_res.blob, &vks_json, &vks_dir, &vk_res.root)
        .expect("vk round-trip failed");
    fs::write(&vk_out, &vk_res.blob).expect("write vk_db.bin");
    fs::write(&review_out, &vk_res.review_text).expect("write vks.review.txt");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        vk_out.display(),
        vk_res.blob.len(),
        hex::encode(vk_res.root),
    );
    println!("dbgen: wrote {}", review_out.display());

    // ----- Names DB -----
    let names_res = names::build_db(&names_json).expect("names db build failed");
    names::round_trip_check(&names_res.blob, &names_json, &names_res.root)
        .expect("names round-trip failed");
    fs::write(&names_out, &names_res.blob).expect("write names_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        names_out.display(),
        names_res.blob.len(),
        hex::encode(names_res.root),
    );

    // ----- Selectors DB (host-side blob) -----
    //
    // Unlike the three DBs above, this one's blob does NOT ship in NS
    // rodata. It's written under tools/companion-stub/ for the future
    // companion app (and for the e2e-test driver, which acts as a
    // dev-only companion stub). Only the 32-byte root crosses into
    // the firmware image via db_roots.rs below.
    let selectors_res = selectors::build_db(&selectors_json).expect("selectors db build failed");
    selectors::round_trip_check(&selectors_res.blob, &selectors_json, &selectors_res.root)
        .expect("selectors round-trip failed");
    if let Some(parent) = selectors_out.parent() {
        fs::create_dir_all(parent).expect("create tools/companion-stub");
    }
    fs::write(&selectors_out, &selectors_res.blob).expect("write selectors_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        selectors_out.display(),
        selectors_res.blob.len(),
        hex::encode(selectors_res.root),
    );

    // ----- Selectors DB (e2e fixture) -----
    //
    // Tiny parallel set used only when the secure crate is built with
    // `--features e2e-test`. The matching SELECTOR_DB_ROOT_E2E in
    // db_roots.rs is selected at compile time via the same feature
    // gate. This keeps `make e2e` runnable without overflowing NS
    // flash with the multi-hundred-KB production blob.
    let selectors_e2e_res =
        selectors::build_db(&selectors_e2e_json).expect("selectors e2e db build failed");
    selectors::round_trip_check(
        &selectors_e2e_res.blob,
        &selectors_e2e_json,
        &selectors_e2e_res.root,
    )
    .expect("selectors e2e round-trip failed");
    fs::write(&selectors_e2e_out, &selectors_e2e_res.blob)
        .expect("write selectors_db_e2e.bin");
    println!(
        "dbgen: wrote {} ({} bytes, e2e root = {})",
        selectors_e2e_out.display(),
        selectors_e2e_res.blob.len(),
        hex::encode(selectors_e2e_res.root),
    );

    // ----- ERC-7730 descriptor catalog (host-side blob) -----
    //
    // Same shape as the selectors DB: the blob lives on the host
    // (companion app) under tools/companion-stub/; only the 32-byte
    // Merkle root crosses into the firmware via db_roots.rs. The
    // companion looks up descriptors by `(chain_id, contract)` and
    // ships the matching IR + Merkle proof in the new sign-input
    // trailer slot (Phase 3 wires that path).
    let erc7730_res = erc7730::build_db(&erc7730_dir, &erc7730_policy)
        .expect("erc7730 db build failed");
    erc7730::round_trip_check(&erc7730_res).expect("erc7730 round-trip failed");
    if let Some(parent) = erc7730_out.parent() {
        fs::create_dir_all(parent).expect("create tools/companion-stub");
    }
    fs::write(&erc7730_out, &erc7730_res.blob).expect("write erc7730_db.bin");
    fs::write(&erc7730_review_out, &erc7730_res.review_text)
        .expect("write erc7730.review.txt");
    println!(
        "dbgen: wrote {} ({} bytes, {} leaves, root = {})",
        erc7730_out.display(),
        erc7730_res.blob.len(),
        erc7730_res.leaf_count,
        hex::encode(erc7730_res.root),
    );
    println!("dbgen: wrote {}", erc7730_review_out.display());

    // ----- ERC-7730 descriptor catalog (e2e fixture) -----
    //
    // Same role as the selectors e2e variant: a tiny parallel catalog
    // used when the secure crate is built with `--features e2e-test`,
    // so QEMU CI runs don't need to bake the full host-side blob into
    // any stub buffer. The matching ERC7730_DESCRIPTORS_ROOT_E2E in
    // db_roots.rs is selected at compile time via the same feature
    // gate.
    let erc7730_e2e_res = erc7730::build_db(&erc7730_e2e_dir, &erc7730_policy)
        .expect("erc7730 e2e db build failed");
    erc7730::round_trip_check(&erc7730_e2e_res)
        .expect("erc7730 e2e round-trip failed");
    fs::write(&erc7730_e2e_out, &erc7730_e2e_res.blob)
        .expect("write erc7730_db_e2e.bin");
    println!(
        "dbgen: wrote {} ({} bytes, {} leaves, e2e root = {})",
        erc7730_e2e_out.display(),
        erc7730_e2e_res.blob.len(),
        erc7730_e2e_res.leaf_count,
        hex::encode(erc7730_e2e_res.root),
    );

    // ----- secure/src/db_roots.rs -----
    //
    // This is the only file the secure-world build sees from the DBs.
    // Five 32-byte Merkle roots are baked into the secure image: the
    // SHA-256 ERC-20 + VK + Names roots (for the transfer display /
    // VK bundle verifier / address-name lookup paths), the Poseidon
    // ERC-20 root (used as the third public input for the CowSwap
    // EIP-712 v3 Groth16 proof), and the ERC-7730 descriptor root
    // (for the Phase-3 trailer parser).
    let roots_rs = render_db_roots(
        &erc20_res.root,
        &vk_res.root,
        &erc20_res.poseidon_root,
        &names_res.root,
        &selectors_res.root,
        &selectors_e2e_res.root,
        &erc7730_res.root,
        &erc7730_e2e_res.root,
    );
    fs::write(&roots_out, &roots_rs).expect("write db_roots.rs");
    println!("dbgen: wrote {}", roots_out.display());

    println!("dbgen: ok");
}

const DB_ROOTS_HEADER: &str = "\
//! Merkle roots of the embedded ERC20 + VK + Names + Selectors + ERC-7730 databases.
//!
//! Generated by `cargo run -p dbgen` from secure/data/erc20.json,
//! secure/data/vks.json, secure/data/names.json,
//! secure/data/selectors.json, and secure/data/erc7730/*.json.
//! DO NOT EDIT BY HAND.
//!
//! The ERC20 / VK / Names blobs live in non-secure rodata.
//! The Selectors + ERC-7730 blobs live on the host (companion app) at
//! `tools/companion-stub/selectors_db.bin` and
//! `tools/companion-stub/erc7730_db.bin` and never ship in
//! the firmware image. The secure world only holds these
//! roots; everything received from NS or the host is
//! verified against them via `crate::erc20::merkle::verify_proof`.
//!
//! `ERC20_POSEIDON_ROOT` is the parallel BLS12-381 Poseidon-Merkle
//! tree over the same sorted (chain_id, contract) entry set that
//! the CowSwap EIP-712 v3 Groth16 circuit consumes as its third
//! public input. It's stored as the 32-byte little-endian canonical
//! encoding of the root scalar, ready to be fed into
//! `bls12_381::Scalar::from_bytes`.
//!
//! `NAMES_DB_ROOT` anchors the address-name DB. Every trusted-UI
//! address render consults this root before a human-readable
//! name is allowed to replace the raw 40-hex address.
//!
//! `SELECTOR_DB_ROOT` anchors the function-selector → text-signature
//! DB. The blob is held by the (untrusted) companion app; bundles
//! crossing the gateway are Merkle-verified against this root and
//! cross-checked against `calldata[0..4]` before any text-sig
//! reaches the trusted UI. Production builds (no `e2e-test`
//! feature) use the full curated set; `e2e-test` builds swap in
//! the smaller `selectors-e2e.json` fixture root so the QEMU NS
//! test driver can bake a tiny companion-stub blob without
//! overflowing flash.
//!
//! `ERC7730_DESCRIPTORS_ROOT` anchors the ERC-7730 clear-signing
//! descriptor catalogue. Same trust model as the Selectors DB —
//! the blob lives host-side under `tools/companion-stub/`, and
//! every bundle crossing the gateway is Merkle-verified against
//! this root by `pqsigner_erc7730::bundle::verify_erc7730_bundle`.
//! The catalog filters through the ERC-8176 policy at
//! `secure/data/erc7730/policy.toml` so attestations are
//! enforced at host build time (preserving invariant #5 — no
//! classical signer on-device).

";

fn render_db_roots(
    erc20_root: &[u8; 32],
    vk_root: &[u8; 32],
    erc20_poseidon_root: &[u8; 32],
    names_root: &[u8; 32],
    selectors_root: &[u8; 32],
    selectors_e2e_root: &[u8; 32],
    erc7730_root: &[u8; 32],
    erc7730_e2e_root: &[u8; 32],
) -> String {
    use std::fmt::Write;

    let mut s = String::with_capacity(DB_ROOTS_HEADER.len() + 8 * 256);
    s.push_str(DB_ROOTS_HEADER);
    emit_root(&mut s, "ERC20_DB_ROOT", erc20_root);
    emit_root(&mut s, "VK_DB_ROOT", vk_root);
    emit_root(&mut s, "ERC20_POSEIDON_ROOT", erc20_poseidon_root);
    emit_root(&mut s, "NAMES_DB_ROOT", names_root);
    writeln!(s, "#[cfg(not(feature = \"e2e-test\"))]").unwrap();
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_root);
    writeln!(s, "#[cfg(feature = \"e2e-test\")]").unwrap();
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_e2e_root);
    s.push_str("#[cfg(not(feature = \"e2e-test\"))]\n");
    emit_root(&mut s, "ERC7730_DESCRIPTORS_ROOT", erc7730_root);
    s.push_str("#[cfg(feature = \"e2e-test\")]\n");
    emit_root(&mut s, "ERC7730_DESCRIPTORS_ROOT", erc7730_e2e_root);
    s
}

fn emit_root(s: &mut String, name: &str, bytes: &[u8; 32]) {
    use std::fmt::Write;
    write!(s, "pub static {name}: [u8; 32] = [").unwrap();
    for (i, b) in bytes.iter().enumerate() {
        if i % 8 == 0 {
            s.push_str("\n    ");
        }
        write!(s, "0x{b:02x}, ").unwrap();
    }
    s.push_str("\n];\n\n");
}
