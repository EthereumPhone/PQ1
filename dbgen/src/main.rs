//! Build-time generator (CLI entry point). See `lib.rs` for the
//! reusable library API consumed by integration tests + xtask.
//!
//! Reads:
//!   secure/data/erc20.json
//!   secure/data/names.json
//!   secure/data/selectors.json
//!   secure/data/selectors-e2e.json
//!   secure/data/erc7730-registry/registry/**/*.json
//!   secure/data/erc7730-registry/ercs/**/*.json
//!   secure/data/erc7730-e2e/*.json
//!   secure/data/erc7730/policy.toml
//!   secure/data/erc7730-e2e/policy.toml
//!
//! Writes (checked into the repo):
//!   tools/companion-stub/erc20_db.bin   (host-side; companion app)
//!   tools/companion-stub/names_db.bin   (host-side; companion app)
//!   tools/companion-stub/selectors_db.bin
//!   tools/companion-stub/selectors_db_e2e.bin
//!   tools/companion-stub/erc7730_db.bin
//!   tools/companion-stub/erc7730_db_e2e.bin
//!   secure/data/erc7730-forced-eligible.set
//!   secure/data/erc7730-forced-eligible-e2e.set
//!   secure/src/db_roots.rs
//!   secure/data/erc7730.review.txt
//!
//! Run manually after editing the JSON sources:
//!
//!   cargo run -p dbgen
//!
//! The runtime parsers live in (all `e2e-test`-gated — they are the
//! QEMU companion stub; production firmware ships no blob, only the
//! root, and verifies companion-supplied bundles):
//!   nonsecure/src/erc20_db.rs   (ERC20 metadata)
//!   nonsecure/src/names_db.rs   (address-name lookup)
//!
//! Both crates physically share the on-disk format definition via
//! sphincs_tz_shared::db_format, so any field-layout change here is a
//! single edit in shared/src/db_format.rs.

use std::fs;
use std::path::PathBuf;

use dbgen::{erc20, erc7730, names, selectors};

const REPO_ROOT_CARGO: &str = env!("CARGO_MANIFEST_DIR");

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is .../sphincs_rust/dbgen — go up one.
    PathBuf::from(REPO_ROOT_CARGO)
        .parent()
        .expect("CARGO_MANIFEST_DIR has no parent")
        .to_path_buf()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Parse minimal CLI flags. We avoid pulling in `clap` to keep
    // build-time deps tight on this tooling crate.
    //
    //   --policy <dev|production>     default: dev (matches the TOML)
    //   --registry-root <dir>         optional; required if any descriptor
    //                                 has an `includes` reference
    let mut force_production = false;
    let mut registry_root: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                let v = args.get(i + 1).map(|s| s.as_str()).unwrap_or("");
                match v {
                    "dev" => force_production = false,
                    "production" => force_production = true,
                    other => {
                        eprintln!("dbgen: --policy must be `dev` or `production` (got `{other}`)");
                        std::process::exit(2);
                    }
                }
                i += 2;
            }
            "--registry-root" => {
                let v = args.get(i + 1).cloned().unwrap_or_default();
                if v.is_empty() {
                    eprintln!("dbgen: --registry-root requires a directory argument");
                    std::process::exit(2);
                }
                registry_root = Some(PathBuf::from(v));
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "dbgen — build-time DB generator\n\
                     \n\
                     Flags:\n  \
                       --policy <dev|production>  ERC-8176 attestation gate (default: dev)\n  \
                       --registry-root <dir>      local mirror of the ERC-7730 registry\n  \
                                                  (required if any descriptor has `includes`)\n"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("dbgen: unknown flag `{other}`");
                std::process::exit(2);
            }
        }
    }

    // The checked-in policy intentionally has no authenticated snapshot or
    // real auditor population yet. Refuse before resolving paths or writing
    // any DB artifact so this code-half cannot masquerade as a root rotation.
    if force_production {
        eprintln!(
            "dbgen: canonical ERC-7730 policy has no independently pinned ERC-8176 snapshot \
             or real trusted-auditor evidence. Refusing before writing any generated artifact; \
             the checked-in catalogue remains dev-unattested until the external gate closes."
        );
        std::process::exit(1);
    }

    let root = repo_root();
    println!("dbgen: workspace root = {}", root.display());
    if let Some(rr) = registry_root.as_ref() {
        println!("dbgen: --registry-root {}", rr.display());
    }

    // Source data lives under secure/data/ for historical reasons
    // (the curated JSON is the same regardless of which world hosts
    // the resulting blob).
    let erc20_json = root.join("secure/data/erc20.json");
    // Small parallel ERC-20 fixture for `--features e2e-test` QEMU builds.
    let erc20_e2e_json = root.join("secure/data/erc20-e2e.json");
    let names_json = root.join("secure/data/names.json");
    // Small parallel Names fixture for `--features e2e-test` QEMU builds.
    let names_e2e_json = root.join("secure/data/names-e2e.json");
    let selectors_json = root.join("secure/data/selectors.json");
    let selectors_e2e_json = root.join("secure/data/selectors-e2e.json");
    // PROD ERC-7730 catalog now sources from the vendored upstream registry
    // (the corpus switch) — built tolerantly (per-descriptor + per-format) so
    // a function the renderer can't decode is skipped, not the whole
    // descriptor. The hand-authored `secure/data/erc7730/` is kept as the
    // render-test fixture set (the host render tests build it via `build_seed`)
    // and as the home of the policy.toml. The e2e fixture catalog is unchanged.
    let erc7730_dir = root.join("secure/data/erc7730");
    let erc7730_policy = erc7730_dir.join("policy.toml");
    let erc7730_registry = root.join("secure/data/erc7730-registry");
    let erc7730_registry_input = erc7730_registry.join("registry");
    let erc7730_curation_manifest = root.join("secure/data/erc7730/curations/manifest.json");
    let erc7730_review_source = erc7730::load_registry_review_source(&erc7730_curation_manifest)
        .unwrap_or_else(|error| {
            eprintln!("dbgen: ERC-7730 review provenance failed: {error}");
            std::process::exit(1);
        });
    let erc7730_e2e_dir = root.join("secure/data/erc7730-e2e");
    // Keep synthetic fixture authority permanently separate from the
    // production policy/snapshot. A future production flip must not make E2E
    // descriptors depend on real auditor evidence or inherit its authority.
    let erc7730_e2e_policy = erc7730_e2e_dir.join("policy.toml");

    // The full DB blobs live on the HOST (companion app), never in
    // the firmware image — exactly like the selectors / ERC-7730
    // blobs below. The firmware embeds the Merkle root plus the fixed release
    // status receipt (via the generated `db_roots.rs`) and Merkle-verifies every
    // companion-supplied bundle against it. The `tools/companion-stub/`
    // copies double as the QEMU e2e companion stub (see the
    // `e2e-test`-gated `nonsecure/src/{erc20,names}_db.rs`).
    let erc20_out = root.join("tools/companion-stub/erc20_db.bin");
    // Tiny e2e fixture blob — see the selectors/erc7730 e2e split below.
    // The full erc20_db.bin can be many MB (host/companion-side only); this
    // small parallel blob is what the `e2e-test` NS stub bakes into 256 KB
    // flash without overflow, matched by ERC20_DB_ROOT under `cfg(e2e-test)`.
    let erc20_e2e_out = root.join("tools/companion-stub/erc20_db_e2e.bin");
    let names_out = root.join("tools/companion-stub/names_db.bin");
    // Tiny e2e fixture blob — the full names_db.bin can grow large
    // (host/companion-side only); this small parallel blob is what the
    // `e2e-test` NS stub bakes into 256 KB flash, matched by NAMES_DB_ROOT
    // under `cfg(e2e-test)`.
    let names_e2e_out = root.join("tools/companion-stub/names_db_e2e.bin");
    // The selectors DB blob also lives on the host (companion app)
    // instead of in NS rodata, so it ships as a separate artifact
    // under tools/companion-stub/. Only the 32-byte SELECTOR_DB_ROOT
    // crosses into the firmware image.
    let selectors_out = root.join("tools/companion-stub/selectors_db.bin");
    // Tiny parallel fixture used by the QEMU e2e test driver.
    // Production builds DO NOT consume this artifact — it's the only
    // way to keep `make e2e` runnable without baking the full
    // host-side blob into NS rodata (which would overflow flash).
    let selectors_e2e_out = root.join("tools/companion-stub/selectors_db_e2e.bin");
    let erc7730_out = root.join("tools/companion-stub/erc7730_db.bin");
    let erc7730_e2e_out = root.join("tools/companion-stub/erc7730_db_e2e.bin");
    let erc7730_status_out = root.join("tools/companion-stub/erc7730_status.bin");
    let erc7730_status_e2e_out = root.join("tools/companion-stub/erc7730_status_e2e.bin");
    let erc7730_review_out = root.join("secure/data/erc7730.review.txt");
    let erc7730_known_calls_out = root.join("secure/data/erc7730-known-calls.bloom");
    let erc7730_known_calls_e2e_out = root.join("secure/data/erc7730-known-calls-e2e.bloom");
    let erc7730_forced_eligible_out = root.join("secure/data/erc7730-forced-eligible.set");
    let erc7730_forced_eligible_e2e_out = root.join("secure/data/erc7730-forced-eligible-e2e.set");
    let roots_out = root.join("secure/src/db_roots.rs");

    // ----- ERC20 metadata DB -----
    // All three host-side blobs share the tools/companion-stub dir;
    // create it once before the first write (selectors/erc7730 below
    // also rely on it existing).
    if let Some(parent) = erc20_out.parent() {
        fs::create_dir_all(parent).expect("create tools/companion-stub");
    }
    let erc20_res = erc20::build_db(&erc20_json).expect("erc20 db build failed");
    erc20::round_trip_check(&erc20_res.blob, &erc20_json, &erc20_res.root)
        .expect("erc20 round-trip failed");
    fs::write(&erc20_out, &erc20_res.blob).expect("write erc20_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, {} entries, root = {})",
        erc20_out.display(),
        erc20_res.blob.len(),
        erc20_res.entry_count,
        hex::encode(erc20_res.root),
    );

    // ----- ERC20 metadata DB (e2e fixture) -----
    //
    // Tiny parallel set used ONLY when the secure crate is built with
    // `--features e2e-test` (the QEMU companion stub bakes the blob into NS
    // rodata). The matching `ERC20_DB_ROOT` under `cfg(feature = "e2e-test")`
    // in db_roots.rs is selected by the same gate, so the production
    // multi-MB blob never has to ship in the 256 KB NS flash. Same shape as
    // the selectors / ERC-7730 e2e splits below.
    let erc20_e2e_res = erc20::build_db(&erc20_e2e_json).expect("erc20 e2e db build failed");
    erc20::round_trip_check(&erc20_e2e_res.blob, &erc20_e2e_json, &erc20_e2e_res.root)
        .expect("erc20 e2e round-trip failed");
    fs::write(&erc20_e2e_out, &erc20_e2e_res.blob).expect("write erc20_db_e2e.bin");
    println!(
        "dbgen: wrote {} ({} bytes, {} entries, e2e root = {})",
        erc20_e2e_out.display(),
        erc20_e2e_res.blob.len(),
        erc20_e2e_res.entry_count,
        hex::encode(erc20_e2e_res.root),
    );

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

    // ----- Names DB (e2e fixture) -----
    //
    // Small parallel set used ONLY under `--features e2e-test` (QEMU stub).
    // The matching NAMES_DB_ROOT under `cfg(feature = "e2e-test")` is selected
    // by the same gate, keeping the full host-side names blob out of the
    // 256 KB NS flash. Same shape as the ERC20 / selectors / ERC-7730 splits.
    let names_e2e_res = names::build_db(&names_e2e_json).expect("names e2e db build failed");
    names::round_trip_check(&names_e2e_res.blob, &names_e2e_json, &names_e2e_res.root)
        .expect("names e2e round-trip failed");
    fs::write(&names_e2e_out, &names_e2e_res.blob).expect("write names_db_e2e.bin");
    println!(
        "dbgen: wrote {} ({} bytes, e2e root = {})",
        names_e2e_out.display(),
        names_e2e_res.blob.len(),
        hex::encode(names_e2e_res.root),
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
    fs::write(&selectors_e2e_out, &selectors_e2e_res.blob).expect("write selectors_db_e2e.bin");
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
    // Tolerant DEV build over the vendored registry. The early CLI fence above
    // rejects the canonical `--policy production` request until independently
    // pinned evidence and real auditors exist.
    let (mut erc7730_res, skips) = erc7730::build_db_tolerant_with_erc20_capabilities(
        &erc7730_registry_input,
        &erc7730_policy,
        Some(&erc7730_registry),
        &erc20_res.capabilities,
    )
    .unwrap_or_else(|e| {
        eprintln!("dbgen: erc7730 registry db build failed: {e}");
        std::process::exit(1);
    });
    erc7730::stamp_registry_review_source(&mut erc7730_res.review_text, &erc7730_review_source)
        .unwrap_or_else(|error| {
            eprintln!("dbgen: ERC-7730 review provenance failed: {error}");
            std::process::exit(1);
        });
    // The full per-skip detail + category roll-up is embedded in the
    // committed, drift-gated `erc7730.review.txt` (see `render_review`); echo
    // just the count here so an operator running dbgen sees at a glance that
    // descriptors were dropped rather than the report being silently discarded
    // (review finding 1.4).
    if !skips.is_empty() {
        eprintln!(
            "dbgen: erc7730 tolerant build recorded {} descriptor/format omission(s) — see the \
             `## skips` section of secure/data/erc7730.review.txt for reasons",
            skips.len(),
        );
    }
    erc7730::round_trip_check(&erc7730_res).expect("erc7730 round-trip failed");
    // Every descriptor-pinned tokenAmount literal must be a DB token, a native
    // sentinel, or a reviewed exception (dbgen/src/token_constant_exceptions.rs).
    erc7730::check_token_amount_constants(
        &erc7730_res.entries,
        &erc20_res.capabilities,
        dbgen::token_constant_exceptions::PRODUCTION,
    )
    .unwrap_or_else(|e| {
        eprintln!("dbgen: ERC-7730 constant-token gate failed: {e}");
        std::process::exit(1);
    });
    let erc7730_status =
        erc7730::catalogue_status_v1(&erc7730_res, erc7730_review_source.manifest_sha256())
            .expect("encode erc7730 catalogue status");
    let erc7730_status_bytes = erc7730_status.to_bytes();
    if let Some(parent) = erc7730_out.parent() {
        fs::create_dir_all(parent).expect("create tools/companion-stub");
    }
    fs::write(&erc7730_out, &erc7730_res.blob).expect("write erc7730_db.bin");
    fs::write(&erc7730_status_out, erc7730_status_bytes).expect("write erc7730_status.bin");
    fs::write(&erc7730_known_calls_out, erc7730_res.known_calls_bloom)
        .expect("write erc7730-known-calls.bloom");
    fs::write(
        &erc7730_forced_eligible_out,
        &erc7730_res.forced_eligible_set,
    )
    .expect("write erc7730-forced-eligible.set");
    fs::write(&erc7730_review_out, &erc7730_res.review_text).expect("write erc7730.review.txt");
    println!(
        "dbgen: wrote {} ({} bytes, {} leaves, root = {})",
        erc7730_out.display(),
        erc7730_res.blob.len(),
        erc7730_res.leaf_count,
        hex::encode(erc7730_res.root),
    );
    println!("dbgen: wrote {}", erc7730_review_out.display());
    println!("dbgen: wrote {}", erc7730_status_out.display());
    println!(
        "dbgen: wrote {} ({} known calls)",
        erc7730_known_calls_out.display(),
        erc7730_res.known_call_count,
    );
    println!(
        "dbgen: wrote {} ({} bytes, {} groups, {} forced-eligible tuples; {} clear-capable)",
        erc7730_forced_eligible_out.display(),
        erc7730_res.forced_eligible_set.len(),
        erc7730_res.forced_eligible_group_count,
        erc7730_res.forced_eligible_count,
        erc7730_res.clear_contract_call_count,
    );

    // ----- ERC-7730 descriptor catalog (e2e fixture) -----
    //
    // Same role as the selectors e2e variant: a tiny parallel catalog
    // used when the secure crate is built with `--features e2e-test`,
    // so QEMU CI runs don't need to bake the full host-side blob into
    // any stub buffer. The matching ERC7730_DESCRIPTORS_ROOT_E2E in
    // db_roots.rs is selected at compile time via the same feature
    // gate.
    let erc7730_e2e_res = erc7730::build_e2e_db_with_policy_override_and_erc20_capabilities(
        &erc7730_e2e_dir,
        &erc7730_e2e_policy,
        false,
        registry_root.as_deref(),
        &erc20_e2e_res.capabilities,
    )
    .unwrap_or_else(|e| {
        eprintln!("dbgen: erc7730 e2e db build failed: {e}");
        std::process::exit(1);
    });
    erc7730::round_trip_check(&erc7730_e2e_res).expect("erc7730 e2e round-trip failed");
    erc7730::check_token_amount_constants(
        &erc7730_e2e_res.entries,
        &erc20_e2e_res.capabilities,
        dbgen::token_constant_exceptions::E2E,
    )
    .unwrap_or_else(|e| {
        eprintln!("dbgen: ERC-7730 e2e constant-token gate failed: {e}");
        std::process::exit(1);
    });
    let erc7730_status_e2e = erc7730::catalogue_status_v1(&erc7730_e2e_res, [0; 32])
        .expect("encode erc7730 e2e catalogue status");
    let erc7730_status_e2e_bytes = erc7730_status_e2e.to_bytes();
    fs::write(&erc7730_e2e_out, &erc7730_e2e_res.blob).expect("write erc7730_db_e2e.bin");
    fs::write(&erc7730_status_e2e_out, erc7730_status_e2e_bytes)
        .expect("write erc7730_status_e2e.bin");
    fs::write(
        &erc7730_known_calls_e2e_out,
        erc7730_e2e_res.known_calls_bloom,
    )
    .expect("write erc7730-known-calls-e2e.bloom");
    fs::write(
        &erc7730_forced_eligible_e2e_out,
        &erc7730_e2e_res.forced_eligible_set,
    )
    .expect("write erc7730-forced-eligible-e2e.set");
    println!(
        "dbgen: wrote {} ({} bytes, {} leaves, e2e root = {})",
        erc7730_e2e_out.display(),
        erc7730_e2e_res.blob.len(),
        erc7730_e2e_res.leaf_count,
        hex::encode(erc7730_e2e_res.root),
    );
    println!(
        "dbgen: wrote {} ({} known calls)",
        erc7730_known_calls_e2e_out.display(),
        erc7730_e2e_res.known_call_count,
    );
    println!(
        "dbgen: wrote {} ({} bytes, {} groups, {} forced-eligible tuples; {} clear-capable)",
        erc7730_forced_eligible_e2e_out.display(),
        erc7730_e2e_res.forced_eligible_set.len(),
        erc7730_e2e_res.forced_eligible_group_count,
        erc7730_e2e_res.forced_eligible_count,
        erc7730_e2e_res.clear_contract_call_count,
    );
    println!("dbgen: wrote {}", erc7730_status_e2e_out.display());

    // ----- secure/src/db_roots.rs -----
    //
    // This is the only file the secure-world build sees from the DBs.
    // It bakes the Merkle roots and selected ERC-7730 status receipt into the
    // secure image: the
    // SHA-256 ERC-20 + Names + Selectors roots (for the transfer
    // display / address-name lookup / selector text-sig paths) and the
    // ERC-7730 descriptor root (for the Phase-3 trailer parser).
    let roots_rs = render_db_roots(
        &erc20_res.root,
        &erc20_e2e_res.root,
        &names_res.root,
        &names_e2e_res.root,
        &selectors_res.root,
        &selectors_e2e_res.root,
        &erc7730_res.root,
        erc7730_res.leaf_count,
        erc7730_res.provenance,
        &erc7730_status_bytes,
        erc7730_res.forced_eligible_set.len(),
        erc7730_res.forced_eligible_group_count,
        erc7730_res.forced_eligible_count,
        &erc7730_e2e_res.root,
        erc7730_e2e_res.leaf_count,
        erc7730_e2e_res.provenance,
        &erc7730_status_e2e_bytes,
        erc7730_e2e_res.forced_eligible_set.len(),
        erc7730_e2e_res.forced_eligible_group_count,
        erc7730_e2e_res.forced_eligible_count,
    );
    fs::write(&roots_out, &roots_rs).expect("write db_roots.rs");
    println!("dbgen: wrote {}", roots_out.display());

    println!("dbgen: ok");
}

const DB_ROOTS_HEADER: &str = "\
//! Merkle roots of the (host-side) ERC20 + Names + Selectors + ERC-7730 databases.
//!
//! Generated by `cargo run -p dbgen` from secure/data/erc20.json,
//! secure/data/names.json, secure/data/selectors.json,
//! secure/data/erc7730-registry/registry/**/*.json,
//! secure/data/erc7730-registry/ercs/**/*.json,
//! secure/data/erc7730-e2e/*.json, secure/data/erc7730/policy.toml, and
//! secure/data/erc7730-e2e/policy.toml.
//! DO NOT EDIT BY HAND.
//!
//! None of the host-side Merkle DB blobs ship in the firmware image. The ERC20 /
//! Names / Selectors / ERC-7730 blobs all live on the host (companion
//! app) under `tools/companion-stub/` and are forwarded over USB as
//! per-tx `(entry, merkle_proof, leaf_index)` bundles. The secure
//! world holds the 32-byte roots plus the generated real ERC-7730 leaf
//! count; everything received from NS or the host is verified against
//! those firmware-pinned values. A malicious companion cannot
//! forge an entry (that needs a SHA-256 second-preimage). Withholding
//! ERC20 / Names / Selectors metadata degrades to the corresponding
//! fail-safe render. A registry-known call requires independently
//! authenticated semantics: normally an exactly bound ERC-7730 descriptor;
//! the explicitly enumerated Safe exception is strict native ERC-20 decoding
//! with exact chain/contract-bound Merkle metadata, re-attributed per direct
//! call or MultiSend record. Without either capability, signing refuses. Only
//! calls absent from the authenticated known-call set may use the generic or
//! ordinary blind-sign fallback.
//! When the default-off `erc7730-forced-blind` feature is selected, the exact
//! refused-known `P73K` set is a separate, co-embedded used array for its
//! distinct forced ceremony. It is not a host database and cannot be supplied
//! or substituted by the companion.
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
//! every bundle crossing the gateway is Merkle-verified against this
//! root and constrained to the generated catalogue count by the secure
//! `crate::tx::erc7730::verify_erc7730_bundle` wrapper.
//! The generated `ERC7730_CATALOGUE_PROVENANCE` constant records whether the
//! exact root was produced by real ERC-8176 verification or by the explicitly
//! dev-only unattested path. Generated compile fences prevent a dev-unattested
//! root from being used without its warning feature and always reject it under
//! `mode-production`. ERC-8176 verification remains host-side (preserving
//! invariant #5 — no classical signer on-device).

";

fn render_db_roots(
    erc20_root: &[u8; 32],
    erc20_e2e_root: &[u8; 32],
    names_root: &[u8; 32],
    names_e2e_root: &[u8; 32],
    selectors_root: &[u8; 32],
    selectors_e2e_root: &[u8; 32],
    erc7730_root: &[u8; 32],
    erc7730_count: usize,
    erc7730_provenance: erc7730::CatalogueProvenance,
    erc7730_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    erc7730_forced_eligible_len: usize,
    erc7730_forced_eligible_group_count: usize,
    erc7730_forced_eligible_count: usize,
    erc7730_e2e_root: &[u8; 32],
    erc7730_e2e_count: usize,
    erc7730_e2e_provenance: erc7730::CatalogueProvenance,
    erc7730_e2e_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    erc7730_forced_eligible_e2e_len: usize,
    erc7730_forced_eligible_e2e_group_count: usize,
    erc7730_forced_eligible_e2e_count: usize,
) -> String {
    use std::fmt::Write;

    let mut s = String::with_capacity(DB_ROOTS_HEADER.len() + 8 * 256);
    s.push_str(DB_ROOTS_HEADER);
    // ERC20_DB_ROOT is e2e-split like SELECTOR_DB_ROOT: production firmware
    // anchors the full multi-MB host-side DB; `e2e-test` builds anchor the
    // tiny erc20-e2e fixture the QEMU NS stub bakes into 256 KB flash.
    writeln!(s, "#[cfg(not(feature = \"e2e-test\"))]").unwrap();
    emit_root(&mut s, "ERC20_DB_ROOT", erc20_root);
    writeln!(s, "#[cfg(feature = \"e2e-test\")]").unwrap();
    emit_root(&mut s, "ERC20_DB_ROOT", erc20_e2e_root);
    // NAMES_DB_ROOT is e2e-split like SELECTOR_DB_ROOT / ERC20_DB_ROOT:
    // production anchors the full host-side names DB; `e2e-test` anchors the
    // tiny names-e2e fixture the QEMU NS stub bakes into 256 KB flash.
    writeln!(s, "#[cfg(not(feature = \"e2e-test\"))]").unwrap();
    emit_root(&mut s, "NAMES_DB_ROOT", names_root);
    writeln!(s, "#[cfg(feature = \"e2e-test\")]").unwrap();
    emit_root(&mut s, "NAMES_DB_ROOT", names_e2e_root);
    writeln!(s, "#[cfg(not(feature = \"e2e-test\"))]").unwrap();
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_root);
    writeln!(s, "#[cfg(feature = \"e2e-test\")]").unwrap();
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_e2e_root);
    s.push_str(&dbgen::render_erc7730_security_tail(
        dbgen::Erc7730SecurityTailInput {
            root: erc7730_root,
            descriptor_count: erc7730_count,
            provenance: erc7730_provenance,
            status: erc7730_status,
            forced_eligible_len: erc7730_forced_eligible_len,
            forced_eligible_group_count: erc7730_forced_eligible_group_count,
            forced_eligible_count: erc7730_forced_eligible_count,
        },
        dbgen::Erc7730SecurityTailInput {
            root: erc7730_e2e_root,
            descriptor_count: erc7730_e2e_count,
            provenance: erc7730_e2e_provenance,
            status: erc7730_e2e_status,
            forced_eligible_len: erc7730_forced_eligible_e2e_len,
            forced_eligible_group_count: erc7730_forced_eligible_e2e_group_count,
            forced_eligible_count: erc7730_forced_eligible_e2e_count,
        },
    ));
    s
}

fn emit_root(s: &mut String, name: &str, bytes: &[u8; 32]) {
    use std::fmt::Write;
    write!(s, "pub static {name}: [u8; 32] = [").unwrap();
    for (i, b) in bytes.iter().enumerate() {
        if i % 8 == 0 {
            s.push_str("\n    ");
        } else {
            s.push(' ');
        }
        write!(s, "0x{b:02x},").unwrap();
    }
    s.push_str("\n];\n\n");
}
